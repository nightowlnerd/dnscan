package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// readIPsFromFile reads IPs from a file (one per line)
func readIPsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ips []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			ips = append(ips, line)
		}
	}
	return ips, scanner.Err()
}

var (
	version = "2.0.0"
)

// verifyWithSlipstream tests if a DNS server actually works with slipstream-client
func verifyWithSlipstream(clientPath, domain, ip string, timeout time.Duration) bool {
	// Give extra time for connection attempt and error to appear
	ctx, cancel := context.WithTimeout(context.Background(), timeout*3)
	defer cancel()

	cmd := exec.CommandContext(ctx, clientPath,
		"--resolver", ip+":53",
		"--domain", domain,
		"--tcp-listen-port", "0", // Use random port
	)

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		return false
	}

	// Poll for "Connection ready" (success) or errors (failure)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		result := output.String()

		// Success: tunnel actually connected
		if strings.Contains(result, "Connection ready") {
			cmd.Process.Kill()
			cmd.Wait()
			return true
		}

		// Failure: connection error
		if strings.Contains(result, "Connection closed") || strings.Contains(result, "became unavailable") {
			cmd.Process.Kill()
			cmd.Wait()
			return false
		}

		time.Sleep(200 * time.Millisecond)
	}

	// Timeout without success or failure = failure
	cmd.Process.Kill()
	cmd.Wait()
	return false
}

func main() {
	// CLI flags
	country := flag.String("country", "ir", "Country code for IP ranges (e.g., ir, cn)")
	mode := flag.String("mode", "fast", "Scan mode: fast, medium, all, list")
	workers := flag.Int("workers", 500, "Number of concurrent workers")
	timeout := flag.Duration("timeout", 2*time.Second, "DNS query timeout")
	output := flag.String("output", "", "Output file (default: stdout)")
	inputFile := flag.String("file", "", "Input file with DNS IPs (one per line)")
	dataDir := flag.String("data-dir", "data", "Directory containing ranges/ and dns/ subdirs")
	progress := flag.Bool("progress", true, "Show progress indicator")
	domain := flag.String("domain", "", "Tunnel domain to verify (e.g., t.example.com). Required for slipstream compatibility.")
	verify := flag.String("verify", "", "Path to slipstream-client binary to verify candidates actually work")
	showVersion := flag.Bool("version", false, "Show version")
	flag.Parse()

	// Set data directory
	DataDir = *dataDir

	if *showVersion {
		fmt.Printf("dnscan v%s\n", version)
		os.Exit(0)
	}

	// Validate mode
	validModes := map[string]bool{"fast": true, "medium": true, "all": true, "list": true}
	if !validModes[*mode] {
		fmt.Fprintf(os.Stderr, "Invalid mode: %s (use: fast, medium, all, list)\n", *mode)
		os.Exit(1)
	}

	// Setup output
	var outFile *os.File
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		outFile = f
	}

	// Get IPs to scan
	var ips <-chan string
	var totalIPs int

	if *inputFile != "" {
		// Read from file
		fileIPs, err := readIPsFromFile(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read file: %v\n", err)
			os.Exit(1)
		}
		ips = IPsFromList(fileIPs)
		totalIPs = len(fileIPs)
	} else if *mode == "list" {
		// Load known DNS servers for country
		dnsList, err := LoadDNSList(*country)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load DNS list for %s: %v\n", *country, err)
			os.Exit(1)
		}
		ips = IPsFromList(dnsList)
		totalIPs = len(dnsList)
	} else {
		// Load IP ranges for country
		ranges, err := LoadRanges(*country)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load ranges for %s: %v\n", *country, err)
			os.Exit(1)
		}
		totalIPs = CountIPsWithMode(ranges, *mode)
		ips = ExpandRangesWithMode(ranges, *mode)
	}

	// Print header
	if *progress {
		fmt.Fprintf(os.Stderr, "DNS Scanner v%s\n", version)
		fmt.Fprintf(os.Stderr, "Country: %s | Mode: %s | Workers: %d | Timeout: %v\n", *country, *mode, *workers, *timeout)
		if *domain != "" {
			fmt.Fprintf(os.Stderr, "Tunnel domain: %s (verifies query reaches server)\n", *domain)
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: No --domain set. Finding generic DNS, not tunnel-compatible!\n")
			fmt.Fprintf(os.Stderr, "         Use: --domain t.example.com for slipstream compatibility\n")
		}
		fmt.Fprintf(os.Stderr, "IPs to scan: %d\n", totalIPs)
		fmt.Fprintf(os.Stderr, "---\n")
	}

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if *progress {
			fmt.Fprintf(os.Stderr, "\nInterrupted, stopping...\n")
		}
		cancel()
	}()

	// Create scanner
	prog := NewProgress(totalIPs, *progress)
	scanner := NewScanner(*workers, *timeout, prog, *domain)

	// Start progress ticker
	var progressDone chan struct{}
	if *progress {
		progressDone = make(chan struct{})
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					scanned, found, total, elapsed := prog.Stats()
					rate := float64(scanned) / elapsed.Seconds()
					pct := float64(scanned) / float64(total) * 100
					fmt.Fprintf(os.Stderr, "\rScanned: %d/%d (%.1f%%) | Found: %d | %.0f IPs/sec   ",
						scanned, total, pct, found, rate)
				case <-ctx.Done():
					return
				case <-progressDone:
					return
				}
			}
		}()
	}

	// Run scanner
	results := scanner.Run(ctx, ips)

	// Collect results
	var workingDNS []string
resultLoop:
	for {
		select {
		case <-ctx.Done():
			break resultLoop
		case result, ok := <-results:
			if !ok {
				break resultLoop
			}
			if result.Working {
				workingDNS = append(workingDNS, result.IP)
				if outFile != nil {
					fmt.Fprintln(outFile, result.IP)
				}
			}
		}
	}

	// Stop progress ticker
	if progressDone != nil {
		close(progressDone)
	}

	// Print final stats
	if *progress {
		scanned, found, _, elapsed := prog.Stats()
		fmt.Fprintf(os.Stderr, "\r                                                              \r")
		fmt.Fprintf(os.Stderr, "---\n")
		fmt.Fprintf(os.Stderr, "Completed: %d IPs in %v\n", scanned, elapsed.Round(time.Millisecond))
		fmt.Fprintf(os.Stderr, "Found: %d DNS candidates\n", found)
	}

	// Verify with slipstream-client if requested
	if *verify != "" && len(workingDNS) > 0 {
		if *progress {
			fmt.Fprintf(os.Stderr, "\nVerifying %d candidates with slipstream-client...\n", len(workingDNS))
		}

		var verified []string
		for i, ip := range workingDNS {
			// Check for interrupt
			select {
			case <-ctx.Done():
				if *progress {
					fmt.Fprintf(os.Stderr, "\nInterrupted during verification\n")
				}
				goto done
			default:
			}

			if *progress {
				fmt.Fprintf(os.Stderr, "\r[%d/%d] Testing %s...   ", i+1, len(workingDNS), ip)
			}
			if verifyWithSlipstream(*verify, *domain, ip, *timeout) {
				verified = append(verified, ip)
				if *progress {
					fmt.Fprintf(os.Stderr, "OK\n")
				}
			} else {
				if *progress {
					fmt.Fprintf(os.Stderr, "FAIL\n")
				}
			}
		}
	done:

		if *progress {
			fmt.Fprintf(os.Stderr, "---\n")
			fmt.Fprintf(os.Stderr, "Verified: %d working with slipstream\n", len(verified))
		}
		workingDNS = verified
	}

	// Print results to stdout if no output file
	if outFile == nil && len(workingDNS) > 0 {
		if *progress {
			fmt.Fprintf(os.Stderr, "---\n")
		}
		for _, ip := range workingDNS {
			fmt.Println(ip)
		}
	}

	// Print usage hint
	if *progress && len(workingDNS) > 0 {
		showDomain := *domain
		if showDomain == "" {
			showDomain = "<domain>"
		}
		max := 10
		if len(workingDNS) < max {
			max = len(workingDNS)
		}
		fmt.Fprintf(os.Stderr, "\nUsage:\n  slipstream-client \\\n")
		for i := 0; i < max; i++ {
			fmt.Fprintf(os.Stderr, "    --resolver %s:53 \\\n", workingDNS[i])
		}
		fmt.Fprintf(os.Stderr, "    --domain %s \\\n", showDomain)
		fmt.Fprintf(os.Stderr, "    --tcp-listen-port 7000\n")
	}
}
