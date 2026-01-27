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
	"sort"
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
	version = "dev"
)

// verifyWithSlipstream tests if a DNS server actually works with slipstream-client
func verifyWithSlipstream(clientPath, domain, ip string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout*3)
	defer cancel()

	cmd := exec.CommandContext(ctx, clientPath,
		"--resolver", ip+":53",
		"--domain", domain,
		"--tcp-listen-port", "0", // Random available port
	)

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		return false
	}

	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Poll for "Connection ready" (success) or errors (failure)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		result := output.String()

		// Success: tunnel connected
		if strings.Contains(result, "Connection ready") {
			return true
		}

		// Failure: connection error
		if strings.Contains(result, "Connection closed") || strings.Contains(result, "became unavailable") {
			return false
		}

		time.Sleep(200 * time.Millisecond)
	}

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
		fmt.Printf("dnscan %s\n", version)
		os.Exit(0)
	}

	// Validate mode
	validModes := map[string]bool{"fast": true, "medium": true, "all": true, "list": true}
	if !validModes[*mode] {
		fmt.Fprintf(os.Stderr, "Invalid mode: %s (use: fast, medium, all, list)\n", *mode)
		os.Exit(1)
	}

	// Validate --verify binary if provided
	if *verify != "" {
		info, err := os.Stat(*verify)
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Verify binary not found: %s\n", *verify)
			os.Exit(1)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot access verify binary: %v\n", err)
			os.Exit(1)
		}
		if info.IsDir() {
			fmt.Fprintf(os.Stderr, "Verify path is a directory, not a binary: %s\n", *verify)
			os.Exit(1)
		}
		if info.Mode()&0111 == 0 {
			fmt.Fprintf(os.Stderr, "Verify binary is not executable: %s\nRun: chmod +x %s\n", *verify, *verify)
			os.Exit(1)
		}
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
		fmt.Fprintf(os.Stderr, "dnscan %s\n", version)
		if *inputFile != "" {
			fmt.Fprintf(os.Stderr, "Source: %s | Workers: %d | Timeout: %v\n", *inputFile, *workers, *timeout)
		} else {
			fmt.Fprintf(os.Stderr, "Country: %s | Mode: %s | Workers: %d | Timeout: %v\n", *country, *mode, *workers, *timeout)
		}
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

	// Phase 2: Verify with slipstream-client if requested
	if *verify != "" && len(workingDNS) > 0 {
		if *progress {
			fmt.Fprintf(os.Stderr, "\nVerifying %d candidates with slipstream-client...\n", len(workingDNS))
		}

		var verified []string
		total := len(workingDNS)
		width := len(fmt.Sprintf("%d", total))
		for i, ip := range workingDNS {
			// Check for interrupt
			select {
			case <-ctx.Done():
				if *progress {
					fmt.Fprintf(os.Stderr, "\nInterrupted during verification\n")
				}
				goto slipstreamDone
			default:
			}

			if *progress {
				fmt.Fprintf(os.Stderr, "[%*d/%d] %-15s  ", width, i+1, total, ip)
			}
			start := time.Now()
			if verifyWithSlipstream(*verify, *domain, ip, *timeout) {
				elapsed := time.Since(start)
				verified = append(verified, ip)
				if *progress {
					fmt.Fprintf(os.Stderr, "\033[32mOK (%.1fs)\033[0m\n", elapsed.Seconds())
				}
			} else {
				if *progress {
					fmt.Fprintf(os.Stderr, "FAIL\n")
				}
			}
		}
	slipstreamDone:

		if *progress {
			fmt.Fprintf(os.Stderr, "---\n")
			fmt.Fprintf(os.Stderr, "Slipstream: %d/%d passed\n", len(verified), len(workingDNS))
		}
		workingDNS = verified
	}

	// Phase 3: Burst test to verify servers handle concurrent load
	var burstResults []*BurstResult
	if *domain != "" && len(workingDNS) > 0 {
		if *progress {
			fmt.Fprintf(os.Stderr, "\nBurst testing %d candidates (%d queries, %d%% required)...\n",
				len(workingDNS), BurstQueries, BurstMinSuccess)
		}

		total := len(workingDNS)
		width := len(fmt.Sprintf("%d", total))
		for i, ip := range workingDNS {
			// Check for interrupt
			select {
			case <-ctx.Done():
				if *progress {
					fmt.Fprintf(os.Stderr, "\nInterrupted during burst test\n")
				}
				goto burstDone
			default:
			}

			if *progress {
				fmt.Fprintf(os.Stderr, "[%*d/%d] %-15s  ", width, i+1, total, ip)
			}

			result := BurstTest(ip, *domain, *timeout)

			if result.Passed() {
				burstResults = append(burstResults, result)
				if *progress {
					// Green for >=85%, yellow for 70-84%
					color := "\033[33m" // yellow
					if result.SuccessRate() >= 85 {
						color = "\033[32m" // green
					}
					fmt.Fprintf(os.Stderr, "%sOK %.0f%% (%.1f qps, p50=%v)\033[0m\n",
						color, result.SuccessRate(), result.QPS(), result.P50().Round(time.Millisecond))
				}
			} else {
				if *progress {
					fmt.Fprintf(os.Stderr, "FAIL %.0f%%\n", result.SuccessRate())
				}
			}
		}
	burstDone:

		// Sort by QPS descending (highest throughput first)
		sort.Slice(burstResults, func(i, j int) bool {
			return burstResults[i].QPS() > burstResults[j].QPS()
		})

		if *progress {
			fmt.Fprintf(os.Stderr, "---\n")
			fmt.Fprintf(os.Stderr, "Burst test: %d/%d passed (sorted by throughput)\n", len(burstResults), len(workingDNS))
		}

		// Extract sorted IPs
		workingDNS = nil
		for _, r := range burstResults {
			workingDNS = append(workingDNS, r.IP)
		}
	}

	// Write results
	if len(workingDNS) > 0 {
		if *progress {
			fmt.Fprintf(os.Stderr, "---\n")
		}
		for _, ip := range workingDNS {
			if outFile != nil {
				fmt.Fprintln(outFile, ip)
			} else {
				fmt.Println(ip)
			}
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
