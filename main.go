package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

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
	cfg := ParseFlags()

	if cfg.ShowVersion {
		fmt.Printf("dnscan %s\n", version)
		os.Exit(0)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	DataDir = cfg.DataDir

	var outFile *os.File
	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		outFile = f
	}

	var ips <-chan string
	var totalIPs int

	if cfg.InputFile != "" {
		fileIPs, err := readIPsFromFile(cfg.InputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read file: %v\n", err)
			os.Exit(1)
		}
		ips = IPsFromList(fileIPs)
		totalIPs = len(fileIPs)
	} else if cfg.Mode == "list" {
		dnsList, err := LoadDNSList(cfg.Country)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load DNS list for %s: %v\n", cfg.Country, err)
			os.Exit(1)
		}
		ips = IPsFromList(dnsList)
		totalIPs = len(dnsList)
	} else {
		ranges, err := LoadRanges(cfg.Country)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load ranges for %s: %v\n", cfg.Country, err)
			os.Exit(1)
		}
		totalIPs = CountIPsWithMode(ranges, cfg.Mode)
		ips = ExpandRangesWithMode(ranges, cfg.Mode)
	}

	PrintBanner(os.Stderr, cfg, totalIPs, version)

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if cfg.Progress {
			fmt.Fprintf(os.Stderr, "\nInterrupted, stopping...\n")
		}
		cancel()
	}()

	// Create scanner
	prog := NewProgress(totalIPs, cfg.Progress)
	scanner := NewScanner(cfg.Workers, cfg.Timeout, 53, prog, cfg.Domain)

	// Start progress ticker
	var progressDone chan struct{}
	if cfg.Progress {
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
	var suspiciousCount int
resultLoop:
	for {
		select {
		case <-ctx.Done():
			break resultLoop
		case result, ok := <-results:
			if !ok {
				break resultLoop
			}
			if result.Suspicious {
				suspiciousCount++
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
	if cfg.Progress {
		scanned, found, _, elapsed := prog.Stats()
		fmt.Fprintf(os.Stderr, "\r                                                              \r")
		fmt.Fprintf(os.Stderr, "Completed: %d IPs in %v\n", scanned, elapsed.Round(time.Millisecond))
		fmt.Fprintf(os.Stderr, "Found: %d DNS candidates\n", found)
		if suspiciousCount > 0 {
			fmt.Fprintf(os.Stderr, "\033[33mWarning: %d servers returned private IPs (possible DNS hijacking)\033[0m\n", suspiciousCount)
		}
	}

	// Phase 2: Verify with slipstream-client if requested
	if cfg.VerifyBinary != "" && len(workingDNS) > 0 {
		if cfg.Progress {
			fmt.Fprintf(os.Stderr, "\nVerifying %d candidates with slipstream-client...\n", len(workingDNS))
		}

		var verified []string
		total := len(workingDNS)
		width := len(fmt.Sprintf("%d", total))
		for i, ip := range workingDNS {
			// Check for interrupt
			select {
			case <-ctx.Done():
				if cfg.Progress {
					fmt.Fprintf(os.Stderr, "\nInterrupted during verification\n")
				}
				goto slipstreamDone
			default:
			}

			if cfg.Progress {
				fmt.Fprintf(os.Stderr, "[%*d/%d] %-15s  ", width, i+1, total, ip)
			}
			start := time.Now()
			if verifyWithSlipstream(cfg.VerifyBinary, cfg.Domain, ip, cfg.Timeout) {
				elapsed := time.Since(start)
				verified = append(verified, ip)
				if cfg.Progress {
					fmt.Fprintf(os.Stderr, "\033[32mOK (%.1fs)\033[0m\n", elapsed.Seconds())
				}
			} else {
				if cfg.Progress {
					fmt.Fprintf(os.Stderr, "FAIL\n")
				}
			}
		}
	slipstreamDone:

		if cfg.Progress {
			fmt.Fprintf(os.Stderr, "---\n")
			fmt.Fprintf(os.Stderr, "Slipstream: %d/%d passed\n", len(verified), len(workingDNS))
		}
		workingDNS = verified
	}

	// Phase 3: Burst test to verify servers handle concurrent load
	var burstResults []*BurstResult
	if cfg.Domain != "" && len(workingDNS) > 0 {
		total := len(workingDNS)

		if total <= 5 {
			// Sequential for small lists - nicer per-IP output
			if cfg.Progress {
				fmt.Fprintf(os.Stderr, "\nBurst testing %d candidates (%d queries, %d%% required)...\n",
					total, BurstQueries, BurstMinSuccess)
			}

			width := len(fmt.Sprintf("%d", total))
			for i, ip := range workingDNS {
				select {
				case <-ctx.Done():
					if cfg.Progress {
						fmt.Fprintf(os.Stderr, "\nInterrupted during burst test\n")
					}
					goto burstDone
				default:
				}

				if cfg.Progress {
					fmt.Fprintf(os.Stderr, "[%*d/%d] %-15s  ", width, i+1, total, ip)
				}

				result := BurstTest(ctx, ip, cfg.Domain, 53, cfg.Timeout)

				if result.Passed() {
					burstResults = append(burstResults, result)
					if cfg.Progress {
						color := "\033[33m"
						if result.SuccessRate() >= 85 {
							color = "\033[32m"
						}
						fmt.Fprintf(os.Stderr, "%sOK %.0f%% (%.1f qps, p50=%v)\033[0m\n",
							color, result.SuccessRate(), result.QPS(), result.P50().Round(time.Millisecond))
					}
				} else {
					if cfg.Progress {
						fmt.Fprintf(os.Stderr, "FAIL %.0f%%\n", result.SuccessRate())
					}
				}
			}
		} else {
			// Parallel for larger lists
			burstWorkers := min(total, 10)
			if cfg.Progress {
				fmt.Fprintf(os.Stderr, "\nBurst testing %d candidates in parallel (%d workers)...\n",
					total, burstWorkers)
			}

			burstProg := NewBurstProgress(total, cfg.Progress)
			var progressDone chan struct{}

			if cfg.Progress {
				progressDone = make(chan struct{})
				go func() {
					ticker := time.NewTicker(500 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-ticker.C:
							tested, passed, tot := burstProg.Stats()
							fmt.Fprintf(os.Stderr, "\rBurst testing: %d/%d tested, %d passed   ", tested, tot, passed)
						case <-ctx.Done():
							return
						case <-progressDone:
							return
						}
					}
				}()
			}

			resultChan := ParallelBurstTest(ctx, workingDNS, cfg.Domain, 53, cfg.Timeout, burstWorkers)
			for result := range resultChan {
				burstProg.Tested()
				if result.Passed() {
					burstProg.Passed()
					burstResults = append(burstResults, result)
				}
			}

			if progressDone != nil {
				close(progressDone)
				fmt.Fprintf(os.Stderr, "\r                                                \r")
			}
		}
	burstDone:

		sort.Slice(burstResults, func(i, j int) bool {
			return burstResults[i].QPS() > burstResults[j].QPS()
		})

		if cfg.Progress {
			fmt.Fprintf(os.Stderr, "---\n")
			fmt.Fprintf(os.Stderr, "Burst test: %d/%d passed (sorted by throughput)\n", len(burstResults), len(workingDNS))
			for _, r := range burstResults {
				color := "\033[33m"
				if r.SuccessRate() >= 85 {
					color = "\033[32m"
				}
				fmt.Fprintf(os.Stderr, "%s%-15s OK %.0f%% (%.1f qps, p50=%v)\033[0m\n",
					color, r.IP, r.SuccessRate(), r.QPS(), r.P50().Round(time.Millisecond))
			}
		}

		workingDNS = nil
		for _, r := range burstResults {
			workingDNS = append(workingDNS, r.IP)
		}
	}

	scanned, _, _, elapsed := prog.Stats()

	var serverResults []ServerResult
	if len(burstResults) > 0 {
		for _, r := range burstResults {
			serverResults = append(serverResults, ServerResult{
				IP:          r.IP,
				QPS:         r.QPS(),
				SuccessRate: r.SuccessRate(),
				LatencyP50:  r.P50(),
			})
		}
	} else {
		for _, ip := range workingDNS {
			serverResults = append(serverResults, ServerResult{IP: ip})
		}
	}

	stats := ScanStats{
		TotalScanned: scanned,
		Found:        int64(len(serverResults)),
		Duration:     elapsed,
	}
	if cfg.InputFile == "" {
		stats.Country = cfg.Country
		stats.Mode = cfg.Mode
	}

	// Write output
	out := os.Stdout
	if outFile != nil {
		out = outFile
	}

	if cfg.JSONOutput {
		NewJSONWriter(out).Write(serverResults, stats)
	} else {
		if outFile != nil || !cfg.Progress {
			NewTextWriter(out).Write(serverResults, stats)
		}
		if cfg.Progress {
			PrintUsageHint(os.Stderr, workingDNS, cfg.Domain)
		}
	}
}
