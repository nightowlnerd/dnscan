package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"
)

var version = "dev"

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

	app, err := NewApp(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer app.Close()

	ips := app.source.IPs()
	totalIPs := app.source.Count()

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
					stats := prog.Stats()
					rate := float64(stats.Processed) / stats.Elapsed.Seconds()
					pct := float64(stats.Processed) / float64(stats.Total) * 100
					fmt.Fprintf(os.Stderr, "\rScanned: %d/%d (%.1f%%) | Found: %d | %.0f IPs/sec   ",
						stats.Processed, stats.Total, pct, stats.Success, rate)
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
		stats := prog.Stats()
		fmt.Fprintf(os.Stderr, "\r                                                              \r")
		fmt.Fprintf(os.Stderr, "Completed: %d IPs in %v\n", stats.Processed, stats.Elapsed.Round(time.Millisecond))
		fmt.Fprintf(os.Stderr, "Found: %d DNS candidates\n", stats.Success)
		if suspiciousCount > 0 {
			fmt.Fprintf(os.Stderr, "\033[33mWarning: %d servers returned private IPs (possible DNS hijacking)\033[0m\n", suspiciousCount)
		}
	}

	// Phase 2: Verify with tunnel client if requested
	if cfg.VerifyBinary != "" && len(workingDNS) > 0 {
		verifier := NewSlipstreamVerifier(cfg.VerifyBinary, cfg.Domain, cfg.Timeout)

		if cfg.Progress {
			fmt.Fprintf(os.Stderr, "\nVerifying %d candidates with %s...\n", len(workingDNS), verifier.Name())
		}

		var verified []string
		total := len(workingDNS)
		width := len(fmt.Sprintf("%d", total))
		for i, ip := range workingDNS {
			select {
			case <-ctx.Done():
				if cfg.Progress {
					fmt.Fprintf(os.Stderr, "\nInterrupted during verification\n")
				}
				goto verifyDone
			default:
			}

			if cfg.Progress {
				fmt.Fprintf(os.Stderr, "[%*d/%d] %-15s  ", width, i+1, total, ip)
			}
			start := time.Now()
			if verifier.Verify(ip) {
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
	verifyDone:

		if cfg.Progress {
			fmt.Fprintf(os.Stderr, "---\n")
			fmt.Fprintf(os.Stderr, "%s: %d/%d passed\n", verifier.Name(), len(verified), len(workingDNS))
		}
		workingDNS = verified
	}

	// Phase 3: Benchmark to verify servers handle concurrent load
	var benchResults []*BenchmarkResult
	if cfg.Domain != "" && len(workingDNS) > 0 {
		total := len(workingDNS)

		if total <= 5 {
			// Sequential for small lists - nicer per-IP output
			if cfg.Progress {
				fmt.Fprintf(os.Stderr, "\nBenchmarking %d candidates (%d queries, %d%% required)...\n",
					total, BenchmarkQueries, BenchmarkThreshold)
			}

			width := len(fmt.Sprintf("%d", total))
			for i, ip := range workingDNS {
				select {
				case <-ctx.Done():
					if cfg.Progress {
						fmt.Fprintf(os.Stderr, "\nInterrupted during benchmark\n")
					}
					goto benchDone
				default:
				}

				if cfg.Progress {
					fmt.Fprintf(os.Stderr, "[%*d/%d] %-15s  ", width, i+1, total, ip)
				}

				result := Benchmark(ctx, ip, cfg.Domain, 53, cfg.Timeout)

				if result.Passed() {
					benchResults = append(benchResults, result)
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
			benchWorkers := min(total, 10)
			if cfg.Progress {
				fmt.Fprintf(os.Stderr, "\nBenchmarking %d candidates in parallel (%d workers)...\n",
					total, benchWorkers)
			}

			benchProg := NewProgress(total, cfg.Progress)
			var progressDone chan struct{}

			if cfg.Progress {
				progressDone = make(chan struct{})
				go func() {
					ticker := time.NewTicker(500 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-ticker.C:
							stats := benchProg.Stats()
							fmt.Fprintf(os.Stderr, "\rBenchmarking: %d/%d tested, %d passed   ", stats.Processed, stats.Total, stats.Success)
						case <-ctx.Done():
							return
						case <-progressDone:
							return
						}
					}
				}()
			}

			resultChan := BenchmarkParallel(ctx, workingDNS, cfg.Domain, 53, cfg.Timeout, benchWorkers)
			for result := range resultChan {
				benchProg.Increment()
				if result.Passed() {
					benchProg.Success()
					benchResults = append(benchResults, result)
				}
			}

			if progressDone != nil {
				close(progressDone)
				fmt.Fprintf(os.Stderr, "\r                                                \r")
			}
		}
	benchDone:

		sort.Slice(benchResults, func(i, j int) bool {
			return benchResults[i].QPS() > benchResults[j].QPS()
		})

		if cfg.Progress {
			fmt.Fprintf(os.Stderr, "---\n")
			fmt.Fprintf(os.Stderr, "Benchmark: %d/%d passed (sorted by throughput)\n", len(benchResults), len(workingDNS))
			for _, r := range benchResults {
				color := "\033[33m"
				if r.SuccessRate() >= 85 {
					color = "\033[32m"
				}
				fmt.Fprintf(os.Stderr, "%s%-15s OK %.0f%% (%.1f qps, p50=%v)\033[0m\n",
					color, r.IP, r.SuccessRate(), r.QPS(), r.P50().Round(time.Millisecond))
			}
		}

		workingDNS = nil
		for _, r := range benchResults {
			workingDNS = append(workingDNS, r.IP)
		}
	}

	finalStats := prog.Stats()

	var serverResults []ServerResult
	if len(benchResults) > 0 {
		for _, r := range benchResults {
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

	outputStats := ScanStats{
		TotalScanned: finalStats.Processed,
		Found:        int64(len(serverResults)),
		Duration:     finalStats.Elapsed,
	}
	if cfg.InputFile == "" {
		outputStats.Country = cfg.Country
		outputStats.Mode = cfg.Mode
	}

	var out io.Writer = os.Stdout
	if app.outFile != nil {
		out = app.outFile
	}

	if cfg.JSONOutput {
		NewJSONWriter(out).Write(serverResults, outputStats)
	} else {
		if app.outFile != nil || !cfg.Progress {
			NewTextWriter(out).Write(serverResults, outputStats)
		}
		if cfg.Progress {
			PrintUsageHint(os.Stderr, workingDNS, cfg.Domain)
		}
	}
}
