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

	var out io.Writer = os.Stdout
	if app.outFile != nil {
		out = app.outFile
	}

	if cfg.JSONOutput {
		NewJSONWriter(out).Write(serverResults, stats)
	} else {
		if app.outFile != nil || !cfg.Progress {
			NewTextWriter(out).Write(serverResults, stats)
		}
		if cfg.Progress {
			PrintUsageHint(os.Stderr, workingDNS, cfg.Domain)
		}
	}
}
