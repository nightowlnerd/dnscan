package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
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

	// Phase 1: Scan
	scanner := NewScanner(cfg.Workers, cfg.Timeout, 53, cfg.Domain, totalIPs, os.Stderr, cfg.Progress)
	workingDNS, suspiciousCount := scanner.Scan(ctx, ips)
	_ = suspiciousCount

	// Phase 2: Verify (optional)
	if cfg.VerifyBinary != "" && len(workingDNS) > 0 {
		verifier := NewSlipstreamVerifier(cfg.VerifyBinary, cfg.Domain, cfg.Timeout, os.Stderr, cfg.Progress)
		workingDNS = verifier.Verify(ctx, workingDNS)
	}

	// Phase 3: Benchmark (optional)
	var benchResults []*BenchmarkResult
	if cfg.Domain != "" && len(workingDNS) > 0 {
		benchmarker := NewBenchmarker(cfg.Domain, 53, cfg.Timeout, os.Stderr, cfg.Progress)
		benchResults = benchmarker.Benchmark(ctx, workingDNS)

		workingDNS = nil
		for _, r := range benchResults {
			workingDNS = append(workingDNS, r.IP)
		}
	}

	// Output results
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
		TotalScanned: int64(totalIPs),
		Found:        int64(len(serverResults)),
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
