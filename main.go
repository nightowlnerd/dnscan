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

	source, err := newIPSource(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var outFile *os.File
	if cfg.OutputFile != "" {
		outFile, err = os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	ips := source.IPs()
	totalIPs := source.Count()

	printBanner(os.Stderr, cfg, totalIPs, version)

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

	scanner := NewScanner(cfg.Workers, cfg.Timeout, 53, cfg.Domain, totalIPs, os.Stderr, cfg.Progress)
	workingDNS := scanner.Scan(ctx, ips)

	if cfg.VerifyBinary != "" && len(workingDNS) > 0 {
		verifier := NewSlipstreamVerifier(cfg.VerifyBinary, cfg.Domain, cfg.Timeout, os.Stderr, cfg.Progress)
		workingDNS = verifier.Verify(ctx, workingDNS)
	}

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
	writeResults(cfg, outFile, workingDNS, benchResults, totalIPs)
}

func newIPSource(cfg *Config) (IPSource, error) {
	if cfg.InputFile != "" {
		return NewFileSource(cfg.InputFile)
	}
	if cfg.Mode == "list" {
		return NewDNSListSource(cfg.DataDir, cfg.Country)
	}
	return NewCIDRSource(cfg.DataDir, cfg.Country, cfg.Mode)
}

func writeResults(cfg *Config, outFile *os.File, workingDNS []string, benchResults []*BenchmarkResult, totalIPs int) {
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

	stats := ScanStats{
		TotalScanned: int64(totalIPs),
		Found:        int64(len(serverResults)),
	}
	if cfg.InputFile == "" {
		stats.Country = cfg.Country
		stats.Mode = cfg.Mode
	}

	var out io.Writer = os.Stdout
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
			printUsageHint(os.Stderr, workingDNS, cfg.Domain)
		}
	}
}
