package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const maxHintServers = 10

type ServerResult struct {
	IP          string
	QPS         float64
	SuccessRate float64
	LatencyP50  time.Duration
}

type ScanStats struct {
	Country      string
	Mode         string
	TotalScanned int64
	Found        int64
	Duration     time.Duration
}

type OutputWriter interface {
	Write(results []ServerResult, stats ScanStats) error
}

// --- JSON ---

type JSONWriter struct {
	w io.Writer
}

func NewJSONWriter(w io.Writer) *JSONWriter {
	return &JSONWriter{w: w}
}

type jsonOutput struct {
	Servers []jsonServer `json:"servers"`
	Scan    jsonScan     `json:"scan"`
}

type jsonServer struct {
	IP          string  `json:"ip"`
	QPS         float64 `json:"qps,omitempty"`
	SuccessRate float64 `json:"success_rate,omitempty"`
	LatencyP50  int64   `json:"latency_p50_ms,omitempty"`
}

type jsonScan struct {
	Country      string `json:"country,omitempty"`
	Mode         string `json:"mode,omitempty"`
	TotalScanned int64  `json:"total_scanned"`
	Found        int64  `json:"found"`
	DurationMs   int64  `json:"duration_ms"`
}

func (j *JSONWriter) Write(results []ServerResult, stats ScanStats) error {
	out := jsonOutput{
		Servers: make([]jsonServer, 0, len(results)),
		Scan: jsonScan{
			Country:      stats.Country,
			Mode:         stats.Mode,
			TotalScanned: stats.TotalScanned,
			Found:        stats.Found,
			DurationMs:   stats.Duration.Milliseconds(),
		},
	}

	for _, r := range results {
		out.Servers = append(out.Servers, jsonServer{
			IP:          r.IP,
			QPS:         r.QPS,
			SuccessRate: r.SuccessRate,
			LatencyP50:  r.LatencyP50.Milliseconds(),
		})
	}

	enc := json.NewEncoder(j.w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// --- Text ---

type TextWriter struct {
	w io.Writer
}

func NewTextWriter(w io.Writer) *TextWriter {
	return &TextWriter{w: w}
}

func (t *TextWriter) Write(results []ServerResult, stats ScanStats) error {
	for _, r := range results {
		if _, err := fmt.Fprintln(t.w, r.IP); err != nil {
			return err
		}
	}
	return nil
}

func printBanner(w io.Writer, cfg *Config, totalIPs int, version string) {
	if !cfg.Progress {
		fmt.Fprintf(w, "Scanning %d IPs...\n", totalIPs)
		return
	}
	fmt.Fprintf(w, "dnscan %s\n", version)
	if cfg.InputFile != "" {
		fmt.Fprintf(w, "Source: %s | Workers: %d | Timeout: %v\n", cfg.InputFile, cfg.Workers, cfg.Timeout)
	} else {
		fmt.Fprintf(w, "Country: %s | Mode: %s | Workers: %d | Timeout: %v\n", cfg.Country, cfg.Mode, cfg.Workers, cfg.Timeout)
	}
	if cfg.Domain != "" {
		fmt.Fprintf(w, "Tunnel domain: %s (verifies query reaches server)\n", cfg.Domain)
	} else {
		fmt.Fprintf(w, "WARNING: No --domain set. Finding generic DNS, not tunnel-compatible!\n")
		fmt.Fprintf(w, "         Use: --domain t.example.com for slipstream compatibility\n")
	}
	fmt.Fprintf(w, "IPs to scan: %d\n", totalIPs)
	fmt.Fprintf(w, "---\n")
}

func printUsageHint(w io.Writer, ips []string, domain string) {
	if len(ips) == 0 {
		return
	}
	if domain == "" {
		domain = "<domain>"
	}
	fmt.Fprintf(w, "\nUsage:\n  slipstream-client \\\n")
	for i := 0; i < min(len(ips), maxHintServers); i++ {
		fmt.Fprintf(w, "    --resolver %s:53 \\\n", ips[i])
	}
	fmt.Fprintf(w, "    --domain %s \\\n", domain)
	fmt.Fprintf(w, "    --tcp-listen-port 7000\n")
}
