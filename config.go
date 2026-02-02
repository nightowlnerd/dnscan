package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

type Config struct {
	Country      string
	Mode         string
	InputFile    string
	DataDir      string
	Workers      int
	Timeout      time.Duration
	Domain       string
	VerifyBinary string
	OutputFile   string
	JSONOutput   bool
	Progress     bool
	ShowVersion  bool
	Threshold    int
}

func ParseFlags() *Config {
	c := &Config{}

	flag.StringVar(&c.Country, "country", "ir", "Country code for IP ranges (e.g., ir, cn)")
	flag.StringVar(&c.Mode, "mode", "fast", "Scan mode: fast, medium, all, list")
	flag.IntVar(&c.Workers, "workers", 500, "Number of concurrent workers")
	flag.DurationVar(&c.Timeout, "timeout", 2*time.Second, "DNS query timeout")
	flag.StringVar(&c.OutputFile, "output", "", "Output file (default: stdout)")
	flag.StringVar(&c.InputFile, "file", "", "Input file with DNS IPs (one per line)")
	flag.StringVar(&c.DataDir, "data-dir", "data", "Directory containing ranges/ and dns/ subdirs")
	flag.BoolVar(&c.Progress, "progress", true, "Show progress indicator")
	flag.StringVar(&c.Domain, "domain", "", "Tunnel domain to verify (e.g., t.example.com)")
	flag.StringVar(&c.VerifyBinary, "verify", "", "Path to slipstream-client binary")
	flag.BoolVar(&c.ShowVersion, "version", false, "Show version")
	flag.BoolVar(&c.JSONOutput, "json", false, "Output results as JSON")
	flag.IntVar(&c.Threshold, "threshold", 70, "Minimum success rate for benchmark (0-100)")

	flag.Parse()

	// JSON is machine output - progress would corrupt it
	if c.JSONOutput {
		c.Progress = false
	}

	return c
}

func (c *Config) Validate() error {
	validModes := map[string]bool{"fast": true, "medium": true, "all": true, "list": true}
	if !validModes[c.Mode] {
		return fmt.Errorf("invalid mode: %s (use: fast, medium, all, list)", c.Mode)
	}

	if c.VerifyBinary != "" {
		info, err := os.Stat(c.VerifyBinary)
		if os.IsNotExist(err) {
			return fmt.Errorf("verify binary not found: %s", c.VerifyBinary)
		}
		if err != nil {
			return fmt.Errorf("cannot access verify binary: %w", err)
		}
		if info.IsDir() {
			return fmt.Errorf("verify path is a directory: %s", c.VerifyBinary)
		}
		if info.Mode()&0111 == 0 {
			return fmt.Errorf("verify binary not executable: %s (run: chmod +x %s)", c.VerifyBinary, c.VerifyBinary)
		}
	}

	return nil
}
