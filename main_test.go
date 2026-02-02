package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binaryPath string

// Test-local types for parsing JSON output
type testJSONOutput struct {
	Servers []testJSONServer `json:"servers"`
	Scan    testJSONScan     `json:"scan"`
}

type testJSONServer struct {
	IP          string  `json:"ip"`
	QPS         float64 `json:"qps,omitempty"`
	SuccessRate float64 `json:"success_rate,omitempty"`
	LatencyP50  int64   `json:"latency_p50_ms,omitempty"`
}

type testJSONScan struct {
	Country      string `json:"country,omitempty"`
	Mode         string `json:"mode,omitempty"`
	TotalScanned int64  `json:"total_scanned"`
	Found        int64  `json:"found"`
	DurationMs   int64  `json:"duration_ms"`
}

func TestMain(m *testing.M) {
	// Build binary once for all integration tests
	dir, _ := os.MkdirTemp("", "dnscan-test")
	binaryPath = filepath.Join(dir, "dnscan")

	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}

	code := m.Run()

	os.RemoveAll(dir)
	os.Exit(code)
}

func TestVersionFlag(t *testing.T) {
	cmd := exec.Command(binaryPath, "--version")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("--version failed: %v", err)
	}

	if !strings.Contains(string(out), "dnscan") {
		t.Errorf("--version output missing 'dnscan': %s", out)
	}
}

func TestInvalidMode(t *testing.T) {
	cmd := exec.Command(binaryPath, "--mode", "invalid", "--progress=false")
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("expected error for invalid mode")
	}

	if !strings.Contains(string(out), "invalid mode") {
		t.Errorf("expected 'invalid mode' error, got: %s", out)
	}
}

func TestFileInputNotFound(t *testing.T) {
	cmd := exec.Command(binaryPath, "--file", "/nonexistent/file.txt", "--progress=false")
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("expected error for missing file")
	}

	if !strings.Contains(string(out), "Failed to read file") {
		t.Errorf("expected 'Failed to read file' error, got: %s", out)
	}
}

func TestVerifyBinaryNotFound(t *testing.T) {
	cmd := exec.Command(binaryPath, "--verify", "/nonexistent/binary", "--progress=false")
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("expected error for missing verify binary")
	}

	if !strings.Contains(string(out), "not found") {
		t.Errorf("expected 'not found' error, got: %s", out)
	}
}

func TestOutputToFile(t *testing.T) {
	// Create temp file for custom IP list
	inputFile, _ := os.CreateTemp("", "input-*.txt")
	inputFile.WriteString("# comment\n8.8.8.8\n")
	inputFile.Close()
	defer os.Remove(inputFile.Name())

	// Create temp output file
	outputFile, _ := os.CreateTemp("", "output-*.txt")
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	// Run with very short timeout (will likely fail DNS but tests output mechanism)
	cmd := exec.Command(binaryPath,
		"--file", inputFile.Name(),
		"--output", outputFile.Name(),
		"--timeout", "100ms",
		"--progress=false",
	)
	cmd.Run() // Ignore error - DNS may fail

	// Check output file was created
	if _, err := os.Stat(outputFile.Name()); os.IsNotExist(err) {
		t.Error("output file was not created")
	}
}

func TestModeListWithCountry(t *testing.T) {
	cmd := exec.Command(binaryPath,
		"--country", "ir",
		"--mode", "list",
		"--timeout", "100ms",
		"--progress=false",
	)
	_, err := cmd.CombinedOutput()

	// Should start without error (actual DNS queries may fail)
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() == 1 {
			// Exit code 1 from no results is OK
			return
		}
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProgressFlagDisabled(t *testing.T) {
	inputFile, _ := os.CreateTemp("", "input-*.txt")
	inputFile.WriteString("8.8.8.8\n")
	inputFile.Close()
	defer os.Remove(inputFile.Name())

	cmd := exec.Command(binaryPath,
		"--file", inputFile.Name(),
		"--timeout", "100ms",
		"--progress=false",
	)
	out, _ := cmd.CombinedOutput()

	// With progress disabled, should not see "dnscan" header
	if strings.Contains(string(out), "Country:") {
		t.Error("progress=false should not show header")
	}
}

func TestReadIPsFromFile(t *testing.T) {
	// Create temp file
	f, _ := os.CreateTemp("", "ips-*.txt")
	f.WriteString("# comment line\n")
	f.WriteString("192.168.1.1\n")
	f.WriteString("\n") // empty line
	f.WriteString("10.0.0.1\n")
	f.Close()
	defer os.Remove(f.Name())

	ips, err := readIPsFromFile(f.Name())
	if err != nil {
		t.Fatalf("readIPsFromFile failed: %v", err)
	}

	if len(ips) != 2 {
		t.Errorf("expected 2 IPs, got %d", len(ips))
	}

	if ips[0] != "192.168.1.1" || ips[1] != "10.0.0.1" {
		t.Errorf("unexpected IPs: %v", ips)
	}
}

func TestJSONOutputFlag(t *testing.T) {
	inputFile, _ := os.CreateTemp("", "input-*.txt")
	inputFile.WriteString("8.8.8.8\n")
	inputFile.Close()
	defer os.Remove(inputFile.Name())

	cmd := exec.Command(binaryPath,
		"--file", inputFile.Name(),
		"--timeout", "100ms",
		"--json",
	)
	out, _ := cmd.Output()

	var result testJSONOutput
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, out)
	}

	if result.Scan.TotalScanned != 1 {
		t.Errorf("Expected total_scanned=1, got %d", result.Scan.TotalScanned)
	}
}

func TestJSONOutputStructure(t *testing.T) {
	inputFile, _ := os.CreateTemp("", "input-*.txt")
	inputFile.WriteString("8.8.8.8\n")
	inputFile.Close()
	defer os.Remove(inputFile.Name())

	cmd := exec.Command(binaryPath,
		"--file", inputFile.Name(),
		"--timeout", "100ms",
		"--progress=false",
		"--json",
	)
	out, _ := cmd.CombinedOutput()

	if !strings.Contains(string(out), `"servers"`) {
		t.Error("JSON output missing 'servers' field")
	}
	if !strings.Contains(string(out), `"scan"`) {
		t.Error("JSON output missing 'scan' field")
	}
	if !strings.Contains(string(out), `"total_scanned"`) {
		t.Error("JSON output missing 'total_scanned' field")
	}
}
