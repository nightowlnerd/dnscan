package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCIDRBlocks(t *testing.T) {
	if !CIDRBlocksExist("data", "ir") {
		if err := DownloadCIDRBlocks("data", "ir"); err != nil {
			t.Fatalf("DownloadCIDRBlocks failed: %v", err)
		}
	}
	ranges, err := LoadCIDRBlocks("data", "ir")
	if err != nil {
		t.Fatalf("LoadCIDRBlocks failed: %v", err)
	}
	if len(ranges) == 0 {
		t.Error("Expected non-empty ranges")
	}
	if ranges[0] == "" {
		t.Error("First range is empty")
	}
}

func TestLoadKnownDNS(t *testing.T) {
	dns, err := LoadKnownDNS("data", "ir")
	if err != nil {
		t.Fatalf("LoadKnownDNS failed: %v", err)
	}
	if len(dns) == 0 {
		t.Error("Expected non-empty DNS list")
	}
	// Check known working DNS is in list
	found := false
	for _, ip := range dns {
		if ip == "185.8.174.140" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 185.8.174.140 in DNS list")
	}
}

func TestDownloadCIDRBlocksInvalidCountry(t *testing.T) {
	err := DownloadCIDRBlocks("data", "xx")
	if err == nil {
		t.Error("Expected error for invalid country")
	}
}

func TestAvailableCountries(t *testing.T) {
	countries := AvailableCountries("data")
	if len(countries) == 0 {
		t.Error("Expected at least one country")
	}
	// Check ir is available
	found := false
	for _, c := range countries {
		if c == "ir" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'ir' in available countries")
	}
}

func TestLoadLinesSkipsComments(t *testing.T) {
	// Create temp file with comments
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := `# comment
192.168.1.1
# another comment
10.0.0.1
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	lines, err := loadLines(path)
	if err != nil {
		t.Fatalf("loadLines failed: %v", err)
	}
	if len(lines) != 2 {
		t.Errorf("Expected 2 lines, got %d", len(lines))
	}
}
