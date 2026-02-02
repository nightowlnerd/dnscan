package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const ipDenyURL = "https://www.ipdeny.com/ipblocks/data/aggregated/%s-aggregated.zone"

func LoadRanges(dataDir, country string) ([]string, error) {
	path := filepath.Join(dataDir, "ranges", country+".zone")

	// Check if file exists, download if not
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Downloading IP ranges for %s...\n", country)
		if err := downloadRanges(country, path); err != nil {
			return nil, fmt.Errorf("failed to download ranges for %s: %w", country, err)
		}
	}

	return loadLines(path)
}

// downloadRanges fetches IP ranges from ipdeny.com
func downloadRanges(country, destPath string) error {
	url := fmt.Sprintf(ipDenyURL, country)

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d - country '%s' may not exist", resp.StatusCode, country)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func LoadDNSList(dataDir, country string) ([]string, error) {
	path := filepath.Join(dataDir, "dns", country+".txt")
	return loadLines(path)
}

// loadLines reads non-empty, non-comment lines from a file
func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	return lines, nil
}

func AvailableCountries(dataDir string) []string {
	rangesDir := filepath.Join(dataDir, "ranges")
	entries, err := os.ReadDir(rangesDir)
	if err != nil {
		return nil
	}

	var countries []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".zone") {
			country := strings.TrimSuffix(e.Name(), ".zone")
			countries = append(countries, country)
		}
	}
	return countries
}
