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

func CIDRBlocksExist(dataDir, country string) bool {
	path := filepath.Join(dataDir, "ranges", country+".zone")
	_, err := os.Stat(path)
	return err == nil
}

func DownloadCIDRBlocks(dataDir, country string) error {
	fmt.Fprintf(os.Stderr, "Downloading IP ranges for %s...\n", country)

	data, err := fetchRanges(country)
	if err != nil {
		return fmt.Errorf("failed to download ranges for %s: %w", country, err)
	}
	defer data.Close()

	path := filepath.Join(dataDir, "ranges", country+".zone")
	if err := saveToFile(path, data); err != nil {
		return fmt.Errorf("failed to save ranges for %s: %w", country, err)
	}
	return nil
}

func LoadCIDRBlocks(dataDir, country string) ([]string, error) {
	path := filepath.Join(dataDir, "ranges", country+".zone")
	return loadLines(path)
}

func LoadKnownDNS(dataDir, country string) ([]string, error) {
	path := filepath.Join(dataDir, "dns", country+".txt")
	return loadLines(path)
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

func fetchRanges(country string) (io.ReadCloser, error) {
	url := fmt.Sprintf(ipDenyURL, country)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d - country '%s' may not exist", resp.StatusCode, country)
	}

	return resp.Body, nil
}

func saveToFile(path string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, r)
	return err
}

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
