package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DataDir is the directory containing ranges and dns files
var DataDir = "data"

// LoadRanges loads IP ranges from data/ranges/<country>.zone
func LoadRanges(country string) ([]string, error) {
	path := filepath.Join(DataDir, "ranges", country+".zone")
	return loadLines(path)
}

// LoadDNSList loads known DNS servers from data/dns/<country>.txt
func LoadDNSList(country string) ([]string, error) {
	path := filepath.Join(DataDir, "dns", country+".txt")
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

// AvailableCountries returns list of countries with range files
func AvailableCountries() []string {
	rangesDir := filepath.Join(DataDir, "ranges")
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
