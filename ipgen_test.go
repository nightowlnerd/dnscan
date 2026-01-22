package main

import (
	"testing"
)

func TestExpandRangesWithModeFast(t *testing.T) {
	ranges := []string{"192.168.1.0/24"}
	ips := ExpandRangesWithMode(ranges, "fast")

	var result []string
	for ip := range ips {
		result = append(result, ip)
	}

	if len(result) != 3 {
		t.Errorf("Fast mode: expected 3 IPs, got %d: %v", len(result), result)
	}

	// Check expected IPs are present
	expected := map[string]bool{
		"192.168.1.1":   false,
		"192.168.1.53":  false,
		"192.168.1.254": false,
	}
	for _, ip := range result {
		expected[ip] = true
	}
	for ip, found := range expected {
		if !found {
			t.Errorf("Fast mode: missing expected IP %s, got %v", ip, result)
		}
	}
}

func TestExpandRangesWithModeMedium(t *testing.T) {
	ranges := []string{"192.168.1.0/24"}
	ips := ExpandRangesWithMode(ranges, "medium")

	var count int
	for range ips {
		count++
	}

	if count != 7 {
		t.Errorf("Medium mode: expected 7 IPs, got %d", count)
	}
}

func TestExpandRangesWithModeAll(t *testing.T) {
	ranges := []string{"192.168.1.0/24"}
	ips := ExpandRangesWithMode(ranges, "all")

	var count int
	for range ips {
		count++
	}

	if count != 254 {
		t.Errorf("All mode: expected 254 IPs, got %d", count)
	}
}

func TestExpandRangesWithMode16(t *testing.T) {
	ranges := []string{"10.0.0.0/16"}

	// Fast mode on /16 should give 3 IPs * 256 subnets = 768
	ips := ExpandRangesWithMode(ranges, "fast")
	var count int
	for range ips {
		count++
	}

	expected := 3 * 256
	if count != expected {
		t.Errorf("/16 fast mode: expected %d IPs, got %d", expected, count)
	}
}

func TestCountIPsWithMode(t *testing.T) {
	ranges := []string{"192.168.1.0/24"}

	tests := []struct {
		mode     string
		expected int
	}{
		{"fast", 3},
		{"medium", 7},
		{"all", 254},
	}

	for _, tt := range tests {
		count := CountIPsWithMode(ranges, tt.mode)
		if count != tt.expected {
			t.Errorf("CountIPsWithMode(%s): expected %d, got %d", tt.mode, tt.expected, count)
		}
	}
}

func TestIPsFromList(t *testing.T) {
	input := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	ips := IPsFromList(input)

	var result []string
	for ip := range ips {
		result = append(result, ip)
	}

	if len(result) != len(input) {
		t.Errorf("Expected %d IPs, got %d", len(input), len(result))
	}
}

func TestInvalidCIDR(t *testing.T) {
	ranges := []string{"invalid-cidr"}
	ips := ExpandRangesWithMode(ranges, "fast")

	var count int
	for range ips {
		count++
	}

	if count != 0 {
		t.Errorf("Invalid CIDR: expected 0 IPs, got %d", count)
	}
}
