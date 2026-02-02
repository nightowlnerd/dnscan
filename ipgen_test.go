package main

import (
	"testing"
)

func TestExpandCIDRFast(t *testing.T) {
	blocks := []string{"192.168.1.0/24"}
	ips := ExpandCIDR(blocks, "fast")

	var result []string
	for ip := range ips {
		result = append(result, ip)
	}

	if len(result) != 3 {
		t.Errorf("Fast mode: expected 3 IPs, got %d: %v", len(result), result)
	}

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

func TestExpandCIDRMedium(t *testing.T) {
	blocks := []string{"192.168.1.0/24"}
	ips := ExpandCIDR(blocks, "medium")

	var count int
	for range ips {
		count++
	}

	if count != 7 {
		t.Errorf("Medium mode: expected 7 IPs, got %d", count)
	}
}

func TestExpandCIDRAll(t *testing.T) {
	blocks := []string{"192.168.1.0/24"}
	ips := ExpandCIDR(blocks, "all")

	var count int
	for range ips {
		count++
	}

	if count != 254 {
		t.Errorf("All mode: expected 254 IPs, got %d", count)
	}
}

func TestExpandCIDR16(t *testing.T) {
	blocks := []string{"10.0.0.0/16"}

	ips := ExpandCIDR(blocks, "fast")
	var count int
	for range ips {
		count++
	}

	expected := 3 * 256
	if count != expected {
		t.Errorf("/16 fast mode: expected %d IPs, got %d", expected, count)
	}
}

func TestCountCIDRIPs(t *testing.T) {
	blocks := []string{"192.168.1.0/24"}

	tests := []struct {
		mode     string
		expected int
	}{
		{"fast", 3},
		{"medium", 7},
		{"all", 254},
	}

	for _, tt := range tests {
		count := CountCIDRIPs(blocks, tt.mode)
		if count != tt.expected {
			t.Errorf("CountCIDRIPs(%s): expected %d, got %d", tt.mode, tt.expected, count)
		}
	}
}

func TestInvalidCIDR(t *testing.T) {
	blocks := []string{"invalid-cidr"}
	ips := ExpandCIDR(blocks, "fast")

	var count int
	for range ips {
		count++
	}

	if count != 0 {
		t.Errorf("Invalid CIDR: expected 0 IPs, got %d", count)
	}
}
