package main

import (
	"net"
	"testing"
	"time"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
		desc     string
	}{
		// Private ranges - should be detected
		{"10.0.0.1", true, "10.x.x.x (RFC 1918)"},
		{"10.255.255.255", true, "10.x.x.x upper bound"},
		{"172.16.0.1", true, "172.16.x.x (RFC 1918)"},
		{"172.31.255.255", true, "172.31.x.x upper bound"},
		{"192.168.0.1", true, "192.168.x.x (RFC 1918)"},
		{"192.168.255.255", true, "192.168.x.x upper bound"},
		{"127.0.0.1", true, "loopback"},
		{"169.254.1.1", true, "link-local"},
		{"100.64.0.1", true, "CGNAT"},
		{"100.127.255.255", true, "CGNAT upper bound"},
		{"0.0.0.0", true, "zero address"},

		// Public IPs - should not be detected
		{"8.8.8.8", false, "Google DNS"},
		{"1.1.1.1", false, "Cloudflare DNS"},
		{"185.8.174.140", false, "Iranian DNS"},
		{"172.15.255.255", false, "just below 172.16.0.0"},
		{"172.32.0.0", false, "just above 172.31.255.255"},
		{"100.63.255.255", false, "just below CGNAT"},
		{"100.128.0.0", false, "just above CGNAT"},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		result := isPrivateIP(ip)
		if result != tt.expected {
			t.Errorf("isPrivateIP(%s) = %v, expected %v (%s)",
				tt.ip, result, tt.expected, tt.desc)
		}
	}
}

func TestIsPrivateIPNil(t *testing.T) {
	if isPrivateIP(nil) {
		t.Error("isPrivateIP(nil) should return false")
	}
}

func TestRandomSubdomain(t *testing.T) {
	s1 := randomSubdomain()
	s2 := randomSubdomain()

	// Should be hex encoded (16 chars for 8 bytes)
	if len(s1) != 16 {
		t.Errorf("randomSubdomain length = %d, expected 16", len(s1))
	}

	// Should be different each time
	if s1 == s2 {
		t.Error("randomSubdomain should generate unique values")
	}
}

func TestRandomSlipstreamSubdomain(t *testing.T) {
	s1 := randomSlipstreamSubdomain()
	s2 := randomSlipstreamSubdomain()

	// Base32 encoded 32 bytes = 52 chars
	if len(s1) != 52 {
		t.Errorf("randomSlipstreamSubdomain length = %d, expected 52", len(s1))
	}

	// Should be different each time
	if s1 == s2 {
		t.Error("randomSlipstreamSubdomain should generate unique values")
	}
}

func TestBurstResultSuccessRate(t *testing.T) {
	tests := []struct {
		queries    int
		successful int
		expected   float64
	}{
		{20, 20, 100.0},
		{20, 10, 50.0},
		{20, 0, 0.0},
		{0, 0, 0.0},
	}

	for _, tt := range tests {
		r := &BurstResult{
			Queries:    tt.queries,
			Successful: tt.successful,
		}
		if r.SuccessRate() != tt.expected {
			t.Errorf("SuccessRate(%d/%d) = %.1f, expected %.1f",
				tt.successful, tt.queries, r.SuccessRate(), tt.expected)
		}
	}
}

func TestBurstResultQPS(t *testing.T) {
	r := &BurstResult{
		Successful: 10,
		Duration:   time.Second,
	}
	if r.QPS() != 10.0 {
		t.Errorf("QPS = %.1f, expected 10.0", r.QPS())
	}

	// Zero duration edge case
	r2 := &BurstResult{Duration: 0}
	if r2.QPS() != 0.0 {
		t.Error("QPS with zero duration should be 0")
	}
}

func TestBurstResultP50(t *testing.T) {
	r := &BurstResult{
		Latencies: []time.Duration{
			10 * time.Millisecond,
			20 * time.Millisecond,
			30 * time.Millisecond,
			40 * time.Millisecond,
			50 * time.Millisecond,
		},
	}

	p50 := r.P50()
	if p50 != 30*time.Millisecond {
		t.Errorf("P50 = %v, expected 30ms", p50)
	}

	// Empty latencies
	r2 := &BurstResult{}
	if r2.P50() != 0 {
		t.Error("P50 with no latencies should be 0")
	}
}

func TestBurstResultPassed(t *testing.T) {
	tests := []struct {
		queries    int
		successful int
		expected   bool
	}{
		{20, 14, true},  // 70% exactly
		{20, 15, true},  // 75%
		{20, 13, false}, // 65%
		{20, 0, false},  // 0%
	}

	for _, tt := range tests {
		r := &BurstResult{
			Queries:    tt.queries,
			Successful: tt.successful,
		}
		if r.Passed() != tt.expected {
			t.Errorf("Passed(%d/%d = %.0f%%) = %v, expected %v",
				tt.successful, tt.queries, r.SuccessRate(), r.Passed(), tt.expected)
		}
	}
}

func TestProgressStats(t *testing.T) {
	p := NewProgress(100, true)

	p.Increment()
	p.Increment()
	p.Found()

	scanned, found, total, elapsed := p.Stats()
	if scanned != 2 {
		t.Errorf("scanned = %d, expected 2", scanned)
	}
	if found != 1 {
		t.Errorf("found = %d, expected 1", found)
	}
	if total != 100 {
		t.Errorf("total = %d, expected 100", total)
	}
	if elapsed < 0 {
		t.Error("elapsed should not be negative")
	}
}
