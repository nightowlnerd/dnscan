package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Burst test parameters - tune these for accuracy vs speed tradeoff
const (
	BurstQueries      = 20 // Number of queries per burst test
	BurstConcurrency  = 5  // Concurrent queries during burst
	BurstMinSuccess   = 70 // Minimum success rate % to pass
	BurstSubdomainLen = 32 // Bytes for random subdomain (32 = ~52 base32 chars)
)

// randomSubdomain generates a random subdomain prefix
func randomSubdomain() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// randomSlipstreamSubdomain generates a subdomain similar to slipstream's Base32 encoding
func randomSlipstreamSubdomain() string {
	b := make([]byte, BurstSubdomainLen)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// ScanResult holds the result of a DNS probe
type ScanResult struct {
	IP         string
	Working    bool
	Suspicious bool
	RTT        time.Duration
	Error      error
}

// isPrivateIP detects DNS hijacking by checking if response IPs are in reserved ranges
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",     // Common in corporate/ISP hijacking
		"172.16.0.0/12",  // Often used by captive portals
		"192.168.0.0/16", // Home routers sometimes hijack DNS
		"127.0.0.0/8",    // Loopback, used to block domains
		"169.254.0.0/16", // Link-local, indicates broken resolution
		"100.64.0.0/10",  // CGNAT, ISP-level interception
		"0.0.0.0/8",      // Invalid, used to sink traffic
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Scanner manages the worker pool for DNS probing
type Scanner struct {
	workers      int
	timeout      time.Duration
	progress     *Progress
	verifyDomain string // If set, verify this domain can be resolved (for slipstream)
}

// Progress tracks scanning progress
type Progress struct {
	total     int64
	scanned   int64
	found     int64
	startTime time.Time
	enabled   bool
	mu        sync.Mutex
}

// NewProgress creates a new progress tracker
func NewProgress(total int, enabled bool) *Progress {
	return &Progress{
		total:     int64(total),
		startTime: time.Now(),
		enabled:   enabled,
	}
}

// Increment marks one IP as scanned
func (p *Progress) Increment() {
	atomic.AddInt64(&p.scanned, 1)
}

// Found marks a working DNS found
func (p *Progress) Found() {
	atomic.AddInt64(&p.found, 1)
}

// Stats returns current stats
func (p *Progress) Stats() (scanned, found, total int64, elapsed time.Duration) {
	return atomic.LoadInt64(&p.scanned),
		atomic.LoadInt64(&p.found),
		p.total,
		time.Since(p.startTime)
}

// NewScanner creates a new scanner with given workers and timeout
func NewScanner(workers int, timeout time.Duration, progress *Progress, verifyDomain string) *Scanner {
	return &Scanner{
		workers:      workers,
		timeout:      timeout,
		progress:     progress,
		verifyDomain: verifyDomain,
	}
}

// Probe tests if an IP is a working DNS server
func (s *Scanner) Probe(ip string) ScanResult {
	client := &dns.Client{
		Net:         "udp",
		Timeout:     s.timeout,
		ReadTimeout: s.timeout,
	}

	// First test: can it resolve google.com?
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)
	m.RecursionDesired = true

	reply, rtt, err := client.Exchange(m, ip+":53")
	if err != nil {
		return ScanResult{IP: ip, Working: false, Error: err}
	}

	// Check for valid response with actual answer
	if reply == nil || reply.Rcode != dns.RcodeSuccess || len(reply.Answer) == 0 {
		return ScanResult{IP: ip, Working: false}
	}

	for _, ans := range reply.Answer {
		if a, ok := ans.(*dns.A); ok {
			if isPrivateIP(a.A) {
				return ScanResult{IP: ip, Working: false, Suspicious: true}
			}
		}
	}

	// If verify domain is set, check if query reaches our authoritative server
	// Slipstream uses TXT records exclusively, so test with TXT
	// Any response (NXDOMAIN, NOERROR, etc.) = query reached server
	// Only timeout/error = didn't reach
	if s.verifyDomain != "" {
		// Use random subdomain to avoid DNS caching
		testDomain := randomSubdomain() + "." + s.verifyDomain

		m2 := new(dns.Msg)
		m2.SetQuestion(dns.Fqdn(testDomain), dns.TypeTXT)
		m2.RecursionDesired = true
		// Set EDNS0 with 1232 byte UDP payload (matches slipstream)
		m2.SetEdns0(1232, false)

		reply2, rtt2, err := client.Exchange(m2, ip+":53")
		if err != nil {
			return ScanResult{IP: ip, Working: false, Error: err}
		}

		// Any response = query reached our authoritative server
		if reply2 != nil {
			return ScanResult{IP: ip, Working: true, RTT: rtt2}
		}
		return ScanResult{IP: ip, Working: false}
	}

	return ScanResult{IP: ip, Working: true, RTT: rtt}
}

// Run starts the scanner with a worker pool
func (s *Scanner) Run(ctx context.Context, ips <-chan string) <-chan ScanResult {
	results := make(chan ScanResult, s.workers)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-ips:
					if !ok {
						return
					}
					result := s.Probe(ip)
					if s.progress != nil {
						s.progress.Increment()
						if result.Working {
							s.progress.Found()
						}
					}
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

// BurstResult holds results from a burst test
type BurstResult struct {
	IP         string
	Queries    int
	Successful int
	Failed     int
	Latencies  []time.Duration
	Duration   time.Duration
}

// SuccessRate returns percentage of successful queries
func (r *BurstResult) SuccessRate() float64 {
	if r.Queries == 0 {
		return 0
	}
	return float64(r.Successful) / float64(r.Queries) * 100
}

// QPS returns queries per second
func (r *BurstResult) QPS() float64 {
	if r.Duration == 0 {
		return 0
	}
	return float64(r.Successful) / r.Duration.Seconds()
}

// P50 returns median latency
func (r *BurstResult) P50() time.Duration {
	return r.percentile(50)
}

func (r *BurstResult) percentile(p int) time.Duration {
	if len(r.Latencies) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(r.Latencies))
	copy(sorted, r.Latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := len(sorted) * p / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// Passed returns true if burst test meets minimum success rate
func (r *BurstResult) Passed() bool {
	return r.SuccessRate() >= BurstMinSuccess
}

// BurstTest runs concurrent DNS queries to test server reliability under load
func BurstTest(ip, domain string, timeout time.Duration) *BurstResult {
	result := &BurstResult{
		IP:      ip,
		Queries: BurstQueries,
	}

	client := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, BurstConcurrency)

	start := time.Now()

	for i := 0; i < BurstQueries; i++ {
		wg.Add(1)
		sem <- struct{}{}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			subdomain := randomSlipstreamSubdomain()
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(subdomain+"."+domain), dns.TypeTXT)
			m.RecursionDesired = true
			m.SetEdns0(1232, false)

			_, rtt, err := client.Exchange(m, ip+":53")

			mu.Lock()
			if err != nil {
				result.Failed++
			} else {
				result.Successful++
				result.Latencies = append(result.Latencies, rtt)
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	result.Duration = time.Since(start)
	return result
}
