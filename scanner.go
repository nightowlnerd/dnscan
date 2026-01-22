package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// randomSubdomain generates a random subdomain prefix
func randomSubdomain() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ScanResult holds the result of a DNS probe
type ScanResult struct {
	IP      string
	Working bool
	RTT     time.Duration
	Error   error
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
