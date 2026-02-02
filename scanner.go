package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const probeDomain = "google.com"

// ScanResult holds the outcome of probing a single DNS server.
type ScanResult struct {
	IP         string
	Working    bool
	Suspicious bool // true if server returned private IP (possible hijacking)
	RTT        time.Duration
	Error      error
}

// Scanner probes DNS servers for availability and hijacking detection.
type Scanner struct {
	workers      int
	timeout      time.Duration
	port         int
	progress     *Progress
	verifyDomain string
}

func NewScanner(workers int, timeout time.Duration, port int, progress *Progress, verifyDomain string) *Scanner {
	if port == 0 {
		port = 53
	}
	return &Scanner{
		workers:      workers,
		timeout:      timeout,
		port:         port,
		progress:     progress,
		verifyDomain: verifyDomain,
	}
}

// Probe tests a single IP for DNS availability.
func (s *Scanner) Probe(ip string) ScanResult {
	client := &dns.Client{
		Net:         "udp",
		Timeout:     s.timeout,
		ReadTimeout: s.timeout,
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(probeDomain), dns.TypeA)
	m.RecursionDesired = true

	addr := fmt.Sprintf("%s:%d", ip, s.port)
	reply, rtt, err := client.Exchange(m, addr)
	if err != nil {
		return ScanResult{IP: ip, Working: false, Error: err}
	}

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

	if s.verifyDomain != "" {
		testDomain := randomSubdomain() + "." + s.verifyDomain

		m2 := new(dns.Msg)
		m2.SetQuestion(dns.Fqdn(testDomain), dns.TypeTXT)
		m2.RecursionDesired = true
		m2.SetEdns0(EDNSBufferSize, false)

		reply2, rtt2, err := client.Exchange(m2, addr)
		if err != nil {
			return ScanResult{IP: ip, Working: false, Error: err}
		}

		if reply2 != nil {
			return ScanResult{IP: ip, Working: true, RTT: rtt2}
		}
		return ScanResult{IP: ip, Working: false}
	}

	return ScanResult{IP: ip, Working: true, RTT: rtt}
}

// Run starts a worker pool that probes IPs concurrently.
func (s *Scanner) Run(ctx context.Context, ips <-chan string) <-chan ScanResult {
	results := make(chan ScanResult, s.workers)
	var wg sync.WaitGroup

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
							s.progress.Success()
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

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

var privateRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"100.64.0.0/10",
	"0.0.0.0/8",
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func randomSubdomain() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
