package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const probeDomain = "google.com"

type ScanResult struct {
	IP         string
	Working    bool
	Suspicious bool
	RTT        time.Duration
	Error      error
}

type Scanner struct {
	workers      int
	timeout      time.Duration
	port         int
	verifyDomain string
	total        int
	output       io.Writer
	showProgress bool
}

func NewScanner(workers int, timeout time.Duration, port int, verifyDomain string, total int, output io.Writer, showProgress bool) *Scanner {
	if port == 0 {
		port = 53
	}
	return &Scanner{
		workers:      workers,
		timeout:      timeout,
		port:         port,
		verifyDomain: verifyDomain,
		total:        total,
		output:       output,
		showProgress: showProgress,
	}
}

func (s *Scanner) Scan(ctx context.Context, ips <-chan string) []string {
	prog := NewProgress(s.total, s.showProgress)

	tickCtx, stopTick := context.WithCancel(ctx)
	go s.tick(tickCtx, prog)

	var working []string
	var suspicious int
	for result := range s.run(ctx, ips, prog) {
		if result.Suspicious {
			suspicious++
		}
		if result.Working {
			working = append(working, result.IP)
		}
	}

	stopTick()
	s.summary(prog, suspicious)
	return working
}

func (s *Scanner) tick(ctx context.Context, prog *Progress) {
	if !s.showProgress || s.output == nil {
		return
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			st := prog.Stats()
			rate := float64(st.Processed) / st.Elapsed.Seconds()
			pct := float64(st.Processed) / float64(st.Total) * 100
			fmt.Fprintf(s.output, "\rScanned: %d/%d (%.1f%%) | Found: %d | %.0f IPs/sec   ",
				st.Processed, st.Total, pct, st.Success, rate)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Scanner) summary(prog *Progress, suspicious int) {
	if !s.showProgress || s.output == nil {
		return
	}
	st := prog.Stats()
	rate := float64(st.Processed) / st.Elapsed.Seconds()
	fmt.Fprintf(s.output, "\r\033[1;32mScan: %d/%d | Found: %d | %.0f IPs/sec | %v\033[0m          \n",
		st.Processed, st.Total, st.Success, rate, st.Elapsed.Round(time.Millisecond))
	if suspicious > 0 {
		fmt.Fprintf(s.output, "\033[33mWarning: %d servers returned private IPs (possible DNS hijacking)\033[0m\n", suspicious)
	}
}

func (s *Scanner) run(ctx context.Context, ips <-chan string, prog *Progress) <-chan ScanResult {
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
					result := s.probe(ip)
					prog.Increment()
					if result.Working {
						prog.Success()
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

func (s *Scanner) probe(ip string) ScanResult {
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
