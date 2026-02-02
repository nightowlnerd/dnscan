package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	BenchmarkQueries      = 20
	BenchmarkConcurrency  = 5
	BenchmarkThreshold   = 70
	BenchmarkSubdomainLen = 32
	EDNSBufferSize        = 1232 // matches slipstream UDP payload
)

type BenchmarkResult struct {
	IP         string
	Queries    int
	Successful int
	Failed     int
	Latencies  []time.Duration
	Duration   time.Duration
}

func (r *BenchmarkResult) SuccessRate() float64 {
	if r.Queries == 0 {
		return 0
	}
	return float64(r.Successful) / float64(r.Queries) * 100
}

func (r *BenchmarkResult) QPS() float64 {
	if r.Duration == 0 {
		return 0
	}
	return float64(r.Successful) / r.Duration.Seconds()
}

func (r *BenchmarkResult) P50() time.Duration {
	return r.percentile(50)
}

func (r *BenchmarkResult) percentile(p int) time.Duration {
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

func (r *BenchmarkResult) Passed() bool {
	return r.SuccessRate() >= BenchmarkThreshold
}

func randomBenchmarkSubdomain() string {
	b := make([]byte, BenchmarkSubdomainLen)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// Benchmark runs concurrent DNS queries to test server reliability under load
func Benchmark(ctx context.Context, ip, domain string, port int, timeout time.Duration) *BenchmarkResult {
	if port == 0 {
		port = 53
	}
	addr := fmt.Sprintf("%s:%d", ip, port)

	result := &BenchmarkResult{
		IP:      ip,
		Queries: BenchmarkQueries,
	}

	client := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, BenchmarkConcurrency)

	start := time.Now()

	for i := 0; i < BenchmarkQueries; i++ {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				mu.Lock()
				result.Failed++
				mu.Unlock()
				return
			default:
			}

			subdomain := randomBenchmarkSubdomain()
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(subdomain+"."+domain), dns.TypeTXT)
			m.RecursionDesired = true
			m.SetEdns0(EDNSBufferSize, false)

			_, rtt, err := client.Exchange(m, addr)

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

// BenchmarkParallel runs benchmarks on multiple IPs concurrently
func BenchmarkParallel(ctx context.Context, ips []string, domain string, port int,
	timeout time.Duration, workers int) <-chan *BenchmarkResult {

	results := make(chan *BenchmarkResult, workers)
	ipChan := make(chan string, len(ips))

	go func() {
		defer close(ipChan)
		for _, ip := range ips {
			select {
			case ipChan <- ip:
			case <-ctx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-ipChan:
					if !ok {
						return
					}
					result := Benchmark(ctx, ip, domain, port, timeout)
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
