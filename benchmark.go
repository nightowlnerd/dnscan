package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	BenchmarkQueries      = 20
	BenchmarkConcurrency  = 5
	BenchmarkThreshold    = 70
	BenchmarkSubdomainLen = 32
	EDNSBufferSize        = 1232
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

type Benchmarker struct {
	domain       string
	port         int
	timeout      time.Duration
	output       io.Writer
	showProgress bool
}

func NewBenchmarker(domain string, port int, timeout time.Duration, output io.Writer, showProgress bool) *Benchmarker {
	if port == 0 {
		port = 53
	}
	return &Benchmarker{
		domain:       domain,
		port:         port,
		timeout:      timeout,
		output:       output,
		showProgress: showProgress,
	}
}

func (b *Benchmarker) Benchmark(ctx context.Context, ips []string) []*BenchmarkResult {
	if len(ips) == 0 {
		return nil
	}

	prog := NewProgress(len(ips), b.showProgress)

	tickCtx, stopTick := context.WithCancel(ctx)
	defer stopTick()
	go b.tick(tickCtx, prog)

	var results []*BenchmarkResult
	if len(ips) <= 5 {
		results = b.sequential(ctx, ips, prog)
	} else {
		results = b.parallel(ctx, ips, prog)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].QPS() > results[j].QPS()
	})

	b.summary(results, len(ips))
	return results
}

func (b *Benchmarker) tick(ctx context.Context, prog *Progress) {
	if !b.showProgress || b.output == nil {
		return
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			st := prog.Stats()
			fmt.Fprintf(b.output, "\rBenchmarking: %d/%d tested, %d passed   ",
				st.Processed, st.Total, st.Success)
		case <-ctx.Done():
			fmt.Fprint(b.output, "\r\033[K")
			return
		}
	}
}

func (b *Benchmarker) summary(results []*BenchmarkResult, total int) {
	if !b.showProgress || b.output == nil {
		return
	}
	fmt.Fprintf(b.output, "Benchmark: %d/%d passed (sorted by throughput)\n", len(results), total)
	for _, r := range results {
		color := "\033[33m"
		if r.SuccessRate() >= 85 {
			color = "\033[32m"
		}
		fmt.Fprintf(b.output, "%s%-15s %.0f%% (%.1f qps, p50=%v)\033[0m\n",
			color, r.IP, r.SuccessRate(), r.QPS(), r.P50().Round(time.Millisecond))
	}
}

func (b *Benchmarker) sequential(ctx context.Context, ips []string, prog *Progress) []*BenchmarkResult {
	var results []*BenchmarkResult
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		result := b.benchmark(ctx, ip)
		prog.Increment()
		if result.Passed() {
			prog.Success()
			results = append(results, result)
		}
	}
	return results
}

func (b *Benchmarker) parallel(ctx context.Context, ips []string, prog *Progress) []*BenchmarkResult {
	workers := min(len(ips), 10)

	resultChan := make(chan *BenchmarkResult, workers)
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
					result := b.benchmark(ctx, ip)
					select {
					case resultChan <- result:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var results []*BenchmarkResult
	for result := range resultChan {
		prog.Increment()
		if result.Passed() {
			prog.Success()
			results = append(results, result)
		}
	}
	return results
}

func (b *Benchmarker) benchmark(ctx context.Context, ip string) *BenchmarkResult {
	addr := fmt.Sprintf("%s:%d", ip, b.port)

	result := &BenchmarkResult{
		IP:      ip,
		Queries: BenchmarkQueries,
	}

	client := &dns.Client{
		Net:     "udp",
		Timeout: b.timeout,
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
			m.SetQuestion(dns.Fqdn(subdomain+"."+b.domain), dns.TypeTXT)
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

func randomBenchmarkSubdomain() string {
	b := make([]byte, BenchmarkSubdomainLen)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
