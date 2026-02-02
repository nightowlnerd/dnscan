package main

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type mockDNSServer struct {
	server   *dns.Server
	addr     string
	ip       string
	port     int
	response net.IP
}

func newMockDNSServer(responseIP string) (*mockDNSServer, error) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	addr := conn.LocalAddr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	mock := &mockDNSServer{
		addr:     addr,
		ip:       host,
		port:     port,
		response: net.ParseIP(responseIP),
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", mock.handleQuery)

	mock.server = &dns.Server{
		PacketConn: conn,
		Handler:    mux,
	}

	go mock.server.ActivateAndServe()
	time.Sleep(50 * time.Millisecond)

	return mock, nil
}

func (m *mockDNSServer) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA:
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   m.response,
			})
		case dns.TypeTXT:
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"mock"},
			})
		}
	}

	w.WriteMsg(msg)
}

func (m *mockDNSServer) Close() {
	if m.server != nil {
		m.server.Shutdown()
	}
}

func TestE2EBasicScan(t *testing.T) {
	mock, err := newMockDNSServer("93.184.216.34")
	if err != nil {
		t.Fatalf("Failed to start mock DNS: %v", err)
	}
	defer mock.Close()

	scanner := NewScanner(1, 2*time.Second, mock.port, nil, "")
	result := scanner.Probe(mock.ip)

	if !result.Working {
		t.Errorf("Expected working, got error: %v", result.Error)
	}
	if result.Suspicious {
		t.Error("Public IP should not be suspicious")
	}
}

func TestE2EHijackingDetection(t *testing.T) {
	mock, err := newMockDNSServer("10.10.34.34")
	if err != nil {
		t.Fatalf("Failed to start mock DNS: %v", err)
	}
	defer mock.Close()

	scanner := NewScanner(1, 2*time.Second, mock.port, nil, "")
	result := scanner.Probe(mock.ip)

	if result.Working {
		t.Error("Private IP response should not be working")
	}
	if !result.Suspicious {
		t.Error("Private IP response should be suspicious")
	}
}

func TestE2EDomainVerification(t *testing.T) {
	mock, err := newMockDNSServer("93.184.216.34")
	if err != nil {
		t.Fatalf("Failed to start mock DNS: %v", err)
	}
	defer mock.Close()

	scanner := NewScanner(1, 2*time.Second, mock.port, nil, "test.example.com")
	result := scanner.Probe(mock.ip)

	if !result.Working {
		t.Errorf("Domain verification should pass, got: %v", result.Error)
	}
}

func TestE2EBenchmark(t *testing.T) {
	mock, err := newMockDNSServer("93.184.216.34")
	if err != nil {
		t.Fatalf("Failed to start mock DNS: %v", err)
	}
	defer mock.Close()

	result := Benchmark(context.Background(), mock.ip, "test.example.com", mock.port, 2*time.Second)

	if result.Queries != BenchmarkQueries {
		t.Errorf("Expected %d queries, got %d", BenchmarkQueries, result.Queries)
	}
	if result.SuccessRate() < 90 {
		t.Errorf("Expected high success rate, got %.1f%%", result.SuccessRate())
	}
	if !result.Passed() {
		t.Errorf("Should pass burst test, got %.1f%%", result.SuccessRate())
	}
}

func TestE2EWorkerPool(t *testing.T) {
	mock, err := newMockDNSServer("93.184.216.34")
	if err != nil {
		t.Fatalf("Failed to start mock DNS: %v", err)
	}
	defer mock.Close()

	ips := []string{mock.ip, "192.0.2.1"} // second IP won't respond
	progress := NewProgress(len(ips), false)
	scanner := NewScanner(2, 500*time.Millisecond, mock.port, progress, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results := scanner.Run(ctx, sliceToChannel(ips))

	var working, total int
	for r := range results {
		total++
		if r.Working {
			working++
		}
	}

	if total != 2 {
		t.Errorf("Expected 2 results, got %d", total)
	}
	if working != 1 {
		t.Errorf("Expected 1 working, got %d", working)
	}
}

func TestE2EAllPrivateRanges(t *testing.T) {
	privateIPs := []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1"}

	for _, ip := range privateIPs {
		mock, err := newMockDNSServer(ip)
		if err != nil {
			t.Fatalf("Failed for %s: %v", ip, err)
		}

		scanner := NewScanner(1, 2*time.Second, mock.port, nil, "")
		result := scanner.Probe(mock.ip)
		mock.Close()

		if result.Working {
			t.Errorf("%s should not be working", ip)
		}
		if !result.Suspicious {
			t.Errorf("%s should be suspicious", ip)
		}
	}
}

func TestE2ETimeout(t *testing.T) {
	scanner := NewScanner(1, 100*time.Millisecond, 65534, nil, "")
	result := scanner.Probe("127.0.0.1")

	if result.Working {
		t.Error("Non-responsive should not be working")
	}
	if result.Error == nil {
		t.Error("Expected timeout error")
	}
}

func TestE2EProgressTracking(t *testing.T) {
	mock, err := newMockDNSServer("93.184.216.34")
	if err != nil {
		t.Fatalf("Failed to start mock DNS: %v", err)
	}
	defer mock.Close()

	ips := []string{mock.ip, mock.ip, mock.ip}
	progress := NewProgress(len(ips), false)
	scanner := NewScanner(1, 2*time.Second, mock.port, progress, "")

	results := scanner.Run(context.Background(), sliceToChannel(ips))
	for range results {
	}

	stats := progress.Stats()
	if stats.Processed != 3 || stats.Success != 3 || stats.Total != 3 {
		t.Errorf("Progress mismatch: processed=%d success=%d total=%d", stats.Processed, stats.Success, stats.Total)
	}
}

func TestE2EBenchmarkQPS(t *testing.T) {
	mock, err := newMockDNSServer("93.184.216.34")
	if err != nil {
		t.Fatalf("Failed to start mock DNS: %v", err)
	}
	defer mock.Close()

	result := Benchmark(context.Background(), mock.ip, "test.example.com", mock.port, 2*time.Second)

	if result.QPS() <= 0 {
		t.Errorf("QPS should be positive, got %.2f", result.QPS())
	}
	if result.P50() <= 0 {
		t.Errorf("P50 should be positive, got %v", result.P50())
	}
}

func TestE2EBenchmarkParallel(t *testing.T) {
	// Start 3 mock servers
	var mocks []*mockDNSServer
	var ips []string
	for i := 0; i < 3; i++ {
		mock, err := newMockDNSServer("93.184.216.34")
		if err != nil {
			t.Fatalf("Failed to start mock %d: %v", i, err)
		}
		mocks = append(mocks, mock)
		ips = append(ips, mock.ip)
	}
	defer func() {
		for _, m := range mocks {
			m.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// All mocks use same port pattern, so we use first mock's port
	resultChan := BenchmarkParallel(ctx, ips, "test.example.com", mocks[0].port, 2*time.Second, 3)

	var count, passed int
	for r := range resultChan {
		count++
		if r.Passed() {
			passed++
		}
	}

	if count != 3 {
		t.Errorf("Expected 3 results, got %d", count)
	}
	if passed != 3 {
		t.Errorf("Expected 3 passed, got %d", passed)
	}
}

func TestE2EBenchmarkContextCancellation(t *testing.T) {
	mock, err := newMockDNSServer("93.184.216.34")
	if err != nil {
		t.Fatalf("Failed to start mock DNS: %v", err)
	}
	defer mock.Close()

	// Cancel immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := Benchmark(ctx, mock.ip, "test.example.com", mock.port, 2*time.Second)

	// Should return early with partial/no results
	if result.Successful == BenchmarkQueries {
		t.Error("Expected early termination with cancelled context")
	}
}

func TestProgressUnified(t *testing.T) {
	prog := NewProgress(10, true)

	prog.Increment()
	prog.Increment()
	prog.Success()

	stats := prog.Stats()
	if stats.Processed != 2 {
		t.Errorf("Expected 2 processed, got %d", stats.Processed)
	}
	if stats.Success != 1 {
		t.Errorf("Expected 1 success, got %d", stats.Success)
	}
	if stats.Total != 10 {
		t.Errorf("Expected total 10, got %d", stats.Total)
	}
}

func TestE2EBenchmarkResultMetrics(t *testing.T) {
	mock, err := newMockDNSServer("93.184.216.34")
	if err != nil {
		t.Fatalf("Failed to start mock DNS: %v", err)
	}
	defer mock.Close()

	result := Benchmark(context.Background(), mock.ip, "test.example.com", mock.port, 2*time.Second)

	if result.IP != mock.ip {
		t.Errorf("IP mismatch: got %s, expected %s", result.IP, mock.ip)
	}
	if result.QPS() <= 0 {
		t.Error("QPS should be positive")
	}
	if result.SuccessRate() < 70 {
		t.Errorf("SuccessRate too low: %.1f", result.SuccessRate())
	}
	if result.P50() < 0 {
		t.Error("P50 latency should not be negative")
	}
}
