package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const VerifyWorkers = 10

type Verifier interface {
	Verify(ctx context.Context, ips []string) []string
	Name() string
}

type SlipstreamVerifier struct {
	clientPath   string
	domain       string
	timeout      time.Duration
	output       io.Writer
	showProgress bool
}

func NewSlipstreamVerifier(clientPath, domain string, timeout time.Duration, output io.Writer, showProgress bool) *SlipstreamVerifier {
	return &SlipstreamVerifier{
		clientPath:   clientPath,
		domain:       domain,
		timeout:      timeout,
		output:       output,
		showProgress: showProgress,
	}
}

func (v *SlipstreamVerifier) Name() string {
	return "slipstream"
}

func (v *SlipstreamVerifier) Verify(ctx context.Context, ips []string) []string {
	if len(ips) == 0 {
		return nil
	}

	prog := NewProgress(len(ips), v.showProgress)

	tickCtx, stopTick := context.WithCancel(ctx)
	go v.tick(tickCtx, prog)

	var verified []string
	if len(ips) <= 5 {
		verified = v.sequential(ctx, ips, prog)
	} else {
		verified = v.parallel(ctx, ips, prog)
	}

	stopTick()
	v.summary(prog, len(verified), len(ips))
	return verified
}

func (v *SlipstreamVerifier) sequential(ctx context.Context, ips []string, prog *Progress) []string {
	var verified []string
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return verified
		default:
		}
		prog.Increment()
		if v.testIP(ip) {
			prog.Success()
			verified = append(verified, ip)
		}
	}
	return verified
}

func (v *SlipstreamVerifier) parallel(ctx context.Context, ips []string, prog *Progress) []string {
	workers := min(len(ips), VerifyWorkers)

	ipChan := make(chan string, len(ips))
	resultChan := make(chan string, workers)

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
					passed := v.testIP(ip)
					prog.Increment()
					if passed {
						prog.Success()
						select {
						case resultChan <- ip:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var verified []string
	for ip := range resultChan {
		verified = append(verified, ip)
	}
	return verified
}

func (v *SlipstreamVerifier) tick(ctx context.Context, prog *Progress) {
	if !v.showProgress || v.output == nil {
		return
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			st := prog.Stats()
			fmt.Fprintf(v.output, "\rVerifying: %d/%d tested, %d passed   ",
				st.Processed, st.Total, st.Success)
		case <-ctx.Done():
			return
		}
	}
}

func (v *SlipstreamVerifier) summary(prog *Progress, passed, total int) {
	if !v.showProgress || v.output == nil {
		return
	}
	fmt.Fprintf(v.output, "\r\033[1;32mVerify: %d/%d | Passed: %d | %s\033[0m          \n", total, total, passed, v.Name())
}

func (v *SlipstreamVerifier) testIP(ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout*3)
	defer cancel()

	cmd := exec.CommandContext(ctx, v.clientPath,
		"--resolver", ip+":53",
		"--domain", v.domain,
		"--tcp-listen-port", "0",
	)

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		return false
	}

	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	deadline := time.Now().Add(v.timeout)

	for time.Now().Before(deadline) {
		result := output.String()

		if strings.Contains(result, "Connection ready") {
			return true
		}

		if strings.Contains(result, "Connection closed") || strings.Contains(result, "became unavailable") {
			return false
		}

		time.Sleep(200 * time.Millisecond)
	}

	return false
}
