package main

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

type Verifier interface {
	Verify(ip string) bool
	Name() string
}

type SlipstreamVerifier struct {
	clientPath string
	domain     string
	timeout    time.Duration
}

func NewSlipstreamVerifier(clientPath, domain string, timeout time.Duration) *SlipstreamVerifier {
	return &SlipstreamVerifier{
		clientPath: clientPath,
		domain:     domain,
		timeout:    timeout,
	}
}

func (v *SlipstreamVerifier) Name() string {
	return "slipstream"
}

func (v *SlipstreamVerifier) Verify(ip string) bool {
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
