VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: build build-linux build-all clean test

build:
	go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dnscan .

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dnscan-linux-amd64 .

build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dnscan-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dnscan-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dnscan-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dnscan-darwin-arm64 .

clean:
	rm -f dnscan dnscan-*

test:
	go test -v ./...
