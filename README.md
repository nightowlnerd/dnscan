# dns-scanner

Fast DNS scanner for finding working recursive resolvers that can reach a specific authoritative server. Built for DNS tunnel compatibility testing.

## Build

```bash
# Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dns-scanner-linux-amd64 .

# macOS
go build -o dns-scanner .
```

## Usage

```bash
./dns-scanner --domain <tunnel-domain> [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | - | Tunnel domain to verify (required) |
| `--mode` | fast | `list`, `fast`, `medium`, `all` |
| `--workers` | 5000 | Concurrent workers |
| `--timeout` | 2s | DNS query timeout |
| `--file` | - | Custom DNS IP list |
| `--output` | stdout | Output file |
| `--progress` | true | Show progress |
| `--verify` | - | Path to slipstream-client binary for actual verification |

## Modes

| Mode | IPs | Description |
|------|-----|-------------|
| list | 170 | Known working DNS servers |
| fast | ~12K | Priority Iranian ranges |
| medium | ~30K | ISP ranges |
| all | ~100K | Full scan |

## Examples

```bash
# Quick test with known servers
./dns-scanner --domain t.example.com --mode list

# Broader scan
./dns-scanner --domain t.example.com --mode fast --timeout 5s

# Custom list, save results
./dns-scanner --domain t.example.com --file my-dns.txt --output working.txt

# Slow network: fewer workers, longer timeout
./dns-scanner --domain t.example.com --mode fast --workers 2000 --timeout 10s

# Verify candidates actually work with slipstream
./dns-scanner --domain t.example.com --mode list --verify ./slipstream-client
```

## Server Setup

Run a DNS responder on your authoritative server:

```bash
dnsmasq --no-daemon --log-queries --address=/t.example.com/1.2.3.4
```

Scanner verifies DNS servers can reach your server by checking for successful A record response.
