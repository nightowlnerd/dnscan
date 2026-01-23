# dnscan

[![CI](https://github.com/nightowlnerd/dnscan/actions/workflows/ci.yml/badge.svg)](https://github.com/nightowlnerd/dnscan/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nightowlnerd/dnscan)](https://github.com/nightowlnerd/dnscan/releases)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**English** | [فارسی](README.fa.md)

Find working DNS servers for DNS tunnels during internet blackouts. Scans country-specific IP ranges to find recursive resolvers that can reach your tunnel server.

## Use Case

During internet restrictions, DNS tunnels (like [slipstream](https://github.com/Mygod/slipstream-rust)) can bypass blocks by encoding traffic in DNS queries. This tool finds DNS servers that:
1. Accept recursive queries
2. Can reach your authoritative DNS server
3. Actually work with your tunnel client

## Quick Start

```bash
# Download and extract
curl -LO https://github.com/nightowlnerd/dnscan/releases/latest/download/dnscan.tar.gz
tar xzf dnscan.tar.gz

# Scan known Iranian DNS servers
./dnscan-linux-amd64 --country ir --domain t.example.com --mode list
```

**Important:** The `data/` directory must be in the same folder as the binary.

## Build from Source

```bash
# Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dnscan-linux-amd64 .

# macOS
go build -o dnscan .
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--country` | ir | Country code (ir, cn, etc.) |
| `--domain` | - | Your tunnel domain (e.g., t.example.com) |
| `--mode` | fast | Scan mode: `list`, `fast`, `medium`, `all` |
| `--workers` | 5000 | Concurrent workers |
| `--timeout` | 2s | DNS query timeout |
| `--file` | - | Custom IP list (one per line) |
| `--data-dir` | data | Path to data directory |
| `--output` | stdout | Save results to file |
| `--progress` | true | Show progress bar |
| `--verify` | - | Path to slipstream-client binary |

## Scan Modes

| Mode | What it does | Speed |
|------|--------------|-------|
| `list` | Tests known working DNS from `data/dns/<country>.txt` | Fastest (~170 IPs) |
| `fast` | Samples .1, .53, .254 from each /24 subnet | Fast |
| `medium` | Samples .1, .2, .10, .53, .100, .200, .254 | Medium |
| `all` | Tests every IP (1-254) in each subnet | Slowest |

## Examples

```bash
# Quick test - known DNS servers only
./dnscan --country ir --domain t.example.com --mode list

# Broader scan - sample common DNS IPs
./dnscan --country ir --domain t.example.com --mode fast

# Full verification - test with actual tunnel client
./dnscan --country ir --domain t.example.com --mode list --verify ./slipstream-client

# Save results to file
./dnscan --country ir --domain t.example.com --mode fast --output working-dns.txt

# Use custom IP list
./dnscan --file my-servers.txt --domain t.example.com

# Scan China ranges
./dnscan --country cn --domain t.example.com --mode fast
```

## The --verify Flag

By default, the scanner only checks if a DNS server responds. With `--verify`, it tests each candidate with the actual slipstream-client to confirm the tunnel works:

```bash
./dnscan --domain t.example.com --mode list --verify ./slipstream-client
```

Get slipstream-client from: https://github.com/Mygod/slipstream-rust/releases

## Data Files

```
data/
  ranges/
    ir.zone    # IP ranges (CIDR blocks)
    cn.zone
  dns/
    ir.txt     # Known working DNS servers
    cn.txt
```

### Update IP Ranges

IP ranges are from [ipdeny.com](https://www.ipdeny.com/ipblocks/). Update when needed:

```bash
# Iran
curl -o data/ranges/ir.zone https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone

# China
curl -o data/ranges/cn.zone https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone
```

### Add Known DNS

Edit `data/dns/<country>.txt` to add DNS servers you've found working:

```
# data/dns/ir.txt
185.8.174.140
130.185.77.69
# Add more...
```

## Server Setup

Before scanning, your tunnel server must be running. The scanner sends DNS queries to your domain - if the server isn't running, all DNS servers will appear to fail.

For slipstream:
```bash
# On your server
docker run -d --network host bashsiz/slipstream-rust slipstream-server \
  --dns-listen-port 53 \
  --domain t.example.com \
  --target-address 127.0.0.1:22
```

For testing without a tunnel (just check DNS reachability):
```bash
# Simple DNS responder
dnsmasq --no-daemon --log-queries --address=/t.example.com/1.2.3.4
```

## Output

Working DNS servers are printed to stdout (one per line):
```
185.8.174.140
130.185.77.69
217.218.127.127
```

Use with slipstream:
```bash
./slipstream-client \
  --resolver 185.8.174.140:53 \
  --resolver 130.185.77.69:53 \
  --domain t.example.com \
  --tcp-listen-port 7000
```

## Troubleshooting

**No DNS servers found:**
- Is your tunnel server running?
- Is port 53 open on your server?
- Try `--mode list` first (tests known working DNS)
- Increase `--timeout 5s`

**Slow scanning:**
- Reduce `--workers 2000`
- Use `--mode list` or `--mode fast`

**"Failed to load ranges":**
- Ensure `data/` directory is next to binary
- Check `data/ranges/<country>.zone` exists
