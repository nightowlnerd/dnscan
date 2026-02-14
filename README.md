# dnscan

[![CI](https://github.com/nightowlnerd/dnscan/actions/workflows/ci.yml/badge.svg)](https://github.com/nightowlnerd/dnscan/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nightowlnerd/dnscan)](https://github.com/nightowlnerd/dnscan/releases)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**English** | [فارسی](README.fa.md)

Find working DNS servers for DNS tunnels during internet blackouts. Scans country-specific IP ranges to find recursive resolvers that can reach your tunnel server.

## Features

- 🧪 **Burst Testing** - Filters servers that respond to single queries but fail under real load (e.g., 1.1.1.1 shows 0% success)
- 🛡️ **DNS Hijacking Detection** - Detects and warns when servers return private IPs
- ⚡ **QPS Sorting** - Results sorted by throughput (queries per second)
- 🎨 **Color Coding** - Green for ≥threshold+15%, yellow for threshold to threshold+15%

## Use Case

During internet restrictions, DNS tunnels (like [slipstream](https://github.com/nightowlnerd/slipstream-rust)) can bypass blocks by encoding traffic in DNS queries. This tool finds DNS servers that:
1. Accept recursive queries
2. Can reach your authoritative DNS server
3. Actually work with your tunnel client

## Quick Start

```bash
# Download and extract (Linux amd64)
curl -LO https://github.com/nightowlnerd/dnscan/releases/latest/download/dnscan-linux-amd64.tar.gz
tar xzf dnscan-linux-amd64.tar.gz

# Scan known Iranian DNS servers
./dnscan --country ir --domain t.example.com --mode list
```

![dnscan screenshot](screenshot.jpg)

**Note:** Tarball includes `dnscan` binary + `data/` folder.

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
| `--workers` | 500 | Concurrent workers |
| `--timeout` | 2s | DNS query timeout |
| `--file` | - | Custom IP list (one per line) |
| `--data-dir` | data | Path to data directory |
| `--output` | stdout | Save results to file |
| `--progress` | true | Show progress bar |
| `--verify` | - | Path to slipstream-client binary |
| `--json` | false | Output results as JSON |
| `--threshold` | 70 | Minimum success rate for benchmark (0-100) |

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

## Burst Testing

When `--domain` is specified, dnscan tests each candidate with 20 concurrent queries. This filters out servers like 1.1.1.1 that respond to single queries but fail under real slipstream load.

Results are sorted by QPS (queries per second) - fastest servers listed first.

## DNS Hijacking Detection

If your ISP hijacks DNS (queries return private IPs like 10.x.x.x), dnscan rejects those servers and warns you:

```
Warning: 5 servers returned private IPs (possible DNS hijacking)
```

## The --verify Flag

By default, the scanner only checks if a DNS server responds. With `--verify`, it tests each candidate with the actual slipstream-client to confirm the tunnel works:

```bash
./dnscan --domain t.example.com --mode list --verify ./slipstream-client
```

Output shows connection time for each server:
```
[1/5] 208.67.222.222   OK (0.4s)
[2/5] 8.8.8.8          OK (0.2s)
[3/5] 217.218.127.127  FAIL
```

Get slipstream-client from: https://github.com/nightowlnerd/slipstream-rust/releases

## Data Files

```
data/
  ranges/
    ir.zone    # IP ranges (CIDR blocks)
  dns/
    ir.txt     # Known working DNS servers
```

### Auto-download IP Ranges

IP ranges are auto-downloaded from [ipdeny.com](https://www.ipdeny.com/ipblocks/) when you use a new country:

```bash
# First run auto-downloads de.zone
./dnscan --country de --domain t.example.com --mode fast
```

### Add Known DNS

Edit `data/dns/<country>.txt` to add DNS servers you've found working (used by `--mode list`):

```
# data/dns/ir.txt
185.8.174.140
130.185.77.69
```

## Server Setup

Before scanning, your tunnel server must be running. The scanner sends DNS queries to your domain - if the server isn't running, all DNS servers will appear to fail.

For slipstream:
```bash
# On your server
slipstream-server \
  --dns-listen-port 53 \
  --domain t.example.com \
  --target-address 127.0.0.1:22
```

Get slipstream binaries from: https://github.com/nightowlnerd/slipstream-rust/releases

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
- Reduce `--workers 200`
- Use `--mode list` or `--mode fast`

**"Failed to download ranges":**
- Check internet connection
- Country code may not exist on ipdeny.com
