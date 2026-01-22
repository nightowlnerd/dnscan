# dns-scanner

Fast DNS scanner for finding working recursive resolvers. Supports country-specific IP ranges and DNS tunnel compatibility testing.

## Build

```bash
# Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dns-scanner-linux-amd64 .

# macOS
go build -o dns-scanner .
```

## Usage

```bash
./dns-scanner --country <code> --domain <tunnel-domain> [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--country` | ir | Country code (ir, cn, etc.) |
| `--domain` | - | Tunnel domain to verify |
| `--mode` | fast | `list`, `fast`, `medium`, `all` |
| `--workers` | 5000 | Concurrent workers |
| `--timeout` | 2s | DNS query timeout |
| `--file` | - | Custom DNS IP list |
| `--data-dir` | data | Path to data directory |
| `--output` | stdout | Output file |
| `--progress` | true | Show progress |
| `--verify` | - | Path to slipstream-client for verification |

## Modes

| Mode | Strategy | IPs per /24 |
|------|----------|-------------|
| list | Known DNS from `data/dns/<country>.txt` | - |
| fast | Sample .1, .53, .254 | 3 |
| medium | Sample .1, .2, .10, .53, .100, .200, .254 | 7 |
| all | Every IP | 254 |

## Data Files

```
data/
  ranges/
    ir.zone    # IP ranges from ipdeny.com
    cn.zone
  dns/
    ir.txt     # Known working DNS servers
    cn.txt
```

### Update IP Ranges

```bash
# Iran
curl -o data/ranges/ir.zone https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone

# China
curl -o data/ranges/cn.zone https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone
```

## Examples

```bash
# Quick test with known servers
./dns-scanner --country ir --domain t.example.com --mode list

# Fast scan
./dns-scanner --country ir --domain t.example.com --mode fast

# Full scan with verification
./dns-scanner --country ir --domain t.example.com --mode all --verify ./slipstream-client

# Custom list
./dns-scanner --file my-dns.txt --domain t.example.com

# Different country
./dns-scanner --country cn --domain t.example.com --mode fast
```

## Server Setup

Run a DNS responder on your authoritative server:

```bash
dnsmasq --no-daemon --log-queries --address=/t.example.com/1.2.3.4
```
