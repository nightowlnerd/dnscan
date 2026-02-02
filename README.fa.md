# dnscan

[![CI](https://github.com/nightowlnerd/dnscan/actions/workflows/ci.yml/badge.svg)](https://github.com/nightowlnerd/dnscan/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nightowlnerd/dnscan)](https://github.com/nightowlnerd/dnscan/releases)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev/)

[English](README.md) | **فارسی**

پیدا کردن سرورهای DNS فعال برای تونل‌های DNS در زمان قطعی اینترنت. این ابزار رنج‌های IP کشورهای مختلف را اسکن می‌کند تا resolverهای بازگشتی که می‌توانند به سرور تونل شما برسند را پیدا کند.

## ویژگی‌ها

- 🧪 **تست Burst** - سرورهایی که فقط به یک کوئری جواب می‌دهند اما زیر بار واقعی fail می‌شوند را فیلتر می‌کند (مثل 1.1.1.1 که 0% موفقیت دارد)
- 🛡️ **تشخیص DNS Hijacking** - سرورهایی که IP خصوصی برمی‌گردانند را شناسایی و هشدار می‌دهد
- ⚡ **مرتب‌سازی بر اساس QPS** - نتایج بر اساس سرعت (queries per second) مرتب می‌شوند
- 🎨 **رنگ‌بندی** - سبز برای ≥threshold+15%، زرد برای threshold تا threshold+15%

## کاربرد

در زمان محدودیت‌های اینترنتی، تونل‌های DNS (مثل [slipstream](https://github.com/Mygod/slipstream-rust)) می‌توانند با کدگذاری ترافیک در کوئری‌های DNS، محدودیت‌ها را دور بزنند. این ابزار سرورهای DNS را پیدا می‌کند که:
1. کوئری‌های بازگشتی را قبول کنند
2. بتوانند به سرور DNS شما برسند
3. واقعاً با کلاینت تونل شما کار کنند

## شروع سریع

```bash
# دانلود و استخراج (Linux amd64)
curl -LO https://github.com/nightowlnerd/dnscan/releases/latest/download/dnscan-linux-amd64.tar.gz
tar xzf dnscan-linux-amd64.tar.gz

# اسکن سرورهای DNS ایران
./dnscan --country ir --domain t.example.com --mode list
```

![dnscan screenshot](screenshot.jpg)

**نکته:** فایل tarball شامل باینری `dnscan` و پوشه `data/` است. رنج‌های IP برای کشورهای جدید به صورت خودکار دانلود می‌شوند.

## ساخت از سورس

```bash
# Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dnscan-linux-amd64 .

# macOS
go build -o dnscan .
```

## پرچم‌ها

| پرچم | پیش‌فرض | توضیحات |
|------|---------|---------|
| `--country` | ir | کد کشور (ir, cn, و غیره) |
| `--domain` | - | دامنه تونل شما (مثلاً t.example.com) |
| `--mode` | fast | حالت اسکن: `list`, `fast`, `medium`, `all` |
| `--workers` | 500 | تعداد workerهای همزمان |
| `--timeout` | 2s | تایم‌اوت کوئری DNS |
| `--file` | - | لیست IP سفارشی (هر خط یک IP) |
| `--data-dir` | data | مسیر پوشه data |
| `--output` | stdout | ذخیره نتایج در فایل |
| `--progress` | true | نمایش نوار پیشرفت |
| `--verify` | - | مسیر باینری slipstream-client |
| `--json` | false | خروجی به فرمت JSON |
| `--threshold` | 70 | حداقل نرخ موفقیت برای بنچمارک (0-100) |

## حالت‌های اسکن

| حالت | عملکرد | سرعت |
|------|--------|------|
| `list` | تست DNSهای شناخته‌شده از `data/dns/<country>.txt` | سریع‌ترین (~۱۷۰ IP) |
| `fast` | نمونه‌گیری .1, .53, .254 از هر سابنت /24 | سریع |
| `medium` | نمونه‌گیری .1, .2, .10, .53, .100, .200, .254 | متوسط |
| `all` | تست همه IPها (1-254) در هر سابنت | کندترین |

## مثال‌ها

```bash
# تست سریع - فقط DNSهای شناخته‌شده
./dnscan --country ir --domain t.example.com --mode list

# اسکن گسترده‌تر - نمونه‌گیری IPهای رایج DNS
./dnscan --country ir --domain t.example.com --mode fast

# تأیید کامل - تست با کلاینت واقعی تونل
./dnscan --country ir --domain t.example.com --mode list --verify ./slipstream-client

# ذخیره نتایج در فایل
./dnscan --country ir --domain t.example.com --mode fast --output working-dns.txt

# استفاده از لیست IP سفارشی
./dnscan --file my-servers.txt --domain t.example.com

# اسکن رنج‌های چین
./dnscan --country cn --domain t.example.com --mode fast
```

## تست Burst

وقتی `--domain` مشخص شود، dnscan هر سرور کاندید را با 20 کوئری همزمان تست می‌کند. این کار سرورهایی مثل 1.1.1.1 را که به یک کوئری جواب می‌دهند اما زیر بار واقعی slipstream fail می‌شوند، فیلتر می‌کند.

نتایج بر اساس QPS (queries per second) مرتب می‌شوند - سریع‌ترین سرورها اول نشان داده می‌شوند.

## تشخیص DNS Hijacking

اگر ISP شما DNS را hijack کرده باشد (کوئری‌ها به IP خصوصی مثل 10.x.x.x برمی‌گردند)، dnscan این سرورها را رد کرده و هشدار می‌دهد:

```
Warning: 5 servers returned private IPs (possible DNS hijacking)
```

## پرچم --verify

به صورت پیش‌فرض، اسکنر فقط چک می‌کند که آیا سرور DNS پاسخ می‌دهد. با `--verify`، هر کاندیدا را با slipstream-client واقعی تست می‌کند تا کارکرد تونل را تأیید کند:

```bash
./dnscan --domain t.example.com --mode list --verify ./slipstream-client
```

دریافت slipstream-client از: https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases

خروجی زمان اتصال هر سرور را نشان می‌دهد:
```
[1/5] 208.67.222.222   OK (0.4s)
[2/5] 8.8.8.8          OK (0.2s)
[3/5] 217.218.127.127  FAIL
```

## فایل‌های داده

```
data/
  ranges/
    ir.zone    # رنج‌های IP (بلوک‌های CIDR)
  dns/
    ir.txt     # سرورهای DNS شناخته‌شده
```

### دانلود خودکار رنج‌های IP

رنج‌های IP به صورت خودکار از [ipdeny.com](https://www.ipdeny.com/ipblocks/) دانلود می‌شوند وقتی کشور جدیدی استفاده کنید:

```bash
# اولین اجرا de.zone را دانلود می‌کند
./dnscan --country de --domain t.example.com --mode fast
```

### اضافه کردن DNS

فایل `data/dns/<country>.txt` را ویرایش کنید (برای `--mode list` استفاده می‌شود):

```
# data/dns/ir.txt
185.8.174.140
130.185.77.69
```

## راه‌اندازی سرور

قبل از اسکن، سرور تونل شما باید در حال اجرا باشد. اسکنر کوئری‌های DNS به دامنه شما می‌فرستد - اگر سرور در حال اجرا نباشد، همه سرورهای DNS ناموفق به نظر می‌رسند.

برای slipstream:

```bash
# روی سرور شما
docker run -d --network host bashsiz/slipstream-rust slipstream-server \
  --dns-listen-port 53 \
  --domain t.example.com \
  --target-address 127.0.0.1:22
```

برای تست بدون تونل (فقط چک کردن دسترسی DNS):

```bash
# DNS responder ساده
dnsmasq --no-daemon --log-queries --address=/t.example.com/1.2.3.4
```

## خروجی

سرورهای DNS فعال در stdout چاپ می‌شوند (هر خط یکی):

```
185.8.174.140
130.185.77.69
217.218.127.127
```

استفاده با slipstream:

```bash
./slipstream-client \
  --resolver 185.8.174.140:53 \
  --resolver 130.185.77.69:53 \
  --domain t.example.com \
  --tcp-listen-port 7000
```

## عیب‌یابی

**هیچ سرور DNS پیدا نشد:**
- آیا سرور تونل شما در حال اجراست؟
- آیا پورت 53 روی سرور شما باز است؟
- اول `--mode list` را امتحان کنید (DNSهای شناخته‌شده را تست می‌کند)
- تایم‌اوت را افزایش دهید `--timeout 5s`

**اسکن کند:**
- workerها را کاهش دهید `--workers 200`
- از `--mode list` یا `--mode fast` استفاده کنید

**"Failed to download ranges":**
- اتصال اینترنت را چک کنید
- کد کشور ممکن است در ipdeny.com وجود نداشته باشد
