<div dir="rtl">

# dnscan

[![CI](https://github.com/nightowlnerd/dnscan/actions/workflows/ci.yml/badge.svg)](https://github.com/nightowlnerd/dnscan/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nightowlnerd/dnscan)](https://github.com/nightowlnerd/dnscan/releases)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev/)

[English](README.md) | **فارسی**

پیدا کردن سرورهای DNS فعال برای تونل‌های DNS در زمان قطعی اینترنت. این ابزار رنج‌های IP کشورهای مختلف را اسکن می‌کند تا resolverهای بازگشتی که می‌توانند به سرور تونل شما برسند را پیدا کند.

## کاربرد

در زمان محدودیت‌های اینترنتی، تونل‌های DNS (مثل [slipstream](https://github.com/Mygod/slipstream-rust)) می‌توانند با کدگذاری ترافیک در کوئری‌های DNS، محدودیت‌ها را دور بزنند. این ابزار سرورهای DNS را پیدا می‌کند که:
1. کوئری‌های بازگشتی را قبول کنند
2. بتوانند به سرور DNS شما برسند
3. واقعاً با کلاینت تونل شما کار کنند

## شروع سریع

</div>

```bash
# دانلود و استخراج (Linux amd64)
curl -LO https://github.com/nightowlnerd/dnscan/releases/latest/download/dnscan-linux-amd64.tar.gz
tar xzf dnscan-linux-amd64.tar.gz

# اسکن سرورهای DNS ایران
./dnscan --country ir --domain t.example.com --mode list
```

<div dir="rtl">

**نکته:** فایل tarball شامل باینری `dnscan` و پوشه `data/` است.

## ساخت از سورس

</div>

```bash
# Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dnscan-linux-amd64 .

# macOS
go build -o dnscan .
```

<div dir="rtl">

## پرچم‌ها

| پرچم | پیش‌فرض | توضیحات |
|------|---------|---------|
| `--country` | ir | کد کشور (ir, cn, و غیره) |
| `--domain` | - | دامنه تونل شما (مثلاً t.example.com) |
| `--mode` | fast | حالت اسکن: `list`, `fast`, `medium`, `all` |
| `--workers` | 5000 | تعداد workerهای همزمان |
| `--timeout` | 2s | تایم‌اوت کوئری DNS |
| `--file` | - | لیست IP سفارشی (هر خط یک IP) |
| `--data-dir` | data | مسیر پوشه data |
| `--output` | stdout | ذخیره نتایج در فایل |
| `--progress` | true | نمایش نوار پیشرفت |
| `--verify` | - | مسیر باینری slipstream-client |

## حالت‌های اسکن

| حالت | عملکرد | سرعت |
|------|--------|------|
| `list` | تست DNSهای شناخته‌شده از `data/dns/<country>.txt` | سریع‌ترین (~۱۷۰ IP) |
| `fast` | نمونه‌گیری .1, .53, .254 از هر سابنت /24 | سریع |
| `medium` | نمونه‌گیری .1, .2, .10, .53, .100, .200, .254 | متوسط |
| `all` | تست همه IPها (1-254) در هر سابنت | کندترین |

## مثال‌ها

</div>

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

<div dir="rtl">

## پرچم --verify

به صورت پیش‌فرض، اسکنر فقط چک می‌کند که آیا سرور DNS پاسخ می‌دهد. با `--verify`، هر کاندیدا را با slipstream-client واقعی تست می‌کند تا کارکرد تونل را تأیید کند:

</div>

```bash
./dnscan --domain t.example.com --mode list --verify ./slipstream-client
```

<div dir="rtl">

دریافت slipstream-client از: https://github.com/Mygod/slipstream-rust/releases

## فایل‌های داده

</div>

```
data/
  ranges/
    ir.zone    # رنج‌های IP (بلوک‌های CIDR)
    cn.zone
  dns/
    ir.txt     # سرورهای DNS شناخته‌شده
    cn.txt
```

<div dir="rtl">

### بروزرسانی رنج‌های IP

رنج‌های IP از [ipdeny.com](https://www.ipdeny.com/ipblocks/) هستند. در صورت نیاز بروزرسانی کنید:

</div>

```bash
# ایران
curl -o data/ranges/ir.zone https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone

# چین
curl -o data/ranges/cn.zone https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone
```

<div dir="rtl">

### اضافه کردن DNS

فایل `data/dns/<country>.txt` را ویرایش کنید تا سرورهای DNS که پیدا کرده‌اید را اضافه کنید:

</div>

```
# data/dns/ir.txt
185.8.174.140
130.185.77.69
# اضافه کنید...
```

<div dir="rtl">

## راه‌اندازی سرور

قبل از اسکن، سرور تونل شما باید در حال اجرا باشد. اسکنر کوئری‌های DNS به دامنه شما می‌فرستد - اگر سرور در حال اجرا نباشد، همه سرورهای DNS ناموفق به نظر می‌رسند.

برای slipstream:

</div>

```bash
# روی سرور شما
docker run -d --network host bashsiz/slipstream-rust slipstream-server \
  --dns-listen-port 53 \
  --domain t.example.com \
  --target-address 127.0.0.1:22
```

<div dir="rtl">

برای تست بدون تونل (فقط چک کردن دسترسی DNS):

</div>

```bash
# DNS responder ساده
dnsmasq --no-daemon --log-queries --address=/t.example.com/1.2.3.4
```

<div dir="rtl">

## خروجی

سرورهای DNS فعال در stdout چاپ می‌شوند (هر خط یکی):

</div>

```
185.8.174.140
130.185.77.69
217.218.127.127
```

<div dir="rtl">

استفاده با slipstream:

</div>

```bash
./slipstream-client \
  --resolver 185.8.174.140:53 \
  --resolver 130.185.77.69:53 \
  --domain t.example.com \
  --tcp-listen-port 7000
```

<div dir="rtl">

## عیب‌یابی

**هیچ سرور DNS پیدا نشد:**
- آیا سرور تونل شما در حال اجراست؟
- آیا پورت 53 روی سرور شما باز است؟
- اول `--mode list` را امتحان کنید (DNSهای شناخته‌شده را تست می‌کند)
- تایم‌اوت را افزایش دهید `--timeout 5s`

**اسکن کند:**
- workerها را کاهش دهید `--workers 2000`
- از `--mode list` یا `--mode fast` استفاده کنید

**"Failed to load ranges":**
- مطمئن شوید پوشه `data/` کنار باینری است
- چک کنید `data/ranges/<country>.zone` وجود دارد

</div>
