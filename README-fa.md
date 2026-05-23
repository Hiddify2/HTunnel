# 🚇 HTunnel

[![مجوز: MIT](https://img.shields.io/badge/مجوز-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![آخرین نسخه در گیت‌هاب](https://img.shields.io/github/v/release/AmiRCandy/HTunnel)](https://github.com/AmiRCandy/HTunnel/releases)

> **⚠️ هشدار: فقط برای اهداف آموزشی**
>
> این پروژه صرفاً برای اهداف آموزشی و پژوهشی و نمایش مفاهیم شبکه ایجاد شده است.
> نویسنده مسئول هیچ‌گونه سوءاستفاده یا آسیب ناشی از این پروژه نیست.
> با استفاده از این کد، شما موافقت می‌کنید که آن را به صورت **قانونی و اخلاقی** استفاده کنید و به قوانین محلی و سیاست‌های شبکه احترام بگذارید.

---

## 📖 HTunnel چیست؟

**HTunnel** یک تونل UDP با کارایی بالا برای محیط‌های شبکه‌ای چالش‌برانگیز است. این ابزار از رویکرد **انتقال نامتقارن** استفاده می‌کند:

| جهت | روش | توضیحات |
|------|------|----------|
| **آپ‌لینک** (کلاینت → سرور) | پروکسی SOCKS5 | ترافیک UDP معمولی از طریق پروکسی SOCKS5 بالادستی |
| **داون‌لینک** (سرور → کلاینت) | UDP جعلی | بسته‌ها با آدرس‌های مبدأ جعلی از استخر قابل تنظیم |

این طراحی باعث می‌شود آپلودها شبیه ترافیک SOCKS5 معمولی به نظر برسند، در حالی که دانلودها از بسته‌های جعلی پراکنده استفاده می‌کنند.

### 🏗️ معماری

```
┌─────┐     ┌──────────────┐     ┌──────────────┐     ┌────────┐
│ برنامه │────▶│ SOCKS5 محلی │────▶│  پروکسی     │────▶│ سرور │
└─────┘     └──────────────┘     │  SOCKS5     │     └────────┘
                                  │  بالادستی    │         ▲
                                  └──────────────┘         │
                                        ▲                  │
                                        │                  │
                                   داون‌لینک UDP جعلی       │
                                   (از استخر IP)          │
                                        │                  │
                                  ┌─────┴──────────────────┘
                                  │
                            ┌─────▼─────┐
                            │  کلاینت   │
                            └───────────┘
```

---
## 🚀 اسکریپت راه‌اندازی سریع

HTunnel یک اسکریپت تعاملی نصب دارد که همه چیز را به صورت خودکار پیکربندی می‌کند!

### استفاده از setup.sh

```bash
# دانلود اسکریپت راه‌اندازی
curl -O https://raw.githubusercontent.com/AmiRCandy/HTunnel/main/setup.sh

# اجرایی کردن اسکریپت
chmod +x setup.sh

# اجرای اسکریپت (نیاز به sudo)
sudo ./setup.sh
```

**⚠️ نکته مهم برای سرورهای ایران:**
به دلیل فیلترینگ اینترنت، دانلود از گیت‌هاب در سرورهای ایران ممکن است با مشکل مواجه شود. در این صورت:
- از فیلترشکن یا VPN استفاده کنید
- یا اسکریپت را دستی اجرا کنید (بخش دانلود را رد کنید)
- یا باینری‌ها را از طریق دیگری دانلود و در مسیر پروژه قرار دهید

اسکریپت موارد زیر را انجام می‌دهد:
- ✅ تشخیص خودکار رابط شبکه (با استفاده از `ip route`)
- ✅ پرسش کلاینت یا سرور بودن
- ✅ دریافت تعاملی همه تنظیمات پیکربندی
- ✅ تشخیص خودکار IP عمومی
- ✅ دانلود جدیدترین باینری‌ها از انتشارهای گیت‌هاب (یا ساخت از سورس)
- ✅ ایجاد فایل‌های JSON پیکربندی با فرمت صحیح
- ✅ نصب اختیاری به عنوان سرویس systemd (اجرای خودکار در بوت)
- ✅ اجرای اختیاری HTunnel

**کارهایی که اسکریپت به صورت خودکار انجام می‌دهد:**
۱. تشخیص رابط پیش‌فرض با استفاده از `ip r | grep default`
۲. پرسش حالت کلاینت یا سرور
۳. درخواست آدرس‌های IP و تنظیمات
۴. دانلود `HTunnel-client-linux-x86_64` یا `HTunnel-server-linux-x86_64` از انتشارهای گیت‌هاب
۵. ایجاد `config/client.json` یا `config/server.json` با تنظیمات شما
۶. تنظیم قابلیت `CAP_NET_RAW` یا اجرا با sudo
۷. اجرای اختیاری HTunnel

---
## �️ راهنمای نصب

### مرحله ۱: پیش‌نیازهای سیستم

**موارد اجباری:**
- سیستم‌عامل **Linux** (کرنل ۴.x یا جدیدتر)
- دسترسی ریشه (root) یا قابلیت `CAP_NET_RAW`
- حداقل یک رابط شبکه با IP عمومی

**برای ساخت از سورس:**
- ابزار **Rust** (نسخه 1.75 به بالا): [نصب Rust](https://rustup.rs/)
- Git

### مرحله ۲: انتخاب روش نصب

#### روش ۱: دانلود بسته‌های آماده (توصیه شده) 📦

۱. به صفحه [انتشارهای گیت‌هاب](https://github.com/AmiRCandy/HTunnel/releases) مراجعه کنید
۲. آخرین نسخه را برای معماری خود دانلود کنید:

```bash
# برای سیستم‌های x86_64 - دانلود کلاینت
wget https://github.com/AmiRCandy/HTunnel/releases/latest/download/HTunnel-client-linux-x86_64
chmod +x HTunnel-client-linux-x86_64

# دانلود سرور
wget https://github.com/AmiRCandy/HTunnel/releases/latest/download/HTunnel-server-linux-x86_64
chmod +x HTunnel-server-linux-x86_64

# اختیاری: تغییر نام و انتقال به مسیر سیستم
sudo mv HTunnel-client-linux-x86_64 /usr/local/bin/client
sudo mv HTunnel-server-linux-x86_64 /usr/local/bin/server
```

**نکته:** باینری‌ها فایل‌های اجرایی مستقل هستند (نه آرشیو tar.gz). فقط دانلود کنید، اجرایی کنید و اجرا!

#### روش ۲: ساخت از سورس 🔧

```bash
# ۱. نصب Rust (اگر قبلاً نصب نشده)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# ۲. کلون کردن مخزن
git clone https://github.com/AmiRCandy/HTunnel.git
cd HTunnel

# ۳. ساخت در حالت انتشار (باینری بهینه‌شده)
cargo build --release

# ۴. باینری‌ها اکنون در target/release/ قرار دارند
ls -lh target/release/client target/release/server

# ۵. اختیاری: انتقال به مسیر سیستم
sudo cp target/release/client target/release/server /usr/local/bin/
```

### مرحله ۳: تأیید نصب

```bash
# بررسی عملکرد باینری‌ها
./client --help
./server --help

# باید اطلاعات استفاده نمایش داده شود
```

---

## ⚙️ راهنمای پیکربندی

### درک فایل‌های پیکربندی

HTunnel از فایل‌های پیکربندی **JSON** با پشتیبانی از کامنت استفاده می‌کند. دو پیکربندی جداگانه نیاز است:
- **پیکربندی کلاینت**: `config/client.json` - برای ماشین کلاینت
- **پیکربندی سرور**: `config/server.json` - برای ماشین سرور

### مرحله ۱: به دست آوردن آدرس‌های IP

قبل از پیکربندی، این آدرس‌های IP را جمع‌آوری کنید:

```bash
# دریافت IP عمومی (روی هر دو ماشین اجرا کنید)
curl -4 ifconfig.me
# یا
ip -4 addr show | grep inet

# یادداشت کنید:
# - IP واقعی خودتان (real_ip)
# - IP واقعی همتای شما (peer_real_ip)
# - انتخاب IPهای جعلی برای استخر (faked_ip, faked_ip_pool)
```

### مرحله ۲: پیکربندی سرور

فایل `config/server.json` را ویرایش کنید:

```json
{
  // آدرس گوش دادن برای کانال داده تونل (0.0.0.0 یعنی همه رابط‌ها)
  "listen": "0.0.0.0:51820",

  // رابط شبکه (از "auto" برای تشخیص خودکار استفاده کنید)
  "interface": "eth0",

  // IP عمومی واقعی سرور
  "real_ip": "203.0.113.1",

  // IP عمومی واقعی کلاینت
  "peer_real_ip": "198.51.100.1",

  // آدرس مبدأ جعلی برای بسته‌های خروجی
  "faked_ip": "1.2.3.4",

  // استخر آدرس‌های جعلی برای چرخش (اختیاری)
  "faked_ip_pool": ["1.2.3.4", "5.6.7.8", "9.10.11.12"],

  // پورت کانال داده UDP (باید با کلاینت یکی باشد)
  "data_port": 51820,

  // آدرس‌های IP مجاز کلاینت اضافی (IP عمومی پروکسی را اینجا اضافه کنید)
  "allowed_peers": [],

  // تنظیمات عملکرد
  "tunnel_count": 4,
  "mtu": 1380,
  "initial_cwnd": 10.0,

  // در سرور استفاده نمی‌شود (برای یکسان بودن ساختار موجود است)
  "uplink_proxy": null
}
```

**نکات پیکربندی سرور:**
- از `"interface": "auto"` برای تشخیص خودکار رابط شبکه استفاده کنید
- اگر کلاینت از پروکسی استفاده می‌کند، IP عمومی پروکسی را به `allowed_peers` اضافه کنید
- `faked_ip_pool` امکان چرخش بین چندین IP جعلی را فراهم می‌کند

### مرحله ۳: پیکربندی کلاینت

فایل `config/client.json` را ویرایش کنید:

```json
{
  // آدرس پروکسی SOCKS5 محلی (برنامه‌ها به اینجا متصل می‌شوند)
  "listen": "127.0.0.1:9234",

  // رابط شبکه (از "auto" برای تشخیص خودکار استفاده کنید)
  "interface": "auto",

  // IP عمومی واقعی کلاینت
  "real_ip": "198.51.100.1",

  // IP عمومی واقعی سرور
  "peer_real_ip": "203.0.113.1",

  // آدرس جعلی مورد انتظار که سرور استفاده می‌کند
  "peer_fake_ip": "1.2.3.4",

  // پورت کانال داده UDP (باید با سرور یکی باشد)
  "data_port": 51820,

  // آدرس‌های IP مجاز سرور اضافی
  "allowed_peers": [],

  // تنظیمات عملکرد
  "tunnel_count": 4,
  "mtu": 1380,
  "initial_cwnd": 10.0,

  // پروکسی SOCKS5 بالادستی برای آپ‌لینک (host:port)
  // اگر از پروکسی استفاده نمی‌کنید، null بگذارید
  "uplink_proxy": "127.0.0.1:1081"
}
```

**نکات پیکربندی کلاینت:**
- `listen` را روی یک آدرس محلی تنظیم کنید (مثلاً `127.0.0.1:9234`)
- مرورگر/برنامه خود را برای استفاده از این پروکسی SOCKS5 تنظیم کنید
- اگر نیاز به عبور از پروکسی دارید، `uplink_proxy` را تنظیم کنید

### مرحله ۴: راه‌اندازی پروکسی SOCKS5 (اختیاری)

اگر به یک پروکسی SOCKS5 بالادستی برای آپ‌لینک کلاینت نیاز دارید:

**گزینه ۱: استفاده از پنل ۳x-ui (توصیه شده برای کاربران VPN)**

۱. یک **Inbound** جدید در پنل ۳x-ui ایجاد کنید:
   - پروتکل: **SOCKS**
   - پورت: `1081` (یا هر پورت دلخواه)
   - نتورک: **tcp,udp** (حالت Mixed)
   - فعال‌سازی پشتیبانی UDP

۲. یک قانون **Outbound** ایجاد کنید:
   - نوع: پیکربندی VPN شما (VLESS، VMess، Trojan، و...)
   - آن را به Inbound ساخته شده SOCKS متصل کنید

۳. پیکربندی کلاینت HTunnel (`config/client.json`):
```json
{
  "listen": "127.0.0.1:9234",
  "interface": "auto",
  "real_ip": "198.51.100.1",
  "peer_real_ip": "203.0.113.1",
  "peer_fake_ip": "1.2.3.4",
  "data_port": 51820,
  "allowed_peers": [],
  "tunnel_count": 4,
  "mtu": 1380,
  "initial_cwnd": 10.0,
  "uplink_proxy": "127.0.0.1:1081"
}
```

**جریان:** `برنامه → HTunnel SOCKS5 (9234) → ۳x-ui SOCKS5 Inbound (1081) → VPN Outbound → اینترنت`

**گزینه ۲: استفاده از Dante Server**

```bash
# نصب dante-server
sudo apt install dante-server

# پیکربندی /etc/danted.conf برای پشتیبانی UDP
# سپس راه‌اندازی سرویس
sudo systemctl start danted

# استفاده در پیکربندی کلاینت:
# "uplink_proxy": "127.0.0.1:1080"
```

**گزینه ۳: استفاده از پروکسی موجود**

```json
{
  // فقط آدرس IP:پورت پروکسی موجود را وارد کنید
  "uplink_proxy": "proxy.example.com:1080"
}
```

### مرحله ۵: تست پیکربندی

```bash
# اعتبارسنجی نحو JSON
cat config/server.json | jq .
cat config/client.json | jq .

# اگر jq را ندارید:
# پیکربندی هنگام اجرای برنامه اعتبارسنجی می‌شود
```

---

## 🚀 اجرای HTunnel

### راه‌اندازی سرور

```bash
# روش ۱: استفاده از sudo (توصیه شده برای تولید)
sudo ./server --config config/server.json

# روش ۲: استفاده از قابلیت‌ها (امن‌تر)
sudo setcap cap_net_raw+ep ./server
./server --config config/server.json

# خروجی مورد انتظار:
# INFO  HTunnel server starting | real=203.0.113.1 fake=1.2.3.4 peer=198.51.100.1
# INFO  Server listening on 0.0.0.0:51820
```

### راه‌اندازی کلاینت

```bash
# روش ۱: استفاده از sudo
sudo ./client --config config/client.json

# روش ۲: استفاده از قابلیت‌ها
sudo setcap cap_net_raw+ep ./client
./client --config config/client.json

# خروجی مورد انتظار:
# INFO  HTunnel client starting | real=198.51.100.1 peer=203.0.113.1
# INFO  SOCKS5 proxy listening on 127.0.0.1:9234
```

### تست اتصال

```bash
# روی ماشین کلاینت، پروکسی SOCKS5 را تست کنید
curl --socks5 127.0.0.1:9234 https://api.ipify.org?format=json

# باید IP جعلی سرور یا IP واقعی را برگرداند
```

### اجرا به عنوان سرویس (Systemd)

**ایجاد سرویس سرور:**

```bash
sudo nano /etc/systemd/system/htunnel-server.service
```

این محتوا را اضافه کنید:
```ini
[Unit]
Description=HTunnel Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/server --config /etc/htunnel/server.json
Restart=always
RestartSec=10
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

**ایجاد سرویس کلاینت:**

```bash
sudo nano /etc/systemd/system/htunnel-client.service
```

این محتوا را اضافه کنید:
```ini
[Unit]
Description=HTunnel Client
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/client --config /etc/htunnel/client.json
Restart=always
RestartSec=10
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

**فعال‌سازی و شروع:**

```bash
# بارگذاری مجدد systemd
sudo systemctl daemon-reload

# فعال‌سازی در هنگام بوت
sudo systemctl enable htunnel-server  # روی سرور
sudo systemctl enable htunnel-client  # روی کلاینت

# شروع سرویس‌ها
sudo systemctl start htunnel-server
sudo systemctl start htunnel-client

# بررسی وضعیت
sudo systemctl status htunnel-server
sudo systemctl status htunnel-client

# مشاهده لاگ‌ها
sudo journalctl -u htunnel-server -f
sudo journalctl -u htunnel-client -f
```

---

## 🔧 عیب‌یابی

### مشکلات رایج

**۱. خطای دسترسی (سوکت‌های خام)**
```bash
# راه‌حل ۱: استفاده از sudo
sudo ./server --config config/server.json

# راه‌حل ۲: تنظیم قابلیت‌ها
sudo setcap cap_net_raw+ep ./server
./server --config config/server.json
```

**۲. پورت در حال استفاده است**
```bash
# بررسی چه برنامه‌ای از پورت استفاده می‌کند
sudo netstat -tulpn | grep 51820

# تغییر پورت در فایل پیکربندی
```

**۳. مشکلات اتصال**
```bash
# بررسی قوانین فایروال
sudo iptables -L -n | grep 51820

# اجازه دادن پورت
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
```

**۴. پیکربندی JSON نامعتبر**
```bash
# اعتبارسنجی JSON
cat config/server.json | jq .
# خطاهای نحوی را برطرف کنید
```

---

## ⚙️ پیکربندی

HTunnel از فایل‌های پیکربندی **JSON** با پشتیبانی از کامنت (`//` و `/* */`) استفاده می‌کند.

### پیکربندی کلاینت (`config/client.json`)

```json
{
  // آدرس پروکسی SOCKS5 محلی. مرورگر/برنامه را برای استفاده از این آدرس تنظیم کنید.
  "listen": "127.0.0.1:9234",

  // رابط شبکه برای سوکت‌های خام (یا "auto" برای تشخیص خودکار)
  "interface": "eth0",

  // آدرس واقعی این ماشین
  "real_ip": "1.1.1.1",

  // آدرس واقعی سرور HTunnel
  "peer_real_ip": "203.0.113.1",

  // آدرس مبدأ جعلی که سرور استفاده می‌کند
  "peer_fake_ip": "1.2.3.4",

  // پورت کانال داده UDP (باید با سرور یکی باشد)
  "data_port": 51820,

  // آدرس‌های IP مجاز اضافی
  "allowed_peers": [],

  // تنظیمات عملکرد
  "tunnel_count": 4,
  "mtu": 1380,
  "initial_cwnd": 10.0,

  // پروکسی SOCKS5 برای آپ‌لینک (host:port)
  "uplink_proxy": "127.0.0.1:1081"
}
```

### پیکربندی سرور (`config/server.json`)

```json
{
  // آدرس گوش دادن برای کانال داده تونل
  "listen": "0.0.0.0:51820",

  // رابط شبکه برای سوکت‌های خام (یا "auto" برای تشخیص خودکار)
  "interface": "eth0",

  // آدرس واقعی سرور
  "real_ip": "203.0.113.1",

  // آدرس واقعی کلاینت
  "peer_real_ip": "1.1.1.1",

  // آدرس مبدأ جعلی برای بسته‌های خروجی
  "faked_ip": "1.2.3.4",

  // استخر آدرس‌های جعلی برای چرخش
  "faked_ip_pool": ["1.2.3.4", "5.6.7.8"],

  // پورت کانال داده UDP (باید با کلاینت یکی باشد)
  "data_port": 51820,

  // آدرس‌های IP مجاز کلاینت (IP عمومی پروکسی را اینجا اضافه کنید)
  "allowed_peers": [],

  // تنظیمات عملکرد
  "tunnel_count": 4,
  "mtu": 1380,
  "initial_cwnd": 10.0,

  // در سرور استفاده نمی‌شود (برای یکسان بودن ساختار موجود است)
  "uplink_proxy": null
}
```

### فیلدهای پیکربندی

| فیلد | کلاینت | سرور | توضیحات |
|------|--------|------|----------|
| `listen` | ✅ | ✅ | آدرس گوش دادن (SOCKS5 برای کلاینت، کانال داده برای سرور) |
| `interface` | ✅ | ✅ | رابط شبکه برای سوکت‌های خام |
| `real_ip` | ✅ | ✅ | آدرس IP واقعی این ماشین |
| `peer_real_ip` | ✅ | ✅ | آدرس IP واقعی همتا |
| `peer_fake_ip` | ✅ | ❌ | آدرس جعلی مورد انتظار از همتا |
| `faked_ip` | ❌ | ✅ | آدرس مبدأ جعلی برای بسته‌های خروجی |
| `faked_ip_pool` | ❌ | ✅ | استخر آدرس‌های جعلی برای چرخش |
| `data_port` | ✅ | ✅ | پورت کانال داده UDP |
| `allowed_peers` | ✅ | ✅ | آدرس‌های IP مجاز اضافی |
| `tunnel_count` | ✅ | ✅ | تعداد تونل‌های موازی |
| `mtu` | ✅ | ✅ | حداکثر بایت پayload در هر بسته |
| `initial_cwnd` | ✅ | ✅ | پنجره ازدحام اولیه |
| `uplink_proxy` | ✅ | ❌ | پروکسی SOCKS5 بالادستی برای آپ‌لینک |

---

## 📝 نکات و راهنمایی‌ها

- **پروکسی SOCKS5:** اگر آپ‌لینک کلاینت از پروکسی SOCKS5 عبور می‌کند، IP عمومی پروکسی را به `allowed_peers` در سرور اضافه کنید
- **استخر IP:** سرور می‌تواند بین چندین IP جعلی برای توزیع بهتر چرخش کند
- **تشخیص خودکار رابط:** `interface` را روی `"auto"` تنظیم کنید تا رابط شبکه با IP عمومی به طور خودکار تشخیص داده شود
- **MTU:** زیر ۱۴۰۰ بایت نگه دارید تا از تکه‌تکه شدن جلوگیری شود
- **دسترسی‌ها:** سوکت‌های خام نیاز به `CAP_NET_RAW` یا اجرا با دسترسی ریشه دارند

---

## 🤝 مشارکت

مشارکت‌ها خوش‌آمدید! لطفاً:

1. مخزن را فورک کنید
2. یک شاخه ویژگی ایجاد کنید (`git checkout -b feature/amazing-feature`)
3. تغییرات را کامیت کنید (`git commit -m 'Add amazing feature'`)
4. به شاخه پوش کنید (`git push origin feature/amazing-feature`)
5. یک Pull Request باز کنید

لطفاً قبل از ارسال، تغییرات خود را به دقت تست کنید.

---

## 📄 مجوز

این پروژه تحت مجوز **MIT** منتشر شده است - جزئیات را در فایل [LICENSE](LICENSE) ببینید.

---

## ⚠️ سلب مسئولیت

HTunnel صرفاً برای **اهداف آموزشی و پژوهشی مشروع** ارائه شده است.

قبل از موارد زیر حتماً اجازه صریح داشته باشید:
- ارسال بسته‌ها با آدرس مبدأ جعلی
- تونل زدن از طریق زیرساخت شبکه‌ای که مالک آن نیستید
- استفاده از این ابزار در محیط‌های شبکه محدود شده

**کاربر به تنهایی مسئول رعایت قوانین محلی و سیاست‌های شبکه است.**

---

<p align="center">
  با ❤️ برای اهداف آموزشی ساخته شده است
</p>
