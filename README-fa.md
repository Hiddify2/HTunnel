# HTunnel

> **⚠️ فقط برای اهداف آموزشی**
> این نرم‌افزار تنها برای اهداف آموزشی و پژوهشی ارائه شده است. کاربران مسئول رعایت قوانین و مقررات مرتبط هستند. نویسنده مسئول سوء استفاده از این ابزار نیست.

**HTunnel** یک تونل UDP با انتقال نامتقارن است:

- **آپ‌لینک (کلاینت → سرور)**: UDP معمولی از طریق پروکسی SOCKS5 بالادستی.
- **داون‌لینک (سرور → کلاینت)**: بسته‌های UDP با آدرس مبدأ جعلی از یک استخر قابل تنظیم.

## معماری

```
[برنامه] -> [SOCKS5 محلی] -> [پروکسی بالادستی SOCKS5] -> [سرور]
                                  ^
                                  |
                         داون‌لینک UDP جعلی
```

## شروع سریع

### پیش‌نیازها

- **Linux** (نیاز به CAP_NET_RAW)
- Rust toolchain: `rustup update`
- پروکسی SOCKS5 بالادستی برای آپ‌لینک

### ساخت

```bash
cargo build --release
```

### اجرا

سرور:

```bash
sudo ./target/release/server --config config/server.json
```

کلاینت:

```bash
sudo ./target/release/client --config config/client.json
```

## پیکربندی (JSON)

HTunnel از فایل‌های JSON در پوشه `config/` استفاده می‌کند.

### کلاینت

- `real_ip`: آدرس واقعی کلاینت
- `peer_real_ip`: آدرس واقعی سرور
- `peer_faked_ip`: آدرس مبدأ جعلی سرور برای داون‌لینک
- `data_port`: پورت UDP (باید یکی باشد)
- `allowed_peers`: IPهای اضافی برای پذیرش
- `interface`: نام رابط شبکه
- `listen`: آدرس SOCKS5 محلی (host:port)
- `uplink_proxy`: پروکسی SOCKS5 بالادستی (host:port)
- `tunnel_count`, `mtu`, `initial_cwnd`: تنظیمات عملکرد

### سرور

- `real_ip`: آدرس واقعی سرور
- `peer_real_ip`: آدرس واقعی کلاینت
- `faked_ip`: آدرس مبدأ جعلی (اگر استخر خالی است)
- `faked_ip_pool`: استخر آدرس‌های جعلی
- `data_port`: پورت UDP (باید یکی باشد)
- `allowed_peers`: لیست مجاز برای آپ‌لینک (IP عمومی پروکسی را اضافه کنید)
- `interface`: نام رابط شبکه
- `tunnel_count`, `mtu`, `initial_cwnd`: تنظیمات عملکرد

نکته‌ها:

- اگر آپ‌لینک از پروکسی SOCKS5 می‌آید، IP عمومی پروکسی را در `allowed_peers` سرور قرار دهید.
- `peer_faked_ip` در سرور اختیاری است و می‌توان فقط از `allowed_peers` استفاده کرد.

## مجوز

MIT. جزئیات در [LICENSE](./LICENSE).
