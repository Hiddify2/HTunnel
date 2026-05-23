# 🚇 HTunnel

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/AmiRCandy/HTunnel)](https://github.com/AmiRCandy/HTunnel/releases)

> ⚠️ **WARNING: Educational Purpose Only**
>
> This project is created strictly for educational and research purposes to demonstrate networking concepts.
> The author is **not responsible** for any misuse or damage caused by this project.
> By using this code, you agree to use it **legally and ethically** and respect local laws and network policies.

---

## 📖 What is HTunnel?

**HTunnel** is a high-performance UDP tunnel designed for challenging network environments. It uses an **asymmetric transport** approach:

| Direction | Method | Description |
|-----------|--------|-------------|
| **Uplink** (Client → Server) | SOCKS5 Proxy | Normal UDP traffic through an upstream SOCKS5 proxy |
| **Downlink** (Server → Client) | Fake UDP | Packets with configurable fake source IPs |

This design makes uploads look like regular SOCKS5 traffic while downloads use sparse faked packets from a configurable IP pool.

### 🏗️ Architecture

```
┌─────┐     ┌──────────────┐     ┌──────────────┐     ┌────────┐
│ App │────▶│ Local SOCKS5 │────▶│  Upstream   │────▶│ Server │
└─────┘     └──────────────┘     │  SOCKS5     │     └────────┘
                                  │  Proxy      │         ▲
                                  └──────────────┘         │
                                        ▲                  │
                                        │                  │
                                   faked UDP downlink       │
                                   (from IP pool)          │
                                        │                  │
                                  ┌─────┴──────────────────┘
                                  │
                            ┌─────▼─────┐
                            │   Client  │
                            └───────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- **Linux** system (requires `CAP_NET_RAW` capability)
- **Rust** toolchain (1.75+): [Install Rust](https://rustup.rs/)
- Upstream **SOCKS5 proxy** for client uplink

### Option 1: Download Pre-built Binaries 📦

Download the latest binaries from the [GitHub Releases](https://github.com/AmiRCandy/HTunnel/releases) page:

```bash
# Download and extract
wget https://github.com/AmiRCandy/HTunnel/releases/latest/download/htunnel-x86_64-unknown-linux-gnu.tar.gz
tar -xzf htunnel-x86_64-unknown-linux-gnu.tar.gz

# Make binaries executable
chmod +x client server
```

### Option 2: Build from Source 🔧

```bash
# Clone the repository
git clone https://github.com/AmiRCandy/HTunnel.git
cd HTunnel

# Build in release mode
cargo build --release

# Binaries will be in target/release/
# - client
# - server
```

### Running

**Server:**
```bash
sudo ./target/release/server --config config/server.json
```

**Client:**
```bash
sudo ./target/release/client --config config/client.json
```

> **Note:** Requires `sudo` or `CAP_NET_RAW` capability for raw socket access.

---

## ⚙️ Configuration

HTunnel uses **JSON** configuration files with support for comments (`//` and `/* */`).

### Client Configuration (`config/client.json`)

```json
{
  // Local SOCKS5 proxy address. Configure your browser/app to use this.
  "listen": "127.0.0.1:9234",

  // Network interface for raw sockets (or "auto" for auto-detection)
  "interface": "eth0",

  // Your real IP address
  "real_ip": "1.1.1.1",

  // Server's real IP address
  "peer_real_ip": "203.0.113.1",

  // Expected fake IP that server uses for replies
  "peer_fake_ip": "1.2.3.4",

  // UDP data channel port (must match server)
  "data_port": 51820,

  // Additional allowed peer IPs
  "allowed_peers": [],

  // Performance settings
  "tunnel_count": 4,
  "mtu": 1380,
  "initial_cwnd": 10.0,

  // Upstream SOCKS5 proxy for uplink (host:port)
  "uplink_proxy": "127.0.0.1:1081"
}
```

### Server Configuration (`config/server.json`)

```json
{
  // Listen address for tunnel data channel
  "listen": "0.0.0.0:51820",

  // Network interface for raw sockets (or "auto" for auto-detection)
  "interface": "eth0",

  // Server's real IP address
  "real_ip": "203.0.113.1",

  // Client's real IP address
  "peer_real_ip": "1.1.1.1",

  // Fake source IP for outgoing packets
  "faked_ip": "1.2.3.4",

  // Pool of fake IPs for rotation
  "faked_ip_pool": ["1.2.3.4", "5.6.7.8"],

  // UDP data channel port (must match client)
  "data_port": 51820,

  // Additional allowed client IPs (add proxy IPs here)
  "allowed_peers": [],

  // Performance settings
  "tunnel_count": 4,
  "mtu": 1380,
  "initial_cwnd": 10.0,

  // Not used on server (kept for schema consistency)
  "uplink_proxy": null
}
```

### Configuration Fields

| Field | Client | Server | Description |
|-------|---------|--------|-------------|
| `listen` | ✅ | ✅ | Listen address (SOCKS5 for client, data channel for server) |
| `interface` | ✅ | ✅ | Network interface for raw sockets |
| `real_ip` | ✅ | ✅ | Real IP address of this machine |
| `peer_real_ip` | ✅ | ✅ | Real IP address of the peer |
| `peer_fake_ip` | ✅ | ❌ | Expected fake IP from peer |
| `faked_ip` | ❌ | ✅ | Fake source IP for outgoing packets |
| `faked_ip_pool` | ❌ | ✅ | Pool of fake IPs for rotation |
| `data_port` | ✅ | ✅ | UDP data channel port |
| `allowed_peers` | ✅ | ✅ | Additional allowed IP addresses |
| `tunnel_count` | ✅ | ✅ | Number of parallel tunnels |
| `mtu` | ✅ | ✅ | Max payload bytes per packet |
| `initial_cwnd` | ✅ | ✅ | Initial congestion window |
| `uplink_proxy` | ✅ | ❌ | Upstream SOCKS5 proxy for uplink |

---

## 📝 Notes & Tips

- **SOCKS5 Proxy:** If client uplink goes through a SOCKS5 proxy, add the proxy's public IP to `allowed_peers` on the server
- **IP Pool:** Server can rotate between multiple fake IPs for better distribution
- **Auto Interface:** Set `interface` to `"auto"` to auto-detect the network interface with public IP
- **MTU:** Keep below 1400 bytes to avoid fragmentation
- **Permissions:** Raw sockets require `CAP_NET_RAW` or running as root

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please test your changes thoroughly before submitting.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

HTunnel is intended for **legitimate network research and educational purposes** only.

Ensure you have explicit permission before:
- Sending packets with fake source IPs
- Tunneling through network infrastructure you don't own
- Using this tool in restricted network environments

**The user is solely responsible for complying with local laws and network policies.**

---

<p align="center">
  Made with ❤️ for educational purposes
</p>
