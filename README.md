# 🚇 HTunnel

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Hiddify2/HTunnel)](https://github.com/Hiddify2/HTunnel/releases)

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
## 🚀 Quick Setup Script

HTunnel provides an interactive setup script that automaticaly configures everything for you!

### Using setup.sh

```bash
# Download the setup script
curl -O https://raw.githubusercontent.com/Hiddify2/HTunnel/main/setup.sh

# Make it executable
chmod +x setup.sh

# Run the setup (requires sudo)
sudo ./setup.sh
```

The script will:
- ✅ Auto-detect your network interface (using `ip route`)
- ✅ Ask if you want to configure Client or Server
- ✅ Interactive ask for all configuration options
- ✅ Auto-detect your public IP
- ✅ Download latest binaries from GitHub releases (or build from source)
- ✅ Create properly formatted JSON config files
- ✅ Optionally install as systemd service (auto-start on boot)
- ✅ Optionally run HTunnel immediately

**What the script does automatically:**
1. Detects default interface using `ip r | grep default`
2. Asks for Client or Server mode
3. Prompts for IP addresses and configuration
4. Downloads `HTunnel-client-linux-x86_64` or `HTunnel-server-linux-x86_64` from GitHub releases
5. Creates `config/client.json` or `config/server.json` with your settings
6. Sets `CAP_NET_RAW` capability or runs with sudo
7. Optionally starts HTunnel for you

---
## �️ Installation Guide

### Step 1: System Requirements

**Required:**
- **Linux** operating system (kernel 4.x or newer)
- Root access or `CAP_NET_RAW` capability
- At least one network interface with public IP

**For building from source:**
- **Rust** toolchain (1.75+): [Install Rust](https://rustup.rs/)
- Git

### Step 2: Choose Installation Method

#### Method 1: Download Pre-built Binaries (Recommended) 📦

1. Visit the [GitHub Releases](https://github.com/Hiddify2/HTunnel/releases) page
2. Download the latest release for your architecture:

```bash
# For x86_64 systems - Download client
wget https://github.com/Hiddify2/HTunnel/releases/latest/download/HTunnel-client-linux-x86_64
chmod +x HTunnel-client-linux-x86_64

# Download server
wget https://github.com/Hiddify2/HTunnel/releases/latest/download/HTunnel-server-linux-x86_64
chmod +x HTunnel-server-linux-x86_64

# Optional: Rename and move to system path
sudo mv HTunnel-client-linux-x86_64 /usr/local/bin/client
sudo mv HTunnel-server-linux-x86_64 /usr/local/bin/server
```

**Note:** The binaries are standalone executables (not tar.gz archives). Just download, make executable, and run!

#### Method 2: Build from Source 🔧

```bash
# 1. Install Rust if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 2. Clone the repository
git clone https://github.com/Hiddify2/HTunnel.git
cd HTunnel

# 3. Build in release mode (optimized binary)
cargo build --release

# 4. Binaries are now in target/release/
ls -lh target/release/client target/release/server

# 5. Optional: Move to system path
sudo cp target/release/client target/release/server /usr/local/bin/
```

### Step 3: Verify Installation

```bash
# Check if binaries work
./client --help
./server --help

# Should display usage information
```

---

## ⚙️ Configuration Guide

### Understanding the Configuration Files

HTunnel uses **JSON** configuration files with support for comments. Two separate configs are needed:
- **Client config**: `config/client.json` - For the client machine
- **Server config**: `config/server.json` - For the server machine

### Step 1: Get Your IP Addresses

Before configuring, gather these IP addresses:

```bash
# Get your public IP (run on each machine)
curl -4 ifconfig.me
# or
ip -4 addr show | grep inet

# Note down:
# - Your real IP (real_ip)
# - Peer's real IP (peer_real_ip)
# - Decide on fake IPs for the pool (faked_ip, faked_ip_pool)
```

### Step 2: Configure the Server

Edit `config/server.json`:

```json
{
  // Listen address for tunnel data channel (0.0.0.0 means all interfaces)
  "listen": "0.0.0.0:51820",

  // Network interface (use "auto" for auto-detection)
  "interface": "eth0",

  // Server's real public IP
  "real_ip": "203.0.113.1",

  // Client's real public IP
  "peer_real_ip": "198.51.100.1",

  // Fake source IP for outgoing packets
  "faked_ip": "1.2.3.4",

  // Pool of fake IPs for rotation (optional)
  "faked_ip_pool": ["1.2.3.4", "5.6.7.8", "9.10.11.12"],

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

**Server Configuration Tips:**
- Use `"interface": "auto"` to auto-detect the network interface
- Add client's SOCKS5 proxy IP to `allowed_peers` if client uses a proxy
- `faked_ip_pool` enables IP rotation for better distribution

### Step 3: Configure the Client

Edit `config/client.json`:

```json
{
  // Local SOCKS5 proxy address (applications connect here)
  "listen": "127.0.0.1:9234",

  // Network interface (use "auto" for auto-detection)
  "interface": "eth0",

  // Client's real public IP
  "real_ip": "198.51.100.1",

  // Server's real public IP
  "peer_real_ip": "203.0.113.1",

  // Expected fake IP that server uses for replies
  "peer_fake_ip": "1.2.3.4",

  // UDP data channel port (must match server)
  "data_port": 51820,

  // Additional allowed server IPs
  "allowed_peers": [],

  // Performance settings
  "tunnel_count": 4,
  "mtu": 1380,
  "initial_cwnd": 10.0,

  // Upstream SOCKS5 proxy for uplink (host:port)
  // Leave as null if not using a proxy
  "uplink_proxy": "127.0.0.1:1081"
}
```

**Client Configuration Tips:**
- Set `listen` to a local address (e.g., `127.0.0.1:9234`)
- Configure your browser/app to use this SOCKS5 proxy
- Set `uplink_proxy` if you need to route through another SOCKS5 proxy

### Step 4: Set Up SOCKS5 Proxy (Optional)

If you need an upstream SOCKS5 proxy for the client uplink:

**Option 1: Using 3x-ui Panel (Recommended for VPN users)**

1. Create a new **Inbound** in your 3x-ui panel:
   - Protocol: **SOCKS**
   - Port: `1081` (or any port you prefer)
   - Network: **tcp,udp** (Mixed mode)
   - Enable UDP support

2. Create an **Outbound** rule:
   - Type: Your VPN configuration (VLESS, VMess, Trojan, etc.)
   - Link it to the SOCKS inbound you just created

3. Configure HTunnel client (`config/client.json`):
```json
{
  "listen": "127.0.0.1:9234",
  "interface": "eth0",
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

**Flow:** `App → HTunnel SOCKS5 (9234) → 3x-ui SOCKS5 Inbound (1081) → VPN Outbound → Internet`

**Option 2: Using Dante Server**

```bash
# Install dante-server
sudo apt install dante-server

# Configure /etc/danted.conf for UDP support
# Then start the service
sudo systemctl start danted

# Use in client config:
# "uplink_proxy": "127.0.0.1:1080"
```

**Option 3: Using Existing Proxy**

```json
{
  // Just configure the existing proxy IP:port
  "uplink_proxy": "proxy.example.com:1080"
}
```

### Step 5: Test Configuration

```bash
# Validate JSON syntax
cat config/server.json | jq .
cat config/client.json | jq .

# If you don't have jq:
# The config will be validated when you run the program
```

---

## 🚀 Running HTunnel

### Starting the Server

```bash
# Method 1: Using sudo (recommended for production)
sudo ./server --config config/server.json

# Method 2: Using capabilities (more secure)
sudo setcap cap_net_raw+ep ./server
./server --config config/server.json

# Expected output:
# INFO  HTunnel server starting | real=203.0.113.1 fake=1.2.3.4 peer=198.51.100.1
# INFO  Server listening on 0.0.0.0:51820
```

### Starting the Client

```bash
# Method 1: Using sudo
sudo ./client --config config/client.json

# Method 2: Using capabilities
sudo setcap cap_net_raw+ep ./client
./client --config config/client.json

# Expected output:
# INFO  HTunnel client starting | real=198.51.100.1 peer=203.0.113.1
# INFO  SOCKS5 proxy listening on 127.0.0.1:9234
```

### Testing the Connection

```bash
# On the client machine, test the SOCKS5 proxy
curl --socks5 127.0.0.1:9234 https://api.ipify.org?format=json

# Should return the server's fake IP or real IP
```

### Running as a Service (Systemd)

**Create server service:**

```bash
sudo nano /etc/systemd/system/htunnel-server.service
```

Add this content:
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

**Create client service:**

```bash
sudo nano /etc/systemd/system/htunnel-client.service
```

Add this content:
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

**Enable and start:**

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable htunnel-server  # on server
sudo systemctl enable htunnel-client  # on client

# Start services
sudo systemctl start htunnel-server
sudo systemctl start htunnel-client

# Check status
sudo systemctl status htunnel-server
sudo systemctl status htunnel-client

# View logs
sudo journalctl -u htunnel-server -f
sudo journalctl -u htunnel-client -f
```

---

## 🔧 Troubleshooting

### Common Issues

**1. Permission Denied (Raw Sockets)**
```bash
# Solution 1: Use sudo
sudo ./server --config config/server.json

# Solution 2: Set capabilities
sudo setcap cap_net_raw+ep ./server
./server --config config/server.json
```

**2. Port Already in Use**
```bash
# Check what's using the port
sudo netstat -tulpn | grep 51820

# Change port in config file
```

**3. Connection Issues**
```bash
# Check firewall rules
sudo iptables -L -n | grep 51820

# Allow port
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
```

**4. Invalid JSON Config**
```bash
# Validate JSON
cat config/server.json | jq .
# Fix any syntax errors
```

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
  Made with ❤️ By Hiddify Team
</p>
