# HTunnel

**HTunnel** is an advanced IP tunneling system that uses **asymmetric transport** to evade network restrictions:

- **Uplink (Client → Server)**: Data flows through a TCP connection via an upstream SOCKS proxy
- **Downlink (Server → Client)**: Data returns as **spoofed IP packets** (UDP or ICMP) appearing to come from innocent IPs
- **Server Egress**: Server traffic can exit directly or through a SOCKS proxy (e.g., WARP)

This architecture makes tunnel traffic difficult to detect or block because:
- Upload packets look like normal SOCKS traffic, not VPN data
- Download packets are sparse spoofed packets that don't form a continuous connection
- The server can hide its true IP behind a proxy

---

## Architecture

```
┌─────────────┐
│   Client    │
│  (TUN app)  │
└────────┬────┘
         │ (Raw spoofed UDP/ICMP)
         │ (Download)
         │
         ├──→ [Server Response Packets - Spoofed IPs]
         │
         └──→ TCP SOCKS uplink (Upload to server via proxy)
              │
              ↓
         ┌─────────────┐
         │    SOCKS    │
         │   Proxy     │
         └─────────────┘
              │
              ↓
         ┌─────────────┐
         │   Server    │
         │  (TUN app)  │
         └─────┬───────┘
               │
               ├──→ [Outbound: Direct or via SOCKS proxy]
               │
               └──→ TUN interface
```

---

## Quick Start

### Prerequisites

- **Linux** (requires CAP_NET_RAW, CAP_NET_ADMIN)
- Rust toolchain: `rustup update`
- Local SOCKS proxy (e.g., Shadowsocks, WARP SOCKS endpoint)

### Build

```bash
cargo build --release
```

Binaries:
- `target/release/client` - HTunnel client
- `target/release/server` - HTunnel server

### Run

#### Server

```bash
sudo ./target/release/server --config config/server-new.json
```

#### Client

```bash
sudo ./target/release/client --config config/client-new.json
```

(Use `sudo` because both need to create and manage TUN interfaces.)

---

## Configuration

HTunnel uses **JSON configuration files** (not TOML).

### Client Configuration (`config/client-new.json`)

```json
{
  "inbounds": [
    {
      "type": "socks",
      "listen": "127.0.0.1:1080"
    }
  ],
  "outbounds": [
    {
      "type": "HTunnel",
      "server": "SERVER_IP:1081",
      "client_uplink": {
        "type": "socks",
        "server": "127.0.0.1",
        "port": 1080
      },
      "client_downlink": {
        "type": "fake",
        "transport": "udp",
        "listen": "CLIENT_IP:1081",
        "excepted_fake_ip_pool": ["8.8.4.4", "1.1.1.1"]
      }
    }
  ]
}
```

**Fields:**

| Field | Purpose |
|-------|---------|
| `inbounds[0].listen` | SOCKS proxy listen address (local) |
| `outbounds[0].server` | Server address and port (e.g., `example.com:1081`) |
| `outbounds[0].client_uplink.server` | Upstream SOCKS proxy (e.g., `127.0.0.1:1080` for local Shadowsocks) |
| `outbounds[0].client_uplink.port` | Upstream SOCKS proxy port |
| `outbounds[0].client_downlink.transport` | Protocol: `"udp"` or `"icmp"` |
| `outbounds[0].client_downlink.excepted_fake_ip_pool` | Spoofed IP pool for responses from server |

### Server Configuration (`config/server-new.json`)

```json
{
  "inbounds": [
    {
      "type": "HTunnel",
      "listen": "0.0.0.0:1081",
      "client_downlink": {
        "type": "fake",
        "transport": "udp",
        "target": "CLIENT_IP:1080",
        "fake_ip_pool": ["1.2.3.4", "5.6.7.8"]
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct"
    },
    {
      "type": "socks",
      "server": "127.0.0.1",
      "port": 1080
    }
  ]
}
```

**Fields:**

| Field | Purpose |
|-------|---------|
| `inbounds[0].listen` | Server listen address (receives tunnel setup packets) |
| `inbounds[0].client_downlink.target` | Client's real IP (where to send spoofed responses) |
| `inbounds[0].client_downlink.transport` | Protocol: `"udp"` or `"icmp"` |
| `inbounds[0].client_downlink.fake_ip_pool` | Pool of spoofed source IPs for responses |
| `outbounds[0]` | Route traffic directly (no proxy) |
| `outbounds[1]` | Route traffic via SOCKS proxy (e.g., WARP) |

**Select Outbound Mode:**
- First `outbound` entry with a `type` that matches the traffic is used.
- Usually, pick index 0 for `"direct"` or 1 for `"socks"` by reordering entries.

---

## How It Works

### Client-to-Server (Upload)

1. **User's App** connects to local SOCKS proxy (e.g., `127.0.0.1:1080`).
2. **Client** reads from TUN, creates tunnel packet.
3. **Client** sends packet through **upstream SOCKS proxy** (e.g., Shadowsocks) to reach the server.
4. **Server** receives packet on its UDP/ICMP socket.

### Server-to-Client (Download)

1. **Server** generates response (e.g., IP packet data).
2. **Server** wraps it in a spoofed UDP/ICMP packet.
3. **Server** sends with fake source IP from the pool (e.g., `8.8.4.4`).
4. **Client** receives spoofed packet on raw socket.
5. **Client** unwraps and writes to TUN.

### Key Asymmetry

- **Upload** flows through normal TCP (via SOCKS), easily blends in with web traffic.
- **Download** uses spoofed packets, scattered and low-volume, harder to detect as a tunnel.

---

## Configuration Tips

### 1. Fake IP Pool

Choose believable spoofed IPs to avoid suspicion:

**Good choices:**
- `8.8.4.4`, `8.8.8.8` (Google DNS)
- `1.1.1.1`, `1.0.0.1` (Cloudflare DNS)
- `208.67.222.222` (OpenDNS)

**Bad choices:**
- Private IPs (e.g., `192.168.x.x`)
- Reserved/bogon ranges
- Obviously fake IPs

### 2. Upstream SOCKS Proxy

Ensure your upstream SOCKS proxy:
- Runs on your local machine or a trusted network
- Supports SOCKS5 (minimum)
- Can handle both TCP CONNECT and UDP ASSOCIATE

Common options:
- **Shadowsocks**: `ss-local -c config.json`
- **WARP**: Use official SOCKS endpoint (if available)
- **Tor**: `socks5 127.0.0.1:9050`

### 3. Server Outbound

Decide how the server sends tunnel responses:

**Direct:**
```json
{ "type": "direct" }
```
Server sends traffic directly from its IP.

**Via SOCKS (e.g., WARP):**
```json
{
  "type": "socks",
  "server": "127.0.0.1",
  "port": 1080
}
```
Server routes tunnel responses through a proxy, hiding its true IP.

---

## Troubleshooting

### "Cannot create TUN device"

- Ensure you run as root or with `CAP_NET_ADMIN` and `CAP_NET_RAW`.
- On Linux, you may need to create `/dev/net/tun`:
  ```bash
  sudo mkdir -p /dev/net
  sudo mknod /dev/net/tun c 10 200
  ```

### "Tunnel handshake timed out"

- Check that the server is running and listening on the correct port.
- Verify firewall rules allow traffic on the tunnel port.
- Confirm the upstream SOCKS proxy is accessible and running.

### "Raw socket permission denied"

- Run with `sudo` or ensure CAP_NET_RAW:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=ep ./target/release/server
  sudo setcap cap_net_raw,cap_net_admin=ep ./target/release/client
  ```

### High latency / packet loss

- Check upstream SOCKS proxy performance.
- Verify network path to server (ping, traceroute).
- Increase `channel_capacity` in config (if specified).

---

## Performance Tuning

**MTU (Maximum Transmission Unit)**

Default: `1380` bytes.

For better performance on high-latency networks:
- Increase MTU if your network supports larger packets (test with `ping -M do -s 1400 destination`).
- Keep below the physical network MTU to avoid fragmentation.

**Tunnel Count**

Default: `4` parallel tunnels.

- Increase for higher throughput.
- Decrease if experiencing packet loss or congestion.

**Channel Capacity**

Default: `4096` packets per tunnel queue.

- Increase for bursty traffic.
- Decrease if memory is constrained.

---

## Security Considerations

1. **Spoofed Packets**: Because the server sends spoofed packets, some networks may drop them.
   - Use ISP-friendly IPs in your pool.
   - Test in your environment before deployment.

2. **No Encryption**: HTunnel does **not encrypt** tunnel payloads.
   - Use HTTPS or another encryption layer over the tunnel for sensitive data.

3. **Upstream SOCKS Proxy Security**:
   - Ensure your SOCKS proxy is trusted (use TLS/mTLS if possible).
   - Do not proxy through untrusted networks.

4. **IP Reputation**:
   - Spoofed IPs may be logged by the recipient's firewall.
   - Use the pool sparingly to avoid reputation damage.

---

## License

MIT License. See [LICENSE](./LICENSE) for details.

---

## Examples

### Example 1: Basic Setup (Local Testing)

**Server:**
```json
{
  "inbounds": [
    {
      "type": "HTunnel",
      "listen": "0.0.0.0:1081",
      "client_downlink": {
        "type": "fake",
        "transport": "udp",
        "target": "192.168.1.100:1081",
        "fake_ip_pool": ["8.8.8.8"]
      }
    }
  ],
  "outbounds": [
    { "type": "direct" }
  ]
}
```

**Client:**
```json
{
  "inbounds": [
    {
      "type": "socks",
      "listen": "127.0.0.1:1080"
    }
  ],
  "outbounds": [
    {
      "type": "HTunnel",
      "server": "192.168.1.200:1081",
      "client_uplink": {
        "type": "direct"
      },
      "client_downlink": {
        "type": "fake",
        "transport": "udp",
        "excepted_fake_ip_pool": ["8.8.8.8"]
      }
    }
  ]
}
```

### Example 2: Using WARP (Production)

**Server:**
```json
{
  "inbounds": [
    {
      "type": "HTunnel",
      "listen": "0.0.0.0:1081",
      "client_downlink": {
        "type": "fake",
        "transport": "udp",
        "target": "CLIENT_IP:1081",
        "fake_ip_pool": ["1.1.1.1", "8.8.8.8", "208.67.222.222"]
      }
    }
  ],
  "outbounds": [
    {
      "type": "socks",
      "server": "127.0.0.1",
      "port": 40000
    }
  ]
}
```

**Client:**
```json
{
  "inbounds": [
    {
      "type": "socks",
      "listen": "127.0.0.1:1080"
    }
  ],
  "outbounds": [
    {
      "type": "HTunnel",
      "server": "SERVER_IP:1081",
      "client_uplink": {
        "type": "socks",
        "server": "127.0.0.1",
        "port": 40001
      },
      "client_downlink": {
        "type": "fake",
        "transport": "udp",
        "excepted_fake_ip_pool": ["1.1.1.1", "8.8.8.8", "208.67.222.222"]
      }
    }
  ]
}
```

(Run WARP SOCKS proxies on ports 40000 and 40001 respectively.)

---

## Contributing

Bug reports and pull requests welcome. Please test changes thoroughly.

---

## Disclaimer

HTunnel is intended for **legitimate network research and educational purposes**. Ensure you have permission before:
- Sending spoofed packets
- Tunneling through network infrastructure you don't own
- Using this tool in any restricted network environment

**Respect local laws and network policies.**
