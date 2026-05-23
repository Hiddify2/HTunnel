# HTunnel

> [!WARNING]
> **Educational Purpose Only**
>
> This project is created strictly for educational and research purposes.
> It is intended to demonstrate concepts, techniques, and implementation details in a controlled and ethical manner.
>
> The author is **not responsible** for any misuse, abuse, or damage caused by this project.
> Any actions performed using this code are the sole responsibility of the user.
>
> By using this project, you agree to use it **legally and ethically**.

**HTunnel** is a UDP tunnel with asymmetric transport:

- **Uplink (client → server)**: normal UDP sent through an upstream SOCKS5 proxy.
- **Downlink (server → client)**: faked UDP packets from a configurable IP pool.

This keeps uploads looking like regular SOCKS5 traffic while downloads are sparse faked packets.

## Architecture

```
[App] -> [Local SOCKS5] -> [Uplink SOCKS5 Proxy] -> [Server]
                                      ^
                                      |
                            faked UDP downlink
```

## Quick Start

### Prerequisites

- **Linux** (requires CAP_NET_RAW)
- Rust toolchain: `rustup update`
- Upstream SOCKS5 proxy for uplink UDP

### Build

```bash
cargo build --release
```

### Run

Server:

```bash
sudo ./target/release/server --config config/server.toml
```

Client:

```bash
sudo ./target/release/client --config config/client.toml
```

## Configuration (TOML)

HTunnel uses TOML config files in `config/`.

### Client

- `real_ip`: client real IPv4
- `peer_real_ip`: server real IPv4
- `peer_faked_ip`: server faked source IP (expected on downlink)
- `data_port`: UDP port (must match server)
- `allowed_peers`: extra source IPs to accept
- `interface`: network interface name
- `socks5_port`: local SOCKS5 listen port
- `uplink_proxy`: upstream SOCKS5 proxy (host:port)
- `tunnel_count`, `mtu`, `initial_cwnd`: performance tuning

### Server

- `real_ip`: server real IPv4
- `peer_real_ip`: client real IPv4
- `faked_ip`: faked source IP (required if pool is empty)
- `faked_ip_pool`: faked IP rotation pool
- `data_port`: UDP port (must match client)
- `allowed_peers`: allowlist for uplink sources (add proxy public IP here)
- `interface`: network interface name
- `tunnel_count`, `mtu`, `initial_cwnd`: performance tuning

Notes:

- If client uplink goes through a SOCKS5 proxy, add the proxy public IP to `allowed_peers` on the server.
- `peer_faked_ip` is optional on the server; use `allowed_peers` instead.

## License

MIT License. See [LICENSE](./LICENSE).

---

## Contributing

Bug reports and pull requests welcome. Please test changes thoroughly.

---

## Disclaimer

HTunnel is intended for **legitimate network research and educational purposes**. Ensure you have permission before:
- Sending faked packets
- Tunneling through network infrastructure you don't own
- Using this tool in any restricted network environment

**Respect local laws and network policies.**
