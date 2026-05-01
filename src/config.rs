//! Configuration types for HTunnel.
//!
//! Supports loading JSON config files from `config/*-new.json`.
//! The application extracts tunnel parameters from `inbounds` (server listen,
//! spoofed pool) and `outbounds` (client uplink, server egress mode).

use std::net::{Ipv4Addr, SocketAddr};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProtocol {
    Udp,
    Icmp,
}

/// Server or client outbound/upstream mode.
#[derive(Debug, Clone)]
pub enum OutboundMode {
    Direct,
    Socks { server: String, port: u16 },
}

/// Top-level runtime configuration used by HTunnel.
/// Fields are populated from JSON config, with sensible defaults for omitted values.
#[derive(Debug, Clone)]
pub struct Config {
    pub real_ip: Ipv4Addr,
    pub peer_real_ip: Ipv4Addr,
    pub spoofed_ip: Ipv4Addr,
    pub peer_spoofed_ip: Ipv4Addr,
    pub spoofed_ip_pool: Vec<Ipv4Addr>,
    pub protocol: TunnelProtocol,
    pub data_port: u16,
    pub icmp_id: u16,
    pub allowed_peers: Vec<Ipv4Addr>,
    pub tunnel_count: usize,
    pub pre_shared_key: String,  // Kept for compatibility, but not used
    pub interface: String,
    pub tun_name: String,
    pub tun_ip: Ipv4Addr,
    pub tun_peer_ip: Ipv4Addr,
    pub tun_netmask: Ipv4Addr,
    pub mtu: usize,
    pub tun_mtu: usize,
    pub channel_capacity: usize,
    pub forward_ports: Vec<u16>,
    pub forward_port: u16,
    /// Server-side: listen address for tunnel packets (e.g., "0.0.0.0:1081")
    pub server_listen: Option<String>,
    /// Client-side: SOCKS inbound listen for local connections (e.g., "127.0.0.1:1080")
    pub socks_listen: Option<String>,
    /// Client-side: SOCKS5 proxy port (parsed from socks_listen)
    pub socks5_port: u16,
    /// Server outbound mode (direct or socks upstream for tunnel egress)
    pub outbound: Option<OutboundMode>,
    /// Client uplink: upstream proxy to send tunnel packets through (TCP encapsulation)
    pub client_uplink: Option<OutboundMode>,
}

impl Config {
    /// Load configuration from a JSON file.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Cannot read config '{}': {}", path, e))?;

        let v: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("invalid JSON config '{}': {}", path, e))?;

        let mut cfg = Self::default();

        // Parse inbounds
        if let Some(inbounds) = v.get("inbounds").and_then(|o| o.as_array()) {
            for ib in inbounds {
                if let Some(t) = ib.get("type").and_then(|s| s.as_str()) {
                    match t {
                        "HTunnel" => {
                            // Server-side inbound
                            if let Some(listen) = ib.get("listen").and_then(|s| s.as_str()) {
                                cfg.server_listen = Some(listen.to_string());
                                if let Ok(sa) = listen.parse::<SocketAddr>() {
                                    cfg.data_port = sa.port();
                                }
                            }

                            // Extract spoofed IP pool and protocol from client_downlink
                            if let Some(cd) = ib.get("client_downlink") {
                                if let Some(transport) = cd.get("transport").and_then(|s| s.as_str()) {
                                    cfg.protocol = match transport.to_lowercase().as_str() {
                                        "icmp" => TunnelProtocol::Icmp,
                                        _ => TunnelProtocol::Udp,
                                    };
                                }

                                // Parse fake_ip_pool (spoofed IPs)
                                if let Some(pool) = cd.get("fake_ip_pool").and_then(|a| a.as_array()) {
                                    let mut ips = Vec::new();
                                    for ipv in pool {
                                        if let Some(s) = ipv.as_str() {
                                            if let Ok(ip) = s.parse::<Ipv4Addr>() {
                                                ips.push(ip);
                                            }
                                        }
                                    }
                                    if !ips.is_empty() {
                                        cfg.spoofed_ip_pool = ips.clone();
                                        if cfg.spoofed_ip == Ipv4Addr::new(0, 0, 0, 0) {
                                            cfg.spoofed_ip = ips[0];
                                        }
                                    }
                                }

                                // Extract target (client IP for server to send to)
                                if let Some(target) = cd.get("target").and_then(|s| s.as_str()) {
                                    if let Ok(sa) = target.parse::<SocketAddr>() {
                                        cfg.peer_real_ip = match sa.ip() {
                                            std::net::IpAddr::V4(a) => a,
                                            _ => cfg.peer_real_ip,
                                        };
                                    }
                                }
                            }
                        }
                        "socks" => {
                            // Client-side SOCKS inbound
                            if let Some(listen) = ib.get("listen").and_then(|s| s.as_str()) {
                                cfg.socks_listen = Some(listen.to_string());
                                // Parse port from listen address
                                if let Ok(sa) = listen.parse::<SocketAddr>() {
                                    cfg.socks5_port = sa.port();
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Parse outbounds
        if let Some(outbounds) = v.get("outbounds").and_then(|o| o.as_array()) {
            for ob in outbounds {
                if let Some(t) = ob.get("type").and_then(|s| s.as_str()) {
                    match t {
                        "HTunnel" => {
                            // Client-side HTunnel outbound
                            if let Some(server) = ob.get("server").and_then(|s| s.as_str()) {
                                if let Ok(sa) = server.parse::<SocketAddr>() {
                                    cfg.peer_real_ip = match sa.ip() {
                                        std::net::IpAddr::V4(a) => a,
                                        _ => cfg.peer_real_ip,
                                    };
                                    cfg.data_port = sa.port();
                                }
                            }

                            // Parse client_uplink (upstream proxy for tunnel upload)
                            if let Some(u) = ob.get("client_uplink") {
                                if let Some(typ) = u.get("type").and_then(|s| s.as_str()) {
                                    match typ {
                                        "socks" => {
                                            if let (Some(srv), Some(port)) = (
                                                u.get("server").and_then(|s| s.as_str()),
                                                u.get("port").and_then(|p| p.as_u64()),
                                            ) {
                                                cfg.client_uplink = Some(OutboundMode::Socks {
                                                    server: srv.to_string(),
                                                    port: port as u16,
                                                });
                                            }
                                        }
                                        "direct" => {
                                            cfg.client_uplink = Some(OutboundMode::Direct);
                                        }
                                        _ => {}
                                    }
                                }
                            }

                            // Parse client_downlink (spoofed response channel)
                            if let Some(cd) = ob.get("client_downlink") {
                                if let Some(transport) = cd.get("transport").and_then(|s| s.as_str()) {
                                    cfg.protocol = match transport.to_lowercase().as_str() {
                                        "icmp" => TunnelProtocol::Icmp,
                                        _ => TunnelProtocol::Udp,
                                    };
                                }

                                if let Some(pool) = cd.get("excepted_fake_ip_pool").and_then(|a| a.as_array()) {
                                    let mut ips = Vec::new();
                                    for ipv in pool {
                                        if let Some(s) = ipv.as_str() {
                                            if let Ok(ip) = s.parse::<Ipv4Addr>() {
                                                ips.push(ip);
                                            }
                                        }
                                    }
                                    if !ips.is_empty() {
                                        cfg.spoofed_ip_pool = ips.clone();
                                        if cfg.spoofed_ip == Ipv4Addr::new(0, 0, 0, 0) {
                                            cfg.spoofed_ip = ips[0];
                                        }
                                    }
                                }
                            }
                        }
                        "direct" => {
                            cfg.outbound = Some(OutboundMode::Direct);
                        }
                        "socks" => {
                            if let (Some(srv), Some(port)) = (
                                ob.get("server").and_then(|s| s.as_str()),
                                ob.get("port").and_then(|p| p.as_u64()),
                            ) {
                                cfg.outbound = Some(OutboundMode::Socks {
                                    server: srv.to_string(),
                                    port: port as u16,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(cfg)
    }

    /// Returns true if `ip` is a trusted peer address.
    pub fn is_peer_allowed(&self, ip: &Ipv4Addr) -> bool {
        *ip == self.peer_real_ip
            || *ip == self.peer_spoofed_ip
            || self.allowed_peers.contains(ip)
    }

    /// Pick a (possibly random) spoofed source IP from the configured pool.
    /// Falls back to `spoofed_ip` when the pool is empty.
    pub fn pick_spoofed_ip(&self) -> Ipv4Addr {
        if self.spoofed_ip_pool.is_empty() {
            return self.spoofed_ip;
        }
        use rand::seq::SliceRandom;
        *self
            .spoofed_ip_pool
            .choose(&mut rand::thread_rng())
            .unwrap_or(&self.spoofed_ip)
    }

    /// Normalized client port filter list. Empty means "no filter".
    pub fn effective_forward_ports(&self) -> Vec<u16> {
        let mut ports = if !self.forward_ports.is_empty() {
            self.forward_ports.clone()
        } else if self.forward_port != 0 {
            vec![self.forward_port]
        } else {
            Vec::new()
        };

        ports.retain(|p| *p != 0);
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            real_ip: Ipv4Addr::new(0, 0, 0, 0),
            peer_real_ip: Ipv4Addr::new(0, 0, 0, 0),
            spoofed_ip: Ipv4Addr::new(0, 0, 0, 0),
            peer_spoofed_ip: Ipv4Addr::new(0, 0, 0, 0),
            spoofed_ip_pool: Vec::new(),
            protocol: TunnelProtocol::Udp,
            data_port: 1081,
            icmp_id: 0x4321,
            allowed_peers: Vec::new(),
            tunnel_count: 4,
            pre_shared_key: String::new(),
            interface: "eth0".to_string(),
            tun_name: "candy0".to_string(),
            tun_ip: Ipv4Addr::new(10, 66, 0, 2),
            tun_peer_ip: Ipv4Addr::new(10, 66, 0, 1),
            tun_netmask: Ipv4Addr::new(255, 255, 255, 252),
            mtu: 1380,
            tun_mtu: 1380,
            channel_capacity: 4096,
            forward_ports: Vec::new(),
            forward_port: 0,
            server_listen: None,
            socks_listen: None,
            socks5_port: 1080,
            outbound: None,
            client_uplink: None,
        }
    }
}
