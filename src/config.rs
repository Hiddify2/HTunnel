//! Configuration types for HTunnel.
//!
//! Both client and server share this configuration schema. Load with
//! `Config::from_file("config/client.toml")`.

use std::net::Ipv4Addr;
use serde::Deserialize;

/// Top-level configuration loaded from a TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// The real (physical) IPv4 address of this node.
    pub real_ip: Ipv4Addr,

    /// The real IPv4 address of the remote peer.
    pub peer_real_ip: Ipv4Addr,

    /// The faked source IP this node puts in outgoing packets (server only).
    #[serde(default)]
    pub faked_ip: Option<Ipv4Addr>,

    /// The faked source IP the peer uses (expected in incoming packets).
    /// Client uses this to accept downlink packets; server may omit it.
    #[serde(default)]
    pub peer_faked_ip: Option<Ipv4Addr>,

    /// Optional pool of faked IPs for rotation (server only). If empty,
    /// `faked_ip` is used.
    #[serde(default)]
    pub faked_ip_pool: Vec<Ipv4Addr>,

    /// UDP destination port used for the data channel.
    pub data_port: u16,

    /// Whitelist of peer real IPs whose packets are accepted. In addition to
    /// `peer_real_ip`, any address in this list is trusted.
    #[serde(default)]
    pub allowed_peers: Vec<Ipv4Addr>,

    /// Number of independent parallel tunnels to maintain.
    #[serde(default = "default_tunnel_count")]
    pub tunnel_count: usize,

    /// Network interface name to bind raw sockets to (e.g. "eth0", "ens3").
    pub interface: String,

    /// Port for the local SOCKS5 proxy (client only, ignored on server).
    #[serde(default = "default_socks5_port")]
    pub socks5_port: u16,

    /// SOCKS5 proxy (host:port) used for client uplink UDP.
    /// Server ignores this field.
    #[serde(default)]
    pub uplink_proxy: Option<String>,

    /// Maximum payload size per tunnel packet (bytes, default 1380).
    #[serde(default = "default_mtu")]
    pub mtu: usize,

    /// Initial congestion window in packets.
    #[serde(default = "default_cwnd")]
    pub initial_cwnd: f64,
}

fn default_tunnel_count() -> usize { 4 }
fn default_socks5_port() -> u16 { 1080 }
fn default_mtu() -> usize { 1380 }
fn default_cwnd() -> f64 { 10.0 }

impl Config {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Cannot read config '{}': {}", path, e))?;
        toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Invalid config '{}': {}", path, e))
    }

    /// Returns true if `ip` is a trusted peer address.
    pub fn is_peer_allowed(&self, ip: &Ipv4Addr) -> bool {
        *ip == self.peer_real_ip
            || self.peer_faked_ip.is_some_and(|p| *ip == p)
            || self.allowed_peers.contains(ip)
    }

    /// Pick a (possibly random) faked source IP from the configured pool.
    /// Falls back to `faked_ip` when the pool is empty.
    pub fn pick_faked_ip(&self) -> anyhow::Result<Ipv4Addr> {
        if self.faked_ip_pool.is_empty() {
            return self
                .faked_ip
                .ok_or_else(|| anyhow::anyhow!("faked_ip is required for server"));
        }
        use rand::seq::SliceRandom;
        if let Some(ip) = self
            .faked_ip_pool
            .choose(&mut rand::thread_rng())
            .copied()
        {
            return Ok(ip);
        }
        self
            .faked_ip
            .ok_or_else(|| anyhow::anyhow!("faked_ip is required for server"))
    }
}
