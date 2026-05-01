//! Configuration system for HTunnel.
//!
//! Supports the new JSON-based schema with modular inbounds and outbounds.

use std::net::{Ipv4Addr, SocketAddr};
use serde::{Deserialize, Serialize};

/// Top-level configuration container.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InboundConfig {
    Socks {
        listen: String,
    },
    HTunnel {
        listen: String,
        encryption: ServerEncryptionConfig,
        client_downlink: ServerDownlinkConfig,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutboundConfig {
    Direct,
    Socks {
        server: String,
        port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    HTunnel {
        server: String,
        encryption: ClientEncryptionConfig,
        client_uplink: ClientUplinkConfig,
        client_downlink: ClientDownlinkConfig,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientEncryptionConfig {
    pub server_password: String,
    pub client_password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerEncryptionConfig {
    pub server_password: String,
    pub client_passwords: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientUplinkConfig {
    Socks {
        server: String,
        port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientDownlinkConfig {
    Fake {
        transport: String,
        listen: String,
        #[serde(default)]
        excepted_fake_ip_pool: Vec<Ipv4Addr>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerDownlinkConfig {
    Fake {
        transport: String,
        target: String,
        #[serde(default)]
        fake_ip_pool: Vec<Ipv4Addr>,
    },
}

impl Config {
    /// Load configuration from a JSON file.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Cannot read config '{}': {}", path, e))?;
        serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Invalid JSON config '{}': {}", path, e))
    }

    /// Helper to find the HTunnel outbound (client mode).
    pub fn get_htunnel_outbound(&self) -> Option<&OutboundConfig> {
        self.outbounds.iter().find(|o| matches!(o, OutboundConfig::HTunnel { .. }))
    }

    /// Helper to find the HTunnel inbound (server mode).
    pub fn get_htunnel_inbound(&self) -> Option<&InboundConfig> {
        self.inbounds.iter().find(|i| matches!(i, InboundConfig::HTunnel { .. }))
    }
}

/// Common defaults used across the app (retained from old version).
pub const DEFAULT_MTU: usize = 1380;
pub const DEFAULT_CWND: f64 = 10.0;
pub const HEARTBEAT_IDLE_TIMEOUT_SECS: u64 = 5;
pub const HEARTBEAT_MIN_INTERVAL_SECS: u64 = 2;
