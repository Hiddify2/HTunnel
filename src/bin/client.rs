//! HTunnel **client** binary.
//!
//! Starts a local SOCKS5 proxy and connects it to the remote HTunnel server
//! via a UDP tunnel.
//!
//! Usage:
//!   cargo run --bin client -- --config config/client.toml

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::Parser;

use htunnel::config::Config;
use htunnel::raw_socket::RawReceiver;
use htunnel::socks5::run_socks5;
use htunnel::tunnel::{OutboundSender, PeerAddr, TunnelManager};
use htunnel::udp_proxy::UdpProxySender;

#[derive(Parser, Debug)]
#[command(name = "client", about = "HTunnel client (SOCKS5 proxy)")]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config/client.toml")]
    config: String,

    /// Override log level (e.g. debug, info, warn).
    #[arg(short, long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialise logging.
    let level = args
        .log_level
        .as_deref()
        .unwrap_or("info");
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let cfg = Arc::new(Config::from_file(&args.config)?);

    log::info!(
        "HTunnel client starting | real={} spoof={} peer={}",
        cfg.real_ip,
        cfg.spoofed_ip,
        cfg.peer_real_ip
    );

    let uplink_proxy = cfg
        .uplink_proxy
        .as_deref()
        .ok_or_else(|| anyhow!("client config missing uplink_proxy"))?;

    // Build the SOCKS5 UDP-associate sender for client uplink.
    let sender = UdpProxySender::connect(uplink_proxy).await?;
    let sender = OutboundSender::Proxy(sender);

    // Build the raw socket receiver (listens for spoofed UDP downlink).
    let mut allowed = cfg.allowed_peers.clone();
    allowed.push(cfg.peer_real_ip);
    allowed.push(cfg.peer_spoofed_ip);
    let mut receiver = RawReceiver::spawn(cfg.data_port, allowed)?;

    // Build the tunnel manager.
    let peer_addr = PeerAddr {
        local_spoof: cfg.pick_spoofed_ip(),
        peer_real:   cfg.peer_real_ip,
        data_port:   cfg.data_port,
        is_server:   false,
    };
    let manager = TunnelManager::new(sender, peer_addr, cfg.clone());

    // ── Background task: process incoming packets ─────────────────────────────
    let mgr2 = manager.clone();
    tokio::spawn(async move {
        loop {
            if let Some(incoming) = receiver.recv().await {
                // The server never initiates tunnels, so SYN packets are
                // unexpected on the client side – just log and ignore.
                if let Err(e) = mgr2
                    .handle_incoming(incoming.src_ip, incoming.pkt)
                    .await
                {
                    log::warn!("handle_incoming: {}", e);
                }
            }
        }
    });

    // ── Background task: periodic housekeeping (retransmit, heartbeat) ───────
    let mgr3 = manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            if let Err(e) = mgr3.tick().await {
                log::warn!("tick: {}", e);
            }
        }
    });

    // ── Foreground: SOCKS5 proxy ──────────────────────────────────────────────
    run_socks5(cfg, manager).await?;

    Ok(())
}
