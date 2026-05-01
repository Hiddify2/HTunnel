//! HTunnel **server** binary.
//!
//! Listens for incoming tunnel connections from clients and forwards IP
//! packets between the TUN interface and the tunnel network. Supports both
//! direct and SOCKS-based outbound modes for tunnel egress traffic.
//!
//! Usage:
//!   cargo run --bin server -- --config config/server-new.json

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use bytes::Bytes;
use clap::Parser;
use tokio::sync::mpsc;

use HTunnel::config::Config;
use HTunnel::raw_socket::RawSender;
use HTunnel::tun::TunDevice;
use HTunnel::tun_bridge::{
    run_tun_reader, spawn_tun_writer, spawn_tunnel_to_tun, TunnelPool,
};
use HTunnel::tunnel::{PeerAddr, TunnelManager};
use HTunnel::udp_listener::run_udp_listener;
use HTunnel::tcp_server::run_tcp_server;

#[derive(Parser, Debug)]
#[command(name = "server", about = "HTunnel server (tunnel endpoint)")]
struct Args {
    /// Path to the JSON configuration file.
    #[arg(short, long, default_value = "config/server-new.json")]
    config: String,

    /// Override log level.
    #[arg(short, long)]
    log_level: Option<String>,
}


#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let level = args.log_level.as_deref().unwrap_or("info");
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let cfg = Arc::new(Config::from_file(&args.config)?);

    if cfg.channel_capacity == 0 {
        bail!("channel_capacity must be > 0");
    }

    log::info!(
        "HTunnel server starting | real={} spoof={} peer={}",
        cfg.real_ip,
        cfg.spoofed_ip,
        cfg.peer_real_ip
    );

    let sender = RawSender::spawn()?;

    let peer_addr = PeerAddr {
        local_spoof: cfg.pick_spoofed_ip(),
        peer_real:   cfg.peer_real_ip,
        data_port:   cfg.data_port,
        icmp_id:     cfg.icmp_id,
        is_server:   true,
    };
    let manager = TunnelManager::new(sender, peer_addr, cfg.clone(), None);

    let tun_mtu = if cfg.tun_mtu == 0 { cfg.mtu } else { cfg.tun_mtu.min(cfg.mtu) };
    if cfg.tun_mtu > cfg.mtu {
        log::warn!("tun_mtu {} > mtu {} - clamping", cfg.tun_mtu, cfg.mtu);
    }

    let tun = Arc::new(TunDevice::create(
        &cfg.tun_name,
        cfg.tun_ip,
        cfg.tun_peer_ip,
        cfg.tun_netmask,
        tun_mtu,
    )?);

    let pool = TunnelPool::new();

    let (net_to_tun_tx, net_to_tun_rx) = mpsc::channel::<Bytes>(cfg.channel_capacity);
    spawn_tun_writer(tun.clone(), net_to_tun_rx);

    // TUN -> tunnel forwarding (no port filter on server).
    let tun_reader = tun.clone();
    let pool_reader = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = run_tun_reader(tun_reader, pool_reader, &[]).await {
            log::warn!("tun reader stopped: {}", e);
        }
    });

    log::info!(
        "TUN {} up ({} <-> {}) mtu {}",
        tun.name(),
        cfg.tun_ip,
        cfg.tun_peer_ip,
        tun.mtu()
    );

    // ── Spawn UDP listener for direct UDP packets ────────────────────────────
    let cfg_udp = cfg.clone();
    let mgr_udp = manager.clone();
    let pool_udp = pool.clone();
    let tx_udp = net_to_tun_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = run_udp_listener(cfg_udp, mgr_udp, pool_udp, tx_udp).await {
            log::error!("UDP listener error: {}", e);
        }
    });

    // ── Spawn TCP server for SOCKS tunnel clients ────────────────────────────
    let cfg_tcp = cfg.clone();
    let mgr_tcp = manager.clone();
    let pool_tcp = pool.clone();
    let tx_tcp = net_to_tun_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = run_tcp_server(cfg_tcp, mgr_tcp, pool_tcp, tx_tcp).await {
            log::error!("TCP server error: {}", e);
        }
    });

    // ── Periodic housekeeping ────────────────────────────────────────────────
    let mgr_tick = manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            if let Err(e) = mgr_tick.tick().await {
                log::warn!("tick: {}", e);
            }
        }
    });

    // ── Main loop: just wait for shutdown ────────────────────────────────────
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
