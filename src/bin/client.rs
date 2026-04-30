//! HTunnel **client** binary.
//!
//! Creates a local TUN interface and forwards IP packets to the remote
//! HTunnel server via IP spoofing (UDP/ICMP). Client tunneling (upload)
//! is encapsulated via TCP uplink when configured; server responses are
//! spoofed.
//!
//! Usage:
//!   cargo run --bin client -- --config config/client-new.json

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use bytes::Bytes;
use clap::Parser;
use tokio::sync::mpsc;

use htunnel::config::Config;
use htunnel::raw_socket::{RawReceiver, RawSender};
use htunnel::tun::TunDevice;
use htunnel::tun_bridge::{
    run_tun_reader, spawn_tun_writer, spawn_tunnel_to_tun, TunnelPool,
};
use htunnel::tunnel::{PeerAddr, TunnelManager};

#[derive(Parser, Debug)]
#[command(name = "client", about = "htunnel client (TUN forwarder)")]
struct Args {
    /// Path to the JSON configuration file.
    #[arg(short, long, default_value = "config/client-new.json")]
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
        "htunnel client starting | real={} spoof={} peer={}",
        cfg.real_ip,
        cfg.spoofed_ip,
        cfg.peer_real_ip
    );

    // Build the raw socket sender.
    let sender = RawSender::spawn()?;

    // Build the raw socket receiver (listens for UDP data + ICMP control).
    let mut allowed = cfg.allowed_peers.clone();
    allowed.push(cfg.peer_real_ip);
    allowed.push(cfg.peer_spoofed_ip);
    let mut receiver = RawReceiver::spawn(cfg.protocol, cfg.data_port, cfg.icmp_id, allowed)?;

    // Build the tunnel manager.
    let peer_addr = PeerAddr {
        local_spoof: cfg.pick_spoofed_ip(),
        peer_real:   cfg.peer_real_ip,
        data_port:   cfg.data_port,
        icmp_id:     cfg.icmp_id,
        is_server:   false,
    };
    // Create an uplink channel (client) for TCP-encapsulated upload to server.
    let (uplink_tx, uplink_rx) = mpsc::channel::<Bytes>(4096);
    let manager = TunnelManager::new(sender, peer_addr, cfg.clone(), Some(uplink_tx));

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

    // ── Foreground: TUN + port forwarding ───────────────────────────────────
    run_tun_client(cfg, manager).await?;

    Ok(())
}

async fn run_tun_client(cfg: Arc<Config>, manager: TunnelManager) -> Result<()> {
    if cfg.tunnel_count == 0 {
        bail!("tunnel_count must be > 0");
    }
    if cfg.channel_capacity == 0 {
        bail!("channel_capacity must be > 0");
    }

    let tun_mtu = if cfg.tun_mtu == 0 {
        cfg.mtu
    } else {
        cfg.tun_mtu.min(cfg.mtu)
    };
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

    let forward_ports = cfg.effective_forward_ports();


    let pool = TunnelPool::new();

    let (net_to_tun_tx, net_to_tun_rx) = mpsc::channel::<Bytes>(cfg.channel_capacity);
    spawn_tun_writer(tun.clone(), net_to_tun_rx);

    for _ in 0..cfg.tunnel_count {
        let (tid, app_rx, net_tx) = manager.open_tunnel().await?;
        if !manager.wait_established(tid, Duration::from_secs(15)).await {
            bail!("tunnel {} handshake timed out", tid);
        }
        pool.add_tunnel(tid, net_tx).await;
        spawn_tunnel_to_tun(app_rx, net_to_tun_tx.clone());
    }

    log::info!("{} tunnels established", cfg.tunnel_count);

    log::info!(
        "TUN {} up ({} <-> {}) mtu {}",
        tun.name(),
        cfg.tun_ip,
        cfg.tun_peer_ip,
        tun.mtu()
    );

    if forward_ports.is_empty() {
        log::warn!("forward_ports empty - forwarding all TCP/UDP ports");
    } else {
        log::info!("forwarding TCP/UDP ports {:?}", forward_ports);
    }

    run_tun_reader(tun, pool, &forward_ports).await
}
