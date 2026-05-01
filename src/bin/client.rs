//! HTunnel **client** binary.
//!
//! Starts a local SOCKS5 proxy and connects it to the remote HTunnel server
//! via a SOCKS5 UDP uplink and spoofed UDP downlink.

use std::sync::Arc;
use std::time::Duration;
use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, bail};
use clap::Parser;

use HTunnel::config::{Config, OutboundConfig, ClientUplinkConfig, ClientDownlinkConfig, DEFAULT_MTU};
use HTunnel::raw_socket::RawReceiver;
use HTunnel::socks5_uplink::Socks5Uplink;
use HTunnel::tunnel::{OutboundTransport, TunnelManager};

#[derive(Parser, Debug)]
#[command(name = "client", about = "HTunnel client")]
struct Args {
    /// Path to the JSON configuration file.
    #[arg(short, long, default_value = "config/client-new.json")]
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

    let cfg = Config::from_file(&args.config)?;
    let htunnel_outbound = cfg.get_htunnel_outbound()
        .context("No HTunnel outbound found in config")?;

    let (server_addr_str, _encryption, uplink_cfg, downlink_cfg) = match htunnel_outbound {
        OutboundConfig::HTunnel { server, encryption, client_uplink, client_downlink } => {
            (server, encryption, client_uplink, client_downlink)
        }
        _ => unreachable!(),
    };

    let server_addr: SocketAddr = server_addr_str.parse()
        .with_context(|| format!("Invalid server address: {}", server_addr_str))?;

    log::info!("HTunnel client starting. Server: {}", server_addr);

    // 1. Setup SOCKS5 Uplink
    let uplink = match uplink_cfg {
        ClientUplinkConfig::Socks { server, port, username, password } => {
            let relay = Socks5Uplink::connect(
                server,
                *port,
                username.as_deref(),
                password.as_deref(),
            ).await?;
            Arc::new(relay)
        }
    };

    // 2. Setup Raw Receiver for Downlink
    let (_transport, listen_addr_str, excepted_ips) = match downlink_cfg {
        ClientDownlinkConfig::Fake { transport, listen, excepted_fake_ip_pool } => {
            (transport, listen, excepted_fake_ip_pool)
        }
    };

    let listen_addr: SocketAddr = listen_addr_str.parse()
        .with_context(|| format!("Invalid downlink listen address: {}", listen_addr_str))?;

    let mut allowed = excepted_ips.clone();
    // Always allow unspecified (permissive mode) for now to ensure connectivity
    // while the user is still tuning their IP pools.
    if !allowed.contains(&Ipv4Addr::UNSPECIFIED) {
        allowed.push(Ipv4Addr::UNSPECIFIED);
    }
    if let SocketAddr::V4(v4) = server_addr {
        allowed.push(*v4.ip());
    }

    log::info!("Downlink RawReceiver listening on port {} (permissive: {})", listen_addr.port(), allowed.contains(&Ipv4Addr::UNSPECIFIED));
    let mut receiver = RawReceiver::spawn(listen_addr.port(), allowed)?;

    // 3. Initialize TunnelManager
    let outbound = OutboundTransport::Socks5Uplink {
        relay: uplink,
        server_addr,
    };
    let manager = TunnelManager::new(outbound);

    // ── Background task: process incoming packets (Downlink) ──────────────────
    let mgr_recv = manager.clone();
    tokio::spawn(async move {
        while let Some(incoming) = receiver.recv().await {
            if let Err(e) = mgr_recv.handle_incoming(incoming.src_ip, incoming.pkt).await {
                log::trace!("handle_incoming error: {}", e);
            }
        }
    });

    // ── Background task: periodic housekeeping ────────────────────────────────
    let mgr_tick = manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            if let Err(e) = mgr_tick.tick().await {
                log::warn!("tick error: {}", e);
            }
        }
    });

    // 4. Start Local SOCKS5 Proxy
    let socks_inbound = cfg.inbounds.iter().find_map(|i| {
        if let HTunnel::config::InboundConfig::Socks { listen } = i {
            Some(listen)
        } else {
            None
        }
    }).context("No SOCKS inbound found in config")?;

    let socks_listen_addr: SocketAddr = socks_inbound.parse()?;
    
    log::info!("SOCKS5 proxy starting on {}", socks_listen_addr);
    HTunnel::socks5::run_socks5_addr(socks_listen_addr, manager, DEFAULT_MTU).await?;

    Ok(())
}
