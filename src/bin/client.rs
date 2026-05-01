//! HTunnel **client** binary.
//!
//! Starts a local SOCKS5 proxy and connects it to the remote HTunnel server
//! via a SOCKS5 UDP uplink and spoofed UDP downlink.

use std::sync::Arc;
use std::time::Duration;
use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use clap::Parser;

use htunnel::config::{Config, OutboundConfig, ClientUplinkConfig, ClientDownlinkConfig, DEFAULT_MTU, DEFAULT_CWND};
use htunnel::raw_socket::RawReceiver;
use htunnel::socks5::run_socks5_addr;
use htunnel::socks5_uplink::Socks5Uplink;
use htunnel::tunnel::{OutboundTransport, TunnelManager};

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

    let (server_addr_str, encryption, uplink_cfg, downlink_cfg) = match htunnel_outbound {
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
    let (transport, listen_addr_str, excepted_ips) = match downlink_cfg {
        ClientDownlinkConfig::Fake { transport, listen, excepted_fake_ip_pool } => {
            (transport, listen, excepted_fake_ip_pool)
        }
    };

    let listen_addr: SocketAddr = listen_addr_str.parse()
        .with_context(|| format!("Invalid downlink listen address: {}", listen_addr_str))?;

    // We only support UDP for fake transport in this refactor as per requirements.
    if transport != "udp" {
        bail!("Only 'udp' transport is supported for fake downlink");
    }

    // On the client, the RawReceiver listens for packets coming from the server.
    // The server will use one of its spoofed IPs.
    // For simplicity, we'll allow any IP for now, or we could filter by the server's real IP.
    // The old code used allowed_peers.
    let mut allowed = excepted_ips.clone();
    if let SocketAddr::V4(v4) = server_addr {
        allowed.push(*v4.ip());
    }
    
    // Note: RawReceiver::spawn needs data_port and icmp_id.
    // In the new config, we'll use the port from the listen address.
    let mut receiver = RawReceiver::spawn(listen_addr.port(), 0, allowed)?;

    // 3. Initialize TunnelManager
    let outbound = OutboundTransport::Socks5Uplink {
        relay: uplink,
        server_addr,
    };
    let manager = TunnelManager::new(outbound, DEFAULT_MTU, DEFAULT_CWND);

    // ── Background task: process incoming packets (Downlink) ──────────────────
    let mgr2 = manager.clone();
    tokio::spawn(async move {
        loop {
            if let Some(incoming) = receiver.recv().await {
                if let Err(e) = mgr2.handle_incoming(incoming.src_ip, incoming.pkt).await {
                    log::warn!("handle_incoming error: {}", e);
                }
            }
        }
    });

    // ── Background task: periodic housekeeping ────────────────────────────────
    let mgr3 = manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            if let Err(e) = mgr3.tick().await {
                log::warn!("tick error: {}", e);
            }
        }
    });

    // ── Foreground: SOCKS5 proxy (Inbound) ───────────────────────────────────
    // Find the SOCKS inbound
    let socks_inbound = cfg.inbounds.iter().find_map(|i| {
        if let HTunnel::config::InboundConfig::Socks { listen } = i {
            Some(listen)
        } else {
            None
        }
    }).context("No SOCKS inbound found in config")?;

    let socks_listen_addr: SocketAddr = socks_inbound.parse()?;
    
    // We need to adapt run_socks5 to the new config or just use the listen addr.
    // For now, I'll modify run_socks5 to take a SocketAddr.
    HTunnel::socks5::run_socks5_addr(socks_listen_addr, manager, DEFAULT_MTU).await?;

    Ok(())
}
