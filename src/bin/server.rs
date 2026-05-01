//! HTunnel **server** binary.
//!
//! Listens for incoming tunnel connections from clients via standard UDP (uplink)
//! and sends responses via spoofed UDP (downlink).

use std::sync::Arc;
use std::time::Duration;
use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use HTunnel::config::{Config, InboundConfig, OutboundConfig, ServerDownlinkConfig, DEFAULT_MTU, DEFAULT_CWND};
use HTunnel::raw_socket::RawSender;
use HTunnel::tunnel::{OutboundTransport, TunnelManager};
use HTunnel::packet::CandyPacket;

#[derive(Parser, Debug)]
#[command(name = "server", about = "HTunnel server")]
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

    let cfg = Config::from_file(&args.config)?;
    let htunnel_inbound = cfg.get_htunnel_inbound()
        .context("No HTunnel inbound found in config")?;

    let (listen_addr_str, _encryption, downlink_cfg) = match htunnel_inbound {
        InboundConfig::HTunnel { listen, encryption, client_downlink } => {
            (listen, encryption, client_downlink)
        }
        _ => unreachable!(),
    };

    let listen_addr: SocketAddr = listen_addr_str.parse()
        .with_context(|| format!("Invalid listen address: {}", listen_addr_str))?;

    log::info!("HTunnel server starting. Listening on UDP: {}", listen_addr);

    // 1. Setup Raw Sender for Downlink
    let sender = RawSender::spawn()?;

    let (transport, target_addr_str, fake_ip_pool) = match downlink_cfg {
        ServerDownlinkConfig::Fake { transport, target, fake_ip_pool } => {
            (transport, target, fake_ip_pool)
        }
    };

    if transport != "udp" {
        bail!("Only 'udp' transport is supported for fake downlink");
    }

    let target_addr: SocketAddr = target_addr_str.parse()
        .with_context(|| format!("Invalid target address: {}", target_addr_str))?;

    let client_real = match target_addr {
        SocketAddr::V4(v4) => *v4.ip(),
        _ => bail!("Only IPv4 target addresses are supported for spoofing"),
    };

    // Pick a spoofed source IP
    let local_spoof = if fake_ip_pool.is_empty() {
        Ipv4Addr::new(1, 1, 1, 1)
    } else {
        fake_ip_pool[0]
    };

    // 2. Initialize TunnelManager
    let outbound = OutboundTransport::SpoofedDownlink {
        sender,
        client_real,
        local_spoof,
        data_port: target_addr.port(),
    };
    let manager = TunnelManager::new(outbound, DEFAULT_MTU, DEFAULT_CWND);

    // 3. Setup Standard UDP Socket for Uplink
    let udp_uplink = UdpSocket::bind(listen_addr).await
        .context("Failed to bind UDP uplink socket")?;

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

    // ── Main receive loop (Uplink) ───────────────────────────────────────────
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src_addr) = match udp_uplink.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("UDP recv_from error: {}", e);
                continue;
            }
        };

        let payload = &buf[..n];
        let pkt = match CandyPacket::decode(Bytes::copy_from_slice(payload)) {
            Ok(p) => p,
            Err(e) => {
                log::trace!("Failed to decode CandyPacket from {}: {}", src_addr, e);
                continue;
            }
        };

        let src_ip = match src_addr {
            SocketAddr::V4(v4) => *v4.ip(),
            _ => Ipv4Addr::new(0, 0, 0, 0),
        };

        match manager.handle_incoming(src_ip, pkt).await {
            Ok(Some((syn_pkt, src_ip))) => {
                let mgr2 = manager.clone();
                let cfg2 = Arc::new(cfg.clone());
                tokio::spawn(async move {
                    if let Err(e) = handle_new_tunnel(syn_pkt, src_ip, mgr2, cfg2).await {
                        log::warn!("session error: {}", e);
                    }
                });
            }
            Ok(None) => {}
            Err(e) => log::warn!("handle_incoming: {}", e),
        }
    }
}

async fn handle_new_tunnel(
    syn:     CandyPacket,
    src_ip:  Ipv4Addr,
    manager: TunnelManager,
    _cfg:     Arc<Config>,
) -> Result<()> {
    let (tunnel_id, mut app_rx, net_tx) = manager
        .accept_syn(syn, src_ip)
        .await
        .context("accept_syn")?;

    let first_msg = tokio::time::timeout(Duration::from_secs(15), app_rx.recv())
        .await
        .context("timeout waiting for CONNECT meta")?
        .context("tunnel closed before CONNECT meta")?;

    let first_msg_bytes = first_msg.context("empty CONNECT meta")?;
    let meta = String::from_utf8_lossy(&first_msg_bytes);
    let (target_host, target_port) = parse_connect_meta(&meta)?;

    log::info!("tunnel {} forwarding to {}:{}", tunnel_id, target_host, target_port);

    let target_addr = format!("{}:{}", target_host, target_port);
    let tcp_stream = TcpStream::connect(&target_addr).await
        .with_context(|| format!("connect to {}", target_addr))?;

    let (mut tcp_r, mut tcp_w) = tcp_stream.into_split();

    // Tunnel → TCP
    let t_to_tcp = tokio::spawn(async move {
        while let Some(data) = app_rx.recv().await {
            if tcp_w.write_all(&data).await.is_err() { break; }
        }
    });

    // TCP → tunnel
    let net_tx2 = net_tx;
    let tcp_to_t = tokio::spawn(async move {
        let mut buf = vec![0u8; DEFAULT_MTU];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = Bytes::copy_from_slice(&buf[..n]);
                    if net_tx2.send(chunk).await.is_err() { break; }
                }
            }
        }
    });

    tokio::select! {
        _ = t_to_tcp => {}
        _ = tcp_to_t => {}
    }

    manager.close_tunnel(tunnel_id).await;
    Ok(())
}

fn parse_connect_meta(meta: &str) -> Result<(String, u16)> {
    let rest = meta.strip_prefix("CONNECT ").context("missing CONNECT prefix")?;
    let (host, port_str) = rest.rsplit_once(':').context("missing ':'")?;
    let port = port_str.trim().parse::<u16>().context("invalid port")?;
    Ok((host.to_string(), port))
}
