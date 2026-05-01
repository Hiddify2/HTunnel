//! UDP listener: server-side receiver for tunnel packets.
//!
//! Simple UDP socket that listens for incoming tunnel packets on the configured port.

use std::net::SocketAddr;
use std::sync::Arc;
use anyhow::{Context, Result};
use bytes::Bytes;

use crate::config::Config;
use crate::packet::CandyPacket;
use crate::tunnel::TunnelManager;
use crate::tun_bridge::{spawn_tunnel_to_tun, TunnelPool};

/// Start the UDP listener.
///
/// Listens for incoming tunnel packets on the configured UDP port.
pub async fn run_udp_listener(
    cfg: Arc<Config>,
    manager: TunnelManager,
    pool: TunnelPool,
    net_to_tun_tx: tokio::sync::mpsc::Sender<Bytes>,
) -> Result<()> {
    let listen_addr = format!("0.0.0.0:{}", cfg.data_port);
    let socket = tokio::net::UdpSocket::bind(&listen_addr)
        .await
        .with_context(|| format!("Failed to bind UDP listener on {}", listen_addr))?;

    log::info!("UDP listener listening on {}", listen_addr);

    let mut buf = vec![0u8; 65536];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer_addr)) => {
                let data = &buf[..n];
                let peer_ip = match peer_addr.ip() {
                    std::net::IpAddr::V4(ip) => ip,
                    _ => {
                        log::trace!("dropping IPv6 packet from {}", peer_addr);
                        continue;
                    }
                };

                // Check peer whitelist
                if !cfg.is_peer_allowed(&peer_ip) {
                    log::trace!("dropping packet from disallowed IP {}", peer_ip);
                    continue;
                }

                // Decode packet
                match CandyPacket::decode(Bytes::copy_from_slice(data)) {
                    Ok(pkt) => {
                        // Route packet through tunnel manager
                        match manager.handle_incoming(peer_ip, pkt).await {
                            Ok(Some((syn_pkt, _))) => {
                                // New tunnel SYN received - accept and add to pool
                                match manager.accept_syn(syn_pkt, peer_ip).await {
                                    Ok((tid, app_rx, net_tx)) => {
                                        pool.add_tunnel(tid, net_tx).await;
                                        spawn_tunnel_to_tun(app_rx, net_to_tun_tx.clone());
                                        log::info!(
                                            "Tunnel {} accepted from {} (UDP)",
                                            tid, peer_ip
                                        );
                                    }
                                    Err(e) => log::warn!("accept_syn error: {}", e),
                                }
                            }
                            Ok(None) => {}
                            Err(e) => log::debug!("handle_incoming error: {}", e),
                        }
                    }
                    Err(e) => {
                        log::trace!("Failed to decode packet from {}: {}", peer_ip, e);
                    }
                }
            }
            Err(e) => {
                log::warn!("UDP recv error: {}", e);
            }
        }
    }
}
