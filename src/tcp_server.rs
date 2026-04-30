//! TCP server listener: accept tunnel packets from clients over TCP.
//!
//! The server listens on a TCP port (derived from config) and accepts client
//! connections. For each client, packets are read from the TCP stream and
//! fed into the tunnel manager.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::packet::CandyPacket;
use crate::tunnel::TunnelManager;

/// Start the TCP server listener.
///
/// Listens for incoming client connections on the configured TCP port,
/// reads framed tunnel packets, and feeds them into the tunnel manager.
pub async fn run_tcp_server(
    cfg: Arc<Config>,
    manager: TunnelManager,
) -> Result<()> {
    // Derive listen address from config
    let listen_addr = format!("0.0.0.0:{}", cfg.data_port);

    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("Failed to bind TCP server on {}", listen_addr))?;

    log::info!("TCP server listening on {}", listen_addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let cfg_clone = cfg.clone();
                let mgr_clone = manager.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, peer_addr, cfg_clone, mgr_clone).await {
                        log::warn!("Client {} error: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                log::warn!("TCP accept error: {}", e);
                continue;
            }
        }
    }
}

/// Handle a single client connection.
///
/// Reads framed tunnel packets and routes them to the tunnel manager.
async fn handle_client(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    cfg: Arc<Config>,
    manager: TunnelManager,
) -> Result<()> {
    log::info!("Client connected from {}", peer_addr);

    let client_ip = match peer_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => {
            log::warn!("IPv6 not supported, closing connection");
            return Ok(());
        }
    };

    let mut buf = BytesMut::with_capacity(8192);

    loop {
        // Read frame length (4 bytes)
        if buf.len() < 4 {
            let mut tmp = vec![0u8; 4096];
            match stream.read(&mut tmp).await? {
                0 => {
                    log::info!("Client {} disconnected", peer_addr);
                    break;
                }
                n => {
                    buf.extend_from_slice(&tmp[..n]);
                }
            }
        }

        // Process complete frames
        while buf.len() >= 4 {
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

            // Sanity check
            if len > 65536 {
                log::warn!("Frame length too large: {}", len);
                return Ok(());
            }

            if buf.len() < 4 + len {
                // Incomplete frame, read more
                break;
            }

            // Extract frame payload
            let payload = buf[4..4 + len].to_vec();
            buf.advance(4 + len);

            // Decode as CandyPacket
            match CandyPacket::decode(Bytes::from(payload)) {
                Ok(pkt) => {
                    // Check peer whitelist
                    if !cfg.is_peer_allowed(&client_ip) {
                        log::trace!("Dropping packet from disallowed IP {}", client_ip);
                        continue;
                    }

                    // Route packet through tunnel manager
                    match manager.handle_incoming(client_ip, pkt).await {
                        Ok(Some((syn_pkt, _))) => {
                            // New tunnel SYN received
                            match manager.accept_syn(syn_pkt, client_ip).await {
                                Ok((tid, _app_rx, _net_tx)) => {
                                    log::info!(
                                        "Tunnel {} accepted from {} (TCP)",
                                        tid, client_ip
                                    );
                                }
                                Err(e) => log::warn!("accept_syn error: {}", e),
                            }
                        }
                        Ok(None) => {}
                        Err(e) => log::warn!("handle_incoming error: {}", e),
                    }
                }
                Err(e) => {
                    log::trace!("Failed to decode packet from {}: {}", client_ip, e);
                }
            }
        }
    }

    log::info!("Client handler for {} finished", peer_addr);
    Ok(())
}

// Helper to consume the BytesMut buffer
trait BufAdvance {
    fn advance(&mut self, cnt: usize);
}

impl BufAdvance for BytesMut {
    fn advance(&mut self, cnt: usize) {
        let _ = self.split_to(cnt);
    }
}
