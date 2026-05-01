//! TCP server listener: accept tunnel packets from clients over TCP.
//!
//! The server listens on a TCP port (derived from config) and accepts client
//! connections. For each client, packets are read from the TCP stream and
//! fed into the tunnel manager.

use std::net::SocketAddr;
use std::sync::Arc;
use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::packet::CandyPacket;
use crate::tunnel::TunnelManager;
use crate::tun_bridge::{spawn_tunnel_to_tun, TunnelPool};

/// Start the TCP server listener.
///
/// Listens for incoming client connections on the configured TCP port,
/// reads framed tunnel packets, and feeds them into the tunnel manager.
pub async fn run_tcp_server(
    cfg: Arc<Config>,
    manager: TunnelManager,
    pool: TunnelPool,
    net_to_tun_tx: tokio::sync::mpsc::Sender<Bytes>,
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
                let pool_clone = pool.clone();
                let tx_clone = net_to_tun_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, peer_addr, cfg_clone, mgr_clone, pool_clone, tx_clone).await {
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
/// Also spawns a task to forward responses back through the TCP connection.
async fn handle_client(
    stream: TcpStream,
    peer_addr: SocketAddr,
    cfg: Arc<Config>,
    manager: TunnelManager,
    pool: TunnelPool,
    net_to_tun_tx: tokio::sync::mpsc::Sender<Bytes>,
) -> Result<()> {
    log::info!("Client connected from {}", peer_addr);

    let client_ip = match peer_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => {
            log::warn!("IPv6 not supported, closing connection");
            return Ok(());
        }
    };

    // Split the stream for bidirectional communication
    let (mut tcp_reader, mut tcp_writer) = stream.into_split();

    // Channel for sending responses back through TCP
    let (tcp_tx, mut tcp_rx) = tokio::sync::mpsc::channel::<Bytes>(1024);

    // Store active tunnel IDs to clean up on disconnect
    let active_tunnels = Arc::new(std::sync::Mutex::new(Vec::<u32>::new()));
    let active_tunnels_write = active_tunnels.clone();

    // Spawn task to forward responses from channel to TCP stream
    let write_task = tokio::spawn(async move {
        while let Some(packet) = tcp_rx.recv().await {
            let len = packet.len() as u32;
            let mut frame = BytesMut::with_capacity(4 + packet.len());
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(&packet);

            if let Err(e) = tcp_writer.write_all(&frame).await {
                log::debug!("TCP write error: {}", e);
                break;
            }
        }
    });

    let mut buf = BytesMut::with_capacity(8192);

    loop {
        tokio::select! {
            // Handle incoming data from TCP
            read_result = read_frame(&mut tcp_reader, &mut buf) => {
                match read_result {
                    Ok(Some(payload)) => {
                        // Decode as CandyPacket
                        match CandyPacket::decode(payload) {
                            Ok(pkt) => {
                                // Check peer whitelist
                                if !cfg.is_peer_allowed(&client_ip) {
                                    log::trace!("Dropping packet from disallowed IP {}", client_ip);
                                    continue;
                                }

                                // Route packet through tunnel manager
                                match manager.handle_incoming(client_ip, pkt).await {
                                    Ok(Some((syn_pkt, _))) => {
                                        // New tunnel SYN received - accept and add to pool
                                        match manager.accept_syn(syn_pkt, client_ip).await {
                                            Ok((tid, app_rx, net_tx)) => {
                                                // Register TCP response channel for this tunnel
                                                manager.register_tcp_response(tid, tcp_tx.clone());
                                                active_tunnels_write.lock().unwrap().push(tid);

                                                pool.add_tunnel(tid, net_tx).await;
                                                spawn_tunnel_to_tun(app_rx, net_to_tun_tx.clone());
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
                    Ok(None) => {
                        log::info!("Client {} disconnected", peer_addr);
                        break;
                    }
                    Err(e) => {
                        log::debug!("TCP read error from {}: {}", peer_addr, e);
                        break;
                    }
                }
            }
            // If write task ends, we're done
            _ = &mut write_task => {
                break;
            }
        }
    }

    // Clean up: unregister TCP response channels for all tunnels
    let tunnels_to_clean = {
        let guard = active_tunnels.lock().unwrap();
        guard.clone()
    };
    for tid in tunnels_to_clean {
        manager.remove_tcp_response(tid);
    }

    log::info!("Client handler for {} finished", peer_addr);
    Ok(())
}

/// Read a framed packet from the TCP stream.
/// Returns Ok(Some(payload)) on success, Ok(None) on EOF, Err on error.
async fn read_frame(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    buf: &mut BytesMut,
) -> Result<Option<Bytes>> {
    // Ensure we have at least 4 bytes for length
    while buf.len() < 4 {
        let mut tmp = [0u8; 4096];
        match reader.read(&mut tmp).await? {
            0 => return Ok(None), // EOF
            n => buf.extend_from_slice(&tmp[..n]),
        }
    }

    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    // Sanity check
    if len > 65536 {
        bail!("Frame length too large: {}", len);
    }

    // Read more data if needed
    while buf.len() < 4 + len {
        let mut tmp = [0u8; 4096];
        match reader.read(&mut tmp).await? {
            0 => return Ok(None), // EOF
            n => buf.extend_from_slice(&tmp[..n]),
        }
    }

    // Extract payload
    let payload = Bytes::copy_from_slice(&buf[4..4 + len]);
    buf.advance(4 + len);
    Ok(Some(payload))
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
