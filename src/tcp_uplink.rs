//! TCP uplink: client-side connector to upstream SOCKS proxy.
//!
//! Establishes a SOCKS5 connection to an upstream proxy, performs CONNECT to the
//! server, and relays framed tunnel packets over the TCP stream.

use std::net::{Ipv4Addr, SocketAddr};
use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::packet::CandyPacket;
use crate::tunnel::TunnelManager;

/// SOCKS5 authentication methods
const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_NOACCEPT: u8 = 0xff;

/// SOCKS5 command codes
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_RESP_SUCCESS: u8 = 0x00;

/// Address type codes
const ATYP_IPV4: u8 = 0x01;

/// Start the TCP uplink handler.
///
/// Connects to the upstream SOCKS proxy, performs CONNECT to the server,
/// then relays framed packets from the uplink channel over the TCP stream.
pub async fn spawn_tcp_uplink(
    upstream: &str,
    server_addr: Ipv4Addr,
    server_port: u16,
    mut uplink_rx: mpsc::Receiver<Bytes>,
    manager: TunnelManager,
) -> Result<()> {
    // Parse upstream proxy address
    let upstream_addr = upstream.parse::<SocketAddr>()
        .with_context(|| format!("Invalid upstream proxy address: {}", upstream))?;

    // Connect to upstream SOCKS proxy
    let mut stream = TcpStream::connect(upstream_addr)
        .await
        .with_context(|| format!("Cannot connect to SOCKS proxy: {}", upstream_addr))?;

    log::info!("Connected to upstream SOCKS proxy at {}", upstream_addr);

    // Perform SOCKS5 handshake
    perform_socks5_auth(&mut stream).await?;

    // Send CONNECT request to the server
    perform_socks5_connect(&mut stream, server_addr, server_port).await?;

    log::info!("SOCKS5 tunnel established to {}:{}", server_addr, server_port);

    let (mut tcp_reader, mut tcp_writer) = stream.into_split();
    let mut read_buf = BytesMut::with_capacity(8192);

    loop {
        tokio::select! {
            maybe_packet = uplink_rx.recv() => {
                match maybe_packet {
                    Some(packet) => {
                        send_framed_packet(&mut tcp_writer, &packet).await?;
                    }
                    None => {
                        log::info!("TCP uplink channel closed");
                        return Ok(());
                    }
                }
            }
            read_result = read_frame(&mut tcp_reader, &mut read_buf) => {
                match read_result {
                    Ok(Some(payload)) => {
                        if let Ok(pkt) = CandyPacket::decode(payload) {
                            if let Err(e) = manager.handle_incoming(server_addr, pkt).await {
                                log::debug!("uplink handle_incoming: {}", e);
                            }
                        }
                    }
                    Ok(None) => {
                        log::info!("TCP uplink connection closed by peer");
                        return Ok(());
                    }
                    Err(e) => {
                        log::warn!("TCP uplink read error: {}", e);
                        return Err(e);
                    }
                }
            }
        }
    }
}

/// Perform SOCKS5 authentication (method negotiation).
async fn perform_socks5_auth(stream: &mut TcpStream) -> Result<()> {
    // Send: VER(1) + NMETHODS(1) + METHODS(N)
    // We support only NO_AUTH for simplicity
    let auth_req = [SOCKS5_VERSION, 1, AUTH_NONE];
    stream.write_all(&auth_req).await?;

    // Read: VER(1) + METHOD(1)
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;

    if resp[0] != SOCKS5_VERSION {
        bail!("SOCKS proxy responded with invalid version: {}", resp[0]);
    }

    if resp[1] == AUTH_NOACCEPT {
        bail!("SOCKS proxy requires authentication (not supported)");
    }

    if resp[1] != AUTH_NONE {
        bail!("SOCKS proxy selected unsupported authentication method: {}", resp[1]);
    }

    Ok(())
}

/// Perform SOCKS5 CONNECT to the server.
async fn perform_socks5_connect(
    stream: &mut TcpStream,
    server_addr: Ipv4Addr,
    server_port: u16,
) -> Result<()> {
    // Build CONNECT request:
    // VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR + DST.PORT
    let mut req = BytesMut::with_capacity(10);
    req.extend_from_slice(&[SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, ATYP_IPV4]);
    req.extend_from_slice(&server_addr.octets());
    req.extend_from_slice(&server_port.to_be_bytes());

    stream.write_all(&req).await?;

    // Read CONNECT response:
    // VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2)
    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp).await?;

    if resp[0] != SOCKS5_VERSION {
        bail!("Invalid SOCKS5 response version: {}", resp[0]);
    }

    if resp[1] != SOCKS5_RESP_SUCCESS {
        bail!("SOCKS5 CONNECT failed with reply code: {}", resp[1]);
    }

    Ok(())
}

/// Send a framed packet over the TCP stream.
///
/// Frame format: 4 bytes (big-endian length) + payload
async fn send_framed_packet<W>(stream: &mut W, packet: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let len = packet.len() as u32;
    let mut frame = BytesMut::with_capacity(4 + packet.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(packet);

    stream.write_all(&frame).await?;
    Ok(())
}

/// Read a framed packet from the TCP stream.
/// Returns Ok(Some(payload)) on success, Ok(None) on EOF, Err on error.
async fn read_frame(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    buf: &mut BytesMut,
) -> Result<Option<Bytes>> {
    while buf.len() < 4 {
        let mut tmp = [0u8; 4096];
        match reader.read(&mut tmp).await? {
            0 => return Ok(None),
            n => buf.extend_from_slice(&tmp[..n]),
        }
    }

    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > 65536 {
        bail!("Frame length too large: {}", len);
    }

    while buf.len() < 4 + len {
        let mut tmp = [0u8; 4096];
        match reader.read(&mut tmp).await? {
            0 => return Ok(None),
            n => buf.extend_from_slice(&tmp[..n]),
        }
    }

    let payload = Bytes::copy_from_slice(&buf[4..4 + len]);
    let _ = buf.split_to(4 + len);
    Ok(Some(payload))
}
