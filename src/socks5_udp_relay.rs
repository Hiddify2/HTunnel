//! SOCKS5 UDP relay for client uplink packets.
//!
//! This connects to an upstream SOCKS5 proxy, negotiates UDP ASSOCIATE, and
//! sends HTunnel tunnel packets as UDP datagrams through the proxy.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_NOACCEPT: u8 = 0xff;

const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS5_RESP_SUCCESS: u8 = 0x00;

const ATYP_IPV4: u8 = 0x01;

pub async fn spawn_socks5_udp_relay(
    upstream: &str,
    server_addr: Ipv4Addr,
    server_port: u16,
    mut uplink_rx: mpsc::Receiver<Bytes>,
) -> Result<()> {
    let upstream_addr = upstream
        .parse::<SocketAddr>()
        .with_context(|| format!("Invalid upstream proxy address: {}", upstream))?;

    let mut control = TcpStream::connect(upstream_addr)
        .await
        .with_context(|| format!("Cannot connect to SOCKS proxy: {}", upstream_addr))?;

    log::info!("Connected to upstream SOCKS proxy at {}", upstream_addr);

    perform_socks5_auth(&mut control).await?;
    perform_socks5_udp_associate(&mut control).await?;

    let relay_addr = read_udp_relay_addr(&mut control).await?;
    log::info!("SOCKS5 UDP relay established at {}", relay_addr);

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("bind UDP socket for SOCKS relay")?;

    while let Some(packet) = uplink_rx.recv().await {
        let framed = build_socks5_udp_frame(server_addr, server_port, &packet);
        socket
            .send_to(&framed, relay_addr)
            .await
            .context("send UDP datagram through SOCKS relay")?;
    }

    Ok(())
}

async fn perform_socks5_auth(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(&[SOCKS5_VERSION, 1, AUTH_NONE]).await?;

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

async fn perform_socks5_udp_associate(stream: &mut TcpStream) -> Result<()> {
    let mut req = BytesMut::with_capacity(10);
    req.extend_from_slice(&[SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4]);
    req.extend_from_slice(&[0, 0, 0, 0]);
    req.extend_from_slice(&0u16.to_be_bytes());
    stream.write_all(&req).await?;
    Ok(())
}

async fn read_udp_relay_addr(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp).await?;

    if resp[0] != SOCKS5_VERSION {
        bail!("Invalid SOCKS5 response version: {}", resp[0]);
    }
    if resp[1] != SOCKS5_RESP_SUCCESS {
        bail!("SOCKS5 UDP ASSOCIATE failed with reply code: {}", resp[1]);
    }

    let atyp = resp[3];
    match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            let mut port = [0u8; 2];
            stream.read_exact(&mut addr).await?;
            stream.read_exact(&mut port).await?;
            Ok(SocketAddr::from((Ipv4Addr::from(addr), u16::from_be_bytes(port))))
        }
        _ => bail!("SOCKS5 UDP relay returned unsupported address type {}", atyp),
    }
}

fn build_socks5_udp_frame(dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(10 + payload.len());
    frame.extend_from_slice(&[0x00, 0x00, 0x00, ATYP_IPV4]);
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}