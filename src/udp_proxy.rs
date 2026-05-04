//! Minimal SOCKS5 UDP-associate sender for client uplink traffic.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream, UdpSocket};

const SOCKS_VER: u8 = 0x05;
const CMD_UDP_ASSOC: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Clone)]
pub struct UdpProxySender {
    relay_addr: SocketAddr,
    socket:     Arc<UdpSocket>,
    _control:   Arc<TcpStream>,
}

impl UdpProxySender {
    /// Connect to a SOCKS5 proxy and establish a UDP ASSOC relay.
    pub async fn connect(proxy: &str) -> Result<Self> {
        let proxy_addr = resolve_proxy(proxy)
            .await
            .with_context(|| format!("resolve uplink_proxy {}", proxy))?;

        let mut control = TcpStream::connect(proxy_addr)
            .await
            .with_context(|| format!("connect SOCKS5 uplink_proxy {}", proxy))?;

        // Method negotiation: no-auth only.
        control.write_all(&[SOCKS_VER, 0x01, 0x00]).await?;
        let mut method = [0u8; 2];
        control.read_exact(&mut method).await?;
        if method != [SOCKS_VER, 0x00] {
            bail!("SOCKS5 uplink_proxy does not allow no-auth");
        }

        // UDP ASSOC request: let proxy pick relay address/port.
        let req = [SOCKS_VER, CMD_UDP_ASSOC, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
        control.write_all(&req).await?;

        let relay = read_reply(&mut control).await?;
        let relay_addr = if relay.ip().is_unspecified() {
            SocketAddr::new(proxy_addr.ip(), relay.port())
        } else {
            relay
        };

        let socket = if relay_addr.is_ipv6() {
            UdpSocket::bind(("::", 0)).await?
        } else {
            UdpSocket::bind(("0.0.0.0", 0)).await?
        };

        Ok(Self {
            relay_addr,
            socket: Arc::new(socket),
            _control: Arc::new(control),
        })
    }

    /// Send a UDP payload through the proxy to the given destination.
    pub async fn send(&self, dst_ip: Ipv4Addr, dst_port: u16, payload: Bytes) -> Result<()> {
        let mut buf = Vec::with_capacity(10 + payload.len());
        // RSV(2) + FRAG(1)
        buf.extend_from_slice(&[0x00, 0x00, 0x00]);
        // ATYP + DST.ADDR + DST.PORT
        buf.push(ATYP_IPV4);
        buf.extend_from_slice(&dst_ip.octets());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf.extend_from_slice(&payload);

        self.socket
            .send_to(&buf, self.relay_addr)
            .await
            .context("send UDP via uplink_proxy")?;
        Ok(())
    }
}

async fn resolve_proxy(proxy: &str) -> Result<SocketAddr> {
    let mut addrs = lookup_host(proxy).await?;
    addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("uplink_proxy has no resolved addresses"))
}

async fn read_reply(control: &mut TcpStream) -> Result<SocketAddr> {
    let mut head = [0u8; 4];
    control.read_exact(&mut head).await?;
    if head[0] != SOCKS_VER {
        bail!("SOCKS5 reply has bad version {}", head[0]);
    }
    if head[1] != 0x00 {
        bail!("SOCKS5 UDP ASSOC failed with code {}", head[1]);
    }

    let atyp = head[3];
    match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            let mut port = [0u8; 2];
            control.read_exact(&mut addr).await?;
            control.read_exact(&mut port).await?;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), u16::from_be_bytes(port)))
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            let mut port = [0u8; 2];
            control.read_exact(&mut addr).await?;
            control.read_exact(&mut port).await?;
            Ok(SocketAddr::new(IpAddr::from(addr), u16::from_be_bytes(port)))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            control.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            let mut port = [0u8; 2];
            control.read_exact(&mut host).await?;
            control.read_exact(&mut port).await?;
            let host = String::from_utf8_lossy(&host);
            let mut addrs = lookup_host(format!("{}:{}", host, u16::from_be_bytes(port))).await?;
            addrs
                .next()
                .ok_or_else(|| anyhow::anyhow!("SOCKS5 relay domain resolved to no addresses"))
        }
        _ => bail!("SOCKS5 reply has unknown ATYP {}", atyp),
    }
}
