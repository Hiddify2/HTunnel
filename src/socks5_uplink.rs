//! SOCKS5 UDP Uplink implementation.
//!
//! Handles the UDP ASSOCIATE handshake and provides a relay for outbound packets.

use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::{bail, Context, Result};
use bytes::{BytesMut, BufMut};

pub struct Socks5Uplink {
    /// The UDP socket used to send data to the relay.
    udp_sock: UdpSocket,
    /// The address of the SOCKS5 UDP relay.
    relay_addr: SocketAddr,
    /// The TCP stream that must be kept open to maintain the association.
    _tcp_keepalive: TcpStream,
}

impl Socks5Uplink {
    /// Establish a SOCKS5 UDP association.
    pub async fn connect(
        proxy_host: &str,
        proxy_port: u16,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self> {
        let proxy_addr = format!("{}:{}", proxy_host, proxy_port);
        let mut tcp = TcpStream::connect(&proxy_addr)
            .await
            .with_context(|| format!("failed to connect to SOCKS5 proxy at {}", proxy_addr))?;

        // 1. Version & Method Selection
        // We support No Auth (0) and Username/Password (2).
        let mut greeting = vec![0x05, 0x01, 0x00];
        if username.is_some() {
            greeting[1] = 0x02;
            greeting.push(0x02);
        }
        tcp.write_all(&greeting).await?;

        let mut method_resp = [0u8; 2];
        tcp.read_exact(&mut method_resp).await?;
        if method_resp[0] != 0x05 {
            bail!("SOCKS5 greeting failed: invalid version");
        }

        match method_resp[1] {
            0x00 => {} // No Auth
            0x02 => {
                // Username/Password Auth
                let u = username.unwrap();
                let p = password.unwrap_or("");
                let mut auth_req = Vec::new();
                auth_req.push(0x01); // Sub-negotiation version
                auth_req.push(u.len() as u8);
                auth_req.extend_from_slice(u.as_bytes());
                auth_req.push(p.len() as u8);
                auth_req.extend_from_slice(p.as_bytes());
                tcp.write_all(&auth_req).await?;

                let mut auth_resp = [0u8; 2];
                tcp.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    bail!("SOCKS5 authentication failed");
                }
            }
            0xFF => bail!("SOCKS5 proxy requires authentication method we don't support"),
            _ => bail!("SOCKS5 proxy selected unsupported method: {}", method_resp[1]),
        }

        // 2. UDP ASSOCIATE Request
        // We tell the proxy to relay UDP from any address/port (0.0.0.0:0).
        let assoc_req = vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        tcp.write_all(&assoc_req).await?;

        let mut assoc_resp = [0u8; 10];
        tcp.read_exact(&mut assoc_resp).await?;
        if assoc_resp[1] != 0x00 {
            bail!("SOCKS5 UDP ASSOCIATE failed: error code {}", assoc_resp[1]);
        }

        // Parse relay address
        let relay_ip = match assoc_resp[3] {
            0x01 => {
                let ip = std::net::Ipv4Addr::new(assoc_resp[4], assoc_resp[5], assoc_resp[6], assoc_resp[7]);
                std::net::IpAddr::V4(ip)
            }
            _ => bail!("SOCKS5 relay address type {} not supported yet", assoc_resp[3]),
        };
        let relay_port = u16::from_be_bytes([assoc_resp[8], assoc_resp[9]]);
        let relay_addr = SocketAddr::new(relay_ip, relay_port);

        log::info!("SOCKS5 UDP association established. Relay: {}", relay_addr);

        // Bind a local UDP socket to send/receive data
        let udp_sock = UdpSocket::bind("0.0.0.0:0").await?;

        Ok(Self {
            udp_sock,
            relay_addr,
            _tcp_keepalive: tcp,
        })
    }

    /// Send a payload through the SOCKS5 UDP relay.
    pub async fn send_to(&self, payload: &[u8], target: SocketAddr) -> Result<()> {
        log::trace!("Socks5Uplink: sending {} bytes to target {}", payload.len(), target);
        let mut pkt = BytesMut::with_capacity(10 + payload.len());
        // SOCKS5 UDP Header
        pkt.put_u16(0); // RSV
        pkt.put_u8(0);  // FRAG
        match target {
            SocketAddr::V4(v4) => {
                pkt.put_u8(0x01); // ATYP IPv4
                pkt.put_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                pkt.put_u8(0x04); // ATYP IPv6
                pkt.put_slice(&v6.ip().octets());
            }
        }
        pkt.put_u16(target.port());
        pkt.put_slice(payload);

        self.udp_sock.send_to(&pkt, self.relay_addr).await?;
        Ok(())
    }
}
