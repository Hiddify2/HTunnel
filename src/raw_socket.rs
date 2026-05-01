//! Raw-socket I/O layer.
//!
//! Provides two abstractions:
//!
//! - [`RawSender`] – builds and transmits spoofed IPv4/UDP or IPv4/ICMP packets
//!   via a `SOCK_RAW | IPPROTO_RAW` socket with `IP_HDRINCL`.
//! - [`RawReceiver`] – receives raw IP packets from a `SOCK_RAW | IPPROTO_UDP`
//!   or `SOCK_RAW | IPPROTO_ICMP` socket and demultiplexes them into
//!   `CandyPacket`s.
//!
//! Both types are bridge objects between the blocking raw-socket world and the
//! async Tokio world.  Each spawns background `std::thread`s that communicate
//! with the Tokio task graph through `tokio::sync::mpsc` channels.

use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::io::RawFd;

use anyhow::{Context, Result};
use bytes::Bytes;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet_packet::udp::MutableUdpPacket;
use pnet_packet::MutablePacket;
use tokio::sync::mpsc;

use crate::packet::CandyPacket;

// ── Constants ────────────────────────────────────────────────────────────────

const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;

/// IP TTL for spoofed packets.
const SPOOF_TTL: u8 = 64;

// ── Outgoing packet descriptor ────────────────────────────────────────────────

/// A request to transmit a single spoofed packet.
#[derive(Debug)]
pub enum OutPacket {
    /// Send a UDP packet carrying `payload` on the data channel.
    Udp {
        src_ip:   Ipv4Addr,
        dst_ip:   Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload:  Bytes,
    },
}

/// A received packet that has been validated and parsed.
#[derive(Debug)]
pub struct InPacket {
    /// True source IP (from the IP header).
    pub src_ip: Ipv4Addr,
    /// Parsed HTunnel application packet.
    pub pkt:    CandyPacket,
}

// ── RawSender ────────────────────────────────────────────────────────────────

/// Sends spoofed IPv4 packets using a background thread.
///
/// Clone the inner `mpsc::Sender` to send packets from multiple tasks.
pub struct RawSender {
    tx: mpsc::Sender<OutPacket>,
}

impl RawSender {
    /// Spawn the background sender thread and return a `RawSender` handle.
    pub fn spawn() -> Result<Self> {
        let fd = create_raw_send_socket()?;
        let (tx, mut rx) = mpsc::channel::<OutPacket>(4096);

        // Dedicated blocking sender thread. This avoids expensive per-packet
        // spawn_blocking scheduling overhead under high packet rates.
        std::thread::Builder::new()
            .name("raw-send".into())
            .spawn(move || {
                while let Some(out) = rx.blocking_recv() {
                    if let Err(e) = send_out_packet(fd, out) {
                        log::warn!("raw-send error: {:#} (check CAP_NET_RAW and IP routing)", e);
                    }
                }
                unsafe { libc::close(fd) };
            })
            .context("spawn raw send thread")?;

        Ok(Self { tx })
    }

    /// Enqueue an [`OutPacket`] for transmission.
    pub async fn send(&self, pkt: OutPacket) -> Result<()> {
        self.tx.send(pkt).await.context("raw sender closed")
    }
}

// ── RawReceiver ───────────────────────────────────────────────────────────────

/// Receives and parses incoming raw IP packets in a background thread.
pub struct RawReceiver {
    rx: mpsc::Receiver<InPacket>,
}

impl RawReceiver {
    /// Spawn background threads for UDP and ICMP reception and return a
    /// combined `RawReceiver`.
    ///
    /// `icmp_id` – the ICMP identifier to match (filters out foreign pings).
    /// `allowed` – set of peer IPs whose packets are trusted.
    pub fn spawn(
        data_port:   u16,
        allowed:     Vec<Ipv4Addr>,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel::<InPacket>(4096);

        let udp_sock = create_udp_recv_socket(data_port)?;

        // UDP receive thread
        {
            let tx2      = tx;
            let allowed2 = allowed;
            std::thread::Builder::new()
                .name("raw-recv-udp".into())
                .spawn(move || {
                    udp_recv_loop(udp_sock, data_port, &allowed2, tx2);
                })
                .context("spawn udp recv thread")?;
        }

        Ok(Self { rx })
    }

    /// Await the next validated incoming packet.
    pub async fn recv(&mut self) -> Option<InPacket> {
        self.rx.recv().await
    }
}

// ── Socket creation helpers ───────────────────────────────────────────────────

pub fn create_raw_send_socket() -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("create_raw_send_socket failed");
    }

    let one: libc::c_int = 1;
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    if res < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err).context("setsockopt(IP_HDRINCL) failed");
    }
    Ok(fd)
}

fn create_udp_recv_socket(data_port: u16) -> Result<UdpSocket> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, data_port))
        .context("bind UDP receive socket")?;
    sock.set_nonblocking(false).context("configure UDP receive socket")?;
    Ok(sock)
}

// ── Packet transmission ───────────────────────────────────────────────────────

fn send_out_packet(fd: RawFd, out: OutPacket) -> Result<()> {
    match out {
        OutPacket::Udp { src_ip, dst_ip, src_port, dst_port, payload } => {
            let raw = build_udp_packet(src_ip, dst_ip, src_port, dst_port, &payload);
            raw_sendto(fd, &raw, dst_ip)
        }
    }
}

fn raw_sendto(fd: RawFd, data: &[u8], dst: Ipv4Addr) -> Result<()> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port   = 0;
    addr.sin_addr   = libc::in_addr { s_addr: u32::from(dst).to_be() };

    let n = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if n < 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!("sendto to {} failed: {}", dst, err));
    }
    Ok(())
}

// ── Packet reception loops ────────────────────────────────────────────────────

fn udp_recv_loop(sock: UdpSocket, data_port: u16, allowed: &[Ipv4Addr], tx: mpsc::Sender<InPacket>) {
    log::info!("RawReceiver: starting UDP recv loop on port {}", data_port);
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src_addr) = match sock.recv_from(&mut buf) {
            Ok(v)  => v,
            Err(e) => { log::warn!("udp recvfrom: {}", e); continue; }
        };
        let src_ip = match src_addr {
            std::net::SocketAddr::V4(v4) => *v4.ip(),
            std::net::SocketAddr::V6(_) => {
                log::trace!("RawReceiver: dropping IPv6 packet from {}", src_addr);
                continue;
            }
        };
        log::trace!("RawReceiver: recv_from returned {} bytes from {}", n, src_ip);
        let data = &buf[..n];

        log::trace!("RawReceiver: received {} bytes from {}. First 20 bytes: {:02x?}", n, src_ip, &data[..data.len().min(20)]);

        // Validate source IP against whitelist
        if !is_allowed(src_ip, allowed) {
            log::trace!("RawReceiver: dropping packet from unauthorized ip: {}", src_ip);
            continue;
        }

        log::trace!("RawReceiver: accepted packet from {}, payload {} bytes", src_ip, data.len());

        let payload = bytes::Bytes::copy_from_slice(data);
        match CandyPacket::decode(payload) {
            Ok(pkt) => {
                let _ = tx.blocking_send(InPacket { src_ip, pkt });
            }
            Err(e) => log::trace!("RawReceiver: candy decode error: {}", e),
        }
    }
}

fn is_allowed(ip: Ipv4Addr, allowed: &[Ipv4Addr]) -> bool {
    if allowed.is_empty() { return true; }
    if allowed.contains(&Ipv4Addr::UNSPECIFIED) { return true; }
    allowed.contains(&ip)
}

// ── Packet builders ───────────────────────────────────────────────────────────

/// Build a spoofed IPv4/UDP packet.
pub fn build_udp_packet(
    src_ip:   Ipv4Addr,
    dst_ip:   Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload:  &[u8],
) -> Vec<u8> {
    let udp_total = UDP_HDR_LEN + payload.len();
    let ip_total  = IP_HDR_LEN + udp_total;

    let mut buf = vec![0u8; ip_total];

    // Fill UDP header (starts at byte 20)
    {
        let udp_buf = &mut buf[IP_HDR_LEN..];
        let mut pkt = MutableUdpPacket::new(udp_buf).unwrap();
        pkt.set_source(src_port);
        pkt.set_destination(dst_port);
        pkt.set_length(udp_total as u16);
        pkt.set_payload(payload);
        let cksum = pnet_packet::udp::ipv4_checksum(&pkt.to_immutable(), &src_ip, &dst_ip);
        pkt.set_checksum(cksum);
    }

    fill_ipv4_header(&mut buf, src_ip, dst_ip, IpNextHeaderProtocols::Udp, ip_total);
    buf
}

fn fill_ipv4_header(
    buf:      &mut [u8],
    src_ip:   Ipv4Addr,
    dst_ip:   Ipv4Addr,
    protocol: pnet_packet::ip::IpNextHeaderProtocol,
    ip_total: usize,
) {
    let mut pkt = MutableIpv4Packet::new(buf).unwrap();
    pkt.set_version(4);
    pkt.set_header_length(5); // 5 × 4 = 20 bytes
    pkt.set_dscp(0);
    pkt.set_ecn(0);
    
    // On Linux, when using IP_HDRINCL, the total_length and fragment_offset
    // MUST be in host byte order.
    #[cfg(target_os = "linux")]
    {
        let total_len = ip_total as u16;
        let buf = pkt.packet_mut();
        buf[2..4].copy_from_slice(&total_len.to_ne_bytes());
    }
    #[cfg(not(target_os = "linux"))]
    pkt.set_total_length(ip_total as u16);

    pkt.set_identification(rand::random());
    pkt.set_flags(Ipv4Flags::DontFragment);
    pkt.set_fragment_offset(0);
    pkt.set_ttl(SPOOF_TTL);
    pkt.set_next_level_protocol(protocol);
    pkt.set_source(src_ip);
    pkt.set_destination(dst_ip);
    pkt.set_checksum(0); // zero before computing
    
    // Checksum is always network byte order, but pnet handles it.
    let cksum = pnet_packet::ipv4::checksum(&pkt.to_immutable());
    pkt.set_checksum(cksum);
}
