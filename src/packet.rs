//! HTunnel wire protocol – simplified version without ARQ/Congestion.
//!
//! Rides inside SOCKS5 UDP (uplink) or spoofed UDP (downlink).

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// 4-byte magic number at the start of every CandyPacket.
pub const MAGIC: u32 = 0xCA_FE_5F_00;
/// Current protocol version.
pub const VERSION: u8 = 2;
/// Minimum wire size of a CandyPacket (no payload).
pub const HEADER_SIZE: usize = 10;

/// Type of a CandyPacket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketKind {
    /// Application data.
    Data = 0,
    /// Tunnel open request (client → server).
    Syn = 3,
    /// Tunnel open acknowledgement (server → client).
    SynAck = 4,
    /// Tunnel teardown.
    Fin = 5,
}

impl TryFrom<u8> for PacketKind {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Data),
            3 => Ok(Self::Syn),
            4 => Ok(Self::SynAck),
            5 => Ok(Self::Fin),
            _ => bail!("unknown packet kind {}", v),
        }
    }
}

/// An application-level HTunnel packet (Simplified).
///
/// Wire format (big-endian):
/// ```text
/// [magic:4][version:1][kind:1][tunnel_id:4][payload…]
/// ```
#[derive(Debug, Clone)]
pub struct CandyPacket {
    pub kind:      PacketKind,
    pub tunnel_id: u32,
    pub payload:   Bytes,
}

impl CandyPacket {
    pub fn new_syn(tunnel_id: u32) -> Self {
        Self { kind: PacketKind::Syn, tunnel_id, payload: Bytes::new() }
    }

    pub fn new_syn_ack(tunnel_id: u32) -> Self {
        Self { kind: PacketKind::SynAck, tunnel_id, payload: Bytes::new() }
    }

    pub fn new_data(tunnel_id: u32, payload: Bytes) -> Self {
        Self { kind: PacketKind::Data, tunnel_id, payload }
    }

    pub fn new_fin(tunnel_id: u32) -> Self {
        Self { kind: PacketKind::Fin, tunnel_id, payload: Bytes::new() }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_SIZE + self.payload.len());
        buf.put_u32(MAGIC);
        buf.put_u8(VERSION);
        buf.put_u8(self.kind as u8);
        buf.put_u32(self.tunnel_id);
        buf.put(self.payload.clone());
        buf.freeze()
    }

    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            bail!("packet too short: {} bytes (min {})", data.len(), HEADER_SIZE);
        }
        let magic = data.get_u32();
        if magic != MAGIC {
            bail!("bad magic 0x{:08x}", magic);
        }
        let version = data.get_u8();
        if version != VERSION {
            bail!("unsupported version {}", version);
        }
        let kind      = PacketKind::try_from(data.get_u8())?;
        let tunnel_id = data.get_u32();
        let payload   = data; // remaining bytes
        Ok(CandyPacket { kind, tunnel_id, payload })
    }
}
