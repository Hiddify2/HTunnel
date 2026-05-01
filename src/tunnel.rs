//! Simplified Tunnel Manager without ARQ or Congestion Control.
//!
//! Provides basic multiplexing and forwarding of UDP packets.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::{mpsc, Mutex, Notify};

use crate::packet::{CandyPacket, PacketKind};
use crate::raw_socket::{OutPacket, RawSender};

const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    SynSent,
    Established,
}

struct Tunnel {
    id:          u32,
    state:       TunnelState,
    app_tx:      mpsc::Sender<Bytes>,
    last_active: Instant,
    established_notify: Arc<Notify>,
    peer_ip:     Ipv4Addr,
}

impl Tunnel {
    fn new(
        id:      u32,
        state:   TunnelState,
        app_tx:  mpsc::Sender<Bytes>,
        peer_ip: Ipv4Addr,
    ) -> Self {
        Self {
            id,
            state,
            app_tx,
            last_active: Instant::now(),
            established_notify: Arc::new(Notify::new()),
            peer_ip,
        }
    }

    fn touch(&mut self) { self.last_active = Instant::now(); }

    fn is_idle(&self, timeout: Duration) -> bool {
        Instant::now().duration_since(self.last_active) > timeout
    }
}

pub enum OutboundTransport {
    Socks5Uplink {
        relay: Arc<crate::socks5_uplink::Socks5Uplink>,
        server_addr: SocketAddr,
    },
    SpoofedDownlink {
        sender: RawSender,
        local_spoofs: Vec<Ipv4Addr>,
        data_port: u16,
    },
}

struct ManagerInner {
    tunnels:               DashMap<u32, Arc<Mutex<Tunnel>>>,
    outbound:              OutboundTransport,
    established_notifiers: DashMap<u32, Arc<Notify>>,
}

#[derive(Clone)]
pub struct TunnelManager(Arc<ManagerInner>);

impl TunnelManager {
    pub fn new(outbound: OutboundTransport) -> Self {
        Self(Arc::new(ManagerInner {
            tunnels: DashMap::new(),
            outbound,
            established_notifiers: DashMap::new(),
        }))
    }

    pub async fn open_tunnel(&self) -> Result<(u32, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>)> {
        let id: u32 = rand::random();
        let (app_tx, app_rx) = mpsc::channel::<Bytes>(1024);
        let (net_tx, net_rx) = mpsc::channel::<Bytes>(1024);

        let peer_ip = match &self.0.outbound {
            OutboundTransport::Socks5Uplink { server_addr, .. } => {
                match server_addr {
                    SocketAddr::V4(v4) => *v4.ip(),
                    _ => Ipv4Addr::new(0,0,0,0),
                }
            }
            _ => Ipv4Addr::new(0,0,0,0),
        };

        let tunnel = Tunnel::new(id, TunnelState::SynSent, app_tx, peer_ip);
        let established_notify = tunnel.established_notify.clone();
        self.0.tunnels.insert(id, Arc::new(Mutex::new(tunnel)));
        self.0.established_notifiers.insert(id, established_notify);

        // Spawn forwarding task (Net → Transport)
        let mgr = self.clone();
        tokio::spawn(async move {
            let mut net_rx = net_rx;
            while let Some(data) = net_rx.recv().await {
                let pkt = CandyPacket::new_data(id, data);
                if let Err(e) = mgr.transmit(pkt).await {
                    log::debug!("tunnel {} transmit error: {}", id, e);
                    break;
                }
            }
        });

        // Send SYN
        self.transmit(CandyPacket::new_syn(id)).await?;
        log::info!("tunnel {} opened (SYN sent)", id);

        Ok((id, app_rx, net_tx))
    }

    pub async fn accept_syn(
        &self,
        syn:             CandyPacket,
        src_ip:          Ipv4Addr,
        peer_ip_override: Option<Ipv4Addr>,
    ) -> Result<(u32, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>)> {
        let id = syn.tunnel_id;
        if self.0.tunnels.contains_key(&id) {
            return Err(anyhow!("duplicate tunnel {}", id));
        }

        let (app_tx, app_rx) = mpsc::channel::<Bytes>(1024);
        let (net_tx, net_rx) = mpsc::channel::<Bytes>(1024);
        let peer_ip = peer_ip_override.unwrap_or(src_ip);

        let tunnel = Tunnel::new(id, TunnelState::Established, app_tx, peer_ip);
        self.0.tunnels.insert(id, Arc::new(Mutex::new(tunnel)));

        // Spawn forwarding task (Net → Transport)
        let mgr = self.clone();
        tokio::spawn(async move {
            let mut net_rx = net_rx;
            while let Some(data) = net_rx.recv().await {
                let pkt = CandyPacket::new_data(id, data);
                if let Err(e) = mgr.transmit(pkt).await {
                    log::debug!("tunnel {} transmit error: {}", id, e);
                    break;
                }
            }
        });

        // Send SYN-ACK
        self.transmit(CandyPacket::new_syn_ack(id)).await?;
        log::info!("tunnel {} accepted from {}", id, peer_ip);

        Ok((id, app_rx, net_tx))
    }

    pub async fn handle_incoming(&self, src_ip: Ipv4Addr, pkt: CandyPacket) -> Result<Option<(CandyPacket, Ipv4Addr)>> {
        match pkt.kind {
            PacketKind::Syn => Ok(Some((pkt, src_ip))),
            PacketKind::SynAck => {
                if let Some(t) = self.0.tunnels.get(&pkt.tunnel_id) {
                    let mut t = t.lock().await;
                    if t.state == TunnelState::SynSent {
                        t.state = TunnelState::Established;
                        t.established_notify.notify_waiters();
                    }
                    t.touch();
                }
                Ok(None)
            }
            PacketKind::Data => {
                if let Some(t) = self.0.tunnels.get(&pkt.tunnel_id) {
                    let mut t = t.lock().await;
                    t.touch();
                    let _ = t.app_tx.try_send(pkt.payload);
                }
                Ok(None)
            }
            PacketKind::Fin => {
                self.close_tunnel(pkt.tunnel_id).await;
                Ok(None)
            }
        }
    }

    pub async fn is_established(&self, id: u32) -> bool {
        if let Some(t) = self.0.tunnels.get(&id) {
            let t = t.lock().await;
            if t.state == TunnelState::Established { return true; }
        }
        if let Some(n) = self.0.established_notifiers.get(&id) {
            let n = n.clone();
            n.notified().await;
            return true;
        }
        false
    }

    pub async fn close_tunnel(&self, id: u32) {
        if let Some((_, t)) = self.0.tunnels.remove(&id) {
            let _ = self.transmit(CandyPacket::new_fin(id)).await;
            log::info!("tunnel {} closed", id);
        }
        self.0.established_notifiers.remove(&id);
    }

    pub async fn tick(&self) -> Result<()> {
        let now = Instant::now();
        let mut to_remove = Vec::new();
        for r in self.0.tunnels.iter() {
            let t = r.value().lock().await;
            if t.is_idle(TUNNEL_IDLE_TIMEOUT) {
                to_remove.push(*r.key());
            }
        }
        for id in to_remove {
            self.close_tunnel(id).await;
        }
        Ok(())
    }

    async fn transmit(&self, pkt: CandyPacket) -> Result<()> {
        match &self.0.outbound {
            OutboundTransport::Socks5Uplink { relay, server_addr } => {
                let enc = pkt.encode();
                relay.send_to(&enc, *server_addr).await
            }
            OutboundTransport::SpoofedDownlink { sender, local_spoofs, data_port } => {
                let peer_ip = {
                    let arc = self.0.tunnels.get(&pkt.tunnel_id)
                        .map(|r| r.value().clone())
                        .ok_or_else(|| anyhow!("tunnel {} missing during transmit", pkt.tunnel_id))?;
                    let ip = arc.lock().await.peer_ip;
                    ip
                };
                
                let spoof_idx = pkt.tunnel_id as usize % local_spoofs.len();
                let src_ip = local_spoofs[spoof_idx];

                let enc = pkt.encode();
                let out = OutPacket::Udp {
                    src_ip,
                    dst_ip:   peer_ip,
                    src_port: *data_port,
                    dst_port: *data_port,
                    payload:  enc,
                };
                sender.send(out).await
            }
        }
    }
}
