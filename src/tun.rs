//! Linux TUN device support.
//!
//! Creates and configures a TUN interface and provides async read/write
//! operations for raw IP packets.

use std::ffi::CStr;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use tokio::io::unix::AsyncFd;

#[cfg(target_os = "linux")]
const TUN_DEVICE: &str = "/dev/net/tun";

#[cfg(target_os = "linux")]
const IFF_TUN: libc::c_short = 0x0001;
#[cfg(target_os = "linux")]
const IFF_NO_PI: libc::c_short = 0x1000;

#[cfg(target_os = "linux")]
const TUNSETIFF: libc::c_ulong = 0x400454ca;

#[cfg(target_os = "linux")]
struct TunFd {
    fd: RawFd,
}

#[cfg(target_os = "linux")]
impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(target_os = "linux")]
impl Drop for TunFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Handle for an async TUN device.
#[cfg(target_os = "linux")]
pub struct TunDevice {
    name: String,
    fd:   AsyncFd<TunFd>,
    mtu:  usize,
}

#[cfg(target_os = "linux")]
impl TunDevice {
    /// Create and configure a TUN device.
    pub fn create(
        name: &str,
        addr: Ipv4Addr,
        peer: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: usize,
    ) -> Result<Self> {
        if name.len() >= libc::IFNAMSIZ {
            bail!("tun name '{}' too long", name);
        }
        if addr == peer {
            bail!("tun_ip and tun_peer_ip must be different");
        }

        let fd = open_tun()?;
        let if_name = attach_tun(fd, name)?;
        set_nonblocking(fd)?;

        configure_interface(&if_name, addr, peer, netmask, mtu)
            .context("configure tun interface")?;

        let fd = AsyncFd::new(TunFd { fd })
            .context("attach tun fd to async runtime")?;

        Ok(Self {
            name: if_name,
            fd,
            mtu,
        })
    }

    pub fn name(&self) -> &str { &self.name }
    pub fn mtu(&self) -> usize { self.mtu }

    /// Read a single IP packet from the TUN device.
    pub async fn read_packet(&self) -> Result<Bytes> {
        let mut buf = vec![0u8; self.mtu + 128];
        loop {
            let mut guard = self.fd.readable().await?;
            let res = guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });

            match res {
                Ok(Ok(n)) => {
                    buf.truncate(n);
                    return Ok(Bytes::from(buf));
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_would_block) => continue,
            }
        }
    }

    /// Write a single IP packet to the TUN device.
    pub async fn write_packet(&self, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            let mut guard = self.fd.writable().await?;
            let res = guard.try_io(|inner| {
                let ptr = unsafe { data.as_ptr().add(offset) } as *const libc::c_void;
                let len = data.len() - offset;
                let n = unsafe { libc::write(inner.as_raw_fd(), ptr, len) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });

            match res {
                Ok(Ok(n)) => offset += n,
                Ok(Err(e)) => return Err(e.into()),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub struct TunDevice;

#[cfg(not(target_os = "linux"))]
impl TunDevice {
    pub fn create(
        _name: &str,
        _addr: Ipv4Addr,
        _peer: Ipv4Addr,
        _netmask: Ipv4Addr,
        _mtu: usize,
    ) -> Result<Self> {
        bail!("TUN is supported only on Linux")
    }

    pub fn name(&self) -> &str { "" }
    pub fn mtu(&self) -> usize { 0 }

    pub async fn read_packet(&self) -> Result<Bytes> {
        bail!("TUN is supported only on Linux")
    }

    pub async fn write_packet(&self, _data: &[u8]) -> Result<()> {
        bail!("TUN is supported only on Linux")
    }
}

#[cfg(target_os = "linux")]
fn open_tun() -> Result<RawFd> {
    let path = std::ffi::CString::new(TUN_DEVICE).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("open /dev/net/tun failed (CAP_NET_ADMIN required)");
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn attach_tun(fd: RawFd, name: &str) -> Result<String> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_ifr_name(&mut ifr, name)?;
    unsafe { ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI; }

    let res = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
    if res < 0 {
        return Err(io::Error::last_os_error())
            .context("ioctl(TUNSETIFF) failed");
    }

    let if_name = unsafe { CStr::from_ptr(ifr.ifr_name.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Ok(if_name)
}

#[cfg(target_os = "linux")]
fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error()).context("fcntl(F_GETFL) failed");
    }
    let res = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if res < 0 {
        return Err(io::Error::last_os_error()).context("fcntl(F_SETFL) failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_interface(
    if_name: &str,
    addr: Ipv4Addr,
    peer: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: usize,
) -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error()).context("socket(AF_INET, SOCK_DGRAM) failed");
    }

    let res = (|| {
        set_if_addr(sock, if_name, addr)?;
        set_if_netmask(sock, if_name, netmask)?;
        if let Err(e) = set_if_dstaddr(sock, if_name, peer) {
            log::warn!("SIOCSIFDSTADDR failed for {}: {}", if_name, e);
        }
        set_if_mtu(sock, if_name, mtu)?;
        set_if_up(sock, if_name)?;
        Ok(())
    })();

    unsafe { libc::close(sock) };
    res
}

#[cfg(target_os = "linux")]
fn set_ifr_name(ifr: &mut libc::ifreq, name: &str) -> Result<()> {
    if name.len() >= libc::IFNAMSIZ {
        bail!("interface name '{}' too long", name);
    }
    unsafe {
        ptr::write_bytes(ifr.ifr_name.as_mut_ptr(), 0, libc::IFNAMSIZ);
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            name.len(),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_if_addr(sock: RawFd, name: &str, addr: Ipv4Addr) -> Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_ifr_name(&mut ifr, name)?;

    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr = libc::in_addr { s_addr: u32::from(addr).to_be() };

    unsafe {
        let dst = &mut ifr.ifr_ifru.ifru_addr as *mut _ as *mut libc::sockaddr_in;
        *dst = sin;
    }

    ioctl_ifreq(sock, libc::SIOCSIFADDR as libc::c_ulong, &mut ifr)
        .context("SIOCSIFADDR")
}

#[cfg(target_os = "linux")]
fn set_if_netmask(sock: RawFd, name: &str, netmask: Ipv4Addr) -> Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_ifr_name(&mut ifr, name)?;

    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr = libc::in_addr { s_addr: u32::from(netmask).to_be() };

    unsafe {
        let dst = &mut ifr.ifr_ifru.ifru_netmask as *mut _ as *mut libc::sockaddr_in;
        *dst = sin;
    }

    ioctl_ifreq(sock, libc::SIOCSIFNETMASK as libc::c_ulong, &mut ifr)
        .context("SIOCSIFNETMASK")
}

#[cfg(target_os = "linux")]
fn set_if_dstaddr(sock: RawFd, name: &str, dst: Ipv4Addr) -> Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_ifr_name(&mut ifr, name)?;

    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr = libc::in_addr { s_addr: u32::from(dst).to_be() };

    unsafe {
        let out = &mut ifr.ifr_ifru.ifru_dstaddr as *mut _ as *mut libc::sockaddr_in;
        *out = sin;
    }

    ioctl_ifreq(sock, libc::SIOCSIFDSTADDR as libc::c_ulong, &mut ifr)
        .context("SIOCSIFDSTADDR")
}

#[cfg(target_os = "linux")]
fn set_if_mtu(sock: RawFd, name: &str, mtu: usize) -> Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_ifr_name(&mut ifr, name)?;
    unsafe { ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int; }

    ioctl_ifreq(sock, libc::SIOCSIFMTU as libc::c_ulong, &mut ifr)
        .context("SIOCSIFMTU")
}

#[cfg(target_os = "linux")]
fn set_if_up(sock: RawFd, name: &str) -> Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_ifr_name(&mut ifr, name)?;

    ioctl_ifreq(sock, libc::SIOCGIFFLAGS as libc::c_ulong, &mut ifr)
        .context("SIOCGIFFLAGS")?;

    let flags = unsafe { ifr.ifr_ifru.ifru_flags };
    let new_flags = flags | (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    unsafe { ifr.ifr_ifru.ifru_flags = new_flags; }

    ioctl_ifreq(sock, libc::SIOCSIFFLAGS as libc::c_ulong, &mut ifr)
        .context("SIOCSIFFLAGS")
}

#[cfg(target_os = "linux")]
fn ioctl_ifreq(sock: RawFd, req: libc::c_ulong, ifr: &mut libc::ifreq) -> Result<()> {
    let res = unsafe { libc::ioctl(sock, req, ifr) };
    if res < 0 {
        Err(io::Error::last_os_error()).context("ioctl failed")
    } else {
        Ok(())
    }
}
