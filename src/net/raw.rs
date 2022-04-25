use std::fmt;
use std::io;
use std::net;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket, RawSocket};

use libc::c_int;
use socket2::{Domain, Protocol, Socket, Type};

use crate::{event, Interest, Registry, sys, Token};
use crate::io_source::IoSource;

#[cfg_attr(feature = "os-poll", doc = "```")]
#[cfg_attr(not(feature = "os-poll"), doc = "```ignore")]
pub struct NetRawSocket {
    inner: IoSource<socket2::Socket>,
}

impl NetRawSocket {
    pub fn new(domain: Domain, protocol: Option<Protocol>) -> io::Result<NetRawSocket> {
        let ty = Type::RAW;
        let socket = Socket::new(domain, ty, protocol)?;

        Ok(NetRawSocket { inner: IoSource::new(socket) })
    }

    pub fn from_fd(fd: c_int) -> NetRawSocket {
        let socket = unsafe { socket2::Socket::from_raw_fd(fd) };
        NetRawSocket { inner: IoSource::new(socket) }
    }

    // #[cfg_attr(feature = "os-poll", doc = "```")]
    // #[cfg_attr(not(feature = "os-poll"), doc = "```ignore")]
    // pub fn bind(&self) -> io::Result<NetRawSocket> {
    // }

    #[cfg_attr(all(feature = "os-poll", not(target_os = "freebsd")), doc = "```")]
    #[cfg_attr(
    any(not(feature = "os-poll"), target_os = "freebsd"),
    doc = "```ignore"
    )]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr().map(Into::into)
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr().map(Into::into)
    }

    pub fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.inner.do_io(|inner| inner.send_to(buf, &target.into()))
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.do_io(|inner| inner.send(buf))
    }

    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.inner.connect(addr.into())
    }


    #[cfg_attr(feature = "os-poll", doc = "```")]
    #[cfg_attr(not(feature = "os-poll"), doc = "```ignore")]
    pub fn set_broadcast(&self, on: bool) -> io::Result<()> {
        self.inner.set_broadcast(on)
    }

    #[cfg_attr(feature = "os-poll", doc = "```")]
    #[cfg_attr(not(feature = "os-poll"), doc = "```ignore")]
    pub fn broadcast(&self) -> io::Result<bool> {
        self.inner.broadcast()
    }

    pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.inner.set_multicast_loop_v4(on)
    }

    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        self.inner.multicast_loop_v4()
    }

    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_multicast_ttl_v4(ttl)
    }

    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        self.inner.multicast_ttl_v4()
    }

    pub fn set_multicast_loop_v6(&self, on: bool) -> io::Result<()> {
        self.inner.set_multicast_loop_v6(on)
    }

    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        self.inner.multicast_loop_v6()
    }

    #[cfg_attr(feature = "os-poll", doc = "```")]
    #[cfg_attr(not(feature = "os-poll"), doc = "```ignore")]
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    #[cfg_attr(feature = "os-poll", doc = "```")]
    #[cfg_attr(not(feature = "os-poll"), doc = "```ignore")]
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn join_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        self.inner.join_multicast_v4(multiaddr, interface)
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn join_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        self.inner.join_multicast_v6(multiaddr, interface)
    }

    /// Executes an operation of the `IP_DROP_MEMBERSHIP` type.
    ///
    /// For more information about this option, see
    /// [`join_multicast_v4`][link].
    ///
    /// [link]: #method.join_multicast_v4
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn leave_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        self.inner.leave_multicast_v4(multiaddr, interface)
    }

    /// Executes an operation of the `IPV6_DROP_MEMBERSHIP` type.
    ///
    /// For more information about this option, see
    /// [`join_multicast_v6`][link].
    ///
    /// [link]: #method.join_multicast_v6
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn leave_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        self.inner.leave_multicast_v6(multiaddr, interface)
    }

    /// Get the value of the `IPV6_V6ONLY` option on this socket.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn only_v6(&self) -> io::Result<bool> {
        (&self.inner).only_v6()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    #[cfg_attr(unix, doc = "```no_run")]
    #[cfg_attr(windows, doc = "```ignore")]
    pub fn try_io<F, T>(&self, f: F) -> io::Result<T>
        where
            F: FnOnce() -> io::Result<T>,
    {
        self.inner.do_io(|_| f())
    }
}

impl event::Source for NetRawSocket {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.inner.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.inner.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.inner.deregister(registry)
    }
}

impl fmt::Debug for NetRawSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

#[cfg(unix)]
impl IntoRawFd for NetRawSocket {
    fn into_raw_fd(self) -> RawFd {
        self.inner.into_inner().into_raw_fd()
    }
}

#[cfg(unix)]
impl AsRawFd for NetRawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

#[cfg(unix)]
impl FromRawFd for NetRawSocket {
    /// Converts a `RawFd` to a `NetRawSocket`.
    ///
    /// # Notes
    ///
    /// The caller is responsible for ensuring that the socket is in
    /// non-blocking mode.
    unsafe fn from_raw_fd(fd: RawFd) -> NetRawSocket {
        NetRawSocket::from_fd(FromRawFd::from_raw_fd(fd))
    }
}

#[cfg(windows)]
impl IntoRawSocket for NetRawSocket {
    fn into_raw_socket(self) -> RawSocket {
        self.inner.into_inner().into_raw_socket()
    }
}

#[cfg(windows)]
impl AsRawSocket for NetRawSocket {
    fn as_raw_socket(&self) -> RawSocket {
        self.inner.as_raw_socket()
    }
}

#[cfg(windows)]
impl FromRawSocket for NetRawSocket {
    /// Converts a `RawSocket` to a `NetRawSocket`.
    ///
    /// # Notes
    ///
    /// The caller is responsible for ensuring that the socket is in
    /// non-blocking mode.
    unsafe fn from_raw_socket(socket: RawSocket) -> NetRawSocket {
        NetRawSocket::from_fd(FromRawSocket::from_raw_socket(socket))
    }
}
