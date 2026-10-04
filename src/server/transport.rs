//! QUIC transport parameters and UDP socket setup for the server endpoint.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{IdleTimeout, TransportConfig, VarInt};
use socket2::{Domain, Protocol, Socket, Type};
#[cfg(target_os = "linux")]
use tracing::debug;

pub(super) fn create_transport_config() -> anyhow::Result<Arc<TransportConfig>> {
  let mut transport = TransportConfig::default();
  transport.keep_alive_interval(Some(Duration::from_secs(5)));
  transport.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(20))?));
  // Limits streams the *client* may open; it only ever opens the control stream.
  transport.max_concurrent_bidi_streams(VarInt::from_u32(4));
  transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
  Ok(Arc::new(transport))
}

pub(super) fn create_udp_socket(bind_addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
  let socket = Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(Protocol::UDP))?;
  socket.set_nonblocking(true)?;

  #[cfg(target_os = "linux")]
  configure_linux_socket(&socket);

  socket.bind(&bind_addr.into())?;
  Ok(socket.into())
}

#[cfg(target_os = "linux")]
fn configure_linux_socket(socket: &Socket) {
  use std::os::fd::AsRawFd;
  const UDP_GRO: libc::c_int = 104;
  const UDP_SEGMENT: libc::c_int = 103; // GSO for send offload

  let fd = socket.as_raw_fd();
  let enable: libc::c_int = 1;

  // Enable UDP GRO (receive offload)
  let result = unsafe {
    libc::setsockopt(
      fd,
      libc::SOL_UDP,
      UDP_GRO,
      &enable as *const _ as *const libc::c_void,
      std::mem::size_of::<libc::c_int>() as libc::socklen_t,
    )
  };
  if result == 0 {
    debug!("UDP_GRO enabled");
  } else {
    debug!("UDP_GRO not available: {}", std::io::Error::last_os_error());
  }

  // Enable UDP GSO (send offload)
  let segment_size: u16 = 1472; // Typical MTU - headers
  let result = unsafe {
    libc::setsockopt(
      fd,
      libc::SOL_UDP,
      UDP_SEGMENT,
      &segment_size as *const _ as *const libc::c_void,
      std::mem::size_of::<u16>() as libc::socklen_t,
    )
  };
  if result == 0 {
    debug!("UDP_GSO enabled with segment size {}", segment_size);
  } else {
    debug!("UDP_GSO not available: {}", std::io::Error::last_os_error());
  }

  // Set IP_TOS for lower latency (DSCP EF)
  let tos: libc::c_int = 0xB8; // DSCP EF
  let _ = unsafe {
    libc::setsockopt(
      fd,
      libc::IPPROTO_IP,
      libc::IP_TOS,
      &tos as *const _ as *const libc::c_void,
      std::mem::size_of::<libc::c_int>() as libc::socklen_t,
    )
  };
}
