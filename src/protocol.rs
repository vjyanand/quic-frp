//! Control protocol definitions and frame I/O for QUIC streams.
//!
//! Protocol format:
//! - Control messages: 4-byte length prefix + bincode-encoded payload
//! - Data streams: 2-byte port header + raw bidirectional data

use bincode::{Decode, Encode, encode_to_vec};
use compio_quic::{RecvStream, SendStream};
use tracing::trace;

use crate::config::ServiceDefinition;

/// Messages sent from client to server on control stream
#[derive(Debug, Clone, Encode, Decode)]
pub enum ClientControlMessage {
  /// Register a new service for proxying
  RegisterService(ServiceDefinition),
  /// Unregister an existing service
  UnregisterService(ServiceDefinition),
}

/// Messages sent from server to client on control stream
#[derive(Debug, Clone, Encode, Decode)]
pub enum ServerControlMessage {
  /// Acknowledgment for service registration
  ServiceRegistered { service_name: String, success: bool, error: Option<String> },
  /// Acknowledgment for service unregistration
  ServiceUnregistered { service_name: String, success: bool, error: Option<String> },
}

/// Writes a framed control message to a *unidirectional* or *bidi* SendStream.
pub async fn write_frame<T: Encode>(
  stream: &mut SendStream,
  frame: &T,
) -> anyhow::Result<()> {
  let serialized = encode_to_vec(frame, bincode::config::standard())?;
  let len = (serialized.len() as u32).to_be_bytes();
  trace!("Writing frame of length {:?}", len);
  // Write 4-byte length
  stream.write_all(&len).await?;
  // Write payload
  stream.write_all(&serialized).await?;
  Ok(())
}

/// Reads exactly one framed control message.
pub async fn read_frame<T: bincode::Decode<()>>(
  stream: &mut RecvStream,
) -> anyhow::Result<T> {
  let mut len_buf = [0u8; 4];
  stream.read_exact(&mut len_buf[..]).await?;
  let frame_len = u32::from_be_bytes(len_buf) as usize;
  trace!("Reading frame of length {}", frame_len);
  // Sanity check to prevent OOM
  if frame_len > 1024 * 1024 {
    anyhow::bail!("Frame too large: {} bytes", frame_len);
  }
  let mut buf = vec![0u8; frame_len];
  stream.read_exact(&mut buf[..]).await?;
  let (frame, _) = bincode::decode_from_slice::<T, _>(&buf, bincode::config::standard())?;
  Ok(frame)
}

/// Read a 2-byte port header from incoming data stream
pub async fn read_port_header(stream: &mut RecvStream) -> anyhow::Result<u16> {
  let mut buf = [0u8; 2];
  stream.read_exact(&mut buf[..]).await?;
  Ok(u16::from_be_bytes(buf))
}
