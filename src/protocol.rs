//! Control protocol definitions and frame I/O for QUIC streams.
//!
//! Protocol format:
//! - Control messages: 4-byte length prefix + bincode-encoded payload
//! - Data streams: 2-byte port header + raw bidirectional data

use bincode::{Decode, Encode, config::standard, decode_from_slice, encode_to_vec};
use compio_quic::{RecvStream, SendStream};
use log::trace;

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

/// Write a length-prefixed bincode frame to a QUIC send stream
pub async fn write_frame<T: Encode>(
  stream: &mut SendStream,
  frame: &T,
) -> anyhow::Result<()> {
  let payload = encode_to_vec(frame, standard())?;
  let len_bytes = (payload.len() as u32).to_be_bytes();

  trace!("Writing frame: {} bytes", payload.len());

  // Write length prefix
  stream.write_all(&len_bytes).await?;
  // Write payload
  stream.write_all(&payload).await?;

  Ok(())
}

/// Read a length-prefixed bincode frame from a QUIC recv stream
pub async fn read_frame<T: Decode<()>>(stream: &mut RecvStream) -> anyhow::Result<T> {
  // Read 4-byte length prefix
  let mut len_buf = [0u8; 4];
  stream.read_exact(&mut len_buf[..]).await?;
  let frame_len = u32::from_be_bytes(len_buf) as usize;

  trace!("Reading frame: {} bytes", frame_len);

  // Sanity check to prevent OOM
  if frame_len > 1024 * 1024 {
    anyhow::bail!("Frame too large: {} bytes", frame_len);
  }

  // Read payload
  let mut buf = vec![0u8; frame_len];
  stream.read_exact(&mut buf).await?;

  // Decode
  let (frame, _) = decode_from_slice(&buf, standard())?;
  Ok(frame)
}

/// Read a 2-byte port header from incoming data stream
pub async fn read_port_header(stream: &mut RecvStream) -> anyhow::Result<u16> {
  let mut buf = [0u8; 2];
  stream.read_exact(&mut buf[..]).await?;
  Ok(u16::from_be_bytes(buf))
}
