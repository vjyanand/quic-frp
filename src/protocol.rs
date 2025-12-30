use quinn::{RecvStream, SendStream};
use tracing::trace;

use crate::config::ServiceDefinition;

#[derive(Debug, Clone, bitcode::Encode, bitcode::Decode)]
pub enum ClientControlMessage {
  /// Register a new service for proxying
  RegisterService(ServiceDefinition),
  /// Unregister an existing service
  DeregisterService(ServiceDefinition),
}

/// Messages sent from server to client on control stream
#[derive(Debug, Clone, bitcode::Encode, bitcode::Decode)]
pub enum ServerAckMessage {
  /// Acknowledgment for service registration
  ServiceRegistered { service_name: String, success: bool, error: Option<String> },
  /// Acknowledgment for service unregistration
  ServiceUnregistered { service_name: String, success: bool, error: Option<String> },
}

pub async fn read_frame<T: for<'a> bitcode::Decode<'a>>(stream: &mut RecvStream) -> anyhow::Result<T> {
  let mut len_buf = [0u8; 4];
  stream.read_exact(&mut len_buf[..]).await?;
  let frame_len = u32::from_be_bytes(len_buf) as usize;
  trace!("Reading frame of length {}", frame_len);

  let mut buf = vec![0u8; frame_len];
  stream.read_exact(&mut buf[..]).await?;
  let frame = bitcode::decode::<T>(&buf)?;
  Ok(frame)
}

pub async fn write_frame<T: bitcode::Encode>(stream: &mut SendStream, frame: &T) -> anyhow::Result<()> {
  let serialized = bitcode::encode(frame);
  let len = (serialized.len() as u32).to_be_bytes();
  trace!("Writing frame of length {:?}", len);
  // Write 4-byte length
  stream.write_all(&len).await?;
  // Write payload
  stream.write_all(&serialized).await?;
  Ok(())
}

/// Read a 2-byte port header from incoming data stream
pub async fn read_port_header(stream: &mut RecvStream) -> anyhow::Result<u16> {
  let mut buf = [0u8; 2];
  stream.read_exact(&mut buf[..]).await?;
  Ok(u16::from_be_bytes(buf))
}
