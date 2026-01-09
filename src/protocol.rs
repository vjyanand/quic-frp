use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

pub async fn read_frame<T: for<'a> bitcode::Decode<'a>, R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<T> {
  let frame_len = reader.read_u8().await?;
  trace!("Reading frame of length {}", frame_len);

  let mut buf = vec![0u8; frame_len as usize];
  reader.read_exact(&mut buf[..]).await?;
  let frame = bitcode::decode::<T>(&buf)?;
  Ok(frame)
}

pub async fn write_frame<T: bitcode::Encode, W: AsyncWrite + Unpin>(writer: &mut W, frame: &T) -> anyhow::Result<()> {
  let serialized = bitcode::encode(frame);
  let len = serialized.len() as u8;
  trace!("Writing frame of length {:?}", len);

  // Write 4-byte length
  writer.write_u8(len).await?;

  // Write payload
  writer.write_all(&serialized).await?;
  Ok(())
}

/// Read a 2-byte port header from incoming data stream
pub async fn read_port_header<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<u16> {
  let mut buf = [0u8; 2];
  reader.read_exact(&mut buf[..]).await?;
  Ok(u16::from_be_bytes(buf))
}
