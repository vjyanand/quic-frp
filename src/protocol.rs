use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, trace};

use crate::config::ServiceDefinition;

const MAX_FRAME_LEN: usize = 64 * 1024;

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
  let frame_len = match reader.read_u16().await {
    Ok(n) => n as usize,
    Err(e) => {
      debug!("read_frame: failed reading length prefix: kind={:?} err={}", e.kind(), e);
      return Err(e.into());
    }
  };
  debug!("read_frame: length prefix = {} bytes (type={})", frame_len, std::any::type_name::<T>());

  if frame_len > MAX_FRAME_LEN {
    return Err(anyhow::anyhow!("frame length {} exceeds maximum {}", frame_len, MAX_FRAME_LEN));
  }
  if frame_len == 0 {
    debug!("read_frame: ZERO-length frame — likely length-prefix desync");
    return Err(anyhow::anyhow!("zero-length frame"));
  }

  let mut buf = vec![0u8; frame_len];
  if let Err(e) = reader.read_exact(&mut buf[..]).await {
    debug!("read_frame: failed reading body of {} bytes: kind={:?} err={}", frame_len, e.kind(), e);
    return Err(e.into());
  }

  match bitcode::decode::<T>(&buf) {
    Ok(frame) => Ok(frame),
    Err(e) => Err(anyhow::anyhow!("bitcode decode error: {} (frame_len={})", e, frame_len)),
  }
}

pub async fn write_frame<T: bitcode::Encode, W: AsyncWrite + Unpin>(writer: &mut W, frame: &T) -> anyhow::Result<()> {
  let serialized = bitcode::encode(frame);
  if serialized.len() > MAX_FRAME_LEN {
    return Err(anyhow::anyhow!("frame length {} exceeds maximum {}", serialized.len(), MAX_FRAME_LEN));
  }
  let len = serialized.len() as u16;
  writer.write_u16(len).await?;
  writer.write_all(&serialized).await?;
  writer.flush().await?;
  trace!("write_frame: flushed {} bytes (+2 length prefix)", len);
  Ok(())
}

/// Read a 2-byte port header from incoming data stream
pub async fn read_port_header<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<u16> {
  let mut buf = [0u8; 2];
  reader.read_exact(&mut buf[..]).await?;
  Ok(u16::from_be_bytes(buf))
}
