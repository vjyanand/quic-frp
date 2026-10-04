use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, trace};

use crate::config::ServiceDefinition;

const MAX_FRAME_LEN: usize = u16::MAX as usize;

/// First frame the client sends on the control stream. Carries the auth token
/// after the TLS handshake, so it is never exposed in the cleartext ClientHello.
#[derive(Debug, Clone, bitcode::Encode, bitcode::Decode)]
pub struct ClientHello {
  pub token: Option<String>,
}

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

/// Header the server writes at the start of every data stream: the remote port and
/// whether the stream payload is snappy-compressed. Carrying the compression flag
/// per stream keeps both ends in agreement even while a config reload is in flight.
pub struct StreamHeader {
  pub port: u16,
  pub compression: bool,
}

pub async fn write_stream_header<W: AsyncWrite + Unpin>(writer: &mut W, header: &StreamHeader) -> anyhow::Result<()> {
  let [hi, lo] = header.port.to_be_bytes();
  writer.write_all(&[hi, lo, header.compression as u8]).await?;
  Ok(())
}

pub async fn read_stream_header<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<StreamHeader> {
  let mut buf = [0u8; 3];
  reader.read_exact(&mut buf[..]).await?;
  let compression = match buf[2] {
    0 => false,
    1 => true,
    flag => return Err(anyhow::anyhow!("invalid compression flag {} in stream header", flag)),
  };
  Ok(StreamHeader { port: u16::from_be_bytes([buf[0], buf[1]]), compression })
}

/// Compare secrets without short-circuiting on the first mismatched byte.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
  a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn frame_roundtrip_at_max_len() {
    // The largest payload that fits must survive the u16 length prefix.
    let hello = (0..MAX_FRAME_LEN)
      .rev()
      .map(|n| ClientHello { token: Some("x".repeat(n)) })
      .find(|hello| bitcode::encode(hello).len() <= MAX_FRAME_LEN)
      .unwrap();
    assert!(bitcode::encode(&hello).len() > MAX_FRAME_LEN - 8);
    let mut buf = Vec::new();
    write_frame(&mut buf, &hello).await.unwrap();
    let decoded: ClientHello = read_frame(&mut &buf[..]).await.unwrap();
    assert_eq!(decoded.token, hello.token);
  }

  #[tokio::test]
  async fn frame_over_max_len_rejected() {
    let hello = ClientHello { token: Some("x".repeat(MAX_FRAME_LEN + 1)) };
    assert!(write_frame(&mut Vec::new(), &hello).await.is_err());
  }

  #[tokio::test]
  async fn stream_header_roundtrip() {
    for (port, compression) in [(80u16, false), (65535, true)] {
      let mut buf = Vec::new();
      write_stream_header(&mut buf, &StreamHeader { port, compression }).await.unwrap();
      let header = read_stream_header(&mut &buf[..]).await.unwrap();
      assert_eq!((header.port, header.compression), (port, compression));
    }
    assert!(read_stream_header(&mut &[0u8, 80, 7][..]).await.is_err());
  }

  #[test]
  fn constant_time_eq_works() {
    assert!(constant_time_eq(b"secret", b"secret"));
    assert!(!constant_time_eq(b"secret", b"secreT"));
    assert!(!constant_time_eq(b"secret", b"secret!"));
  }
}
