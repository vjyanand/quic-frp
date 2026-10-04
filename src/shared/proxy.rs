//! Bidirectional forwarding between a TCP connection and a QUIC stream, shared by
//! client and server, with optional snappy compression.
//!
//! Compressed streams are a sequence of frames: `[kind: u8][len: u32 BE][payload]`.
//! Each frame carries at most `MAX_BLOCK` bytes of original data. A block that
//! does not shrink is sent raw, so already-compressed or encrypted traffic
//! costs only the 5-byte header.

use std::io;

use quinn::{RecvStream, SendStream};
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy},
  net::TcpStream,
};
use tracing::debug;

const MAX_BLOCK: usize = 64 * 1024;
const HEADER_LEN: usize = 5;
const KIND_RAW: u8 = 0;
const KIND_SNAPPY: u8 = 1;

/// Forward data both ways until each direction hits EOF or an error.
pub async fn proxy(mut tcp: TcpStream, quic_send: &mut SendStream, quic_recv: &mut RecvStream, compression: bool) {
  let (mut tcp_r, mut tcp_w) = tcp.split();

  let upstream = async {
    let res = if compression {
      compress_copy(&mut tcp_r, quic_send).await
    } else {
      copy(&mut tcp_r, quic_send).await.map(drop)
    };
    let _ = quic_send.finish();
    res
  };

  let downstream = async {
    let res = if compression {
      decompress_copy(quic_recv, &mut tcp_w).await
    } else {
      copy(quic_recv, &mut tcp_w).await.map(drop)
    };
    let _ = tcp_w.shutdown().await;
    res
  };

  let (up, down) = tokio::join!(upstream, downstream);
  if let Err(e) = up {
    debug!("tcp -> quic ended with error: {}", e);
  }
  if let Err(e) = down {
    debug!("quic -> tcp ended with error: {}", e);
  }
}

/// Read until EOF, writing each chunk as one compressed (or raw) frame.
async fn compress_copy<R, W>(reader: &mut R, writer: &mut W) -> io::Result<()>
where
  R: AsyncRead + Unpin + ?Sized,
  W: AsyncWrite + Unpin + ?Sized,
{
  let mut input = vec![0u8; MAX_BLOCK];
  let mut frame = vec![0u8; HEADER_LEN + snap::raw::max_compress_len(MAX_BLOCK)];
  let mut encoder = snap::raw::Encoder::new();

  loop {
    let n = reader.read(&mut input).await?;
    if n == 0 {
      return writer.flush().await;
    }

    let compressed_len = encoder.compress(&input[..n], &mut frame[HEADER_LEN..]).map_err(io::Error::other)?;
    let (kind, len) = if compressed_len < n {
      (KIND_SNAPPY, compressed_len)
    } else {
      frame[HEADER_LEN..HEADER_LEN + n].copy_from_slice(&input[..n]);
      (KIND_RAW, n)
    };
    frame[0] = kind;
    frame[1..HEADER_LEN].copy_from_slice(&(len as u32).to_be_bytes());
    writer.write_all(&frame[..HEADER_LEN + len]).await?;
  }
}

/// Decode frames written by `compress_copy` until a clean EOF between frames.
async fn decompress_copy<R, W>(reader: &mut R, writer: &mut W) -> io::Result<()>
where
  R: AsyncRead + Unpin + ?Sized,
  W: AsyncWrite + Unpin + ?Sized,
{
  let mut header = [0u8; HEADER_LEN];
  let mut payload = vec![0u8; snap::raw::max_compress_len(MAX_BLOCK)];
  let mut output = vec![0u8; MAX_BLOCK];
  let mut decoder = snap::raw::Decoder::new();

  loop {
    // EOF is only clean on a frame boundary.
    if reader.read(&mut header[..1]).await? == 0 {
      return writer.flush().await;
    }
    reader.read_exact(&mut header[1..]).await?;

    let kind = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let max_len = match kind {
      KIND_RAW => MAX_BLOCK,
      KIND_SNAPPY => payload.len(),
      _ => return Err(invalid_data(format!("unknown frame kind {kind}"))),
    };
    if len > max_len {
      return Err(invalid_data(format!("frame length {len} exceeds {max_len}")));
    }

    reader.read_exact(&mut payload[..len]).await?;
    if kind == KIND_RAW {
      writer.write_all(&payload[..len]).await?;
    } else {
      let n = decoder.decompress(&payload[..len], &mut output).map_err(invalid_data)?;
      writer.write_all(&output[..n]).await?;
    }
  }
}

fn invalid_data(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, e)
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Incompressible bytes (xorshift64).
  fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    (0..len)
      .map(|_| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as u8
      })
      .collect()
  }

  /// Push `data` through compress -> decompress over tiny duplex pipes, so writes are
  /// partial and back-pressured (the case the old tokio-snappy adapter dropped data on).
  async fn roundtrip(data: &[u8]) -> Vec<u8> {
    let (mut src_w, mut src_r) = tokio::io::duplex(1024);
    let (mut wire_w, mut wire_r) = tokio::io::duplex(997);
    let (mut dst_w, mut dst_r) = tokio::io::duplex(1024);

    let feed = async {
      src_w.write_all(data).await.unwrap();
      src_w.shutdown().await.unwrap();
    };
    let encode = async {
      compress_copy(&mut src_r, &mut wire_w).await.unwrap();
      wire_w.shutdown().await.unwrap();
    };
    let decode = async {
      decompress_copy(&mut wire_r, &mut dst_w).await.unwrap();
      dst_w.shutdown().await.unwrap();
    };
    let mut out = Vec::new();
    let collect = dst_r.read_to_end(&mut out);
    let (_, _, _, read) = tokio::join!(feed, encode, decode, collect);
    read.unwrap();
    out
  }

  #[tokio::test]
  async fn roundtrips_compressible_incompressible_and_empty() {
    let text = b"the quick brown fox ".repeat(50_000);
    for data in [text, noise(300_000), Vec::new(), vec![7u8; MAX_BLOCK * 3 + 1]] {
      assert!(roundtrip(&data).await == data, "roundtrip mismatch for {} bytes", data.len());
    }
  }

  #[tokio::test]
  async fn rejects_corrupt_frames() {
    let oversized = [&[KIND_RAW][..], &((MAX_BLOCK + 1) as u32).to_be_bytes()].concat();
    let bad_kind = [9u8, 0, 0, 0, 1, 0];
    let truncated_header = [KIND_RAW, 0, 0];
    for input in [&oversized[..], &bad_kind[..], &truncated_header[..]] {
      let mut sink = Vec::new();
      assert!(decompress_copy(&mut &input[..], &mut sink).await.is_err());
    }
  }

  #[tokio::test]
  async fn incompressible_blocks_are_sent_raw() {
    let noise = noise(MAX_BLOCK);
    let mut wire = Vec::new();
    compress_copy(&mut &noise[..], &mut wire).await.unwrap();
    assert_eq!(wire[0], KIND_RAW);
    assert_eq!(wire.len(), HEADER_LEN + noise.len());
  }
}
