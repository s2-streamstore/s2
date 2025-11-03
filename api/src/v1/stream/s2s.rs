use std::{
    io::{Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use enum_ordinalize::Ordinalize;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use futures::Stream;
use zstd::zstd_safe::WriteBuf;

/*
  REGULAR MESSAGE:
  ┌─────────────┬────────────┬─────────────────────────────┐
  │   LENGTH    │   FLAGS    │        PAYLOAD DATA         │
  │  (3 bytes)  │  (1 byte)  │     (variable length)       │
  ├─────────────┼────────────┼─────────────────────────────┤
  │ 0x00 00 XX  │ 0 CA XXXXX │  Compressed proto message   │
  └─────────────┴────────────┴─────────────────────────────┘

  TERMINAL MESSAGE:
  ┌─────────────┬────────────┬─────────────┬───────────────┐
  │   LENGTH    │   FLAGS    │ STATUS CODE │   JSON BODY   │
  │  (3 bytes)  │  (1 byte)  │  (2 bytes)  │  (variable)   │
  ├─────────────┼────────────┼─────────────┼───────────────┤
  │ 0x00 00 XX  │ 1 CA XXXXX │   HTTP Code │   JSON data   │
  └─────────────┴────────────┴─────────────┴───────────────┘

  LENGTH = size of (FLAGS + PAYLOAD), does NOT include length header itself
  Maximum message size: 2^24 - 1 = 16,777,215 bytes
*/

const LENGTH_PREFIX_SIZE: usize = 3;
const STATUS_CODE_SIZE: usize = 2;
const MAX_MESSAGE_SIZE: usize = (1 << 24) - 1; // 16MB - 1

/*
Flag byte layout:
  ┌───┬───┬───┬───┬───┬───┬───┬───┐
  │ 7 │ 6 │ 5 │ 4 │ 3 │ 2 │ 1 │ 0 │  Bit positions
  ├───┼───┴───┼───┴───┴───┴───┴───┤
  │ T │  C C  │   Reserved (0s)   │  Purpose
  └───┴───────┴───────────────────┘

  T = Terminal flag (1 bit)
  C = Compression (2 bits, encodes 0-3)
*/

const FLAG_TOTAL_SIZE: usize = 1;
const FLAG_TERMINAL: u8 = 0b1000_0000;
const FLAG_COMPRESSION_MASK: u8 = 0b0110_0000;
const FLAG_COMPRESSION_SHIFT: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ordinalize)]
#[repr(u8)]
pub enum CompressionAlgorithm {
    None = 0,
    Zstd = 1,
    Gzip = 2,
}

impl CompressionAlgorithm {
    pub fn from_accept_encoding(headers: &http::HeaderMap) -> Self {
        let mut gzip = false;
        for header_value in headers.get_all(http::header::ACCEPT_ENCODING) {
            if let Ok(value) = header_value.to_str() {
                for encoding in value.split(',') {
                    let encoding = encoding.trim().split(';').next().unwrap_or("").trim();
                    if encoding.eq_ignore_ascii_case("zstd") {
                        return Self::Zstd;
                    } else if encoding.eq_ignore_ascii_case("gzip") {
                        gzip = true;
                    }
                }
            }
        }
        if gzip { Self::Gzip } else { Self::None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedData {
    compression: CompressionAlgorithm,
    payload: Bytes,
}

impl CompressedData {
    pub fn for_proto(
        compression: CompressionAlgorithm,
        proto: &impl prost::Message,
    ) -> std::io::Result<Self> {
        Self::compress(compression, proto.encode_to_vec())
    }

    fn compress(
        compression: CompressionAlgorithm,
        data: impl Into<Bytes>,
    ) -> std::io::Result<Self> {
        let payload = data.into();
        if payload.len() < 1024 * 1024 {
            return Ok(Self {
                compression,
                payload,
            });
        }
        let payload = match compression {
            CompressionAlgorithm::None => payload,
            CompressionAlgorithm::Gzip => {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&payload)?;
                let compressed = encoder.finish()?;
                Bytes::from(compressed.into_boxed_slice())
            }
            CompressionAlgorithm::Zstd => {
                let compressed = zstd::encode_all(payload.as_slice(), 0)?;
                Bytes::from(compressed.into_boxed_slice())
            }
        };
        Ok(Self {
            compression,
            payload,
        })
    }

    fn decompressed(self) -> std::io::Result<Bytes> {
        match self.compression {
            CompressionAlgorithm::None => Ok(self.payload),
            CompressionAlgorithm::Gzip => {
                let mut decoder = GzDecoder::new(self.payload.as_slice());
                let mut buf = Vec::with_capacity(self.payload.len() * 2);
                decoder.read_to_end(&mut buf)?;
                Ok(Bytes::from(buf.into_boxed_slice()))
            }
            CompressionAlgorithm::Zstd => {
                let mut buf = Vec::with_capacity(self.payload.len() * 2);
                zstd::stream::copy_decode(self.payload.as_slice(), &mut buf)?;
                Ok(Bytes::from(buf.into_boxed_slice()))
            }
        }
    }

    pub fn try_into_proto<P: prost::Message + Default>(self) -> std::io::Result<P> {
        let payload = self.decompressed()?;
        P::decode(payload.as_ref())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalMessage {
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionMessage {
    Regular(CompressedData),
    Terminal(TerminalMessage),
}

impl From<CompressedData> for SessionMessage {
    fn from(data: CompressedData) -> Self {
        Self::Regular(data)
    }
}

impl From<TerminalMessage> for SessionMessage {
    fn from(msg: TerminalMessage) -> Self {
        Self::Terminal(msg)
    }
}

impl SessionMessage {
    pub fn regular(
        compression: CompressionAlgorithm,
        proto: &impl prost::Message,
    ) -> std::io::Result<Self> {
        Ok(Self::Regular(CompressedData::for_proto(
            compression,
            proto,
        )?))
    }

    pub fn encode(&self) -> Bytes {
        let encoded_size = FLAG_TOTAL_SIZE + self.payload_size();
        assert!(
            encoded_size <= MAX_MESSAGE_SIZE,
            "payload exceeds maximum message size"
        );
        let mut buf = BytesMut::with_capacity(LENGTH_PREFIX_SIZE + encoded_size);
        buf.put_uint(encoded_size as u64, 3);
        match self {
            Self::Regular(msg) => {
                let flag =
                    (msg.compression.ordinal() << FLAG_COMPRESSION_SHIFT) & FLAG_COMPRESSION_MASK;
                buf.put_u8(flag);
                buf.extend_from_slice(&msg.payload);
            }
            Self::Terminal(msg) => {
                buf.put_u8(FLAG_TERMINAL);
                buf.put_u16(msg.status);
                buf.extend_from_slice(msg.body.as_bytes());
            }
        }
        buf.freeze()
    }

    fn decode_message(mut buf: Bytes) -> std::io::Result<Self> {
        let flag = buf.get_u8();

        let is_terminal = (flag & FLAG_TERMINAL) != 0;
        if is_terminal {
            if buf.len() < STATUS_CODE_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "terminal message missing status code",
                ));
            }
            let status = buf.get_u16();
            let body = String::from_utf8(buf.into()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid utf-8")
            })?;
            return Ok(TerminalMessage { status, body }.into());
        }

        let compression_bits = (flag & FLAG_COMPRESSION_MASK) >> FLAG_COMPRESSION_SHIFT;
        let Some(compression) = CompressionAlgorithm::from_ordinal(compression_bits) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown compression algorithm",
            ));
        };

        Ok(CompressedData {
            compression,
            payload: buf,
        }
        .into())
    }

    fn payload_size(&self) -> usize {
        match self {
            Self::Regular(msg) => msg.payload.len(),
            Self::Terminal(msg) => STATUS_CODE_SIZE + msg.body.len(),
        }
    }
}

pub struct FramedMessageStream<S> {
    inner: S,
    compression: CompressionAlgorithm,
    terminated: bool,
}

impl<S> FramedMessageStream<S> {
    pub fn new(compression: CompressionAlgorithm, inner: S) -> Self {
        Self {
            inner,
            compression,
            terminated: false,
        }
    }
}

impl<S, P, E> Stream for FramedMessageStream<S>
where
    S: Stream<Item = Result<P, E>> + Unpin,
    P: prost::Message,
    E: Into<TerminalMessage>,
{
    type Item = std::io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.terminated {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(item))) => {
                let bytes =
                    SessionMessage::regular(self.compression, &item).map(|msg| msg.encode());
                Poll::Ready(Some(bytes))
            }
            Poll::Ready(Some(Err(e))) => {
                self.terminated = true;
                let bytes = SessionMessage::Terminal(e.into()).encode();
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(None) => {
                self.terminated = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct FrameDecoder;

impl tokio_util::codec::Decoder for FrameDecoder {
    type Item = SessionMessage;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < LENGTH_PREFIX_SIZE {
            return Ok(None);
        }

        let length = ((src[0] as usize) << 16) | ((src[1] as usize) << 8) | (src[2] as usize);

        if length > MAX_MESSAGE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "message size exceeds maximum",
            ));
        }

        let total_size = LENGTH_PREFIX_SIZE + length;
        if src.len() < total_size {
            return Ok(None);
        }

        src.advance(LENGTH_PREFIX_SIZE);
        let frame_bytes = src.split_to(length).freeze();
        Ok(Some(SessionMessage::decode_message(frame_bytes)?))
    }
}

#[cfg(test)]
mod test {
    // TODO: port over tests without private deps
}
