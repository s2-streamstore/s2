use std::{
    fmt,
    io::{Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use futures_core::Stream;
use strum::FromRepr;

/*
  REGULAR MESSAGE:
  ┌─────────────┬────────────┬─────────────────────────────┐
  │   LENGTH    │   FLAGS    │        PAYLOAD DATA         │
  │  (3 bytes)  │  (1 byte)  │     (variable length)       │
  ├─────────────┼────────────┼─────────────────────────────┤
  │ 0x00 00 XX  │ 0 CA RXXXX │  Compressed proto message   │
  └─────────────┴────────────┴─────────────────────────────┘

  TERMINAL MESSAGE:
  ┌─────────────┬────────────┬─────────────┬───────────────┐
  │   LENGTH    │   FLAGS    │ STATUS CODE │   JSON BODY   │
  │  (3 bytes)  │  (1 byte)  │  (2 bytes)  │  (variable)   │
  ├─────────────┼────────────┼─────────────┼───────────────┤
  │ 0x00 00 XX  │ 1 CA RXXXX │   HTTP Code │   JSON data   │
  └─────────────┴────────────┴─────────────┴───────────────┘

  LENGTH = size of (FLAGS + PAYLOAD), does NOT include length header itself
  Implemented limit: 2.5 MiB (smaller than 24-bit protocol maximum)
*/

const LENGTH_PREFIX_SIZE: usize = 3;
const STATUS_CODE_SIZE: usize = 2;
const COMPRESSION_THRESHOLD_BYTES: usize = 1024; // 1 KiB
const MAX_FRAME_BYTES: usize = 5 * 512 * 1024; // 2.5 MiB

/*
Flag byte layout:
  ┌───┬───┬───┬───┬───┬───┬───┬───┐
  │ 7 │ 6 │ 5 │ 4 │ 3 │ 2 │ 1 │ 0 │  Bit positions
  ├───┼───┴───┼───┼───┴───┴───┴───┤
  │ T │  C C  │ R │ Reserved (0s) │  Purpose
  └───┴───────┴───┴───────────────┘

  T = Terminal flag (1 bit)
  C = Compression (2 bits, encodes 0-3)
  R = Reconnect advised (1 bit, set by a server that is about to terminate)
*/

const FLAG_TOTAL_SIZE: usize = 1;
// The frame length budget includes one flag byte, so payload bytes are capped at budget - flag.
const MAX_FRAME_PAYLOAD_BYTES: usize = MAX_FRAME_BYTES - FLAG_TOTAL_SIZE;
/// Maximum body bytes allowed in a terminal S2S frame (`MAX_FRAME_BYTES - 1 flag - 2 status`).
pub const MAX_TERMINAL_BODY_BYTES: usize = MAX_FRAME_PAYLOAD_BYTES - STATUS_CODE_SIZE;
const MAX_DECOMPRESSED_PAYLOAD_BYTES: usize = MAX_FRAME_PAYLOAD_BYTES;
const FLAG_TERMINAL: u8 = 0b1000_0000;
const FLAG_COMPRESSION_MASK: u8 = 0b0110_0000;
const FLAG_COMPRESSION_SHIFT: u8 = 5;
const FLAG_RECONNECT_ADVISED: u8 = 0b0001_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
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
                    let mut parts = encoding.split(';');
                    let encoding = parts.next().unwrap_or("").trim();
                    if parts.any(is_zero_qvalue) {
                        continue;
                    }
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

/// Whether an `Accept-Encoding` parameter is a `q=0` weight, which marks the coding as
/// "not acceptable" (RFC 9110 §12.4.2).
fn is_zero_qvalue(param: &str) -> bool {
    let Some((name, value)) = param.split_once('=') else {
        return false;
    };
    name.trim().eq_ignore_ascii_case("q") && value.trim().parse::<f32>().is_ok_and(|q| q == 0.0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedData {
    compression: CompressionAlgorithm,
    reconnect_advised: bool,
    payload: Bytes,
}

impl CompressedData {
    pub fn for_proto(
        compression: CompressionAlgorithm,
        proto: &impl prost::Message,
    ) -> std::io::Result<Self> {
        Self::compress(compression, proto.encode_to_vec())
    }

    /// Whether this frame carried the reconnect-advised flag.
    ///
    /// A server sets the flag on responses when it is about to terminate,
    /// signaling that the client should proactively reconnect.
    pub fn reconnect_advised(&self) -> bool {
        self.reconnect_advised
    }

    fn compress(compression: CompressionAlgorithm, data: Vec<u8>) -> std::io::Result<Self> {
        if data.len() > MAX_DECOMPRESSED_PAYLOAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "payload exceeds decompressed limit",
            ));
        }

        if compression == CompressionAlgorithm::None || data.len() < COMPRESSION_THRESHOLD_BYTES {
            return Ok(Self {
                compression: CompressionAlgorithm::None,
                reconnect_advised: false,
                payload: data.into(),
            });
        }
        let mut buf = Vec::with_capacity(data.len());
        match compression {
            CompressionAlgorithm::Gzip => {
                let mut encoder = GzEncoder::new(buf, Compression::default());
                encoder.write_all(data.as_slice())?;
                buf = encoder.finish()?;
            }
            CompressionAlgorithm::Zstd => {
                zstd::stream::copy_encode(data.as_slice(), &mut buf, 0)?;
            }
            CompressionAlgorithm::None => unreachable!("handled above"),
        };
        let payload = Bytes::from(buf.into_boxed_slice());
        if payload.len() > MAX_FRAME_PAYLOAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "compressed payload exceeds frame limit",
            ));
        }
        Ok(Self {
            compression,
            reconnect_advised: false,
            payload,
        })
    }

    pub fn decompressed(self) -> std::io::Result<Bytes> {
        let initial_capacity = self
            .payload
            .len()
            .saturating_mul(2)
            .clamp(COMPRESSION_THRESHOLD_BYTES, MAX_DECOMPRESSED_PAYLOAD_BYTES);

        // Decode at most `MAX_DECOMPRESSED_PAYLOAD_BYTES + 1` bytes
        fn read_to_end_limited(
            mut reader: impl Read,
            initial_capacity: usize,
        ) -> std::io::Result<Bytes> {
            let mut limited = reader
                .by_ref()
                .take((MAX_DECOMPRESSED_PAYLOAD_BYTES + 1) as u64);
            let mut buf = Vec::with_capacity(initial_capacity);
            limited.read_to_end(&mut buf)?;
            if buf.len() > MAX_DECOMPRESSED_PAYLOAD_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "decompressed payload exceeds limit",
                ));
            }
            Ok(Bytes::from(buf.into_boxed_slice()))
        }

        match self.compression {
            CompressionAlgorithm::None => {
                if self.payload.len() > MAX_DECOMPRESSED_PAYLOAD_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "decompressed payload exceeds limit",
                    ));
                }
                Ok(self.payload)
            }
            CompressionAlgorithm::Gzip => {
                let mut decoder = GzDecoder::new(&self.payload[..]);
                read_to_end_limited(&mut decoder, initial_capacity)
            }
            CompressionAlgorithm::Zstd => {
                let mut decoder = zstd::stream::Decoder::new(&self.payload[..])?;
                // 16 MiB max window covers standard streaming zstd encoders (e.g. 8 MiB default
                // windowLog=23) while bounding decoder memory well below libzstd's 128 MiB default.
                decoder.window_log_max(24)?;
                read_to_end_limited(&mut decoder, initial_capacity)
            }
        }
    }

    /// Decode the protobuf payload, copying `Bytes` fields into independent allocations so
    /// decoded fields do not pin the full frame or transport buffer in memory (for example, while
    /// queued on the server or when an untrusted frame carries skipped unknown-field padding).
    pub fn try_into_proto<P: prost::Message + Default>(self) -> std::io::Result<P> {
        let payload = self.decompressed()?;
        P::decode(payload.as_ref())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Decode the protobuf payload zero-copy by slicing `Bytes` fields directly from the frame
    /// buffer.
    ///
    /// Intended for trusted response frames (such as SDK read streams) where avoiding per-field
    /// copies is desirable and callers understand decoded `Bytes` slices share the frame buffer.
    pub fn try_into_proto_zero_copy<P: prost::Message + Default>(self) -> std::io::Result<P> {
        let payload = self.decompressed()?;
        P::decode(payload).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalMessage {
    pub status: u16,
    pub body: Bytes,
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
        match self {
            Self::Regular(msg) => {
                let encoded_size = FLAG_TOTAL_SIZE + msg.payload.len();
                assert!(
                    encoded_size <= MAX_FRAME_BYTES,
                    "payload exceeds encoder limit"
                );
                let mut buf = BytesMut::with_capacity(LENGTH_PREFIX_SIZE + encoded_size);
                buf.put_uint(encoded_size as u64, 3);
                let mut flag =
                    ((msg.compression as u8) << FLAG_COMPRESSION_SHIFT) & FLAG_COMPRESSION_MASK;
                if msg.reconnect_advised {
                    flag |= FLAG_RECONNECT_ADVISED;
                }
                buf.put_u8(flag);
                buf.extend_from_slice(&msg.payload);
                buf.freeze()
            }
            Self::Terminal(msg) => {
                let body = if msg.body.len() <= MAX_TERMINAL_BODY_BYTES {
                    &msg.body[..]
                } else {
                    &msg.body[..MAX_TERMINAL_BODY_BYTES]
                };
                let encoded_size = FLAG_TOTAL_SIZE + STATUS_CODE_SIZE + body.len();
                let mut buf = BytesMut::with_capacity(LENGTH_PREFIX_SIZE + encoded_size);
                buf.put_uint(encoded_size as u64, 3);
                buf.put_u8(FLAG_TERMINAL);
                buf.put_u16(msg.status);
                buf.extend_from_slice(body);
                buf.freeze()
            }
        }
    }

    fn decode_message(mut buf: Bytes) -> std::io::Result<Self> {
        if buf.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "empty frame payload",
            ));
        }
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
            return Ok(TerminalMessage { status, body: buf }.into());
        }

        let compression_bits = (flag & FLAG_COMPRESSION_MASK) >> FLAG_COMPRESSION_SHIFT;
        let Some(compression) = CompressionAlgorithm::from_repr(compression_bits) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown compression algorithm",
            ));
        };

        Ok(CompressedData {
            compression,
            reconnect_advised: (flag & FLAG_RECONNECT_ADVISED) != 0,
            payload: buf,
        }
        .into())
    }
}

/// Set the reconnect-advised flag on an already encoded frame.
///
/// Terminal frames are returned unchanged.
pub fn advise_reconnect(frame: Bytes) -> Bytes {
    if frame
        .get(LENGTH_PREFIX_SIZE)
        .is_none_or(|flag| flag & FLAG_TERMINAL != 0)
    {
        return frame;
    }

    let mut frame = frame
        .try_into_mut()
        .unwrap_or_else(|frame| BytesMut::from(frame.as_ref()));
    frame[LENGTH_PREFIX_SIZE] |= FLAG_RECONNECT_ADVISED;
    frame.freeze()
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
            Poll::Ready(Some(Ok(item))) => match SessionMessage::regular(self.compression, &item) {
                Ok(msg) => Poll::Ready(Some(Ok(msg.encode()))),
                Err(err) => {
                    self.terminated = true;
                    Poll::Ready(Some(Err(err)))
                }
            },
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

fn parse_frame_length(src: &[u8]) -> std::io::Result<usize> {
    let length = ((src[0] as usize) << 16) | ((src[1] as usize) << 8) | (src[2] as usize);
    if length > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame exceeds decode limit",
        ));
    }
    Ok(length)
}

/// Reserve capacity for an in-progress straddled S2S frame in geometric steps bounded by 2x the
/// bytes actually received so far, clamping to exact `total_size` once reached. This prevents a
/// stalled 3-byte prefix from pre-allocating a 2.5 MiB buffer while keeping completed straddled
/// frames at 1.0x capacity.
fn reserve_for_partial_frame(buffer: &mut Vec<u8>, total_size: usize, incoming_len: usize) {
    let next_len = buffer.len().saturating_add(incoming_len);
    if next_len > buffer.capacity() {
        let target = total_size.min(next_len.saturating_mul(2)).max(next_len);
        buffer.reserve_exact(target.saturating_sub(buffer.len()));
    }
}

pub struct FrameDecoder;

/// Incremental S2S frame decoder for chunked [`Bytes`] streams.
///
/// Complete frames inside an incoming `Bytes` chunk are decoded zero-copy directly from that
/// chunk. Only frames straddling chunk boundaries are reassembled into an isolated per-frame
/// buffer (taken on completion so idle sessions retain zero slab capacity).
///
/// By default ([`Self::new`]), partial-frame buffer reservations grow geometrically capped at `2x`
/// bytes received so far (safe for untrusted server inputs). Trusted client streams may opt into
/// [`Self::with_full_pre_reserve`] to reserve the validated frame length up front in a single
/// allocation once the 3-byte length prefix arrives.
#[derive(Default)]
pub struct ChunkFrameDecoder {
    buffer: Vec<u8>,
    pre_reserve_full: bool,
}

impl fmt::Debug for ChunkFrameDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkFrameDecoder")
            .field("buffered_len", &self.buffer.len())
            .field("buffered_capacity", &self.buffer.capacity())
            .field("pre_reserve_full", &self.pre_reserve_full)
            .finish()
    }
}

impl ChunkFrameDecoder {
    /// Create a decoder with bounded geometric (`<= 2x` received bytes) partial-frame reservation,
    /// suitable for untrusted peers such as server-side append extractors.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            pre_reserve_full: false,
        }
    }

    /// Create a decoder that pre-reserves the exact validated frame length once the 3-byte prefix
    /// arrives (1 allocation per large straddled frame), suitable for trusted streams such as the
    /// SDK client.
    pub fn with_full_pre_reserve() -> Self {
        Self {
            buffer: Vec::new(),
            pre_reserve_full: true,
        }
    }

    /// Number of buffered bytes belonging to an incomplete trailing frame.
    pub fn remaining_len(&self) -> usize {
        self.buffer.len()
    }

    /// Validate that no incomplete trailing frame remains at end of stream.
    pub fn finish(self) -> std::io::Result<()> {
        if !self.buffer.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "truncated s2s frame at end of stream ({} bytes remaining)",
                    self.buffer.len()
                ),
            ));
        }
        Ok(())
    }

    fn reserve_partial(&mut self, total_size: usize, incoming_len: usize) {
        if self.pre_reserve_full {
            let needed = total_size.saturating_sub(self.buffer.len());
            if self.buffer.capacity() < total_size {
                self.buffer.reserve_exact(needed);
            }
        } else {
            reserve_for_partial_frame(&mut self.buffer, total_size, incoming_len);
        }
    }

    /// Decode the next complete S2S frame from `chunk` (and any previously buffered straddled
    /// prefix).
    ///
    /// Call in a loop until `Ok(None)` is returned; once `Ok(None)` is returned, `chunk` has been
    /// completely consumed (with any trailing partial frame buffered internally).
    ///
    /// Discard the decoder after an `Err` is returned; framing errors do not guarantee a
    /// recoverable stream position.
    pub fn decode_next(&mut self, chunk: &mut Bytes) -> std::io::Result<Option<SessionMessage>> {
        if !self.buffer.is_empty() {
            if chunk.is_empty() {
                return Ok(None);
            }
            if self.buffer.len() < LENGTH_PREFIX_SIZE {
                let header_needed = (LENGTH_PREFIX_SIZE - self.buffer.len()).min(chunk.len());
                self.buffer.extend_from_slice(&chunk[..header_needed]);
                chunk.advance(header_needed);
                if self.buffer.len() < LENGTH_PREFIX_SIZE {
                    return Ok(None);
                }
            }
            let length = parse_frame_length(&self.buffer)?;
            let total_size = LENGTH_PREFIX_SIZE + length;
            let needed = total_size.saturating_sub(self.buffer.len());
            if chunk.len() < needed {
                if !chunk.is_empty() {
                    self.reserve_partial(total_size, chunk.len());
                    self.buffer.extend_from_slice(chunk);
                    chunk.clear();
                } else if self.pre_reserve_full {
                    self.reserve_partial(total_size, 0);
                }
                return Ok(None);
            }
            if needed > 0 {
                self.buffer.reserve_exact(needed);
                self.buffer.extend_from_slice(&chunk[..needed]);
                chunk.advance(needed);
            }
            let frame = std::mem::take(&mut self.buffer);
            let mut frame_bytes = Bytes::from(frame);
            frame_bytes.advance(LENGTH_PREFIX_SIZE);
            debug_assert_eq!(frame_bytes.len(), length);
            return Ok(Some(SessionMessage::decode_message(frame_bytes)?));
        }

        if chunk.is_empty() {
            return Ok(None);
        }
        if chunk.len() >= LENGTH_PREFIX_SIZE {
            let length = parse_frame_length(chunk)?;
            let total_size = LENGTH_PREFIX_SIZE + length;
            if chunk.len() >= total_size {
                chunk.advance(LENGTH_PREFIX_SIZE);
                let frame_bytes = chunk.split_to(length);
                return Ok(Some(SessionMessage::decode_message(frame_bytes)?));
            }
            self.reserve_partial(total_size, chunk.len());
        }
        self.buffer.extend_from_slice(chunk);
        chunk.clear();
        Ok(None)
    }
}

impl tokio_util::codec::Decoder for FrameDecoder {
    type Item = SessionMessage;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < LENGTH_PREFIX_SIZE {
            return Ok(None);
        }

        let length = parse_frame_length(src)?;
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
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use bytes::BytesMut;
    use futures::StreamExt;
    use http::HeaderValue;
    use proptest::{collection::vec, prelude::*};
    use prost::Message;
    use tokio_util::codec::Decoder;

    use super::*;

    #[derive(Clone, PartialEq, prost::Message)]
    struct TestProto {
        #[prost(bytes, tag = "1")]
        payload: Vec<u8>,
    }

    impl TestProto {
        fn new(payload: Vec<u8>) -> Self {
            Self { payload }
        }
    }

    #[derive(Debug, Clone)]
    struct TestError {
        status: u16,
        body: &'static str,
    }

    impl From<TestError> for TerminalMessage {
        fn from(val: TestError) -> Self {
            TerminalMessage {
                status: val.status,
                body: Bytes::from_static(val.body.as_bytes()),
            }
        }
    }

    fn decode_once(bytes: &Bytes) -> io::Result<SessionMessage> {
        let mut decoder = FrameDecoder;
        let mut buf = BytesMut::from(bytes.as_ref());
        decoder
            .decode(&mut buf)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "frame incomplete"))
    }

    fn compression_strategy() -> impl proptest::strategy::Strategy<Value = CompressionAlgorithm> {
        prop_oneof![
            Just(CompressionAlgorithm::None),
            Just(CompressionAlgorithm::Gzip),
            Just(CompressionAlgorithm::Zstd),
        ]
    }

    fn chunk_bytes(data: &Bytes, pattern: &[usize]) -> Vec<Bytes> {
        let mut chunks = Vec::new();
        let mut offset = 0;
        for &hint in pattern {
            if offset >= data.len() {
                break;
            }
            let remaining = data.len() - offset;
            let take = (hint % remaining).saturating_add(1).min(remaining);
            chunks.push(data.slice(offset..offset + take));
            offset += take;
        }
        if offset < data.len() {
            chunks.push(data.slice(offset..));
        }
        if chunks.is_empty() {
            chunks.push(data.clone());
        }
        chunks
    }

    proptest! {
        #[test]
        fn regular_session_message_round_trips_proptest(
            algo in compression_strategy(),
            payload in vec(any::<u8>(), 0..=COMPRESSION_THRESHOLD_BYTES * 4)
        ) {
            let proto = TestProto::new(payload.clone());
            let msg = SessionMessage::regular(algo, &proto).unwrap();
            let encoded = msg.encode();
            let decoded = decode_once(&encoded).unwrap();

            prop_assert!(matches!(decoded, SessionMessage::Regular(_)));
            let SessionMessage::Regular(data) = decoded else { unreachable!() };

            let expected_compression = if algo == CompressionAlgorithm::None || proto.encoded_len() < COMPRESSION_THRESHOLD_BYTES {
                CompressionAlgorithm::None
            } else {
                algo
            };
            let actual_compression = data.compression;

            let restored = data.try_into_proto::<TestProto>().unwrap();
            prop_assert_eq!(restored.payload, payload);
            prop_assert_eq!(actual_compression, expected_compression);
        }

        #[test]
        fn frame_decoder_handles_chunked_frames(
            algo in compression_strategy(),
            payload in vec(any::<u8>(), 0..=COMPRESSION_THRESHOLD_BYTES * 4),
            chunk_pattern in vec(0usize..=16, 0..=16)
        ) {
            let proto = TestProto::new(payload);
            let msg = SessionMessage::regular(algo, &proto).unwrap();
            let encoded = msg.encode();
            let expected = decode_once(&encoded).unwrap();

            let chunks = chunk_bytes(&encoded, &chunk_pattern);
            prop_assert_eq!(chunks.iter().map(|c| c.len()).sum::<usize>(), encoded.len());

            let mut decoder = FrameDecoder;
            let mut buf = BytesMut::new();
            let mut decoded = None;

            for (idx, chunk) in chunks.iter().enumerate() {
                buf.extend_from_slice(chunk.as_ref());
                let result = decoder.decode(&mut buf).expect("decode invocation failed");
                if idx < chunks.len() - 1 {
                    prop_assert!(result.is_none());
                } else {
                    let message = result.expect("final chunk should produce frame");
                    prop_assert!(buf.is_empty());
                    decoded = Some(message);
                }
            }

            let decoded = decoded.expect("decoder never emitted frame");
            prop_assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn from_accept_encoding_prefers_zstd() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, zstd, br"),
        );

        let algo = CompressionAlgorithm::from_accept_encoding(&headers);
        assert_eq!(algo, CompressionAlgorithm::Zstd);
    }

    #[test]
    fn from_accept_encoding_falls_back_to_gzip() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip;q=0.8, deflate"),
        );

        let algo = CompressionAlgorithm::from_accept_encoding(&headers);
        assert_eq!(algo, CompressionAlgorithm::Gzip);
    }

    #[rstest::rstest]
    #[case("zstd;q=0, gzip", CompressionAlgorithm::Gzip)]
    #[case("zstd; q=0.0, gzip;q=0.5", CompressionAlgorithm::Gzip)]
    #[case("gzip;q=0", CompressionAlgorithm::None)]
    #[case("gzip;Q=0.000, zstd;q=0", CompressionAlgorithm::None)]
    #[case("zstd;q=0.001", CompressionAlgorithm::Zstd)]
    fn from_accept_encoding_skips_refused_codings(
        #[case] accept_encoding: &'static str,
        #[case] expected: CompressionAlgorithm,
    ) {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::ACCEPT_ENCODING,
            HeaderValue::from_static(accept_encoding),
        );

        let algo = CompressionAlgorithm::from_accept_encoding(&headers);
        assert_eq!(algo, expected);
    }

    #[test]
    fn from_accept_encoding_defaults_to_none() {
        let headers = http::HeaderMap::new();
        let algo = CompressionAlgorithm::from_accept_encoding(&headers);
        assert_eq!(algo, CompressionAlgorithm::None);
    }

    #[test]
    fn regular_session_message_round_trips() {
        let proto = TestProto::new(vec![1, 2, 3, 4]);
        let msg = SessionMessage::regular(CompressionAlgorithm::None, &proto).unwrap();
        let encoded = msg.encode();
        let decoded = decode_once(&encoded).unwrap();

        match decoded {
            SessionMessage::Regular(data) => {
                assert_eq!(data.compression, CompressionAlgorithm::None);
                let restored = data.try_into_proto::<TestProto>().unwrap();
                assert_eq!(restored, proto);
            }
            SessionMessage::Terminal(_) => panic!("expected regular message"),
        }
    }

    #[test]
    fn terminal_session_message_round_trips() {
        let terminal = TerminalMessage {
            status: 418,
            body: Bytes::from_static(b"short-circuit"),
        };
        let msg = SessionMessage::from(terminal.clone());
        let encoded = msg.encode();
        let decoded = decode_once(&encoded).unwrap();

        match decoded {
            SessionMessage::Regular(_) => panic!("expected terminal message"),
            SessionMessage::Terminal(decoded_terminal) => {
                assert_eq!(decoded_terminal, terminal);
            }
        }
    }

    #[test]
    fn frame_decoder_waits_for_complete_frame() {
        let proto = TestProto::new(vec![9, 9, 9]);
        let msg = SessionMessage::regular(CompressionAlgorithm::None, &proto).unwrap();
        let encoded = msg.encode();
        let mut decoder = FrameDecoder;

        let split_idx = encoded.len() - 1;
        let mut buf = BytesMut::from(&encoded[..split_idx]);
        assert!(decoder.decode(&mut buf).unwrap().is_none());
        buf.extend_from_slice(&encoded[split_idx..]);
        let decoded = decoder.decode(&mut buf).unwrap().unwrap();

        match decoded {
            SessionMessage::Regular(data) => {
                let restored = data.try_into_proto::<TestProto>().unwrap();
                assert_eq!(restored, proto);
            }
            SessionMessage::Terminal(_) => panic!("expected regular message"),
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn frame_decoder_rejects_frames_exceeding_decode_limit() {
        let length = MAX_FRAME_BYTES + 1;
        let prefix = [
            ((length >> 16) & 0xFF) as u8,
            ((length >> 8) & 0xFF) as u8,
            (length & 0xFF) as u8,
        ];
        let mut buf = BytesMut::from(prefix.as_slice());
        let mut decoder = FrameDecoder;
        let err = decoder.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    #[should_panic(expected = "encoder limit")]
    fn session_message_encode_rejects_frames_over_limit() {
        let data = CompressedData {
            compression: CompressionAlgorithm::None,
            reconnect_advised: false,
            payload: Bytes::from(vec![0u8; MAX_FRAME_BYTES]),
        };
        let msg = SessionMessage::from(data);
        let _ = msg.encode();
    }

    #[test]
    fn frame_decoder_rejects_unknown_compression() {
        let mut raw = vec![0, 0, 1];
        raw.push(0x60);
        let mut decoder = FrameDecoder;
        let mut buf = BytesMut::from(raw.as_slice());
        let err = decoder.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_decoder_rejects_terminal_without_status() {
        let mut raw = vec![0, 0, 1];
        raw.push(FLAG_TERMINAL);
        let mut decoder = FrameDecoder;
        let mut buf = BytesMut::from(raw.as_slice());
        let err = decoder.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_decoder_handles_empty_payload() {
        let raw = vec![0, 0, 0];
        let mut decoder = FrameDecoder;
        let mut buf = BytesMut::from(raw.as_slice());
        let err = decoder.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn compressed_data_round_trip_gzip() {
        let payload = vec![42; 1_200_000];
        let proto = TestProto::new(payload.clone());
        let msg = SessionMessage::regular(CompressionAlgorithm::Gzip, &proto).unwrap();
        let encoded = msg.encode();
        let decoded = decode_once(&encoded).unwrap();

        match decoded {
            SessionMessage::Regular(data) => {
                assert_eq!(data.compression, CompressionAlgorithm::Gzip);
                assert!(data.payload.len() < proto.encode_to_vec().len());
                let restored = data.try_into_proto::<TestProto>().unwrap();
                assert_eq!(restored.payload, payload);
            }
            SessionMessage::Terminal(_) => panic!("expected regular message"),
        }
    }

    #[test]
    fn compressed_data_round_trip_zstd() {
        let payload = vec![7; 1_100_000];
        let proto = TestProto::new(payload.clone());
        let msg = SessionMessage::regular(CompressionAlgorithm::Zstd, &proto).unwrap();
        let encoded = msg.encode();
        let decoded = decode_once(&encoded).unwrap();

        match decoded {
            SessionMessage::Regular(data) => {
                assert_eq!(data.compression, CompressionAlgorithm::Zstd);
                assert!(data.payload.len() < proto.encode_to_vec().len());
                let restored = data.try_into_proto::<TestProto>().unwrap();
                assert_eq!(restored.payload, payload);
            }
            SessionMessage::Terminal(_) => panic!("expected regular message"),
        }
    }

    #[test]
    fn decompression_rejects_payloads_exceeding_limit() {
        let payload = vec![0; MAX_DECOMPRESSED_PAYLOAD_BYTES + 1];
        let proto = TestProto::new(payload);
        let encoded = proto.encode_to_vec();

        for algo in [CompressionAlgorithm::Gzip, CompressionAlgorithm::Zstd] {
            let compressed = match algo {
                CompressionAlgorithm::Gzip => {
                    let mut out = Vec::new();
                    let mut encoder = GzEncoder::new(&mut out, Compression::default());
                    encoder.write_all(encoded.as_slice()).unwrap();
                    encoder.finish().unwrap();
                    out
                }
                CompressionAlgorithm::Zstd => {
                    let mut out = Vec::new();
                    zstd::stream::copy_encode(encoded.as_slice(), &mut out, 0).unwrap();
                    out
                }
                CompressionAlgorithm::None => unreachable!("explicitly excluded in test"),
            };

            let data = CompressedData {
                compression: algo,
                reconnect_advised: false,
                payload: Bytes::from(compressed),
            };
            assert!(data.payload.len() <= MAX_FRAME_PAYLOAD_BYTES);

            let err = data.try_into_proto::<TestProto>().expect_err("should fail");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(
                err.to_string()
                    .contains("decompressed payload exceeds limit")
            );
        }
    }

    #[test]
    fn compress_rejects_payloads_exceeding_decompressed_limit() {
        let payload = vec![0; MAX_DECOMPRESSED_PAYLOAD_BYTES + 1];
        let proto = TestProto::new(payload);

        let err = CompressedData::compress(CompressionAlgorithm::Gzip, proto.encode_to_vec())
            .expect_err("should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string()
                .contains("payload exceeds decompressed limit")
        );
    }

    #[test]
    fn compress_allows_payload_at_exact_limit_without_encode_panic() {
        let payload = vec![0; MAX_DECOMPRESSED_PAYLOAD_BYTES];
        let data = CompressedData::compress(CompressionAlgorithm::None, payload).unwrap();
        let encoded = SessionMessage::from(data).encode();
        assert_eq!(encoded.len(), LENGTH_PREFIX_SIZE + MAX_FRAME_BYTES);
    }

    #[test]
    fn compress_rejects_incompressible_payload_that_exceeds_frame_limit_after_compression() {
        let mut payload = vec![0u8; MAX_DECOMPRESSED_PAYLOAD_BYTES];
        let mut x = 0x1234_5678u32;
        for byte in &mut payload {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *byte = (x & 0xFF) as u8;
        }

        for algo in [CompressionAlgorithm::Gzip, CompressionAlgorithm::Zstd] {
            let err = CompressedData::compress(algo, payload.clone()).expect_err("should fail");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(
                err.to_string()
                    .contains("compressed payload exceeds frame limit")
            );
        }
    }

    #[test]
    fn framed_message_stream_yields_terminal_on_error() {
        let proto = TestProto::new(vec![1, 2, 3]);
        let items = vec![
            Ok(proto.clone()),
            Err(TestError {
                status: 500,
                body: "boom",
            }),
            Ok(proto.clone()),
        ];

        let stream = futures::stream::iter(items);
        let framed = FramedMessageStream::new(CompressionAlgorithm::None, stream);
        let outputs = futures::executor::block_on(async {
            framed.collect::<Vec<std::io::Result<Bytes>>>().await
        });

        assert_eq!(outputs.len(), 2);

        let first = outputs[0].as_ref().expect("first frame ok");
        match decode_once(first).unwrap() {
            SessionMessage::Regular(data) => {
                let restored = data.try_into_proto::<TestProto>().unwrap();
                assert_eq!(restored, proto);
            }
            SessionMessage::Terminal(_) => panic!("expected regular message"),
        }

        let second = outputs[1].as_ref().expect("second frame ok");
        match decode_once(second).unwrap() {
            SessionMessage::Regular(_) => panic!("expected terminal message"),
            SessionMessage::Terminal(term) => {
                assert_eq!(term.status, 500);
                assert_eq!(term.body, "boom");
            }
        }
    }

    #[test]
    fn framed_message_stream_stops_after_termination() {
        let mut stream = FramedMessageStream::new(
            CompressionAlgorithm::None,
            futures::stream::iter(vec![
                Ok(TestProto::new(vec![0])),
                Err(TestError {
                    status: 400,
                    body: "bad",
                }),
            ]),
        );

        let mut cx = Context::from_waker(futures::task::noop_waker_ref());

        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(bytes))) => match decode_once(&bytes).unwrap() {
                SessionMessage::Regular(_) => {}
                SessionMessage::Terminal(_) => panic!("expected regular message"),
            },
            other => panic!("unexpected poll result: {other:?}"),
        }

        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(bytes))) => match decode_once(&bytes).unwrap() {
                SessionMessage::Terminal(term) => {
                    assert_eq!(term.status, 400);
                    assert_eq!(term.body, "bad");
                }
                SessionMessage::Regular(_) => panic!("expected terminal message"),
            },
            other => panic!("unexpected poll result: {other:?}"),
        }

        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(None) => {}
            other => panic!("expected stream to terminate, got {other:?}"),
        }
    }

    #[test]
    fn framed_message_stream_terminates_after_encoding_error() {
        let oversized = MAX_DECOMPRESSED_PAYLOAD_BYTES + 1;
        let items: Vec<Result<TestProto, TestError>> = vec![
            Ok(TestProto::new(vec![0u8; oversized])),
            Ok(TestProto::new(vec![1u8; oversized])),
        ];
        let mut stream =
            FramedMessageStream::new(CompressionAlgorithm::None, futures::stream::iter(items));

        let mut cx = Context::from_waker(futures::task::noop_waker_ref());

        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(Some(Err(err))) => {
                assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
                assert!(
                    err.to_string()
                        .contains("payload exceeds decompressed limit")
                );
            }
            other => panic!("expected encoding error, got {other:?}"),
        }

        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(None) => {}
            other => panic!("expected stream to terminate after encoding error, got {other:?}"),
        }
    }

    fn wire_frame_strategy() -> impl proptest::strategy::Strategy<Value = Vec<u8>> {
        let regular = (
            compression_strategy(),
            vec(any::<u8>(), 0..=COMPRESSION_THRESHOLD_BYTES * 2),
        )
            .prop_map(|(algo, payload)| {
                SessionMessage::regular(algo, &TestProto::new(payload))
                    .unwrap()
                    .encode()
                    .to_vec()
            });
        let terminal = (any::<u16>(), vec(any::<u8>(), 0..=64)).prop_map(|(status, body)| {
            SessionMessage::Terminal(TerminalMessage {
                status,
                body: Bytes::from(body),
            })
            .encode()
            .to_vec()
        });
        let oversized_len = MAX_FRAME_BYTES + 1;
        let error_frame = prop_oneof![
            // Zero-length frame (empty payload).
            Just(vec![0, 0, 0]),
            // Oversized length prefix (> MAX_FRAME_BYTES).
            Just(vec![
                ((oversized_len >> 16) & 0xFF) as u8,
                ((oversized_len >> 8) & 0xFF) as u8,
                (oversized_len & 0xFF) as u8,
                0x00,
            ]),
            // Unknown compression bits (0b11).
            Just(vec![0, 0, 1, 0x60]),
            // Terminal frame missing 2-byte status code.
            Just(vec![0, 0, 1, FLAG_TERMINAL]),
        ];
        prop_oneof![
            4 => regular,
            2 => terminal,
            1 => error_frame,
        ]
    }

    fn split_wire_with_empties(wire: &[u8], hints: &[usize]) -> Vec<Bytes> {
        let mut chunks = Vec::new();
        let mut offset = 0;
        for &hint in hints {
            if offset >= wire.len() {
                break;
            }
            if hint == 0 {
                chunks.push(Bytes::new());
                continue;
            }
            let remaining = wire.len() - offset;
            let take = hint.min(remaining);
            chunks.push(Bytes::copy_from_slice(&wire[offset..offset + take]));
            offset += take;
        }
        if offset < wire.len() {
            chunks.push(Bytes::copy_from_slice(&wire[offset..]));
        }
        chunks
    }

    proptest! {
        #[test]
        fn chunk_frame_decoder_matches_frame_decoder_across_splits_and_errors(
            frames in vec(wire_frame_strategy(), 1..=5),
            trailing_truncation in proptest::option::of(1usize..=8),
            split_hints in vec(0usize..=12, 0..=24),
        ) {
            let mut wire = Vec::new();
            for frame in &frames {
                wire.extend_from_slice(frame);
            }
            if let Some(trim) = trailing_truncation {
                // Append a valid regular frame prefix missing its last bytes.
                let partial = SessionMessage::regular(
                    CompressionAlgorithm::None,
                    &TestProto::new(vec![0x55; 16]),
                )
                .unwrap()
                .encode();
                let keep = partial.len().saturating_sub(trim).max(1);
                wire.extend_from_slice(&partial[..keep]);
            }

            let chunks = split_wire_with_empties(&wire, &split_hints);

            // Reference: tokio_util::codec::Decoder (FrameDecoder + BytesMut).
            let mut ref_dec = FrameDecoder;
            let mut ref_buf = BytesMut::new();
            let mut ref_msgs = Vec::new();
            let mut ref_err = None;
            'ref_loop: for chunk in &chunks {
                ref_buf.extend_from_slice(chunk);
                loop {
                    match ref_dec.decode(&mut ref_buf) {
                        Ok(Some(msg)) => ref_msgs.push(msg),
                        Ok(None) => break,
                        Err(e) => {
                            ref_err = Some(e.kind());
                            break 'ref_loop;
                        }
                    }
                }
            }

            for mut dec in [
                ChunkFrameDecoder::new(),
                ChunkFrameDecoder::with_full_pre_reserve(),
            ] {
                let mut msgs = Vec::new();
                let mut err = None;
                'dec_loop: for chunk in &chunks {
                    let mut c = chunk.clone();
                    loop {
                        match dec.decode_next(&mut c) {
                            Ok(Some(msg)) => msgs.push(msg),
                            Ok(None) => break,
                            Err(e) => {
                                err = Some(e.kind());
                                break 'dec_loop;
                            }
                        }
                    }
                }
                prop_assert_eq!(&msgs, &ref_msgs);
                prop_assert_eq!(err, ref_err);
                if ref_err.is_none() {
                    prop_assert_eq!(dec.remaining_len(), ref_buf.len());
                    if dec.remaining_len() == 0 {
                        prop_assert_eq!(dec.buffer.capacity(), 0);
                    }
                }
            }
        }
    }

    #[test]
    fn try_into_proto_copies_while_zero_copy_aliases_frame_buffer() {
        #[derive(Clone, PartialEq, prost::Message)]
        struct BytesProto {
            #[prost(bytes = "bytes", tag = "1")]
            payload: Bytes,
        }

        let proto = BytesProto {
            payload: Bytes::from_static(b"small-record-body"),
        };
        let frame = SessionMessage::regular(CompressionAlgorithm::None, &proto)
            .unwrap()
            .encode();
        let frame_start = frame.as_ptr() as usize;
        let frame_end = frame_start + frame.len();

        let mut wire = frame.clone();
        let mut decoder = ChunkFrameDecoder::new();
        let SessionMessage::Regular(data) = decoder.decode_next(&mut wire).unwrap().unwrap() else {
            panic!("expected regular frame");
        };
        assert!(wire.is_empty());

        let copied = data.clone().try_into_proto::<BytesProto>().unwrap();
        assert_eq!(copied, proto);
        let copied_ptr = copied.payload.as_ptr() as usize;
        assert!(
            copied_ptr < frame_start || copied_ptr >= frame_end,
            "try_into_proto must copy out of the frame buffer"
        );

        let zero_copy = data.try_into_proto_zero_copy::<BytesProto>().unwrap();
        assert_eq!(zero_copy, proto);
        let zc_start = zero_copy.payload.as_ptr() as usize;
        let zc_end = zc_start + zero_copy.payload.len();
        assert!(
            zc_start >= frame_start && zc_end <= frame_end,
            "try_into_proto_zero_copy must alias the frame buffer"
        );
    }

    #[test]
    fn chunk_frame_decoder_bounds_stalled_prefixes_and_pre_reserves_without_realloc() {
        // 1. Server mode (`new()`): stalled 3-byte prefix claiming 2 MiB must not pre-allocate.
        let mut server = ChunkFrameDecoder::new();
        let mut stalled = Bytes::from_static(&[0x20, 0x00, 0x00]); // 2 MiB frame
        assert!(server.decode_next(&mut stalled).unwrap().is_none());
        assert_eq!(server.remaining_len(), 3);
        assert!(
            server.buffer.capacity() <= 64,
            "unexpected server pre-allocation on 3-byte prefix: {}",
            server.buffer.capacity()
        );

        // Server mode converges to exact capacity across multi-chunk frames and drops idle slab.
        for payload_len in [307 * 1024, 1024 * 1024 + 5] {
            let proto = TestProto::new(vec![0xAB; payload_len]);
            let frame = SessionMessage::regular(CompressionAlgorithm::None, &proto)
                .unwrap()
                .encode();
            let mut dec = ChunkFrameDecoder::new();
            let mut decoded = None;
            for piece in frame.chunks(16 * 1024) {
                let mut chunk = Bytes::copy_from_slice(piece);
                while let Some(msg) = dec.decode_next(&mut chunk).unwrap() {
                    decoded = Some(msg);
                }
            }
            assert_eq!(dec.remaining_len(), 0);
            assert_eq!(dec.buffer.capacity(), 0);
            let SessionMessage::Regular(data) = decoded.expect("frame decoded") else {
                panic!("expected regular frame");
            };
            assert_eq!(data.try_into_proto::<TestProto>().unwrap(), proto);
        }

        // 2. Client mode (`with_full_pre_reserve()`): split 3-byte prefix + 512 KiB frame whose
        //    final 16 KiB chunk crosses into small Frame 2 + partial Frame 3 pre-reserves once with
        //    zero reallocation and drops the large buffer immediately on Frame 1 completion.
        let f1 = SessionMessage::regular(
            CompressionAlgorithm::None,
            &TestProto::new(vec![0xEE; 512 * 1024]),
        )
        .unwrap()
        .encode();
        let f2 =
            SessionMessage::regular(CompressionAlgorithm::None, &TestProto::new(vec![0x42; 64]))
                .unwrap()
                .encode();
        let f3 =
            SessionMessage::regular(CompressionAlgorithm::None, &TestProto::new(vec![0x77; 128]))
                .unwrap()
                .encode();
        let mut wire = Vec::with_capacity(f1.len() + f2.len() + 10);
        wire.extend_from_slice(&f1);
        wire.extend_from_slice(&f2);
        wire.extend_from_slice(&f3[..10]);

        let mut chunks = vec![Bytes::copy_from_slice(&wire[..1])];
        for slice in wire[1..].chunks(16 * 1024) {
            chunks.push(Bytes::copy_from_slice(slice));
        }

        let mut client = ChunkFrameDecoder::with_full_pre_reserve();
        let mut reserved_ptr: Option<*const u8> = None;
        let mut decoded_count = 0usize;
        for mut chunk in chunks {
            while let Some(msg) = client.decode_next(&mut chunk).unwrap() {
                assert!(matches!(msg, SessionMessage::Regular(_)));
                decoded_count += 1;
                if decoded_count == 1 {
                    assert_eq!(
                        client.buffer.capacity(),
                        0,
                        "large Frame 1 buffer must be taken immediately"
                    );
                    assert!(
                        !chunk.is_empty(),
                        "Frame 2 and partial Frame 3 must remain in chunk for zero-copy decode"
                    );
                }
            }
            if decoded_count == 0 && client.remaining_len() >= 3 {
                assert!(client.buffer.capacity() >= f1.len());
                match reserved_ptr {
                    None => reserved_ptr = Some(client.buffer.as_ptr()),
                    Some(ptr) => assert_eq!(
                        client.buffer.as_ptr(),
                        ptr,
                        "pre-reserved frame must not reallocate on subsequent chunks"
                    ),
                }
            }
        }
        assert_eq!(decoded_count, 2);
        assert_eq!(client.remaining_len(), 10);
        assert!(
            client.buffer.capacity() <= f3.len() + 64,
            "partial Frame 3 must use a small buffer, got {}",
            client.buffer.capacity()
        );
        let err = client.finish().expect_err("truncated trailing frame");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(err.to_string().contains("10 bytes remaining"));
        ChunkFrameDecoder::new().finish().unwrap();
    }
}
