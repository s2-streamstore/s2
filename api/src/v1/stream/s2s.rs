use std::{
    io::{Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::{Compression, bufread::GzDecoder, write::GzEncoder};
use futures_core::Stream;
use strum::FromRepr;

use crate::compression::{ZSTD_MAX_WINDOW_LOG, compressed_capacity_bound, shrink_if_excess_slack};

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
const REGULAR_HEADER_SIZE: usize = LENGTH_PREFIX_SIZE + FLAG_TOTAL_SIZE;
// The frame length budget includes one flag byte, so payload bytes are capped at budget - flag.
const MAX_FRAME_PAYLOAD_BYTES: usize = MAX_FRAME_BYTES - FLAG_TOTAL_SIZE;
/// Maximum body bytes allowed in a terminal S2S frame (`MAX_FRAME_BYTES - 1 flag - 2 status`).
pub const MAX_TERMINAL_BODY_BYTES: usize = MAX_FRAME_PAYLOAD_BYTES - STATUS_CODE_SIZE;
const MAX_DECOMPRESSED_PAYLOAD_BYTES: usize = MAX_FRAME_PAYLOAD_BYTES;
const FLAG_TERMINAL: u8 = 0b1000_0000;
const FLAG_COMPRESSION_MASK: u8 = 0b0110_0000;
const FLAG_COMPRESSION_SHIFT: u8 = 5;
const FLAG_RECONNECT_ADVISED: u8 = 0b0001_0000;
const FRAME_MIN_SLACK_BYTES: usize = 64;

fn validate_decompressed_len(len: usize) -> std::io::Result<()> {
    if len > MAX_DECOMPRESSED_PAYLOAD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload exceeds decompressed limit",
        ));
    }
    Ok(())
}

fn validate_decoded_len(len: usize) -> std::io::Result<()> {
    if len > MAX_DECOMPRESSED_PAYLOAD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "decompressed payload exceeds limit",
        ));
    }
    Ok(())
}

fn zstd_encode_into(raw: &[u8], out: Vec<u8>) -> std::io::Result<Vec<u8>> {
    let mut encoder = zstd::stream::write::Encoder::new(out, 0)?;
    // Explicitly pledging the source length writes the exact content size and clamps the frame's
    // decoder window across all payload sizes (including `>= 128 KiB`, where `copy_encode` omits
    // content size and advertises a 2 MiB window) without relying on `copy_encode`'s internal
    // buffering.
    encoder.set_pledged_src_size(Some(raw.len() as u64))?;
    encoder.write_all(raw)?;
    encoder.finish()
}

/// Compress `raw` by appending to `out`, enforcing `MAX_FRAME_PAYLOAD_BYTES` on the newly appended
/// compressed payload bytes and trimming excess pre-allocated slack.
fn compress_into(
    compression: CompressionAlgorithm,
    raw: &[u8],
    out: Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    let prefix_len = out.len();
    let mut out = match compression {
        CompressionAlgorithm::Gzip => {
            let mut encoder = GzEncoder::new(out, Compression::default());
            encoder.write_all(raw)?;
            encoder.finish()?
        }
        CompressionAlgorithm::Zstd => zstd_encode_into(raw, out)?,
        CompressionAlgorithm::None => unreachable!("caller handles uncompressed payloads"),
    };
    let payload_len = out.len() - prefix_len;
    if payload_len > MAX_FRAME_PAYLOAD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "compressed payload exceeds frame limit",
        ));
    }
    // Trim excess pre-allocated slack when compression ratio is high so inflight frames
    // don't pin an uncompressed-sized allocation while awaiting acknowledgement.
    shrink_if_excess_slack(&mut out, FRAME_MIN_SLACK_BYTES);
    Ok(out)
}

fn read_to_end_limited(reader: impl Read, initial_capacity: usize) -> std::io::Result<Bytes> {
    let mut limited = reader.take((MAX_DECOMPRESSED_PAYLOAD_BYTES + 1) as u64);
    let mut buf = Vec::with_capacity(initial_capacity);
    limited.read_to_end(&mut buf)?;
    validate_decoded_len(buf.len())?;
    shrink_if_excess_slack(&mut buf, FRAME_MIN_SLACK_BYTES);
    Ok(Bytes::from(buf))
}

fn regular_flag(compression: CompressionAlgorithm, reconnect_advised: bool) -> u8 {
    let mut flag = ((compression as u8) << FLAG_COMPRESSION_SHIFT) & FLAG_COMPRESSION_MASK;
    if reconnect_advised {
        flag |= FLAG_RECONNECT_ADVISED;
    }
    flag
}

fn write_length_prefix(dst: &mut [u8], frame_len: usize) {
    debug_assert!(frame_len <= MAX_FRAME_BYTES);
    dst[0] = ((frame_len >> 16) & 0xFF) as u8;
    dst[1] = ((frame_len >> 8) & 0xFF) as u8;
    dst[2] = (frame_len & 0xFF) as u8;
}

/// Encode `proto` into `dst` using prost's `#[doc(hidden)]` `encode_raw` (avoiding a second
/// `encoded_len()` walk) and verify the written byte count matches `expected_len`.
fn encode_proto_into(
    proto: &impl prost::Message,
    expected_len: usize,
    dst: &mut Vec<u8>,
) -> std::io::Result<()> {
    let start_len = dst.len();
    proto.encode_raw(dst);
    if dst.len() - start_len != expected_len {
        return Err(std::io::Error::other(
            "protobuf encoder wrote unexpected payload length",
        ));
    }
    Ok(())
}

/// Encode a protobuf message directly into a wire-ready S2S regular frame.
///
/// Output bytes, below-threshold uncompressed fallback (`< 1 KiB`), and error kinds/messages match
/// [`SessionMessage::regular`] followed by [`SessionMessage::encode`].
pub fn encode_regular_frame(
    compression: CompressionAlgorithm,
    proto: &impl prost::Message,
) -> std::io::Result<Bytes> {
    let encoded_len = proto.encoded_len();
    validate_decompressed_len(encoded_len)?;

    let effective = compression.effective_for(encoded_len);
    if effective == CompressionAlgorithm::None {
        let mut buf = Vec::with_capacity(REGULAR_HEADER_SIZE + encoded_len);
        buf.extend_from_slice(&[0u8; REGULAR_HEADER_SIZE]);
        encode_proto_into(proto, encoded_len, &mut buf)?;
        write_length_prefix(&mut buf, FLAG_TOTAL_SIZE + encoded_len);
        return Ok(Bytes::from(buf));
    }

    let mut raw = Vec::with_capacity(encoded_len);
    encode_proto_into(proto, encoded_len, &mut raw)?;

    let flag = regular_flag(effective, false);
    let mut out = Vec::with_capacity(REGULAR_HEADER_SIZE + compressed_capacity_bound(raw.len()));
    out.extend_from_slice(&[0, 0, 0, flag]);
    let mut out = compress_into(effective, &raw, out)?;
    let payload_len = out.len() - REGULAR_HEADER_SIZE;
    write_length_prefix(&mut out, FLAG_TOTAL_SIZE + payload_len);
    Ok(Bytes::from(out))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u8)]
pub enum CompressionAlgorithm {
    None = 0,
    Zstd = 1,
    Gzip = 2,
}

impl CompressionAlgorithm {
    fn effective_for(self, raw_len: usize) -> Self {
        if raw_len < COMPRESSION_THRESHOLD_BYTES {
            Self::None
        } else {
            self
        }
    }

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
        let encoded_len = proto.encoded_len();
        validate_decompressed_len(encoded_len)?;
        let mut raw = Vec::with_capacity(encoded_len);
        encode_proto_into(proto, encoded_len, &mut raw)?;
        Self::compress(compression, raw)
    }

    /// Whether this frame carried the reconnect-advised flag.
    ///
    /// A server sets the flag on responses when it is about to terminate,
    /// signaling that the client should proactively reconnect.
    pub fn reconnect_advised(&self) -> bool {
        self.reconnect_advised
    }

    fn compress(compression: CompressionAlgorithm, data: Vec<u8>) -> std::io::Result<Self> {
        validate_decompressed_len(data.len())?;

        let effective = compression.effective_for(data.len());
        if effective == CompressionAlgorithm::None {
            return Ok(Self {
                compression: CompressionAlgorithm::None,
                reconnect_advised: false,
                payload: data.into(),
            });
        }
        let buf = compress_into(
            effective,
            data.as_slice(),
            Vec::with_capacity(compressed_capacity_bound(data.len())),
        )?;
        Ok(Self {
            compression: effective,
            reconnect_advised: false,
            payload: Bytes::from(buf),
        })
    }

    pub fn decompressed(self) -> std::io::Result<Bytes> {
        let initial_capacity = self
            .payload
            .len()
            .saturating_mul(2)
            .clamp(COMPRESSION_THRESHOLD_BYTES, MAX_DECOMPRESSED_PAYLOAD_BYTES);

        match self.compression {
            CompressionAlgorithm::None => {
                validate_decoded_len(self.payload.len())?;
                Ok(self.payload)
            }
            CompressionAlgorithm::Gzip => {
                let mut decoder = GzDecoder::new(&self.payload[..]);
                read_to_end_limited(&mut decoder, initial_capacity)
            }
            CompressionAlgorithm::Zstd => {
                let mut decoder = zstd::stream::Decoder::with_buffer(&self.payload[..])?;
                decoder.window_log_max(ZSTD_MAX_WINDOW_LOG)?;
                read_to_end_limited(&mut decoder, initial_capacity)
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
                buf.put_u8(regular_flag(msg.compression, msg.reconnect_advised));
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
            Poll::Ready(Some(Ok(item))) => match encode_regular_frame(self.compression, &item) {
                Ok(frame) => Poll::Ready(Some(Ok(frame))),
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

pub struct FrameDecoder;

impl tokio_util::codec::Decoder for FrameDecoder {
    type Item = SessionMessage;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < LENGTH_PREFIX_SIZE {
            return Ok(None);
        }

        let length = ((src[0] as usize) << 16) | ((src[1] as usize) << 8) | (src[2] as usize);

        if length > MAX_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "frame exceeds decode limit",
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
            prop_assert_eq!(encode_regular_frame(algo, &proto).unwrap(), encoded.clone());
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
            let encoded = encode_regular_frame(algo, &proto).unwrap();
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

    fn incompressible_bytes(len: usize) -> Vec<u8> {
        let mut payload = vec![0u8; len];
        let mut x = 0x1234_5678u32;
        for byte in &mut payload {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *byte = (x & 0xFF) as u8;
        }
        payload
    }

    #[test]
    fn compress_rejects_incompressible_payload_that_exceeds_frame_limit_after_compression() {
        let payload = incompressible_bytes(MAX_DECOMPRESSED_PAYLOAD_BYTES);

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

    #[test]
    fn encode_regular_frame_matches_legacy_and_threshold_boundary() {
        // TestProto wraps `bytes` field tag 1 (1 B tag + 2 B varint for lengths 128..=16383), so
        // payload lengths 1020 and 1021 straddle the 1024-byte compression threshold at encoded
        // lengths 1023 (uncompressed) and 1024 (compressed).
        let below = TestProto::new(vec![0x5Au8; 1020]);
        assert_eq!(below.encoded_len(), COMPRESSION_THRESHOLD_BYTES - 1);
        let at_threshold = TestProto::new(vec![0x5Au8; 1021]);
        assert_eq!(at_threshold.encoded_len(), COMPRESSION_THRESHOLD_BYTES);

        for algo in [
            CompressionAlgorithm::None,
            CompressionAlgorithm::Gzip,
            CompressionAlgorithm::Zstd,
        ] {
            for (proto, should_compress) in [
                (TestProto::new(vec![]), false),
                (TestProto::new(vec![0x5Au8; 16]), false),
                (below.clone(), false),
                (at_threshold.clone(), true),
                (TestProto::new(vec![0x5Au8; 8192]), true),
            ] {
                let fused = encode_regular_frame(algo, &proto).unwrap();
                let legacy = SessionMessage::regular(algo, &proto).unwrap().encode();
                assert_eq!(fused, legacy);

                let expected_compression = if should_compress {
                    algo
                } else {
                    CompressionAlgorithm::None
                };
                assert_eq!(
                    (fused[LENGTH_PREFIX_SIZE] & FLAG_COMPRESSION_MASK) >> FLAG_COMPRESSION_SHIFT,
                    expected_compression as u8
                );

                let SessionMessage::Regular(data) = decode_once(&fused).unwrap() else {
                    panic!("expected regular frame");
                };
                assert_eq!(data.compression, expected_compression);
                assert_eq!(data.try_into_proto::<TestProto>().unwrap(), proto);
            }
        }
    }

    #[test]
    fn encode_regular_frame_enforces_size_limits() {
        // Exact MAX_DECOMPRESSED_PAYLOAD_BYTES encoded length (1 B tag + 4 B varint = 5 B
        // overhead).
        let exact_max = TestProto::new(vec![0u8; MAX_DECOMPRESSED_PAYLOAD_BYTES - 5]);
        assert_eq!(exact_max.encoded_len(), MAX_DECOMPRESSED_PAYLOAD_BYTES);
        let frame = encode_regular_frame(CompressionAlgorithm::None, &exact_max).unwrap();
        assert_eq!(frame.len(), LENGTH_PREFIX_SIZE + MAX_FRAME_BYTES);
        let SessionMessage::Regular(data) = decode_once(&frame).unwrap() else {
            panic!("expected regular frame");
        };
        assert_eq!(data.try_into_proto::<TestProto>().unwrap(), exact_max);

        // Over decompressed limit fails before compressing for all algorithms.
        let over_max = TestProto::new(vec![0u8; MAX_DECOMPRESSED_PAYLOAD_BYTES - 4]);
        assert_eq!(over_max.encoded_len(), MAX_DECOMPRESSED_PAYLOAD_BYTES + 1);
        for algo in [
            CompressionAlgorithm::None,
            CompressionAlgorithm::Gzip,
            CompressionAlgorithm::Zstd,
        ] {
            let err = encode_regular_frame(algo, &over_max).expect_err("should fail");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(
                err.to_string()
                    .contains("payload exceeds decompressed limit")
            );
        }

        // Incompressible payload at exact decompressed limit exceeds frame limit after compression.
        let incompressible_proto =
            TestProto::new(incompressible_bytes(MAX_DECOMPRESSED_PAYLOAD_BYTES - 5));
        assert_eq!(
            incompressible_proto.encoded_len(),
            MAX_DECOMPRESSED_PAYLOAD_BYTES
        );
        for algo in [CompressionAlgorithm::Gzip, CompressionAlgorithm::Zstd] {
            let err = encode_regular_frame(algo, &incompressible_proto).expect_err("should fail");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(
                err.to_string()
                    .contains("compressed payload exceeds frame limit")
            );
        }
    }

    #[test]
    fn compressed_frames_trim_slack_for_small_and_large_compressible_payloads() {
        for size in [2_000usize, 4_000, 256 * 1024] {
            let proto = TestProto::new(vec![0u8; size]);
            for alg in [CompressionAlgorithm::Gzip, CompressionAlgorithm::Zstd] {
                let frame = encode_regular_frame(alg, &proto).unwrap();
                let frame_len = frame.len();
                let frame_cap = frame.try_into_mut().unwrap().capacity();
                assert!(
                    frame_cap <= frame_len + (frame_len / 8).max(FRAME_MIN_SLACK_BYTES) + 64,
                    "encode_regular_frame({alg:?}, {size}): len={frame_len} retained cap={frame_cap}"
                );

                let compressed = CompressedData::for_proto(alg, &proto).unwrap();
                let payload_len = compressed.payload.len();
                let payload_cap = compressed.payload.try_into_mut().unwrap().capacity();
                assert!(
                    payload_cap <= payload_len + (payload_len / 8).max(FRAME_MIN_SLACK_BYTES) + 64,
                    "CompressedData::for_proto({alg:?}, {size}): len={payload_len} retained cap={payload_cap}"
                );

                let decompressed = CompressedData::for_proto(alg, &proto)
                    .unwrap()
                    .decompressed()
                    .unwrap();
                let decomp_len = decompressed.len();
                let decomp_cap = decompressed.try_into_mut().unwrap().capacity();
                assert!(
                    decomp_cap <= decomp_len + (decomp_len / 8).max(FRAME_MIN_SLACK_BYTES) + 64,
                    "CompressedData::decompressed({alg:?}, {size}): len={decomp_len} retained cap={decomp_cap}"
                );
            }
        }
    }

    #[test]
    fn zstd_encoded_frames_record_content_size_and_bounded_window() {
        for (size, window_log_max) in [(2_048usize, 12u32), (200 * 1024, 18)] {
            let proto = TestProto::new(vec![0x5Au8; size]);
            let frame = encode_regular_frame(CompressionAlgorithm::Zstd, &proto).unwrap();
            let SessionMessage::Regular(data) = decode_once(&frame).unwrap() else {
                panic!("expected regular frame");
            };
            assert_eq!(data.compression, CompressionAlgorithm::Zstd);
            assert_eq!(
                zstd::zstd_safe::get_frame_content_size(data.payload.as_ref()).unwrap(),
                Some(proto.encoded_len() as u64),
                "expected exact pledged content size for {size}-byte payload"
            );

            // With `set_pledged_src_size`, libzstd clamps the frame window to the payload size
            // instead of advertising a 2 MiB streaming window on `>= 128 KiB` payloads.
            let mut decoder = zstd::stream::Decoder::with_buffer(data.payload.as_ref()).unwrap();
            decoder.window_log_max(window_log_max).unwrap();
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).unwrap();
            assert_eq!(TestProto::decode(out.as_slice()).unwrap(), proto);
        }
    }

    #[test]
    fn decompressed_decodes_legacy_zstd_frame_without_content_size() {
        let proto = TestProto::new(vec![0x3Cu8; 4_096]);
        let raw = proto.encode_to_vec();
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
        encoder.write_all(raw.as_slice()).unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(
            zstd::zstd_safe::get_frame_content_size(&compressed).unwrap(),
            None,
            "test fixture must omit zstd content size"
        );

        let data = CompressedData {
            compression: CompressionAlgorithm::Zstd,
            reconnect_advised: false,
            payload: Bytes::from(compressed),
        };
        assert_eq!(data.try_into_proto::<TestProto>().unwrap(), proto);
    }
}
