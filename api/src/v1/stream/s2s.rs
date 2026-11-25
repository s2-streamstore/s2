use std::{
    cell::RefCell,
    io::{Cursor, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::{Compression, bufread::MultiGzDecoder, write::GzEncoder};
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
// 16 MiB max window covers standard streaming zstd encoders (e.g. 8 MiB default windowLog=23)
// while bounding decoder memory well below libzstd's 128 MiB default.
const ZSTD_WINDOW_LOG_MAX: u32 = 24;
const MAX_ENCODE_SCRATCH_CAPACITY: usize = 1024 * 1024 + 64 * 1024;

thread_local! {
    static ZSTD_COMPRESSOR: RefCell<Option<zstd::bulk::Compressor<'static>>> =
        const { RefCell::new(None) };
    static ZSTD_DCTX: RefCell<Option<zstd::zstd_safe::DCtx<'static>>> =
        const { RefCell::new(None) };
    static ENCODE_SCRATCH: RefCell<Option<BytesMut>> = const { RefCell::new(None) };
}

fn compress_zstd_into<C: zstd::zstd_safe::WriteBuf + ?Sized>(
    src: &[u8],
    dst: &mut C,
) -> std::io::Result<usize> {
    let result = ZSTD_COMPRESSOR.try_with(|cell| {
        let Ok(mut slot) = cell.try_borrow_mut() else {
            return None;
        };
        let compressor = match slot.as_mut() {
            Some(c) => c,
            None => match zstd::bulk::Compressor::new(0) {
                Ok(c) => slot.insert(c),
                Err(err) => return Some(Err(err)),
            },
        };
        Some(compressor.compress_to_buffer(src, dst))
    });
    if let Ok(Some(res)) = result {
        return res;
    }
    let mut compressor = zstd::bulk::Compressor::new(0)?;
    compressor.compress_to_buffer(src, dst)
}

fn maybe_shrink_vec(buf: &mut Vec<u8>, min_slack: usize) {
    if buf.capacity() > buf.len().saturating_mul(2) && buf.capacity() - buf.len() > min_slack {
        buf.shrink_to_fit();
    }
}

fn read_to_end_limited(mut reader: impl Read, initial_capacity: usize) -> std::io::Result<Bytes> {
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
    maybe_shrink_vec(&mut buf, 16 * 1024);
    Ok(Bytes::from(buf))
}

fn create_bounded_dctx() -> std::io::Result<zstd::zstd_safe::DCtx<'static>> {
    let mut dctx = zstd::zstd_safe::DCtx::try_create()
        .ok_or_else(|| std::io::Error::other("zstd could not allocate a decompression context"))?;
    dctx.set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(
        ZSTD_WINDOW_LOG_MAX,
    ))
    .map_err(|code| std::io::Error::other(zstd::zstd_safe::get_error_name(code)))?;
    Ok(dctx)
}

fn decompress_zstd_with_dctx(
    dctx: &mut zstd::zstd_safe::DCtx<'static>,
    src: &[u8],
    exact_size: Option<usize>,
    fallback_capacity: usize,
) -> std::io::Result<Bytes> {
    // Explicit session reset keeps DCtx reuse safe across all zstd 0.14.x patch versions
    // (0.14.0-0.14.2 did not reset inside `Decoder::with_context`).
    dctx.reset(zstd::zstd_safe::ResetDirective::SessionOnly)
        .map_err(|code| std::io::Error::other(zstd::zstd_safe::get_error_name(code)))?;

    if let Some(exact) = exact_size
        && !src.is_empty()
    {
        let mut buf = Vec::with_capacity(exact);
        dctx.decompress(&mut buf, src).map_err(|code| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                zstd::zstd_safe::get_error_name(code),
            )
        })?;
        debug_assert!(buf.len() <= MAX_DECOMPRESSED_PAYLOAD_BYTES);
        maybe_shrink_vec(&mut buf, 16 * 1024);
        return Ok(Bytes::from(buf));
    }

    let mut decoder = zstd::stream::read::Decoder::with_context(src, dctx);
    read_to_end_limited(&mut decoder, fallback_capacity)
}

/// Returns the exact total decompressed size when every frame in `data` declares its
/// `Frame_Content_Size` (stepping over skippable frames). Returns `None` if any frame omits its
/// content size, if `data` is malformed, or if the total overflows `usize`.
///
/// Unlike `zstd::bulk::Decompressor::upper_bound`, this never falls back to `ZSTD_decompressBound`
/// when a downstream crate enables `zstd/experimental`, so conservative block-size bounds can never
/// falsely reject valid below-limit streaming frames.
fn exact_zstd_decompressed_size(mut data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    let mut total = 0u64;
    while !data.is_empty() {
        let frame_len = zstd::zstd_safe::find_frame_compressed_size(data).ok()?;
        let content = zstd::zstd_safe::get_frame_content_size(data).ok()??;
        total = total.checked_add(content)?;
        data = data.get(frame_len..)?;
    }
    usize::try_from(total).ok()
}

fn decompress_zstd_limited(src: &[u8], fallback_capacity: usize) -> std::io::Result<Bytes> {
    let exact_size = match exact_zstd_decompressed_size(src) {
        Some(exact) if exact > MAX_DECOMPRESSED_PAYLOAD_BYTES => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed payload exceeds limit",
            ));
        }
        other => other,
    };

    let result = ZSTD_DCTX.try_with(|cell| {
        let Ok(mut slot) = cell.try_borrow_mut() else {
            return None;
        };
        let dctx = match slot.as_mut() {
            Some(d) => d,
            None => match create_bounded_dctx() {
                Ok(d) => slot.insert(d),
                Err(err) => return Some(Err(err)),
            },
        };
        Some(decompress_zstd_with_dctx(
            dctx,
            src,
            exact_size,
            fallback_capacity,
        ))
    });
    if let Ok(Some(res)) = result {
        return res;
    }

    let mut dctx = create_bounded_dctx()?;
    decompress_zstd_with_dctx(&mut dctx, src, exact_size, fallback_capacity)
}

fn with_encode_scratch<R>(capacity: usize, f: impl FnOnce(&mut BytesMut) -> R) -> R {
    let mut f = Some(f);
    let result = ENCODE_SCRATCH.try_with(|cell| {
        let Ok(mut slot) = cell.try_borrow_mut() else {
            return None;
        };
        let scratch = slot.get_or_insert_with(BytesMut::new);
        scratch.clear();
        scratch.reserve(capacity);
        let out = f.take().expect("closure invoked once")(scratch);
        scratch.clear();
        if scratch.capacity() > MAX_ENCODE_SCRATCH_CAPACITY {
            *slot = None;
        }
        Some(out)
    });
    if let Ok(Some(out)) = result {
        return out;
    }
    let mut scratch = BytesMut::with_capacity(capacity);
    f.take().expect("closure invoked once")(&mut scratch)
}

fn regular_flag(compression: CompressionAlgorithm, reconnect_advised: bool) -> u8 {
    let mut flag = ((compression as u8) << FLAG_COMPRESSION_SHIFT) & FLAG_COMPRESSION_MASK;
    if reconnect_advised {
        flag |= FLAG_RECONNECT_ADVISED;
    }
    flag
}

fn write_length_prefix(dst: &mut [u8], frame_len: usize) {
    dst[0] = ((frame_len >> 16) & 0xFF) as u8;
    dst[1] = ((frame_len >> 8) & 0xFF) as u8;
    dst[2] = (frame_len & 0xFF) as u8;
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

/// Encode a protobuf message directly into a wire-ready S2S regular frame.
pub fn encode_regular_frame(
    compression: CompressionAlgorithm,
    proto: &impl prost::Message,
) -> std::io::Result<Bytes> {
    let encoded_len = proto.encoded_len();
    encode_regular_frame_with(compression, encoded_len, |buf| {
        proto
            .encode(buf)
            .expect("buffer has exact capacity for proto");
    })
}

/// Encode a protobuf payload directly into a wire-ready S2S regular frame using a caller-supplied
/// encoder closure.
///
/// `encoded_len` must equal the exact number of bytes written by `encode_payload`.
pub fn encode_regular_frame_with(
    compression: CompressionAlgorithm,
    encoded_len: usize,
    encode_payload: impl FnOnce(&mut BytesMut),
) -> std::io::Result<Bytes> {
    if encoded_len > MAX_DECOMPRESSED_PAYLOAD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload exceeds decompressed limit",
        ));
    }

    if compression == CompressionAlgorithm::None || encoded_len < COMPRESSION_THRESHOLD_BYTES {
        let header_size = LENGTH_PREFIX_SIZE + FLAG_TOTAL_SIZE;
        let mut buf = BytesMut::with_capacity(header_size + encoded_len);
        buf.put_slice(&[0, 0, 0, regular_flag(CompressionAlgorithm::None, false)]);
        encode_payload(&mut buf);
        let payload_len = buf.len() - header_size;
        debug_assert_eq!(payload_len, encoded_len);
        if payload_len > MAX_DECOMPRESSED_PAYLOAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "payload exceeds decompressed limit",
            ));
        }
        write_length_prefix(&mut buf, FLAG_TOTAL_SIZE + payload_len);
        return Ok(buf.freeze());
    }

    with_encode_scratch(encoded_len, |raw| {
        encode_payload(raw);
        debug_assert_eq!(raw.len(), encoded_len);
        if raw.len() > MAX_DECOMPRESSED_PAYLOAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "payload exceeds decompressed limit",
            ));
        }

        let header_size = LENGTH_PREFIX_SIZE + FLAG_TOTAL_SIZE;
        let flag = regular_flag(compression, false);
        let mut out = match compression {
            CompressionAlgorithm::Gzip => {
                let mut buf = Vec::with_capacity(header_size + raw.len());
                buf.extend_from_slice(&[0, 0, 0, flag]);
                let mut encoder = GzEncoder::new(buf, Compression::default());
                encoder.write_all(raw)?;
                encoder.finish()?
            }
            CompressionAlgorithm::Zstd => {
                let bound = zstd::compress_bound(raw.len());
                let mut buf = Vec::with_capacity(header_size + bound);
                buf.extend_from_slice(&[0, 0, 0, flag]);
                let mut cursor = Cursor::new(buf);
                cursor.set_position(header_size as u64);
                compress_zstd_into(raw, &mut cursor)?;
                cursor.into_inner()
            }
            CompressionAlgorithm::None => unreachable!("handled above"),
        };

        let payload_len = out.len() - header_size;
        if payload_len > MAX_FRAME_PAYLOAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "compressed payload exceeds frame limit",
            ));
        }
        write_length_prefix(&mut out, FLAG_TOTAL_SIZE + payload_len);
        // Trim excess pre-allocated slack when compression ratio is high so inflight frames
        // don't pin an uncompressed-sized allocation while awaiting acknowledgement.
        maybe_shrink_vec(&mut out, 4096);
        Ok(Bytes::from(out))
    })
}

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
        let payload = match compression {
            CompressionAlgorithm::Gzip => {
                let mut encoder =
                    GzEncoder::new(Vec::with_capacity(data.len()), Compression::default());
                encoder.write_all(data.as_slice())?;
                let mut buf = encoder.finish()?;
                maybe_shrink_vec(&mut buf, 4096);
                Bytes::from(buf)
            }
            CompressionAlgorithm::Zstd => {
                let mut buf = Vec::with_capacity(zstd::compress_bound(data.len()));
                compress_zstd_into(data.as_slice(), &mut buf)?;
                maybe_shrink_vec(&mut buf, 4096);
                Bytes::from(buf)
            }
            CompressionAlgorithm::None => unreachable!("handled above"),
        };
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
                let mut decoder = MultiGzDecoder::new(&self.payload[..]);
                read_to_end_limited(&mut decoder, initial_capacity)
            }
            CompressionAlgorithm::Zstd => {
                decompress_zstd_limited(&self.payload[..], initial_capacity)
            }
        }
    }

    pub fn try_into_proto<P: prost::Message + Default>(self) -> std::io::Result<P> {
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

impl FrameDecoder {
    /// Decode one complete S2S frame directly from a [`Bytes`] buffer without copying.
    ///
    /// Returns `Ok(None)` without modifying `src` if fewer bytes than a complete frame are
    /// present.
    pub fn decode_bytes(src: &mut Bytes) -> std::io::Result<Option<SessionMessage>> {
        if src.len() < LENGTH_PREFIX_SIZE {
            return Ok(None);
        }

        let length = parse_frame_length(src)?;
        let total_size = LENGTH_PREFIX_SIZE + length;
        if src.len() < total_size {
            return Ok(None);
        }

        src.advance(LENGTH_PREFIX_SIZE);
        let frame_bytes = src.split_to(length);
        Ok(Some(SessionMessage::decode_message(frame_bytes)?))
    }

    /// Peek the total wire size (`3 + length`) of the next S2S frame if at least 3 bytes are
    /// available, validating against the maximum frame size limit.
    pub fn peek_total_frame_len(src: &[u8]) -> std::io::Result<Option<usize>> {
        if src.len() < LENGTH_PREFIX_SIZE {
            return Ok(None);
        }
        Ok(Some(LENGTH_PREFIX_SIZE + parse_frame_length(src)?))
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

    #[test]
    fn encode_regular_frame_and_decode_bytes_round_trip_all_algorithms() {
        for algo in [
            CompressionAlgorithm::None,
            CompressionAlgorithm::Gzip,
            CompressionAlgorithm::Zstd,
        ] {
            for size in [0usize, 16, COMPRESSION_THRESHOLD_BYTES - 1, 8192] {
                let proto = TestProto::new(vec![0x5Au8; size]);
                let fused = encode_regular_frame(algo, &proto).unwrap();
                let legacy = SessionMessage::regular(algo, &proto).unwrap().encode();
                if algo == CompressionAlgorithm::None
                    || proto.encoded_len() < COMPRESSION_THRESHOLD_BYTES
                {
                    assert_eq!(fused, legacy);
                }

                assert_eq!(
                    FrameDecoder::peek_total_frame_len(&fused).unwrap(),
                    Some(fused.len())
                );
                let mut bytes = fused.clone();
                let decoded = FrameDecoder::decode_bytes(&mut bytes)
                    .unwrap()
                    .expect("complete frame");
                assert!(bytes.is_empty());
                let SessionMessage::Regular(data) = decoded else {
                    panic!("expected regular frame");
                };
                assert_eq!(data.try_into_proto::<TestProto>().unwrap(), proto);
            }
        }
    }

    fn zstd_s2s_frame(compressed: &[u8]) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_uint((FLAG_TOTAL_SIZE + compressed.len()) as u64, 3);
        buf.put_u8(regular_flag(CompressionAlgorithm::Zstd, false));
        buf.extend_from_slice(compressed);
        buf.freeze()
    }

    fn decode_regular_bytes(mut frame: Bytes) -> CompressedData {
        match FrameDecoder::decode_bytes(&mut frame).unwrap().unwrap() {
            SessionMessage::Regular(data) => data,
            SessionMessage::Terminal(_) => panic!("expected regular frame"),
        }
    }

    #[test]
    fn zstd_dctx_recovers_after_truncated_and_oversized_frames_and_handles_multiframe() {
        // Pseudo-random data that does not trivially compress to a single tiny block.
        let mut state: u32 = 0x1234_5678;
        let data: Vec<u8> = (0..300_000)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect();
        let proto = TestProto::new(data);
        let good = encode_regular_frame(CompressionAlgorithm::Zstd, &proto).unwrap();
        let payload = &good[LENGTH_PREFIX_SIZE + FLAG_TOTAL_SIZE..];

        // 1. Truncated frame must fail without poisoning thread-local DCtx.
        let truncated = zstd_s2s_frame(&payload[..payload.len() / 2]);
        assert!(decode_regular_bytes(truncated).decompressed().is_err());
        assert_eq!(
            decode_regular_bytes(good.clone())
                .try_into_proto::<TestProto>()
                .unwrap(),
            proto
        );

        // 2. Oversized streaming zstd frame (no content size in header) must fail cleanly.
        let oversized = vec![0xEEu8; MAX_DECOMPRESSED_PAYLOAD_BYTES + 64 * 1024];
        let oversized_compressed = zstd::stream::encode_all(&oversized[..], 0).unwrap();
        assert!(
            decode_regular_bytes(zstd_s2s_frame(&oversized_compressed))
                .decompressed()
                .is_err()
        );
        assert_eq!(
            decode_regular_bytes(good)
                .try_into_proto::<TestProto>()
                .unwrap(),
            proto
        );

        // 3. Concatenated multi-frame zstd payload and 0-byte zstd frame both round-trip.
        let p1 = TestProto::new(vec![0x41u8; 4096]);
        let raw = p1.encode_to_vec();
        let half = raw.len() / 2;
        let mut multi = zstd::bulk::compress(&raw[..half], 0).unwrap();
        multi.extend_from_slice(&zstd::bulk::compress(&raw[half..], 0).unwrap());
        assert_eq!(
            decode_regular_bytes(zstd_s2s_frame(&multi))
                .try_into_proto::<TestProto>()
                .unwrap(),
            p1
        );

        let empty_compressed = zstd::bulk::compress(&[], 0).unwrap();
        assert_eq!(
            decode_regular_bytes(zstd_s2s_frame(&empty_compressed))
                .decompressed()
                .unwrap(),
            Bytes::new()
        );

        // 4. Streaming zstd frame with many flushed tiny chunks (no declared content size) must
        //    still decode cleanly even if a downstream crate enables `zstd/experimental`.
        let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        for b in 0u8..24 {
            enc.write_all(&[b]).unwrap();
            enc.flush().unwrap();
        }
        let flushed = enc.finish().unwrap();
        assert_eq!(exact_zstd_decompressed_size(&flushed), None);
        assert_eq!(
            decode_regular_bytes(zstd_s2s_frame(&flushed))
                .decompressed()
                .unwrap()
                .as_ref(),
            &(0u8..24).collect::<Vec<_>>()[..]
        );
    }

    #[test]
    fn compressed_data_for_proto_trims_slack_on_highly_compressible_payload() {
        let proto = TestProto::new(vec![0u8; 256 * 1024]);
        for alg in [CompressionAlgorithm::Gzip, CompressionAlgorithm::Zstd] {
            let compressed = CompressedData::for_proto(alg, &proto).unwrap();
            assert!(compressed.payload.len() < 4096);
            assert_eq!(compressed.try_into_proto::<TestProto>().unwrap(), proto);
        }
    }

    #[test]
    fn gzip_s2s_decodes_multi_member_payload_and_enforces_total_limit() {
        let gzip_chunk = |data: &[u8]| {
            let mut enc = GzEncoder::new(Vec::new(), Compression::default());
            enc.write_all(data).unwrap();
            enc.finish().unwrap()
        };
        let gzip_frame = |payload: &[u8]| {
            let mut raw = Vec::with_capacity(4 + payload.len());
            let body_len = 1 + payload.len();
            raw.extend_from_slice(&(body_len as u32).to_be_bytes()[1..]);
            raw.push((CompressionAlgorithm::Gzip as u8) << 5);
            raw.extend_from_slice(payload);
            Bytes::from(raw)
        };
        let decode_regular = |raw: Bytes| -> CompressedData {
            let mut buf = BytesMut::from(raw.as_ref());
            match FrameDecoder.decode(&mut buf).unwrap().unwrap() {
                SessionMessage::Regular(data) => data,
                SessionMessage::Terminal(_) => panic!("expected regular frame"),
            }
        };

        let mut multi = gzip_chunk(b"first-");
        multi.extend_from_slice(&gzip_chunk(b"second"));
        assert_eq!(
            decode_regular(gzip_frame(&multi))
                .decompressed()
                .unwrap()
                .as_ref(),
            b"first-second"
        );

        // Total output across all gzip members must still enforce MAX_DECOMPRESSED_PAYLOAD_BYTES.
        let half_over = vec![0x55u8; MAX_DECOMPRESSED_PAYLOAD_BYTES / 2 + 1024];
        let mut oversized_multi = gzip_chunk(&half_over);
        oversized_multi.extend_from_slice(&gzip_chunk(&half_over));
        assert!(
            decode_regular(gzip_frame(&oversized_multi))
                .decompressed()
                .is_err()
        );
    }
}
