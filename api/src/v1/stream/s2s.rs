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
  Implemented limit: 2 MiB (smaller than 24-bit protocol maximum)
*/

const LENGTH_PREFIX_SIZE: usize = 3;
const STATUS_CODE_SIZE: usize = 2;
const COMPRESSION_THRESHOLD_BYTES: usize = 1024; // 1 KiB
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

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

    fn compress(compression: CompressionAlgorithm, data: Vec<u8>) -> std::io::Result<Self> {
        if compression == CompressionAlgorithm::None || data.len() < COMPRESSION_THRESHOLD_BYTES {
            return Ok(Self {
                compression: CompressionAlgorithm::None,
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
            encoded_size <= MAX_FRAME_BYTES,
            "payload exceeds encoder limit"
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
        if buf.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
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
    use futures::{StreamExt, stream};
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

    impl Into<TerminalMessage> for TestError {
        fn into(self) -> TerminalMessage {
            TerminalMessage {
                status: self.status,
                body: self.body.to_string(),
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

            let expected_compression = if algo == CompressionAlgorithm::None || payload.len() < COMPRESSION_THRESHOLD_BYTES {
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
            body: "short-circuit".to_string(),
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
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
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

        let stream = stream::iter(items.into_iter());
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
            stream::iter(vec![
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
}
