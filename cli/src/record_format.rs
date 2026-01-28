use std::{io, io::BufRead, path::PathBuf, pin::Pin};

use clap::ValueEnum;
use futures::Stream;
use s2_sdk::types::{AppendRecord, SequencedRecord};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncBufReadExt, AsyncWrite, BufWriter},
    sync::mpsc,
};
use tokio_stream::wrappers::{LinesStream, ReceiverStream};
use tracing::trace;

use crate::error::RecordParseError;

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum RecordFormat {
    /// Plaintext record body as UTF-8.
    /// If the body is not valid UTF-8, this will be a lossy decoding.
    /// Headers cannot be represented, so command records are sent to stderr when reading.
    #[default]
    #[clap(alias = "")]
    Text,
    /// JSON format with UTF-8 headers and body.
    /// If the data is not valid UTF-8, this will be a lossy decoding.
    #[clap(alias = "raw")]
    Json,
    /// JSON format with headers and body encoded as Base64.
    #[clap(aliases = ["base64", "json-binsafe"])]
    JsonBase64,
}

#[derive(Debug, Clone)]
pub enum RecordsIn {
    File(PathBuf),
    Stdin,
}

/// Sink for records in a read session.
#[derive(Debug, Clone)]
pub enum RecordsOut {
    File(PathBuf),
    Stdout,
}

impl RecordsIn {
    pub async fn reader(
        &self,
    ) -> io::Result<Pin<Box<dyn Stream<Item = io::Result<String>> + Send>>> {
        match self {
            RecordsIn::File(path) => {
                let file = File::open(path).await?;
                let stream: Pin<Box<dyn Stream<Item = io::Result<String>> + Send>> =
                    Box::pin(LinesStream::new(tokio::io::BufReader::new(file).lines()));
                Ok(stream)
            }
            RecordsIn::Stdin => Ok(Box::pin(stdio_lines_stream(std::io::stdin()))),
        }
    }
}

impl RecordsOut {
    pub async fn writer(&self) -> io::Result<Box<dyn AsyncWrite + Send + Unpin>> {
        match self {
            RecordsOut::File(path) => {
                trace!(?path, "opening file writer");
                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .append(true)
                    .open(path)
                    .await?;

                Ok(Box::new(BufWriter::new(file)))
            }
            RecordsOut::Stdout => {
                trace!("stdout writer");
                Ok(Box::new(BufWriter::new(tokio::io::stdout())))
            }
        }
    }
}

fn stdio_lines_stream<F>(f: F) -> ReceiverStream<io::Result<String>>
where
    F: std::io::Read + Send + 'static,
{
    let lines = std::io::BufReader::new(f).lines();
    let (tx, rx) = mpsc::channel(s2_sdk::types::RECORD_BATCH_MAX.count);
    let _handle = std::thread::spawn(move || {
        for line in lines {
            if tx.blocking_send(line).is_err() {
                return;
            }
        }
    });
    ReceiverStream::new(rx)
}

pub fn parse_records_input_source(s: &str) -> Result<RecordsIn, io::Error> {
    match s {
        "" | "-" => Ok(RecordsIn::Stdin),
        _ => Ok(RecordsIn::File(PathBuf::from(s))),
    }
}

pub fn parse_records_output_source(s: &str) -> Result<RecordsOut, io::Error> {
    match s {
        "" | "-" => Ok(RecordsOut::Stdout),
        _ => Ok(RecordsOut::File(PathBuf::from(s))),
    }
}

pub trait RecordParser<I>
where
    I: Stream<Item = io::Result<String>> + Send + Unpin,
{
    type RecordStream: Stream<Item = Result<AppendRecord, RecordParseError>> + Send + Unpin;

    fn parse_records(lines: I) -> Self::RecordStream;
}

pub trait RecordWriter {
    async fn write_record(
        record: &SequencedRecord,
        writer: &mut (impl AsyncWrite + Unpin),
    ) -> io::Result<()>;
}

pub use body::TextFormatter;
pub type JsonFormatter = json::Formatter<false>;
pub type JsonBase64Formatter = json::Formatter<true>;

mod body {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::{Stream, StreamExt};
    use s2_sdk::types::{AppendRecord, SequencedRecord};
    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use super::{RecordParseError, RecordParser, RecordWriter};

    pub struct TextFormatter;

    impl RecordWriter for TextFormatter {
        async fn write_record(
            record: &SequencedRecord,
            writer: &mut (impl AsyncWrite + Unpin),
        ) -> io::Result<()> {
            let s = String::from_utf8_lossy(&record.body);
            writer.write_all(s.as_bytes()).await
        }
    }

    impl<I> RecordParser<I> for TextFormatter
    where
        I: Stream<Item = io::Result<String>> + Send + Unpin,
    {
        type RecordStream = RecordStream<I>;

        fn parse_records(lines: I) -> Self::RecordStream {
            RecordStream(lines)
        }
    }

    pub struct RecordStream<S>(S);

    impl<S> Stream for RecordStream<S>
    where
        S: Stream<Item = io::Result<String>> + Send + Unpin,
    {
        type Item = Result<AppendRecord, RecordParseError>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.0.poll_next_unpin(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
                Poll::Ready(Some(Ok(s))) => Poll::Ready(Some(
                    AppendRecord::new(s).map_err(|e| RecordParseError::Parse(e.to_string())),
                )),
            }
        }
    }
}

mod json {
    use std::{
        borrow::Cow,
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use base64ct::{Base64, Encoding};
    use bytes::Bytes;
    use futures::{Stream, StreamExt};
    use s2_sdk::types::{AppendRecord, Header, SequencedRecord};
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use super::{RecordParseError, RecordParser, RecordWriter};

    #[derive(Debug, Clone, Default)]
    struct CowStr<'a, const BIN_SAFE: bool>(Cow<'a, str>);

    impl<const BIN_SAFE: bool> CowStr<'_, BIN_SAFE> {
        fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
    }

    type OwnedCowStr<const BIN_SAFE: bool> = CowStr<'static, BIN_SAFE>;

    impl<'a, const BIN_SAFE: bool> From<&'a [u8]> for CowStr<'a, BIN_SAFE> {
        fn from(value: &'a [u8]) -> Self {
            Self(if BIN_SAFE {
                Base64::encode_string(value).into()
            } else {
                String::from_utf8_lossy(value)
            })
        }
    }

    impl<const BIN_SAFE: bool> TryFrom<OwnedCowStr<BIN_SAFE>> for Bytes {
        type Error = String;

        fn try_from(value: OwnedCowStr<BIN_SAFE>) -> Result<Self, Self::Error> {
            let CowStr(s) = value;

            Ok(if BIN_SAFE {
                Base64::decode_vec(&s).map_err(|_| format!("invalid base64: {s}"))?
            } else {
                s.into_owned().into_bytes()
            }
            .into())
        }
    }

    impl<const BIN_SAFE: bool> Serialize for CowStr<'_, BIN_SAFE> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.0.serialize(serializer)
        }
    }

    impl<'de, const BIN_SAFE: bool> Deserialize<'de> for OwnedCowStr<BIN_SAFE> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            String::deserialize(deserializer).map(|s| CowStr(s.into()))
        }
    }

    pub struct Formatter<const BIN_SAFE: bool>;

    #[derive(Debug, Clone, Serialize)]
    struct SerializableSequencedRecord<'a, const BIN_SAFE: bool> {
        seq_num: u64,
        timestamp: u64,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        headers: Vec<(CowStr<'a, BIN_SAFE>, CowStr<'a, BIN_SAFE>)>,
        #[serde(skip_serializing_if = "CowStr::is_empty")]
        body: CowStr<'a, BIN_SAFE>,
    }

    impl<'a, const BIN_SAFE: bool> From<&'a SequencedRecord>
        for SerializableSequencedRecord<'a, BIN_SAFE>
    {
        fn from(value: &'a SequencedRecord) -> Self {
            let SequencedRecord {
                timestamp,
                seq_num,
                headers,
                body,
                ..
            } = value;

            let headers: Vec<(CowStr<BIN_SAFE>, CowStr<BIN_SAFE>)> = headers
                .iter()
                .map(|h| (h.name.as_ref().into(), h.value.as_ref().into()))
                .collect();

            let body: CowStr<BIN_SAFE> = body.as_ref().into();

            SerializableSequencedRecord {
                timestamp: *timestamp,
                seq_num: *seq_num,
                headers,
                body,
            }
        }
    }

    impl<const BIN_SAFE: bool> RecordWriter for Formatter<BIN_SAFE> {
        async fn write_record(
            record: &SequencedRecord,
            writer: &mut (impl AsyncWrite + Unpin),
        ) -> io::Result<()> {
            let record: SerializableSequencedRecord<BIN_SAFE> = record.into();
            let s = serde_json::to_string(&record).map_err(io::Error::other)?;
            writer.write_all(s.as_bytes()).await
        }
    }

    impl<const BIN_SAFE: bool, I> RecordParser<I> for Formatter<BIN_SAFE>
    where
        I: Stream<Item = io::Result<String>> + Send + Unpin,
    {
        type RecordStream = RecordStream<BIN_SAFE, I>;

        fn parse_records(lines: I) -> Self::RecordStream {
            RecordStream(lines)
        }
    }

    #[derive(Debug, Clone, Deserialize)]
    struct DeserializableAppendRecord<const BIN_SAFE: bool> {
        timestamp: Option<u64>,
        #[serde(default)]
        headers: Vec<(OwnedCowStr<BIN_SAFE>, OwnedCowStr<BIN_SAFE>)>,
        #[serde(default)]
        body: OwnedCowStr<BIN_SAFE>,
    }

    impl<const BIN_SAFE: bool> TryFrom<DeserializableAppendRecord<BIN_SAFE>> for AppendRecord {
        type Error = String;

        fn try_from(value: DeserializableAppendRecord<BIN_SAFE>) -> Result<Self, Self::Error> {
            let DeserializableAppendRecord {
                timestamp,
                headers,
                body,
            } = value;

            let body_bytes: Bytes = body.try_into()?;
            let mut record = AppendRecord::new(body_bytes).map_err(|e| e.to_string())?;

            if !headers.is_empty() {
                let parsed_headers: Vec<Header> = headers
                    .into_iter()
                    .map(|(name, value)| {
                        let name_bytes: Bytes = name.try_into()?;
                        let value_bytes: Bytes = value.try_into()?;
                        Ok(Header::new(name_bytes, value_bytes))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                record = record
                    .with_headers(parsed_headers)
                    .map_err(|e| e.to_string())?;
            }

            if let Some(ts) = timestamp {
                record = record.with_timestamp(ts);
            }

            Ok(record)
        }
    }

    pub struct RecordStream<const BIN_SAFE: bool, S>(S);

    impl<const BIN_SAFE: bool, S> Stream for RecordStream<BIN_SAFE, S>
    where
        S: Stream<Item = io::Result<String>> + Send + Unpin,
    {
        type Item = Result<AppendRecord, RecordParseError>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            fn parse_record<const BIN_SAFE: bool>(
                s: String,
            ) -> Result<AppendRecord, RecordParseError> {
                let append_record: DeserializableAppendRecord<BIN_SAFE> =
                    serde_json::from_str(&s).map_err(|e| RecordParseError::Parse(e.to_string()))?;

                Ok(append_record.try_into()?)
            }

            match self.0.poll_next_unpin(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
                Poll::Ready(Some(Ok(s))) => Poll::Ready(Some(parse_record::<BIN_SAFE>(s))),
            }
        }
    }
}
