mod command;
mod envelope;
mod fencing;
mod metering;

use bytes::Bytes;
pub use command::{CommandOp, CommandPayloadError, CommandRecord};
pub use envelope::{EnvelopeRecord, HeaderValidationError};
pub use fencing::{FencingToken, FencingTokenTooLongError, MAX_FENCING_TOKEN_LENGTH};
pub use metering::{Metered, MeteredExt, MeteredSize};

use crate::deep_size::DeepSize;

pub type SeqNum = u64;
pub type NonZeroSeqNum = std::num::NonZeroU64;
pub type Timestamp = u64;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct StreamPosition {
    pub seq_num: SeqNum,
    pub timestamp: Timestamp,
}

impl StreamPosition {
    pub const MIN: StreamPosition = StreamPosition {
        seq_num: SeqNum::MIN,
        timestamp: Timestamp::MIN,
    };
}

impl std::fmt::Display for StreamPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} @ {}", self.seq_num, self.timestamp)
    }
}

impl DeepSize for StreamPosition {
    fn deep_size(&self) -> usize {
        self.seq_num.deep_size() + self.timestamp.deep_size()
    }
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum RecordPartsError {
    #[error("unknown command")]
    UnknownCommand,
    #[error("invalid `{0}` command: {1}")]
    CommandPayload(CommandOp, CommandPayloadError),
    #[error("invalid header: {0}")]
    Header(#[from] HeaderValidationError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: Bytes,
    pub value: Bytes,
}

impl DeepSize for Header {
    fn deep_size(&self) -> usize {
        self.name.len() + self.value.len()
    }
}

impl MeteredSize for Record {
    fn metered_size(&self) -> usize {
        match self {
            Self::Command(command) => command.metered_size(),
            Self::Envelope(envelope) => envelope.metered_size(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Record {
    Command(CommandRecord),
    Envelope(EnvelopeRecord),
}

impl DeepSize for Record {
    fn deep_size(&self) -> usize {
        match self {
            Self::Command(c) => c.deep_size(),
            Self::Envelope(e) => e.deep_size(),
        }
    }
}

impl Record {
    pub fn try_from_parts(headers: Vec<Header>, body: Bytes) -> Result<Self, RecordPartsError> {
        if headers.len() == 1 {
            let header = &headers[0];
            if header.name.is_empty() {
                let op = CommandOp::from_id(header.value.as_ref())
                    .ok_or(RecordPartsError::UnknownCommand)?;
                let command_record = CommandRecord::try_from_parts(op, body.as_ref())
                    .map_err(|e| RecordPartsError::CommandPayload(op, e))?;
                return Ok(Self::Command(command_record));
            }
        }
        let envelope = EnvelopeRecord::try_from_parts(headers, body)?;
        Ok(Self::Envelope(envelope))
    }

    pub fn sequenced(self, position: StreamPosition) -> SequencedRecord {
        Sequenced::new(position, self)
    }

    pub fn into_parts(self) -> (Vec<Header>, Bytes) {
        match self {
            Record::Envelope(e) => e.into_parts(),
            Record::Command(c) => {
                let op = c.op();
                let header = Header {
                    name: Bytes::new(),
                    value: Bytes::from_static(op.to_id()),
                };
                (vec![header], c.payload())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sequenced<T> {
    position: StreamPosition,
    inner: T,
}

impl<T> Sequenced<T> {
    pub const fn new(position: StreamPosition, inner: T) -> Self {
        Self { position, inner }
    }

    pub const fn position(&self) -> &StreamPosition {
        &self.position
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn as_ref(&self) -> Sequenced<&T> {
        Sequenced::new(self.position, &self.inner)
    }

    pub fn parts(&self) -> (StreamPosition, &T) {
        (self.position, &self.inner)
    }

    pub fn into_parts(self) -> (StreamPosition, T) {
        (self.position, self.inner)
    }
}

pub type SequencedRecord = Sequenced<Record>;

impl<T> MeteredSize for Sequenced<T>
where
    T: MeteredSize,
{
    fn metered_size(&self) -> usize {
        self.inner.metered_size()
    }
}

impl<T> DeepSize for Sequenced<T>
where
    T: DeepSize,
{
    fn deep_size(&self) -> usize {
        self.position.deep_size() + self.inner.deep_size()
    }
}

impl<T> Metered<T>
where
    T: MeteredSize,
{
    pub fn sequenced(self, position: StreamPosition) -> Metered<Sequenced<T>> {
        Metered::with_size(
            self.metered_size(),
            Sequenced::new(position, self.into_inner()),
        )
    }
}

impl<T> Metered<Sequenced<T>> {
    pub fn parts(&self) -> (StreamPosition, Metered<&T>) {
        let size = self.metered_size();
        let (position, inner) = self.as_ref().into_inner().parts();
        (position, Metered::with_size(size, inner))
    }

    pub fn into_parts(self) -> (StreamPosition, Metered<T>) {
        let size = self.metered_size();
        let (position, inner) = self.into_inner().into_parts();
        (position, Metered::with_size(size, inner))
    }
}

#[cfg(test)]
mod test {
    use rstest::rstest;

    use super::*;

    fn semantic_metered_size(record: &Record) -> usize {
        let (headers, body) = record.clone().into_parts();
        8 + (2 * headers.len())
            + headers
                .iter()
                .map(|header| header.name.len() + header.value.len())
                .sum::<usize>()
            + body.len()
    }

    #[test]
    fn empty_header_name_solo() {
        let headers = vec![Header {
            name: Bytes::new(),
            value: Bytes::from("hi"),
        }];
        let body = Bytes::from("hello");
        assert_eq!(
            Record::try_from_parts(headers, body),
            Err(RecordPartsError::UnknownCommand)
        );
    }

    #[test]
    fn empty_header_name_among_others() {
        let headers = vec![
            Header {
                name: Bytes::from("boku"),
                value: Bytes::from("hi"),
            },
            Header {
                name: Bytes::new(),
                value: Bytes::from("hi"),
            },
        ];
        let body = Bytes::from("hello");
        assert_eq!(
            Record::try_from_parts(headers, body),
            Err(RecordPartsError::Header(HeaderValidationError::NameEmpty))
        );
    }

    fn command_parts(op: &'static [u8], payload: &'static [u8]) -> (Vec<Header>, Bytes) {
        let headers = vec![Header {
            name: Bytes::new(),
            value: Bytes::from_static(op),
        }];
        let body = Bytes::from_static(payload);
        (headers, body)
    }

    fn assert_valid_command_record(op: &'static [u8], payload: &'static [u8]) {
        let (headers, body) = command_parts(op, payload);
        let record = Record::try_from_parts(headers.clone(), body.clone()).unwrap();
        let record_metered = record.metered_size();
        match &record {
            Record::Command(cmd) => {
                assert_eq!(cmd.op().to_id(), op);
                assert_eq!(cmd.payload().as_ref(), payload);
            }
            other => panic!("Command expected, got {other:?}"),
        }
        assert_eq!(record_metered, semantic_metered_size(&record));
        let sequenced_record = record.clone().sequenced(StreamPosition {
            seq_num: 42,
            timestamp: 100_000,
        });
        let sequenced_metered = sequenced_record.metered_size();
        assert_eq!(record_metered, sequenced_metered);
        assert_eq!(
            sequenced_record.position,
            StreamPosition {
                seq_num: 42,
                timestamp: 100_000,
            }
        );
        assert_eq!(
            sequenced_record.inner,
            Record::try_from_parts(headers, body).unwrap()
        );
    }

    #[rstest]
    #[case::fence_empty(b"fence", b"")]
    #[case::fence_uuid(b"fence", b"my-special-uuid")]
    #[case::trim_0(b"trim", b"\x00\x00\x00\x00\x00\x00\x00\x00")]
    fn valid_command_records(#[case] op: &'static [u8], #[case] payload: &'static [u8]) {
        assert_valid_command_record(op, payload);
    }

    #[rstest]
    #[case::fence_too_long(
        b"fence",
        b"toolongtoolongtoolongtoolongtoolongtoolongtoolong",
        RecordPartsError::CommandPayload(
            CommandOp::Fence,
            CommandPayloadError::FencingTokenTooLong(FencingTokenTooLongError(49)),
        )
    )]
    #[case::trim_empty(
        b"trim",
        b"",
        RecordPartsError::CommandPayload(CommandOp::Trim, CommandPayloadError::TrimPointSize(0),)
    )]
    #[case::trim_overflow(
        b"trim",
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        RecordPartsError::CommandPayload(CommandOp::Trim, CommandPayloadError::TrimPointSize(9),)
    )]
    fn invalid_command_records(
        #[case] op: &'static [u8],
        #[case] payload: &'static [u8],
        #[case] expected: RecordPartsError,
    ) {
        let (headers, body) = command_parts(op, payload);
        assert_eq!(Record::try_from_parts(headers, body), Err(expected));
    }
}
