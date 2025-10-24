use std::{fmt, str::Utf8Error};

use bytes::{BufMut, Bytes};
use compact_str::CompactString;
use enum_ordinalize::Ordinalize;

use super::{Encodable, FencingTokenTooLongError, InternalRecordError, fencing::FencingToken};
use crate::{deep_size::DeepSize, record::SeqNum};

pub const COMMAND_ID_FENCE: &[u8] = b"fence";
pub const COMMAND_ID_TRIM: &[u8] = b"trim";

#[derive(Debug, PartialEq, Eq, Clone, Copy, Ordinalize)]
#[repr(u8)]
pub enum CommandOp {
    Fence,
    Trim,
}

impl CommandOp {
    pub fn to_id(self) -> &'static [u8] {
        match self {
            Self::Fence => COMMAND_ID_FENCE,
            Self::Trim => COMMAND_ID_TRIM,
        }
    }

    pub fn from_id(name: &[u8]) -> Option<Self> {
        match name {
            COMMAND_ID_FENCE => Some(Self::Fence),
            COMMAND_ID_TRIM => Some(Self::Trim),
            _ => None,
        }
    }
}

impl fmt::Display for CommandOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = std::str::from_utf8(self.to_id()).map_err(|_| fmt::Error)?;
        f.write_str(name)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CommandRecord {
    Fence(FencingToken),
    Trim(SeqNum),
}

impl DeepSize for CommandRecord {
    fn deep_size(&self) -> usize {
        match self {
            Self::Fence(token) => token.deep_size(),
            Self::Trim(seq_num) => seq_num.deep_size(),
        }
    }
}

impl CommandRecord {
    pub fn op(&self) -> CommandOp {
        match self {
            CommandRecord::Fence(_) => CommandOp::Fence,
            CommandRecord::Trim(_) => CommandOp::Trim,
        }
    }

    pub fn payload(&self) -> Bytes {
        match self {
            Self::Fence(token) => Bytes::copy_from_slice(token.as_bytes()),
            Self::Trim(trim_point) => Bytes::copy_from_slice(&trim_point.to_be_bytes()),
        }
    }

    pub fn try_from_parts(op: CommandOp, payload: &[u8]) -> Result<Self, CommandPayloadError> {
        match op {
            CommandOp::Fence => {
                let token = CompactString::from_utf8(payload)
                    .map_err(CommandPayloadError::InvalidUtf8)?
                    .try_into()?;
                Ok(Self::Fence(token))
            }
            CommandOp::Trim => {
                let trim_point = SeqNum::from_be_bytes(
                    payload
                        .try_into()
                        .map_err(|_| CommandPayloadError::TrimPointSize(payload.len()))?,
                );
                Ok(Self::Trim(trim_point))
            }
        }
    }
}

impl TryFrom<&[u8]> for CommandRecord {
    type Error = InternalRecordError;

    fn try_from(record: &[u8]) -> Result<Self, Self::Error> {
        if record.is_empty() {
            return Err(InternalRecordError::Truncated("CommandOrdinal"));
        }
        let op = CommandOp::from_ordinal(record[0]).ok_or(InternalRecordError::InvalidValue(
            "CommandOrdinal",
            "unknown",
        ))?;
        Self::try_from_parts(op, &record[1..]).map_err(Into::into)
    }
}

impl Encodable for CommandRecord {
    fn encoded_size(&self) -> usize {
        1 + match self {
            CommandRecord::Fence(token) => token.len(),
            CommandRecord::Trim(trim_point) => size_of_val(trim_point),
        }
    }

    fn encode_into(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.op().ordinal());
        match self {
            CommandRecord::Fence(token) => {
                buf.put_slice(token.as_bytes());
            }
            CommandRecord::Trim(trim_point) => {
                buf.put_u64(*trim_point);
            }
        }
    }
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum CommandPayloadError {
    #[error("Invalid UTF-8")]
    InvalidUtf8(Utf8Error),
    #[error(transparent)]
    FencingTokenTooLong(#[from] FencingTokenTooLongError),
    #[error("Earliest sequence number to trim to was {0} bytes, must be 8")]
    TrimPointSize(usize),
}

impl From<CommandPayloadError> for InternalRecordError {
    fn from(e: CommandPayloadError) -> Self {
        match e {
            CommandPayloadError::InvalidUtf8(_) => {
                InternalRecordError::InvalidValue("CommandPayload", "fencing token not valid utf8")
            }
            CommandPayloadError::FencingTokenTooLong(_) => {
                InternalRecordError::InvalidValue("CommandPayload", "fencing token too long")
            }
            CommandPayloadError::TrimPointSize(_) => {
                InternalRecordError::InvalidValue("CommandPayload", "trim point size")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use compact_str::ToCompactString;
    use enum_ordinalize::Ordinalize;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    fn roundtrip(cmd: CommandRecord, expected_len: usize) {
        assert_eq!(cmd.encoded_size(), expected_len);
        let encoded = cmd.to_bytes();
        assert_eq!(encoded.len(), expected_len);
        assert_eq!(CommandRecord::try_from(encoded.as_ref()), Ok(cmd));
    }

    #[test]
    fn command_op_names() {
        for cmd in CommandOp::VARIANTS {
            let name = cmd.to_id();
            assert_eq!(CommandOp::from_id(name), Some(*cmd));
        }
        assert_eq!(CommandOp::from_id(b""), None);
        assert_eq!(CommandOp::from_id(b"invalid"), None);
    }

    #[test]
    fn fencing_token_invalid_utf8() {
        assert!(matches!(
            CommandRecord::try_from_parts(CommandOp::Fence, &[0xff]),
            Err(CommandPayloadError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn fencing_token_too_long() {
        assert_eq!(
            CommandRecord::try_from_parts(
                CommandOp::Fence,
                b"0123456789012345678901234567890123456789"
            ),
            Err(CommandPayloadError::FencingTokenTooLong(
                FencingTokenTooLongError(40)
            ))
        );
    }

    #[rstest]
    #[case::empty("")]
    #[case::arbit("arbitrary")]
    #[case::full("0123456789012345")]
    fn fence_roundtrip(#[case] token: &str) {
        let cmd = CommandRecord::Fence(FencingToken::try_from(token.to_compact_string()).unwrap());
        assert_eq!(
            CommandRecord::try_from_parts(CommandOp::Fence, token.as_bytes()),
            Ok(cmd.clone())
        );
        roundtrip(cmd, 1 + token.len());
    }

    #[rstest]
    #[case::empty(b"")]
    #[case::too_small(b"0123")]
    #[case::too_big(b"0123456789")]
    fn trim_point_size(#[case] payload: &[u8]) {
        assert_eq!(
            CommandRecord::try_from_parts(CommandOp::Trim, payload),
            Err(CommandPayloadError::TrimPointSize(payload.len()))
        );
    }

    proptest! {
        #[test]
        fn trim_roundtrip(trim_point in any::<SeqNum>()) {
            let cmd = CommandRecord::Trim(trim_point);
            assert_eq!(CommandRecord::try_from_parts(CommandOp::Trim, trim_point.to_be_bytes().as_slice()), Ok(cmd.clone()));
            roundtrip(cmd, 9);
        }
    }

    #[test]
    fn decode_invalid_command() {
        let try_convert = |raw: &[u8]| CommandRecord::try_from(raw);
        assert_eq!(
            try_convert(&[]),
            Err(InternalRecordError::Truncated("CommandOrdinal"))
        );
        assert_eq!(
            try_convert(&[0xff]),
            Err(InternalRecordError::InvalidValue(
                "CommandOrdinal",
                "unknown"
            ))
        );
        assert_eq!(
            try_convert(&[CommandOp::Fence.ordinal(), 0xff, 0xff]),
            Err(InternalRecordError::InvalidValue(
                "CommandPayload",
                "fencing token not valid utf8"
            ))
        );
        assert_eq!(
            try_convert(&[
                CommandOp::Fence.ordinal(),
                b'0',
                b'1',
                b'2',
                b'3',
                b'4',
                b'5',
                b'6',
                b'7',
                b'8',
                b'9',
                b'0',
                b'1',
                b'2',
                b'3',
                b'4',
                b'5',
                b'6',
                b'7',
                b'8',
                b'9',
                b'0',
                b'1',
                b'2',
                b'3',
                b'4',
                b'5',
                b'6',
                b'7',
                b'8',
                b'9',
                b'0',
                b'1',
                b'2',
                b'3',
                b'4',
                b'5',
                b'6',
                b'7',
                b'8',
                b'9',
            ]),
            Err(CommandPayloadError::FencingTokenTooLong(FencingTokenTooLongError(40)).into())
        );
        assert_eq!(
            try_convert(&[CommandOp::Trim.ordinal(), 0xff]),
            Err(CommandPayloadError::TrimPointSize(1).into())
        );
    }
}
