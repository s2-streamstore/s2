use std::{fmt, str::Utf8Error};

use bytes::Bytes;
use compact_str::CompactString;

use super::{FencingTokenTooLongError, MeteredSize, fencing::FencingToken};
use crate::{deep_size::DeepSize, record::SeqNum};

pub const COMMAND_ID_FENCE: &[u8] = b"fence";
pub const COMMAND_ID_TRIM: &[u8] = b"trim";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

impl MeteredSize for CommandRecord {
    fn metered_size(&self) -> usize {
        8 + 2
            + self.op().to_id().len()
            + match self {
                Self::Fence(token) => token.len(),
                Self::Trim(trim_point) => size_of_val(trim_point),
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

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum CommandPayloadError {
    #[error("invalid UTF-8")]
    InvalidUtf8(Utf8Error),
    #[error(transparent)]
    FencingTokenTooLong(#[from] FencingTokenTooLongError),
    #[error("earliest sequence number to trim to was {0} bytes, must be 8")]
    TrimPointSize(usize),
}

#[cfg(test)]
mod tests {
    use compact_str::ToCompactString;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    #[test]
    fn command_op_names() {
        for cmd in [CommandOp::Fence, CommandOp::Trim] {
            let name = cmd.to_id();
            assert_eq!(CommandOp::from_id(name), Some(cmd));
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
        assert_eq!(
            cmd.metered_size(),
            8 + 2 + CommandOp::Fence.to_id().len() + token.len()
        );
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

    #[test]
    fn metered_size_is_computed_without_materializing_payload() {
        let fence =
            CommandRecord::Fence(FencingToken::try_from("fence-me".to_compact_string()).unwrap());
        assert_eq!(
            fence.metered_size(),
            8 + 2 + CommandOp::Fence.to_id().len() + "fence-me".len()
        );

        let trim = CommandRecord::Trim(42);
        assert_eq!(
            trim.metered_size(),
            8 + 2 + CommandOp::Trim.to_id().len() + size_of_val(&42u64)
        );
    }

    proptest! {
        #[test]
        fn trim_roundtrip(trim_point in any::<SeqNum>()) {
            let cmd = CommandRecord::Trim(trim_point);
            assert_eq!(CommandRecord::try_from_parts(CommandOp::Trim, trim_point.to_be_bytes().as_slice()), Ok(cmd.clone()));
            assert_eq!(cmd.metered_size(), 8 + 2 + CommandOp::Trim.to_id().len() + size_of::<SeqNum>());
        }
    }
}
