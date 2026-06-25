mod batcher;
mod codec;
mod encryption;
mod framing;
mod iterator;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use batcher::{RecordBatch, RecordBatcher};
pub use codec::StoredRecordDecodeError;
pub(crate) use codec::WireEncode;
pub use encryption::{
    EncryptedRecord, RecordDecryptionError, decrypt_read_session_output, decrypt_stored_record,
    encrypt_append_input, encrypt_record,
};
pub use framing::{
    StoredRecord, StoredSequencedBytes, StoredSequencedRecord, decode_stored_record,
    encode_stored_record,
};
pub use iterator::StoredRecordIterator;
use s2_common::stream::{
    AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts, ReadBatch, ReadSessionOutput,
};

pub type StoredAppendRecord = AppendRecord<StoredRecord>;
pub type StoredAppendRecordParts = AppendRecordParts<StoredRecord>;
pub type StoredAppendRecordBatch = AppendRecordBatch<StoredRecord>;
pub type StoredAppendInput = AppendInput<StoredRecord>;
pub type StoredReadBatch = ReadBatch<StoredRecord>;
pub type StoredReadSessionOutput = ReadSessionOutput<StoredRecord>;
