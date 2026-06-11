mod batcher;
mod encoding;
mod encryption;
mod framing;
mod iterator;

pub use batcher::{RecordBatch, RecordBatcher};
pub(crate) use encoding::Encodable;
pub use encoding::StoredRecordDecodeError;
pub use encryption::{
    EncryptedRecord, RecordDecryptionError, decrypt_read_session_output, decrypt_stored_record,
    encrypt_append_input, encrypt_record,
};
pub use framing::{
    StoredEncodable, StoredRecord, StoredSequencedBytes, StoredSequencedRecord,
    decode_if_command_record, decode_record, decode_stored_record, try_metered_size,
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
