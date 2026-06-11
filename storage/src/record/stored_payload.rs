use s2_common::{
    encryption::EncryptionSpec,
    record::{Metered, Record, Sequenced},
    stream::{
        AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts, ReadBatch,
        ReadSessionOutput,
    },
};

use super::{RecordDecryptionError, StoredRecord, decrypt_stored_record, encrypt_record};

pub type StoredAppendRecord = AppendRecord<StoredRecord>;
pub type StoredAppendRecordParts = AppendRecordParts<StoredRecord>;
pub type StoredAppendRecordBatch = AppendRecordBatch<StoredRecord>;
pub type StoredAppendInput = AppendInput<StoredRecord>;
pub type StoredReadBatch = ReadBatch<StoredRecord>;
pub type StoredReadSessionOutput = ReadSessionOutput<StoredRecord>;

pub fn encrypt_append_input(
    input: AppendInput,
    encryption: &EncryptionSpec,
    aad: &[u8],
) -> StoredAppendInput {
    let AppendInput {
        records,
        match_seq_num,
        fencing_token,
    } = input;
    let records = records
        .into_iter()
        .map(|record| {
            let AppendRecordParts { timestamp, record } = record.into_parts();
            AppendRecord::try_from(AppendRecordParts {
                timestamp,
                record: encrypt_record(record, encryption, aad),
            })
            .expect("record encryption preserves append record limits")
        })
        .collect::<Vec<_>>();

    AppendInput {
        records: AppendRecordBatch::try_from(records)
            .expect("record encryption preserves append batch limits"),
        match_seq_num,
        fencing_token,
    }
}

pub fn decrypt_read_session_output(
    output: StoredReadSessionOutput,
    encryption: &EncryptionSpec,
    aad: &[u8],
) -> Result<ReadSessionOutput, RecordDecryptionError> {
    match output {
        ReadSessionOutput::Heartbeat(tail) => Ok(ReadSessionOutput::Heartbeat(tail)),
        ReadSessionOutput::Batch(batch) => {
            decrypt_read_batch(batch, encryption, aad).map(ReadSessionOutput::Batch)
        }
    }
}

fn decrypt_read_batch(
    batch: StoredReadBatch,
    encryption: &EncryptionSpec,
    aad: &[u8],
) -> Result<ReadBatch, RecordDecryptionError> {
    let records: Result<Metered<Vec<Sequenced<Record>>>, RecordDecryptionError> = batch
        .records
        .into_inner()
        .into_iter()
        .map(|record| {
            let (position, record) = record.into_parts();
            decrypt_stored_record(record, encryption, aad).map(|record| record.sequenced(position))
        })
        .collect();

    Ok(ReadBatch {
        records: records?,
        tail: batch.tail,
    })
}
