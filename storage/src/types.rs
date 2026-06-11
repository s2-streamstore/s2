pub mod stream {
    use s2_common::{
        encryption::EncryptionSpec,
        record::{Metered, MeteredExt as _, Record, Sequenced},
        types::stream::{
            AppendInput, AppendRecord, AppendRecordBatch, AppendRecordParts, ReadBatch,
            ReadSessionOutput,
        },
    };

    use crate::record::{
        RecordDecryptionError, StoredRecord, decrypt_stored_record, encrypt_record,
    };

    pub type StoredAppendRecord = AppendRecord<StoredRecord>;
    pub type StoredAppendRecordParts = AppendRecordParts<StoredRecord>;
    pub type StoredAppendRecordBatch = AppendRecordBatch<StoredRecord>;
    pub type StoredAppendInput = AppendInput<StoredRecord>;
    pub type StoredReadBatch = ReadBatch<StoredRecord>;
    pub type StoredReadSessionOutput = ReadSessionOutput<StoredRecord>;

    pub trait AppendInputStorageExt {
        fn into_stored(self) -> StoredAppendInput;
        fn encrypt(self, encryption: &EncryptionSpec, aad: &[u8]) -> StoredAppendInput;
    }

    impl AppendInputStorageExt for AppendInput<Record> {
        fn into_stored(self) -> StoredAppendInput {
            let AppendInput {
                records,
                match_seq_num,
                fencing_token,
            } = self;
            let records = records
                .into_iter()
                .map(|record| {
                    let AppendRecordParts { timestamp, record } = record.into_parts();
                    AppendRecord::try_from(AppendRecordParts {
                        timestamp,
                        record: StoredRecord::from(record.into_inner()).metered(),
                    })
                    .expect("stored record conversion preserves append record limits")
                })
                .collect::<Vec<_>>();

            AppendInput {
                records: AppendRecordBatch::try_from(records)
                    .expect("stored record conversion preserves append batch limits"),
                match_seq_num,
                fencing_token,
            }
        }

        fn encrypt(self, encryption: &EncryptionSpec, aad: &[u8]) -> StoredAppendInput {
            let AppendInput {
                records,
                match_seq_num,
                fencing_token,
            } = self;
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
    }

    pub trait StoredReadBatchExt {
        fn decrypt(
            self,
            encryption: &EncryptionSpec,
            aad: &[u8],
        ) -> Result<ReadBatch, RecordDecryptionError>;
    }

    impl StoredReadBatchExt for ReadBatch<StoredRecord> {
        fn decrypt(
            self,
            encryption: &EncryptionSpec,
            aad: &[u8],
        ) -> Result<ReadBatch, RecordDecryptionError> {
            let records: Result<Metered<Vec<Sequenced<Record>>>, RecordDecryptionError> = self
                .records
                .into_inner()
                .into_iter()
                .map(|record| {
                    let (position, record) = record.into_parts();
                    decrypt_stored_record(record, encryption, aad)
                        .map(|record| record.sequenced(position))
                })
                .collect();

            Ok(ReadBatch {
                records: records?,
                tail: self.tail,
            })
        }
    }

    pub trait StoredReadSessionOutputExt {
        fn decrypt(
            self,
            encryption: &EncryptionSpec,
            aad: &[u8],
        ) -> Result<ReadSessionOutput, RecordDecryptionError>;
    }

    impl StoredReadSessionOutputExt for ReadSessionOutput<StoredRecord> {
        fn decrypt(
            self,
            encryption: &EncryptionSpec,
            aad: &[u8],
        ) -> Result<ReadSessionOutput, RecordDecryptionError> {
            match self {
                Self::Heartbeat(tail) => Ok(ReadSessionOutput::Heartbeat(tail)),
                Self::Batch(batch) => batch.decrypt(encryption, aad).map(ReadSessionOutput::Batch),
            }
        }
    }
}
