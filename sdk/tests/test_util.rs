#![cfg(feature = "test-util")]

use async_trait::async_trait;
use futures_util::StreamExt;
use s2_sdk::{
    StreamReadOps,
    types::{ReadBatch, ReadInput, S2Error, SequencedRecord, StreamPosition, Streaming},
};

struct MockReader;

#[async_trait]
impl StreamReadOps for MockReader {
    async fn check_tail(&self) -> Result<StreamPosition, S2Error> {
        Ok(StreamPosition::new(1, 2))
    }

    async fn read(&self, _input: ReadInput) -> Result<ReadBatch, S2Error> {
        let record = SequencedRecord::from_parts(0, 1, Vec::new(), "record");
        Ok(ReadBatch::new(
            vec![record],
            Some(StreamPosition::new(1, 2)),
        ))
    }

    async fn read_session(&self, _input: ReadInput) -> Result<Streaming<ReadBatch>, S2Error> {
        let record = SequencedRecord::from_parts(0, 1, Vec::new(), "record");
        let batch = ReadBatch::new(vec![record], Some(StreamPosition::new(1, 2)));
        Ok(Box::pin(futures_util::stream::iter([Ok(batch)])))
    }
}

#[tokio::test]
async fn mock_read_stream_ops_can_use_public_fixtures() {
    let reader: Box<dyn StreamReadOps> = Box::new(MockReader);

    assert_eq!(
        reader.check_tail().await.unwrap(),
        StreamPosition::new(1, 2)
    );

    let batch = reader.read(ReadInput::new()).await.unwrap();
    assert_eq!(batch.records[0].seq_num, 0);
    assert_eq!(batch.tail, Some(StreamPosition::new(1, 2)));

    let mut session = reader.read_session(ReadInput::new()).await.unwrap();
    let batch = session.next().await.unwrap().unwrap();
    assert_eq!(batch.records[0].seq_num, 0);
    assert_eq!(batch.records[0].body, "record");
    assert_eq!(batch.tail, Some(StreamPosition::new(1, 2)));
    assert!(session.next().await.is_none());
}
