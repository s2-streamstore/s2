#![cfg(feature = "test-util")]

use s2_sdk::types::{Header, ReadBatch, SequencedRecord, StreamPosition};

#[test]
fn downstream_tests_can_construct_read_fixtures() {
    let record =
        SequencedRecord::from_parts(41, 1_234, vec![Header::new("source", "fixture")], "record");
    let tail = StreamPosition::new(42, 1_234);
    let batch = ReadBatch::new(vec![record], Some(tail));

    assert_eq!(batch.records[0].seq_num, 41);
    assert_eq!(batch.records[0].timestamp, 1_234);
    assert_eq!(batch.records[0].headers[0].name, "source");
    assert_eq!(batch.records[0].headers[0].value, "fixture");
    assert_eq!(batch.records[0].body, "record");
    assert_eq!(batch.tail, Some(tail));
}
