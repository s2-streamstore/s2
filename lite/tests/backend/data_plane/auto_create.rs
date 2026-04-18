use bytes::Bytes;
use s2_common::types::{
    config::BasinConfig,
    stream::{AppendInput, ListStreamsRequest, ReadEnd, ReadFrom, ReadStart},
};

use super::common::*;

async fn assert_stream_count(
    backend: &s2_lite::backend::Backend,
    basin_name: &s2_common::types::basin::BasinName,
    expected: usize,
) {
    let stream_list = backend
        .list_streams(basin_name.clone(), ListStreamsRequest::default())
        .await
        .expect("Failed to list streams");
    assert_eq!(stream_list.values.len(), expected);
}

#[tokio::test]
async fn test_backend_append_auto_creates_stream() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_append: true,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "backend-auto-create-append", basin_config).await;
    let stream_name = test_stream_name("missing");

    let input = AppendInput {
        records: create_test_record_batch(vec![Bytes::from_static(b"should fail")]),
        match_seq_num: None,
        fencing_token: None,
    };

    let ack = backend
        .append(basin_name.clone(), stream_name.clone(), input)
        .await
        .expect("Failed to append to auto-created stream");

    assert_eq!(ack.end.seq_num, 1);
    assert_stream_count(&backend, &basin_name, 1).await;
    let tail = backend
        .check_tail(basin_name, stream_name)
        .await
        .expect("Failed to check tail on auto-created stream");
    assert_eq!(tail.seq_num, 1);
}

#[tokio::test]
async fn test_backend_read_auto_creates_stream() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_read: true,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "backend-auto-create-read", basin_config).await;
    let stream_name = test_stream_name("missing");

    let start = ReadStart {
        from: ReadFrom::SeqNum(0),
        clamp: false,
    };
    let _session = backend
        .read(
            basin_name.clone(),
            stream_name.clone(),
            start,
            ReadEnd::default(),
        )
        .await
        .expect("Failed to open read session on auto-created stream");
    assert_stream_count(&backend, &basin_name, 1).await;
    let tail = backend
        .check_tail(basin_name, stream_name)
        .await
        .expect("Failed to check tail on auto-created read stream");
    assert_eq!(tail.seq_num, 0);
}

#[tokio::test]
async fn test_backend_check_tail_auto_creates_stream() {
    let backend = create_backend().await;
    let basin_config = BasinConfig {
        create_stream_on_read: true,
        ..Default::default()
    };
    let basin_name = create_test_basin(&backend, "backend-auto-create-tail", basin_config).await;
    let stream_name = test_stream_name("missing");

    let tail = backend
        .check_tail(basin_name.clone(), stream_name)
        .await
        .expect("Failed to check tail on auto-created stream");

    assert_eq!(tail.seq_num, 0);
    assert_stream_count(&backend, &basin_name, 1).await;
}
