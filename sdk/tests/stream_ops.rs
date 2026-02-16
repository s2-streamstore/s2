mod common;

use std::time::Duration;

use assert_matches::assert_matches;
use common::{S2Stream, SharedS2Basin, s2_config, unique_basin_name, unique_stream_name};
use futures::StreamExt;
use rstest::rstest;
use s2_sdk::{
    append_session::AppendSessionConfig, batching::BatchingConfig, producer::ProducerConfig,
    types::*,
};
use test_context::test_context;
use time::OffsetDateTime;

fn now_millis() -> u64 {
    (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as u64
}

fn past_millis(offset_ms: u64) -> u64 {
    now_millis().saturating_sub(offset_ms)
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn tail_of_new_stream(stream: &S2Stream) -> Result<(), S2Error> {
    let tail = stream.check_tail().await?;

    assert_eq!(tail.seq_num, 0);

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn tail_of_nonexistent_stream_errors(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream = basin.stream(unique_stream_name());

    let result = stream.check_tail().await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert_eq!(code, "stream_not_found");
        }
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn single_append(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);
    assert_eq!(ack.tail.seq_num, 1);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn multiple_appends(stream: &S2Stream) -> Result<(), S2Error> {
    let input1 = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);
    let input2 = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "ipsum",
    )?])?);
    let input3 = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("dolor")?,
        AppendRecord::new("sit")?,
    ])?);

    let ack1 = stream.append(input1).await?;
    let ack2 = stream.append(input2).await?;
    let ack3 = stream.append(input3).await?;

    assert_eq!(ack1.start.seq_num, 0);
    assert_eq!(ack1.end.seq_num, 1);
    assert_eq!(ack2.start.seq_num, 1);
    assert_eq!(ack2.end.seq_num, 2);
    assert_eq!(ack3.start.seq_num, 2);
    assert_eq!(ack3.end.seq_num, 4);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_with_headers(stream: &S2Stream) -> Result<(), S2Error> {
    let headers = vec![Header::new("key1", "value1"), Header::new("key2", "value2")];
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?
    .with_headers(headers.clone())?])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);

    let batch = stream.read(ReadInput::new()).await?;

    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0].headers.len(), headers.len());

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_with_match_seq_num(stream: &S2Stream) -> Result<(), S2Error> {
    let input1 = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?,
        AppendRecord::new("ipsum")?,
    ])?)
    .with_match_seq_num(0);

    let ack1 = stream.append(input1).await?;

    assert_eq!(ack1.start.seq_num, 0);
    assert_eq!(ack1.end.seq_num, 2);

    let input2 = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "dolor",
    )?])?)
    .with_match_seq_num(2);

    let ack2 = stream.append(input2).await?;

    assert_eq!(ack2.start.seq_num, 2);
    assert_eq!(ack2.end.seq_num, 3);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_count_limit_partial(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?,
        AppendRecord::new("ipsum")?,
        AppendRecord::new("dolor")?,
    ])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 3);

    let batch = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(1)))
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(2))),
        )
        .await?;

    assert_eq!(batch.records.len(), 2);
    assert_eq!(batch.records[0].seq_num, 1);
    assert_eq!(batch.records[0].body, "ipsum");
    assert_eq!(batch.records[1].seq_num, 2);
    assert_eq!(batch.records[1].body, "dolor");

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_count_limit_exact(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?,
        AppendRecord::new("ipsum")?,
        AppendRecord::new("dolor")?,
    ])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 3);

    let batch = stream
        .read(
            ReadInput::new()
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(3))),
        )
        .await?;

    assert_eq!(batch.records.len(), 3);
    assert_eq!(batch.records[0].seq_num, 0);
    assert_eq!(batch.records[0].body, "lorem");
    assert_eq!(batch.records[2].seq_num, 2);
    assert_eq!(batch.records[2].body, "dolor");

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_count_limit_exceeds(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?,
        AppendRecord::new("ipsum")?,
    ])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 2);

    let batch = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(5))),
        )
        .await?;

    assert_eq!(batch.records.len(), 2);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_count_over_max_clamps(stream: &S2Stream) -> Result<(), S2Error> {
    let records = (0..1000)
        .map(|i| AppendRecord::new(format!("record-{i}")))
        .collect::<Result<Vec<_>, _>>()?;
    let input = AppendInput::new(AppendRecordBatch::try_from_iter(records)?);
    stream.append(input).await?;

    let records = (0..5)
        .map(|i| AppendRecord::new(format!("tail-{i}")))
        .collect::<Result<Vec<_>, _>>()?;
    let input = AppendInput::new(AppendRecordBatch::try_from_iter(records)?);
    stream.append(input).await?;

    let batch = stream
        .read(
            ReadInput::new()
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(2000))),
        )
        .await?;

    assert_eq!(batch.records.len(), 1000);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_bytes_limit_partial(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?,
        AppendRecord::new("ipsum")?,
        AppendRecord::new("dolor")?,
    ])?);
    let bytes_limit = input.records.metered_bytes() - 5;

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 3);

    let batch = stream
        .read(
            ReadInput::new()
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_bytes(bytes_limit))),
        )
        .await?;

    assert_eq!(batch.records.len(), 2);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_bytes_limit_exact(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);
    let bytes_limit = input.records.metered_bytes();

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let batch = stream
        .read(
            ReadInput::new()
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_bytes(bytes_limit))),
        )
        .await?;

    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0].body, "lorem");

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_bytes_limit_exceeds(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?,
        AppendRecord::new("ipsum")?,
    ])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 2);

    let batch = stream
        .read(
            ReadInput::new()
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_bytes(1000))),
        )
        .await?;

    assert_eq!(batch.records.len(), 2);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_bytes_over_max_clamps(stream: &S2Stream) -> Result<(), S2Error> {
    let body = "a".repeat(700_000);
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        body.clone(),
    )?])?);
    stream.append(input).await?;

    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        body,
    )?])?);
    stream.append(input).await?;

    let batch =
        stream
            .read(ReadInput::new().with_stop(
                ReadStop::new().with_limits(ReadLimits::new().with_bytes(2 * 1024 * 1024)),
            ))
            .await?;

    let read_bytes: usize = batch.records.iter().map(|r| r.metered_bytes()).sum();
    assert!(read_bytes <= 1024 * 1024);
    assert_eq!(batch.records.len(), 1);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_from_seq_num_with_bytes_limit(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?,
        AppendRecord::new("ipsum")?,
        AppendRecord::new("dolor")?,
        AppendRecord::new("sit")?,
    ])?);
    let bytes_limit = input.records[1].metered_bytes() + input.records[2].metered_bytes();

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 4);

    let batch = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(1)))
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_bytes(bytes_limit))),
        )
        .await?;

    assert_eq!(batch.records.len(), 2);
    assert_eq!(batch.records[0].seq_num, 1);
    assert_eq!(batch.records[0].body, "ipsum");
    assert_eq!(batch.records[1].seq_num, 2);
    assert_eq!(batch.records[1].body, "dolor");

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_zero_bytes_limit(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let batch = stream
        .read(
            ReadInput::new()
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_bytes(0))),
        )
        .await?;

    assert_eq!(batch.records.len(), 0);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_unbounded_limit(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?,
        AppendRecord::new("ipsum")?,
    ])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 2);

    let batch = stream
        .read(ReadInput::new().with_stop(ReadStop::new().with_limits(ReadLimits::new())))
        .await?;

    assert_eq!(batch.records.len(), 2);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_empty_body_record(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new("")?])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_with_mismatched_seq_num_errors(stream: &S2Stream) -> Result<(), S2Error> {
    let input1 = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let ack = stream.append(input1).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let input2 = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "ipsum",
    )?])?)
    .with_match_seq_num(0);

    let result = stream.append(input2).await;

    assert_matches!(
        result,
        Err(S2Error::AppendConditionFailed(
            AppendConditionFailed::SeqNumMismatch(1)
        ))
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_session_with_mismatched_seq_num_errors(stream: &S2Stream) -> Result<(), S2Error> {
    let session = stream.append_session(AppendSessionConfig::new());

    let input1 = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let ack = session.submit(input1).await?.await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let input2 = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "ipsum",
    )?])?)
    .with_match_seq_num(0);

    let result = session.submit(input2).await?.await;

    assert_matches!(
        result,
        Err(S2Error::AppendConditionFailed(
            AppendConditionFailed::SeqNumMismatch(1)
        ))
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_with_matching_fencing_token_succeeds(stream: &S2Stream) -> Result<(), S2Error> {
    let fencing_token = FencingToken::generate(30).expect("valid fencing token");
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([CommandRecord::fence(
        fencing_token.clone(),
    )
    .into()])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "ipsum",
    )?])?)
    .with_fencing_token(fencing_token);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 1);
    assert_eq!(ack.end.seq_num, 2);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_with_mismatched_fencing_token_errors(stream: &S2Stream) -> Result<(), S2Error> {
    let fencing_token_1 = FencingToken::generate(30).expect("valid fencing token");
    let input1 = AppendInput::new(AppendRecordBatch::try_from_iter([CommandRecord::fence(
        fencing_token_1.clone(),
    )
    .into()])?);

    let ack = stream.append(input1).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let fencing_token_2 = FencingToken::generate(30).expect("valid fencing token");
    let input2 = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "ipsum",
    )?])?)
    .with_fencing_token(fencing_token_2);

    let result = stream.append(input2).await;

    assert_matches!(
        result,
        Err(S2Error::AppendConditionFailed(AppendConditionFailed::FencingTokenMismatch(fencing_token))) => {
            assert_eq!(fencing_token, fencing_token_1)
        }
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_session_with_mismatched_fencing_token_errors(
    stream: &S2Stream,
) -> Result<(), S2Error> {
    let session = stream.append_session(AppendSessionConfig::new());

    let fencing_token_1 = FencingToken::generate(30).expect("valid fencing token");
    let input1 = AppendInput::new(AppendRecordBatch::try_from_iter([CommandRecord::fence(
        fencing_token_1.clone(),
    )
    .into()])?);

    let ack = session.submit(input1).await?.await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let fencing_token_2 = FencingToken::generate(30).expect("valid fencing token");
    let input2 = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "ipsum",
    )?])?)
    .with_fencing_token(fencing_token_2);

    let result = session.submit(input2).await?.await;

    assert_matches!(
        result,
        Err(S2Error::AppendConditionFailed(AppendConditionFailed::FencingTokenMismatch(fencing_token))) => {
            assert_eq!(fencing_token, fencing_token_1)
        }
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_empty_stream_errors(stream: &S2Stream) -> Result<(), S2Error> {
    let result = stream.read(ReadInput::new()).await;

    assert_matches!(
        result,
        Err(S2Error::ReadUnwritten(StreamPosition {
            seq_num: 0,
            timestamp: 0,
            ..
        }))
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_beyond_tail_errors(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let result = stream
        .read(ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::SeqNum(10))))
        .await;

    assert_matches!(
        result,
        Err(S2Error::ReadUnwritten(StreamPosition { seq_num: 1, .. }))
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_beyond_tail_with_clamp_to_tail_errors(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let result = stream
        .read(
            ReadInput::new().with_start(
                ReadStart::new()
                    .with_from(ReadFrom::SeqNum(10))
                    .with_clamp_to_tail(true),
            ),
        )
        .await;

    assert_matches!(
        result,
        Err(S2Error::ReadUnwritten(StreamPosition { seq_num: 1, .. }))
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_beyond_tail_with_clamp_to_tail_and_wait_returns_empty_batch(
    stream: &S2Stream,
) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let batch = stream
        .read(
            ReadInput::new()
                .with_start(
                    ReadStart::new()
                        .with_from(ReadFrom::SeqNum(10))
                        .with_clamp_to_tail(true),
                )
                .with_stop(ReadStop::new().with_wait(1)),
        )
        .await?;

    assert!(batch.records.is_empty());

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_session_beyond_tail_errors(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let result = stream
        .read_session(ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::SeqNum(10))))
        .await;

    assert!(result.is_err());
    assert_matches!(
        result.err().expect("should be err"),
        S2Error::ReadUnwritten(StreamPosition { seq_num: 1, .. })
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_session_beyond_tail_with_clamp_to_tail(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let mut batches = stream
        .read_session(
            ReadInput::new().with_start(
                ReadStart::new()
                    .with_from(ReadFrom::SeqNum(10))
                    .with_clamp_to_tail(true),
            ),
        )
        .await?;

    let result = tokio::time::timeout(Duration::from_secs(1), batches.next()).await;
    assert_matches!(result, Err(tokio::time::error::Elapsed { .. }));

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_with_empty_header_value(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?
    .with_headers([Header::new("key1", ""), Header::new("key2", "")])?])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let batch = stream.read(ReadInput::new()).await?;

    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0].headers.len(), 2);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_mixed_records_with_and_without_headers(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?.with_headers([Header::new("key1", "value1")])?,
        AppendRecord::new("ipsum")?
            .with_headers([Header::new("key2", ""), Header::new("key3", "value3")])?,
        AppendRecord::new("dolor")?,
    ])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 3);

    let batch = stream.read(ReadInput::new()).await?;

    assert_eq!(batch.records.len(), 3);
    assert_eq!(batch.records[0].headers.len(), 1);
    assert_eq!(batch.records[1].headers.len(), 2);
    assert_eq!(batch.records[2].headers.len(), 0);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn check_tail_after_multiple_appends(stream: &S2Stream) -> Result<(), S2Error> {
    let input1 = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let ack1 = stream.append(input1).await?;

    assert_eq!(ack1.start.seq_num, 0);
    assert_eq!(ack1.end.seq_num, 1);

    let tail1 = stream.check_tail().await?;
    assert_eq!(tail1.seq_num, 1);

    let input2 = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("ipsum")?,
        AppendRecord::new("dolor")?,
    ])?);

    let ack2 = stream.append(input2).await?;

    assert_eq!(ack2.start.seq_num, 1);
    assert_eq!(ack2.end.seq_num, 3);

    let tail2 = stream.check_tail().await?;
    assert_eq!(tail2.seq_num, 3);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_from_timestamp(stream: &S2Stream) -> Result<(), S2Error> {
    let base_timestamp = past_millis(10_000);
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?.with_timestamp(base_timestamp),
        AppendRecord::new("ipsum")?.with_timestamp(base_timestamp + 1),
        AppendRecord::new("dolor")?.with_timestamp(base_timestamp + 2),
        AppendRecord::new("sit")?.with_timestamp(base_timestamp + 3),
    ])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.start.timestamp, base_timestamp);
    assert_eq!(ack.end.seq_num, 4);
    assert_eq!(ack.end.timestamp, base_timestamp + 3);

    let batch = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::Timestamp(base_timestamp + 1))),
        )
        .await?;

    assert_eq!(batch.records.len(), 3);
    assert_eq!(batch.records[0].seq_num, 1);
    assert_eq!(batch.records[0].timestamp, base_timestamp + 1);
    assert_eq!(batch.records[1].seq_num, 2);
    assert_eq!(batch.records[1].timestamp, base_timestamp + 2);
    assert_eq!(batch.records[2].seq_num, 3);
    assert_eq!(batch.records[2].timestamp, base_timestamp + 3);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_from_timestamp_with_count_limit(stream: &S2Stream) -> Result<(), S2Error> {
    let base_timestamp = past_millis(10_000);
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?.with_timestamp(base_timestamp),
        AppendRecord::new("ipsum")?.with_timestamp(base_timestamp + 1),
        AppendRecord::new("dolor")?.with_timestamp(base_timestamp + 2),
        AppendRecord::new("sit")?.with_timestamp(base_timestamp + 3),
    ])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.start.timestamp, base_timestamp);
    assert_eq!(ack.end.seq_num, 4);
    assert_eq!(ack.end.timestamp, base_timestamp + 3);

    let batch = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::Timestamp(base_timestamp + 2)))
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(1))),
        )
        .await?;

    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0].seq_num, 2);
    assert_eq!(batch.records[0].timestamp, base_timestamp + 2);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_from_timestamp_with_bytes_limit(stream: &S2Stream) -> Result<(), S2Error> {
    let base_timestamp = past_millis(10_000);
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?.with_timestamp(base_timestamp),
        AppendRecord::new("ipsum")?.with_timestamp(base_timestamp + 1),
        AppendRecord::new("dolor")?.with_timestamp(base_timestamp + 2),
        AppendRecord::new("sit")?.with_timestamp(base_timestamp + 3),
    ])?);
    let bytes_limit = input.records[1].metered_bytes() + 5;

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.start.timestamp, base_timestamp);
    assert_eq!(ack.end.seq_num, 4);
    assert_eq!(ack.end.timestamp, base_timestamp + 3);

    let batch = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::Timestamp(base_timestamp + 1)))
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_bytes(bytes_limit))),
        )
        .await?;

    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0].seq_num, 1);
    assert_eq!(batch.records[0].timestamp, base_timestamp + 1);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_from_timestamp_in_future_errors(stream: &S2Stream) -> Result<(), S2Error> {
    let base_timestamp = past_millis(10_000);
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?.with_timestamp(base_timestamp),
        AppendRecord::new("ipsum")?.with_timestamp(base_timestamp + 1),
    ])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.start.timestamp, base_timestamp);
    assert_eq!(ack.end.seq_num, 2);
    assert_eq!(ack.end.timestamp, base_timestamp + 1);

    let result = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::Timestamp(base_timestamp + 100))),
        )
        .await;

    assert_matches!(result, Err(S2Error::ReadUnwritten(tail)) => {
        assert_eq!(tail.seq_num, 2);
        assert_eq!(tail.timestamp, base_timestamp + 1);
    });

    Ok(())
}

#[test]
fn append_record_batch_rejects_empty() {
    let result = AppendRecordBatch::try_from_iter(std::iter::empty::<AppendRecord>());

    assert_matches!(result, Err(ValidationError(msg)) => {
        assert!(msg.contains("batch is empty"));
    });
}

#[test]
fn append_record_batch_rejects_too_many_records() {
    let records = (0..1001).map(|_| AppendRecord::new("a").expect("valid record"));
    let result = AppendRecordBatch::try_from_iter(records);

    assert_matches!(result, Err(ValidationError(msg)) => {
        assert!(msg.contains("number of records"));
    });
}

#[test]
fn append_record_rejects_too_large() {
    let body = "a".repeat(1024 * 1024 + 1);
    let result = AppendRecord::new(body);

    assert_matches!(result, Err(ValidationError(msg)) => {
        assert!(msg.contains("metered_bytes"));
    });
}

#[test]
fn fencing_token_rejects_too_long() {
    let result: Result<FencingToken, _> = "a".repeat(37).parse();

    assert!(result.is_err());
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_max_batch_size(stream: &S2Stream) -> Result<(), S2Error> {
    let records = (0..1000)
        .map(|_| AppendRecord::new("a"))
        .collect::<Result<Vec<_>, _>>()?;
    let input = AppendInput::new(AppendRecordBatch::try_from_iter(records)?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1000);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_with_client_timestamp(stream: &S2Stream) -> Result<(), S2Error> {
    let timestamp = past_millis(1_000);
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?
    .with_timestamp(timestamp)])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.timestamp, timestamp);

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn append_without_timestamp_client_require_errors(
    basin: &SharedS2Basin,
) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    let config = StreamConfig::new()
        .with_timestamping(TimestampingConfig::new().with_mode(TimestampingMode::ClientRequire));

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(config))
        .await?;

    let stream = basin.stream(stream_name.clone());
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let result = stream.append(input).await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert_eq!(code, "invalid");
        }
    );

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn append_with_future_timestamp_uncapped_false_caps(
    basin: &SharedS2Basin,
) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    let config =
        StreamConfig::new().with_timestamping(TimestampingConfig::new().with_uncapped(false));

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(config))
        .await?;

    let stream = basin.stream(stream_name.clone());
    let now = now_millis();
    let future = now + 3_600_000;
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?
    .with_timestamp(future)])?);

    let ack = stream.append(input).await?;

    assert!(ack.start.timestamp < future);

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn append_with_future_timestamp_uncapped_true_preserves(
    basin: &SharedS2Basin,
) -> Result<(), S2Error> {
    let stream_name = unique_stream_name();
    let config =
        StreamConfig::new().with_timestamping(TimestampingConfig::new().with_uncapped(true));

    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(config))
        .await?;

    let stream = basin.stream(stream_name.clone());
    let now = now_millis();
    let future = now + 3_600_000;
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?
    .with_timestamp(future)])?);

    let ack = stream.append(input).await?;

    assert_eq!(ack.start.timestamp, future);

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_with_past_timestamp_adjusts_monotonic(stream: &S2Stream) -> Result<(), S2Error> {
    let base = past_millis(10_000);
    let first_timestamp = base + 10;
    let past_timestamp = base;

    let input_1 = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "first",
    )?
    .with_timestamp(first_timestamp)])?);
    let ack_1 = stream.append(input_1).await?;

    let input_2 = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "second",
    )?
    .with_timestamp(past_timestamp)])?);
    let ack_2 = stream.append(input_2).await?;

    assert!(ack_2.start.timestamp >= ack_1.end.timestamp);

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn append_to_nonexistent_stream_errors(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream = basin.stream(unique_stream_name());
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let result = stream.append(input).await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert_eq!(code, "stream_not_found");
        }
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_invalid_command_header_errors(stream: &S2Stream) -> Result<(), S2Error> {
    let record = AppendRecord::new("lorem")?.with_headers([Header::new("", "not-a-command")])?;
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([record])?);

    let result = stream.append(input).await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert_eq!(code, "invalid");
        }
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_invalid_command_header_with_extra_headers_errors(
    stream: &S2Stream,
) -> Result<(), S2Error> {
    let record = AppendRecord::new("lorem")?
        .with_headers([Header::new("", "fence"), Header::new("extra", "value")])?;
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([record])?);

    let result = stream.append(input).await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert_eq!(code, "invalid");
        }
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn fence_set_and_clear_token(stream: &S2Stream) -> Result<(), S2Error> {
    let token = FencingToken::generate(30).expect("valid fencing token");
    let set_input = AppendInput::new(AppendRecordBatch::try_from_iter([CommandRecord::fence(
        token.clone(),
    )
    .into()])?);
    let ack_1 = stream.append(set_input).await?;

    assert_eq!(ack_1.start.seq_num, 0);

    let clear_token: FencingToken = "".parse().expect("valid fencing token");
    let clear_input = AppendInput::new(AppendRecordBatch::try_from_iter([CommandRecord::fence(
        clear_token,
    )
    .into()])?);
    let ack_2 = stream.append(clear_input).await?;

    assert_eq!(ack_2.start.seq_num, 1);

    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);
    let ack_3 = stream.append(input).await?;

    assert_eq!(ack_3.start.seq_num, 2);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn trim_command_is_accepted(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("record-1")?,
        AppendRecord::new("record-2")?,
        AppendRecord::new("record-3")?,
    ])?);
    let _ = stream.append(input).await?;

    let trim_input = AppendInput::new(AppendRecordBatch::try_from_iter([
        CommandRecord::trim(2).into()
    ])?);
    let ack = stream.append(trim_input).await?;

    assert!(ack.end.seq_num > 0);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn trim_to_future_seq_num_noop(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "record-1",
    )?])?);
    let _ = stream.append(input).await?;

    let trim_input = AppendInput::new(AppendRecordBatch::try_from_iter([CommandRecord::trim(
        999_999,
    )
    .into()])?);
    let ack = stream.append(trim_input).await?;

    assert!(ack.end.seq_num > 0);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_empty_stream_with_wait_returns_empty(stream: &S2Stream) -> Result<(), S2Error> {
    let batch = stream
        .read(ReadInput::new().with_stop(ReadStop::new().with_wait(1)))
        .await?;

    assert!(batch.records.is_empty());

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_count_zero_returns_empty(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?,
        AppendRecord::new("ipsum")?,
    ])?);
    let _ = stream.append(input).await?;

    let batch = stream
        .read(
            ReadInput::new()
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(0))),
        )
        .await?;

    assert!(batch.records.is_empty());

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_bytes_zero_returns_empty(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?,
        AppendRecord::new("ipsum")?,
    ])?);
    let _ = stream.append(input).await?;

    let batch = stream
        .read(
            ReadInput::new()
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_bytes(0))),
        )
        .await?;

    assert!(batch.records.is_empty());

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_from_tail_offset_variants(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("record-0")?,
        AppendRecord::new("record-1")?,
        AppendRecord::new("record-2")?,
        AppendRecord::new("record-3")?,
        AppendRecord::new("record-4")?,
    ])?);
    let _ = stream.append(input).await?;

    let result = stream
        .read(ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::TailOffset(0))))
        .await;
    assert_matches!(result, Err(S2Error::ReadUnwritten(StreamPosition { .. })));

    let batch = stream
        .read(ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::TailOffset(3))))
        .await?;
    assert_eq!(batch.records.len(), 3);
    assert_eq!(batch.records[0].seq_num, 2);

    let batch = stream
        .read(ReadInput::new().with_start(ReadStart::new().with_from(ReadFrom::TailOffset(999))))
        .await?;
    assert_eq!(batch.records[0].seq_num, 0);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_until_timestamp(stream: &S2Stream) -> Result<(), S2Error> {
    let base_timestamp = past_millis(10_000);
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?.with_timestamp(base_timestamp),
        AppendRecord::new("ipsum")?.with_timestamp(base_timestamp + 1),
        AppendRecord::new("dolor")?.with_timestamp(base_timestamp + 2),
    ])?);
    let _ = stream.append(input).await?;

    let batch = stream
        .read(ReadInput::new().with_stop(ReadStop::new().with_until(..(base_timestamp + 2))))
        .await?;

    assert_eq!(batch.records.len(), 2);
    assert_eq!(batch.records[0].timestamp, base_timestamp);
    assert_eq!(batch.records[1].timestamp, base_timestamp + 1);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_start_timestamp_ge_until_errors(stream: &S2Stream) -> Result<(), S2Error> {
    let base_timestamp = past_millis(10_000);
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?.with_timestamp(base_timestamp),
        AppendRecord::new("ipsum")?.with_timestamp(base_timestamp + 1),
        AppendRecord::new("dolor")?.with_timestamp(base_timestamp + 2),
    ])?);
    let _ = stream.append(input).await?;

    let result = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::new().with_from(ReadFrom::Timestamp(base_timestamp + 2)))
                .with_stop(ReadStop::new().with_until(..(base_timestamp + 2))),
        )
        .await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert_eq!(code, "invalid");
        }
    );

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn read_nonexistent_stream_errors(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream = basin.stream(unique_stream_name());
    let result = stream.read(ReadInput::new()).await;

    assert_matches!(
        result,
        Err(S2Error::Server(ErrorResponse { code, .. })) => {
            assert_eq!(code, "stream_not_found");
        }
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_session_close_delivers_all_acks(stream: &S2Stream) -> Result<(), S2Error> {
    let session = stream.append_session(AppendSessionConfig::default());

    let ticket1 = session
        .submit(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("lorem")?,
            AppendRecord::new("ipsum")?,
        ])?))
        .await?;
    let ticket2 = session
        .submit(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("dolor")?,
        ])?))
        .await?;
    let ticket3 = session
        .submit(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("sit")?,
        ])?))
        .await?;

    session.close().await?;

    let ack1 = ticket1.await?;
    let ack2 = ticket2.await?;
    let ack3 = ticket3.await?;

    assert_eq!(ack1.start.seq_num, 0);
    assert_eq!(ack1.end.seq_num, 2);
    assert_eq!(ack2.start.seq_num, 2);
    assert_eq!(ack2.end.seq_num, 3);
    assert_eq!(ack3.start.seq_num, 3);
    assert_eq!(ack3.end.seq_num, 4);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn batch_submit_ticket_drop_should_not_affect_others(
    stream: &S2Stream,
) -> Result<(), S2Error> {
    let session = stream.append_session(AppendSessionConfig::default());

    let _ticket1 = session
        .submit(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("lorem")?,
            AppendRecord::new("ipsum")?,
        ])?))
        .await?;
    drop(_ticket1);

    let ticket2 = session
        .submit(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("dolor")?,
        ])?))
        .await?;

    session.close().await?;

    let ack2 = ticket2.await?;
    assert_eq!(ack2.start.seq_num, 2);
    assert_eq!(ack2.end.seq_num, 3);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn producer_delivers_all_acks(stream: &S2Stream) -> Result<(), S2Error> {
    let producer = stream.producer(ProducerConfig::default());

    let ack1 = producer.submit(AppendRecord::new("lorem")?).await?.await?;
    let ack2 = producer.submit(AppendRecord::new("ipsum")?).await?.await?;
    let ack3 = producer.submit(AppendRecord::new("dolor")?).await?.await?;

    assert_eq!(ack1.seq_num, 0);
    assert_eq!(ack2.seq_num, 1);
    assert_eq!(ack3.seq_num, 2);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn producer_close_delivers_all_indexed_acks_from_same_ack(
    stream: &S2Stream,
) -> Result<(), S2Error> {
    let producer = stream.producer(ProducerConfig::default());

    let ticket1 = producer.submit(AppendRecord::new("lorem")?).await?;
    let ticket2 = producer.submit(AppendRecord::new("ipsum")?).await?;
    let ticket3 = producer.submit(AppendRecord::new("dolor")?).await?;

    producer.close().await?;

    let ack1 = ticket1.await?;
    let ack2 = ticket2.await?;
    let ack3 = ticket3.await?;

    assert_eq!(ack1.seq_num, 0);
    assert_eq!(ack2.seq_num, 1);
    assert_eq!(ack3.seq_num, 2);

    assert_eq!(ack1.batch, ack2.batch);
    assert_eq!(ack2.batch, ack3.batch);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn producer_close_delivers_all_indexed_acks_from_different_acks(
    stream: &S2Stream,
) -> Result<(), S2Error> {
    let producer = stream.producer(
        ProducerConfig::default()
            .with_batching(BatchingConfig::default().with_max_batch_records(1)?),
    );

    let ticket1 = producer.submit(AppendRecord::new("lorem")?).await?;
    let ticket2 = producer.submit(AppendRecord::new("ipsum")?).await?;
    let ticket3 = producer.submit(AppendRecord::new("dolor")?).await?;

    producer.close().await?;

    let ack1 = ticket1.await?;
    let ack2 = ticket2.await?;
    let ack3 = ticket3.await?;

    assert_eq!(ack1.seq_num, 0);
    assert_eq!(ack2.seq_num, 1);
    assert_eq!(ack3.seq_num, 2);

    assert_ne!(ack1.batch, ack2.batch);
    assert_ne!(ack2.batch, ack3.batch);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn producer_drop_errors_all_claimable_tickets(stream: &S2Stream) -> Result<(), S2Error> {
    let producer = stream.producer(
        ProducerConfig::default()
            .with_batching(BatchingConfig::default().with_linger(Duration::from_secs(1))),
    );

    let ticket1 = producer.submit(AppendRecord::new("lorem")?).await?;
    let ticket2 = producer.submit(AppendRecord::new("ipsum")?).await?;

    drop(producer);

    let result1 = ticket1.await;
    let result2 = ticket2.await;

    assert_matches!(result1, Err(S2Error::Client(msg)) => {
        assert_eq!(msg, "producer dropped without calling close");
    });
    assert_matches!(result2, Err(S2Error::Client(msg)) => {
        assert_eq!(msg, "producer dropped without calling close");
    });

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn producer_drop_errors_no_claimable_tickets(stream: &S2Stream) -> Result<(), S2Error> {
    let producer = stream.producer(ProducerConfig::default());

    let ticket1 = producer.submit(AppendRecord::new("lorem")?).await?;
    let ticket2 = producer.submit(AppendRecord::new("ipsum")?).await?;

    let ack1 = tokio::time::timeout(Duration::from_secs(10), ticket1)
        .await
        .expect("ticket1 timed out")?;
    let ack2 = tokio::time::timeout(Duration::from_secs(10), ticket2)
        .await
        .expect("ticket2 timed out")?;

    drop(producer);

    assert_eq!(ack1.seq_num, 0);
    assert_eq!(ack2.seq_num, 1);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn record_submit_ticket_drop_should_not_affect_others(
    stream: &S2Stream,
) -> Result<(), S2Error> {
    let producer = stream.producer(ProducerConfig::default());

    let _ticket1 = producer.submit(AppendRecord::new("lorem")?).await?;
    drop(_ticket1);

    let ticket2 = producer.submit(AppendRecord::new("ipsum")?).await?;

    producer.close().await?;

    let ack2 = ticket2.await?;
    assert_eq!(ack2.seq_num, 1);

    Ok(())
}

#[tokio::test]
async fn create_stream_inherits_basin_default_config() -> Result<(), S2Error> {
    let config = s2_config(Compression::None).expect("valid S2 config");
    let s2 = s2_sdk::S2::new(config).expect("valid S2");

    let basin_name = unique_basin_name();
    let default_stream_config = StreamConfig::new()
        .with_storage_class(StorageClass::Standard)
        .with_retention_policy(RetentionPolicy::Age(3600))
        .with_delete_on_empty(DeleteOnEmptyConfig::new().with_min_age(Duration::from_secs(3600)));
    let basin_config = BasinConfig::new().with_default_stream_config(default_stream_config);

    s2.create_basin(CreateBasinInput::new(basin_name.clone()).with_config(basin_config))
        .await?;

    let basin = s2.basin(basin_name.clone());
    let stream_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()))
        .await?;

    let stream_config = basin.get_stream_config(stream_name.clone()).await?;
    assert_matches!(
        stream_config,
        StreamConfig {
            storage_class: Some(StorageClass::Standard),
            retention_policy: Some(RetentionPolicy::Age(3600)),
            delete_on_empty: Some(DeleteOnEmptyConfig {
                min_age_secs: 3600,
                ..
            }),
            ..
        }
    );

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;
    s2.delete_basin(DeleteBasinInput::new(basin_name)).await?;

    Ok(())
}

#[rstest]
#[case::gzip(Compression::Gzip)]
#[case::zstd(Compression::Zstd)]
#[tokio::test]
async fn compression_roundtrip_unary(#[case] compression: Compression) -> Result<(), S2Error> {
    let config = s2_config(compression).expect("valid S2 config");
    let s2 = s2_sdk::S2::new(config).expect("valid S2");

    let basin_name = unique_basin_name();
    let basin_config = BasinConfig::new()
        .with_default_stream_config(StreamConfig::new().with_storage_class(StorageClass::Standard));
    s2.create_basin(CreateBasinInput::new(basin_name.clone()).with_config(basin_config))
        .await?;

    let basin = s2.basin(basin_name.clone());
    let stream_name = unique_stream_name();
    let stream_config =
        StreamConfig::new().with_timestamping(TimestampingConfig::new().with_uncapped(true));
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(stream_config))
        .await?;

    let stream = basin.stream(stream_name.clone());

    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("s".repeat(2048))?,
        AppendRecord::new("2".repeat(2048))?,
    ])?);
    let ack = stream.append(input).await?;
    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 2);

    let batch = stream.read(ReadInput::new()).await?;
    assert_eq!(batch.records.len(), 2);

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;
    s2.delete_basin(DeleteBasinInput::new(basin_name)).await?;

    Ok(())
}

#[rstest]
#[case::gzip(Compression::Gzip)]
#[case::zstd(Compression::Zstd)]
#[tokio::test]
async fn compression_roundtrip_session(#[case] compression: Compression) -> Result<(), S2Error> {
    let config = s2_config(compression).expect("valid S2 config");
    let s2 = s2_sdk::S2::new(config).expect("valid S2");

    let basin_name = unique_basin_name();
    let basin_config = BasinConfig::new().with_default_stream_config(
        StreamConfig::new()
            .with_timestamping(TimestampingConfig::new().with_mode(TimestampingMode::Arrival)),
    );
    s2.create_basin(CreateBasinInput::new(basin_name.clone()).with_config(basin_config))
        .await?;

    let basin = s2.basin(basin_name.clone());
    let stream_name = unique_stream_name();
    let stream_config = StreamConfig::new().with_storage_class(StorageClass::Standard);
    basin
        .create_stream(CreateStreamInput::new(stream_name.clone()).with_config(stream_config))
        .await?;

    let stream = basin.stream(stream_name.clone());

    // Payload must be >= 1KiB to trigger compression (COMPRESSION_THRESHOLD_BYTES)
    let session = stream.append_session(AppendSessionConfig::default());
    let ticket = session
        .submit(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("s2".repeat(10240))?,
        ])?))
        .await?;
    session.close().await?;

    let ack = ticket.await?;
    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    let mut batches = stream.read_session(ReadInput::new()).await?;
    let batch = batches.next().await.expect("should have batch")?;
    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0].body.len(), 20480);

    basin
        .delete_stream(DeleteStreamInput::new(stream_name))
        .await?;
    s2.delete_basin(DeleteBasinInput::new(basin_name)).await?;

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn append_session_for_non_existent_stream_errors(
    basin: &SharedS2Basin,
) -> Result<(), S2Error> {
    let stream = basin.stream(unique_stream_name());

    let session = stream.append_session(AppendSessionConfig::new());

    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "lorem",
    )?])?);

    let result = session.submit(input).await?.await;

    assert_matches!(result, Err(S2Error::Server(err)) => {
        assert_eq!(err.code, "stream_not_found");
    });

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn producer_for_non_existent_stream_errors(basin: &SharedS2Basin) -> Result<(), S2Error> {
    let stream = basin.stream(unique_stream_name());

    let producer = stream.producer(
        ProducerConfig::new().with_batching(BatchingConfig::new().with_max_batch_records(10)?),
    );
    let num_records = 2000;

    let mut tickets = Vec::with_capacity(num_records);
    for i in 0..num_records {
        match producer
            .submit(AppendRecord::new(format!("record-{i}"))?)
            .await
        {
            Ok(ticket) => tickets.push(ticket),
            Err(S2Error::Server(err)) => {
                assert_eq!(err.code, "stream_not_found");
            }
            Err(e) => return Err(e),
        }
    }

    for ticket in tickets {
        let result = ticket.await;
        assert_matches!(result, Err(S2Error::Server(err)) => {
            assert_eq!(err.code, "stream_not_found");
        });
    }

    Ok(())
}
