mod common;

use std::time::Duration;

use assert_matches::assert_matches;
use common::{S2Stream, SharedS2Basin, s2, s2_config, unique_basin_name, unique_stream_name};
use s2_sdk::{
    append_session::AppendSessionConfig, error::*, producer::ProducerConfig,
    read_session::ReadSessionConfig, types::*,
};
use test_context::test_context;

fn now_millis() -> u64 {
    Timestamp::now().as_millisecond() as u64
}

fn past_millis(offset_ms: u64) -> u64 {
    now_millis().saturating_sub(offset_ms)
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_and_check_tail(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(stream.check_tail().await?.seq_num, 0);

    let ack1 = stream.append(AppendRecord::new("lorem")?).await?;
    assert_eq!(ack1.start.seq_num, 0);
    assert_eq!(ack1.end.seq_num, 1);
    assert_eq!(ack1.tail.seq_num, 1);
    assert_eq!(stream.check_tail().await?.seq_num, 1);

    let ack2 = stream.append(AppendRecord::new("ipsum")?).await?;
    assert_eq!(ack2.start.seq_num, 1);
    assert_eq!(ack2.end.seq_num, 2);

    let ack3 = stream
        .append(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("dolor")?,
            AppendRecord::new("sit")?,
        ])?))
        .await?;
    assert_eq!(ack3.start.seq_num, 2);
    assert_eq!(ack3.end.seq_num, 4);
    assert_eq!(stream.check_tail().await?.seq_num, 4);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_record_shapes(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("")?,
        AppendRecord::new("lorem")?.with_headers([Header::new("key1", "value1")])?,
        AppendRecord::new("ipsum")?
            .with_headers([Header::new("key2", ""), Header::new("key3", "value3")])?,
        AppendRecord::new("dolor")?,
    ])?);

    let ack = stream.append(input).await?;
    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 4);

    let batch = stream
        .read(ReadInput::new().with_start(ReadStart::SeqNum(0)))
        .await?;
    assert_eq!(batch.records.len(), 4);
    assert!(batch.records[0].body.is_empty());
    assert!(batch.records[0].headers.is_empty());
    assert_eq!(
        batch.records[1].headers,
        vec![Header::new("key1", "value1")]
    );
    assert_eq!(
        batch.records[2].headers,
        vec![Header::new("key2", ""), Header::new("key3", "value3")]
    );
    assert!(batch.records[3].headers.is_empty());

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_match_seq_num(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    let ack1 = stream
        .append(
            AppendInput::new(AppendRecordBatch::try_from_iter([
                AppendRecord::new("lorem")?,
                AppendRecord::new("ipsum")?,
            ])?)
            .with_match_seq_num(0),
        )
        .await?;
    assert_eq!(ack1.start.seq_num, 0);
    assert_eq!(ack1.end.seq_num, 2);

    let ack2 = stream
        .append(
            AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
                "dolor",
            )?])?)
            .with_match_seq_num(2),
        )
        .await?;
    assert_eq!(ack2.start.seq_num, 2);
    assert_eq!(ack2.end.seq_num, 3);

    // Unary mismatch -> SeqNumMismatchError(3).
    let unary_err = stream
        .append(
            AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
                "stale",
            )?])?)
            .with_match_seq_num(0),
        )
        .await;
    assert_matches!(
        unary_err,
        Err(AppendError::SeqNumMismatch(SeqNumMismatchError {
            assignable_seq_num: 3,
            ..
        }))
    );

    // S2S session mismatch -> AppendSessionError::SeqNumMismatch(3).
    let session = stream.append_session(AppendSessionConfig::new())?;
    let session_err = session
        .submit(
            AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
                "stale-s2s",
            )?])?)
            .with_match_seq_num(0),
        )
        .await?
        .await;
    assert_matches!(
        session_err,
        Err(AppendSessionError::SeqNumMismatch(SeqNumMismatchError {
            assignable_seq_num: 3,
            ..
        }))
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_fencing_token(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    let token_1 = FencingToken::generate(30).expect("valid fencing token");
    let ack = stream.append(CommandRecord::fence(token_1.clone())).await?;
    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1);

    // Matching token succeeds.
    let ack = stream
        .append(
            AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
                "fenced",
            )?])?)
            .with_fencing_token(token_1.clone()),
        )
        .await?;
    assert_eq!(ack.start.seq_num, 1);
    assert_eq!(ack.end.seq_num, 2);

    // Unary mismatched token fails with FencingTokenMismatchError.
    let token_2 = FencingToken::generate(30).expect("valid fencing token");
    let unary_err = stream
        .append(
            AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
                "wrong",
            )?])?)
            .with_fencing_token(token_2.clone()),
        )
        .await;
    assert_matches!(
        unary_err,
        Err(AppendError::FencingTokenMismatch(FencingTokenMismatchError {
            current_fencing_token,
            ..
        })) => {
            assert_eq!(current_fencing_token, token_1);
        }
    );

    // S2S session mismatched token fails with AppendSessionError::FencingTokenMismatch.
    let session = stream.append_session(AppendSessionConfig::new())?;
    let session_err = session
        .submit(
            AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
                "wrong-s2s",
            )?])?)
            .with_fencing_token(token_2),
        )
        .await?
        .await;
    assert_matches!(
        session_err,
        Err(AppendSessionError::FencingTokenMismatch(FencingTokenMismatchError {
            current_fencing_token,
            ..
        })) => {
            assert_eq!(current_fencing_token, token_1);
        }
    );

    // Clearing the fencing token allows subsequent unfenced appends.
    let clear_token: FencingToken = "".parse().expect("valid empty fencing token");
    let ack = stream.append(CommandRecord::fence(clear_token)).await?;
    assert_eq!(ack.start.seq_num, 2);
    let ack = stream.append(AppendRecord::new("unfenced")?).await?;
    assert_eq!(ack.start.seq_num, 3);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_invalid_command_headers_error(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    for headers in [
        vec![Header::new("", "not-a-command")],
        vec![Header::new("", "fence"), Header::new("extra", "value")],
    ] {
        let record = AppendRecord::new("lorem")?.with_headers(headers)?;
        let result = stream
            .append(AppendInput::new(AppendRecordBatch::try_from_iter([
                record,
            ])?))
            .await;
        assert_matches!(
            result,
            Err(AppendError::Server(ServerError { code, .. })) => {
                assert_eq!(code.as_deref(), Some("invalid"));
            }
        );
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_trim_commands(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    let _ = stream
        .append(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("record-1")?,
            AppendRecord::new("record-2")?,
            AppendRecord::new("record-3")?,
        ])?))
        .await?;

    let ack1 = stream.append(CommandRecord::trim(2)).await?;
    assert!(ack1.end.seq_num > 0);

    let ack2 = stream.append(CommandRecord::trim(999_999)).await?;
    assert!(ack2.end.seq_num > ack1.end.seq_num);

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn append_timestamping_policies(
    basin: &SharedS2Basin,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. ClientRequire rejects missing timestamps.
    let req_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(req_name.clone()).with_config(
            StreamConfig::new().with_timestamping(
                TimestampingConfig::new().with_mode(TimestampingMode::ClientRequire),
            ),
        ))
        .await?;
    let err = basin
        .stream(req_name.clone())
        .append(AppendRecord::new("lorem")?)
        .await;
    assert_matches!(
        err,
        Err(AppendError::Server(ServerError { code, .. })) => {
            assert_eq!(code.as_deref(), Some("invalid"));
        }
    );
    basin.delete_stream(req_name).await?;

    // 2. uncapped=false caps future timestamps, and past timestamps adjust monotonically.
    let capped_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(capped_name.clone()).with_config(
            StreamConfig::new().with_timestamping(TimestampingConfig::new().with_uncapped(false)),
        ))
        .await?;
    let capped = basin.stream(capped_name.clone());
    let future = now_millis() + 3_600_000;
    let ack_future = capped
        .append(AppendRecord::new("future")?.with_timestamp(future))
        .await?;
    assert!(ack_future.start.timestamp < future);

    let ack_past = capped
        .append(AppendRecord::new("past")?.with_timestamp(past_millis(10_000)))
        .await?;
    assert!(ack_past.start.timestamp >= ack_future.end.timestamp);
    basin.delete_stream(capped_name).await?;

    // 3. uncapped=true preserves future timestamps verbatim.
    let uncapped_name = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(uncapped_name.clone()).with_config(
            StreamConfig::new().with_timestamping(TimestampingConfig::new().with_uncapped(true)),
        ))
        .await?;
    let future = now_millis() + 3_600_000;
    let ack = basin
        .stream(uncapped_name.clone())
        .append(AppendRecord::new("future")?.with_timestamp(future))
        .await?;
    assert_eq!(ack.start.timestamp, future);
    basin.delete_stream(uncapped_name).await?;

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_limits(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?,
        AppendRecord::new("ipsum")?,
        AppendRecord::new("dolor")?,
        AppendRecord::new("sit")?,
    ])?);
    let r0_bytes = input.records()[0].metered_bytes() as u64;
    let r12_bytes =
        (input.records()[1].metered_bytes() + input.records()[2].metered_bytes()) as u64;
    let total_bytes = input.metered_bytes() as u64;

    let ack = stream.append(input).await?;
    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 4);

    // Unbounded read returns all 4 records.
    let all = stream
        .read(ReadInput::new().with_start(ReadStart::SeqNum(0)))
        .await?;
    assert_eq!(all.records.len(), 4);

    // Count limits: zero, partial from offset, exact, and exceeds.
    let zero_count = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(0))
                .with_count(0),
        )
        .await?;
    assert!(zero_count.records.is_empty());

    let partial_count = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(1))
                .with_count(2),
        )
        .await?;
    assert_eq!(partial_count.records.len(), 2);
    assert_eq!(partial_count.records[0].seq_num, 1);
    assert_eq!(partial_count.records[0].body, "ipsum");
    assert_eq!(partial_count.records[1].seq_num, 2);
    assert_eq!(partial_count.records[1].body, "dolor");

    let exact_count = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(0))
                .with_count(4),
        )
        .await?;
    assert_eq!(exact_count.records.len(), 4);

    let exceeds_count = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(0))
                .with_count(10),
        )
        .await?;
    assert_eq!(exceeds_count.records.len(), 4);

    // Bytes limits: zero, exact single record, partial from offset, partial from start, exceeds.
    let zero_bytes = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(0))
                .with_bytes(0),
        )
        .await?;
    assert!(zero_bytes.records.is_empty());

    let exact_bytes = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(0))
                .with_bytes(r0_bytes),
        )
        .await?;
    assert_eq!(exact_bytes.records.len(), 1);
    assert_eq!(exact_bytes.records[0].body, "lorem");

    let offset_bytes = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(1))
                .with_bytes(r12_bytes),
        )
        .await?;
    assert_eq!(offset_bytes.records.len(), 2);
    assert_eq!(offset_bytes.records[0].seq_num, 1);
    assert_eq!(offset_bytes.records[1].seq_num, 2);

    let partial_bytes = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(0))
                .with_bytes(total_bytes - 5),
        )
        .await?;
    assert_eq!(partial_bytes.records.len(), 3);

    let exceeds_bytes = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(0))
                .with_bytes(1000),
        )
        .await?;
    assert_eq!(exceeds_bytes.records.len(), 4);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_count_over_max_clamps(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    let records = (0..1000)
        .map(|i| AppendRecord::new(format!("record-{i}")))
        .collect::<Result<Vec<_>, _>>()?;
    let ack = stream
        .append(AppendInput::new(AppendRecordBatch::try_from_iter(records)?))
        .await?;
    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.end.seq_num, 1000);

    let records = (0..5)
        .map(|i| AppendRecord::new(format!("tail-{i}")))
        .collect::<Result<Vec<_>, _>>()?;
    stream
        .append(AppendInput::new(AppendRecordBatch::try_from_iter(records)?))
        .await?;

    let batch = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(0))
                .with_count(2000),
        )
        .await?;
    assert_eq!(batch.records.len(), 1000);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_with_bytes_over_max_clamps(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    let body = "a".repeat(700_000);
    stream.append(AppendRecord::new(body.clone())?).await?;
    stream.append(AppendRecord::new(body)?).await?;

    let batch = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(0))
                .with_bytes(2 * 1024 * 1024),
        )
        .await?;
    let read_bytes: usize = batch.records.iter().map(|r| r.metered_bytes()).sum();
    assert!(read_bytes <= 1024 * 1024);
    assert_eq!(batch.records.len(), 1);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_from_tail_offset_variants(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = stream
        .append(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("record-0")?,
            AppendRecord::new("record-1")?,
            AppendRecord::new("record-2")?,
            AppendRecord::new("record-3")?,
            AppendRecord::new("record-4")?,
        ])?))
        .await?;

    let result = stream
        .read(ReadInput::new().with_start(ReadStart::TailOffset(0)))
        .await;
    assert_matches!(
        result,
        Err(ReadError::ReadUnwritten(ReadUnwrittenError {
            tail: StreamPosition { seq_num: 5, .. },
            ..
        }))
    );

    let batch = stream
        .read(ReadInput::new().with_start(ReadStart::TailOffset(3)))
        .await?;
    assert_eq!(batch.records.len(), 3);
    assert_eq!(batch.records[0].seq_num, 2);

    let batch = stream
        .read(ReadInput::new().with_start(ReadStart::TailOffset(999)))
        .await?;
    assert_eq!(batch.records[0].seq_num, 0);

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_timestamp_bounds(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    let base = past_millis(10_000);
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([
        AppendRecord::new("lorem")?.with_timestamp(base),
        AppendRecord::new("ipsum")?.with_timestamp(base + 1),
        AppendRecord::new("dolor")?.with_timestamp(base + 2),
        AppendRecord::new("sit")?.with_timestamp(base + 3),
    ])?);
    let bytes_for_one = (input.records()[1].metered_bytes() + 5) as u64;

    let ack = stream.append(input).await?;
    assert_eq!(ack.start.seq_num, 0);
    assert_eq!(ack.start.timestamp, base);
    assert_eq!(ack.end.seq_num, 4);
    assert_eq!(ack.end.timestamp, base + 3);

    // Start from timestamp.
    let batch = stream
        .read(ReadInput::new().with_start(ReadStart::Timestamp(base + 1)))
        .await?;
    assert_eq!(batch.records.len(), 3);
    assert_eq!(batch.records[0].seq_num, 1);
    assert_eq!(batch.records[0].timestamp, base + 1);
    assert_eq!(batch.records[2].seq_num, 3);
    assert_eq!(batch.records[2].timestamp, base + 3);

    // Timestamp + count limit.
    let by_count = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::Timestamp(base + 2))
                .with_count(1),
        )
        .await?;
    assert_eq!(by_count.records.len(), 1);
    assert_eq!(by_count.records[0].seq_num, 2);

    // Timestamp + bytes limit.
    let by_bytes = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::Timestamp(base + 1))
                .with_bytes(bytes_for_one),
        )
        .await?;
    assert_eq!(by_bytes.records.len(), 1);
    assert_eq!(by_bytes.records[0].seq_num, 1);

    // Exclusive `until` upper bound.
    let until = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(0))
                .with_until(base + 2),
        )
        .await?;
    assert_eq!(until.records.len(), 2);
    assert_eq!(until.records[0].timestamp, base);
    assert_eq!(until.records[1].timestamp, base + 1);

    // Future start timestamp returns ReadUnwritten.
    let future = stream
        .read(ReadInput::new().with_start(ReadStart::Timestamp(base + 100)))
        .await;
    assert_matches!(future, Err(ReadError::ReadUnwritten(ReadUnwrittenError { tail, .. })) => {
        assert_eq!(tail.seq_num, 4);
        assert_eq!(tail.timestamp, base + 3);
    });

    // start timestamp >= until returns server invalid error.
    let bad_bounds = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::Timestamp(base + 2))
                .with_until(base + 2),
        )
        .await;
    assert_matches!(
        bad_bounds,
        Err(ReadError::Server(ServerError { code, .. })) => {
            assert_eq!(code.as_deref(), Some("invalid"));
        }
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_empty_and_beyond_tail_unary(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    // Empty stream: without wait -> ReadUnwritten(0, 0); with wait -> empty batch.
    assert_matches!(
        stream.read(ReadInput::new()).await,
        Err(ReadError::ReadUnwritten(ReadUnwrittenError {
            tail: StreamPosition {
                seq_num: 0,
                timestamp: 0,
                ..
            },
            ..
        }))
    );
    let waited_empty = stream
        .read(ReadInput::new().with_wait(Duration::from_secs(1))?)
        .await?;
    assert!(waited_empty.records.is_empty());

    // Beyond tail: without wait (with or without clamp) -> ReadUnwritten(1); with clamp + wait ->
    // empty batch.
    let ack = stream.append(AppendRecord::new("lorem")?).await?;
    assert_eq!(ack.end.seq_num, 1);

    for clamp in [false, true] {
        let res = stream
            .read(
                ReadInput::new()
                    .with_start(ReadStart::SeqNum(10))
                    .with_clamp(clamp),
            )
            .await;
        assert_matches!(
            res,
            Err(ReadError::ReadUnwritten(ReadUnwrittenError {
                tail: StreamPosition { seq_num: 1, .. },
                ..
            }))
        );
    }

    let clamped_wait = stream
        .read(
            ReadInput::new()
                .with_start(ReadStart::SeqNum(10))
                .with_clamp(true)
                .with_wait(Duration::from_secs(1))?,
        )
        .await?;
    assert!(clamped_wait.records.is_empty());

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_session_beyond_tail_and_clamp(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    let ack = stream.append(AppendRecord::new("lorem")?).await?;
    assert_eq!(ack.end.seq_num, 1);

    // Without clamp -> ReadUnwritten(1).
    let mut unclamped = stream.read_session(
        ReadInput::new().with_start(ReadStart::SeqNum(10)),
        ReadSessionConfig::default(),
    )?;
    let err = unclamped
        .next()
        .await
        .expect("should yield error")
        .expect_err("should be err");
    assert_matches!(
        err,
        ReadSessionError::ReadUnwritten(ReadUnwrittenError {
            tail: StreamPosition { seq_num: 1, .. },
            ..
        })
    );

    // With clamp -> clamps to tail and stays open waiting for new records.
    let mut clamped = stream.read_session(
        ReadInput::new()
            .with_start(ReadStart::SeqNum(10))
            .with_clamp(true),
        ReadSessionConfig::default(),
    )?;
    assert_eq!(clamped.next_seq_num(), None);
    let result = tokio::time::timeout(Duration::from_secs(1), clamped.next()).await;
    assert_matches!(result, Err(tokio::time::error::Elapsed { .. }));
    assert_eq!(clamped.next_seq_num(), Some(ack.tail.seq_num));

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn read_session_reports_caught_up_after_tail_delivery(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    let ack = stream
        .append(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("first")?,
            AppendRecord::new("second")?,
        ])?))
        .await?;
    let mut session = stream.read_session(
        ReadInput::new().with_start(ReadStart::TailOffset(2)),
        ReadSessionConfig::default(),
    )?;
    let mut caught_up = session.caught_up();
    let mut seq_nums = Vec::new();

    assert!(!session.is_caught_up());
    assert_eq!(session.next_seq_num(), None);
    let caught_up_tail = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                tail = &mut caught_up => break tail,
                record = session.next() => {
                    let record = record.expect("session should reach the tail")?;
                    seq_nums.push(record.seq_num);
                }
            }
        }
    })
    .await
    .expect("session should reach the tail within 30 seconds")?;

    assert!(session.is_caught_up());
    assert_eq!(seq_nums, [ack.tail.seq_num - 2, ack.tail.seq_num - 1]);
    assert_eq!(caught_up_tail, ack.tail);
    assert_eq!(session.next_seq_num(), Some(ack.tail.seq_num));

    let next_ack = stream.append(AppendRecord::new("third")?).await?;
    let next_record = tokio::time::timeout(Duration::from_secs(30), session.next())
        .await
        .expect("session should keep reading after catching up")
        .expect("session should remain open")?;

    assert_eq!(next_record.seq_num, ack.tail.seq_num);
    assert!(session.is_caught_up());
    assert_eq!(session.last_observed_tail(), Some(next_ack.tail));

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn nonexistent_stream_errors(
    basin: &SharedS2Basin,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream = basin.stream(unique_stream_name());

    assert_matches!(
        stream.check_tail().await,
        Err(ReadError::Server(ServerError { code, .. })) => {
            assert_eq!(code.as_deref(), Some("stream_not_found"));
        }
    );
    assert_matches!(
        stream.append(AppendRecord::new("lorem")?).await,
        Err(AppendError::Server(ServerError { code, .. })) => {
            assert_eq!(code.as_deref(), Some("stream_not_found"));
        }
    );
    assert_matches!(
        stream.read(ReadInput::new()).await,
        Err(ReadError::Server(ServerError { code, .. })) => {
            assert_eq!(code.as_deref(), Some("stream_not_found"));
        }
    );

    let session = stream.append_session(AppendSessionConfig::new())?;
    let session_res = match session.submit(AppendRecord::new("lorem")?).await {
        Ok(ticket) => ticket.await,
        Err(e) => Err(e),
    };
    match session_res {
        Err(AppendSessionError::Server(err)) => {
            assert_eq!(err.code.as_deref(), Some("stream_not_found"));
        }
        Err(AppendSessionError::SessionClosed(closed)) => {
            assert_matches!(
                closed.failure(),
                Some(AppendSessionError::Server(err)) => {
                    assert_eq!(err.code.as_deref(), Some("stream_not_found"));
                }
            );
        }
        other => panic!("unexpected result: {other:?}"),
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn append_session_and_producer_roundtrip(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    // Pipelined AppendSession batches + close().
    let session = stream.append_session(AppendSessionConfig::default())?;
    let t1 = session
        .submit(AppendInput::new(AppendRecordBatch::try_from_iter([
            AppendRecord::new("lorem")?,
            AppendRecord::new("ipsum")?,
        ])?))
        .await?;
    let t2 = session.submit(AppendRecord::new("dolor")?).await?;
    let t3 = session.submit(AppendRecord::new("sit")?).await?;
    session.close().await?;

    let ack1 = t1.await?;
    let ack2 = t2.await?;
    let ack3 = t3.await?;
    assert_eq!((ack1.start.seq_num, ack1.end.seq_num), (0, 2));
    assert_eq!((ack2.start.seq_num, ack2.end.seq_num), (2, 3));
    assert_eq!((ack3.start.seq_num, ack3.end.seq_num), (3, 4));

    // Producer co-batching + flush() + close().
    let producer = stream.producer(
        ProducerConfig::new()
            .with_match_seq_num(4)
            .with_linger(Duration::from_secs(60)),
    )?;
    let p1 = producer.submit(AppendRecord::new("a")?).await?;
    let p2 = producer.submit(AppendRecord::new("b")?).await?;
    let p3 = producer.submit(AppendRecord::new("c")?).await?;
    producer.flush().await?;

    let pa1 = p1.await?;
    let pa2 = p2.await?;
    let pa3 = p3.await?;
    assert_eq!((pa1.seq_num, pa2.seq_num, pa3.seq_num), (4, 5, 6));
    assert_eq!(pa1.batch, pa2.batch);
    assert_eq!(pa2.batch, pa3.batch);

    let p4 = producer.submit(AppendRecord::new("d")?).await?;
    producer.close().await?;
    assert_eq!(p4.await?.seq_num, 7);

    Ok(())
}

#[test_context(SharedS2Basin)]
#[tokio_shared_rt::test(shared)]
async fn compression_roundtrip(basin: &SharedS2Basin) -> Result<(), Box<dyn std::error::Error>> {
    for compression in [Compression::Gzip, Compression::Zstd] {
        let client = s2_sdk::S2::new(s2_config(compression).expect("valid S2 config"))?;
        let compressed_basin = client.basin(basin.basin_name().clone());

        let stream_name = unique_stream_name();
        basin
            .create_stream(CreateStreamInput::new(stream_name.clone()))
            .await?;
        let stream = compressed_basin.stream(stream_name.clone());

        // Unary roundtrip with payloads above 1 KiB.
        let ack = stream
            .append(AppendInput::new(AppendRecordBatch::try_from_iter([
                AppendRecord::new("s".repeat(2048))?,
                AppendRecord::new("2".repeat(2048))?,
            ])?))
            .await?;
        assert_eq!((ack.start.seq_num, ack.end.seq_num), (0, 2));

        let batch = stream
            .read(ReadInput::new().with_start(ReadStart::SeqNum(0)))
            .await?;
        assert_eq!(batch.records.len(), 2);

        // S2S session roundtrip with payload >= 1 KiB compression threshold.
        let session = stream.append_session(AppendSessionConfig::default())?;
        let ticket = session
            .submit(AppendRecord::new("s2".repeat(10240))?)
            .await?;
        session.close().await?;
        let ack = ticket.await?;
        assert_eq!((ack.start.seq_num, ack.end.seq_num), (2, 3));

        let mut records = stream.read_session(
            ReadInput::new().with_start(ReadStart::SeqNum(2)),
            ReadSessionConfig::default(),
        )?;
        let record = records.next().await.expect("should have record")?;
        assert_eq!(record.body.len(), 20480);

        basin.delete_stream(stream_name).await?;
    }

    Ok(())
}

#[tokio::test]
async fn basin_default_and_auto_create_stream_config() -> Result<(), Box<dyn std::error::Error>> {
    let s2 = s2();
    let basin_name = unique_basin_name();
    let default_stream_config = StreamConfig::new()
        .with_storage_class("standard")
        .with_retention_policy(RetentionPolicy::Age(7200))
        .with_delete_on_empty(DeleteOnEmptyConfig::new().with_min_age(Duration::from_secs(600))?);
    s2.create_basin(
        CreateBasinInput::new(basin_name.clone()).with_config(
            BasinConfig::new()
                .with_default_stream_config(default_stream_config)
                .with_create_stream_on_append(true)
                .with_create_stream_on_read(true),
        ),
    )
    .await?;
    let basin = s2.basin(basin_name.clone());

    // 1. Explicit create_stream inherits basin default_stream_config.
    let existing_stream = unique_stream_name();
    basin
        .create_stream(CreateStreamInput::new(existing_stream.clone()))
        .await?;
    let inherited = basin.get_stream_config(existing_stream.clone()).await?;
    assert_eq!(inherited.storage_class(), Some("standard"));
    assert_eq!(
        inherited.retention_policy(),
        Some(&RetentionPolicy::Age(7200))
    );
    assert_eq!(
        inherited.delete_on_empty().map(|d| d.min_age()),
        Some(Duration::from_secs(600))
    );

    let override_config = StreamConfig::new()
        .with_retention_policy(RetentionPolicy::Age(3600))
        .with_delete_on_empty(DeleteOnEmptyConfig::new().with_min_age(Duration::from_secs(300))?);

    // 2. Unary append_with_stream_config applies override when auto-creating a stream.
    let unary_stream = unique_stream_name();
    basin
        .stream(unary_stream.clone())
        .append_with_stream_config(AppendRecord::new("hello")?, override_config.clone())
        .await?;
    let config = basin.get_stream_config(unary_stream).await?;
    assert_eq!(config.storage_class(), Some("standard"));
    assert_eq!(config.retention_policy(), Some(&RetentionPolicy::Age(3600)));
    assert_eq!(
        config.delete_on_empty().map(|d| d.min_age()),
        Some(Duration::from_secs(300))
    );

    // 3. Producer with_stream_config applies override when auto-creating a stream.
    let session_stream = unique_stream_name();
    let producer = basin
        .stream(session_stream.clone())
        .producer(ProducerConfig::new().with_stream_config(override_config.clone()))?;
    producer.submit(AppendRecord::new("hello")?).await?.await?;
    producer.close().await?;
    let config = basin.get_stream_config(session_stream).await?;
    assert_eq!(config.retention_policy(), Some(&RetentionPolicy::Age(3600)));
    assert_eq!(
        config.delete_on_empty().map(|d| d.min_age()),
        Some(Duration::from_secs(300))
    );

    // 4. append_with_stream_config on an existing stream leaves its config unchanged.
    basin
        .stream(existing_stream.clone())
        .append_with_stream_config(AppendRecord::new("hello")?, override_config.clone())
        .await?;
    let after = basin.get_stream_config(existing_stream).await?;
    assert_eq!(after, inherited);
    assert_ne!(after.retention_policy(), Some(&RetentionPolicy::Age(3600)));

    // 5. read_session with_stream_config applies override when auto-creating a stream.
    let read_stream = unique_stream_name();
    let mut session = basin.stream(read_stream.clone()).read_session(
        ReadInput::new().with_stream_config(override_config),
        ReadSessionConfig::default(),
    )?;
    let mut caught_up = session.caught_up();
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            res = &mut caught_up => res.map(|_| ()),
            item = session.next() => match item {
                Some(Err(e)) => Err(e),
                _ => Ok(()),
            },
        }
    })
    .await
    .expect("read session should connect and create stream")?;
    let config = basin.get_stream_config(read_stream).await?;
    assert_eq!(config.retention_policy(), Some(&RetentionPolicy::Age(3600)));

    s2.delete_basin(basin_name).await?;
    Ok(())
}
