mod bench;
mod cli;
mod config;
mod error;
mod lite;
mod ops;
mod record_format;
mod types;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::{pin::Pin, time::Duration};

use clap::Parser;
use cli::{Cli, Command, ConfigCommand, ListBasinsArgs, ListStreamsArgs};
use colored::Colorize;
use config::{
    ConfigKey, load_cli_config, load_config_file, sdk_config, set_config_value, unset_config_value,
};
use error::{CliError, OpKind};
use futures::{Stream, StreamExt, TryStreamExt};
use json_to_table::json_to_table;
use record_format::{
    JsonBase64Formatter, JsonFormatter, RecordFormat, RecordParser, RecordWriter, TextFormatter,
};
use s2_sdk::{
    S2,
    types::{
        AppendRetryPolicy, BasinState, CreateStreamInput, DeleteOnEmptyConfig, DeleteStreamInput,
        MeteredBytes, Metric, RetentionPolicy, RetryConfig, StreamConfig as SdkStreamConfig,
        StreamName, TimestampingConfig, TimestampingMode,
    },
};
use strum::VariantNames;
use tabled::{Table, Tabled};
use tokio::{io::AsyncWriteExt, select};
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};
use types::{AccessTokenInfo, BasinConfig, S2BasinAndMaybeStreamUri, StreamConfig};

#[tokio::main]
async fn main() -> miette::Result<()> {
    miette::set_panic_hook();
    run().await?;
    Ok(())
}

async fn run() -> Result<(), CliError> {
    let commands = Cli::try_parse().unwrap_or_else(|e| {
        // Customize error message for metric commands to say "metric" instead of "subcommand"
        let msg = e.to_string();
        if msg.contains("requires a subcommand") && msg.contains("get-") && msg.contains("-metrics")
        {
            let msg = msg
                .replace("requires a subcommand", "requires a metric")
                .replace("[subcommands:", "[metrics:");
            eprintln!("{msg}");
            std::process::exit(2);
        }
        e.exit()
    });

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .pretty()
                .with_span_events(FmtSpan::NEW)
                .compact()
                .with_writer(std::io::stderr),
        )
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Command::Config(config_cmd) = &commands.command {
        match config_cmd {
            ConfigCommand::List => {
                let config = load_config_file()?;
                for k in ConfigKey::VARIANTS {
                    if let Ok(key) = k.parse::<ConfigKey>()
                        && let Some(v) = config.get(key)
                    {
                        println!("{} = {}", k, v);
                    }
                }
            }
            ConfigCommand::Get { key } => {
                let config = load_config_file()?;
                if let Some(v) = config.get(*key) {
                    println!("{}", v);
                }
            }
            ConfigCommand::Set { key, value } => {
                let saved_path = set_config_value(*key, value.clone())?;
                eprintln!("{}", format!("✓ {} set", key).green().bold());
                eprintln!(
                    "  Configuration saved to: {}",
                    saved_path.display().to_string().cyan()
                );
            }
            ConfigCommand::Unset { key } => {
                let saved_path = unset_config_value(*key)?;
                eprintln!("{}", format!("✓ {} unset", key).green().bold());
                eprintln!(
                    "  Configuration saved to: {}",
                    saved_path.display().to_string().cyan()
                );
            }
        }
        return Ok(());
    }

    if let Command::Lite(args) = commands.command {
        return lite::run(args).await;
    }

    let cli_config = load_cli_config()?;
    let sdk_config = sdk_config(&cli_config)?;
    let s2 = S2::new(sdk_config.clone()).map_err(CliError::SdkInit)?;

    match commands.command {
        Command::Config(..) | Command::Lite(..) => unreachable!(),

        Command::Ls(args) => {
            if let Some(ref uri) = args.uri {
                // List streams
                let S2BasinAndMaybeStreamUri {
                    basin,
                    stream: uri_prefix,
                } = uri.clone();

                if uri_prefix.is_some() && args.prefix.is_some() {
                    return Err(CliError::InvalidArgs(miette::miette!(
                        help = "Make sure to provide the prefix once either using '--prefix' opt or in URI like 's2://basin-name/prefix'",
                        "Multiple prefixes provided"
                    )));
                }

                let list_streams_args = ListStreamsArgs {
                    uri: S2BasinAndMaybeStreamUri {
                        basin: basin.clone(),
                        stream: uri_prefix,
                    },
                    prefix: args
                        .prefix
                        .clone()
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|e| CliError::InvalidArgs(miette::miette!("{e}")))?,
                    start_after: args
                        .start_after
                        .clone()
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|e| CliError::InvalidArgs(miette::miette!("{e}")))?,
                    limit: args.limit,
                    no_auto_paginate: args.no_auto_paginate,
                };

                let mut streams = ops::list_streams(&s2, list_streams_args).await?;
                while let Some(stream_info) = streams.try_next().await? {
                    println!(
                        "s2://{}/{} {}",
                        basin,
                        stream_info.name,
                        stream_info.created_at.to_string().green(),
                    );
                }
            } else {
                // List basins
                let list_basins_args = ListBasinsArgs {
                    prefix: args
                        .prefix
                        .clone()
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|e| CliError::InvalidArgs(miette::miette!("{e}")))?,
                    start_after: args
                        .start_after
                        .clone()
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|e| CliError::InvalidArgs(miette::miette!("{e}")))?,
                    limit: args.limit,
                    no_auto_paginate: args.no_auto_paginate,
                };

                let mut basins = ops::list_basins(&s2, list_basins_args).await?;
                while let Some(basin_info) = basins.try_next().await? {
                    println!(
                        "{} {}",
                        basin_info.name,
                        format_basin_state(basin_info.state)
                    );
                }
            }
        }

        Command::ListBasins(args) => {
            let mut basins = ops::list_basins(&s2, args).await?;
            while let Some(basin_info) = basins.try_next().await? {
                println!(
                    "{} {}",
                    basin_info.name,
                    format_basin_state(basin_info.state)
                );
            }
        }

        Command::CreateBasin(args) => {
            let info = ops::create_basin(&s2, args).await?;

            let message = match info.state {
                BasinState::Creating => "✓ Basin creation requested".yellow().bold(),
                BasinState::Active => "✓ Basin created".green().bold(),
                BasinState::Deleting => "Basin is being deleted".red().bold(),
            };
            eprintln!("{message}");
        }

        Command::DeleteBasin { basin } => {
            ops::delete_basin(&s2, &basin.into()).await?;
            eprintln!("{}", "✓ Basin deletion requested".green().bold());
        }

        Command::GetBasinConfig { basin } => {
            let basin_config: BasinConfig = ops::get_basin_config(&s2, &basin.into()).await?.into();
            println!("{}", json_to_table(&serde_json::to_value(&basin_config)?));
        }

        Command::ReconfigureBasin(args) => {
            let config = ops::reconfigure_basin(&s2, args).await?;

            eprintln!("{}", "✓ Basin reconfigured".green().bold());
            println!("{}", json_to_table(&serde_json::to_value(&config)?));
        }

        Command::ListAccessTokens(args) => {
            let mut tokens = ops::list_access_tokens(&s2, args).await?;
            while let Some(token_info) = tokens.try_next().await? {
                let info = AccessTokenInfo::from(token_info);
                println!("{}", json_to_table(&serde_json::to_value(&info)?));
            }
        }

        Command::IssueAccessToken(args) => {
            let token = ops::issue_access_token(&s2, args).await?;
            println!("{}", token);
        }

        Command::RevokeAccessToken { id } => {
            ops::revoke_access_token(&s2, id.clone()).await?;
            eprintln!(
                "{}",
                format!("✓ Access token '{}' revoked", id).green().bold()
            );
        }

        Command::GetAccountMetrics(args) => {
            let metrics = ops::get_account_metrics(&s2, args).await?;
            print_metrics(&metrics);
        }

        Command::GetBasinMetrics(args) => {
            let metrics = ops::get_basin_metrics(&s2, args).await?;
            print_metrics(&metrics);
        }

        Command::GetStreamMetrics(args) => {
            let metrics = ops::get_stream_metrics(&s2, args).await?;
            print_metrics(&metrics);
        }

        Command::ListStreams(args) => {
            let basin_name = args.uri.basin.clone();
            let mut streams = ops::list_streams(&s2, args).await?;
            while let Some(stream_info) = streams.try_next().await? {
                println!("s2://{}/{}", basin_name, stream_info.name);
            }
        }

        Command::CreateStream(args) => {
            ops::create_stream(&s2, args).await?;
            eprintln!("{}", "✓ Stream created".green().bold());
        }

        Command::DeleteStream { uri } => {
            ops::delete_stream(&s2, uri).await?;
            eprintln!("{}", "✓ Stream deletion requested".green().bold());
        }

        Command::GetStreamConfig { uri } => {
            let stream_config = ops::get_stream_config(&s2, uri).await?;
            let stream_config: StreamConfig = stream_config.into();
            println!("{}", json_to_table(&serde_json::to_value(&stream_config)?));
        }

        Command::ReconfigureStream(args) => {
            let config = ops::reconfigure_stream(&s2, args).await?;

            eprintln!("{}", "✓ Stream reconfigured".green().bold());
            println!("{}", json_to_table(&serde_json::to_value(&config)?));
        }

        Command::CheckTail { uri } => {
            let tail = ops::check_tail(&s2, uri).await?;
            println!("{}", format_position(tail.seq_num, tail.timestamp));
        }

        Command::Trim(args) => {
            let trim_point = args.trim_point;
            let out = ops::trim(&s2, args).await?;
            eprintln!(
                "{}",
                format!(
                    "✓ [APPENDED] trim to {} // tail: {}",
                    trim_point,
                    format_position(out.start.seq_num, out.start.timestamp)
                )
                .green()
                .bold()
            );
        }

        Command::Fence(args) => {
            let fencing_token = args.new_fencing_token.clone();
            let out = ops::fence(&s2, args).await?;
            eprintln!(
                "{}",
                format!(
                    "✓ [APPENDED] new fencing token \"{}\" // tail: {}",
                    fencing_token,
                    format_position(out.start.seq_num, out.start.timestamp)
                )
                .green()
                .bold()
            );
        }

        Command::Append(args) => {
            let records_in = args
                .input
                .reader()
                .await
                .map_err(|e| CliError::RecordReaderInit(e.to_string()))?;

            let record_stream: Pin<Box<dyn Stream<Item = _> + Send + Unpin>> = match args.format {
                RecordFormat::Text => Box::pin(TextFormatter::parse_records(records_in)),
                RecordFormat::Json => Box::pin(JsonFormatter::parse_records(records_in)),
                RecordFormat::JsonBase64 => {
                    Box::pin(JsonBase64Formatter::parse_records(records_in))
                }
            };

            let acks = ops::append(
                &s2,
                record_stream,
                args.uri,
                args.fencing_token,
                args.match_seq_num,
                *args.linger,
            );
            let mut acks = std::pin::pin!(acks);
            let mut last_printed_batch_end: Option<u64> = None;

            loop {
                select! {
                    ack = acks.next() => {
                        match ack {
                            Some(Ok(ack)) => {
                                if last_printed_batch_end.is_none_or(|end| end != ack.batch.end.seq_num) {
                                    last_printed_batch_end = Some(ack.batch.end.seq_num);
                                    eprintln!(
                                        "{}",
                                        format!(
                                            "✓ [APPENDED] {}..{} // tail: {}",
                                            ack.batch.start.seq_num,
                                            ack.batch.end.seq_num,
                                            format_position(ack.batch.tail.seq_num, ack.batch.tail.timestamp)
                                        )
                                        .green()
                                        .bold()
                                    );
                                }
                            }
                            Some(Err(e)) => {
                                return Err(e);
                            }
                            None => break, // Stream exhausted, all done
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("{}", "■ [ABORTED]".red().bold());
                        break;
                    }
                }
            }
        }

        Command::Read(args) => {
            let mut batches = ops::read(&s2, &args).await?;
            let mut writer = args
                .output
                .writer()
                .await
                .map_err(|e| CliError::RecordWrite(e.to_string()))?;

            loop {
                select! {
                    batch = batches.next() => {
                        match batch {
                            Some(Ok(batch)) => {
                                let num_records = batch.records.len();
                                let batch_len: usize = batch.records.iter().map(|r| r.metered_bytes()).sum();

                                let seq_range = match (batch.records.first(), batch.records.last()) {
                                    (Some(first), Some(last)) => first.seq_num..=last.seq_num,
                                    _ => continue,
                                };

                                eprintln!(
                                    "{}",
                                    format!(
                                        "⦿ {batch_len} bytes ({num_records} {} in range {seq_range:?})",
                                        if num_records == 1 { "record" } else { "records" }
                                    )
                                    .blue()
                                    .bold()
                                );

                                for record in &batch.records {
                                    write_record(record, &mut writer, args.format).await?;
                                    let skip_newline = matches!(args.format, RecordFormat::Text)
                                        && record.is_command_record();
                                    if !skip_newline {
                                        writer
                                            .write_all(b"\n")
                                            .await
                                            .map_err(|e| CliError::RecordWrite(e.to_string()))?;
                                    }
                                }

                                writer
                                    .flush()
                                    .await
                                    .map_err(|e| CliError::RecordWrite(e.to_string()))?;
                            }
                            Some(Err(e)) => {
                                return Err(CliError::op(OpKind::Read, e));
                            }
                            None => break,
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("{}", "■ [ABORTED]".red().bold());
                        break;
                    }
                }
            }
        }

        Command::Tail(args) => {
            let mut records = ops::tail(&s2, &args).await?;
            let mut writer = args
                .output
                .writer()
                .await
                .map_err(|e| CliError::RecordWrite(e.to_string()))?;

            loop {
                select! {
                    record = records.next() => {
                        match record {
                            Some(Ok(record)) => {
                                write_record(&record, &mut writer, args.format).await?;
                                writer
                                    .write_all(b"\n")
                                    .await
                                    .map_err(|e| CliError::RecordWrite(e.to_string()))?;
                                writer
                                    .flush()
                                    .await
                                    .map_err(|e| CliError::RecordWrite(e.to_string()))?;
                            }
                            Some(Err(e)) => {
                                return Err(e);
                            }
                            None => break,
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("{}", "■ [ABORTED]".red().bold());
                        break;
                    }
                }
            }
        }

        Command::Bench(args) => {
            let basin_name = args.basin.0.clone();
            let stream_name: StreamName = format!("bench/{}", uuid::Uuid::new_v4())
                .parse()
                .expect("valid stream name");

            eprintln!(
                "Creating temporary stream s2://{}/{} (storage class: {})",
                basin_name,
                stream_name,
                args.storage_class
                    .as_ref()
                    .map(|sc| format!("{:?}", sc))
                    .unwrap_or_else(|| "<default>".to_owned())
            );

            let mut stream_config = SdkStreamConfig::new()
                .with_retention_policy(RetentionPolicy::Age(3600))
                .with_delete_on_empty(
                    DeleteOnEmptyConfig::new().with_min_age(Duration::from_secs(60)),
                )
                .with_timestamping(
                    TimestampingConfig::new()
                        .with_mode(TimestampingMode::ClientRequire)
                        .with_uncapped(true),
                );
            stream_config.storage_class = args.storage_class.map(Into::into);

            let s2 = S2::new(sdk_config.clone().with_retry(
                RetryConfig::new().with_append_retry_policy(AppendRetryPolicy::NoSideEffects),
            ))
            .map_err(CliError::SdkInit)?;

            let basin = s2.basin(basin_name);
            basin
                .create_stream(
                    CreateStreamInput::new(stream_name.clone()).with_config(stream_config),
                )
                .await
                .map_err(|e| CliError::op(OpKind::Bench, e))?;

            eprintln!(
                "Running for {} targeting {} MiB/s with {} byte records, Ctrl+C to end early",
                args.duration, args.target_mibps, args.record_size,
            );

            bench::run(
                basin.stream(stream_name.clone()),
                args.record_size as usize,
                args.target_mibps,
                *args.duration,
                *args.catchup_delay,
            )
            .await?;

            basin
                .delete_stream(DeleteStreamInput::new(stream_name))
                .await
                .map_err(|e| CliError::op(OpKind::Bench, e))?;
        }
    }

    Ok(())
}

fn format_basin_state(state: BasinState) -> colored::ColoredString {
    match state {
        BasinState::Active => "active".green(),
        BasinState::Creating => "creating".yellow(),
        BasinState::Deleting => "deleting".red(),
    }
}

fn format_position(seq_num: u64, timestamp: u64) -> String {
    format!("{seq_num} @ {timestamp}")
}

async fn write_record(
    record: &s2_sdk::types::SequencedRecord,
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    format: RecordFormat,
) -> Result<(), CliError> {
    match format {
        RecordFormat::Text => {
            if record.is_command_record() {
                if let Some(header) = record.headers.first() {
                    let cmd_type = &header.value;
                    let cmd_desc = if cmd_type.as_ref() == b"fence" {
                        let fencing_token = String::from_utf8_lossy(&record.body);
                        format!("new fencing token \"{}\"", fencing_token)
                    } else if cmd_type.as_ref() == b"trim" {
                        let trim_point = if record.body.len() >= 8 {
                            u64::from_be_bytes(record.body[..8].try_into().unwrap_or_default())
                        } else {
                            0
                        };
                        format!("trim to {}", trim_point)
                    } else {
                        "unknown command".to_string()
                    };
                    eprintln!(
                        "{} // {}",
                        cmd_desc.bold(),
                        format_position(record.seq_num, record.timestamp)
                    );
                }
            } else {
                TextFormatter::write_record(record, writer)
                    .await
                    .map_err(|e| CliError::RecordWrite(e.to_string()))?;
            }
        }
        RecordFormat::Json => {
            JsonFormatter::write_record(record, writer)
                .await
                .map_err(|e| CliError::RecordWrite(e.to_string()))?;
        }
        RecordFormat::JsonBase64 => {
            JsonBase64Formatter::write_record(record, writer)
                .await
                .map_err(|e| CliError::RecordWrite(e.to_string()))?;
        }
    }
    Ok(())
}

fn format_timestamp(ts: u32) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let time = UNIX_EPOCH + Duration::from_secs(ts as u64);
    humantime::format_rfc3339_seconds(time).to_string()
}

fn format_unit(unit: s2_sdk::types::MetricUnit) -> &'static str {
    match unit {
        s2_sdk::types::MetricUnit::Bytes => "bytes",
        s2_sdk::types::MetricUnit::Operations => "operations",
    }
}

fn print_metrics(metrics: &[Metric]) {
    #[derive(Tabled)]
    struct AccumulationRow {
        interval_start: String,
        count: String,
    }

    #[derive(Tabled)]
    struct GaugeRow {
        time: String,
        value: String,
    }

    for metric in metrics {
        match metric {
            Metric::Scalar(m) => {
                println!("{}: {} {}", m.name, m.value, format_unit(m.unit));
            }
            Metric::Accumulation(m) => {
                let rows: Vec<AccumulationRow> = m
                    .values
                    .iter()
                    .map(|(ts, value)| AccumulationRow {
                        interval_start: format_timestamp(*ts),
                        count: value.to_string(),
                    })
                    .collect();

                println!("{}", m.name);

                let mut table = Table::new(rows);
                table.modify(
                    tabled::settings::object::Columns::last(),
                    tabled::settings::Alignment::right(),
                );

                let interval_col = "interval start time".to_string();
                let count_col = format_unit(m.unit).to_string();
                table.with(
                    tabled::settings::Modify::new(tabled::settings::object::Cell::new(0, 0))
                        .with(tabled::settings::Format::content(|_| interval_col.clone())),
                );
                table.with(
                    tabled::settings::Modify::new(tabled::settings::object::Cell::new(0, 1))
                        .with(tabled::settings::Format::content(|_| count_col.clone())),
                );

                println!("{table}");
                println!();
            }
            Metric::Gauge(m) => {
                let rows: Vec<GaugeRow> = m
                    .values
                    .iter()
                    .map(|(ts, value)| GaugeRow {
                        time: format_timestamp(*ts),
                        value: value.to_string(),
                    })
                    .collect();

                let count_col = format_unit(m.unit).to_string();
                println!("{}\n", m.name);

                let mut table = Table::new(rows);
                table.modify(
                    tabled::settings::object::Columns::last(),
                    tabled::settings::Alignment::right(),
                );

                table.with(
                    tabled::settings::Modify::new(tabled::settings::object::Cell::new(0, 1))
                        .with(tabled::settings::Format::content(|_| count_col.clone())),
                );

                println!("{table}");
                println!();
            }
            Metric::Label(m) => {
                println!("{}:", m.name);
                for label in &m.values {
                    println!("  {}", label);
                }
            }
        }
    }
}
