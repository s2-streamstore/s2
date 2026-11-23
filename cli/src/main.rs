//! S2 command-line interface.

mod access_token;
mod apply;
mod auth;
mod bench;
mod cli;
mod config;
mod credential_store;
mod diff;
mod environment;
mod error;
mod lite;
mod login;
mod metrics;
mod ops;
mod record_format;
mod types;
mod update;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::{pin::Pin, process::ExitCode, time::Duration};

use clap::Parser;
use cli::{
    AccessTokenCommand, ApplyArgs, AuthAccessTokenCommand, AuthCommand, BasinCommand, Cli, Command,
    ConfigCommand, ListBasinsArgs, ListStreamsArgs, LocationCommand, MetricsCommand,
    NetworkPolicyCommand, StreamCommand,
};
use colored::{Color, Colorize};
use config::{
    AuthMethod, ConfigKey, CredentialStore, load_config_file, sdk_config, select_auth_method,
    set_config_value, unset_config_value,
};
use error::{CliError, OpKind};
use futures::{Stream, StreamExt};
use json_to_table::json_to_table;
use record_format::{
    JsonBase64Formatter, JsonFormatter, RecordFormat, RecordParser, RecordWriter, TextFormatter,
};
use s2_sdk::{
    S2,
    types::{
        AppendRetryPolicy, Command as SdkCommand, CreateStreamInput, DeleteOnEmptyConfig,
        EncryptionKey, LocationInfo, Metric, PrivateNet, RetentionPolicy, RetryConfig,
        StreamConfig as SdkStreamConfig, StreamName, Timestamp, TimestampingConfig,
        TimestampingMode,
    },
};
use strum::VariantNames;
use tabled::{Table, Tabled};
use tokio::{io::AsyncWriteExt, select};
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};
use types::{
    AccessTokenInfo, BasinConfig, NetworkPolicyInfo, S2BasinAndMaybeStreamUri, StreamConfig,
};

fn install_rustls_crypto_provider() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install aws-lc-rs as default rustls crypto provider");
}

#[tokio::main]
async fn main() -> miette::Result<ExitCode> {
    install_rustls_crypto_provider();
    miette::set_panic_hook();

    let cli = parse_cli();
    let passive_update_check = allows_passive_update_check(cli.command.as_ref());
    let update_check = if passive_update_check {
        update::spawn_check()
    } else {
        None
    };

    let result = run(cli).await;
    if passive_update_check && result.is_ok() {
        update::notify(update_check).await;
    }
    Ok(result?)
}

/// Whether the arguments ask for the help of `s2` itself. It takes no options of its own, so
/// that is `-h`, `--help` or a bare `help` in first position.
fn wants_top_level_help() -> bool {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("-h" | "--help") => true,
        Some("help") => args.next().is_none(),
        _ => false,
    }
}

fn parse_cli() -> Cli {
    Cli::try_parse().unwrap_or_else(|e| {
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
        // Top-level help is rendered again with its own layout, which is only built here.
        if e.kind() == clap::error::ErrorKind::DisplayHelp
            && wants_top_level_help()
            && let Err(help) = cli::command_with_top_level_help().try_get_matches()
        {
            help.exit()
        }
        e.exit()
    })
}

fn allows_passive_update_check(command: Option<&Command>) -> bool {
    !matches!(
        command,
        Some(
            Command::Lite(_)
                | Command::Login(_)
                | Command::Logout(_)
                | Command::Auth(
                    AuthCommand::Login(_) | AuthCommand::Logout(_) | AuthCommand::Status,
                )
                | Command::Update(_)
        )
    )
}

fn print_legacy_access_token_deprecation(config: &config::CliConfig) {
    if config.has_legacy_access_token() {
        eprintln!(
            "{}",
            "! `access_token` in config.toml is deprecated.\n  Run `s2 auth access-token migrate` to move it to secure storage."
                .yellow()
        );
    }
}

fn print_token_change(message: &str, change: &access_token::TokenChange) {
    eprintln!("{}", format!("✓ {message}").green().bold());
    if change.replaced {
        eprintln!("  - Previous access token replaced.");
    }
    match change.credential_store {
        CredentialStore::Keyring => {
            eprintln!(
                "  - Access token saved to: {}",
                "OS credential store".cyan()
            );
        }
        CredentialStore::File => {
            #[cfg(unix)]
            eprintln!(
                "{}",
                "  - Warning: the access token is stored in a plaintext file with user-only permissions."
                    .yellow()
            );
            #[cfg(not(unix))]
            eprintln!(
                "{}",
                "  - Warning: the access token is stored in a plaintext file using the platform's default user-directory permissions."
                    .yellow()
            );
            if let Some(path) = change.credential_path.as_ref() {
                eprintln!(
                    "  - Access token saved to: {}",
                    path.display().to_string().cyan()
                );
            }
        }
    }
    eprintln!(
        "  - Configuration saved to: {}",
        change.config_path.display().to_string().cyan()
    );
    if let Some(error) = change.cleanup_warning.as_ref() {
        eprintln!(
            "{}",
            format!("  - Warning: an older local credential remains queued for cleanup: {error}")
                .yellow()
        );
    }
    if config::access_token_from_environment()
        .ok()
        .flatten()
        .is_some()
    {
        eprintln!(
            "{}",
            "  - Warning: S2_ACCESS_TOKEN is set and remains active. Unset it to use the selected credential."
                .yellow()
        );
    }
}

fn print_token_removal(removal: access_token::TokenRemoval) {
    if removal.removed {
        eprintln!("{}", "✓ Access token removed".green().bold());
        eprintln!("{}", "  - This does not revoke the access token.".yellow());
    } else {
        eprintln!("{}", "✓ No access token to remove".green().bold());
    }
    if let Some(path) = removal.config_path {
        eprintln!(
            "  - Configuration saved to: {}",
            path.display().to_string().cyan()
        );
    }
    if let Some(error) = removal.cleanup_warning {
        eprintln!(
            "{}",
            format!("  - Warning: an older local credential remains queued for cleanup: {error}")
                .yellow()
        );
    }
    if config::access_token_from_environment()
        .ok()
        .flatten()
        .is_some()
    {
        eprintln!(
            "{}",
            "  - Warning: S2_ACCESS_TOKEN remains set and is still active.".yellow()
        );
    }
}

async fn run(cli: Cli) -> Result<ExitCode, CliError> {
    let Some(command) = cli.command else {
        cli::command_with_top_level_help().print_help().ok();
        std::process::exit(0);
    };

    if let Command::Lite(args) = command {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();
        return lite::run(args).await.map(|()| ExitCode::SUCCESS);
    }

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

    if let Command::Login(args) = &command {
        login::login(args).await?;
        return Ok(ExitCode::SUCCESS);
    }

    if let Command::Logout(args) = &command {
        login::logout(args).await?;
        return Ok(ExitCode::SUCCESS);
    }

    if let Command::Auth(auth_cmd) = &command {
        match auth_cmd {
            AuthCommand::Login(args) => login::login(args).await?,
            AuthCommand::Logout(args) => login::logout(args).await?,
            AuthCommand::Status => return auth::status().await,
            AuthCommand::Use { method } => {
                let saved_path = select_auth_method(*method).await?;
                let message = match method {
                    AuthMethod::AccessToken => "✓ Access token selected",
                    AuthMethod::BrowserLogin => "✓ Browser login selected",
                };
                eprintln!("{}", message.green().bold());
                eprintln!(
                    "  - Configuration saved to: {}",
                    saved_path.display().to_string().cyan()
                );
                if login::has_access_token_environment_variable() {
                    eprintln!(
                        "{}",
                        "  - Warning: S2_ACCESS_TOKEN is set and remains active. Unset it to use the selected credential."
                            .yellow()
                    );
                }
            }
            AuthCommand::AccessToken { command } => match command {
                AuthAccessTokenCommand::Set(args) => {
                    let change = access_token::set(args).await?;
                    print_token_change("Access token saved", &change);
                }
                AuthAccessTokenCommand::Migrate(args) => {
                    let change = access_token::migrate(args).await?;
                    print_token_change("Legacy access token migrated", &change);
                }
                AuthAccessTokenCommand::Remove => {
                    print_token_removal(access_token::remove().await?);
                }
            },
        }
        return Ok(ExitCode::SUCCESS);
    }

    if let Command::Config(config_cmd) = &command {
        match config_cmd {
            ConfigCommand::List => {
                let config = load_config_file()?;
                print_legacy_access_token_deprecation(&config);
                for k in ConfigKey::VARIANTS {
                    if let Ok(key) = k.parse::<ConfigKey>()
                        && let Some(v) = config.get(key)
                    {
                        println!("{} = {}", k, v);
                    }
                }
            }
            ConfigCommand::Get { key } => {
                if matches!(key, ConfigKey::AccessToken) {
                    return Err(error::CliConfigError::CredentialNotReadable.into());
                }
                let config = load_config_file()?;
                if let Some(v) = config.get(*key) {
                    println!("{}", v);
                }
            }
            ConfigCommand::Set { key, value } => {
                if matches!(key, ConfigKey::AccessToken) {
                    eprintln!(
                        "{}",
                        "! `s2 config set access_token` is deprecated.\n  Use `s2 auth access-token set` instead."
                            .yellow()
                    );
                    let change = access_token::set_from_argument(value.clone()).await?;
                    print_token_change("Access token saved", &change);
                } else {
                    let saved_path = set_config_value(*key, value.clone()).await?;
                    eprintln!("{}", format!("✓ {} set", key).green().bold());
                    eprintln!(
                        "  Configuration saved to: {}",
                        saved_path.display().to_string().cyan()
                    );
                }
            }
            ConfigCommand::Unset { key } => {
                if matches!(key, ConfigKey::AccessToken) {
                    print_token_removal(access_token::remove().await?);
                } else {
                    let saved_path = unset_config_value(*key).await?;
                    eprintln!("{}", format!("✓ {} unset", key).green().bold());
                    eprintln!(
                        "  Configuration saved to: {}",
                        saved_path.display().to_string().cyan()
                    );
                }
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    if let Command::Update(args) = &command {
        update::apply::run(args)
            .await
            .map_err(|e| CliError::Update(e.to_string()))?;
        return Ok(ExitCode::SUCCESS);
    }

    if let Command::Apply(ApplyArgs { schema: true, .. }) = &command {
        let schema = s2_resource_spec::json_schema();
        println!(
            "{}",
            serde_json::to_string_pretty(&schema).expect("valid schema")
        );
        return Ok(ExitCode::SUCCESS);
    }

    if let Command::Diff(args) = &command {
        diff::validate_args(args)?;
    }

    let (cli_config, credential) = login::resolve_access_token().await?;
    print_legacy_access_token_deprecation(&cli_config);
    credential.validate_destination(&cli_config)?;
    let sdk_config = credential.configure_sdk(sdk_config(
        &cli_config,
        credential.access_token(),
        update::user_agent(),
    )?);
    let token_source = Some(credential.source());
    let target = environment::Target::detect(&cli_config);
    let s2 = S2::new(sdk_config).map_err(|e| {
        if let Some(source) = token_source
            && !error::is_valid_access_token(credential.access_token())
        {
            CliError::MalformedAccessToken(e.into(), source)
        } else {
            CliError::SdkInit(e.into())
        }
    })?;
    let mut exit_code = ExitCode::SUCCESS;
    let result: Result<(), CliError> = (async {
        match command {
        Command::Login(..)
        | Command::Logout(..)
        | Command::Auth(..)
        | Command::Config(..)
        | Command::Lite(..)
        | Command::Update(..) => {
            unreachable!()
        }

        Command::Ls(args) => {
            if let Some(ref uri) = args.uri {
                // List streams
                let S2BasinAndMaybeStreamUri {
                    basin,
                    stream: uri_prefix,
                } = uri.clone();

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

                let (streams, _) = ops::list_streams(&s2, list_streams_args).await?;
                for stream_info in streams {
                    print_listing_with_created_at(
                        format!("s2://{}/{}", basin, stream_info.name),
                        stream_info.created_at.to_string(),
                        stream_info.deleted_at.is_some(),
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

                let (basins, _) = ops::list_basins(&s2, list_basins_args).await?;
                for basin_info in basins {
                    print_basin_listing(
                        basin_info.name.to_string(),
                        basin_info.location.as_deref(),
                        basin_info.deleted_at.is_some(),
                    );
                }
            }
        }

        Command::ListBasins(args) | Command::Basin(BasinCommand::List(args)) => {
            let (basins, _) = ops::list_basins(&s2, args).await?;
            for basin_info in basins {
                print_basin_listing(
                    basin_info.name.to_string(),
                    basin_info.location.as_deref(),
                    basin_info.deleted_at.is_some(),
                );
            }
        }

        Command::CreateBasin(args) | Command::Basin(BasinCommand::Create(args)) => {
            let _info = ops::create_basin(&s2, args).await?;
            eprintln!("{}", "✓ Basin created".green().bold());
        }

        Command::DeleteBasin { basin } | Command::Basin(BasinCommand::Delete { basin }) => {
            ops::delete_basin(&s2, &basin.into()).await?;
            eprintln!("{}", "✓ Basin deletion requested".green().bold());
        }

        Command::GetBasinConfig { basin } | Command::Basin(BasinCommand::Get { basin }) => {
            let basin_config: BasinConfig = ops::get_basin_config(&s2, &basin.into()).await?.into();
            println!("{}", json_to_table(&serde_json::to_value(&basin_config)?));
        }

        Command::ReconfigureBasin(args) | Command::Basin(BasinCommand::Reconfigure(args)) => {
            let config = ops::reconfigure_basin(&s2, args).await?;

            eprintln!("{}", "✓ Basin reconfigured".green().bold());
            println!("{}", json_to_table(&serde_json::to_value(&config)?));
        }

        Command::ListAccessTokens(args) | Command::AccessToken(AccessTokenCommand::List(args)) => {
            let (tokens, _) = ops::list_access_tokens(&s2, args).await?;
            let tokens: Vec<AccessTokenInfo> =
                tokens.into_iter().map(AccessTokenInfo::from).collect();
            let id_width = tokens.iter().map(|info| info.id.len()).max().unwrap_or(0);
            let blocks: Vec<String> = tokens
                .iter()
                .map(|info| info.summary_block(id_width))
                .collect();
            if !blocks.is_empty() {
                println!("{}", blocks.join("\n\n"));
            }
        }

        Command::IssueAccessToken(args) | Command::AccessToken(AccessTokenCommand::Issue(args)) => {
            let token = ops::issue_access_token(&s2, *args).await?;
            println!("{}", token);
        }

        Command::RevokeAccessToken { id } | Command::AccessToken(AccessTokenCommand::Revoke { id }) => {
            ops::revoke_access_token(&s2, id.clone()).await?;
            eprintln!(
                "{}",
                format!("✓ Access token '{}' revoked", id).green().bold()
            );
        }

        Command::NetworkPolicy(NetworkPolicyCommand::List(args)) => {
            let (policies, _) = ops::list_network_policies(&s2, args).await?;
            let policies: Vec<NetworkPolicyInfo> =
                policies.into_iter().map(NetworkPolicyInfo::from).collect();
            let id_width = policies.iter().map(|info| info.id.len()).max().unwrap_or(0);
            let blocks: Vec<String> = policies
                .iter()
                .map(|info| info.summary_block(id_width))
                .collect();
            if !blocks.is_empty() {
                println!("{}", blocks.join("\n\n"));
            }
        }

        Command::NetworkPolicy(NetworkPolicyCommand::Create(args)) => {
            let info = ops::create_network_policy(&s2, args).await?;
            eprintln!("{}", "✓ Network policy created".green().bold());
            println!("{}", info.id);
        }

        Command::NetworkPolicy(NetworkPolicyCommand::Get { id }) => {
            let info = NetworkPolicyInfo::from(ops::get_network_policy(&s2, id).await?);
            println!("{}", json_to_table(&serde_json::to_value(&info)?));
        }

        Command::NetworkPolicy(NetworkPolicyCommand::Delete { id }) => {
            ops::delete_network_policy(&s2, id.clone()).await?;
            eprintln!(
                "{}",
                format!("✓ Network policy '{}' deleted", id).green().bold()
            );
        }

        Command::Diff(args) => {
            let use_diff_exit_code = args.exit_code;
            let outcome = diff::run(&s2, args).await?;
            if use_diff_exit_code && outcome.has_differences {
                exit_code = ExitCode::from(1);
            }
        }

        Command::ListLocations | Command::Location(LocationCommand::List) => {
            let locations = ops::list_locations(&s2).await?;
            for location_info in locations {
                print_location_listing(&location_info, true);
            }
        }

        Command::GetDefaultLocation | Command::Location(LocationCommand::GetDefault) => {
            let location = ops::get_default_location(&s2).await?;
            print_location_listing(&location, false);
        }

        Command::SetDefaultLocation { location }
        | Command::Location(LocationCommand::SetDefault { location }) => {
            let location_name = location.to_string();
            let location = ops::set_default_location(&s2, location).await?;
            eprintln!(
                "{}",
                format!("✓ Default location set to '{}'", location_name)
                    .green()
                    .bold()
            );
            print_location_listing(&location, false);
        }

        Command::GetAccountMetrics(args) | Command::Metrics(MetricsCommand::Account(args)) => {
            let output = args.output;
            let token_activity = matches!(
                args.metric,
                cli::AccountMetricCommand::TokenActivity(_)
            );
            let billable_usage = matches!(
                args.metric,
                cli::AccountMetricCommand::EstimatedBillableUsage(_)
            );
            let (range, metrics) = ops::get_account_metrics(&s2, args).await?;
            if output != cli::MetricsOutput::Pretty {
                print_metrics(&metrics, output, None);
            } else if token_activity {
                print_token_activity(&metrics);
            } else if billable_usage {
                print_time_range(range.as_ref());
                let by_interval = range.is_some_and(|range| range.interval().is_some());
                print_estimated_billable_usage(&metrics, by_interval);
            } else {
                print_metrics(&metrics, output, range.as_ref());
            }
        }

        Command::GetBasinMetrics(args) | Command::Metrics(MetricsCommand::Basin(args)) => {
            let output = args.output;
            let (range, metrics) = ops::get_basin_metrics(&s2, args).await?;
            print_metrics(&metrics, output, range.as_ref());
        }

        Command::GetStreamMetrics(args) | Command::Metrics(MetricsCommand::Stream(args)) => {
            let output = args.output;
            let (range, metrics) = ops::get_stream_metrics(&s2, args).await?;
            print_metrics(&metrics, output, range.as_ref());
        }

        Command::ListStreams(args) | Command::Stream(StreamCommand::List(args)) => {
            let basin_name = args.uri.basin.clone();
            let (streams, _) = ops::list_streams(&s2, args).await?;
            for stream_info in streams {
                print_listing_uri(
                    format!("s2://{}/{}", basin_name, stream_info.name),
                    stream_info.deleted_at.is_some(),
                );
            }
        }

        Command::CreateStream(args) | Command::Stream(StreamCommand::Create(args)) => {
            ops::create_stream(&s2, args).await?;
            eprintln!("{}", "✓ Stream created".green().bold());
        }

        Command::DeleteStream { uri } | Command::Stream(StreamCommand::Delete { uri }) => {
            ops::delete_stream(&s2, uri).await?;
            eprintln!("{}", "✓ Stream deletion requested".green().bold());
        }

        Command::GetStreamConfig { uri } | Command::Stream(StreamCommand::Get { uri }) => {
            let stream_config = ops::get_stream_config(&s2, uri).await?;
            let stream_config: StreamConfig = stream_config.into();
            println!("{}", json_to_table(&serde_json::to_value(&stream_config)?));
        }

        Command::ReconfigureStream(args) | Command::Stream(StreamCommand::Reconfigure(args)) => {
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
                    format_position(out.tail.seq_num, out.tail.timestamp)
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
                    format_position(out.tail.seq_num, out.tail.timestamp)
                )
                .green()
                .bold()
            );
        }

        Command::Append(args) => {
            let encryption_key = resolve_encryption_key(&args.encryption_key)?;
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
                encryption_key.as_ref(),
                ops::AppendOptions {
                    fencing_token: args.fencing_token,
                    match_seq_num: args.match_seq_num,
                    linger: *args.linger,
                    stream_config: (!args.stream_config.is_empty())
                        .then(|| args.stream_config.into()),
                },
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
            let encryption_key = resolve_encryption_key(&args.encryption_key)?;
            let mut batches = ops::read(&s2, &args, encryption_key.as_ref())?;
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
            let encryption_key = resolve_encryption_key(&args.encryption_key)?;
            let mut records = ops::tail(&s2, &args, encryption_key.as_ref())?;
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
                                let skip_newline = matches!(args.format, RecordFormat::Text)
                                    && record.is_command_record();
                                if !skip_newline {
                                    writer
                                        .write_all(b"\n")
                                        .await
                                        .map_err(|e| CliError::RecordWrite(e.to_string()))?;
                                }
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

        Command::Apply(ApplyArgs {
            file,
            dry_run,
            schema: _,
        }) => {
            let file = file.expect("--file is required when --schema is not set");
            let spec = apply::load(&file).map_err(CliError::InvalidArgs)?;
            if dry_run {
                apply::dry_run(&s2, spec)
                    .await
                    .map_err(|e| CliError::Apply(e.to_string()))?;
            } else {
                apply::apply(&s2, spec)
                    .await
                    .map_err(|e| CliError::Apply(e.to_string()))?;
                eprintln!("{}", "✓ Done".green().bold());
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
                args.storage_class.as_deref().unwrap_or("<default>")
            );

            let mut stream_config = SdkStreamConfig::new()
                .with_retention_policy(RetentionPolicy::Age(3600))
                .with_delete_on_empty(
                    DeleteOnEmptyConfig::new()
                        .with_min_age(Duration::from_secs(60))
                        .expect("whole-second duration"),
                )
                .with_timestamping(
                    TimestampingConfig::new()
                        .with_mode(TimestampingMode::ClientRequire)
                        .with_uncapped(true),
                );
            if let Some(storage_class) = args.storage_class {
                stream_config = stream_config.with_storage_class(storage_class);
            }

            let s2 = s2
                .with_retry(
                    RetryConfig::new().with_append_retry_policy(AppendRetryPolicy::NoSideEffects),
                )
                .map_err(|e| CliError::SdkInit(e.into()))?;

            let basin = s2.basin(basin_name);
            basin
                .create_stream(
                    CreateStreamInput::new(stream_name.clone()).with_config(stream_config),
                )
                .await
                .map_err(|e| CliError::op(OpKind::Bench, e))?;

            let linger = args.linger.map_or_else(
                || bench::default_linger(args.target_mibps, args.record_size),
                Into::into,
            );
            eprintln!(
                "Running for {} targeting {} MiB/s with {} byte records and {} linger, Ctrl+C to end early",
                args.duration,
                args.target_mibps,
                args.record_size,
                humantime::format_duration(linger),
            );

            let bench_result = bench::run(
                basin.stream(stream_name.clone()),
                args.record_size as usize,
                args.target_mibps,
                linger,
                *args.duration,
                *args.catchup_delay,
            )
            .await;

            let delete_result = basin
                .delete_stream(stream_name)
                .await
                .map_err(|e| CliError::op(OpKind::Bench, e));
            bench_result?;
            delete_result?;
        }
        }
        Ok(())
    })
    .await;

    result
        .map(|()| exit_code)
        .map_err(|err| err.with_token_source(token_source).with_target(target))
}

fn format_position(seq_num: u64, timestamp: u64) -> String {
    format!("{seq_num} @ {timestamp}")
}

fn print_listing_uri(uri: String, is_deleting: bool) {
    let uri = format_listing_uri(uri, is_deleting);
    if is_deleting {
        println!("{} {}", uri, deletion_marker());
    } else {
        println!("{uri}");
    }
}

fn print_basin_listing(name: String, location: Option<&str>, is_deleting: bool) {
    let name = format_listing_uri(name, is_deleting);
    let location = location.map(|location| format!("({location})").color(location_color(location)));
    match (location, is_deleting) {
        (Some(location), true) => println!("{} {} {}", name, location, deletion_marker()),
        (Some(location), false) => println!("{} {}", name, location),
        (None, true) => println!("{} {}", name, deletion_marker()),
        (None, false) => println!("{name}"),
    }
}

fn print_location_listing(location: &LocationInfo, is_list_item: bool) {
    print!("{}", render_location_listing(location, is_list_item));
}

/// A location, with its storage classes one to a line and the default one marked.
fn render_location_listing(location: &LocationInfo, is_list_item: bool) -> String {
    let name = location.name.as_ref();
    let (heading, indent) = if is_list_item {
        (format!("- {}", name.color(location_color(name))), "    ")
    } else {
        (name.to_owned(), "  ")
    };
    let visibility = format_location_visibility(location.is_private);
    let mut out = format!("{heading} {visibility}\n");
    let default = location.default_storage_class.as_ref();
    let classes = location.storage_classes.as_deref().unwrap_or_default();
    match &location.storage_classes {
        Some(classes) if classes.is_empty() => {
            out.push_str(&format!("{indent}storage classes: none\n"));
        }
        Some(classes) => {
            out.push_str(&format!("{indent}storage classes:\n"));
            for class in classes {
                if Some(class) == default {
                    out.push_str(&format!("{indent}  {class} {}\n", "(default)".dimmed()));
                } else {
                    out.push_str(&format!("{indent}  {class}\n"));
                }
            }
        }
        None => {}
    }
    // A default that is not among the classes listed still has to be shown.
    if let Some(default) = default.filter(|default| !classes.contains(default)) {
        out.push_str(&format!("{indent}default storage class: {default}\n"));
    }
    match &location.private_net {
        Some(PrivateNet::Aws(aws)) => {
            out.push_str(&format!(
                "{indent}privatelink service name: {}\n",
                aws.service_name
            ));
            if let Some(private_dns_name) = &aws.private_dns_name {
                out.push_str(&format!(
                    "{indent}privatelink dns name: {private_dns_name}\n"
                ));
            }
        }
        Some(PrivateNet::Unknown(kind)) => out.push_str(&format!("{indent}private net: {kind}\n")),
        Some(_) | None => {}
    }
    out
}

fn format_location_visibility(is_private: bool) -> colored::ColoredString {
    if is_private {
        "(private)".yellow()
    } else {
        "(public)".green()
    }
}

fn print_listing_with_created_at(uri: String, created_at: String, is_deleting: bool) {
    let uri = format_listing_uri(uri, is_deleting);
    let created_at = if is_deleting {
        created_at.red()
    } else {
        created_at.green()
    };

    if is_deleting {
        println!("{} {} {}", uri, created_at, deletion_marker());
    } else {
        println!("{} {}", uri, created_at);
    }
}

fn format_listing_uri(uri: String, is_deleting: bool) -> colored::ColoredString {
    if is_deleting { uri.red() } else { uri.normal() }
}

fn location_color(location: &str) -> Color {
    const PALETTE: [Color; 8] = [
        Color::Green,
        Color::Magenta,
        Color::BrightBlue,
        Color::BrightGreen,
        Color::Yellow,
        Color::BrightCyan,
        Color::Cyan,
        Color::BrightMagenta,
    ];

    // FNV-1a keeps the palette index stable across runs.
    let hash = location.bytes().fold(0x811c9dc5_u32, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x01000193)
    });
    PALETTE[hash as usize % PALETTE.len()]
}

fn deletion_marker() -> colored::ColoredString {
    "[deleting]".red().bold()
}

async fn write_record(
    record: &s2_sdk::types::SequencedRecord,
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    format: RecordFormat,
) -> Result<(), CliError> {
    match format {
        RecordFormat::Text => {
            if record.is_command_record() {
                let cmd_desc = match record.command() {
                    Some(SdkCommand::Fence { fencing_token }) => {
                        format!("new fencing token \"{fencing_token}\"")
                    }
                    Some(SdkCommand::Trim { trim_point }) => format!("trim to {trim_point}"),
                    _ => format!(
                        "unknown command \"{}\"",
                        String::from_utf8_lossy(&record.headers[0].value)
                    ),
                };
                eprintln!(
                    "{} // {}",
                    cmd_desc.bold(),
                    format_position(record.seq_num, record.timestamp)
                );
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

/// ` (2h 5m ago)` for a time in the past, and nothing for one that is not.
fn format_ago(ts: Timestamp) -> String {
    metrics::format_age(ts, Timestamp::now())
        .map(|age| format!(" ({age} ago)"))
        .unwrap_or_default()
}

/// Token activity grouped by outcome. Anything in the set that is not a record is printed as any
/// other metric would be.
fn print_token_activity(metrics: &[Metric]) {
    let (records, rest): (Vec<&Metric>, Vec<&Metric>) = metrics
        .iter()
        .partition(|metric| matches!(metric, Metric::Record(_)));
    let records: Vec<_> = records
        .into_iter()
        .filter_map(|metric| match metric {
            Metric::Record(record) => Some(record),
            _ => None,
        })
        .collect();
    if records.is_empty() && rest.is_empty() {
        eprintln!("No recorded use.");
    }
    let width = std::io::IsTerminal::is_terminal(&std::io::stdout())
        .then(terminal_size::terminal_size)
        .flatten()
        .map(|(terminal_size::Width(width), _)| width as usize);
    print!(
        "{}",
        metrics::render_token_activity(&records, Timestamp::now(), width)
    );
    let rest: Vec<Metric> = rest.into_iter().cloned().collect();
    print_metrics(&rest, cli::MetricsOutput::Pretty, None);
}

fn print_estimated_billable_usage(metrics: &[Metric], by_interval: bool) {
    let rendered = metrics::render_estimated_billable_usage(metrics, by_interval);
    if rendered.is_empty() {
        eprintln!("No estimated billable usage in the time range.");
    }
    print!("{rendered}");
}

fn print_time_range(range: Option<&s2_sdk::types::TimeRangeAndInterval>) {
    if let Some(range) = range {
        print!("{}", metrics::render_time_range(range.start(), range.end()));
    }
}

/// Pretty output is a glance: without an interval asked for, accumulations are summed over
/// `range`, and a long gauge is sampled. JSON has every point.
fn print_metrics(
    metrics: &[Metric],
    output: cli::MetricsOutput,
    range: Option<&s2_sdk::types::TimeRangeAndInterval>,
) {
    use metrics::format_unit;

    if output == cli::MetricsOutput::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&metrics::to_json(metrics)).expect("metrics as JSON")
        );
        return;
    }

    #[derive(Tabled)]
    struct AccumulationRow {
        interval_start: String,
        count: String,
    }

    print_time_range(range);
    let summed = range.is_some_and(|range| range.interval().is_none());
    if summed {
        let series: Vec<_> = metrics
            .iter()
            .filter_map(|metric| match metric {
                Metric::Accumulation(series) => Some(series),
                _ => None,
            })
            .collect();
        print!("{}", metrics::render_sums(&series));
    }
    // Without a range these are what is left of a set printed elsewhere, which may be nothing.
    if metrics.is_empty() && range.is_some() {
        eprintln!("No data in the time range.");
    }

    for metric in metrics {
        match metric {
            Metric::Scalar(m) => {
                println!("{}: {} {}", m.name, m.value, format_unit(&m.unit));
            }
            Metric::Accumulation(_) if summed => {}
            Metric::Accumulation(m) => {
                let rows: Vec<AccumulationRow> = m
                    .values
                    .iter()
                    .map(|(ts, value)| AccumulationRow {
                        interval_start: ts.to_string(),
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
                let count_col = format_unit(&m.unit).to_string();
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
                let rendered = metrics::render_gauge(m);
                if rendered.is_empty() {
                    eprintln!("{}: no data in the time range.", m.name);
                }
                println!("{rendered}");
            }
            Metric::Label(m) => {
                println!("{}:", m.name);
                for label in &m.values {
                    println!("  {}", label);
                }
            }
            Metric::Record(m) => {
                println!("{} @ {}{}:", m.name, m.timestamp, format_ago(m.timestamp));
                for (field, value) in &m.fields {
                    println!("  {field}: {value}");
                }
            }
            Metric::Unknown(kind) => {
                println!("unrecognized metric kind: {kind}");
            }
            _ => {}
        }
    }
}

fn resolve_encryption_key(
    args: &cli::EncryptionKeyArgs,
) -> Result<Option<EncryptionKey>, CliError> {
    match (&args.key, &args.key_file) {
        (Some(key), _) => Ok(Some(key.clone())),
        (_, Some(path)) => {
            let contents = std::fs::read_to_string(path).map_err(|e| {
                CliError::InvalidArgs(miette::miette!("cannot read encryption key file: {e}"))
            })?;
            Ok(Some(contents.trim().parse::<EncryptionKey>().map_err(
                |e| CliError::InvalidArgs(miette::miette!("{e}")),
            )?))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_listing_marks_the_default_storage_class() {
        colored::control::set_override(false);

        let listed = LocationInfo::new("aws:us-east-1".parse().unwrap(), false)
            .with_storage_classes(["express", "standard"])
            .with_default_storage_class("express");
        let expected = [
            "aws:us-east-1 (public)",
            "  storage classes:",
            "    express (default)",
            "    standard",
            "",
        ];
        assert_eq!(render_location_listing(&listed, false), expected.join("\n"));

        // The default is not lost when the account cannot use it.
        let unlisted = LocationInfo::new("aws:us-east-1".parse().unwrap(), true)
            .with_storage_classes(["standard"])
            .with_default_storage_class("express");
        let expected = [
            "aws:us-east-1 (private)",
            "  storage classes:",
            "    standard",
            "  default storage class: express",
            "",
        ];
        assert_eq!(
            render_location_listing(&unlisted, false),
            expected.join("\n")
        );
    }
}
