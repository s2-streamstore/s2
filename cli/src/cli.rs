use std::{num::NonZeroU64, path::PathBuf, time::Duration};

use clap::{Args, Parser, Subcommand, ValueEnum, builder::styling};
use compact_str::CompactString;
use s2_sdk::types::{
    AccessTokenId, AccessTokenIdPrefix, AccessTokenIdStartAfter, BasinName, BasinNamePrefix,
    BasinNameStartAfter, Cidr, EncryptionKey, FencingToken, NetworkPolicySelector,
    NetworkPolicySlug, NetworkPolicySlugPrefix, NetworkPolicySlugStartAfter, StreamName,
    StreamNamePrefix, StreamNameStartAfter, VpcEndpointId,
};
use sha2::{Digest as _, Sha256};

use crate::{
    environment::{Environment, Shell, Target},
    record_format::{
        RecordFormat, RecordsIn, RecordsOut, parse_records_input_source,
        parse_records_output_source,
    },
    types::{
        AccessTokenPreset, BasinConfig, BillableUsageInterval, EncryptionAlgorithm, Interval,
        LocationName, Operation, PermittedOperationGroups, S2BasinAndMaybeStreamUri,
        S2BasinAndStreamUri, S2BasinUri, StreamConfig,
    },
};

const STYLES: styling::Styles = styling::Styles::styled()
    .header(styling::AnsiColor::Green.on_default().bold())
    .usage(styling::AnsiColor::Green.on_default().bold())
    .literal(styling::AnsiColor::Blue.on_default().bold())
    .placeholder(styling::AnsiColor::Cyan.on_default());

/// Config as `s2 --help` sees it, to tailor the help to where the CLI is pointed. `None` if the
/// config cannot be loaded; help must still print.
static HELP_CONFIG: std::sync::LazyLock<Option<crate::config::CliConfig>> =
    std::sync::LazyLock::new(|| crate::config::load_cli_config().ok());

/// The environment as `s2 --help` sees it. Without a loadable config, the defaults apply.
fn help_environment() -> Environment {
    match HELP_CONFIG.as_ref() {
        Some(config) => Environment::detect(config),
        None => Environment::detect(&crate::config::CliConfig::default()),
    }
}

/// Top-level commands as `s2 --help` lists them. A visible command missing from every group
/// would not be shown at all, which `help_groups_cover_visible_commands` guards.
const COMMAND_GROUPS: &[(&str, &[&str])] = &[
    (
        "Commands",
        &["append", "read", "tail", "check-tail", "trim", "fence"],
    ),
    (
        "Resources",
        &[
            "ls",
            "basin",
            "stream",
            "access-token",
            "network-policy",
            "location",
            "diff",
            "apply",
        ],
    ),
    ("Observability", &["metrics"]),
    ("Setup", &["login", "logout", "auth", "config"]),
    ("Tools", &["bench", "lite", "update"]),
];

/// Suffix for the walkthrough's basin name. On S2, basin names are unique across all accounts,
/// so the example needs one to stay free for whoever copies it. It is derived from the machine
/// and the home directory: the same user sees the same name on every run, logged in or not,
/// without the CLI storing anything. Containers have no machine ID, so there it is random.
fn example_basin_suffix() -> String {
    let machine_id = machine_uid::get().unwrap_or_default();
    let machine_id = machine_id.trim();
    let hex = if machine_id.is_empty() {
        uuid::Uuid::new_v4().simple().to_string()
    } else {
        // Hashed, as a machine ID is not meant to be shown.
        let mut hasher = Sha256::new();
        hasher.update(b"s2-cli-example-basin\0");
        hasher.update(machine_id.as_bytes());
        hasher.update(b"\0");
        if let Some(home) = dirs::home_dir() {
            hasher.update(home.as_os_str().as_encoded_bytes());
        }
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    };
    hex[..7].to_owned()
}

/// A first-use walkthrough.
fn get_started() -> String {
    let environment = help_environment();
    // Without browser login a token goes in the environment. A local endpoint accepts any.
    let auth = if environment.browser_login {
        "s2 login".to_owned()
    } else {
        let token = match environment.target {
            Target::Local => "ignored",
            Target::S2 | Target::Custom => "<token>",
        };
        match environment.shell {
            Shell::Posix => format!("export S2_ACCESS_TOKEN={token}"),
            Shell::PowerShell => format!(r#"$env:S2_ACCESS_TOKEN = "{token}""#),
        }
    };
    // A local endpoint has its own basin names.
    let basin = match environment.target {
        Target::Local => "my-basin".to_owned(),
        Target::S2 | Target::Custom => format!("my-basin-{}", example_basin_suffix()),
    };
    let prompt = match environment.shell {
        Shell::Posix => "$",
        Shell::PowerShell => ">",
    };
    color_print::cformat!(
        r#"<bold><green>Get started:</green></bold>
  <dim>{prompt}</dim> <bold>{auth}</bold>
  <dim>{prompt}</dim> <bold>s2 basin create {basin} --create-stream-on-append</bold>
  <dim>{prompt}</dim> <bold>echo "hello, world" | s2 append s2://{basin}/my-stream</bold>
  <dim>{prompt}</dim> <bold>s2 read s2://{basin}/my-stream --seq-num 0</bold> <dim>--count 10</dim>
"#
    )
}

/// The command with the top-level help laid out by `top_level_help`. Building that help loads
/// the config and may read the machine ID, so this is only for when it is printed.
pub fn command_with_top_level_help() -> clap::Command {
    <Cli as clap::CommandFactory>::command().help_template(top_level_help())
}

/// Help for bare `s2`: clap cannot put subcommands under more than one heading, so the command
/// listing is laid out here.
fn top_level_help() -> String {
    let commands = Command::augment_subcommands(clap::Command::new("s2"));
    let width = COMMAND_GROUPS
        .iter()
        .flat_map(|(_, names)| names.iter())
        .map(|name| name.len())
        .max()
        .unwrap_or(0);

    let mut help = String::new();
    // Only worth a line when it is not S2 itself, e.g. `s2 lite`.
    if let Some(config) = HELP_CONFIG
        .as_ref()
        .filter(|_| help_environment().target != Target::S2)
    {
        let endpoint = crate::login::destination_label(config);
        help.push_str(&color_print::cformat!(
            "<bold><green>Endpoint:</green></bold> {endpoint} <dim>(custom)</dim>\n\n"
        ));
    }
    help.push_str("{usage-heading} {usage}\n\n");
    help.push_str(&get_started());
    for (heading, names) in COMMAND_GROUPS {
        help.push_str(&color_print::cformat!(
            "\n<bold><green>{heading}:</green></bold>\n"
        ));
        for name in *names {
            let about = commands
                .find_subcommand(name)
                .and_then(|command| command.get_about())
                .map(ToString::to_string)
                .unwrap_or_default();
            let padding = " ".repeat(width - name.len());
            help.push_str(&color_print::cformat!(
                "  <bold><blue>{name}</blue></bold>{padding}  {about}\n"
            ));
        }
    }
    help.push_str(&color_print::cformat!(
        "\n<bold><green>Options:</green></bold>\n{{options}}\n\n\
         Run `s2 [COMMAND] --help` for details. Docs: https://s2.dev/docs/cli"
    ));
    help
}

#[derive(Parser, Debug)]
#[command(name = "s2", version = crate::update::long_version(), styles = STYLES)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    // Variants are declared in the order `s2 --help` lists them: setup, resources, stream data,
    // then tools.
    /// Log in to S2 through your browser.
    Login(LoginArgs),

    /// Log out of the browser-authenticated S2 session.
    Logout(LogoutArgs),

    /// Manage CLI authentication.
    #[command(subcommand)]
    Auth(AuthCommand),

    /// Manage CLI configuration.
    #[command(subcommand)]
    Config(ConfigCommand),

    /// List basins, or streams within a basin.
    ///
    /// Lists basins if no basin name is given, otherwise the streams in that basin.
    Ls(LsArgs),

    /// Manage basins (namespaces for streams).
    #[command(subcommand)]
    Basin(BasinCommand),

    /// Manage streams.
    #[command(subcommand)]
    Stream(StreamCommand),

    /// Manage access tokens.
    #[command(subcommand)]
    AccessToken(AccessTokenCommand),

    /// Manage network policies.
    #[command(subcommand)]
    NetworkPolicy(NetworkPolicyCommand),

    /// Manage locations (where basins are physically hosted).
    ///
    /// A basin is created in one location, such as `aws:us-east-1`, and its streams are stored
    /// and served there.
    #[command(
        subcommand,
        after_help = "\
A basin's location is chosen with `s2 basin create --location`. Without the flag, the basin
is created in the account's default location."
    )]
    Location(LocationCommand),

    /// Get account, basin, or stream metrics.
    #[command(subcommand)]
    Metrics(MetricsCommand),

    /// Compare two basins, streams, or access tokens.
    Diff(DiffArgs),

    /// Apply a declarative spec file, ensuring basins and streams.
    ///
    /// Reads a JSON file and ensures the declared basins and streams exist with the
    /// specified configuration. Defaults are applied before comparison; omitted fields are
    /// defaulted, not preserved.
    ///
    /// Dry-run output legend:
    ///   `+` create
    ///   `~` ensure
    ///   `=` unchanged
    ///   `?` storage-class default resolved at apply
    ///
    /// For IDE validation/autocomplete, add `$schema` at the top of each spec file:
    ///   {"$schema":"https://raw.githubusercontent.com/s2-streamstore/s2/main/cli/schema.json","basins":[]}
    ///
    /// For local-only use, point to a local path/URI instead:
    ///   {"$schema":"./cli/schema.json","basins":[]}
    ///
    /// Example spec file:
    ///   {"$schema":"https://raw.githubusercontent.com/s2-streamstore/s2/main/cli/schema.json","basins":[{"name":"my-basin","streams":[{"name":"events"}]}]}
    Apply(ApplyArgs),

    /// Append records to a stream.
    Append(AppendArgs),

    /// Read records from a stream.
    ///
    /// If a limit if specified, reading will stop when the limit is reached or there are no more
    /// records on the stream. If a limit is not specified, the reader will keep tailing and
    /// wait for new records.
    Read(ReadArgs),

    /// Tail a stream, showing the last N records.
    Tail(TailArgs),

    /// Check the tail position of a stream.
    ///
    /// Returns the sequence number that will be assigned to the next record,
    /// and the timestamp of the last record.
    CheckTail {
        /// S2 URI of the format: s2://{basin}/{stream}
        #[arg(value_name = "S2_URI")]
        uri: S2BasinAndStreamUri,
    },

    /// Set a trim point for a stream.
    ///
    /// Trimming is eventually consistent, and trimmed records may be visible
    /// for a brief period.
    Trim(TrimArgs),

    /// Set a fencing token for a stream.
    ///
    /// Fencing is strongly consistent, and subsequent appends that specify a
    /// token will be rejected if it does not match.
    ///
    /// Note that fencing is a cooperative mechanism,
    /// and it is only enforced when a token is provided.
    Fence(FenceArgs),

    /// Benchmark a stream to measure throughput and latency.
    Bench(BenchArgs),

    /// Run S2 Lite server (in-memory by default).
    ///
    /// Starts a lightweight S2-compatible server. Storage is in-memory unless
    /// `--bucket` (S3) or `--local-root` (local filesystem) is set.
    Lite(crate::lite::LiteArgs),

    /// Update the S2 CLI to the latest release.
    ///
    /// Detects how this binary was installed and upgrades it the right way:
    ///   - install script / manual download: downloads the matching release artifact, verifies its
    ///     checksum, and replaces the binary in place where the platform supports it;
    ///   - Homebrew / Cargo: shows (or, with --yes where supported, runs) the upgrade command for
    ///     that package manager;
    ///   - Docker / source build: prints how to update.
    Update(UpdateArgs),

    // The flat names below predate the command groups. They keep working but are hidden from
    // help.
    /// Alias of `s2 basin list`.
    #[command(hide = true)]
    ListBasins(ListBasinsArgs),

    /// Alias of `s2 basin create`.
    #[command(hide = true)]
    CreateBasin(CreateBasinArgs),

    /// Alias of `s2 basin delete`.
    #[command(hide = true)]
    DeleteBasin {
        /// Name of the basin to delete.
        basin: S2BasinUri,
    },

    /// Alias of `s2 basin get`.
    #[command(hide = true)]
    GetBasinConfig {
        /// Basin name to get config for.
        basin: S2BasinUri,
    },

    /// Alias of `s2 basin reconfigure`.
    #[command(hide = true)]
    ReconfigureBasin(ReconfigureBasinArgs),

    /// Alias of `s2 stream list`.
    #[command(hide = true)]
    ListStreams(ListStreamsArgs),

    /// Alias of `s2 stream create`.
    #[command(hide = true)]
    CreateStream(CreateStreamArgs),

    /// Alias of `s2 stream delete`.
    #[command(hide = true)]
    DeleteStream {
        /// S2 URI of the format: s2://{basin}/{stream}
        #[arg(value_name = "S2_URI")]
        uri: S2BasinAndStreamUri,
    },

    /// Alias of `s2 stream get`.
    #[command(hide = true)]
    GetStreamConfig {
        /// S2 URI of the format: s2://{basin}/{stream}
        #[arg(value_name = "S2_URI")]
        uri: S2BasinAndStreamUri,
    },

    /// Alias of `s2 stream reconfigure`.
    #[command(hide = true)]
    ReconfigureStream(ReconfigureStreamArgs),

    /// Alias of `s2 access-token list`.
    #[command(hide = true)]
    ListAccessTokens(ListAccessTokensArgs),

    /// Alias of `s2 access-token issue`.
    #[command(hide = true, after_help = ISSUE_ACCESS_TOKEN_EXAMPLES)]
    IssueAccessToken(Box<IssueAccessTokenArgs>),

    /// Alias of `s2 access-token revoke`.
    #[command(hide = true)]
    RevokeAccessToken {
        /// ID of the access token to revoke.
        id: AccessTokenId,
    },

    /// Alias of `s2 location list`.
    #[command(hide = true)]
    ListLocations,

    /// Alias of `s2 location get-default`.
    #[command(hide = true)]
    GetDefaultLocation,

    /// Alias of `s2 location set-default`.
    #[command(hide = true)]
    SetDefaultLocation {
        /// Location name to make the default.
        location: LocationName,
    },

    /// Alias of `s2 metrics account`.
    #[command(hide = true)]
    GetAccountMetrics(GetAccountMetricsArgs),

    /// Alias of `s2 metrics basin`.
    #[command(hide = true)]
    GetBasinMetrics(GetBasinMetricsArgs),

    /// Alias of `s2 metrics stream`.
    #[command(hide = true)]
    GetStreamMetrics(GetStreamMetricsArgs),
}

#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// Report the installed and latest versions without upgrading.
    #[arg(long, conflicts_with_all = ["skip", "yes"])]
    pub check: bool,

    /// Silence update reminders for the current latest release without
    /// upgrading.
    #[arg(long, conflicts_with = "yes")]
    pub skip: bool,

    /// Do not prompt; for Homebrew and Cargo installs, run the upgrade
    /// command directly where the running executable can be replaced.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Subcommand, Debug)]
pub enum BasinCommand {
    /// List basins.
    List(ListBasinsArgs),

    /// Create a basin.
    Create(CreateBasinArgs),

    /// Delete a basin.
    Delete {
        /// Name of the basin to delete.
        basin: S2BasinUri,
    },

    /// Get basin config.
    Get {
        /// Basin name to get config for.
        basin: S2BasinUri,
    },

    /// Reconfigure a basin.
    Reconfigure(ReconfigureBasinArgs),
}

#[derive(Subcommand, Debug)]
pub enum StreamCommand {
    /// List streams.
    List(ListStreamsArgs),

    /// Create a stream.
    Create(CreateStreamArgs),

    /// Delete a stream.
    Delete {
        /// S2 URI of the format: s2://{basin}/{stream}
        #[arg(value_name = "S2_URI")]
        uri: S2BasinAndStreamUri,
    },

    /// Get stream config.
    Get {
        /// S2 URI of the format: s2://{basin}/{stream}
        #[arg(value_name = "S2_URI")]
        uri: S2BasinAndStreamUri,
    },

    /// Reconfigure a stream.
    Reconfigure(ReconfigureStreamArgs),
}

const ISSUE_ACCESS_TOKEN_EXAMPLES: &str = "\
Examples:
  Append and read on streams `events/*` in basins `company-*`, for one day:

    s2 access-token issue my-new-token \\
      --expires-in 1d \\
      --basins-prefix \"company-\" \\
      --streams-prefix \"events/\" \\
      --ops append,read,check_tail

  Everything in the account:

    s2 access-token issue admin-token --preset full-access

  Read-only on one basin and its streams:

    s2 access-token issue reader-token --preset read-only --basins-exact my-basin

Without `--preset`, the token cannot access basins, streams or access tokens that are given \
neither a prefix nor an exact name.";

#[derive(Subcommand, Debug)]
pub enum AccessTokenCommand {
    /// List access tokens.
    List(ListAccessTokensArgs),

    /// Issue an access token.
    #[command(after_help = ISSUE_ACCESS_TOKEN_EXAMPLES)]
    Issue(Box<IssueAccessTokenArgs>),

    /// Revoke an access token.
    Revoke {
        /// ID of the access token to revoke.
        id: AccessTokenId,
    },
}

#[derive(Subcommand, Debug)]
pub enum NetworkPolicyCommand {
    /// List network policies.
    List(ListNetworkPoliciesArgs),

    /// Create a network policy.
    #[command(after_help = "\
Examples:
  s2 network-policy create office --cidr 203.0.113.0/24
  s2 network-policy create laptop --cidr 198.51.100.7/32 --cidr 2001:db8::/32
  s2 network-policy create vpc-only --aws-vpce vpce-0a1b2c3d4e5f67890")]
    Create(CreateNetworkPolicyArgs),

    /// Get a network policy.
    Get {
        /// Network policy slug, or full `<slug>.<nonce>` reference.
        id: NetworkPolicySelector,
    },

    /// Delete a network policy. It must not be bound to any access token.
    Delete {
        /// Network policy slug, or full `<slug>.<nonce>` reference.
        id: NetworkPolicySelector,
    },
}

#[derive(Subcommand, Debug)]
pub enum LocationCommand {
    /// List the locations basins can be created in.
    List,

    /// Get the default location for new basins.
    GetDefault,

    /// Set the default location for new basins.
    SetDefault {
        /// Location name to make the default.
        location: LocationName,
    },
}

#[derive(Subcommand, Debug)]
pub enum MetricsCommand {
    /// Get account metrics.
    Account(GetAccountMetricsArgs),

    /// Get basin metrics.
    Basin(GetBasinMetricsArgs),

    /// Get stream metrics.
    Stream(GetStreamMetricsArgs),
}

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Log in to S2 through your browser.
    Login(LoginArgs),

    /// Log out of the browser-authenticated S2 session.
    Logout(LogoutArgs),

    /// Show the active authentication method and verify it with S2.
    Status,

    /// Switch authentication methods without deleting either credential.
    Use {
        /// Authentication method to select.
        method: crate::config::AuthMethod,
    },

    /// Manage a stored access token.
    AccessToken {
        #[command(subcommand)]
        command: AuthAccessTokenCommand,
    },
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Print the login URL instead of opening a browser.
    ///
    /// The browser must still be able to reach this machine's loopback callback.
    #[arg(long)]
    pub no_open: bool,

    /// Maximum time to wait for browser authorization.
    #[arg(
        long,
        default_value = "20m",
        value_parser = humantime::parse_duration,
        hide = true
    )]
    pub timeout: Duration,

    /// Override the OAuth issuer.
    #[arg(long, value_name = "URL", hide = true)]
    pub issuer: Option<String>,

    /// Override the OAuth client ID.
    #[arg(long, value_name = "CLIENT_ID", hide = true)]
    pub client_id: Option<String>,

    /// Store credentials in a private file instead of the OS credential store.
    #[arg(long)]
    pub insecure_storage: bool,
}

#[derive(Args, Debug)]
pub struct LogoutArgs {
    /// Remove local credentials without attempting server-side revocation.
    #[arg(long)]
    pub local_only: bool,
}

#[derive(Subcommand, Debug)]
pub enum AuthAccessTokenCommand {
    /// Store an access token.
    Set(AuthAccessTokenSetArgs),

    /// Move a legacy plaintext access token out of the config file.
    Migrate(AuthAccessTokenMigrateArgs),

    /// Remove the locally stored access token.
    ///
    /// This does not revoke the access token.
    Remove,
}

#[derive(Args, Debug)]
pub struct AuthAccessTokenSetArgs {
    /// Read the access token from standard input instead of prompting.
    #[arg(long)]
    pub stdin: bool,

    /// Store the token in a private file instead of the OS credential store.
    #[arg(long)]
    pub insecure_storage: bool,
}

#[derive(Args, Debug)]
pub struct AuthAccessTokenMigrateArgs {
    /// Store the token in a private file instead of the OS credential store.
    #[arg(long)]
    pub insecure_storage: bool,
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// List all configuration values.
    List,
    /// Get a configuration value.
    Get {
        /// Config key
        key: crate::config::ConfigKey,
    },
    /// Set a configuration value.
    Set {
        /// Config key
        key: crate::config::ConfigKey,
        /// Value to set
        value: String,
    },
    /// Unset a configuration value.
    Unset {
        /// Config key
        key: crate::config::ConfigKey,
    },
}

impl std::fmt::Debug for ConfigCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::List => formatter.write_str("List"),
            Self::Get { key } => formatter.debug_struct("Get").field("key", key).finish(),
            Self::Set { key, value } => formatter
                .debug_struct("Set")
                .field("key", key)
                .field(
                    "value",
                    if matches!(key, crate::config::ConfigKey::AccessToken) {
                        &"<redacted>" as &dyn std::fmt::Debug
                    } else {
                        value as &dyn std::fmt::Debug
                    },
                )
                .finish(),
            Self::Unset { key } => formatter.debug_struct("Unset").field("key", key).finish(),
        }
    }
}

#[derive(Args, Debug)]
pub struct LsArgs {
    /// Name of the basin to manage or S2 URI with basin and optionally prefix.
    ///
    /// S2 URI is of the format: s2://{basin}/{prefix}
    #[arg(value_name = "BASIN|S2_URI")]
    pub uri: Option<S2BasinAndMaybeStreamUri>,

    /// Filter to names that begin with this prefix.
    #[arg(short = 'p', long)]
    pub prefix: Option<String>,

    /// Filter to names that lexicographically start after this name.
    #[arg(short = 's', long)]
    pub start_after: Option<String>,

    /// Limit the number of items to return. Acts as page size (max 1000) when using
    /// --no-auto-paginate.
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,

    /// Returns only a single page of items instead of auto-paginating.
    #[arg(long, default_value_t = false)]
    pub no_auto_paginate: bool,
}

#[derive(Args, Debug)]
pub struct ListBasinsArgs {
    /// Filter to basin names that begin with this prefix.
    #[arg(short = 'p', long)]
    pub prefix: Option<BasinNamePrefix>,

    /// Filter to basin names that lexicographically start after this name.
    #[arg(short = 's', long)]
    pub start_after: Option<BasinNameStartAfter>,

    /// Limit the number of basins to return. Acts as page size (max 1000) when using
    /// --no-auto-paginate.
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,

    /// Returns only a single page of basins instead of auto-paginating.
    #[arg(long, default_value_t = false)]
    pub no_auto_paginate: bool,
}

#[derive(Args, Debug)]
pub struct CreateBasinArgs {
    /// Name of the basin to create.
    pub basin: S2BasinUri,

    /// Physical location where the basin and all of its streams will reside, from `s2 location
    /// list`.
    ///
    /// Defaults to the account's default location. It cannot be changed after the basin is
    /// created.
    #[arg(long)]
    pub location: Option<LocationName>,

    #[command(flatten)]
    pub config: BasinConfig,
}

#[derive(Args, Debug)]
pub struct ReconfigureBasinArgs {
    /// Name of the basin to reconfigure.
    pub basin: S2BasinUri,

    /// Encryption algorithm to apply to newly created streams in this basin.
    #[arg(long)]
    pub stream_cipher: Option<EncryptionAlgorithm>,

    /// Create stream on append with basin defaults if it doesn't exist.
    #[arg(long)]
    pub create_stream_on_append: Option<bool>,

    /// Create stream on read with basin defaults if it doesn't exist.
    #[arg(long)]
    pub create_stream_on_read: Option<bool>,

    #[clap(flatten)]
    pub default_stream_config: StreamConfig,
}

#[derive(Args, Debug)]
pub struct ListAccessTokensArgs {
    /// List access tokens that begin with this prefix.
    #[arg(short = 'p', long)]
    pub prefix: Option<AccessTokenIdPrefix>,

    /// Only return access tokens that lexicographically start after this token ID.
    #[arg(short = 's', long)]
    pub start_after: Option<AccessTokenIdStartAfter>,

    /// Limit the number of access tokens to return. Acts as page size (max 1000) when using
    /// --no-auto-paginate.
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,

    /// Returns only a single page of access tokens instead of auto-paginating.
    #[arg(long, default_value_t = false)]
    pub no_auto_paginate: bool,
}

#[derive(Args, Debug)]
pub struct IssueAccessTokenArgs {
    /// Access token ID.
    pub id: AccessTokenId,

    /// Token validity duration (e.g., "30d", "1w", "24h"). Token expires after this duration from
    /// now.
    #[arg(long, conflicts_with = "expires_at")]
    pub expires_in: Option<humantime::Duration>,

    /// Absolute expiration time in RFC3339 format (e.g., "2024-12-31T23:59:59Z").
    #[arg(long, conflicts_with = "expires_in")]
    pub expires_at: Option<String>,

    /// Namespace streams based on the configured stream-level scope, which must be a prefix.
    /// Stream name arguments will be automatically prefixed, and the prefix will be stripped
    /// when listing streams.
    #[arg(long, default_value_t = false)]
    pub auto_prefix_streams: bool,

    /// Basin name prefix allowed. `""` matches all basins.
    #[arg(long, conflicts_with = "basins_exact")]
    pub basins_prefix: Option<BasinNamePrefix>,

    /// Exact basin name allowed.
    #[arg(long)]
    pub basins_exact: Option<BasinName>,

    /// Stream name prefix allowed. `""` matches all streams.
    #[arg(long, conflicts_with = "streams_exact")]
    pub streams_prefix: Option<StreamNamePrefix>,

    /// Exact stream name allowed.
    #[arg(long)]
    pub streams_exact: Option<StreamName>,

    /// Access token ID prefix allowed. `""` matches all tokens.
    #[arg(long, conflicts_with = "access_tokens_exact")]
    pub access_tokens_prefix: Option<AccessTokenIdPrefix>,

    /// Exact access token ID allowed.
    #[arg(long)]
    pub access_tokens_exact: Option<AccessTokenId>,

    /// Permissions on all basins, streams and access tokens, in place of the flags below.
    ///
    /// A `--basins-*`, `--streams-*` or `--access-tokens-*` flag narrows the preset to those
    /// resources of that kind.
    #[arg(long, conflicts_with_all = ["op_group_perms", "ops"])]
    pub preset: Option<AccessTokenPreset>,

    /// Access permissions at the operation group level.
    /// The format is: "account=rw,basin=r,stream=w"
    /// where 'r' indicates read permission and 'w' indicates write permission.
    #[arg(long)]
    pub op_group_perms: Option<PermittedOperationGroups>,

    /// Operations allowed for the token.
    /// A union of allowed operations and groups is used as an effective set of allowed operations.
    #[arg(long, value_delimiter = ',')]
    pub ops: Vec<Operation>,

    /// Slug or full `<slug>.<nonce>` reference of a network policy to restrict the token by.
    /// If the issuing token is itself restricted, the new token inherits its policy.
    #[arg(long)]
    pub network_policy: Option<NetworkPolicySelector>,
}

#[derive(Args, Debug)]
pub struct ListNetworkPoliciesArgs {
    /// List network policies whose slugs begin with this prefix.
    #[arg(short = 'p', long)]
    pub prefix: Option<NetworkPolicySlugPrefix>,

    /// Only return network policies whose slugs lexicographically start after this slug.
    #[arg(short = 's', long)]
    pub start_after: Option<NetworkPolicySlugStartAfter>,

    /// Limit the number of network policies to return. Acts as page size (max 1000) when using
    /// --no-auto-paginate.
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,

    /// Returns only a single page of network policies instead of auto-paginating.
    #[arg(long, default_value_t = false)]
    pub no_auto_paginate: bool,
}

#[derive(Args, Debug)]
#[command(group(clap::ArgGroup::new("policy").required(true).multiple(true)))]
pub struct CreateNetworkPolicyArgs {
    /// Slug, unique to the account. Up to 96 characters of letters, digits, `-` and `_`.
    pub slug: NetworkPolicySlug,

    /// Source CIDR that may use bound tokens over the public path, e.g. `203.0.113.0/24`.
    /// Repeatable. When omitted, bound tokens cannot be used over the public path.
    #[arg(long, alias = "allow-cidr", value_delimiter = ',', group = "policy")]
    pub cidr: Vec<Cidr>,

    /// AWS VPC endpoint ID through which bound tokens may be used, e.g. `vpce-0a1b2c3d4e5f67890`.
    /// Repeatable. When omitted, bound tokens cannot be used through a private network.
    #[arg(long, value_delimiter = ',', group = "policy")]
    pub aws_vpce: Vec<VpcEndpointId>,
}

#[derive(Args, Debug)]
#[command(
    override_usage = "s2 diff [OPTIONS] <LEFT> <RIGHT>",
    after_help = "Examples:\n  s2 diff s2://my-basin/left s2://my-basin/right\n  s2 diff s2://my-basin s2://my-basin/my-stream\n  s2 diff --resource basin basin-left basin-right\n  s2 diff --resource access-token token-left token-right\n  s2 diff s2://my-basin/left s2://my-basin/right --output json\n  s2 diff s2://my-basin/left s2://my-basin/right --exit-code"
)]
pub struct DiffArgs {
    /// First resource to compare.
    pub left: String,

    /// Second resource to compare.
    pub right: String,

    /// Resource type. Inferred when both resources are S2 URIs.
    #[arg(short, long, value_enum)]
    pub resource: Option<DiffResourceKind>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t)]
    pub output: DiffOutput,

    /// Exit with status 1 when differences are found.
    #[arg(long)]
    pub exit_code: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffResourceKind {
    Basin,
    Stream,
    AccessToken,
}

impl DiffResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Basin => "basin",
            Self::Stream => "stream",
            Self::AccessToken => "access-token",
        }
    }
}

#[derive(ValueEnum, Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DiffOutput {
    #[default]
    Text,
    Json,
}

#[derive(ValueEnum, Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum MetricsOutput {
    /// Human-readable tables.
    #[default]
    Pretty,
    /// The metric set as JSON, in the shape of the API response.
    Json,
}

#[derive(Args, Debug)]
pub struct ListStreamsArgs {
    /// Name of the basin to manage or S2 URI with basin and optionally prefix.
    ///
    /// S2 URI is of the format: s2://{basin}/{prefix}
    #[arg(value_name = "BASIN|S2_URI")]
    pub uri: S2BasinAndMaybeStreamUri,

    /// Filter to stream names that begin with this prefix.
    #[arg(short = 'p', long)]
    pub prefix: Option<StreamNamePrefix>,

    /// Filter to stream names that lexicographically start after this name.
    #[arg(short = 's', long)]
    pub start_after: Option<StreamNameStartAfter>,

    /// Limit the number of streams to return. Acts as page size (max 1000) when using
    /// --no-auto-paginate.
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,

    /// Returns only a single page of streams instead of auto-paginating.
    #[arg(long, default_value_t = false)]
    pub no_auto_paginate: bool,
}

#[derive(Args, Debug)]
pub struct CreateStreamArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    #[command(flatten)]
    pub config: StreamConfig,
}

#[derive(Args, Debug)]
pub struct ReconfigureStreamArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    #[clap(flatten)]
    pub config: StreamConfig,
}

#[derive(Args, Debug)]
pub struct TrimArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    /// Earliest sequence number that should be retained.
    /// This sequence number is only allowed to advance,
    /// and any regression will be ignored.
    pub trim_point: u64,

    /// Enforce fencing token.
    #[arg(short = 'f', long)]
    pub fencing_token: Option<FencingToken>,

    /// Enforce that the sequence number issued to the first record matches.
    #[arg(short = 'm', long)]
    pub match_seq_num: Option<u64>,
}

#[derive(Args, Debug)]
pub struct FenceArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    /// New fencing token.
    /// It may be upto 36 characters, and can be empty.
    pub new_fencing_token: FencingToken,

    /// Enforce existing fencing token.
    #[arg(short = 'f', long)]
    pub fencing_token: Option<FencingToken>,

    /// Enforce that the sequence number issued to this command matches.
    #[arg(short = 'm', long)]
    pub match_seq_num: Option<u64>,
}

#[derive(Args, Debug)]
pub struct AppendArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    /// Enforce fencing token.
    #[arg(short = 'f', long)]
    pub fencing_token: Option<FencingToken>,

    /// Enforce that the sequence number issued to the first record matches.
    #[arg(short = 'm', long)]
    pub match_seq_num: Option<u64>,

    /// Input format.
    #[arg(long, value_enum, default_value_t)]
    pub format: RecordFormat,

    /// Input newline delimited records to append from a file or stdin.
    /// Use "-" to read from stdin.
    #[arg(short = 'i', long, value_parser = parse_records_input_source, default_value = "-")]
    pub input: RecordsIn,

    /// How long to wait for more records before flushing a batch.
    #[arg(long, default_value = "5ms")]
    pub linger: humantime::Duration,

    #[command(flatten)]
    pub encryption_key: EncryptionKeyArgs,

    /// Stream configuration to apply if the stream is created on append.
    /// Unset fields inherit the basin's default stream configuration.
    /// Ignored if the stream already exists.
    #[command(
        flatten,
        next_help_heading = "Stream configuration (applied only if the stream is created on append)"
    )]
    pub stream_config: StreamConfig,
}

#[derive(Args, Debug, Clone, Default)]
pub struct EncryptionKeyArgs {
    /// Base64-encoded encryption key material.
    /// Alternatively, set `S2_ENCRYPTION_KEY`.
    #[arg(
        short = 'k',
        long = "encryption-key",
        env = "S2_ENCRYPTION_KEY",
        hide_env_values = true,
        value_name = "KEY",
        group = "encryption_key_source"
    )]
    pub key: Option<EncryptionKey>,

    /// Read base64-encoded encryption key material from file.
    #[arg(
        long = "encryption-key-file",
        conflicts_with = "key",
        value_name = "FILE",
        group = "encryption_key_source"
    )]
    pub key_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ReadArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    /// Starting sequence number (inclusive).
    #[arg(short = 's', long, group = "start")]
    pub seq_num: Option<u64>,

    /// Starting timestamp in milliseconds since Unix epoch (inclusive).
    #[arg(long, group = "start")]
    pub timestamp: Option<u64>,

    /// Starting timestamp as a human-friendly delta from current time e.g. "1h",
    /// which will be converted to milliseconds since Unix epoch.
    #[arg(long, group = "start")]
    pub ago: Option<humantime::Duration>,

    /// Start from N records before the tail of the stream.
    #[arg(long, group = "start")]
    pub tail_offset: Option<u64>,

    /// Limit the number of records returned.
    #[arg(short = 'n', long)]
    pub count: Option<u64>,

    /// Limit the number of bytes returned.
    #[arg(short = 'b', long)]
    pub bytes: Option<u64>,

    /// Clamp the start position at the tail position.
    #[arg(long, default_value_t = false)]
    pub clamp: bool,

    /// Exclusive end-timestamp in milliseconds since Unix epoch.
    /// If provided, results will be limited such that all records returned
    /// will have a timestamp < the one provided via `until`.
    #[arg(long)]
    pub until: Option<u64>,

    /// Output format.
    #[arg(long, value_enum, default_value_t)]
    pub format: RecordFormat,

    /// Output records to a file or stdout.
    /// Use "-" to write to stdout.
    #[arg(short = 'o', long, value_parser = parse_records_output_source, default_value = "-")]
    pub output: RecordsOut,

    #[command(flatten)]
    pub encryption_key: EncryptionKeyArgs,

    /// Stream configuration to apply if the stream is created on read.
    /// Unset fields inherit the basin's default stream configuration.
    /// Ignored if the stream already exists.
    #[command(
        flatten,
        next_help_heading = "Stream configuration (applied only if the stream is created on read)"
    )]
    pub stream_config: StreamConfig,
}

#[derive(Args, Debug)]
pub struct TailArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    /// Output the last N records instead of the default (10).
    #[arg(short = 'n', long = "lines", default_value_t = 10)]
    pub lines: u64,

    /// Follow the stream, waiting for new records to be appended.
    #[arg(short = 'f', long, default_value_t = false)]
    pub follow: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t)]
    pub format: RecordFormat,

    /// Output records to a file or stdout.
    /// Use "-" to write to stdout.
    #[arg(short = 'o', long, value_parser = parse_records_output_source, default_value = "-")]
    pub output: RecordsOut,

    #[command(flatten)]
    pub encryption_key: EncryptionKeyArgs,
}

#[derive(Args, Debug)]
pub struct ApplyArgs {
    /// Path to a JSON spec file defining basins and streams to ensure.
    #[arg(
        short = 'f',
        long,
        value_name = "FILE",
        required_unless_present = "schema"
    )]
    pub file: Option<PathBuf>,
    /// Preview changes without making any mutations.
    ///
    /// Dry-run output legend:
    ///   `+` create
    ///   `~` ensure
    ///   `=` unchanged
    ///   `?` storage-class default resolved at apply
    #[arg(long)]
    pub dry_run: bool,
    /// Print the JSON Schema for the spec file format to stdout.
    #[arg(long, conflicts_with_all = ["file", "dry_run"])]
    pub schema: bool,
}

#[derive(Args, Debug)]
pub struct BenchArgs {
    /// Name of the basin to use for the test.
    pub basin: S2BasinUri,

    /// Storage class for the test stream. Uses basin default if not specified.
    #[arg(short = 'c', long)]
    pub storage_class: Option<CompactString>,

    /// Total metered record size in bytes (includes headers and overhead).
    #[arg(
        short = 'b',
        long,
        default_value_t = 8*1024,
        value_parser = clap::value_parser!(u32).range(128..1024*1024),
    )]
    pub record_size: u32,

    /// Target write throughput in MiB/s.
    #[arg(
        short = 't',
        long,
        value_parser = clap::value_parser!(NonZeroU64),
        default_value_t = NonZeroU64::new(1).expect("non-zero")
    )]
    pub target_mibps: NonZeroU64,

    /// Run test for this duration.
    #[arg(short = 'd', long, default_value = "60s")]
    pub duration: humantime::Duration,

    /// Delay before starting the catchup read.
    #[arg(short = 'w', long, default_value = "20s")]
    pub catchup_delay: humantime::Duration,

    /// How long to wait for more records before sending a batch. Ack and end-to-end latencies
    /// include it. Defaults to none when the target is at most 200 records per second, and
    /// otherwise to 5ms, since S2 throttles a stream past 200 batches per second.
    #[arg(long)]
    pub linger: Option<humantime::Duration>,
}

/// Time range args for gauge metrics (no interval).
#[derive(Args, Debug)]
#[command(group(clap::ArgGroup::new("start_time")))]
#[command(group(clap::ArgGroup::new("end_time")))]
pub struct TimeRangeArgs {
    /// Start time in seconds since Unix epoch.
    #[arg(long = "start-timestamp", group = "start_time")]
    pub start_timestamp: Option<u32>,

    /// Start time as human-friendly delta from current time (e.g., "2h", "1d", "0s").
    /// Defaults to 30 days before the end.
    #[arg(long, group = "start_time")]
    pub start_ago: Option<humantime::Duration>,

    /// End time in seconds since Unix epoch.
    #[arg(long = "end-timestamp", group = "end_time")]
    pub end_timestamp: Option<u32>,

    /// End time as human-friendly delta from current time (e.g., "2h", "1d", "0s").
    /// Defaults to now.
    #[arg(long, group = "end_time")]
    pub end_ago: Option<humantime::Duration>,
}

/// Time range args for accumulation metrics (with interval).
#[derive(Args, Debug)]
pub struct TimeRangeAndIntervalArgs {
    #[command(flatten)]
    pub time_range: TimeRangeArgs,

    /// Show each interval, instead of the sum over the time range.
    #[arg(long)]
    pub interval: Option<Interval>,
}

/// Account metrics.
#[derive(Subcommand, Debug)]
#[command(disable_help_subcommand = true)]
pub enum AccountMetricCommand {
    /// Basins with at least one stream in the time range.
    ActiveBasins(TimeRangeArgs),
    /// Account operations by type.
    AccountOps(TimeRangeAndIntervalArgs),
    /// Estimated billable usage in US dollars by billing dimension.
    /// Counts only hours whose usage is finalized, so the most recent hours are missing.
    EstimatedBillableUsage(EstimatedBillableUsageArgs),
    /// Most recent use of each given access token, per outcome and source address.
    /// May lag by a couple of minutes.
    TokenActivity(TokenActivityArgs),
}

#[derive(Args, Debug)]
pub struct EstimatedBillableUsageArgs {
    #[command(flatten)]
    pub time_range: TimeRangeArgs,

    /// Show the total per interval, instead of each dimension summed over the time range.
    #[arg(long)]
    pub interval: Option<BillableUsageInterval>,
}

#[derive(Args, Debug)]
pub struct TokenActivityArgs {
    /// Access token IDs to look up. Tokens with no recorded use are omitted.
    #[arg(required = true, num_args = 1..=50)]
    pub token_ids: Vec<AccessTokenId>,
}

/// Basin metrics.
#[derive(Subcommand, Debug)]
#[command(disable_help_subcommand = true)]
pub enum BasinMetricCommand {
    /// Total stored bytes across all streams (hourly).
    Storage(TimeRangeArgs),
    /// Append operations by storage class.
    AppendOps(TimeRangeAndIntervalArgs),
    /// Read operations by read type.
    ReadOps(TimeRangeAndIntervalArgs),
    /// Total bytes read across all streams.
    ReadThroughput(TimeRangeAndIntervalArgs),
    /// Total bytes appended across all streams.
    AppendThroughput(TimeRangeAndIntervalArgs),
    /// Basin operations by type.
    BasinOps(TimeRangeAndIntervalArgs),
}

/// Stream metrics.
#[derive(Subcommand, Debug)]
#[command(disable_help_subcommand = true)]
pub enum StreamMetricCommand {
    /// Total stored bytes for the stream (minutely).
    Storage(TimeRangeArgs),
}

#[derive(Args, Debug)]
#[command(subcommand_value_name = "METRIC", subcommand_help_heading = "Metrics")]
pub struct GetAccountMetricsArgs {
    /// Output format.
    #[arg(short, long, value_enum, default_value_t, global = true)]
    pub output: MetricsOutput,

    #[command(subcommand)]
    pub metric: AccountMetricCommand,
}

#[derive(Args, Debug)]
#[command(subcommand_value_name = "METRIC", subcommand_help_heading = "Metrics")]
pub struct GetBasinMetricsArgs {
    /// Basin name.
    pub basin: S2BasinUri,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t, global = true)]
    pub output: MetricsOutput,

    #[command(subcommand)]
    pub metric: BasinMetricCommand,
}

#[derive(Args, Debug)]
#[command(subcommand_value_name = "METRIC", subcommand_help_heading = "Metrics")]
pub struct GetStreamMetricsArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t, global = true)]
    pub output: MetricsOutput,

    #[command(subcommand)]
    pub metric: StreamMetricCommand,
}

#[cfg(test)]
mod tests {
    use clap::{Parser, Subcommand};

    use super::{
        AccessTokenCommand, COMMAND_GROUPS, Cli, Command, DiffArgs, DiffOutput, DiffResourceKind,
        IssueAccessTokenArgs,
    };

    fn issue_access_token_args_from<I, T>(args: I) -> IssueAccessTokenArgs
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cli = Cli::try_parse_from(args).expect("cli parses");
        match cli.command {
            Some(Command::AccessToken(AccessTokenCommand::Issue(args))) => *args,
            other => panic!("unexpected command: {other:?}"),
        }
    }

    fn diff_args_from<I, T>(args: I) -> DiffArgs
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cli = Cli::try_parse_from(args).expect("cli parses");
        match cli.command {
            Some(Command::Diff(args)) => args,
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn diff_parses_basins() {
        let args = diff_args_from(["s2", "diff", "s2://left-basin", "s2://right-basin"]);

        assert_eq!(args.left, "s2://left-basin");
        assert_eq!(args.right, "s2://right-basin");
        assert!(args.resource.is_none());
        assert_eq!(args.output, DiffOutput::Text);
        assert!(!args.exit_code);
    }

    #[test]
    fn diff_parses_streams() {
        let args = diff_args_from([
            "s2",
            "diff",
            "s2://left-basin/left-stream",
            "s2://right-basin/right-stream",
        ]);

        assert_eq!(args.left, "s2://left-basin/left-stream");
        assert_eq!(args.right, "s2://right-basin/right-stream");
        assert!(args.resource.is_none());
    }

    #[test]
    fn diff_parses_explicit_access_tokens() {
        let args = diff_args_from(["s2", "diff", "--resource", "access-token", "left", "right"]);

        assert_eq!(args.left, "left");
        assert_eq!(args.right, "right");
        assert_eq!(args.resource, Some(DiffResourceKind::AccessToken));
    }

    #[test]
    fn diff_parses_explicit_basins() {
        let args = diff_args_from([
            "s2",
            "diff",
            "left-basin",
            "right-basin",
            "--resource",
            "basin",
        ]);

        assert_eq!(args.left, "left-basin");
        assert_eq!(args.right, "right-basin");
        assert_eq!(args.resource, Some(DiffResourceKind::Basin));
    }

    #[test]
    fn diff_parses_explicit_streams() {
        let args = diff_args_from([
            "s2",
            "diff",
            "--resource",
            "stream",
            "s2://left-basin/left-stream",
            "s2://right-basin/right-stream",
        ]);

        assert_eq!(args.resource, Some(DiffResourceKind::Stream));
    }

    #[test]
    fn diff_parses_json_output_and_exit_code() {
        let args = diff_args_from([
            "s2",
            "diff",
            "s2://left/stream",
            "s2://right/stream",
            "--output",
            "json",
            "--exit-code",
        ]);

        assert_eq!(args.output, DiffOutput::Json);
        assert!(args.exit_code);
    }

    // Scripts written against released CLIs use the flat names, so they must keep parsing after
    // the commands moved into groups.
    #[test]
    fn help_groups_cover_visible_commands() {
        let commands = Command::augment_subcommands(clap::Command::new("s2"));
        let mut visible: Vec<&str> = commands
            .get_subcommands()
            .filter(|command| !command.is_hide_set())
            .map(|command| command.get_name())
            .collect();
        let mut grouped: Vec<&str> = COMMAND_GROUPS
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .collect();
        visible.sort_unstable();
        grouped.sort_unstable();
        assert_eq!(grouped, visible);
    }

    #[test]
    fn released_flat_command_names_still_parse() {
        const URI: &str = "s2://my-basin/stream";
        let invocations: [&[&str]; 19] = [
            &["list-basins", "--prefix", "foo"],
            &["create-basin", "my-basin"],
            &["delete-basin", "my-basin"],
            &["get-basin-config", "my-basin"],
            &[
                "reconfigure-basin",
                "my-basin",
                "--create-stream-on-append",
                "true",
            ],
            &["list-streams", "my-basin"],
            &["create-stream", URI],
            &["delete-stream", URI],
            &["get-stream-config", URI],
            &["reconfigure-stream", URI, "--storage-class", "standard"],
            &["list-access-tokens"],
            &["issue-access-token", "my-token"],
            &["revoke-access-token", "my-token"],
            &["list-locations"],
            &["get-default-location"],
            &["set-default-location", "aws:us-east-1"],
            &["get-account-metrics", "token-activity", "my-token"],
            &[
                "get-basin-metrics",
                "my-basin",
                "storage",
                "--start-ago",
                "1h",
                "--end-ago",
                "0s",
            ],
            &[
                "get-stream-metrics",
                URI,
                "storage",
                "--start-ago",
                "1h",
                "--end-ago",
                "0s",
            ],
        ];
        for args in invocations {
            let parsed = Cli::try_parse_from(std::iter::once("s2").chain(args.iter().copied()));
            assert!(parsed.is_ok(), "{args:?}: {}", parsed.unwrap_err());
        }
    }

    #[test]
    fn issue_access_token_streams_prefix_empty_matches_all() {
        let args = issue_access_token_args_from([
            "s2",
            "access-token",
            "issue",
            "my-token",
            "--streams-prefix",
            "",
        ]);

        assert_eq!(args.streams_prefix.unwrap().to_string(), "");
        assert!(args.streams_exact.is_none());
    }

    #[test]
    fn issue_access_token_streams_prefix_accepts_leading_equals() {
        let args = issue_access_token_args_from([
            "s2",
            "access-token",
            "issue",
            "my-token",
            "--streams-prefix",
            "=tenant/",
        ]);

        assert_eq!(args.streams_prefix.unwrap().to_string(), "=tenant/");
        assert!(args.streams_exact.is_none());
    }

    #[test]
    fn issue_access_token_streams_exact_accepts_leading_equals() {
        let args = issue_access_token_args_from([
            "s2",
            "access-token",
            "issue",
            "my-token",
            "--streams-exact",
            "=stream",
        ]);

        assert_eq!(args.streams_exact.unwrap().to_string(), "=stream");
        assert!(args.streams_prefix.is_none());
    }

    #[test]
    fn issue_access_token_streams_flags_conflict() {
        let err = Cli::try_parse_from([
            "s2",
            "access-token",
            "issue",
            "my-token",
            "--streams-prefix",
            "x",
            "--streams-exact",
            "y",
        ]);

        assert!(err.is_err());
    }
}
