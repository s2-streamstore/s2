pub use s2_lite::server::LiteArgs;

use crate::error::CliError;

pub async fn run(args: LiteArgs) -> Result<(), CliError> {
    s2_lite::server::run(args)
        .await
        .map_err(|e| CliError::LiteServer(e.to_string()))
}
