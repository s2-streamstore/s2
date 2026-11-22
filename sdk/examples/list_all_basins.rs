use futures_util::{StreamExt, TryStreamExt};
use s2_sdk::{S2, types::ListAllBasinsInput};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let s2 = S2::from_env()?;

    let input = ListAllBasinsInput::new();

    let basins: Vec<_> = s2.list_all_basins(input).take(10).try_collect().await?;

    println!("{basins:#?}");

    Ok(())
}
