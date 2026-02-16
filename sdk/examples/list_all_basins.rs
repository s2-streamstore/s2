use futures::{StreamExt, TryStreamExt};
use s2_sdk::{
    S2,
    types::{ListAllBasinsInput, S2Config},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let access_token =
        std::env::var("S2_ACCESS_TOKEN").map_err(|_| "S2_ACCESS_TOKEN env var not set")?;

    let config = S2Config::new(access_token);
    let s2 = S2::new(config)?;

    let input = ListAllBasinsInput::new();

    let basins: Vec<_> = s2.list_all_basins(input).take(10).try_collect().await?;

    println!("{basins:#?}");

    Ok(())
}
