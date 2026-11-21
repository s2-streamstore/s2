use s2_sdk::{
    S2,
    types::{BasinName, S2Config},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let access_token =
        std::env::var("S2_ACCESS_TOKEN").map_err(|_| "S2_ACCESS_TOKEN env var not set")?;
    let basin_name: BasinName = std::env::var("S2_BASIN")
        .map_err(|_| "S2_BASIN env var not set")?
        .parse()?;

    let config = S2Config::new(access_token);
    let s2 = S2::new(config)?;

    s2.delete_basin(basin_name).await?;
    println!("Deletion requested");

    Ok(())
}
