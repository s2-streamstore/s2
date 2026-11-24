use s2_sdk::{S2, types::BasinName};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let basin_name: BasinName = std::env::var("S2_BASIN")
        .map_err(|_| "S2_BASIN env var not set")?
        .parse()?;

    let s2 = S2::from_env()?;

    s2.delete_basin(basin_name).await?;
    println!("Deletion requested");

    Ok(())
}
