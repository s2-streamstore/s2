use s2_sdk::{
    S2,
    types::{BasinName, ListStreamsInput},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let basin_name: BasinName = std::env::var("S2_BASIN")
        .map_err(|_| "S2_BASIN env var not set")?
        .parse()?;

    let s2 = S2::from_env()?;
    let basin = s2.basin(basin_name);

    let input = ListStreamsInput::new().with_prefix("my-".parse()?);
    let page = basin.list_streams(input).await?;
    println!("{page:#?}");

    Ok(())
}
