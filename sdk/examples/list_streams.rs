use s2_sdk::{
    S2,
    types::{BasinName, ListStreamsInput, S2Config},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let access_token =
        std::env::var("S2_ACCESS_TOKEN").map_err(|_| "S2_ACCESS_TOKEN env var not set")?;
    let basin_name: BasinName = std::env::var("S2_BASIN")
        .map_err(|_| "S2_BASIN env var not set")?
        .parse()?;

    let s2 = S2::new(S2Config::new(access_token))?;
    let basin = s2.basin(basin_name);

    let input = ListStreamsInput::new().with_prefix("my-".parse()?);
    let page = basin.list_streams(input).await?;
    println!("{page:#?}");

    Ok(())
}
