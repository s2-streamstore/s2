use s2_sdk::{S2, types::ListAllBasinsInput};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let s2 = S2::from_env()?;

    let mut stream = s2.list_all_basins(ListAllBasinsInput::new());
    let mut basins = Vec::new();
    while basins.len() < 10
        && let Some(basin) = stream.next().await
    {
        basins.push(basin?);
    }

    println!("{basins:#?}");

    Ok(())
}
