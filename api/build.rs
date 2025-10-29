fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::Config::new()
        .bytes(["."])
        .compile_protos(&["protos/s2/v1/s2.proto"], &["protos/s2/v1"])?;
    Ok(())
}
