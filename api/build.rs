fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::Config::new()
        .bytes(["."])
        .compile_protos(&["specs/s2/v1/s2.proto"], &["specs/s2/v1"])?;
    Ok(())
}
