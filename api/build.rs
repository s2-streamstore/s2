fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "codegen")]
    {
        prost_build::Config::new()
            .bytes(["."])
            .out_dir("src/v1/stream/proto")
            .compile_protos(&["protos/s2/v1/s2.proto"], &["protos/s2/v1"])?;
    }
    Ok(())
}
