fn main() -> Result<(), Box<dyn std::error::Error>> {
    let compiler = protoc_bin_vendored::protoc_bin_path()?;
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(&compiler);
    tonic_prost_build::configure().compile_with_config(
        config,
        &["../../packages/contracts/proto/nex/guard/v1/guard.proto"],
        &["../../packages/contracts/proto"],
    )?;
    println!("cargo:rerun-if-changed=../../packages/contracts/proto/nex/guard/v1/guard.proto");
    Ok(())
}
