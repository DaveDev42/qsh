//! Compiles `proto/qsh/wire/v1.proto` with `protox` (a pure-Rust protobuf
//! compiler) + `prost-build`, so no `protoc` binary is needed on dev or CI
//! machines. Generated code lands in `$OUT_DIR/qsh.wire.v1.rs` and is
//! included by `src/wire.rs`.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join("proto");
    let proto_file = proto_root.join("qsh/wire/v1.proto");

    println!("cargo:rerun-if-changed={}", proto_file.display());
    println!("cargo:rerun-if-changed=build.rs");

    let file_descriptors = protox::compile([&proto_file], [&proto_root])?;

    // prost-build already derives `Eq`/`Hash` wherever the message allows
    // it, so property tests can compare decoded values directly. `bytes`
    // fields stay `Vec<u8>` (the default), keeping the sans-IO crate free of
    // `bytes::Bytes` in its public API.
    prost_build::Config::new().compile_fds(file_descriptors)?;
    Ok(())
}
