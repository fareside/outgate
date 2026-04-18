use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let snapshot_path = out_dir.join("DENO_SNAPSHOT.bin");

    deno_runtime::snapshot::create_runtime_snapshot(snapshot_path, Default::default(), vec![]);

    println!("cargo:rerun-if-changed=build.rs");
}
