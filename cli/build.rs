//! Records the target triple the CLI is built for so `s2 update` can pick the
//! matching release artifact at runtime (e.g. `s2-aarch64-apple-darwin.zip`).

fn main() {
    let target = std::env::var("TARGET").expect("cargo sets TARGET for build scripts");
    println!("cargo:rustc-env=S2_TARGET={target}");
}
