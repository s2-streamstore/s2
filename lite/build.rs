use std::path::Path;

fn main() {
    let dist = Path::new(env!("CARGO_MANIFEST_DIR")).join("dashboard/apps/lite/dist");
    println!("cargo:rerun-if-changed={}", dist.display());
    if !dist.join("index.html").is_file() {
        panic!(
            "the dashboard bundle is missing at {}.\n\
             `lite/dashboard` is a git submodule; run `git submodule update --init lite/dashboard` \
             (or `git pull --recurse-submodules`) and build again.",
            dist.display()
        );
    }
}
