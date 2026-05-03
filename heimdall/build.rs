//! Build helper: keep the vendored DaisyUI CSS files in sync with the
//! Dioxus `dist/` output directory before `rust-embed` bundles it in.
//!
//! This script is best-effort: if the Dioxus build output isn't there yet
//! (first build before `dx build`), it just prints a warning and the
//! daemon ships an empty UI bundle (404s on `/`).

use std::{fs, path::PathBuf};

fn main() {
    let dist = PathBuf::from("../heimdall-ui/target/dx/heimdall-ui/release/web/public/assets");
    let src = PathBuf::from("../heimdall-ui/assets");

    println!("cargo:rerun-if-changed={}", src.join("daisyui-full.min.css").display());
    println!("cargo:rerun-if-changed={}", src.join("daisyui-themes.min.css").display());
    println!("cargo:rerun-if-changed=../heimdall-ui/target/dx/heimdall-ui/release/web/public/index.html");

    if !dist.exists() {
        println!(
            "cargo:warning=heimdall-ui dist not found at {} — UI will be empty. Run `cd heimdall-ui && dx build --platform web --release`.",
            dist.display()
        );
        return;
    }

    for name in ["daisyui-full.min.css", "daisyui-themes.min.css"] {
        let from = src.join(name);
        let to = dist.join(name);
        if from.exists() && (!to.exists() || file_differs(&from, &to)) {
            if let Err(e) = fs::copy(&from, &to) {
                println!("cargo:warning=failed to copy {} → {}: {e}", from.display(), to.display());
            }
        }
    }
}

fn file_differs(a: &std::path::Path, b: &std::path::Path) -> bool {
    let am = fs::metadata(a).ok().and_then(|m| m.modified().ok());
    let bm = fs::metadata(b).ok().and_then(|m| m.modified().ok());
    match (am, bm) {
        (Some(a), Some(b)) => a > b,
        _ => true,
    }
}
