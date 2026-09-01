use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=interpose/interpose.c");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=HEIMDALL_INTERPOSE_CC");
    println!("cargo:rerun-if-env-changed=HEIMDALL_INTERPOSE_SIGNING_IDENTITY_SHA1");

    let target = env::var("TARGET").expect("Cargo sets TARGET");
    let host = env::var("HOST").expect("Cargo sets HOST");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo sets target OS");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo sets target architecture");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));

    let file_name = match target_os.as_str() {
        "linux" => "libheimdall_interpose.so",
        "macos" => "libheimdall_interpose.dylib",
        other => panic!("Heimdall does not support interposition on {other}"),
    };
    let artifact = output.join(file_name);
    println!("cargo:rustc-env=HEIMDALL_INTERPOSE_LIBRARY_NAME={file_name}");

    // Why: Linux CI type-checks Darwin without an Apple SDK. The placeholder
    // keeps Rust target selection honest; native packaging must replace it
    // with a signed Mach-O artifact before the backend can become available.
    if target_os == "macos" && target != host {
        fs::write(&artifact, b"HEIMDALL_INTERPOSE_NATIVE_BUILD_REQUIRED")
            .expect("write Darwin cross-check placeholder");
        println!("cargo:rustc-env=HEIMDALL_INTERPOSE_ARTIFACT_KIND=cross-check-placeholder");
        return;
    }

    let source = PathBuf::from("interpose/interpose.c");
    let explicit_compiler = env::var_os("HEIMDALL_INTERPOSE_CC").or_else(|| env::var_os("CC"));
    let mut command = if target_os == "macos" && explicit_compiler.is_none() {
        let mut command = Command::new("xcrun");
        command.arg("clang");
        command
    } else {
        Command::new(explicit_compiler.unwrap_or_else(|| "cc".into()))
    };
    command.env("NIX_LDFLAGS", "");
    command.args([
        "-O2",
        "-g0",
        "-fPIC",
        "-fno-stack-protector",
        "-Wall",
        "-Wextra",
        "-Werror",
    ]);

    if target_os == "linux" {
        command.args([
            "-shared",
            "-nostdlib",
            "-nodefaultlibs",
            "-Wl,-z,relro,-z,now",
            "-Wl,-soname,libheimdall_interpose.so",
        ]);
    } else {
        command.args([
            "-dynamiclib",
            "-mmacosx-version-min=11.0",
            "-Wl,-install_name,@rpath/libheimdall_interpose.dylib",
            "-arch",
            match target_arch.as_str() {
                "aarch64" => "arm64",
                "x86_64" => "x86_64",
                other => panic!("unsupported macOS interpose architecture {other}"),
            },
        ]);
    }
    command.arg(&source).arg("-o").arg(&artifact);
    let status = command.status().expect("run interpose C compiler");
    assert!(status.success(), "interpose C compiler failed");

    if target_os == "macos" {
        let identity =
            env::var("HEIMDALL_INTERPOSE_SIGNING_IDENTITY_SHA1").unwrap_or_else(|_| "-".into());
        let mut codesign = Command::new("codesign");
        codesign.args(["--force", "--sign", &identity]);
        if identity != "-" {
            codesign.arg("--timestamp");
        }
        let status = codesign
            .arg(&artifact)
            .status()
            .expect("sign embedded interpose library");
        assert!(
            status.success(),
            "signing embedded interpose library failed"
        );
    }

    println!("cargo:rustc-env=HEIMDALL_INTERPOSE_ARTIFACT_KIND=native");
}
