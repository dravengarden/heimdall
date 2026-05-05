# Heimdall flake — pure-Nix build of the eBPF object, the React/MUI
# UI bundle, and the userspace daemon. `nix build` produces a binary
# byte-identical to `cargo build --release` followed by `bun run build`,
# without an external build orchestration step.
#
# Three derivations:
#
#   • heimdall-ebpf    — nightly Rust + bpfel-unknown-none + build-std,
#                        produces an ELF with embedded BTF.
#   • heimdall-ui      — Bun + Vite, produces dist/ static bundle.
#   • heimdall         — stable Rust workspace build, embeds both via
#                        include_bytes! and rust-embed.
#
# Inputs:
#   • nixpkgs unstable for current bun (≥1.2 with text bun.lock support)
#     and bpf-linker.
#   • fenix for nightly Rust pinned to heimdall-ebpf/rust-toolchain.toml
#     (its fromToolchainFile reader handles channel + components +
#     targets in one shot).
{
  description = "heimdall — transparent SOCKS5 + TLS observability for k8s pods";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # crane handles the eBPF cross-target build, specifically the
    # `-Z build-std=core` vendor which needs both heimdall-ebpf's deps
    # AND the rust-src std-library deps in a single vendor tree. stock
    # rustPlatform.buildRustPackage doesn't compose vendors that way.
    crane = {
      url = "github:ipetkov/crane";
    };
  };

  outputs = { self, nixpkgs, fenix, crane }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ fenix.overlays.default ];
      };
      lib = pkgs.lib;

      # Nightly pinned via heimdall-ebpf/rust-toolchain.toml. The
      # fakeHash gets replaced on first `nix build` — fenix prints the
      # actual hash, you paste it back in.
      rustNightly = pkgs.fenix.fromToolchainFile {
        file = ./heimdall-ebpf/rust-toolchain.toml;
        sha256 = "sha256-yeJzwn4p8HYe2nLp6fIgUvEa6Q+s9DSz8xCu/lZabUk=";
      };

      # Stable for the userspace daemon. Heimdall has no MSRV file;
      # latest stable is fine.
      rustStable = pkgs.fenix.stable.toolchain;
      rustPlatform = pkgs.makeRustPlatform {
        cargo = rustStable;
        rustc = rustStable;
      };

      # ── bpf-linker 0.10.2 from upstream ───────────────────────────────
      # nixpkgs ships 0.9.15 (LLVM 19), which can't parse the bitcode
      # rustc nightly emits (≥ LLVM 22) — link fails with "Invalid
      # record". Build 0.10.2 from source against LLVM 22 dev libs.
      bpfLinkerSrc = pkgs.fetchFromGitHub {
        owner = "aya-rs";
        repo = "bpf-linker";
        rev = "v0.10.2";
        hash = "sha256-jtTDjbE2F5uj9lSTO0CuOY0fXp5IZKKMJBgAStk0c48=";
      };
      # bpf-linker's build.rs treats LLVM_PREFIX as a single
      # "complete" install (expects bin/llvm-config + lib/libLLVM.so
      # + share/cmake under one tree). nixpkgs splits these across
      # llvm.dev / llvm.lib / llvm outputs. Stitch them back via
      # symlinkJoin so the build.rs sees what it expects.
      llvm22-combined = pkgs.symlinkJoin {
        name = "llvm-22-combined";
        paths = [
          pkgs.llvmPackages_22.llvm
          pkgs.llvmPackages_22.llvm.dev
          pkgs.llvmPackages_22.llvm.lib
        ];
      };
      bpf-linker = rustPlatform.buildRustPackage {
        pname = "bpf-linker";
        version = "0.10.2";
        src = bpfLinkerSrc;

        cargoLock = {
          lockFile = "${bpfLinkerSrc}/Cargo.lock";
          # bpf-linker pulls compiletest-rs from a git rev (not yet
          # released to crates.io with the patch they need). importCargoLock
          # needs a hash for it.
          outputHashes = {
            "compiletest_rs-0.11.2" =
              "sha256-RaRXhEwfovb0FMePsZ+gHx+T19XsrWxBkNoDXjL7hWg=";
          };
        };

        nativeBuildInputs = [
          pkgs.llvmPackages_22.llvm.dev
          # llvm-sys' build.rs invokes `clang` for bindgen + linking
          # checks. Use the matching clang version.
          pkgs.llvmPackages_22.clang
        ];
        buildInputs = [
          pkgs.llvmPackages_22.llvm
          pkgs.libxml2
          pkgs.zlib
          pkgs.ncurses
        ];
        # Both env vars point at the merged tree; llvm-sys uses
        # llvm-config (bin/), bpf-linker also wants libLLVM.so (lib/)
        # in the same prefix.
        LLVM_SYS_220_PREFIX = llvm22-combined;
        LLVM_PREFIX = llvm22-combined;

        # Disable the `rust-llvm-22` default feature: it pulls in
        # `aya-rustc-llvm-proxy`, whose build.rs spawns a nested
        # `cargo metadata` call that fights with Nix's vendor layout
        # (`failed to read /build/cargo-vendor-dir/cargo-vendor-dir`).
        # The proxy exists to dynamic-link rustc's bundled LLVM at
        # runtime so users don't need separate LLVM; we have the
        # nixpkgs llvm-22 right there, no need.
        buildNoDefaultFeatures = true;
        buildFeatures = [ "llvm-22" ];

        # Burn the LLVM 22 lib path into the binary's rpath. nixpkgs
        # splits LLVM into `lib`/`dev`/`out` outputs; the linker only
        # sees the merged prefix at build time, but the resulting
        # binary needs to find libLLVM-22-rc3.so at runtime, and the
        # split-output prefix isn't on the default loader path.
        RUSTFLAGS = "-C link-args=-Wl,-rpath,${pkgs.llvmPackages_22.llvm.lib}/lib";

        # Skip tests — bpf-linker's tests require a full eBPF
        # toolchain + qemu, not relevant for our use.
        doCheck = false;

        meta.mainProgram = "bpf-linker";
      };

      # ── heimdall-ebpf: nightly + build-std + bpfel target ─────────────
      # crane's lib pinned to the nightly toolchain so cargo's
      # `-Z build-std=core` is accepted. Crane's
      # `vendorMultipleCargoDeps` is the trick that makes this work
      # in pure-Nix sandbox: it vendors both heimdall-ebpf's
      # crates.io deps AND the rust-src std-library deps in one tree,
      # so cargo with build-std can resolve everything offline.
      craneLib = (crane.mkLib pkgs).overrideToolchain rustNightly;

      ebpfSrc = pkgs.runCommand "heimdall-ebpf-src" {} ''
        mkdir -p $out
        cp -r ${./heimdall-ebpf} $out/heimdall-ebpf
        cp -r ${./heimdall-common} $out/heimdall-common
        cp ${./heimdall-ebpf/Cargo.lock} $out/Cargo.lock
        # Mirror heimdall-ebpf/.cargo/config.toml at the src root so
        # crane's cargo invocation (run from src root, not the
        # heimdall-ebpf/ subdir) picks up `target =
        # "bpfel-unknown-none"`, the BTF rustflags, and `build-std =
        # ["core"]`. Cargo only auto-discovers .cargo/config.toml from
        # the CWD upward; the manifest-path doesn't change that.
        mkdir -p $out/.cargo
        cp ${./heimdall-ebpf/.cargo/config.toml} $out/.cargo/config.toml
        chmod -R u+w $out
      '';

      heimdall-ebpf = craneLib.buildPackage {
        pname = "heimdall-ebpf";
        version = "0.1.0";

        src = ebpfSrc;

        # Compose two lockfiles into one vendor: heimdall-ebpf's own
        # crates.io deps + rust-src's std-library deps. Without the
        # second one, cargo errors with "no matching package named
        # `rustc-literal-escaper` found" — that's a transitive dep
        # of `proc_macro` from build-std=core.
        cargoVendorDir = craneLib.vendorMultipleCargoDeps {
          cargoLockList = [
            ./heimdall-ebpf/Cargo.lock
            "${rustNightly}/lib/rustlib/src/rust/library/Cargo.lock"
          ];
        };

        # cargo runs from `heimdall-ebpf/` to pick up its own
        # `.cargo/config.toml` (target = bpfel-unknown-none, build-std
        # = ["core"], BTF-emitting rustflags).
        cargoExtraArgs = "--manifest-path heimdall-ebpf/Cargo.toml";
        CARGO_BUILD_TARGET = "bpfel-unknown-none";

        # Use our locally-built bpf-linker 0.10.2 (LLVM 22), not
        # nixpkgs' 0.9.15 (LLVM 19) which can't parse current
        # nightly rustc bitcode.
        nativeBuildInputs = [ bpf-linker ];

        # Skip cargo check — heimdall-ebpf has no host-runnable tests
        # (no_std bpfel binary).
        doCheck = false;

        # The ELF carries BTF; don't let nixpkgs strip it or aya
        # can't load the maps. patchELF would also corrupt the eBPF
        # section layout that the kernel verifier relies on.
        dontStrip = true;
        dontPatchELF = true;
        # Skip crane's automatic "install from cargoBuildLog" hook —
        # it tries to derive bin paths via `cargo metadata` from the
        # src root, which only has heimdall-common's manifest at root,
        # not heimdall-ebpf's. We grab the artifact directly instead.
        doNotPostBuildInstallCargoBinaries = true;
        # Locate the built eBPF object — crane's target dir layout
        # shifts between versions; find by name across the release
        # output directory.
        installPhase = ''
          runHook preInstall
          mkdir -p $out
          # Crane builds out-of-tree by default; the artifact lives
          # under heimdall-ebpf/target (because cargo runs with
          # --manifest-path heimdall-ebpf/Cargo.toml from src root).
          artifact=$(find heimdall-ebpf/target target /build -type f \
            -name heimdall-ebpf -path "*release*" 2>/dev/null | head -1)
          if [ -z "$artifact" ]; then
            echo "ERROR: heimdall-ebpf binary not found" >&2
            find . /build -type f -name 'heimdall-ebpf*' 2>/dev/null \
              | grep -v 'src\|/proc/' | head -20 >&2 || true
            exit 1
          fi
          echo "Installing $artifact"
          cp "$artifact" $out/heimdall-ebpf
          runHook postInstall
        '';
      };

      # ── heimdall-ui: bun install + vite build ─────────────────────────
      # Two-stage: a fixed-output FOD that runs `bun install` (needs
      # network for npm registry), then an offline `bun run build`.
      # Single-step UI build inside one fixed-output derivation: bun
      # install + bun run build, with network access (FOD allows it),
      # outputs the dist/ tree. Avoids the two-stage FOD-then-build
      # split where copying the deps tree out of the FOD lost file
      # contents under Nix's read-only mount semantics.
      heimdall-ui = pkgs.stdenv.mkDerivation {
        pname = "heimdall-ui";
        version = "0.1.0";

        src = lib.cleanSourceWith {
          src = ./heimdall-ui;
          filter = path: type:
            let base = baseNameOf (toString path); in
            !(builtins.elem base [ "node_modules" "dist" ]);
        };

        # nodejs is required because vite.js starts with `#!/usr/bin/env
        # node` — even though `bun --bun` says "use bun runtime",
        # bun still spawns the script via posix_spawn, which means
        # the kernel honors the shebang and looks up `node` in PATH.
        nativeBuildInputs = [ pkgs.bun pkgs.nodejs pkgs.cacert ];

        buildPhase = ''
          runHook preBuild
          export HOME=$TMPDIR
          export NODE_ENV=development
          bun install --frozen-lockfile --no-progress
          # Invoke vite directly via bun on the entry script. Going
          # through `bun run build` (= `bun --bun vite build`) hits a
          # bug in the inner bun's posix_spawn lookup that returns
          # ENOENT on `node_modules/.bin/vite` even though the symlink
          # exists. Direct invocation sidesteps the script-resolver
          # path.
          bun ./node_modules/vite/bin/vite.js build
          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall
          # rust-embed reads `../heimdall-ui/dist/`, so $out is
          # exactly the dist contents, no extra wrapping.
          cp -r dist $out
          runHook postInstall
        '';

        dontPatchShebangs = true;
        dontFixup = true;

        outputHashMode = "recursive";
        outputHashAlgo = "sha256";
        outputHash = "sha256-rLF5x+xveSEg3hD5swGJP71BkGjsFrTasK6zQMlwPjo=";
      };

      # ── heimdall: workspace daemon, embeds the two artifacts above ────
      heimdall = rustPlatform.buildRustPackage {
        pname = "heimdall";
        version = "0.1.0";

        src = lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let base = baseNameOf (toString path); in
            !(builtins.elem base [
              "target" "result" "node_modules" "dist"
            ]);
        };

        cargoLock.lockFile = ./Cargo.lock;

        # Place the eBPF object and UI bundle at the literal paths
        # heimdall/src/main.rs and api.rs expect (include_bytes! and
        # rust-embed are compile-time relative-path lookups).
        preBuild = ''
          mkdir -p heimdall-ebpf/target/bpfel-unknown-none/release
          cp ${heimdall-ebpf}/heimdall-ebpf \
             heimdall-ebpf/target/bpfel-unknown-none/release/heimdall-ebpf
          mkdir -p heimdall-ui/dist
          cp -r ${heimdall-ui}/. heimdall-ui/dist/
        '';

        cargoBuildFlags = [ "--bin" "heimdall" "--package" "heimdall" ];

        # Tests touch /proc, /sys/fs/cgroup, and require root for the
        # eBPF / sqlite paths; not viable inside the sandbox.
        doCheck = false;

        meta = with lib; {
          description = "Transparent SOCKS5 + TLS observability for Kubernetes pods";
          mainProgram = "heimdall";
          platforms = platforms.linux;
          license = licenses.asl20;
        };
      };
    in {
      packages.${system} = {
        inherit heimdall heimdall-ebpf heimdall-ui bpf-linker;
        default = heimdall;
      };

      # `nix develop` shell with everything needed to iterate locally —
      # nightly for eBPF, stable for userspace, bun for UI, plus the
      # surrounding tooling the runbook expects.
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          rustNightly
          rustStable
          pkgs.bpf-linker
          pkgs.bun
          pkgs.pkg-config
          pkgs.cargo-watch
          pkgs.bpftool
        ];
      };
    };
}
