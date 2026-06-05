# Heimdall flake — pure-Nix build of the eBPF object, the React/MUI
# UI bundle, and the userspace daemon. `nix build` produces a binary
# byte-identical to `cargo build --release` followed by `deno task build`,
# without an external build orchestration step.
#
# Three derivations:
#
#   • heimdall-ebpf    — nightly Rust + bpfel-unknown-none + build-std,
#                        produces an ELF with embedded BTF.
#   • heimdall-ui      — Deno + Vite, produces dist/ static bundle.
#   • heimdall         — stable Rust workspace build, embeds both via
#                        include_bytes! and rust-embed.
#
# Inputs:
#   • nixpkgs unstable for bpf-linker; the UI toolchain is a vendored
#     Deno 2.8.1 prebuilt (see the `deno` derivation below).
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
    # Shared Nix builders (buildDenoViteApp) from the public shared-utils
    # monorepo. The UI bundle is built via that shared builder — NOT a
    # hand-rolled FOD here — so source changes always rebuild instead of
    # silently reusing a stale dist.
    shared-utils.url = "github:dravengarden/shared-utils";
    shared-utils.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, fenix, crane, shared-utils }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ fenix.overlays.default ];
      };
      lib = pkgs.lib;
      shared = shared-utils.lib.${system};

      # Deno 2.8.1 — nixpkgs `nixos-unstable` only ships 2.7.14 today, so we
      # pull the official prebuilt binary directly (fetchurl → unzip →
      # autoPatchelfHook fixes the dynamic linker). Once nixpkgs catches up,
      # delete this and use `pkgs.deno`. Matches the pin used by every other
      # columbus project (cowboy/omega/liveview/dashboard/theia/argus).
      deno = pkgs.stdenvNoCC.mkDerivation rec {
        pname = "deno";
        version = "2.8.1";
        src = pkgs.fetchurl {
          url = "https://github.com/denoland/deno/releases/download/v${version}/deno-x86_64-unknown-linux-gnu.zip";
          hash = "sha256-LXu2GVImrIMuC/cQmhFfCvZe5prHl6S73lsnoGzCQtk=";
        };
        nativeBuildInputs = [ pkgs.unzip pkgs.autoPatchelfHook ];
        buildInputs = [ pkgs.stdenv.cc.cc.lib pkgs.zlib ];
        unpackPhase = "unzip $src";
        installPhase = "install -Dm755 deno $out/bin/deno";
        meta.mainProgram = "deno";
      };

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

      # ── heimdall-ui: deno install + vite build ────────────────────────
      # Built through shared-utils' footgun-free `buildDenoViteApp` — NOT a
      # hand-rolled FOD. The old shape wrapped the whole `deno install + vite
      # build` in a single fixed-output derivation, addressed ONLY by its
      # declared outputHash; but the bundle's bytes vary with source, so Nix
      # reused the cached dist whenever the hash wasn't manually rebumped and
      # silently embedded a STALE UI. The builder splits that into a deps-only
      # FOD (keyed by the lockfiles → depsHash) + a normal content-addressed
      # offline build, so any UI source edit rebuilds automatically.
      #
      # stageShell = false: heimdall-ui has its own SDK (no shared
      # @shared-utils/ui _shell seam). installArgs preserves --allow-scripts
      # (esbuild's npm postinstall fetches its platform binary) + --frozen
      # (deno.lock is committed). webRoot = heimdall-ui (deno.json/dist live
      # there). depsHash refreshes only when heimdall-ui's deno.lock /
      # package.json change (lib.fakeHash → build → copy "got").
      heimdall-ui = shared.buildDenoViteApp {
        pname = "heimdall";
        version = "0.1.0";
        src = pkgs.lib.cleanSource ./.;
        webRoot = "heimdall-ui";
        stageShell = false;
        installArgs = "--frozen --allow-scripts";
        depsHash = "sha256-N5g70zrmsXg8odNLDfxllgBoaFhN20JKec1QE22XyUc=";
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
        inherit heimdall heimdall-ebpf heimdall-ui bpf-linker deno;
        default = heimdall;
      };

      # `nix develop` shell with everything needed to iterate locally —
      # nightly for eBPF, stable for userspace, deno for UI, plus the
      # surrounding tooling the runbook expects.
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          rustNightly
          rustStable
          pkgs.bpf-linker
          deno
          pkgs.nodejs_24
          pkgs.pkg-config
          pkgs.cargo-watch
          pkgs.bpftools
          pkgs.nickel
        ];
      };
    };
}
