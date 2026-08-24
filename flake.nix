# Heimdall flake — pure-Nix build of the eBPF object and foreground CLI.
#
# Principal derivations:
#
#   • heimdall-ebpf    — nightly Rust + bpfel-unknown-none + build-std,
#                        produces an ELF with embedded BTF.
#   • heimdall         — stable Rust workspace build, embeds the eBPF ELF.
#   • heimdall-static  — generic musl-linked Linux CLI for release archives.
#
# Inputs:
#   • nixpkgs unstable for bpf-linker.
#   • fenix for nightly Rust pinned to heimdall-ebpf/rust-toolchain.toml
#     (its fromToolchainFile reader handles channel + components +
#     targets in one shot).
{
  description = "heimdall — proxychains-style SOCKS5 wrapper using cgroup eBPF";

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

  outputs =
    {
      self,
      nixpkgs,
      fenix,
      crane,
    }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ fenix.overlays.default ];
      };
      lib = pkgs.lib;
      heimdallVersion = "0.1.2";
      heimdallSrc = lib.cleanSourceWith {
        src = ./.;
        filter =
          path: type:
          let
            base = baseNameOf (toString path);
          in
          !(builtins.elem base [
            "target"
            "result"
            "node_modules"
            "dist"
          ]);
      };

      # Nightly pinned via heimdall-ebpf/rust-toolchain.toml. The
      # fakeHash gets replaced on first `nix build` — fenix prints the
      # actual hash, you paste it back in.
      rustNightly = pkgs.fenix.fromToolchainFile {
        file = ./heimdall-ebpf/rust-toolchain.toml;
        sha256 = "sha256-yeJzwn4p8HYe2nLp6fIgUvEa6Q+s9DSz8xCu/lZabUk=";
      };

      # Stable userspace Rust is independent from the eBPF nightly. Pinning the
      # minimal toolchain prevents a flake update from silently changing the
      # compiler and avoids materializing documentation components in the dev
      # shell.
      rustStable = pkgs.fenix.fromToolchainFile {
        file = ./rust-toolchain.toml;
        sha256 = "sha256-gh/xTkxKHL4eiRXzWv8KP7vfjSk61Iq48x47BEDFgfk=";
      };
      rustPlatform = pkgs.makeRustPlatform {
        cargo = rustStable;
        rustc = rustStable;
      };
      staticRustPlatform = pkgs.pkgsStatic.makeRustPlatform {
        cargo = rustStable;
        rustc = rustStable;
      };
      aarch64MuslPkgs = pkgs.pkgsCross.aarch64-multiplatform-musl;
      aarch64StaticRustPlatform = aarch64MuslPkgs.pkgsStatic.makeRustPlatform {
        cargo = rustStable;
        rustc = rustStable;
      };

      # Cargo's `+toolchain` syntax is implemented by rustup, which is not part
      # of this Nix shell. Keep the exceptional eBPF compiler explicit while
      # leaving ordinary `cargo` and `rustc` on stable.
      cargoNightly = pkgs.writeShellScriptBin "cargo-nightly" ''
        export RUSTC=${rustNightly}/bin/rustc
        export RUSTDOC=${rustNightly}/bin/rustdoc
        exec ${rustNightly}/bin/cargo "$@"
      '';

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
            "compiletest_rs-0.11.2" = "sha256-RaRXhEwfovb0FMePsZ+gHx+T19XsrWxBkNoDXjL7hWg=";
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

      ebpfSrc = pkgs.runCommand "heimdall-ebpf-src" { } ''
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
        version = "0.1.2";

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

      # ── heimdall: foreground CLI, embeds the eBPF artifact ─────────
      heimdall = rustPlatform.buildRustPackage {
        pname = "heimdall";
        version = heimdallVersion;
        src = heimdallSrc;

        cargoLock.lockFile = ./Cargo.lock;

        # Place the eBPF object at the path used by include_bytes!.
        preBuild = ''
          mkdir -p heimdall-ebpf/target/bpfel-unknown-none/release
          cp ${heimdall-ebpf}/heimdall-ebpf \
             heimdall-ebpf/target/bpfel-unknown-none/release/heimdall-ebpf
        '';

        cargoBuildFlags = [
          "--bin"
          "heimdall"
          "--package"
          "heimdall"
        ];

        # Tests touch /proc, /sys/fs/cgroup, and require root for the
        # eBPF / sqlite paths; not viable inside the sandbox.
        doCheck = false;

        meta = with lib; {
          description = "Proxychains-style SOCKS5 wrapper using cgroup eBPF";
          mainProgram = "heimdall";
          platforms = platforms.linux;
          license = licenses.asl20;
        };
      };

      # Generic Linux release artifact. The userspace executable is linked
      # against musl while retaining the same embedded, separately built eBPF
      # object as the ordinary Nix package.
      heimdall-static = staticRustPlatform.buildRustPackage {
        pname = "heimdall-static";
        version = heimdallVersion;
        src = heimdallSrc;

        cargoLock.lockFile = ./Cargo.lock;
        preBuild = ''
          mkdir -p heimdall-ebpf/target/bpfel-unknown-none/release
          cp ${heimdall-ebpf}/heimdall-ebpf \
             heimdall-ebpf/target/bpfel-unknown-none/release/heimdall-ebpf
        '';
        cargoBuildFlags = [
          "--bin"
          "heimdall"
          "--package"
          "heimdall"
        ];
        doCheck = false;

        meta = with lib; {
          description = "Static Heimdall Linux CLI with embedded eBPF";
          mainProgram = "heimdall";
          platforms = [ "x86_64-linux" ];
          license = licenses.asl20;
        };
      };

      heimdall-static-aarch64 = aarch64StaticRustPlatform.buildRustPackage {
        pname = "heimdall-static-aarch64";
        version = heimdallVersion;
        src = heimdallSrc;

        cargoLock.lockFile = ./Cargo.lock;
        preBuild = ''
          mkdir -p heimdall-ebpf/target/bpfel-unknown-none/release
          cp ${heimdall-ebpf}/heimdall-ebpf \
             heimdall-ebpf/target/bpfel-unknown-none/release/heimdall-ebpf
        '';
        cargoBuildFlags = [
          "--bin"
          "heimdall"
          "--package"
          "heimdall"
        ];
        doCheck = false;

        meta = with lib; {
          description = "Static aarch64 Heimdall Linux CLI with embedded eBPF";
          mainProgram = "heimdall";
          platforms = [ "aarch64-linux" ];
          license = licenses.asl20;
        };
      };

      releaseBundle =
        pkgs.runCommand "heimdall-egress-${heimdallVersion}-x86_64-linux-musl"
          {
            version = heimdallVersion;
            nativeBuildInputs = [
              pkgs.coreutils
              pkgs.gnutar
              pkgs.gzip
            ];
          }
          ''
            archive_root=heimdall-egress-${heimdallVersion}-x86_64-linux-musl
            mkdir -p "$out" "$archive_root"
            install -m 0755 ${heimdall-static}/bin/heimdall "$archive_root/heimdall"
            substitute ${./packaging/heimdall-install} "$archive_root/heimdall-install" \
              --replace-fail '@VERSION@' '${heimdallVersion}'
            chmod 0755 "$archive_root/heimdall-install"
            install -m 0644 ${./LICENSE} "$archive_root/LICENSE"
            install -m 0644 ${./README.md} "$archive_root/README.md"
            tar --sort=name --mtime='@1' --owner=0 --group=0 --numeric-owner \
              -czf "$out/$archive_root.tar.gz" "$archive_root"
            (cd "$out" && sha256sum "$archive_root.tar.gz" > "$archive_root.tar.gz.sha256")
          '';

      releaseBundleAarch64 =
        pkgs.runCommand "heimdall-egress-${heimdallVersion}-aarch64-linux-musl"
          {
            version = heimdallVersion;
            nativeBuildInputs = [
              pkgs.coreutils
              pkgs.gnutar
              pkgs.gzip
            ];
          }
          ''
            archive_root=heimdall-egress-${heimdallVersion}-aarch64-linux-musl
            mkdir -p "$out" "$archive_root"
            install -m 0755 ${heimdall-static-aarch64}/bin/heimdall "$archive_root/heimdall"
            substitute ${./packaging/heimdall-install} "$archive_root/heimdall-install" \
              --replace-fail '@VERSION@' '${heimdallVersion}'
            chmod 0755 "$archive_root/heimdall-install"
            install -m 0644 ${./LICENSE} "$archive_root/LICENSE"
            install -m 0644 ${./README.md} "$archive_root/README.md"
            tar --sort=name --mtime='@1' --owner=0 --group=0 --numeric-owner \
              -czf "$out/$archive_root.tar.gz" "$archive_root"
            (cd "$out" && sha256sum "$archive_root.tar.gz" > "$archive_root.tar.gz.sha256")
          '';

      releaseCheck =
        pkgs.runCommand "heimdall-release-check-${heimdallVersion}"
          {
            nativeBuildInputs = [
              pkgs.binutils
              pkgs.coreutils
              pkgs.findutils
              pkgs.gnugrep
              pkgs.gnutar
              pkgs.gzip
            ];
          }
          ''
            sh ${./tests/package/run-acceptance.sh} ${releaseBundle} ${heimdallVersion} x86_64 'Advanced Micro Devices X86-64'
            touch "$out"
          '';

      releaseCheckAarch64 =
        pkgs.runCommand "heimdall-release-check-aarch64-${heimdallVersion}"
          {
            nativeBuildInputs = [
              pkgs.binutils
              pkgs.coreutils
              pkgs.findutils
              pkgs.gnugrep
              pkgs.gnutar
              pkgs.gzip
              pkgs.qemu
            ];
          }
          ''
            sh ${./tests/package/run-acceptance.sh} \
              ${releaseBundleAarch64} ${heimdallVersion} aarch64 AArch64 \
              ${pkgs.qemu}/bin/qemu-aarch64
            touch "$out"
          '';

      vmProxyTest =
        {
          name,
          kernelPackages ? null,
        }:
        pkgs.testers.runNixOSTest {
          inherit name;
          nodes.machine = {
            imports = [
              ./tests/vm/heimdall-proxy.nix
            ]
            ++ lib.optional (kernelPackages != null) { boot.kernelPackages = kernelPackages; };
            _module.args.heimdallPackage = heimdall-static;
            virtualisation = {
              memorySize = 2048;
              cores = 2;
            };
          };
          testScript = ''
            machine.start()
            machine.wait_until_succeeds("test -e /run/heimdall-test/ready")
            machine.succeed("/etc/heimdall-test/run-acceptance.sh")
          '';
        };

      vmBenchmarkTest =
        {
          name,
          kernelPackages ? null,
        }:
        pkgs.testers.runNixOSTest {
          inherit name;
          nodes.machine = {
            imports = [
              ./tests/vm/heimdall-proxy.nix
            ]
            ++ lib.optional (kernelPackages != null) { boot.kernelPackages = kernelPackages; };
            _module.args.heimdallPackage = heimdall-static;
            virtualisation = {
              memorySize = 8192;
              cores = 2;
            };
          };
          testScript = ''
            import json

            machine.start()
            machine.wait_until_succeeds("test -e /run/heimdall-test/ready")
            machine.succeed("systemctl start user@1000.service")
            machine.succeed("install -d -o tester -g users -m 0700 /run/heimdall-test/relay")
            output = machine.succeed(
              "runuser -u tester -- env "
              "HOME=/home/tester "
              "XDG_RUNTIME_DIR=/run/user/1000 "
              "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
              "PATH=/run/wrappers/bin:/run/current-system/sw/bin "
              "HEIMDALL_CAPTURE_SECRET=redaction-secret "
              "/etc/heimdall-test/run-benchmark.py"
            )
            report = json.loads(output)
            assert report["contract"] == "heimdall.benchmark/v1"
            assert report["event_integrity"] == {
              "runs": 86,
              "incomplete_runs": 0,
              "missing_records": 0,
              "out_of_order_records": 0,
              "active_flows_after_close": 0,
              "failed_flows": 0,
              "error_events": 0,
            }
            assert {
              item["concurrency"]
              for item in report["aggregates"]
              if item["scenario"] == "concurrent_cold_start"
            } == {1, 10, 50}
            assert {item["scenario"] for item in report["throughput"]} == {
              "direct_tcp_no_capture",
              "proxy_tcp_no_capture",
              "proxy_udp_no_capture",
              "proxy_tcp_capture",
              "relay_tls_capture",
            }
            assert all(item["transferred_bytes"] > 0 for item in report["throughput"])
            assert all(item["bytes_per_second"] > 0 for item in report["throughput"])
            print("HEIMDALL_BENCHMARK_JSON=" + output.strip())
          '';
        };
    in
    {
      packages.${system} = {
        inherit
          heimdall
          heimdall-static
          heimdall-static-aarch64
          heimdall-ebpf
          bpf-linker
          ;
        default = heimdall;
        release = releaseBundle;
        release-aarch64 = releaseBundleAarch64;
      };

      checks.${system} = {
        release = releaseCheck;
        release-aarch64 = releaseCheckAarch64;
        vm-proxy = vmProxyTest { name = "heimdall-proxy"; };
        vm-proxy-lts = vmProxyTest {
          name = "heimdall-proxy-lts";
          kernelPackages = pkgs.linuxPackages_6_6;
        };
        vm-benchmark = vmBenchmarkTest { name = "heimdall-benchmark"; };
        vm-benchmark-lts = vmBenchmarkTest {
          name = "heimdall-benchmark-lts";
          kernelPackages = pkgs.linuxPackages_6_6;
        };
      };

      # `nix develop` shell with everything needed to iterate locally —
      # nightly for eBPF and stable for userspace.
      devShells.${system} = {
        # Most edits touch userspace Rust. Keep the LLVM 22 eBPF
        # linker closure out of this common path.
        default = pkgs.mkShell {
          packages = [
            rustStable
            pkgs.sccache
            pkgs.cargo-nextest
            pkgs.cargo-deny
            pkgs.cargo-machete
            pkgs.rust-analyzer
            pkgs.jq
            pkgs.pkg-config
            pkgs.cargo-watch
            pkgs.just
            pkgs.nixfmt
            pkgs.nodejs_22
            pkgs.python3
            pkgs.python3Packages.build
            pkgs.python3Packages.setuptools
            pkgs.python3Packages.wheel
            pkgs.python3Packages.twine
            pkgs.uv
            pkgs.gh
            pkgs.actionlint
            pkgs.shellcheck
          ];

        };

        # eBPF is an intentionally separate toolchain: pinned nightly,
        # rust-src/build-std, and the LLVM 22 linker required by its bitcode.
        ebpf = pkgs.mkShell {
          packages = [
            rustNightly
            cargoNightly
            bpf-linker
            pkgs.sccache
            pkgs.bpftools
          ];

        };
      };

      formatter.${system} = pkgs.nixfmt;
    };
}
