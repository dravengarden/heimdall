{
  pkgs,
  lib,
  config,
  heimdallPackage,
  ...
}:
let
  testPython = pkgs.python3.withPackages (pythonPackages: [ pythonPackages.aioquic ]);
  tlsFixture =
    pkgs.runCommand "heimdall-test-tls-fixture" { nativeBuildInputs = [ pkgs.openssl ]; }
      ''
        mkdir -p $out
        # Nix may retain this fixture indefinitely. A short-lived certificate
        # makes a previously green store path fail solely as wall time passes.
        openssl req -x509 -newkey rsa:2048 -nodes \
          -keyout $out/ca-key.pem -out $out/ca.pem \
          -subj /CN=Heimdall-Test-Upstream-CA -days 36500 \
          -addext basicConstraints=critical,CA:TRUE \
          -addext keyUsage=critical,keyCertSign,cRLSign
        openssl req -newkey rsa:2048 -nodes \
          -keyout $out/server-key.pem -out $out/server.csr \
          -subj /CN=fixture.test
        printf '%s\n' \
          'basicConstraints=critical,CA:FALSE' \
          'keyUsage=critical,digitalSignature,keyEncipherment' \
          'extendedKeyUsage=serverAuth' \
          'subjectAltName=DNS:fixture.test' > $out/server.ext
        openssl x509 -req -in $out/server.csr \
          -CA $out/ca.pem -CAkey $out/ca-key.pem -CAcreateserial \
          -out $out/server.pem -days 36500 -extfile $out/server.ext
        rm $out/server.csr $out/server.ext $out/ca-key.pem $out/ca.srl
      '';
  heimdallConfigText = ''
    version = 1

    [execution]
    backend = "ebpf"

    [proxy]
    default_policy = "fake"

    [proxy.outbounds.default]
    type = "socks5"
    server = "127.0.0.1"
    server_port = 1080
    network = ["tcp", "udp"]
    connect_timeout = "2s"

    [proxy.outbounds.dead]
    type = "socks5"
    server = "127.0.0.1"
    server_port = 1099
    network = ["tcp"]
    connect_timeout = "200ms"

    [proxy.policies.fake.dns]
    mode = "fake"
    [proxy.policies.fake.final]
    tcp = { type = "route", outbound = "default" }
    udp = { type = "reject", method = "refused" }

    [proxy.policies.system.dns]
    mode = "system"
    [proxy.policies.system.final]
    tcp = { type = "route", outbound = "default" }
    udp = { type = "reject", method = "refused" }

    [proxy.policies.direct.dns]
    mode = "system"
    [proxy.policies.direct.final]
    tcp = { type = "direct" }
    udp = { type = "reject", method = "refused" }

    [proxy.policies.reject.dns]
    mode = "system"
    [proxy.policies.reject.final]
    tcp = { type = "reject", method = "refused" }
    udp = { type = "reject", method = "refused" }

    [proxy.policies.upstream-down.dns]
    mode = "fake"
    [proxy.policies.upstream-down.final]
    tcp = { type = "route", outbound = "dead" }
    udp = { type = "reject", method = "refused" }

    [proxy.policies.udp.dns]
    mode = "fake"
    [proxy.policies.udp.final]
    tcp = { type = "reject", method = "refused" }
    udp = { type = "route", outbound = "default" }

    [proxy.policies.udp-direct.dns]
    mode = "system"
    [proxy.policies.udp-direct.final]
    tcp = { type = "reject", method = "refused" }
    udp = { type = "direct" }

    [capture]
    mode = "on"
    max_bytes_per_flow = 512
    block_max_bytes = 32
    flush_interval_ms = 20
    boundaries = ["transport", "tls_plaintext.runtime", "tls_plaintext.relay"]
    directions = ["client_to_remote", "remote_to_client"]
    redact_env = ["HEIMDALL_CAPTURE_SECRET"]
    [decrypt]
    mode = "off"
  '';
  heimdallConfig = pkgs.writeText "heimdall-test-config.toml" heimdallConfigText;
  runtimeConfig = pkgs.writeText "heimdall-test-runtime.toml" (
    builtins.replaceStrings [ ''mode = "off"'' ] [ ''mode = "runtime"'' ] heimdallConfigText
  );
  relayConfig = pkgs.writeText "heimdall-test-relay.toml" (
    builtins.replaceStrings
      [ ''mode = "off"'' ]
      [
        ''
          mode = "relay"
          ca_cert = "/run/heimdall-test/relay/ca.pem"
          ca_key = "/run/heimdall-test/relay/ca-key.pem"
        ''
      ]
      heimdallConfigText
  );
  benchmarkNoCaptureConfig = pkgs.writeText "heimdall-benchmark-no-capture.toml" (
    builtins.replaceStrings [ ''mode = "on"'' ] [ ''mode = "off"'' ] heimdallConfigText
  );
  benchmarkCaptureText =
    builtins.replaceStrings
      [
        "max_bytes_per_flow = 512"
        "block_max_bytes = 32"
        "flush_interval_ms = 20"
      ]
      [
        "max_bytes_per_flow = 33554432"
        "block_max_bytes = 65536"
        "flush_interval_ms = 100"
      ]
      heimdallConfigText;
  benchmarkCaptureConfig = pkgs.writeText "heimdall-benchmark-capture.toml" benchmarkCaptureText;
  benchmarkRelayCaptureConfig = pkgs.writeText "heimdall-benchmark-relay-capture.toml" (
    builtins.replaceStrings
      [ ''mode = "off"'' ]
      [
        ''
          mode = "relay"
          ca_cert = "/run/heimdall-test/relay/ca.pem"
          ca_key = "/run/heimdall-test/relay/ca-key.pem"
        ''
      ]
      benchmarkCaptureText
  );
in
{
  networking.hostName = "heimdall-test";
  networking.interfaces.lo.ipv4.addresses = [
    {
      address = "192.0.2.1";
      prefixLength = 32;
    }
  ];
  security.unprivilegedUsernsClone = true;
  security.pki.certificateFiles = [ "${tlsFixture}/ca.pem" ];

  users.users.tester = {
    isNormalUser = true;
    uid = 1000;
    linger = true;
  };
  users.users.unauthorized = {
    isNormalUser = true;
    uid = 1001;
    linger = true;
  };

  security.sudo.extraRules = [
    {
      users = [ "tester" ];
      commands = [
        {
          command = "${heimdallPackage}/bin/heimdall __setup-worker";
          options = [ "NOPASSWD" ];
        }
      ];
    }
  ];

  environment.systemPackages = [
    heimdallPackage
    pkgs.curl
    pkgs.jq
    testPython
    pkgs.gcc
    pkgs.go
    pkgs.git
    pkgs.jdk_headless
    pkgs.nodejs
    pkgs.openssl
    pkgs.bpftools
    pkgs.rustc
    pkgs.time
  ];

  systemd.tmpfiles.rules = [ "d /run/heimdall-test 0755 root root -" ];

  systemd.services.heimdall-test-socks = {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.python3}/bin/python3 ${./socks5_fixture.py}";
      Restart = "on-failure";
    };
  };

  systemd.services.heimdall-test-http = {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.python3}/bin/python3 ${./http_fixture.py}";
      Restart = "on-failure";
    };
  };

  systemd.services.heimdall-test-udp = {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.python3}/bin/python3 ${./udp_fixture.py}";
      Restart = "on-failure";
    };
  };

  systemd.services.heimdall-test-http3 = {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStartPre = "${pkgs.openssl}/bin/openssl req -x509 -newkey rsa:2048 -nodes -keyout /run/heimdall-test/http3-key.pem -out /run/heimdall-test/http3-cert.pem -subj /CN=fixture.test -days 1";
      ExecStart = "${testPython}/bin/python3 ${./http3_fixture.py} /run/heimdall-test/http3-cert.pem /run/heimdall-test/http3-key.pem";
      Restart = "on-failure";
    };
  };

  systemd.services.heimdall-test-tls = {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.python3}/bin/python3 ${./http_fixture.py} ${tlsFixture}/server.pem ${tlsFixture}/server-key.pem";
      Restart = "on-failure";
    };
  };

  systemd.services.heimdall-test-git = {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStartPre = "${pkgs.git}/bin/git init --bare /run/heimdall-test/repo.git";
      ExecStart = "${pkgs.git}/bin/git daemon --reuseaddr --base-path=/run/heimdall-test --export-all --listen=127.0.0.1 --port=19418 /run/heimdall-test/repo.git";
      Restart = "on-failure";
    };
  };

  systemd.services.heimdall-test-ready = {
    wantedBy = [ "multi-user.target" ];
    after = [
      "heimdall-test-http.service"
      "heimdall-test-udp.service"
      "heimdall-test-http3.service"
      "heimdall-test-tls.service"
      "heimdall-test-git.service"
      "user@1000.service"
    ];
    requires = [
      "heimdall-test-http.service"
      "heimdall-test-udp.service"
      "heimdall-test-http3.service"
      "heimdall-test-tls.service"
      "heimdall-test-git.service"
    ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.coreutils}/bin/touch /run/heimdall-test/ready";
    };
  };

  environment.etc."heimdall-test/dual_stack_client.py".source = ./dual_stack_client.py;
  environment.etc."heimdall-test/udp_client.py".source = ./udp_client.py;
  environment.etc."heimdall-test/setup_worker_client.py".source = ./setup_worker_client.py;
  environment.etc."heimdall-test/udp_session_client.py".source = ./udp_session_client.py;
  environment.etc."heimdall-test/udp_port_reuse_client.py".source = ./udp_port_reuse_client.py;
  environment.etc."heimdall-test/udp_connectionless_client.py".source =
    ./udp_connectionless_client.py;
  environment.etc."heimdall-test/udp_shared_port_client.py".source = ./udp_shared_port_client.py;
  environment.etc."heimdall-test/udp_token_stress_client.py".source = ./udp_token_stress_client.py;
  environment.etc."heimdall-test/udp_ipv6_bind_guard_client.py".source =
    ./udp_ipv6_bind_guard_client.py;
  environment.etc."heimdall-test/udp_batch_client.c".source = ./udp_batch_client.c;
  environment.etc."heimdall-test/http3_client.py".source = ./http3_client.py;
  environment.etc."heimdall-test/runtime_client.go".source = ./runtime_client.go;
  environment.etc."heimdall-test/runtime_client.js".source = ./runtime_client.js;
  environment.etc."heimdall-test/RuntimeClient.java".source = ./RuntimeClient.java;
  environment.etc."heimdall-test/runtime_client.rs".source = ./runtime_client.rs;
  environment.etc."heimdall-test/runtime-wrapper" = {
    source = ./runtime-wrapper;
    mode = "0755";
  };
  environment.etc."heimdall-test/run-acceptance.sh" = {
    source = ./run-acceptance.sh;
    mode = "0755";
  };
  environment.etc."heimdall-test/run-benchmark.py" = {
    source = ../perf/vm-baseline.py;
    mode = "0755";
  };
  environment.etc."heimdall-test/udp-throughput.py" = {
    source = ../perf/udp-throughput.py;
    mode = "0755";
  };
  environment.etc."heimdall/config.toml".source = heimdallConfig;
  environment.etc."heimdall-test/runtime.toml".source = runtimeConfig;
  environment.etc."heimdall-test/relay.toml".source = relayConfig;
  environment.etc."heimdall-test/benchmark-no-capture.toml".source = benchmarkNoCaptureConfig;
  environment.etc."heimdall-test/benchmark-capture.toml".source = benchmarkCaptureConfig;
  environment.etc."heimdall-test/benchmark-relay-capture.toml".source = benchmarkRelayCaptureConfig;
  environment.etc."heimdall-test/upstream-ca.pem".source = "${tlsFixture}/ca.pem";

  assertions = [
    {
      assertion = lib.versionAtLeast config.system.build.kernel.version "5.10";
      message = "Heimdall VM requires Linux 5.10 or newer";
    }
  ];
}
