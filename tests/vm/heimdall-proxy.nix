{
  pkgs,
  lib,
  config,
  heimdallPackage,
  ...
}:
let
  testPython = pkgs.python3.withPackages (pythonPackages: [ pythonPackages.aioquic ]);
  heimdallConfig = pkgs.writeText "heimdall-test-config.toml" ''
    version = 1

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
    mode = "off"
    [decrypt]
    mode = "off"
  '';
in
{
  networking.hostName = "heimdall-test";
  security.unprivilegedUsernsClone = true;

  users.users.tester = {
    isNormalUser = true;
    uid = 1000;
    linger = true;
  };

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
    pkgs.rustc
  ];

  systemd.tmpfiles.rules = [ "d /run/heimdall-test 0755 root root -" ];

  systemd.services.heimdall-test-socks = {
    wantedBy = [ "multi-user.target" ];
    before = [ "heimdall.service" ];
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

  systemd.services.heimdall-test-git = {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStartPre = "${pkgs.git}/bin/git init --bare /run/heimdall-test/repo.git";
      ExecStart = "${pkgs.git}/bin/git daemon --reuseaddr --base-path=/run/heimdall-test --export-all --listen=127.0.0.1 --port=19418 /run/heimdall-test/repo.git";
      Restart = "on-failure";
    };
  };

  systemd.services.heimdall = {
    wantedBy = [ "multi-user.target" ];
    after = [
      "network.target"
      "heimdall-test-socks.service"
    ];
    requires = [ "heimdall-test-socks.service" ];
    serviceConfig = {
      Type = "notify";
      NotifyAccess = "main";
      ExecStart = "${heimdallPackage}/bin/heimdall --config ${heimdallConfig} daemon";
      Restart = "on-failure";
      RuntimeDirectory = "heimdall";
      RuntimeDirectoryMode = "0700";
      RuntimeDirectoryPreserve = "restart";
      AmbientCapabilities = [
        "CAP_BPF"
        "CAP_NET_ADMIN"
        "CAP_SYS_ADMIN"
        "CAP_DAC_OVERRIDE"
      ];
      CapabilityBoundingSet = [
        "CAP_BPF"
        "CAP_NET_ADMIN"
        "CAP_SYS_ADMIN"
        "CAP_DAC_OVERRIDE"
      ];
    };
  };

  systemd.services.heimdall-test-ready = {
    wantedBy = [ "multi-user.target" ];
    after = [
      "heimdall.service"
      "heimdall-test-http.service"
      "heimdall-test-udp.service"
      "heimdall-test-http3.service"
      "heimdall-test-git.service"
      "user@1000.service"
    ];
    requires = [
      "heimdall.service"
      "heimdall-test-http.service"
      "heimdall-test-udp.service"
      "heimdall-test-http3.service"
      "heimdall-test-git.service"
    ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.coreutils}/bin/touch /run/heimdall-test/ready";
    };
  };

  environment.etc."heimdall-test/dual_stack_client.py".source = ./dual_stack_client.py;
  environment.etc."heimdall-test/udp_client.py".source = ./udp_client.py;
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
  environment.etc."heimdall/config.toml".source = heimdallConfig;

  assertions = [
    {
      assertion = lib.versionAtLeast config.system.build.kernel.version "5.10";
      message = "Heimdall VM requires Linux 5.10 or newer";
    }
  ];
}
