{
  pkgs,
  lib,
  config,
  heimdallPackage,
  ...
}:
let
  heimdallConfig = pkgs.writeText "heimdall-test-config.toml" ''
    version = 1

    [proxy]
    default_policy = "fake"

    [proxy.outbounds.default]
    type = "socks5"
    server = "127.0.0.1"
    server_port = 1080
    network = ["tcp"]
    connect_timeout = "2s"

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
    pkgs.python3
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
      "user@1000.service"
    ];
    requires = [
      "heimdall.service"
      "heimdall-test-http.service"
    ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.coreutils}/bin/touch /run/heimdall-test/ready";
    };
  };

  environment.etc."heimdall-test/dual_stack_client.py".source = ./dual_stack_client.py;
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
