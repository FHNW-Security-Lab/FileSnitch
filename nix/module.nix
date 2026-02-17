{ config, lib, pkgs, ... }:
let
  cfg = config.services.filesnitch;
  toml = pkgs.formats.toml { };
in {
  options.services.filesnitch = {
    enable = lib.mkEnableOption "FileSnitch daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../default.nix { };
      defaultText = lib.literalExpression "self.packages.${pkgs.system}.default";
      description = "FileSnitch package to use";
    };

    protectionMode = lib.mkOption {
      type = lib.types.enum [ "protect_everything" "protect_critical_only" ];
      default = "protect_everything";
      description = "Protection mode for FileSnitch.";
    };

    excludedExecutables = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Executable paths to always allow.";
    };

    defaultActionOnTimeout = lib.mkOption {
      type = lib.types.enum [ "allow" "deny" ];
      default = "deny";
      description = "Default action when prompt times out.";
    };

    promptTimeoutSeconds = lib.mkOption {
      type = lib.types.int;
      default = 30;
      description = "Prompt timeout in seconds.";
    };

    criticalPaths = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "~/.ssh/**"
        "~/.gnupg/**"
        "~/.aws/**"
        "~/.kube/**"
        "~/.bashrc"
        "~/.zshrc"
        "~/.profile"
        "~/.bash_profile"
        "~/.gitconfig"
        "~/.config/git/**"
        "~/.mozilla/**"
        "~/.config/chromium/**"
        "~/.config/google-chrome/**"
      ];
      description = "Critical paths list.";
    };

    startOnBoot = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether to start filesnitchd automatically at boot.
        When false, the daemon is started on-demand via D-Bus activation
        (for example when filesnitch-ui or filesnitch CLI connects).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.dbus.packages = [ cfg.package ];

    environment.etc."filesnitch/config.toml".source = toml.generate "filesnitch-config.toml" {
      protection_mode = if cfg.protectionMode == "protect_everything"
        then "ProtectEverything"
        else "ProtectCriticalOnly";
      critical_paths = cfg.criticalPaths;
      excluded_executables = cfg.excludedExecutables;
      default_action_on_timeout = if cfg.defaultActionOnTimeout == "allow"
        then "Allow"
        else "Deny";
      prompt_timeout_seconds = cfg.promptTimeoutSeconds;
      log_verbosity = "info";
    };

    systemd.services.filesnitchd = {
      description = "FileSnitch daemon";
      wantedBy = lib.optional cfg.startOnBoot "multi-user.target";
      after = [ "dbus.service" ];
      unitConfig = {
        StartLimitIntervalSec = "5min";
        StartLimitBurst = 3;
      };
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/filesnitchd --config /etc/filesnitch/config.toml";
        Restart = "on-failure";
        RestartSec = 20;
        User = "root";
        Group = "root";
        CapabilityBoundingSet = [ "CAP_SYS_ADMIN" "CAP_DAC_READ_SEARCH" ];
        AmbientCapabilities = [ "CAP_SYS_ADMIN" "CAP_DAC_READ_SEARCH" ];
        NoNewPrivileges = true;
      };
    };
  };
}
