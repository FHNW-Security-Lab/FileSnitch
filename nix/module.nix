{ config, lib, pkgs, flakeInputs ? {}, ... }:

with lib;

let
  cfg = config.services.filesnitch;
  filesnitch = flakeInputs.filesnitch or (throw "FileSnitch flake input not found in flakeInputs");

  configFile = pkgs.writeText "filesnitchd.toml" ''
    [general]
    operation_mode = "${cfg.operationMode}"
    protection_mode = "${cfg.protectionMode}"
    default_action = "${cfg.defaultAction}"
    prompt_timeout = ${toString cfg.promptTimeout}
    db_path = "/var/lib/filesnitchd/rules.db"
    log_level = "${cfg.logLevel}"

    [critical_paths]
    paths = [${concatMapStringsSep ", " (p: "\"${p}\"") cfg.criticalPaths}]

    [excluded_executables]
    paths = [${concatMapStringsSep ", " (p: "\"${p}\"") cfg.excludedExecutables}]
  '';
in
{
  options.services.filesnitch = {
    enable = mkEnableOption "FileSnitch interactive file access firewall";

    operationMode = mkOption {
      type = types.enum [ "learning" "enforce" ];
      default = "learning";
      description = "Operation mode: learning (log only) or enforce (prompt on access)";
    };

    protectionMode = mkOption {
      type = types.enum [ "critical_only" "everything" ];
      default = "critical_only";
      description = "Protection mode: critical files only or everything under /home";
    };

    defaultAction = mkOption {
      type = types.enum [ "deny" "allow" ];
      default = "deny";
      description = "Default action when prompt times out";
    };

    promptTimeout = mkOption {
      type = types.int;
      default = 30;
      description = "Seconds before a prompt auto-applies the default action";
    };

    logLevel = mkOption {
      type = types.enum [ "trace" "debug" "info" "warn" "error" ];
      default = "info";
      description = "Log verbosity level";
    };

    criticalPaths = mkOption {
      type = types.listOf types.str;
      default = [
        ".ssh" ".gnupg" ".bashrc" ".zshrc" ".profile" ".bash_profile"
        ".aws" ".kube" ".gitconfig" ".config/git"
        ".mozilla" ".config/google-chrome" ".config/chromium"
        ".thunderbird" ".config/Code"
      ];
      description = "Paths relative to home directory that receive extra protection";
    };

    excludedExecutables = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Additional executables to exclude from monitoring";
    };
  };

  config = mkIf cfg.enable {
    # Install the daemon package
    environment.systemPackages = [
      filesnitch.packages.${pkgs.system}.filesnitchd
      filesnitch.packages.${pkgs.system}.filesnitch-cli
      filesnitch.packages.${pkgs.system}.filesnitch-ui
    ];

    # D-Bus policy - allow daemon to own the bus name
    services.dbus.packages = [
      filesnitch.packages.${pkgs.system}.filesnitchd
    ];

    # Systemd service
    systemd.services.filesnitchd = {
      description = "FileSnitch - interactive file access firewall daemon";
      wantedBy = []; # D-Bus activated, not started at boot

      serviceConfig = {
        Type = "dbus";
        BusName = "org.filesnitch.Daemon";
        ExecStart = "${filesnitch.packages.${pkgs.system}.filesnitchd}/bin/filesnitchd ${configFile}";
        Restart = "on-failure";
        RestartSec = 5;
        StartLimitBurst = 3;
        WatchdogSec = 30;
        StateDirectory = "filesnitchd";
      };
    };
  };
}
