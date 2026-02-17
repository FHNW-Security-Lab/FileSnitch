{ lib, craneLib, pkg-config, dbus, sqlite, openssl }:

let
  # Raw source (entire flake root) for non-Cargo files (dbus, systemd, config)
  rawSrc = ../.;

  # Cleaned source for cargo build (only Cargo-related files)
  src = craneLib.cleanCargoSource (craneLib.path ../.);

  commonArgs = {
    inherit src;
    pname = "filesnitchd";
    version = "0.1.0";

    nativeBuildInputs = [ pkg-config ];
    buildInputs = [ dbus dbus.dev sqlite openssl ];

    # Only build the daemon crate
    cargoExtraArgs = "-p filesnitchd";
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
craneLib.buildPackage (commonArgs // {
  inherit cargoArtifacts;

  postInstall = ''
    # Install D-Bus configuration
    install -Dm644 ${rawSrc}/dbus/org.filesnitch.Daemon.conf \
      $out/share/dbus-1/system.d/org.filesnitch.Daemon.conf

    # Install D-Bus service activation file
    install -Dm644 ${rawSrc}/dbus/org.filesnitch.Daemon.service \
      $out/share/dbus-1/system-services/org.filesnitch.Daemon.service

    # Fix the Exec path in the D-Bus service file
    substituteInPlace $out/share/dbus-1/system-services/org.filesnitch.Daemon.service \
      --replace-fail "/usr/bin/filesnitchd" "$out/bin/filesnitchd"

    # Install systemd service
    install -Dm644 ${rawSrc}/systemd/filesnitchd.service \
      $out/lib/systemd/system/filesnitchd.service

    # Fix ExecStart path in systemd service
    substituteInPlace $out/lib/systemd/system/filesnitchd.service \
      --replace-fail "/usr/bin/filesnitchd" "$out/bin/filesnitchd"

    # Install default config
    install -Dm644 ${rawSrc}/config/filesnitchd.toml \
      $out/etc/filesnitch/filesnitchd.toml
  '';

  meta = with lib; {
    description = "FileSnitch daemon - interactive file access firewall";
    license = licenses.gpl3;
    platforms = platforms.linux;
  };
})
