{ lib
, rustPlatform
, pkg-config
, dbus
, cargo-deb
, gtk4
, glib
, sqlite
}:
rustPlatform.buildRustPackage {
  pname = "filesnitch";
  version = "0.1.0";
  src = ./.;
  cargoHash = lib.fakeHash;

  nativeBuildInputs = [ pkg-config dbus cargo-deb ];
  buildInputs = [ gtk4 glib sqlite dbus ];

  postInstall = ''
    install -Dm644 assets/systemd/filesnitchd.service $out/lib/systemd/system/filesnitchd.service
    install -Dm644 assets/dbus/org.filesnitch.Daemon.service $out/share/dbus-1/system-services/org.filesnitch.Daemon.service
    install -Dm644 assets/desktop/filesnitch-ui.desktop $out/share/applications/filesnitch-ui.desktop
  '';

  meta = with lib; {
    description = "Interactive file access firewall for Linux home directories";
    license = licenses.gpl3Plus;
    platforms = platforms.linux;
  };
}
