{
  description = "FileSnitch - interactive file access firewall";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "filesnitch";
          version = "0.1.0";
          src = ./.;
          cargoHash = "sha256-wsAuliWp7r2FSC21HJ33Fwub4Oxn13WdUshmPgvy/wU=";

          nativeBuildInputs = with pkgs; [ pkg-config dbus cargo-deb ];
          buildInputs = with pkgs; [ gtk4 glib dbus sqlite ];

          postInstall = ''
            install -Dm644 assets/systemd/filesnitchd.service $out/lib/systemd/system/filesnitchd.service
            install -Dm644 assets/dbus/org.filesnitch.Daemon.service $out/share/dbus-1/system-services/org.filesnitch.Daemon.service
            install -Dm644 assets/dbus/org.filesnitch.Daemon.conf $out/share/dbus-1/system.d/org.filesnitch.Daemon.conf
            install -Dm644 assets/desktop/filesnitch-ui.desktop $out/share/applications/filesnitch-ui.desktop
          '';
        };

        packages.deb = pkgs.stdenv.mkDerivation {
          pname = "filesnitch-deb";
          version = "0.1.0";
          src = ./.;
          nativeBuildInputs = with pkgs; [ cargo cargo-deb rustc pkg-config dbus ];
          buildInputs = with pkgs; [ gtk4 glib sqlite ];
          buildPhase = ''
            export HOME=$TMPDIR
            cargo deb
          '';
          installPhase = ''
            mkdir -p $out
            cp target/debian/*.deb $out/
          '';
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/filesnitch";
        };
      }) // {
        nixosModules.default = import ./nix/module.nix;
      };
}
