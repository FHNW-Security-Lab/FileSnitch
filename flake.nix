{
  description = "FileSnitch - interactive file access firewall for Linux home directories";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        craneLib = crane.mkLib pkgs;
      in
      {
        packages = {
          filesnitchd = pkgs.callPackage ./nix/daemon.nix { inherit craneLib; };
          filesnitch-ui = pkgs.callPackage ./nix/ui.nix { };
          filesnitch-cli = pkgs.callPackage ./nix/cli.nix { };
          default = self.packages.${system}.filesnitchd;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo rustc rust-analyzer clippy rustfmt
            pkg-config dbus dbus.dev openssl sqlite
            python3 python3Packages.pygobject3
            python3Packages.dasbus python3Packages.click
            python3Packages.rich
            gtk4 libadwaita gobject-introspection
          ];
        };
      }
    ) // {
      nixosModules.default = import ./nix/module.nix self;
    };
}
