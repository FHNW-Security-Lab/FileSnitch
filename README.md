# FileSnitch

FileSnitch is an interactive file-access firewall for Linux home directories.

It is split into three Rust components communicating over D-Bus:

- `filesnitchd`: root daemon using Linux `fanotify` permission events.
- `filesnitch-ui`: GTK4 application for prompts, settings, rules, and logs.
- `filesnitch`: CLI for headless operation and rule/config management.

## Features implemented

- Home directory and critical-path layered protection model.
- Rule engine with scope (`exact`, `folder`, `recursive`, `home`, `custom`), permission (`read`, `write`, `read_write`), and duration (`once`, timed, forever).
- SQLite rule/event storage.
- TOML config loading/saving.
- D-Bus API for rule CRUD, config, status, event query, import/export, and permission decisions.
- GTK4 prompt dialog for live permission requests.
- CLI interactive watch mode similar to USBGuard-style approval.
- Nix flake and NixOS module scaffolding.
- `cargo-deb` metadata and service assets for Debian packaging.

## Build

```bash
cargo build --release
```

UI requires GTK4 development libraries.

## Run

Daemon (root, `CAP_SYS_ADMIN` required for fanotify permission mode):

```bash
sudo ./target/release/filesnitchd --config /etc/filesnitch/config.toml
```

CLI:

```bash
./target/release/filesnitch status
./target/release/filesnitch watch
./target/release/filesnitch rules list
```

UI:

```bash
./target/release/filesnitch-ui
```

## Config file

Default path: `/etc/filesnitch/config.toml`

Example:

```toml
protection_mode = "ProtectEverything"
critical_paths = ["~/.ssh/**", "~/.gnupg/**"]
excluded_executables = ["/usr/bin/gpg-agent"]
default_action_on_timeout = "Deny"
prompt_timeout_seconds = 30
log_verbosity = "info"
```

## NixOS module

Enable in your NixOS configuration:

```nix
{
  imports = [ inputs.filesnitch.nixosModules.default ];
  services.filesnitch.enable = true;
  services.filesnitch.protectionMode = "protect_everything";
  services.filesnitch.defaultActionOnTimeout = "deny";
  services.filesnitch.promptTimeoutSeconds = 30;
}
```

## Notes

- This is an initial implementation. Kernel fanotify permission behavior may vary by kernel version and filesystem.
- `buildRustPackage` currently uses `cargoHash = lib.fakeHash`; run one build to get the real hash and replace it.
