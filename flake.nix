{
  description = "Open Sesame v2 — Programmable Desktop Suite";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      packages = forAllSystems (system: {
        default = (pkgsFor system).callPackage ./nix/package.nix { };
        open-sesame = self.packages.${system}.default;
      });

      overlays.default = final: prev: {
        open-sesame = final.callPackage ./nix/package.nix { };
      };

      homeManagerModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.programs.open-sesame;
          tomlFormat = pkgs.formats.toml { };
          defaultPkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        in
        {
          options.programs.open-sesame = {
            enable = lib.mkEnableOption "Open Sesame desktop suite for COSMIC/Wayland";

            package = lib.mkOption {
              type = lib.types.package;
              default = defaultPkg;
              description = "The open-sesame package to use.";
            };

            settings = lib.mkOption {
              type = tomlFormat.type;
              default = { };
              example = lib.literalExpression ''
                {
                  settings = {
                    activation_key = "alt+space";
                    overlay_delay = 720;
                    quick_switch_threshold = 250;
                    background_color = "#000000c8";
                    card_color = "#1e1e1ef0";
                    text_color = "#ffffffff";
                    hint_color = "#646464ff";
                  };
                  keys.g = {
                    apps = [ "ghostty" "com.mitchellh.ghostty" ];
                    launch = "ghostty";
                  };
                  keys.f = {
                    apps = [ "firefox" "org.mozilla.firefox" ];
                    launch = "firefox";
                  };
                }
              '';
              description = ''
                Configuration for Open Sesame, written to
                {file}`~/.config/open-sesame/config.toml`.

                See {command}`sesame --print-config` for default values
                and https://scopecreep-zip.github.io/open-sesame/ for documentation.
              '';
            };

            logLevel = lib.mkOption {
              type = lib.types.enum [
                "error"
                "warn"
                "info"
                "debug"
                "trace"
              ];
              default = "info";
              description = "RUST_LOG level for all Open Sesame daemons.";
            };
          };

          config = lib.mkIf cfg.enable {
            home.packages = [ cfg.package ];

            xdg.configFile."pds/config.toml" = lib.mkIf (cfg.settings != { }) {
              source = tomlFormat.generate "open-sesame-config" cfg.settings;
            };

            # Grouping target — start/stop all daemons together.
            # Pulled in by graphical-session.target so daemons start on login.
            systemd.user.targets.open-sesame = {
              Unit = {
                Description = "Open Sesame Desktop Suite";
                Requires = [ "graphical-session.target" ];
                After = [ "graphical-session.target" ];
              };
              Install = {
                WantedBy = [ "graphical-session.target" ];
              };
            };

            # Profile daemon — IPC bus server, must start before all other daemons.
            systemd.user.services.open-sesame-profile = {
              Unit = {
                Description = "Open Sesame profile daemon (IPC bus)";
                After = [ "graphical-session.target" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "notify";
                ExecStart = "${cfg.package}/bin/daemon-profile";
                Restart = "on-failure";
                RestartSec = 5;
                WatchdogSec = 30;
                Environment = [ "RUST_LOG=${cfg.logLevel}" ];
              };
              Install = {
                WantedBy = [ "open-sesame.target" ];
              };
            };

            # Secrets daemon — encrypted secret store.
            systemd.user.services.open-sesame-secrets = {
              Unit = {
                Description = "Open Sesame secrets daemon";
                Requires = [ "open-sesame-profile.service" ];
                After = [ "open-sesame-profile.service" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "simple";
                ExecStart = "${cfg.package}/bin/daemon-secrets";
                Restart = "on-failure";
                RestartSec = 5;
                Environment = [ "RUST_LOG=${cfg.logLevel}" ];
              };
              Install = {
                WantedBy = [ "open-sesame.target" ];
              };
            };

            # Launcher daemon — desktop entry search and app launch.
            systemd.user.services.open-sesame-launcher = {
              Unit = {
                Description = "Open Sesame launcher daemon";
                Requires = [ "open-sesame-profile.service" ];
                After = [ "open-sesame-profile.service" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "simple";
                ExecStart = "${cfg.package}/bin/daemon-launcher";
                Restart = "on-failure";
                RestartSec = 5;
                Environment = [ "RUST_LOG=${cfg.logLevel}" ];
              };
              Install = {
                WantedBy = [ "open-sesame.target" ];
              };
            };

            # Window manager daemon — overlay window switcher.
            systemd.user.services.open-sesame-wm = {
              Unit = {
                Description = "Open Sesame window manager daemon";
                Requires = [ "open-sesame-profile.service" ];
                After = [ "open-sesame-profile.service" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "notify";
                ExecStart = "${cfg.package}/bin/daemon-wm";
                Restart = "on-failure";
                RestartSec = 5;
                WatchdogSec = 30;
                Environment = [ "RUST_LOG=${cfg.logLevel}" ];
              };
              Install = {
                WantedBy = [ "open-sesame.target" ];
              };
            };

            # Clipboard daemon (stub).
            systemd.user.services.open-sesame-clipboard = {
              Unit = {
                Description = "Open Sesame clipboard daemon";
                Requires = [ "open-sesame-profile.service" ];
                After = [ "open-sesame-profile.service" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "simple";
                ExecStart = "${cfg.package}/bin/daemon-clipboard";
                Restart = "on-failure";
                RestartSec = 5;
                Environment = [ "RUST_LOG=${cfg.logLevel}" ];
              };
              Install = {
                WantedBy = [ "open-sesame.target" ];
              };
            };

            # Input daemon (stub).
            systemd.user.services.open-sesame-input = {
              Unit = {
                Description = "Open Sesame input daemon";
                Requires = [ "open-sesame-profile.service" ];
                After = [ "open-sesame-profile.service" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "simple";
                ExecStart = "${cfg.package}/bin/daemon-input";
                Restart = "on-failure";
                RestartSec = 5;
                Environment = [ "RUST_LOG=${cfg.logLevel}" ];
              };
              Install = {
                WantedBy = [ "open-sesame.target" ];
              };
            };

            # Snippets daemon (stub).
            systemd.user.services.open-sesame-snippets = {
              Unit = {
                Description = "Open Sesame snippets daemon";
                Requires = [ "open-sesame-profile.service" ];
                After = [ "open-sesame-profile.service" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "simple";
                ExecStart = "${cfg.package}/bin/daemon-snippets";
                Restart = "on-failure";
                RestartSec = 5;
                Environment = [ "RUST_LOG=${cfg.logLevel}" ];
              };
              Install = {
                WantedBy = [ "open-sesame.target" ];
              };
            };
          };
        };

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              cargo
              rustc
              rust-analyzer
              clippy
              rustfmt
              tokei
              pkg-config
            ];

            buildInputs = with pkgs; [
              # SQLCipher (rusqlite bundled-sqlcipher)
              openssl

              # GTK4 UI (daemon-wm, daemon-launcher)
              gtk4
              gtk4-layer-shell
              glib
              cairo
              pango
              gdk-pixbuf
              graphene
              libadwaita

              # Wayland (platform-linux)
              wayland
              wayland-protocols
              libxkbcommon

              # System libs
              fontconfig
              pcsclite
              libseccomp
            ];

            # pkg-config needs to find .pc files from buildInputs
            PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" (
              with pkgs;
              [
                openssl.dev
                gtk4.dev
                gtk4-layer-shell.dev
                glib.dev
                cairo.dev
                pango.dev
                gdk-pixbuf.dev
                graphene.dev
                wayland.dev
                wayland-protocols
                libxkbcommon.dev
                fontconfig.dev
                pcsclite.dev
                libseccomp.dev
              ]
            );

            # rust-lld does not consume NIX_LDFLAGS; LIBRARY_PATH ensures
            # the linker can find native .so/.a files from buildInputs.
            LIBRARY_PATH = pkgs.lib.makeLibraryPath (
              with pkgs;
              [
                libseccomp
                openssl
                pcsclite
                fontconfig
                wayland
                libxkbcommon
              ]
            );

            shellHook = ''
              echo "open-sesame v2 devShell ready"
              echo "  cargo check --workspace"
            '';
          };
        }
      );
    };
}
