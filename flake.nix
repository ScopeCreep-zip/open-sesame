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
        open-sesame-headless = (pkgsFor system).callPackage ./nix/package-headless.nix { };
      });

      overlays.default = final: prev: {
        open-sesame = final.callPackage ./nix/package.nix { };
        open-sesame-headless = final.callPackage ./nix/package-headless.nix { };
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
                  key_bindings.g = {
                    apps = [ "ghostty" "com.mitchellh.ghostty" ];
                    launch = "ghostty";
                    tags = [ "dev" "work:corp" ];
                  };
                }
              '';
              description = ''
                Window manager key bindings and WM settings for the default profile.
                Keys are placed under `profiles.default.wm` in the generated config.
              '';
            };

            profiles = lib.mkOption {
              type = lib.types.attrsOf tomlFormat.type;
              default = { };
              example = lib.literalExpression ''
                {
                  default = {
                    launch_profiles.dev = {
                      env = { RUST_LOG = "debug"; };
                      secrets = [ "github-token" ];
                    };
                  };
                  work = {
                    launch_profiles.corp = {
                      env = { CORP_ENV = "production"; };
                      secrets = [ "corp-api-key" ];
                    };
                  };
                }
              '';
              description = ''
                Additional profile configuration. Each key is a trust profile name.
                Values are merged into `profiles.<name>` in the generated config.
                The "default" profile's `wm` section comes from `settings` above;
                use this for `launch_profiles` and additional profiles/vaults.
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
            warnings = lib.optional
              (builtins.pathExists "/dev/input" && !(builtins.elem "input" (config.home.extraGroups or [])))
              ''
                open-sesame: daemon-input requires 'input' group membership for
                keyboard capture on desktops without a focused window.
                Run: sudo usermod -aG input $USER (logout/login required)
                This requirement will be removed once cosmic-comp is patched
                to grant keyboard focus to exclusive layer-shell surfaces
                when no window is focused.
              '';

            home.packages = [ cfg.package ];

            xdg.configFile."pds/config.toml" =
              let
                hasConfig = cfg.settings != { } || cfg.profiles != { };
                # Build the profiles attrset: start with default (wm from settings),
                # then deep-merge any explicit profile overrides.
                defaultProfile = {
                  name = "default";
                  wm = cfg.settings;
                };
                # Merge explicit default profile attrs (e.g. launch_profiles) into the
                # base default profile, then add all other named profiles.
                explicitDefault = cfg.profiles.default or { };
                mergedDefault = defaultProfile // explicitDefault // {
                  # Preserve wm from settings even if profiles.default is set.
                  wm = cfg.settings;
                };
                otherProfiles = lib.filterAttrs (n: _: n != "default") cfg.profiles;
                # Add `name` field to each non-default profile.
                namedOtherProfiles = lib.mapAttrs (name: value: { inherit name; } // value) otherProfiles;
                allProfiles = { default = mergedDefault; } // namedOtherProfiles;
              in
              lib.mkIf hasConfig {
                source = tomlFormat.generate "open-sesame-config" {
                  config_version = 3;
                  global = {
                    default_profile = "default";
                    ipc = { };
                    logging = { };
                  };
                  profiles = allProfiles;
                  crypto = { };
                  agents = { };
                  extensions = { };
                };
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

            # Input daemon — evdev keyboard capture for IPC keyboard routing.
            # Requires `input` group membership for /dev/input/* access.
            #
            # TODO: upstream a fix to cosmic-comp (shell/focus/mod.rs:532-537)
            # so layer-shell surfaces with KeyboardMode::Exclusive receive
            # keyboard focus even when no window is focused. This would
            # eliminate the need for evdev-based keyboard routing and the
            # `input` group requirement entirely.
            # Ref: refresh_focus() early-exits when no toplevel is focused,
            # never discovering exclusive layer surfaces.
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
