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

            # Stable SSH_AUTH_SOCK for systemd user services.
            # On Konductor VMs, /etc/profile.d/konductor-ssh-agent.sh creates
            # a symlink at ~/.ssh/agent.sock pointing to the forwarded agent
            # socket, then imports this variable into the systemd user manager.
            # This environment.d entry ensures newly started services always
            # get the stable path even without an explicit import-environment.
            systemd.user.sessionVariables.SSH_AUTH_SOCK = "\${HOME}/.ssh/agent.sock";

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

            # Ensure %t/pds exists on the host filesystem before services start.
            # ProtectSystem=strict bind-mounts ReadWritePaths into each service's
            # mount namespace — the source directory must exist on the real fs.
            # RuntimeDirectory= cannot do this reliably for user services because
            # the mkdir happens inside the namespace (invisible to other units).
            systemd.user.tmpfiles.rules = [
              "d %t/pds 0700 - - -"
              "d %h/.config/pds 0700 - - -"
              "d %h/.cache/open-sesame 0700 - - -"
            ];

            # Grouping target — start/stop all daemons together.
            # Pulled in by graphical-session.target so daemons start on login.
            systemd.user.targets.open-sesame = {
              Unit = {
                Description = "Open Sesame Desktop Suite";
                Documentation = "https://github.com/scopecreep-zip/open-sesame";
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
                Documentation = "https://github.com/scopecreep-zip/open-sesame";
                After = [ "graphical-session.target" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "notify";
                ExecStart = "${cfg.package}/bin/daemon-profile";
                Restart = "on-failure";
                RestartSec = 5;
                TimeoutStopSec = 5;
                WatchdogSec = 30;
                NoNewPrivileges = true;
                ProtectHome = "read-only";
                ProtectSystem = "strict";
                ReadWritePaths = [ "%t/pds" "%h/.config/pds" ];
                LimitNOFILE = 4096;
                MemoryMax = "128M";
                Environment = [ "RUST_LOG=${cfg.logLevel}" ];
                # SSH agent env written by profile.d hook on each SSH login.
                # %h expands to user home; - prefix makes missing file non-fatal.
                EnvironmentFile = [ "-%h/.config/pds/ssh-agent.env" ];
              };
              Install = {
                WantedBy = [ "open-sesame.target" ];
              };
            };

            # Secrets daemon — encrypted secret store.
            systemd.user.services.open-sesame-secrets = {
              Unit = {
                Description = "Open Sesame secrets daemon";
                Documentation = "https://github.com/scopecreep-zip/open-sesame";
                Requires = [ "open-sesame-profile.service" ];
                After = [ "open-sesame-profile.service" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "notify";
                ExecStart = "${cfg.package}/bin/daemon-secrets";
                Restart = "on-failure";
                RestartSec = 5;
                TimeoutStopSec = 5;
                WatchdogSec = 30;
                NoNewPrivileges = true;
                PrivateNetwork = true;
                ProtectHome = "read-only";
                ProtectSystem = "strict";

                ReadWritePaths = [ "%t/pds" "%h/.config/pds" ];
                LimitNOFILE = 1024;
                LimitMEMLOCK = "64M";
                MemoryMax = "256M";
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
                Documentation = "https://github.com/scopecreep-zip/open-sesame";
                Requires = [ "open-sesame-profile.service" ];
                After = [ "open-sesame-profile.service" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "notify";
                ExecStart = "${cfg.package}/bin/daemon-launcher";
                Restart = "on-failure";
                RestartSec = 5;
                TimeoutStopSec = 5;
                WatchdogSec = 30;
                NoNewPrivileges = true;
                ProtectHome = "read-only";
                ProtectSystem = "strict";

                ReadWritePaths = [ "%t/pds" "%h/.config/pds" ];
                LimitNOFILE = 4096;
                MemoryMax = "128M";
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
                Documentation = "https://github.com/scopecreep-zip/open-sesame";
                Requires = [ "open-sesame-profile.service" ];
                After = [ "open-sesame-profile.service" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "notify";
                ExecStart = "${cfg.package}/bin/daemon-wm";
                Restart = "on-failure";
                RestartSec = 5;
                TimeoutStopSec = 5;
                WatchdogSec = 30;
                NoNewPrivileges = true;
                ProtectHome = "read-only";
                ProtectSystem = "strict";

                ReadWritePaths = [ "%t/pds" "%h/.cache/open-sesame" ];
                LimitNOFILE = 4096;
                MemoryMax = "128M";
                Environment = [ "RUST_LOG=${cfg.logLevel}" ];
                # SSH agent env for auto-unlock via forwarded agent.
                EnvironmentFile = [ "-%h/.config/pds/ssh-agent.env" ];
              };
              Install = {
                WantedBy = [ "open-sesame.target" ];
              };
            };

            # Clipboard daemon.
            systemd.user.services.open-sesame-clipboard = {
              Unit = {
                Description = "Open Sesame clipboard daemon";
                Documentation = "https://github.com/scopecreep-zip/open-sesame";
                Requires = [ "open-sesame-profile.service" ];
                After = [ "open-sesame-profile.service" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "notify";
                ExecStart = "${cfg.package}/bin/daemon-clipboard";
                Restart = "on-failure";
                RestartSec = 5;
                TimeoutStopSec = 5;
                WatchdogSec = 30;
                NoNewPrivileges = true;
                ProtectHome = "read-only";
                ProtectSystem = "strict";

                ReadWritePaths = [ "%t/pds" ];
                LimitNOFILE = 4096;
                MemoryMax = "128M";
                Environment = [ "RUST_LOG=${cfg.logLevel}" ];
              };
              Install = {
                WantedBy = [ "open-sesame.target" ];
              };
            };

            # Input daemon — evdev keyboard capture for IPC keyboard routing.
            # Requires `input` group membership for /dev/input/* access.
            systemd.user.services.open-sesame-input = {
              Unit = {
                Description = "Open Sesame input daemon";
                Documentation = "https://github.com/scopecreep-zip/open-sesame";
                Requires = [ "open-sesame-profile.service" ];
                After = [ "open-sesame-profile.service" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "notify";
                ExecStart = "${cfg.package}/bin/daemon-input";
                Restart = "on-failure";
                RestartSec = 5;
                TimeoutStopSec = 5;
                WatchdogSec = 30;
                NoNewPrivileges = true;
                ProtectHome = "read-only";
                ProtectSystem = "strict";

                ReadWritePaths = [ "%t/pds" ];
                LimitNOFILE = 4096;
                MemoryMax = "128M";
                Environment = [ "RUST_LOG=${cfg.logLevel}" ];
              };
              Install = {
                WantedBy = [ "open-sesame.target" ];
              };
            };

            # Snippets daemon.
            systemd.user.services.open-sesame-snippets = {
              Unit = {
                Description = "Open Sesame snippets daemon";
                Documentation = "https://github.com/scopecreep-zip/open-sesame";
                Requires = [ "open-sesame-profile.service" ];
                After = [ "open-sesame-profile.service" ];
                PartOf = [ "open-sesame.target" ];
              };
              Service = {
                Type = "notify";
                ExecStart = "${cfg.package}/bin/daemon-snippets";
                Restart = "on-failure";
                RestartSec = 5;
                TimeoutStopSec = 5;
                WatchdogSec = 30;
                NoNewPrivileges = true;
                ProtectHome = "read-only";
                ProtectSystem = "strict";

                ReadWritePaths = [ "%t/pds" ];
                LimitNOFILE = 4096;
                MemoryMax = "128M";
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
