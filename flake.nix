{
  description = "Open Sesame v2 — Programmable Desktop Suite";

  nixConfig = {
    extra-substituters = [ "https://scopecreep-zip.cachix.org" ];
    extra-trusted-public-keys = [
      "scopecreep-zip.cachix.org-1:LPiVDsYXJvgljVfZPN43zBWB7ZCGFr2jZ/lBinnPGvU="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    konductor = {
      url = "github:braincraftio/konductor";
      inputs.nixpkgs.follows = "nixpkgs";
      # konductor takes open-sesame as an input; this flake is that input,
      # so the lock does not nest another open-sesame and konductor pair on
      # every update.
      inputs.open-sesame.follows = "";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      konductor,
      ...
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [
            konductor.inputs.rust-overlay.overlays.default
            konductor.overlays.default
          ];
        };
    in
    {
      packages = forAllSystems (system: {
        open-sesame = (pkgsFor system).callPackage ./nix/package.nix { };
        open-sesame-desktop = (pkgsFor system).callPackage ./nix/package-desktop.nix {
          open-sesame = self.packages.${system}.open-sesame;
        };
        default = self.packages.${system}.open-sesame-desktop;
      });

      # nix flake check (mise run test:nix; the Test workflow's nix job).
      checks = forAllSystems (system: {
        home-manager-module = (pkgsFor system).callPackage ./nix/home-manager-check.nix {
          homeManager = konductor.inputs.home-manager;
          module = self.homeManagerModules.default;
          headlessPkg = self.packages.${system}.open-sesame;
          desktopPkg = self.packages.${system}.open-sesame-desktop;
        };
      });

      overlays.default = final: prev: {
        open-sesame = final.callPackage ./nix/package.nix { };
        open-sesame-desktop = final.callPackage ./nix/package-desktop.nix {
          open-sesame = final.open-sesame;
        };
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
          iniFormat = pkgs.formats.ini { };
          systemPkgs = self.packages.${pkgs.stdenv.hostPlatform.system};
          headlessPkg = systemPkgs.open-sesame;
          desktopPkg = systemPkgs.open-sesame-desktop;
          isHeadless = cfg.headless;

          # The units are the packages' own (contrib/systemd, ExecStart
          # patched to the store), the units the .deb, .rpm, and Arch
          # packages ship and the lifecycle validation runs: linked into
          # ~/.config/systemd/user where Home Manager links the units it
          # generates, with the [Install] links `systemctl enable` creates,
          # so sd-switch starts and restarts them on activation.
          headlessServices = map (svc: "open-sesame-${svc}.service") [
            "profile"
            "secrets"
            "launcher"
            "snippets"
          ];
          desktopServices = map (svc: "open-sesame-${svc}.service") [
            "wm"
            "clipboard"
            "input"
          ];
          unitSource = pkg: unit: { source = "${pkg}/lib/systemd/user/${unit}"; };
          unitFiles =
            pkg: units:
            lib.listToAttrs (map (unit: lib.nameValuePair "systemd/user/${unit}" (unitSource pkg unit)) units);
          wantedBy =
            target: pkg: units:
            lib.listToAttrs (
              map (unit: lib.nameValuePair "systemd/user/${target}.wants/${unit}" (unitSource pkg unit)) units
            );
          # RUST_LOG for every daemon, as a drop-in over the unit's own
          # Environment=RUST_LOG=info.
          logLevelDropIn = iniFormat.generate "open-sesame-log-level.conf" {
            Service.Environment = "RUST_LOG=${cfg.logLevel}";
          };
          logLevel =
            units:
            lib.listToAttrs (
              map (
                unit: lib.nameValuePair "systemd/user/${unit}.d/50-log-level.conf" { source = logLevelDropIn; }
              ) units
            );
          headlessUnits = lib.mergeAttrsList [
            (unitFiles headlessPkg ([ "open-sesame-headless.target" ] ++ headlessServices))
            (wantedBy "default.target" headlessPkg [ "open-sesame-headless.target" ])
            (wantedBy "open-sesame-headless.target" headlessPkg headlessServices)
            (logLevel headlessServices)
          ];
          desktopUnits = lib.mergeAttrsList [
            (unitFiles desktopPkg ([ "open-sesame-desktop.target" ] ++ desktopServices))
            (wantedBy "graphical-session.target" desktopPkg [ "open-sesame-desktop.target" ])
            (wantedBy "open-sesame-desktop.target" desktopPkg desktopServices)
            (logLevel desktopServices)
          ];
        in
        {
          options.programs.open-sesame = {
            enable = lib.mkEnableOption "Open Sesame desktop suite for COSMIC/Wayland";

            headless = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Run in headless mode (no GUI daemons). Only starts profile,
                secrets, launcher, and snippets daemons. Suitable for servers,
                containers, and SSH-only environments like Konductor VMs.
              '';
            };

            package = lib.mkOption {
              type = lib.types.package;
              default = if isHeadless then headlessPkg else desktopPkg;
              defaultText = lib.literalExpression "open-sesame or open-sesame-headless (based on headless option)";
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

          config = lib.mkIf cfg.enable (
            lib.mkMerge [
              { xdg.configFile = headlessUnits; }
              (lib.mkIf (!isHeadless) { xdg.configFile = desktopUnits; })
              {
                warnings =
                  lib.optional
                    (
                      !isHeadless
                      && builtins.pathExists "/dev/input"
                      && !(builtins.elem "input" (config.home.extraGroups or [ ]))
                    )
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
                    mergedDefault =
                      defaultProfile
                      // explicitDefault
                      // {
                        # Preserve wm from settings even if profiles.default is set.
                        wm = cfg.settings;
                      };
                    otherProfiles = lib.filterAttrs (n: _: n != "default") cfg.profiles;
                    # Add `name` field to each non-default profile.
                    namedOtherProfiles = lib.mapAttrs (name: value: { inherit name; } // value) otherProfiles;
                    allProfiles = {
                      default = mergedDefault;
                    }
                    // namedOtherProfiles;
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

                # The units' ReadWritePaths (%t/pds, %E/pds, %C/open-sesame)
                # bind-mount into each service's namespace and must exist on the
                # real filesystem first: the daemons that do not declare the
                # matching *Directory= (secrets, snippets, wm, clipboard, input)
                # fail with 226/NAMESPACE until daemon-profile has created them.
                # Created owner-only, as the daemons keep them; fontconfig's cache
                # (optional in open-sesame-wm.service) so daemon-wm caches fonts.
                systemd.user.tmpfiles.rules = [
                  "d %t/pds 0700 - - -"
                  "d ${config.xdg.configHome}/pds 0700 - - -"
                  "d ${config.xdg.cacheHome}/open-sesame 0700 - - -"
                ]
                ++ lib.optionals (!isHeadless) [
                  "d ${config.xdg.cacheHome}/fontconfig 0755 - - -"
                ];
              }
            ]
          );
        };

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          common = pkgs.callPackage ./nix/common.nix { };
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              # Rust toolchain: rust-toolchain.toml (nix/common.nix) plus
              # rust-src and rust-analyzer
              common.devToolchain

              # Build tools
              pkg-config
              patchelf
              cargo-deb
              (pkgs.callPackage ./nix/cargo-generate-rpm.nix { })

              # tests/protocol_validation.sh: the doctor's JSON report
              jq

              # Documentation
              mdbook
              lychee
              tokei

              # Node (semantic-release, commitlint)
              nodejs

              # Linting & formatting
              taplo
              shellcheck
              shfmt
              actionlint
              markdownlint-cli2
              lefthook

              # Supply chain: advisories, licenses, sources, bans (deny.toml).
              # cargo-deny fetches the advisory database with git; a host git
              # run under this shell's LD_LIBRARY_PATH loads the shell's glibc
              # and aborts.
              cargo-deny
              git

              # Task runner (.mise.toml: qa:*, ci:*, cargo:*)
              mise
            ];

            buildInputs = with pkgs; [
              # SQLCipher (rusqlite bundled-sqlcipher)
              openssl

              # Wayland (platform-linux, daemon-wm overlay)
              wayland
              wayland-protocols
              libxkbcommon

              # System libs
              fontconfig
              pcsclite
              libseccomp

              # GTK4 (daemon-launcher `gtk` feature; built by the lefthook
              # pre-commit `cargo clippy --all-targets --all-features` gate)
              glib
              gtk4
            ];

            # pkg-config needs to find .pc files from buildInputs
            PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" (
              with pkgs;
              [
                openssl.dev
                wayland.dev
                wayland-protocols
                libxkbcommon.dev
                fontconfig.dev
                pcsclite.dev
                libseccomp.dev
                glib.dev
                gtk4.dev
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
                glib
                gtk4
              ]
            );

            # Runtime library path for test binaries. Nix-built test executables
            # have RUNPATH pointing to cargo's build dir, not the nix store where
            # shared libs actually live. LD_LIBRARY_PATH fills the gap at runtime.
            LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (
              with pkgs;
              [
                libseccomp
                openssl
                pcsclite
                fontconfig
                wayland
                libxkbcommon
                glib
                gtk4
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
