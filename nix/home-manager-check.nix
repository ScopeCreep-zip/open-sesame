# The Home Manager module, evaluated through homeManagerConfiguration in
# desktop and headless mode, checked against the packages' own units:
#
#   - the module generates no open-sesame unit of its own
#     (systemd.user.services and .targets), so every directive is the
#     shipped unit's;
#   - every unit it links is a file of the mode's packages under
#     lib/systemd/user, at the same name, and nothing else is linked;
#   - every shipped unit of those packages is linked, and enabled exactly
#     as its [Install] WantedBy= says: a <target>.wants/<unit> link for each
#     target it names and no other;
#   - every service has the logLevel drop-in, setting RUST_LOG.
{
  lib,
  pkgs,
  runCommand,
  jq,
  homeManager,
  module,
  headlessPkg,
  desktopPkg,
}:

let
  jsonFormat = pkgs.formats.json { };
  logLevel = "debug";

  evalMode =
    headless:
    let
      config =
        (homeManager.lib.homeManagerConfiguration {
          inherit pkgs;
          modules = [
            module
            {
              home.username = "check";
              home.homeDirectory = "/home/check";
              home.stateVersion = "25.11";
              programs.open-sesame = {
                enable = true;
                inherit headless logLevel;
              };
            }
          ];
        }).config;
      generated = lib.filter (lib.hasPrefix "open-sesame") (
        lib.attrNames config.systemd.user.services ++ lib.attrNames config.systemd.user.targets
      );
      links = lib.filterAttrs (
        name: _: lib.hasPrefix "systemd/user/" name && lib.hasInfix "open-sesame" name
      ) config.xdg.configFile;
    in
    assert lib.assertMsg (generated == [ ])
      "home-manager module (headless = ${lib.boolToString headless}) generates its own units: ${toString generated}";
    {
      packages = [ headlessPkg ] ++ lib.optionals (!headless) [ desktopPkg ];
      links = lib.mapAttrsToList (name: file: {
        name = lib.removePrefix "systemd/user/" name;
        source = toString file.source;
      }) links;
    };

  modes = jsonFormat.generate "open-sesame-home-manager-modes.json" {
    desktop = evalMode false;
    headless = evalMode true;
  };
in
runCommand "open-sesame-home-manager-check"
  {
    nativeBuildInputs = [ jq ];
    inherit logLevel;
  }
  ''
    set -euo pipefail
    fail() { echo "home-manager module: $*" >&2; exit 1; }

    for mode in desktop headless; do
      links=$(jq -c --arg mode "$mode" '.[$mode].links[]' ${modes})
      mapfile -t packages < <(jq -r --arg mode "$mode" '.[$mode].packages[]' ${modes})
      has() { jq -e --arg name "$1" 'select(.name == $name)' <<<"$links" >/dev/null; }

      # Every link: a shipped unit file of this mode's packages, by name, or
      # the logLevel drop-in.
      while read -r link; do
        name=$(jq -r .name <<<"$link")
        source=$(jq -r .source <<<"$link")
        case "$name" in
        *.service.d/50-log-level.conf)
          grep -qx "Environment=RUST_LOG=$logLevel" "$source" \
            || fail "$mode: $name does not set RUST_LOG=$logLevel"
          continue
          ;;
        esac
        unit=''${name##*/}
        shipped=""
        for pkg in "''${packages[@]}"; do
          [[ "$source" == "$pkg/lib/systemd/user/$unit" ]] && shipped=$source
        done
        [[ -n "$shipped" && -f "$shipped" ]] \
          || fail "$mode: $name links $source, not a unit of this mode's packages"
        if [[ "$name" == *.wants/* ]]; then
          target=''${name%%.wants/*}
          sed -n '/^\[Install\]/,/^\[/{s/^WantedBy=//p}' "$shipped" | tr ' ' '\n' | grep -qx "$target" \
            || fail "$mode: $name, but $unit is not WantedBy=$target"
        fi
      done <<<"$links"

      # Every shipped unit: linked, enabled for each WantedBy= target, and,
      # for a service, given the logLevel drop-in.
      for pkg in "''${packages[@]}"; do
        for unit_file in "$pkg"/lib/systemd/user/*; do
          unit=''${unit_file##*/}
          has "$unit" || fail "$mode: shipped $unit is not linked"
          for target in $(sed -n '/^\[Install\]/,/^\[/{s/^WantedBy=//p}' "$unit_file"); do
            has "$target.wants/$unit" || fail "$mode: $unit is WantedBy=$target, not linked there"
          done
          if [[ "$unit" == *.service ]]; then
            has "$unit.d/50-log-level.conf" || fail "$mode: $unit has no logLevel drop-in"
          fi
        done
      done
      echo "$mode: $(wc -l <<<"$links") links checked against ''${packages[*]}"
    done
    touch "$out"
  ''
