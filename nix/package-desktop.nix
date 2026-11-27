{
  lib,
  stdenv,
  callPackage,
  pkg-config,
  installShellFiles,
  makeWrapper,
  perl,
  openssl,
  libgit2,
  fontconfig,
  wayland,
  wayland-protocols,
  libxkbcommon,
  xkeyboard-config,
  libseccomp,
  sqlcipher,
  makeFontsConf,
  dejavu_fonts,
  open-sesame,
}:

let
  common = callPackage ./common.nix { };

  # Desktop-only binary crates + CLI (rebuilt with desktop features).
  binaryCrates = [
    "open-sesame"
    "daemon-wm"
    "daemon-clipboard"
    "daemon-input"
  ];

  expectedBinaries = [
    "sesame"
    "daemon-wm"
    "daemon-clipboard"
    "daemon-input"
  ];
in
common.rustPlatform.buildRustPackage {
  pname = "open-sesame-desktop";
  inherit (common) version src cargoLock;

  nativeBuildInputs = [
    pkg-config
    installShellFiles
    makeWrapper
    perl
  ];

  # cargoUseSystemLibs sets OPENSSL_NO_VENDOR, LIBGIT2_NO_VENDOR, and
  # LIBSQLITE3_SYS_USE_PKG_CONFIG: git2's vendored-openssl and
  # vendored-libgit2 and rusqlite's bundled-sqlcipher yield to these.
  buildInputs = [
    openssl
    libgit2
    fontconfig
    wayland
    wayland-protocols
    libxkbcommon
    libseccomp
    sqlcipher
  ];

  # Build desktop crates with default features (desktop enabled).
  cargoBuildFlags = common.packageFlags binaryCrates;

  cargoTestFlags = [ "--workspace" ];

  # daemon-wm's text tests shape with real fonts; daemon-input's XKB tests
  # compile the default keymap.
  preCheck = ''
    export HOME=$(mktemp -d)
    export XKB_CONFIG_ROOT=${xkeyboard-config}/etc/X11/xkb
    export FONTCONFIG_FILE=${makeFontsConf { fontDirectories = [ dejavu_fonts ]; }}
  '';

  # The headless package provides the base binaries on PATH.
  propagatedBuildInputs = [ open-sesame ];

  dontCargoInstall = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin
    releaseDir=target/${stdenv.hostPlatform.rust.cargoShortTarget}/release
    for bin in ${lib.concatStringsSep " " expectedBinaries}; do
      install -Dm755 "$releaseDir/$bin" "$out/bin/$bin"
    done

    # daemon-input compiles the system keymap from XKB data
    # (xkb_keymap_new_from_names); daemon-wm takes the compositor's keymap.
    wrapProgram $out/bin/daemon-input \
      --set XKB_CONFIG_ROOT "${xkeyboard-config}/etc/X11/xkb"

    # Desktop systemd units
    install -Dm644 contrib/systemd/open-sesame-desktop.target \
      $out/lib/systemd/user/open-sesame-desktop.target
    for svc in wm clipboard input; do
      install -Dm644 "contrib/systemd/open-sesame-$svc.service" \
        "$out/lib/systemd/user/open-sesame-$svc.service"
    done

    # Patch systemd unit ExecStart from FHS /usr/bin/ to nix store path.
    for unit in $out/lib/systemd/user/*.service; do
      substituteInPlace "$unit" \
        --replace-fail "/usr/bin/" "$out/bin/"
    done

    runHook postInstall
  '';

  meta = lib.recursiveUpdate common.meta {
    description = "Open Sesame desktop — window switcher, clipboard, input for COSMIC/Wayland (requires open-sesame)";
  };
}
