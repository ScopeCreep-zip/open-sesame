{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  installShellFiles,
  makeWrapper,
  openssl,
  fontconfig,
  wayland,
  wayland-protocols,
  libxkbcommon,
  xkeyboard-config,
  libseccomp,
  open-sesame,
}:

let
  workspaceToml = builtins.fromTOML (builtins.readFile ../Cargo.toml);

  rootDir = ./..;
  rootEntries = builtins.attrNames (builtins.readDir rootDir);
  isCrateDir = name:
    lib.hasPrefix "core-" name
    || lib.hasPrefix "daemon-" name
    || lib.hasPrefix "platform-" name
    || lib.hasPrefix "extension-" name
    || lib.hasPrefix "sesame-" name
    || name == "open-sesame"
    || name == "xtask";
  crateDirs = lib.filter isCrateDir rootEntries;

  filteredSrc = lib.fileset.toSource {
    root = rootDir;
    fileset = lib.fileset.unions (
      [
        ../Cargo.toml
        ../Cargo.lock
        ../rust-toolchain.toml
        ../config.example.toml
        ../.cargo
        ../contrib
      ]
      ++ map (name: rootDir + "/${name}") crateDirs
    );
  };

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
rustPlatform.buildRustPackage {
  pname = "open-sesame-desktop";
  version = workspaceToml.workspace.package.version;

  src = filteredSrc;

  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "cosmic-client-toolkit-0.2.0" = "sha256-ymn+BUTTzyHquPn4hvuoA3y1owFj8LVrmsPu2cdkFQ8=";
      "cosmic-protocols-0.2.0" = "sha256-ymn+BUTTzyHquPn4hvuoA3y1owFj8LVrmsPu2cdkFQ8=";
      "nucleo-0.5.0" = "sha256-Hm4SxtTSBrcWpXrtSqeO0TACbUxq3gizg1zD/6Yw/sI=";
    };
  };

  nativeBuildInputs = [
    pkg-config
    installShellFiles
    makeWrapper
  ];

  buildInputs = [
    openssl
    fontconfig
    wayland
    wayland-protocols
    libxkbcommon
    libseccomp
  ];

  # Build desktop crates with default features (desktop enabled).
  cargoBuildFlags =
    lib.concatMap (c: [ "--package" c ]) binaryCrates;

  cargoTestFlags = [ "--workspace" ];

  preCheck = ''
    export HOME=$(mktemp -d)
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

    # daemon-wm uses libxkbcommon which needs evdev rules at runtime.
    wrapProgram $out/bin/daemon-wm \
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

  meta = with lib; {
    description = "Open Sesame desktop — window switcher, clipboard, input for COSMIC/Wayland (requires open-sesame)";
    homepage = "https://github.com/ScopeCreep-zip/open-sesame";
    license = licenses.mit;
    maintainers = [ ];
    platforms = platforms.linux;
    mainProgram = "sesame";
  };
}
