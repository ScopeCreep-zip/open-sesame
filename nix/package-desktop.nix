{
  lib,
  stdenv,
  makeRustPlatform,
  rust-bin,
  pkg-config,
  installShellFiles,
  makeWrapper,
  perl,
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
  rustToolchain = rust-bin.stable."1.97.0".minimal.override {
    extensions = [ "rust-src" ];
  };
  rustPlatform = makeRustPlatform {
    cargo = rustToolchain;
    rustc = rustToolchain;
  };

  workspaceToml = builtins.fromTOML (builtins.readFile ../Cargo.toml);

  rootDir = ./..;
  rootEntries = builtins.attrNames (builtins.readDir rootDir);
  isCrateDir =
    name:
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
      "cosmic-client-toolkit-0.2.0" = "sha256-u1Ur9lPm2HE60jCEJVhKtbGYfzV8pdiDjrsGwgKf3nA=";
      "cosmic-protocols-0.2.0" = "sha256-u1Ur9lPm2HE60jCEJVhKtbGYfzV8pdiDjrsGwgKf3nA=";
      "atomicwrites-0.4.2" = "sha256-QZSuGPrJXh+svMeFWqAXoqZQxLq/WfIiamqvjJNVhxA=";
      "cosmic-theme-1.0.0" = "sha256-2By9fKPXsNhoCP1Npyoi3bG8a8Bb15cEXewK6ea0WWo=";
      "smithay-clipboard-0.8.0" = "sha256-GojAFRbhJcP0Rpr+v9WOivgW9x38PZdeBWTbMhkDB3A=";
      "window_clipboard-0.4.1" = "sha256-WO3JFbE+6ESRAfkxrnEFeZyGuhUHLOKOVHcGQyHwoK0=";
      "nucleo-0.5.0" = "sha256-Hm4SxtTSBrcWpXrtSqeO0TACbUxq3gizg1zD/6Yw/sI=";
    };
  };

  nativeBuildInputs = [
    pkg-config
    installShellFiles
    makeWrapper
    perl
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
  cargoBuildFlags = lib.concatMap (c: [
    "--package"
    c
  ]) binaryCrates;

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
