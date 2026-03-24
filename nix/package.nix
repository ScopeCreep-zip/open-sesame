{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  installShellFiles,
  openssl,
  libseccomp,
}:

let
  workspaceToml = builtins.fromTOML (builtins.readFile ../Cargo.toml);

  # Source filter: only include files needed for cargo build.
  # Excludes docs, analysis files, CI configs, v1 source, and other non-build assets.
  # NOTE: All crate dirs are included because Cargo.lock references workspace members
  # and cargo needs their Cargo.toml files to resolve the lock, even if they aren't built.
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

  # Headless binary crates only — no GUI daemons.
  binaryCrates = [
    "open-sesame"
    "daemon-profile"
    "daemon-secrets"
    "daemon-launcher"
    "daemon-snippets"
  ];

  expectedBinaries = [
    "sesame"
    "daemon-profile"
    "daemon-secrets"
    "daemon-launcher"
    "daemon-snippets"
  ];
in
rustPlatform.buildRustPackage {
  pname = "open-sesame";
  version = workspaceToml.workspace.package.version;

  src = filteredSrc;

  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      # Required by Cargo.lock even though headless doesn't build these crates.
      "cosmic-client-toolkit-0.2.0" = "sha256-ymn+BUTTzyHquPn4hvuoA3y1owFj8LVrmsPu2cdkFQ8=";
      "cosmic-protocols-0.2.0" = "sha256-ymn+BUTTzyHquPn4hvuoA3y1owFj8LVrmsPu2cdkFQ8=";
      "nucleo-0.5.0" = "sha256-Hm4SxtTSBrcWpXrtSqeO0TACbUxq3gizg1zD/6Yw/sI=";
    };
  };

  nativeBuildInputs = [
    pkg-config
    installShellFiles
  ];

  buildInputs = [
    openssl
    libseccomp
  ];

  # Build headless crates with desktop features disabled.
  cargoBuildFlags =
    (lib.concatMap (c: [ "--package" c ]) binaryCrates)
    ++ [ "--no-default-features" ];

  cargoTestFlags =
    (lib.concatMap (c: [ "--package" c ]) binaryCrates)
    ++ [ "--no-default-features" ];

  preCheck = ''
    export HOME=$(mktemp -d)
  '';

  dontCargoInstall = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin
    releaseDir=target/${stdenv.hostPlatform.rust.cargoShortTarget}/release
    for bin in ${lib.concatStringsSep " " expectedBinaries}; do
      install -Dm755 "$releaseDir/$bin" "$out/bin/$bin"
    done

    install -Dm644 config.example.toml $out/share/doc/open-sesame/config.example.toml

    # Headless systemd units
    install -Dm644 contrib/systemd/open-sesame-headless.target \
      $out/lib/systemd/user/open-sesame-headless.target
    for svc in profile secrets launcher snippets; do
      install -Dm644 "contrib/systemd/open-sesame-$svc.service" \
        "$out/lib/systemd/user/open-sesame-$svc.service"
    done

    # Patch systemd unit ExecStart from FHS /usr/bin/ to nix store path.
    # Without this, units fail with 203/EXEC on NixOS and standalone nix.
    for unit in $out/lib/systemd/user/*.service; do
      substituteInPlace "$unit" \
        --replace-fail "/usr/bin/" "$out/bin/"
    done

    runHook postInstall
  '';

  meta = with lib; {
    description = "Open Sesame — secrets, profiles, launcher, snippets (headless)";
    homepage = "https://github.com/ScopeCreep-zip/open-sesame";
    license = licenses.mit;
    maintainers = [ ];
    platforms = platforms.linux;
    mainProgram = "sesame";
  };
}
