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
      ]
      ++ map (name: rootDir + "/${name}") crateDirs
    );
  };

  # Headless binary crates only.
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
  pname = "open-sesame-headless";
  version = workspaceToml.workspace.package.version;

  src = filteredSrc;

  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "cosmic-client-toolkit-0.1.0" = "sha256-KvXQJ/EIRyrlmi80WKl2T9Bn+j7GCfQlcjgcEVUxPkc=";
      "cosmic-protocols-0.1.0" = "sha256-KvXQJ/EIRyrlmi80WKl2T9Bn+j7GCfQlcjgcEVUxPkc=";
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

  # Build only headless crates with no default features (disables desktop).
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

    runHook postInstall
  '';

  meta = with lib; {
    description = "Open Sesame headless — secrets, profiles, launcher, snippets (no GUI)";
    homepage = "https://github.com/ScopeCreep-zip/open-sesame";
    license = licenses.mit;
    maintainers = [ ];
    platforms = platforms.linux;
    mainProgram = "sesame";
  };
}
