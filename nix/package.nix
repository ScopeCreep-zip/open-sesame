{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  installShellFiles,
  openssl,
  fontconfig,
  wayland,
  wayland-protocols,
  libxkbcommon,
  libseccomp,
  glib,
  gtk4,
  cairo,
  pango,
  graphene,
  gtk4-layer-shell,
}:

let
  workspaceToml = builtins.fromTOML (builtins.readFile ../Cargo.toml);

  # Source filter: only include files needed for cargo build.
  # Excludes docs, analysis files, CI configs, v1 source, and other non-build assets.
  rootDir = ./..;
  rootEntries = builtins.attrNames (builtins.readDir rootDir);
  isCrateDir = name:
    lib.hasPrefix "core-" name
    || lib.hasPrefix "daemon-" name
    || lib.hasPrefix "platform-" name
    || lib.hasPrefix "extension-" name
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

  # All crates that produce binaries (excludes library-only crates and xtask).
  binaryCrates = [
    "open-sesame"
    "daemon-profile"
    "daemon-secrets"
    "daemon-launcher"
    "daemon-wm"
    "daemon-clipboard"
    "daemon-input"
    "daemon-snippets"
  ];

  # Expected binary names (open-sesame produces "sesame" via [[bin]]).
  expectedBinaries = [
    "sesame"
    "daemon-profile"
    "daemon-secrets"
    "daemon-launcher"
    "daemon-wm"
    "daemon-clipboard"
    "daemon-input"
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
    fontconfig
    wayland
    wayland-protocols
    libxkbcommon
    libseccomp
    glib
    gtk4
    cairo
    pango
    graphene
    gtk4-layer-shell
  ];

  # Explicit --package flags for each binary crate. Using --workspace would
  # also work for the build, but cargoBuildHook may implicitly filter to
  # pname-derived binaries. Explicit package list avoids ambiguity.
  cargoBuildFlags =
    lib.concatMap (c: [ "--package" c ]) binaryCrates;

  cargoTestFlags = [ "--workspace" ];

  # Tests that create $HOME/.cache/ dirs fail in the nix sandbox (/homeless-shelter)
  preCheck = ''
    export HOME=$(mktemp -d)
  '';

  # Generate man pages and shell completions via xtask.
  # TODO: xtask is in [workspace] exclude — cargo cannot resolve it as a
  # workspace member and its deps are not in the vendored directory.
  # Re-enable once xtask is moved into workspace members or given its own
  # Cargo.lock for standalone vendoring.
  # postBuild = ''
  #   cargo run --manifest-path xtask/Cargo.toml -- man
  #   cargo run --manifest-path xtask/Cargo.toml -- completions
  # '';

  # Bypass the default cargoInstallHook which only installs one binary.
  # All binaries are already compiled in target/release/ by cargoBuildHook.
  dontCargoInstall = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin
    releaseDir=target/${stdenv.hostPlatform.rust.cargoShortTarget}/release
    for bin in ${lib.concatStringsSep " " expectedBinaries}; do
      install -Dm755 "$releaseDir/$bin" "$out/bin/$bin"
    done

    # TODO: re-enable once xtask postBuild is restored
    # installManPage target/man/sesame.1.gz
    #
    # installShellCompletion --cmd sesame \
    #   --bash target/completions/sesame.bash \
    #   --zsh target/completions/_sesame \
    #   --fish target/completions/sesame.fish

    install -Dm644 config.example.toml $out/share/doc/open-sesame/config.example.toml

    runHook postInstall
  '';

  meta = with lib; {
    description = "Programmable desktop suite — window switcher, launcher, secrets, and orchestration for COSMIC/Wayland";
    homepage = "https://github.com/ScopeCreep-zip/open-sesame";
    license = licenses.mit;
    maintainers = [ ];
    platforms = platforms.linux;
    mainProgram = "sesame";
  };
}
