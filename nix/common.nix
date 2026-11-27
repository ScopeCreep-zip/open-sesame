# Build inputs shared by the open-sesame nix packages and the devshell: the
# toolchain that rust-toolchain.toml pins, the cargo source set, the
# workspace version and license, and the hashes of the git dependencies
# Cargo.lock pins.
{
  lib,
  makeRustPlatform,
  rust-bin,
}:

let
  rootDir = ./..;
  workspace = (builtins.fromTOML (builtins.readFile ../Cargo.toml)).workspace.package;
  # rust-toolchain.toml's [toolchain] table: the one toolchain pin.
  toolchainSpec = (builtins.fromTOML (builtins.readFile ../rust-toolchain.toml)).toolchain;
  toolchain = rust-bin.fromRustupToolchain toolchainSpec;

  # Every workspace member: Cargo.lock names them all, and cargo resolves the
  # lock from their manifests even when a package builds only some of them.
  isCrateDir =
    name:
    lib.hasPrefix "core-" name
    || lib.hasPrefix "daemon-" name
    || lib.hasPrefix "platform-" name
    || lib.hasPrefix "extension-" name
    || lib.hasPrefix "sesame-" name
    || name == "open-sesame"
    || name == "xtask";
  crateDirs = lib.filter isCrateDir (builtins.attrNames (builtins.readDir rootDir));
in
{
  rustPlatform = makeRustPlatform {
    cargo = toolchain;
    rustc = toolchain;
  };

  # The same toolchain plus the editor components, for the devshell.
  devToolchain = rust-bin.fromRustupToolchain (
    lib.recursiveUpdate toolchainSpec {
      components = toolchainSpec.components ++ [
        "rust-src"
        "rust-analyzer"
      ];
    }
  );

  inherit (workspace) version;

  src = lib.fileset.toSource {
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

  # One entry per git source in Cargo.lock; a pinned rev change in
  # Cargo.toml changes its hash here.
  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "cosmic-client-toolkit-0.2.0" = "sha256-5BEUK/+RwSk6X3/4NRY91Ef1b/vZ0nk0oObN0Y1ylz0=";
      "cosmic-protocols-0.2.0" = "sha256-5BEUK/+RwSk6X3/4NRY91Ef1b/vZ0nk0oObN0Y1ylz0=";
      "atomicwrites-0.4.2" = "sha256-QZSuGPrJXh+svMeFWqAXoqZQxLq/WfIiamqvjJNVhxA=";
      "cosmic-text-0.19.0" = "sha256-1CA6i1HCk403aDe8afNa0mbp21a4SVkj8RdeOlXAIvY=";
      "cosmic-theme-1.0.0" = "sha256-s2JQufF1l23bJKYQ7m1Tb6bFqYv+QBqwZoTUQ9p2OwY=";
      "smithay-clipboard-0.8.0" = "sha256-GojAFRbhJcP0Rpr+v9WOivgW9x38PZdeBWTbMhkDB3A=";
      "window_clipboard-0.4.1" = "sha256-WO3JFbE+6ESRAfkxrnEFeZyGuhUHLOKOVHcGQyHwoK0=";
      "nucleo-0.5.0" = "sha256-uROmRwBtE527jLfDcgV168DIu6HyA5z96cU1wCeLqNA=";
    };
  };

  # The packages' build and test flags for a list of crates.
  packageFlags = lib.concatMap (crate: [
    "--package"
    crate
  ]);

  meta = {
    homepage = workspace.repository;
    license = lib.getLicenseFromSpdxId workspace.license;
    maintainers = [ ];
    platforms = lib.platforms.linux;
    mainProgram = "sesame";
  };
}
