{
  lib,
  stdenv,
  callPackage,
  pkg-config,
  installShellFiles,
  perl,
  openssl,
  libgit2,
  libseccomp,
  sqlcipher,
}:

let
  common = callPackage ./common.nix { };

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
common.rustPlatform.buildRustPackage {
  pname = "open-sesame";
  inherit (common) version src cargoLock;

  nativeBuildInputs = [
    pkg-config
    installShellFiles
    perl
  ];

  # cargoUseSystemLibs sets OPENSSL_NO_VENDOR, LIBGIT2_NO_VENDOR, and
  # LIBSQLITE3_SYS_USE_PKG_CONFIG: git2's vendored-openssl and
  # vendored-libgit2 and rusqlite's bundled-sqlcipher yield to these.
  buildInputs = [
    openssl
    libgit2
    libseccomp
    sqlcipher
  ];

  # Build headless crates with desktop features disabled.
  cargoBuildFlags = common.packageFlags binaryCrates ++ [ "--no-default-features" ];
  cargoTestFlags = common.packageFlags binaryCrates ++ [ "--no-default-features" ];

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

  meta = lib.recursiveUpdate common.meta {
    description = "Open Sesame — secrets, profiles, launcher, snippets (headless)";
  };
}
