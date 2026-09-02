{
  lib,
  rustPlatform,
  fetchFromGitHub,
}:

rustPlatform.buildRustPackage {
  pname = "cargo-generate-rpm";
  version = "0.21.0";

  src = fetchFromGitHub {
    owner = "cat-in-136";
    repo = "cargo-generate-rpm";
    rev = "v0.21.0";
    hash = "sha256-Ok/ATMI2Z9hQPMVaFgngdc/UmaIX4KXhHwyKZZ53zfc=";
  };

  # Upstream does not commit Cargo.lock — generated via cargo generate-lockfile
  # against v0.21.0 source and checked in as cargo-generate-rpm.lock.
  cargoLock.lockFile = ./cargo-generate-rpm.lock;
  postPatch = ''
    cp ${./cargo-generate-rpm.lock} Cargo.lock
  '';

  doCheck = false;

  meta = {
    description = "Cargo subcommand that generates RPM packages from Cargo.toml metadata";
    mainProgram = "cargo-generate-rpm";
    homepage = "https://github.com/cat-in-136/cargo-generate-rpm";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
