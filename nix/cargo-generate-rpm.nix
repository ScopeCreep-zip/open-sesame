{
  lib,
  rustPlatform,
  fetchFromGitHub,
  pkg-config,
  zstd,
}:

rustPlatform.buildRustPackage {
  pname = "cargo-generate-rpm";
  version = "0.21.1";

  src = fetchFromGitHub {
    owner = "cat-in-136";
    repo = "cargo-generate-rpm";
    rev = "v0.21.1";
    hash = "sha256-7E3p1p2hsoJRromyZaMz2FsHMleqbzVJBj93akOUfjA=";
  };

  # Upstream does not commit Cargo.lock — generated via cargo generate-lockfile
  # against v0.21.1 source and checked in as cargo-generate-rpm.lock.
  cargoLock.lockFile = ./cargo-generate-rpm.lock;
  postPatch = ''
    cp ${./cargo-generate-rpm.lock} Cargo.lock
  '';

  # rpm's zstd-compression feature builds zstd-sys, which links the system
  # zstd found through pkg-config.
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ zstd ];
  env.ZSTD_SYS_USE_PKG_CONFIG = true;

  doCheck = false;

  meta = {
    description = "Cargo subcommand that generates RPM packages from Cargo.toml metadata";
    mainProgram = "cargo-generate-rpm";
    homepage = "https://github.com/cat-in-136/cargo-generate-rpm";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
