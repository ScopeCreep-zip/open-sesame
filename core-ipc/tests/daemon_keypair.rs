//! Integration tests for the bus endpoint record and per-daemon keypair
//! persistence.
//!
//! Every location comes from a `core_layout::Layout` under a temporary
//! root, so tests never touch the process environment.

use core_ipc::noise::{self, BusEndpoint, NoiseSuite, generate_keypair};
use core_layout::{KeyFile, Layout};
use core_types::{NoiseCipher, NoiseHash};

#[cfg(unix)]
fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// A layout under a fresh root, with the keys directory created.
async fn layout() -> (tempfile::TempDir, Layout) {
    let root = tempfile::tempdir().unwrap();
    let layout = Layout::under(root.path());
    noise::create_keys_dir(&layout).await.unwrap();
    (root, layout)
}

#[tokio::test]
async fn daemon_keypair_persistence() {
    let (_root, layout) = layout().await;

    // SECURITY INVARIANT: The keys directory must have 0700 permissions to
    // prevent other users from reading daemon private keys.
    #[cfg(unix)]
    assert_eq!(
        mode(&layout.keys_dir().unwrap()),
        0o700,
        "keys directory must have 0700 permissions"
    );

    let kp = generate_keypair().unwrap();
    let written = noise::write_daemon_keypair(&layout, "test-daemon", kp.as_inner())
        .await
        .unwrap();
    let (private, public) = noise::read_daemon_keypair(&layout, "test-daemon")
        .await
        .unwrap();
    assert_eq!(&*private, kp.private());
    assert_eq!(public, <[u8; 32]>::try_from(kp.public()).unwrap());
    assert_eq!(written, public);

    // SECURITY INVARIANT: Private key and checksum files are 0600 — never
    // world-readable. Public key files are 0644.
    #[cfg(unix)]
    for (file, expected) in [
        (KeyFile::Private, 0o600),
        (KeyFile::Public, 0o644),
        (KeyFile::Checksum, 0o600),
    ] {
        let path = layout.daemon_key_file("test-daemon", file).unwrap();
        assert_eq!(mode(&path), expected, "{}", path.display());
    }

    // Missing keypair returns error.
    assert!(
        noise::read_daemon_keypair(&layout, "nonexistent")
            .await
            .is_err(),
        "reading nonexistent keypair must fail"
    );
}

// SECURITY INVARIANT: A tampered checksum must produce an error containing
// "TAMPER DETECTED" naming the files — corrupted keypairs are never
// silently accepted.
#[tokio::test]
async fn a_tampered_checksum_is_rejected() {
    let (_root, layout) = layout().await;
    noise::issue_daemon_keypair(&layout, "test-daemon")
        .await
        .unwrap();
    let checksum = layout
        .daemon_key_file("test-daemon", KeyFile::Checksum)
        .unwrap();
    std::fs::write(&checksum, [0xDE; 32]).unwrap();
    let err = noise::read_daemon_keypair(&layout, "test-daemon")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("TAMPER DETECTED"), "{err}");
    assert!(err.contains(&checksum.display().to_string()), "{err}");
}

// SECURITY INVARIANT: deleting the checksum does not bypass verification;
// every writer writes one, so its absence is an error.
#[tokio::test]
async fn a_missing_checksum_is_rejected() {
    let (_root, layout) = layout().await;
    noise::issue_daemon_keypair(&layout, "test-daemon")
        .await
        .unwrap();
    let checksum = layout
        .daemon_key_file("test-daemon", KeyFile::Checksum)
        .unwrap();
    std::fs::remove_file(&checksum).unwrap();
    let err = noise::read_daemon_keypair(&layout, "test-daemon")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains(&checksum.display().to_string()), "{err}");
}

#[tokio::test]
async fn issued_keypair_is_persisted_and_its_public_key_returned() {
    let (_root, layout) = layout().await;
    let first = noise::issue_daemon_keypair(&layout, "test-daemon")
        .await
        .unwrap();
    let (_, persisted) = noise::read_daemon_keypair(&layout, "test-daemon")
        .await
        .unwrap();
    assert_eq!(first, persisted);

    // Each issue replaces the previous keypair.
    let second = noise::issue_daemon_keypair(&layout, "test-daemon")
        .await
        .unwrap();
    assert_ne!(first, second);
    let (_, persisted) = noise::read_daemon_keypair(&layout, "test-daemon")
        .await
        .unwrap();
    assert_eq!(persisted, second);
}

// SECURITY INVARIANT: the bus endpoint is world-readable and holds no
// private key material; the server's private key is never written.
#[tokio::test]
async fn bus_endpoint_round_trips_and_is_public() {
    let (_root, layout) = layout().await;
    let kp = generate_keypair().unwrap();
    let endpoint = BusEndpoint {
        suite: NoiseSuite::new(NoiseCipher::AesGcm, NoiseHash::Sha256),
        public_key: kp.public().try_into().unwrap(),
    };
    noise::publish_bus_endpoint(&layout, &endpoint)
        .await
        .unwrap();
    assert_eq!(noise::read_bus_endpoint(&layout).await.unwrap(), endpoint);

    let path = layout.bus_endpoint_file().unwrap();
    let contents = std::fs::read(&path).unwrap();
    assert!(
        !contents
            .windows(kp.private().len())
            .any(|w| w == kp.private()),
        "the endpoint must not contain the private key"
    );
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o644);
    let runtime = layout.runtime_dir().unwrap();
    let names: Vec<_> = std::fs::read_dir(&runtime)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        names.iter().all(|n| n == "bus.endpoint" || n == "keys"),
        "only the endpoint and the keys directory are written: {names:?}"
    );
}
