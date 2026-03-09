//! Integration tests for per-daemon keypair persistence.
//!
//! Uses `Mutex<Option<PathBuf>>` runtime directory override instead of
//! `unsafe { set_var(...) }` to avoid race conditions with parallel tests.

use core_ipc::{generate_keypair, noise};

#[tokio::test]
async fn daemon_keypair_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let pds_dir = dir.path().join("pds");
    std::fs::create_dir_all(&pds_dir).unwrap();

    // Set override instead of mutating env (no set_var race).
    noise::set_runtime_dir_override(pds_dir.clone());

    noise::create_keys_dir().await.unwrap();

    // SECURITY INVARIANT: The keys directory must have 0700 permissions to
    // prevent other users from reading daemon private keys.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(pds_dir.join("keys")).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o700,
            "keys directory must have 0700 permissions"
        );
    }

    // Roundtrip: write + read.
    let kp = generate_keypair().unwrap();
    noise::write_daemon_keypair("test-daemon", kp.as_inner()).await.unwrap();

    let (private, public) = noise::read_daemon_keypair("test-daemon").await.unwrap();
    assert_eq!(&*private, kp.private());
    assert_eq!(public, <[u8; 32]>::try_from(kp.public()).unwrap());

    let pub_only = noise::read_daemon_public_key("test-daemon").await.unwrap();
    assert_eq!(pub_only, public);

    // SECURITY INVARIANT: Private key files must have 0600 permissions —
    // never world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(
            pds_dir.join("keys").join("test-daemon.key"),
        )
        .unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "private key must have 0600 permissions"
        );
    }

    // SECURITY INVARIANT: A tampered checksum must produce an error containing
    // "TAMPER DETECTED" — corrupted keypairs must never be silently accepted.
    let checksum_path = pds_dir.join("keys").join("test-daemon.checksum");
    assert!(checksum_path.exists(), "checksum file should exist");

    // Corrupt the checksum file.
    std::fs::write(&checksum_path, [0xDE; 32]).unwrap();
    let result = noise::read_daemon_keypair("test-daemon").await;
    assert!(
        result.is_err(),
        "tampered checksum should be detected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("TAMPER DETECTED"),
        "error should mention tamper detection, got: {err_msg}"
    );

    // Missing keypair returns error.
    let result = noise::read_daemon_keypair("nonexistent").await;
    assert!(result.is_err(), "reading nonexistent keypair must fail");

    // SECURITY INVARIANT: Bus keypair write must create bus.pub, bus.key (0600),
    // and bus.checksum for tamper detection.
    let bus_kp = generate_keypair().unwrap();
    noise::write_bus_keypair(bus_kp.as_inner()).await.unwrap();

    assert!(pds_dir.join("bus.pub").exists(), "bus.pub must exist");
    assert!(pds_dir.join("bus.key").exists(), "bus.key must exist");
    assert!(pds_dir.join("bus.checksum").exists(), "bus.checksum must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(pds_dir.join("bus.key")).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "bus.key must have 0600 permissions"
        );
        // bus.pub must have explicit 0644 permissions (defense-in-depth).
        let meta = std::fs::metadata(pds_dir.join("bus.pub")).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o644,
            "bus.pub must have 0644 permissions"
        );
    }

    // Per-daemon .pub file permissions: 0644.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(
            pds_dir.join("keys").join("test-daemon.pub"),
        )
        .unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o644,
            "daemon .pub file must have 0644 permissions"
        );
    }
}
