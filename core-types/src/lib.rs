//! Shared types, error types, and event schema for the PDS IPC bus.
//!
//! This crate defines the canonical type system shared across all PDS crates.
//! It has zero platform dependencies and is `no_std`-compatible for hot-path types.
//! Minimal external deps: serde, uuid, thiserror.
#![deny(unsafe_code)]

pub mod auth;
pub mod constants;
pub mod crypto;
pub mod denial;
pub mod error;
pub mod events;
pub mod ids;
pub mod oci;
pub mod profile;
pub mod rpc;
pub mod security;
pub mod sensitive;
pub mod window;

// Re-export all public types at crate root for backwards compatibility.
pub use auth::*;
pub use constants::*;
pub use crypto::*;
pub use denial::*;
pub use error::*;
pub use events::*;
pub use ids::*;
pub use oci::*;
pub use profile::*;
pub use rpc::*;
pub use security::*;
pub use sensitive::*;
pub use window::*;

/// Initialize the secure memory subsystem. Must be called before seccomp
/// sandbox is applied in every daemon process.
///
/// Probes for `memfd_secret(2)` support and caches the result. If seccomp
/// is active when the first `ProtectedAlloc` is created, the probe syscall
/// (447) would be blocked and kill the thread. Calling this function early
/// ensures the probe happens before sandbox setup.
pub fn init_secure_memory() {
    core_memory::init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use uuid::Uuid;

    // -- AppId tests (v1 behavioral spec) --

    #[test]
    fn app_id_last_segment_reverse_dns() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert_eq!(id.last_segment(), "ghostty");
    }

    #[test]
    fn app_id_last_segment_simple() {
        let id = AppId::new("firefox");
        assert_eq!(id.last_segment(), "firefox");
    }

    #[test]
    fn app_id_matches_full() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert!(id.matches("com.mitchellh.ghostty"));
    }

    #[test]
    fn app_id_matches_last_segment() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert!(id.matches("ghostty"));
    }

    #[test]
    fn app_id_matches_case_insensitive() {
        let id = AppId::new("com.mitchellh.Ghostty");
        assert!(id.matches("ghostty"));
    }

    #[test]
    fn app_id_matches_other_reverse_dns() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert!(id.matches("org.example.ghostty"));
    }

    #[test]
    fn app_id_no_match() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert!(!id.matches("firefox"));
    }

    // -- SecretRef debug redaction --

    #[test]
    fn secret_ref_debug_does_not_leak_values() {
        let r = SecretRef::Keyring {
            secret: "work/token".into(),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("keyring:work/token"));
        // The ref path is safe to log; the resolved VALUE never appears in this type.
    }

    // -- Sensitivity ordering --

    #[test]
    fn sensitivity_ordering() {
        assert!(SensitivityClass::Public < SensitivityClass::Confidential);
        assert!(SensitivityClass::Confidential < SensitivityClass::Secret);
        assert!(SensitivityClass::Secret < SensitivityClass::TopSecret);
    }

    // -- SecurityLevel ordering --

    #[test]
    fn security_level_ordering() {
        assert!(SecurityLevel::Open < SecurityLevel::Internal);
        assert!(SecurityLevel::Internal < SecurityLevel::ProfileScoped);
        assert!(SecurityLevel::ProfileScoped < SecurityLevel::SecretsOnly);
    }

    // -- Serialization round-trip property tests --

    proptest! {
        #[test]
        fn profile_id_roundtrip_postcard(n in any::<u128>()) {
            let id = ProfileId::from_uuid(Uuid::from_u128(n));
            let bytes = postcard::to_allocvec(&id).unwrap();
            let decoded: ProfileId = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(id, decoded);
        }

        #[test]
        fn window_id_roundtrip_json(n in any::<u128>()) {
            let id = WindowId::from_uuid(Uuid::from_u128(n));
            let json = serde_json::to_string(&id).unwrap();
            let decoded: WindowId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(id, decoded);
        }

        #[test]
        fn app_id_roundtrip_json(s in "[a-z]{1,5}(\\.[a-z]{1,5}){0,3}") {
            let id = AppId::new(s);
            let json = serde_json::to_string(&id).unwrap();
            let decoded: AppId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(id, decoded);
        }

        #[test]
        fn sensitivity_roundtrip_json(idx in 0u8..4) {
            let class = match idx {
                0 => SensitivityClass::Public,
                1 => SensitivityClass::Confidential,
                2 => SensitivityClass::Secret,
                _ => SensitivityClass::TopSecret,
            };
            let json = serde_json::to_string(&class).unwrap();
            let decoded: SensitivityClass = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(class, decoded);
        }

        #[test]
        fn trust_profile_name_roundtrip_postcard_prop(s in "[a-zA-Z][a-zA-Z0-9_-]{0,63}") {
            let name = TrustProfileName::try_from(s).unwrap();
            let bytes = postcard::to_allocvec(&name).unwrap();
            let decoded: TrustProfileName = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(name, decoded);
        }

        #[test]
        fn geometry_roundtrip_postcard(x in any::<i32>(), y in any::<i32>(), w in any::<u32>(), h in any::<u32>()) {
            let geo = Geometry { x, y, width: w, height: h };
            let bytes = postcard::to_allocvec(&geo).unwrap();
            let decoded: Geometry = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(geo, decoded);
        }
    }

    // -- TrustProfileName validation --

    #[test]
    fn trust_profile_name_valid() {
        for name in [
            "default",
            "work",
            "corporate-aws",
            "my_profile",
            "a",
            "A1-b_2",
        ] {
            assert!(
                TrustProfileName::try_from(name).is_ok(),
                "expected '{name}' to be valid"
            );
        }
    }

    #[test]
    fn trust_profile_name_rejects_empty() {
        assert!(TrustProfileName::try_from("").is_err());
    }

    #[test]
    fn trust_profile_name_rejects_path_traversal() {
        assert!(TrustProfileName::try_from(".").is_err());
        assert!(TrustProfileName::try_from("..").is_err());
        assert!(TrustProfileName::try_from("../../etc/passwd").is_err());
    }

    #[test]
    fn trust_profile_name_rejects_slashes() {
        assert!(TrustProfileName::try_from("foo/bar").is_err());
        assert!(TrustProfileName::try_from("foo\\bar").is_err());
    }

    #[test]
    fn trust_profile_name_rejects_spaces_and_special() {
        assert!(TrustProfileName::try_from("foo bar").is_err());
        assert!(TrustProfileName::try_from("foo\0bar").is_err());
        assert!(TrustProfileName::try_from("-leading").is_err());
        assert!(TrustProfileName::try_from("_leading").is_err());
    }

    #[test]
    fn trust_profile_name_rejects_over_64() {
        let long = "a".repeat(65);
        assert!(TrustProfileName::try_from(long).is_err());
    }

    #[test]
    fn trust_profile_name_roundtrip_json() {
        let name = TrustProfileName::try_from("corporate-aws").unwrap();
        let json = serde_json::to_string(&name).unwrap();
        assert_eq!(json, "\"corporate-aws\"");
        let decoded: TrustProfileName = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, name);
    }

    #[test]
    fn trust_profile_name_roundtrip_postcard() {
        let name = TrustProfileName::try_from("my-profile").unwrap();
        let bytes = postcard::to_allocvec(&name).unwrap();
        let decoded: TrustProfileName = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, name);
    }

    #[test]
    fn trust_profile_name_json_rejects_invalid() {
        let result: std::result::Result<TrustProfileName, _> =
            serde_json::from_str("\"../../etc\"");
        assert!(result.is_err());
    }

    #[test]
    fn trust_profile_name_deref_to_str() {
        let name = TrustProfileName::try_from("work").unwrap();
        let s: &str = &name;
        assert_eq!(s, "work");
    }

    #[test]
    fn trust_profile_name_display() {
        let name = TrustProfileName::try_from("work").unwrap();
        assert_eq!(format!("{name}"), "work");
    }

    // -- validate_secret_key --

    #[test]
    fn secret_key_valid() {
        assert!(validate_secret_key("api-key").is_ok());
        assert!(validate_secret_key("a").is_ok());
        assert!(validate_secret_key(&"x".repeat(256)).is_ok());
    }

    #[test]
    fn secret_key_rejects_empty() {
        assert!(validate_secret_key("").is_err());
    }

    #[test]
    fn secret_key_rejects_too_long() {
        assert!(validate_secret_key(&"x".repeat(257)).is_err());
    }

    #[test]
    fn secret_key_rejects_path_traversal() {
        assert!(validate_secret_key("..").is_err());
        assert!(validate_secret_key("foo/../bar").is_err());
    }

    #[test]
    fn secret_key_rejects_separators() {
        assert!(validate_secret_key("foo/bar").is_err());
        assert!(validate_secret_key("foo\\bar").is_err());
    }

    #[test]
    fn secret_key_rejects_null_bytes() {
        assert!(validate_secret_key("foo\0bar").is_err());
        assert!(validate_secret_key("\0").is_err());
    }

    // -- ConflictPolicy --

    #[test]
    fn conflict_policy_default_is_strict() {
        assert_eq!(ConflictPolicy::default(), ConflictPolicy::Strict);
    }

    #[test]
    fn conflict_policy_roundtrip_json() {
        for policy in [
            ConflictPolicy::Strict,
            ConflictPolicy::Warn,
            ConflictPolicy::Last,
        ] {
            let json = serde_json::to_string(&policy).unwrap();
            let decoded: ConflictPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, policy);
        }
    }

    // -- LaunchProfile --

    #[test]
    fn launch_profile_single() {
        let name = TrustProfileName::try_from("work").unwrap();
        let lp = LaunchProfile::single(name.clone());
        assert_eq!(lp.trust_profiles.len(), 1);
        assert_eq!(lp.trust_profiles[0], name);
        assert_eq!(lp.conflict_policy, ConflictPolicy::Strict);
    }

    // -- SensitiveBytes --

    #[test]
    fn sensitive_bytes_debug_redacts() {
        let sb = SensitiveBytes::new(b"super_secret".to_vec());
        let debug = format!("{sb:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("super_secret"));
        assert!(debug.contains("12 bytes"));
    }

    #[test]
    fn sensitive_bytes_accessors() {
        let sb = SensitiveBytes::new(vec![1, 2, 3]);
        assert_eq!(sb.as_bytes(), &[1, 2, 3]);
        assert_eq!(sb.len(), 3);
        assert!(!sb.is_empty());

        let empty = SensitiveBytes::new(vec![]);
        assert!(empty.is_empty());
    }

    #[test]
    fn sensitive_bytes_from_vec() {
        let sb: SensitiveBytes = vec![0xAA, 0xBB].into();
        assert_eq!(sb.as_bytes(), &[0xAA, 0xBB]);
    }

    #[test]
    fn sensitive_bytes_clone() {
        let sb1 = SensitiveBytes::new(vec![1, 2, 3]);
        let sb2 = sb1.clone();
        assert_eq!(sb1.as_bytes(), sb2.as_bytes());
        assert_eq!(sb1, sb2);
        drop(sb1);
        assert_eq!(sb2.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn sensitive_bytes_empty_clone() {
        let sb1 = SensitiveBytes::new(vec![]);
        let sb2 = sb1.clone();
        assert!(sb2.is_empty());
        assert_eq!(sb1, sb2);
    }

    #[test]
    fn sensitive_bytes_postcard_round_trip() {
        let original = SensitiveBytes::new(b"test secret value".to_vec());
        let encoded = postcard::to_stdvec(&original).unwrap();
        let decoded: SensitiveBytes = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), b"test secret value");
        assert_eq!(decoded.len(), 17);
    }

    #[test]
    fn sensitive_bytes_postcard_round_trip_empty() {
        let original = SensitiveBytes::new(vec![]);
        let encoded = postcard::to_stdvec(&original).unwrap();
        let decoded: SensitiveBytes = postcard::from_bytes(&encoded).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(decoded.as_bytes(), b"");
    }

    #[test]
    fn sensitive_bytes_postcard_round_trip_binary() {
        // All byte values 0x00..0xFF to verify no encoding issues.
        let data: Vec<u8> = (0..=255).collect();
        let original = SensitiveBytes::new(data.clone());
        let encoded = postcard::to_stdvec(&original).unwrap();
        let decoded: SensitiveBytes = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), &data);
    }

    #[test]
    fn sensitive_bytes_postcard_wire_compat_with_vec() {
        // Verify that the custom Serialize produces the same encoding
        // as a plain Vec<u8> would. This ensures wire compatibility
        // with the old #[serde(transparent)] implementation.
        let data = b"wire compat test".to_vec();
        let sb = SensitiveBytes::new(data.clone());
        let sb_encoded = postcard::to_stdvec(&sb).unwrap();
        let vec_encoded = postcard::to_stdvec(&data).unwrap();
        assert_eq!(
            sb_encoded, vec_encoded,
            "SensitiveBytes and Vec<u8> must produce identical postcard encoding"
        );
    }

    #[test]
    fn sensitive_bytes_from_slice() {
        let sb = SensitiveBytes::from_slice(b"from-slice-test");
        assert_eq!(sb.as_bytes(), b"from-slice-test");
        assert_eq!(sb.len(), 15);
    }

    #[test]
    fn sensitive_bytes_from_slice_empty() {
        let sb = SensitiveBytes::from_slice(b"");
        assert!(sb.is_empty());
        assert_eq!(sb.as_bytes(), b"");
    }

    #[test]
    fn sensitive_bytes_from_protected_round_trip() {
        // Simulate the SecureBytes → SensitiveBytes zero-copy path.
        let alloc =
            core_memory::ProtectedAlloc::from_slice(b"transfer-test").expect("alloc failed");
        let sb = SensitiveBytes::from_protected(alloc, 13);
        assert_eq!(sb.as_bytes(), b"transfer-test");
        assert_eq!(sb.len(), 13);
    }

    #[test]
    fn sensitive_bytes_from_protected_postcard_round_trip() {
        // Verify that from_protected produces a SensitiveBytes that serializes
        // correctly over postcard (the IPC wire format).
        let alloc = core_memory::ProtectedAlloc::from_slice(b"wire-test").expect("alloc failed");
        let sb = SensitiveBytes::from_protected(alloc, 9);
        let encoded = postcard::to_stdvec(&sb).unwrap();
        let decoded: SensitiveBytes = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), b"wire-test");
    }

    // -- EventKind Debug redaction --

    #[test]
    fn event_kind_debug_redacts_secrets() {
        let unlock = EventKind::UnlockRequest {
            password: SensitiveBytes::new(b"hunter2".to_vec()),
            profile: None,
        };
        let debug = format!("{unlock:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("hunter2"));

        let get_resp = EventKind::SecretGetResponse {
            key: "api-key".into(),
            value: SensitiveBytes::new(b"secret123".to_vec()),
            denial: None,
        };
        let debug = format!("{get_resp:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("secret123"));
        assert!(debug.contains("api-key")); // key name is NOT redacted

        let set = EventKind::SecretSet {
            profile: TrustProfileName::try_from("work").unwrap(),
            key: "db-pass".into(),
            value: SensitiveBytes::new(b"p@ssw0rd".to_vec()),
        };
        let debug = format!("{set:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("p@ssw0rd"));
        assert!(debug.contains("db-pass"));
        assert!(debug.contains("work"));
    }

    // -- EventKind forward compatibility --

    #[test]
    fn event_kind_unknown_variant_deserializes() {
        // Externally-tagged: unknown variant name maps to Unknown via #[serde(other)]
        let json = r#""FutureEventV99""#;
        let event: EventKind = serde_json::from_str(json).unwrap();
        assert!(matches!(event, EventKind::Unknown));
    }

    #[test]
    fn event_kind_known_variant_roundtrips() {
        let event = EventKind::DaemonStarted {
            daemon_id: DaemonId::from_uuid(Uuid::from_u128(42)),
            version: "0.1.0".into(),
            capabilities: vec!["wm".into(), "tiling".into()],
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: EventKind = serde_json::from_str(&json).unwrap();
        // Verify it round-trips to the same variant (not Unknown)
        assert!(matches!(decoded, EventKind::DaemonStarted { .. }));
    }

    // -- AgentId --

    #[test]
    fn agent_id_display_prefix() {
        let id = AgentId::from_uuid(Uuid::from_u128(1));
        let s = format!("{id}");
        assert!(
            s.starts_with("agent-"),
            "AgentId display should have 'agent-' prefix, got: {s}"
        );
    }

    proptest! {
        #[test]
        fn agent_id_roundtrip_postcard(n in any::<u128>()) {
            let id = AgentId::from_uuid(Uuid::from_u128(n));
            let bytes = postcard::to_allocvec(&id).unwrap();
            let decoded: AgentId = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(id, decoded);
        }

        #[test]
        fn agent_id_roundtrip_json(n in any::<u128>()) {
            let id = AgentId::from_uuid(Uuid::from_u128(n));
            let json = serde_json::to_string(&id).unwrap();
            let decoded: AgentId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(id, decoded);
        }
    }

    // -- CryptoConfig enums --

    #[test]
    fn crypto_config_default_is_leading_edge() {
        let cfg = CryptoConfig::default();
        assert_eq!(cfg.kdf, KdfAlgorithm::Argon2id);
        assert_eq!(cfg.hkdf, HkdfAlgorithm::Blake3);
        assert_eq!(cfg.noise_cipher, NoiseCipher::ChaChaPoly);
        assert_eq!(cfg.noise_hash, NoiseHash::Blake2s);
        assert_eq!(cfg.audit_hash, AuditHash::Blake3);
        assert_eq!(cfg.minimum_peer_profile, CryptoProfile::LeadingEdge);
    }

    #[test]
    fn kdf_algorithm_roundtrip_json() {
        for alg in [KdfAlgorithm::Argon2id, KdfAlgorithm::Pbkdf2Sha256] {
            let json = serde_json::to_string(&alg).unwrap();
            let decoded: KdfAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(alg, decoded);
        }
    }

    #[test]
    fn hkdf_algorithm_roundtrip_json() {
        for alg in [HkdfAlgorithm::Blake3, HkdfAlgorithm::HkdfSha256] {
            let json = serde_json::to_string(&alg).unwrap();
            let decoded: HkdfAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(alg, decoded);
        }
    }

    #[test]
    fn noise_cipher_roundtrip_json() {
        for c in [NoiseCipher::ChaChaPoly, NoiseCipher::AesGcm] {
            let json = serde_json::to_string(&c).unwrap();
            let decoded: NoiseCipher = serde_json::from_str(&json).unwrap();
            assert_eq!(c, decoded);
        }
    }

    #[test]
    fn noise_hash_roundtrip_json() {
        for h in [NoiseHash::Blake2s, NoiseHash::Sha256] {
            let json = serde_json::to_string(&h).unwrap();
            let decoded: NoiseHash = serde_json::from_str(&json).unwrap();
            assert_eq!(h, decoded);
        }
    }

    #[test]
    fn audit_hash_roundtrip_json() {
        for h in [AuditHash::Blake3, AuditHash::Sha256] {
            let json = serde_json::to_string(&h).unwrap();
            let decoded: AuditHash = serde_json::from_str(&json).unwrap();
            assert_eq!(h, decoded);
        }
    }

    #[test]
    fn crypto_profile_roundtrip_json() {
        for p in [
            CryptoProfile::LeadingEdge,
            CryptoProfile::GovernanceCompatible,
            CryptoProfile::Custom,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let decoded: CryptoProfile = serde_json::from_str(&json).unwrap();
            assert_eq!(p, decoded);
        }
    }

    #[test]
    fn crypto_config_roundtrip_postcard() {
        let cfg = CryptoConfig::default();
        let bytes = postcard::to_allocvec(&cfg).unwrap();
        let decoded: CryptoConfig = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn kdf_algorithm_kebab_case_serialization() {
        let json = serde_json::to_string(&KdfAlgorithm::Pbkdf2Sha256).unwrap();
        assert_eq!(json, "\"pbkdf2-sha256\"");
        let json = serde_json::to_string(&KdfAlgorithm::Argon2id).unwrap();
        assert_eq!(json, "\"argon2id\"");
    }

    // -- InstallationId --

    #[test]
    fn installation_id_roundtrip_json() {
        let install = InstallationId {
            id: Uuid::from_u128(42),
            org_ns: Some(OrganizationNamespace {
                domain: "braincraft.io".into(),
                namespace: Uuid::from_u128(99),
            }),
            namespace: Uuid::from_u128(123),
            machine_binding: Some(MachineBinding {
                binding_hash: [0xAB; 32],
                binding_type: MachineBindingType::MachineId,
            }),
        };
        let json = serde_json::to_string(&install).unwrap();
        let decoded: InstallationId = serde_json::from_str(&json).unwrap();
        assert_eq!(install, decoded);
    }

    #[test]
    fn installation_id_roundtrip_postcard() {
        let install = InstallationId {
            id: Uuid::from_u128(1),
            org_ns: None,
            namespace: Uuid::from_u128(2),
            machine_binding: None,
        };
        let bytes = postcard::to_allocvec(&install).unwrap();
        let decoded: InstallationId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(install, decoded);
    }

    #[test]
    fn installation_namespace_determinism() {
        // Same org domain produces same namespace UUID via uuid5.
        let ns1 = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"braincraft.io");
        let ns2 = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"braincraft.io");
        assert_eq!(ns1, ns2);

        // Different domains produce different namespaces.
        let ns3 = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"example.com");
        assert_ne!(ns1, ns3);
    }

    // -- OciReference --

    #[test]
    fn oci_reference_parse_full() {
        let r = OciReference::parse("registry.example.com/principal/scope:1.0.0@sha256:abc123")
            .unwrap();
        assert_eq!(r.registry, "registry.example.com");
        assert_eq!(r.principal, "principal");
        assert_eq!(r.scope, "scope");
        assert_eq!(r.revision, "1.0.0");
        assert_eq!(r.provenance.as_deref(), Some("sha256:abc123"));
    }

    #[test]
    fn oci_reference_parse_without_provenance() {
        let r = OciReference::parse("registry.example.com/org/ext:2.0").unwrap();
        assert_eq!(r.registry, "registry.example.com");
        assert_eq!(r.principal, "org");
        assert_eq!(r.scope, "ext");
        assert_eq!(r.revision, "2.0");
        assert!(r.provenance.is_none());
    }

    #[test]
    fn oci_reference_display_roundtrip() {
        let r = OciReference::parse("reg.io/org/ext:1.0@sha256:def").unwrap();
        let s = r.to_string();
        let r2 = OciReference::parse(&s).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn oci_reference_display_roundtrip_no_provenance() {
        let r = OciReference::parse("reg.io/org/ext:1.0").unwrap();
        let s = r.to_string();
        let r2 = OciReference::parse(&s).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn oci_reference_rejects_empty() {
        assert!(OciReference::parse("").is_err());
    }

    #[test]
    fn oci_reference_rejects_missing_revision() {
        assert!(OciReference::parse("reg.io/org/ext").is_err());
    }

    #[test]
    fn oci_reference_rejects_too_few_segments() {
        assert!(OciReference::parse("reg.io/ext:1.0").is_err());
    }

    #[test]
    fn oci_reference_roundtrip_json() {
        let r = OciReference::parse("reg.io/org/ext:1.0@sha256:abc").unwrap();
        let json = serde_json::to_string(&r).unwrap();
        let decoded: OciReference = serde_json::from_str(&json).unwrap();
        assert_eq!(r, decoded);
    }

    // -- CapabilitySet lattice --

    #[test]
    fn capability_set_empty_is_subset_of_all() {
        assert!(CapabilitySet::empty().is_subset(&CapabilitySet::all()));
    }

    #[test]
    fn capability_set_all_is_superset_of_empty() {
        assert!(CapabilitySet::all().is_superset(&CapabilitySet::empty()));
    }

    #[test]
    fn capability_set_union_identity() {
        let a = CapabilitySet::all();
        let empty = CapabilitySet::empty();
        assert_eq!(a.union(&empty), a);
        assert_eq!(empty.union(&a), a);
    }

    #[test]
    fn capability_set_intersection_identity() {
        let a = CapabilitySet::all();
        let empty = CapabilitySet::empty();
        assert_eq!(a.intersection(&empty), empty);
        assert_eq!(empty.intersection(&a), empty);
    }

    #[test]
    fn capability_set_intersection_self_is_self() {
        let a = CapabilitySet::all();
        assert_eq!(a.intersection(&a), a);
    }

    #[test]
    fn capability_set_roundtrip_json() {
        let cs = CapabilitySet::all();
        let json = serde_json::to_string(&cs).unwrap();
        let decoded: CapabilitySet = serde_json::from_str(&json).unwrap();
        assert_eq!(cs, decoded);
    }

    #[test]
    fn capability_delegate_roundtrip_json() {
        let cap = Capability::Delegate {
            max_depth: 3,
            scope: Box::new(CapabilitySet::empty()),
        };
        let json = serde_json::to_string(&cap).unwrap();
        let decoded: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, decoded);
    }

    // -- DelegationGrant --

    #[test]
    fn delegation_grant_roundtrip_json() {
        use std::time::Duration;
        let grant = DelegationGrant {
            delegator: AgentId::from_uuid(Uuid::from_u128(1)),
            scope: CapabilitySet::empty(),
            initial_ttl: Duration::from_secs(3600),
            heartbeat_interval: Duration::from_secs(60),
            nonce: [0xAA; 16],
            point_of_use_filter: None,
            signature: vec![0xBB; 64],
        };
        let json = serde_json::to_string(&grant).unwrap();
        let decoded: DelegationGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(grant, decoded);
    }

    // -- Attestation --

    #[test]
    fn attestation_ucred_roundtrip_json() {
        let att = Attestation::UCred {
            pid: 1234,
            uid: 1000,
            gid: 1000,
        };
        let json = serde_json::to_string(&att).unwrap();
        let decoded: Attestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, decoded);
    }

    #[test]
    fn attestation_delegation_roundtrip_json() {
        let att = Attestation::Delegation {
            delegator: AgentId::from_uuid(Uuid::from_u128(5)),
            scope: CapabilitySet::empty(),
            chain_depth: 2,
        };
        let json = serde_json::to_string(&att).unwrap();
        let decoded: Attestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, decoded);
    }

    #[test]
    fn attestation_type_roundtrip_json() {
        for at in [
            AttestationType::UCred,
            AttestationType::NoiseIK,
            AttestationType::MasterPassword,
            AttestationType::Delegation,
            AttestationType::DeviceAttestation,
        ] {
            let json = serde_json::to_string(&at).unwrap();
            let decoded: AttestationType = serde_json::from_str(&json).unwrap();
            assert_eq!(at, decoded);
        }
    }

    // -- AgentType / AgentIdentity --

    #[test]
    fn agent_type_roundtrip_json() {
        let at = AgentType::AI {
            model_family: "claude".into(),
        };
        let json = serde_json::to_string(&at).unwrap();
        let decoded: AgentType = serde_json::from_str(&json).unwrap();
        assert_eq!(at, decoded);
    }

    #[test]
    fn agent_identity_roundtrip_json() {
        let identity = AgentIdentity {
            id: AgentId::from_uuid(Uuid::from_u128(10)),
            agent_type: AgentType::Human,
            local_id: LocalAgentId::UnixUid(1000),
            installation: InstallationId {
                id: Uuid::from_u128(1),
                org_ns: None,
                namespace: Uuid::from_u128(2),
                machine_binding: None,
            },
            attestations: vec![Attestation::UCred {
                pid: 100,
                uid: 1000,
                gid: 1000,
            }],
            session_scope: CapabilitySet::all(),
            delegation_chain: vec![],
        };
        let json = serde_json::to_string(&identity).unwrap();
        let decoded: AgentIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(identity, decoded);
    }

    // -- TrustLevel ordering --

    #[test]
    fn trust_level_ordering() {
        assert!(TrustLevel::None < TrustLevel::Low);
        assert!(TrustLevel::Low < TrustLevel::Medium);
        assert!(TrustLevel::Medium < TrustLevel::High);
        assert!(TrustLevel::High < TrustLevel::Hardware);
    }

    // -- NetworkTrust ordering --

    #[test]
    fn network_trust_ordering() {
        assert!(NetworkTrust::Local < NetworkTrust::Encrypted);
        assert!(NetworkTrust::Encrypted < NetworkTrust::Onion);
        assert!(NetworkTrust::Onion < NetworkTrust::PublicInternet);
    }

    // -- TrustVector --

    #[test]
    fn trust_vector_roundtrip_json() {
        use std::time::Duration;
        let tv = TrustVector {
            authn_strength: TrustLevel::High,
            authz_freshness: Duration::from_secs(30),
            delegation_depth: 0,
            device_posture: 0.95,
            network_exposure: NetworkTrust::Local,
            agent_type: AgentType::Human,
        };
        let json = serde_json::to_string(&tv).unwrap();
        let decoded: TrustVector = serde_json::from_str(&json).unwrap();
        assert_eq!(tv, decoded);
    }

    // -- ProfileRef --

    #[test]
    fn profile_ref_roundtrip_json() {
        let pr = ProfileRef {
            name: TrustProfileName::try_from("work").unwrap(),
            id: ProfileId::from_uuid(Uuid::from_u128(77)),
            installation: InstallationId {
                id: Uuid::from_u128(1),
                org_ns: None,
                namespace: Uuid::from_u128(2),
                machine_binding: None,
            },
        };
        let json = serde_json::to_string(&pr).unwrap();
        let decoded: ProfileRef = serde_json::from_str(&json).unwrap();
        assert_eq!(pr, decoded);
    }

    // -- CapabilitySet lattice property tests --

    #[test]
    fn capability_set_lattice_properties() {
        let caps_a = CapabilitySet {
            capabilities: [
                Capability::SecretRead { key_pattern: None },
                Capability::SecretWrite { key_pattern: None },
                Capability::ProfileActivate,
            ]
            .into_iter()
            .collect(),
        };
        let caps_b = CapabilitySet {
            capabilities: [
                Capability::SecretWrite { key_pattern: None },
                Capability::Admin,
                Capability::StatusRead,
            ]
            .into_iter()
            .collect(),
        };
        let caps_c = CapabilitySet {
            capabilities: [
                Capability::SecretRead { key_pattern: None },
                Capability::Admin,
                Capability::Lock,
            ]
            .into_iter()
            .collect(),
        };

        // Commutativity of intersection
        assert_eq!(caps_a.intersection(&caps_b), caps_b.intersection(&caps_a));

        // Commutativity of union
        assert_eq!(caps_a.union(&caps_b), caps_b.union(&caps_a));

        // Associativity of intersection
        assert_eq!(
            caps_a.intersection(&caps_b).intersection(&caps_c),
            caps_a.intersection(&caps_b.intersection(&caps_c))
        );

        // Associativity of union
        assert_eq!(
            caps_a.union(&caps_b).union(&caps_c),
            caps_a.union(&caps_b.union(&caps_c))
        );

        // Union is superset of both operands
        let ab = caps_a.union(&caps_b);
        assert!(ab.is_superset(&caps_a));
        assert!(ab.is_superset(&caps_b));

        // Intersection is subset of both operands
        let ab_inter = caps_a.intersection(&caps_b);
        assert!(caps_a.is_superset(&ab_inter));
        assert!(caps_b.is_superset(&ab_inter));

        // Empty is subset of everything
        let empty = CapabilitySet::empty();
        assert!(caps_a.is_superset(&empty));
        assert!(caps_b.is_superset(&empty));
        assert!(caps_c.is_superset(&empty));

        // All is superset of everything
        let all = CapabilitySet::all();
        assert!(all.is_superset(&caps_a));
        assert!(all.is_superset(&caps_b));
        assert!(all.is_superset(&caps_c));

        // Idempotence: union with self is self
        assert_eq!(caps_a.union(&caps_a), caps_a);

        // Idempotence: intersection with self is self
        assert_eq!(caps_a.intersection(&caps_a), caps_a);

        // Absorption: a union (a intersect b) == a
        assert_eq!(caps_a.union(&caps_a.intersection(&caps_b)), caps_a);
    }

    // -- Namespace derivation determinism --

    #[test]
    fn namespace_derivation_determinism() {
        let ns1 = PROFILE_NAMESPACE;
        let ns2 = uuid::Uuid::from_bytes([0xaa; 16]);

        // Same namespace + same name = same ID across 100 iterations
        let expected = uuid::Uuid::new_v5(&ns1, b"profile:work");
        for _ in 0..100 {
            assert_eq!(uuid::Uuid::new_v5(&ns1, b"profile:work"), expected);
        }

        // Different namespace + same name = different ID
        assert_ne!(
            uuid::Uuid::new_v5(&ns1, b"profile:work"),
            uuid::Uuid::new_v5(&ns2, b"profile:work"),
        );

        // Same namespace + different name = different ID
        assert_ne!(
            uuid::Uuid::new_v5(&ns1, b"profile:work"),
            uuid::Uuid::new_v5(&ns1, b"profile:personal"),
        );
    }

    // -- OciReference fuzz / adversarial input tests --

    #[test]
    fn oci_reference_never_panics_on_adversarial_input() {
        let long_input = "a".repeat(65536);
        let inputs: Vec<&str> = vec![
            "",
            " ",
            "/",
            "//",
            ":",
            "@",
            "a@",
            "@a",
            "a:b@c",
            "registry/principal/scope:rev@prov",
            "\0",
            "\0\0\0",
            &long_input,
            "emoji/\u{1f525}/scope:rev",
            "registry/principal/scope:",
            "registry//scope:rev",
            "///:",
            ":@",
            "a/b/c:d@",
            "a/b/c:d@e@f",
        ];
        for input in &inputs {
            let _ = input.parse::<OciReference>(); // must not panic
        }
    }

    // -- Per-vault unlock IPC protocol tests --

    #[test]
    fn test_unlock_request_roundtrip_with_profile() {
        let event = EventKind::UnlockRequest {
            password: SensitiveBytes::new(b"secret".to_vec()),
            profile: Some(TrustProfileName::try_from("work").unwrap()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: EventKind = serde_json::from_str(&json).unwrap();
        match decoded {
            EventKind::UnlockRequest { profile, .. } => {
                assert_eq!(
                    profile.unwrap(),
                    TrustProfileName::try_from("work").unwrap()
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn test_unlock_request_profile_none_deserializes() {
        // Simulate old format without profile field
        let json = r#"{"UnlockRequest":{"password":[1,2,3]}}"#;
        let decoded: EventKind = serde_json::from_str(json).unwrap();
        match decoded {
            EventKind::UnlockRequest { profile, .. } => {
                assert!(
                    profile.is_none(),
                    "missing profile field should default to None"
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn test_lock_request_profile_none_deserializes() {
        let json = r#"{"LockRequest":{}}"#;
        let decoded: EventKind = serde_json::from_str(json).unwrap();
        match decoded {
            EventKind::LockRequest { profile } => {
                assert!(
                    profile.is_none(),
                    "missing profile field should default to None"
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn test_status_response_lock_state_roundtrips() {
        let mut lock_state = std::collections::BTreeMap::new();
        lock_state.insert(TrustProfileName::try_from("work").unwrap(), false);
        lock_state.insert(TrustProfileName::try_from("personal").unwrap(), true);

        let event = EventKind::StatusResponse {
            active_profiles: vec![TrustProfileName::try_from("work").unwrap()],
            default_profile: TrustProfileName::try_from("work").unwrap(),
            daemon_uptimes_ms: vec![],
            locked: false,
            lock_state: lock_state.clone(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: EventKind = serde_json::from_str(&json).unwrap();
        match decoded {
            EventKind::StatusResponse { lock_state: ls, .. } => {
                assert_eq!(ls, lock_state);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn test_status_response_missing_lock_state_defaults_empty() {
        // Old format without lock_state
        let json = r#"{"StatusResponse":{"active_profiles":["work"],"default_profile":"work","daemon_uptimes_ms":[],"locked":false}}"#;
        let decoded: EventKind = serde_json::from_str(json).unwrap();
        match decoded {
            EventKind::StatusResponse { lock_state, .. } => {
                assert!(
                    lock_state.is_empty(),
                    "missing lock_state should default to empty BTreeMap"
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn test_unlock_request_debug_redacts_password_shows_profile() {
        let event = EventKind::UnlockRequest {
            password: SensitiveBytes::new(b"super-secret".to_vec()),
            profile: Some(TrustProfileName::try_from("myprofile").unwrap()),
        };
        let debug = format!("{event:?}");
        assert!(debug.contains("REDACTED"), "password should be redacted");
        assert!(
            !debug.contains("super-secret"),
            "password plaintext must not appear"
        );
        assert!(
            debug.contains("myprofile"),
            "profile name should be visible"
        );
    }
}
