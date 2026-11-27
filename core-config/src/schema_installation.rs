//! Installation identity configuration types.
//!
//! Stored at `Layout::installation_file`, generated once at `sesame init`.

use core_types::{InstallationId, MachineBinding, MachineBindingType, OrganizationNamespace};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// BLAKE3 key-derivation context of the machine binding: the application
/// key machine-id(5) requires for an identifier derived from the machine ID.
const MACHINE_BINDING_CONTEXT: &str = "pds v2 machine-binding";

/// Installation identity stored in `installation.toml`.
///
/// Generated once at `sesame init` and never modified unless the user
/// explicitly re-initializes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationConfig {
    /// Unique installation identifier (UUID v4).
    pub id: Uuid,
    /// Derived namespace for deterministic ID generation
    /// (`InstallationId::derive_namespace`).
    pub namespace: Uuid,
    /// Optional organizational namespace for enterprise deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<OrganizationNamespace>,
    /// Optional machine binding for hardware attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_binding: Option<MachineBindingConfig>,
}

/// Machine binding configuration (the hash serialized as hex in TOML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineBindingConfig {
    /// Hex-encoded hash of machine identity material.
    pub binding_hash: String,
    /// Binding method.
    pub binding_type: MachineBindingType,
}

impl InstallationConfig {
    /// A new installation identity for `id`: the organization namespace of
    /// `org_domain`, the installation namespace derived from both, and a
    /// machine binding when `machine_id` (the contents of the machine
    /// identity file) is present.
    #[must_use]
    pub fn new(id: Uuid, org_domain: Option<&str>, machine_id: Option<&str>) -> Self {
        let org = org_domain.map(OrganizationNamespace::for_domain);
        Self {
            id,
            namespace: InstallationId::derive_namespace(&id, org.as_ref()),
            org,
            machine_binding: machine_id.map(|machine_id| MachineBindingConfig {
                binding_hash: machine_binding_hash(machine_id, &id).to_hex().to_string(),
                binding_type: MachineBindingType::MachineId,
            }),
        }
    }

    /// The installation identity carried on bus messages and audit entries.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Config` when the stored binding hash is not a
    /// 32-byte hex value.
    pub fn identity(&self) -> core_types::Result<InstallationId> {
        let machine_binding = self
            .machine_binding
            .as_ref()
            .map(|binding| {
                blake3::Hash::from_hex(&binding.binding_hash)
                    .map(|hash| MachineBinding {
                        binding_hash: *hash.as_bytes(),
                        binding_type: binding.binding_type,
                    })
                    .map_err(|e| {
                        core_types::Error::Config(format!(
                            "installation machine binding hash is not 32-byte hex: {e}"
                        ))
                    })
            })
            .transpose()?;
        Ok(InstallationId {
            id: self.id,
            org_ns: self.org.clone(),
            namespace: self.namespace,
            machine_binding,
        })
    }
}

/// The binding of installation `id` to the machine whose identity file
/// holds `machine_id`: BLAKE3 `derive_key` under [`MACHINE_BINDING_CONTEXT`]
/// over the trimmed machine ID and the installation ID, so the machine ID
/// cannot be recovered from it.
fn machine_binding_hash(machine_id: &str, id: &Uuid) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_derive_key(MACHINE_BINDING_CONTEXT);
    hasher.update(machine_id.trim().as_bytes());
    hasher.update(id.as_bytes());
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_identity_derives_its_namespaces() {
        let id = Uuid::from_u128(42);
        let config = InstallationConfig::new(id, Some("example.invalid"), None);
        let org = OrganizationNamespace::for_domain("example.invalid");
        assert_eq!(
            config.namespace,
            InstallationId::derive_namespace(&id, Some(&org))
        );
        assert_eq!(config.org, Some(org));
        assert!(config.machine_binding.is_none());
    }

    #[test]
    fn identity_carries_every_persisted_field() {
        let id = Uuid::from_u128(7);
        let config = InstallationConfig::new(id, Some("example.invalid"), Some("0123abcd\n"));
        let identity = config.identity().unwrap();
        assert_eq!(identity.id, id);
        assert_eq!(identity.namespace, config.namespace);
        assert_eq!(identity.org_ns, config.org);
        let binding = identity.machine_binding.unwrap();
        assert_eq!(
            binding.binding_hash,
            *machine_binding_hash("0123abcd", &id).as_bytes()
        );
        assert_eq!(binding.binding_type, MachineBindingType::MachineId);
    }

    #[test]
    fn binding_is_keyed_and_installation_scoped() {
        let a = machine_binding_hash("0123abcd", &Uuid::from_u128(1));
        let b = machine_binding_hash("0123abcd", &Uuid::from_u128(2));
        assert_ne!(a, b);
        let mut unkeyed = blake3::Hasher::new();
        unkeyed.update(b"0123abcd");
        unkeyed.update(Uuid::from_u128(1).as_bytes());
        assert_ne!(a, unkeyed.finalize());
    }

    #[test]
    fn malformed_binding_hash_is_an_error() {
        let mut config = InstallationConfig::new(Uuid::from_u128(1), None, Some("0123abcd"));
        if let Some(binding) = config.machine_binding.as_mut() {
            binding.binding_hash = "zz".into();
        }
        assert!(config.identity().is_err());
    }

    #[test]
    fn persisted_format_reads_back() {
        let toml_str = "id = \"00000000-0000-0000-0000-000000000001\"\n\
                        namespace = \"00000000-0000-0000-0000-000000000002\"\n\
                        [org]\ndomain = \"example.invalid\"\n\
                        namespace = \"00000000-0000-0000-0000-000000000003\"\n\
                        [machine_binding]\n\
                        binding_hash = \"0000000000000000000000000000000000000000000000000000000000000000\"\n\
                        binding_type = \"machine-id\"\n";
        let config: InstallationConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.org.as_ref().unwrap().domain, "example.invalid");
        assert_eq!(
            config.machine_binding.as_ref().unwrap().binding_type,
            MachineBindingType::MachineId
        );
        let unknown = toml_str.replace("machine-id\"", "fingerprint\"");
        assert!(toml::from_str::<InstallationConfig>(&unknown).is_err());
    }
}
