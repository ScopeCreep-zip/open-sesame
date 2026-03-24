# Kubernetes

> **Design Intent.** This page describes how Open Sesame can operate as a secret provider in
> Kubernetes environments. The type system primitives referenced below (`InstallationId`,
> `AgentIdentity`, `DelegationGrant`, `Attestation`) exist today. The Kubernetes-specific
> integration components (sidecar container image, CSI driver, admission webhook) are not yet
> implemented.

## Architecture

Open Sesame in Kubernetes operates as a per-pod or per-node secret provider. The headless
daemon set (`daemon-profile`, `daemon-secrets`) runs inside a sidecar container or as a
DaemonSet, providing secrets to application containers via environment injection or shared
volumes.

No desktop daemons are deployed. The `open-sesame` package alone is sufficient.

## Sidecar Pattern

The sidecar pattern deploys an Open Sesame container alongside each application pod:

```text
Pod
  +-- app-container
  |     Reads secrets from shared volume or environment
  +-- open-sesame-sidecar
        daemon-profile, daemon-secrets
        Mounts: /run/pds (shared tmpfs)
        Mounts: /etc/pds/installation.toml (ConfigMap or Secret)
        Mounts: /etc/pds/policy.toml (ConfigMap)
```

### Secret Projection

The sidecar decrypts vault secrets and writes them to a shared `tmpfs` volume that the
application container mounts:

```bash
# Init container or sidecar entrypoint
sesame init --non-interactive --installation /etc/pds/installation.toml
sesame unlock -p $PROFILE --factor ssh-agent --non-interactive
sesame env -p $PROFILE --export-to /run/pds/secrets.env
```

Alternatively, the sidecar can project secrets as individual files:

```text
/run/pds/secrets/
  +-- database-url
  +-- api-key
  +-- tls-cert
```

The `tmpfs` mount ensures secrets are never written to persistent storage on the node.

### Kubernetes Secret Objects (Design Intent)

A controller component could synchronize vault contents into native Kubernetes `Secret`
objects, enabling standard `envFrom` and volume mount patterns:

```text
Open Sesame Vault (SQLCipher)
  --> Controller watches vault changes
    --> Creates/updates Kubernetes Secret objects
      --> Pods consume via standard envFrom/volumeMount
```

This approach trades the stronger isolation of the sidecar pattern for compatibility with
existing Kubernetes-native workflows.

## Pod Identity

### Installation ID per Pod

Each pod receives a unique `InstallationId` via a pre-seeded `installation.toml`. The
`InstallationConfig` (`core-config/src/schema_installation.rs`) for a pod includes:

| Field | Value | Purpose |
|-------|-------|---------|
| `id` | UUID v4, unique per pod instance | Audit trail attribution |
| `org.domain` | Organization domain | Fleet grouping |
| `machine_binding.binding_type` | `machine-id` | Pod identity binding |
| `machine_binding.binding_hash` | BLAKE3 hash of pod UID + node ID | Anti-migration attestation |

The machine binding hash can incorporate the Kubernetes pod UID and node identity, binding
the installation to a specific pod lifecycle. If the pod is rescheduled to a different node,
the binding hash does not match, requiring re-attestation.

### Workload Attestation (Design Intent)

The `Attestation` enum (`core-types/src/security.rs`) includes `ProcessAttestation` with an
`exe_hash` field. In Kubernetes, workload attestation extends this concept:

- **Container image digest** serves as the `exe_hash`, verified against a signed manifest.
- **Service account token** provides Kubernetes-native identity.
- **Node attestation** via TPM or machine binding provides hardware-rooted trust.

These attestation signals compose into a `TrustVector` (`core-types/src/security.rs`):

```text
TrustVector {
    authn_strength: High,          // Service account + image signature
    authz_freshness: <since last token rotation>,
    delegation_depth: 1,           // Delegated from cluster operator
    device_posture: 0.8,           // Node with TPM but no memfd_secret
    network_exposure: Encrypted,   // Noise IK over loopback or pod network
    agent_type: Service { unit: "my-app-pod" },
}
```

## DaemonSet Pattern (Design Intent)

For clusters where per-pod sidecars are too resource-intensive, a DaemonSet deploys one
Open Sesame instance per node:

```text
Node
  +-- open-sesame DaemonSet pod
  |     daemon-profile, daemon-secrets
  |     Exposes: /run/pds/bus.sock (hostPath)
  |
  +-- app-pod-1  (mounts /run/pds/bus.sock)
  +-- app-pod-2  (mounts /run/pds/bus.sock)
```

Application pods connect to the node-level IPC bus. Each connecting pod authenticates via
`Attestation::UCred` (UID/PID from the Unix domain socket) and receives capabilities scoped
to its service account identity.

The `SecurityLevel` hierarchy (`core-types/src/security.rs`) ensures that application pods
at `Open` or `Internal` clearance cannot read `SecretsOnly` messages on the shared bus.

## Service Mesh Integration (Design Intent)

Open Sesame's Noise IK transport (`core-ipc`) provides mutual authentication with forward
secrecy. In service mesh contexts, Noise IK can serve as an alternative to mTLS for
service-to-service communication:

| Property | mTLS (Istio/Linkerd) | Noise IK |
|----------|---------------------|----------|
| Key exchange | X.509 certificates, CA hierarchy | X25519 static keys, clearance registry |
| Forward secrecy | Per-connection via TLS 1.3 | Per-connection via Noise IK |
| Identity binding | SPIFFE ID in SAN | `AgentId` + `InstallationId` |
| Revocation | CRL/OCSP, short-lived certs | Clearance registry generation counter |
| Trust model | Centralized CA | Peer-to-peer, registry-based |

The clearance registry (`core-ipc/src/registry.rs`) maps X25519 public keys to daemon
identities and security levels. In a Kubernetes context, the registry could be populated
from a shared ConfigMap or CRD, enabling cross-pod Noise IK authentication without a
certificate authority.

## Resource Considerations

### Sidecar Resources

Minimum resource requests for the Open Sesame sidecar:

| Resource | Request | Limit | Notes |
|----------|---------|-------|-------|
| CPU | 10m | 100m | Idle after vault unlock |
| Memory | 32Mi | 128Mi | `LimitMEMLOCK=64M` for secure memory |
| Ephemeral storage | 10Mi | 50Mi | Vault DB + audit log |

### Security Context

```yaml
securityContext:
  runAsNonRoot: true
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  seccompProfile:
    type: RuntimeDefault
```

The Open Sesame daemons apply their own seccomp-bpf filters in-process, layered on top of
the Kubernetes-level seccomp profile.

### memfd_secret in Containers

`memfd_secret(2)` requires `CONFIG_SECRETMEM=y` in the host kernel. Most managed Kubernetes
distributions (GKE, EKS, AKS) use kernels that do not enable this option by default. On these
platforms, Open Sesame falls back to `mmap` with `mlock` and logs the security posture
degradation at ERROR level. Operators running on custom node images or bare-metal Kubernetes
can enable `CONFIG_SECRETMEM=y` for full protection.
