use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use uuid::Uuid;

use crate::auth::{AuthCombineMode, AuthFactorId};
use crate::constants::Timestamp;
use crate::denial::{LaunchDenial, SecretDenialReason, UnlockRejectedReason};
use crate::ids::{
    AgentId, AppId, ClipboardEntryId, CompositorWorkspaceId, DaemonId, MonitorId, ProfileId,
    WindowId,
};
use crate::oci::OciReference;
use crate::profile::TrustProfileName;
use crate::rpc::{ClipboardEntry, InputLayerInfo, LaunchResult, ProfileSummary, SnippetInfo};
use crate::security::{
    AgentType, AttestationType, CapabilitySet, InstallationId, OrganizationNamespace,
    SensitivityClass,
};
use crate::sensitive::SensitiveBytes;
use crate::window::Window;

fn default_clipboard_limit() -> u32 {
    20
}

/// Externally-tagged enum (serde default) for postcard wire compatibility.
/// Postcard does not support `#[serde(tag = "...", content = "...")]`.
/// JSON output uses `{"VariantName": {...}}` format which is still
/// fully deserializable and forward-compatible via `#[serde(other)]`.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EventKind {
    // -- Window Manager Events --
    WindowFocused {
        window_id: WindowId,
        app_id: AppId,
        workspace_id: CompositorWorkspaceId,
    },
    WindowMoved {
        window_id: WindowId,
        from_workspace: CompositorWorkspaceId,
        to_workspace: CompositorWorkspaceId,
    },
    WorkspaceSwitched {
        from: CompositorWorkspaceId,
        to: CompositorWorkspaceId,
        monitor_id: MonitorId,
    },
    LayoutChanged {
        workspace_id: CompositorWorkspaceId,
        layout_name: String,
    },

    // -- Profile Events --
    ProfileActivationBegun {
        target: ProfileId,
        trigger: String,
    },
    ProfileActivated {
        target: ProfileId,
        duration_ms: u32,
    },
    ProfileDeactivationBegun {
        target: ProfileId,
    },
    ProfileDeactivated {
        target: ProfileId,
        duration_ms: u32,
    },
    ProfileActivationFailed {
        target: ProfileId,
        reason: String,
    },
    DefaultProfileChanged {
        previous: ProfileId,
        current: ProfileId,
    },
    ContextChanged {
        changed_signals: Vec<String>,
    },

    // -- Clipboard Events --
    ClipboardChanged {
        entry_id: ClipboardEntryId,
        sensitivity: SensitivityClass,
        content_type: String,
        profile_id: ProfileId,
    },
    ClipboardEntryExpired {
        entry_id: ClipboardEntryId,
    },
    ClipboardScopeSealed {
        profile_id: ProfileId,
    },

    // -- Input Events --
    HotkeyFired {
        sequence: String,
        layer: String,
        action: String,
    },
    LayerChanged {
        from: String,
        to: String,
        trigger_app: Option<AppId>,
    },
    MacroTriggered {
        macro_id: String,
        expansion_preview: String,
    },

    /// Request daemon-input to start forwarding keyboard events for the overlay.
    /// Published by daemon-wm when the overlay activates. daemon-input processes
    /// this as a broadcast event (fire-and-forget, no response expected).
    InputGrabRequest {
        /// Requesting daemon's ID — used to scope the grab.
        requester: DaemonId,
    },

    /// Acknowledge that keyboard grab/forwarding is active.
    /// Sent as a correlated response to `InputGrabRequest`.
    InputGrabResponse {
        success: bool,
        /// If false, reason for failure (e.g., no keyboard devices accessible).
        error: Option<String>,
    },

    /// Release keyboard forwarding. Published by daemon-wm when the overlay
    /// deactivates. Idempotent — safe to send even if no grab is active.
    InputGrabRelease {
        /// Must match the requester from the corresponding `InputGrabRequest`.
        requester: DaemonId,
    },

    /// A keyboard event forwarded from daemon-input while a grab is active.
    /// Carries pre-processed keysym and unicode data so daemon-wm does not
    /// need its own xkbcommon instance.
    InputKeyEvent {
        /// XKB keysym value (e.g., 0xFF1B for Escape, 0xFF0D for Return).
        keyval: u32,
        /// Evdev keycode (hardware scan code, NOT XKB keycode).
        keycode: u32,
        /// true = key press, false = key release.
        pressed: bool,
        /// Active modifier bitmask at time of event. Uses GDK-compatible
        /// bit positions: bit 0 = Shift, bit 2 = Control, bit 3 = Alt (Mod1),
        /// bit 26 = Super (Mod4).
        modifiers: u32,
        /// Unicode character for the key, if applicable. None for modifier
        /// keys, function keys, etc. Only populated on key press, not release.
        unicode: Option<char>,
    },

    // -- Secrets Events (authorized daemons only) --
    SecretResolved {
        secret_ref: String,
        ttl_remaining_s: u32,
    },
    SecretExpired {
        secret_ref: String,
    },
    SsoSessionExpired {
        profile_id: ProfileId,
        provider: String,
    },

    // -- Launcher Events --
    AppLaunched {
        app_id: AppId,
        launch_action: String,
        profile_id: ProfileId,
    },
    QuerySubmitted {
        query: String,
        result_count: u32,
        latency_ms: u32,
    },

    // -- System Events --
    DaemonStarted {
        daemon_id: DaemonId,
        version: String,
        capabilities: Vec<String>,
    },
    DaemonStopped {
        daemon_id: DaemonId,
        reason: String,
    },
    /// Request immediate key rotation. Sent by the CLI to daemon-profile.
    /// daemon-profile triggers phase 1 upon receipt.
    KeyRotationRequest,
    /// Response to `KeyRotationRequest`.
    KeyRotationRequestResponse {
        success: bool,
        error: Option<String>,
    },
    /// Key rotation: daemon-profile announces a new pubkey for a daemon.
    /// Daemons must re-read their keypair and reconnect within the grace period.
    KeyRotationPending {
        /// The daemon whose key is being rotated.
        daemon_name: String,
        /// New X25519 public key (exactly 32 bytes).
        new_pubkey: [u8; 32],
        /// Grace period in seconds before old key is revoked.
        grace_period_s: u32,
    },
    /// Key rotation completed: the registry has been updated.
    KeyRotationComplete {
        daemon_name: String,
    },
    ConfigReloaded {
        daemon_id: DaemonId,
        changed_keys: Vec<String>,
    },
    PolicyApplied {
        source: String,
        locked_keys: Vec<String>,
    },

    /// Audit event: a secret operation was attempted or completed.
    /// Emitted by daemon-secrets after each secret RPC for persistent audit logging.
    /// SECURITY: NEVER includes the secret value. Only metadata.
    SecretOperationAudit {
        /// The type of operation: "get", "set", "delete", "list"
        action: String,
        /// Trust profile the operation targeted
        profile: TrustProfileName,
        /// Secret key name (None for list operations)
        #[serde(default)]
        key: Option<String>,
        /// `DaemonId` of the requester
        requester: DaemonId,
        /// Server-verified name of the requester (if known)
        #[serde(default)]
        requester_name: Option<String>,
        /// Outcome: "success", "denied-locked", "denied-profile-not-active",
        /// "denied-acl", "rate-limited", "not-found", "denied-invalid-key", "failed", "empty"
        outcome: String,
    },

    // -- RPC: Secrets (all scoped by trust profile name) --
    SecretGet {
        profile: TrustProfileName,
        key: String,
    },
    SecretGetResponse {
        key: String,
        /// Secret value bytes. Plaintext over Noise-encrypted IPC transport
        /// (default). With `ipc-field-encryption` feature on daemon-secrets,
        /// this is additionally AES-256-GCM encrypted per-field.
        value: SensitiveBytes,
        /// Typed denial reason. `None` = success, `Some` = denied.
        #[serde(default)]
        denial: Option<SecretDenialReason>,
    },
    SecretSet {
        profile: TrustProfileName,
        key: String,
        /// Secret value bytes. Plaintext over Noise-encrypted IPC transport
        /// (default). With `ipc-field-encryption` feature on daemon-secrets,
        /// this is additionally AES-256-GCM encrypted per-field.
        value: SensitiveBytes,
    },
    SecretSetResponse {
        success: bool,
        /// Typed denial reason. `None` = success, `Some` = denied.
        #[serde(default)]
        denial: Option<SecretDenialReason>,
    },
    SecretDelete {
        profile: TrustProfileName,
        key: String,
    },
    SecretDeleteResponse {
        success: bool,
        /// Typed denial reason. `None` = success, `Some` = denied.
        #[serde(default)]
        denial: Option<SecretDenialReason>,
    },
    SecretList {
        profile: TrustProfileName,
    },
    SecretListResponse {
        keys: Vec<String>,
        /// Typed denial reason. `None` = success, `Some` = denied.
        #[serde(default)]
        denial: Option<SecretDenialReason>,
    },

    // -- RPC: Profile Activation --
    ProfileActivate {
        target: ProfileId,
        profile_name: TrustProfileName,
    },
    ProfileActivateResponse {
        success: bool,
    },
    ProfileDeactivate {
        target: ProfileId,
        profile_name: TrustProfileName,
    },
    ProfileDeactivateResponse {
        success: bool,
    },
    ProfileList,
    ProfileListResponse {
        profiles: Vec<ProfileSummary>,
    },
    SetDefaultProfile {
        profile_name: TrustProfileName,
    },
    SetDefaultProfileResponse {
        success: bool,
    },

    // -- RPC: Status --
    StatusRequest,
    StatusResponse {
        active_profiles: Vec<TrustProfileName>,
        default_profile: TrustProfileName,
        daemon_uptimes_ms: Vec<(DaemonId, u64)>,
        /// True if ALL vaults are locked. Convenience for callers that don't need per-profile granularity.
        locked: bool,
        /// Per-profile lock state. Key = profile name, value = true if locked.
        #[serde(default)]
        lock_state: BTreeMap<TrustProfileName, bool>,
    },

    // -- RPC: Unlock/Lock --
    UnlockRequest {
        /// Vault password bytes (transmitted over UCred-authenticated Unix socket only).
        password: SensitiveBytes,
        /// Target profile to unlock. None = default profile.
        #[serde(default)]
        profile: Option<TrustProfileName>,
    },
    UnlockResponse {
        success: bool,
        /// Which profile was unlocked.
        profile: TrustProfileName,
    },
    /// Typed rejection for unlock when preconditions are not met.
    /// Distinct from `UnlockResponse` { success: false } to avoid ambiguity
    /// between "wrong password" and "already unlocked".
    UnlockRejected {
        reason: UnlockRejectedReason,
        profile: Option<TrustProfileName>,
    },
    /// Unlock a vault using a pre-derived master key (SSH-agent or future backends).
    /// The caller performed signing, KEK derivation, and master key unwrapping.
    SshUnlockRequest {
        master_key: SensitiveBytes,
        profile: TrustProfileName,
        ssh_fingerprint: String,
    },

    LockRequest {
        /// Target profile. None = lock all vaults.
        #[serde(default)]
        profile: Option<TrustProfileName>,
    },
    LockResponse {
        success: bool,
        /// Which profiles were locked.
        profiles_locked: Vec<TrustProfileName>,
    },

    // -- RPC: State Reconciliation --
    /// daemon-profile queries daemon-secrets for authoritative state.
    SecretsStateRequest,
    /// daemon-secrets returns authoritative lock + active profiles.
    SecretsStateResponse {
        /// True if ALL vaults are locked. Convenience for callers that don't need per-profile granularity.
        locked: bool,
        active_profiles: Vec<TrustProfileName>,
        /// Per-profile lock state.
        #[serde(default)]
        lock_state: BTreeMap<TrustProfileName, bool>,
    },

    // -- RPC: Window Manager --
    WmListWindows,
    WmListWindowsResponse {
        windows: Vec<Window>,
    },
    WmActivateWindow {
        window_id: String,
    },
    WmActivateWindowResponse {
        success: bool,
    },
    /// Trigger the window switcher overlay (forward direction).
    WmActivateOverlay,
    /// Trigger the window switcher overlay (backward direction).
    WmActivateOverlayBackward,
    /// Trigger the overlay in launcher mode (skip border-only, start in `FullOverlay`).
    WmActivateOverlayLauncher,
    /// Trigger the overlay in launcher mode with backward initial selection.
    WmActivateOverlayLauncherBackward,
    WmOverlayShown,
    WmOverlayDismissed,

    // -- RPC: Launcher --
    LaunchQuery {
        query: String,
        max_results: u32,
        /// Trust profile context for scoped frecency and launch environment.
        #[serde(default)]
        profile: Option<TrustProfileName>,
    },
    LaunchQueryResponse {
        results: Vec<LaunchResult>,
    },
    LaunchExecute {
        entry_id: String,
        /// Trust profile context — injected as `SESAME_PROFILE` env var in spawned process.
        #[serde(default)]
        profile: Option<TrustProfileName>,
        /// Launch profile tags to compose for environment injection.
        #[serde(default)]
        tags: Vec<String>,
        /// Additional CLI arguments appended to the desktop entry's Exec line.
        #[serde(default)]
        launch_args: Vec<String>,
    },
    LaunchExecuteResponse {
        pid: u32,
        error: Option<String>,
        /// Machine-readable denial reason for programmatic action by the WM.
        #[serde(default)]
        denial: Option<LaunchDenial>,
    },

    // -- RPC: Clipboard --
    ClipboardHistory {
        profile: TrustProfileName,
        #[serde(default = "default_clipboard_limit")]
        limit: u32,
    },
    ClipboardHistoryResponse {
        entries: Vec<ClipboardEntry>,
    },
    ClipboardClear {
        profile: TrustProfileName,
    },
    ClipboardClearResponse {
        success: bool,
    },
    ClipboardGet {
        entry_id: ClipboardEntryId,
    },
    ClipboardGetResponse {
        content: Option<String>,
        content_type: Option<String>,
    },

    // -- RPC: Input --
    InputLayersList,
    InputLayersListResponse {
        layers: Vec<InputLayerInfo>,
    },
    InputStatus,
    InputStatusResponse {
        active_layer: String,
        grabbed_devices: Vec<String>,
        remapping_active: bool,
    },

    // -- RPC: Snippets --
    SnippetList {
        profile: TrustProfileName,
    },
    SnippetListResponse {
        snippets: Vec<SnippetInfo>,
    },
    SnippetExpand {
        profile: TrustProfileName,
        trigger: String,
    },
    SnippetExpandResponse {
        expanded: Option<String>,
    },
    SnippetAdd {
        profile: TrustProfileName,
        trigger: String,
        template: String,
    },
    SnippetAddResponse {
        success: bool,
    },

    // -- Agent Lifecycle --
    AgentConnected {
        agent_id: AgentId,
        agent_type: AgentType,
        attestations: Vec<AttestationType>,
    },
    AgentDisconnected {
        agent_id: AgentId,
        reason: String,
    },

    // -- Namespace Lifecycle --
    InstallationCreated {
        id: InstallationId,
        org: Option<OrganizationNamespace>,
        machine_binding_present: bool,
    },
    ProfileIdMigrated {
        name: TrustProfileName,
        old_id: ProfileId,
        new_id: ProfileId,
    },

    // -- Authorization Broker (v2: defined, not exercised) --
    AuthorizationRequired {
        request_id: Uuid,
        operation: String,
        missing_attestations: Vec<AttestationType>,
        expires_at: Timestamp,
    },
    AuthorizationGrant {
        request_id: Uuid,
        delegator: AgentId,
        scope: CapabilitySet,
        ttl_seconds: u32,
        point_of_use_filter: Option<OciReference>,
    },
    AuthorizationDenied {
        request_id: Uuid,
        reason: String,
    },
    AuthorizationTimeout {
        request_id: Uuid,
    },
    DelegationRevoked {
        delegation_id: Uuid,
        revoker: AgentId,
        reason: String,
    },
    HeartbeatRenewed {
        delegation_id: Uuid,
        renewal_source: AgentId,
        next_deadline: Timestamp,
    },

    // -- Federation (v2: defined, not exercised) --
    FederationSessionEstablished {
        session_id: Uuid,
        remote_installation: InstallationId,
    },
    FederationSessionTerminated {
        session_id: Uuid,
        reason: String,
    },

    // -- Device Posture --
    PostureEvaluated {
        secure_boot: Option<bool>,
        disk_encrypted: Option<bool>,
        screen_locked: Option<bool>,
        composite_score: f64,
    },

    // -- Bus-level errors (generated by the IPC server, not daemons) --
    /// The bus rejected the message. Sent back to the sender as a correlated
    /// response so the client gets an actionable error instead of a silent timeout.
    AccessDenied {
        reason: String,
    },

    // -- RPC: Multi-Factor Auth --
    /// Submit a single authentication factor for vault unlock.
    /// Supports partial multi-factor unlock. daemon-secrets returns
    /// `FactorResponse` indicating whether more factors are needed.
    FactorSubmit {
        /// Which factor is being submitted.
        factor_id: AuthFactorId,
        /// The factor's contribution: pre-derived master key (for any/policy mode)
        /// or factor piece (for all mode).
        key_material: SensitiveBytes,
        /// Target profile.
        profile: TrustProfileName,
        /// Audit metadata from the backend (e.g., SSH fingerprint).
        #[serde(default)]
        audit_metadata: BTreeMap<String, String>,
    },

    /// Response to `FactorSubmit`.
    FactorResponse {
        /// Whether this factor was accepted.
        accepted: bool,
        /// If accepted and all factors satisfied: true. Vault is now unlocked.
        unlock_complete: bool,
        /// Which factors are still needed (empty if `unlock_complete`).
        remaining_factors: Vec<AuthFactorId>,
        /// How many additional factors are still needed.
        remaining_additional: u32,
        /// Target profile.
        profile: TrustProfileName,
        /// Error message if not accepted.
        #[serde(default)]
        error: Option<String>,
    },

    /// Query what factors a vault requires for unlock.
    VaultAuthQuery {
        profile: TrustProfileName,
    },

    /// Response to `VaultAuthQuery`.
    VaultAuthQueryResponse {
        profile: TrustProfileName,
        /// Which factors are enrolled.
        enrolled_factors: Vec<AuthFactorId>,
        /// The vault's auth policy.
        auth_policy: AuthCombineMode,
        /// Whether a partial unlock is in progress.
        partial_in_progress: bool,
        /// If partial in progress, which factors have been received.
        #[serde(default)]
        received_factors: Vec<AuthFactorId>,
    },

    // -- RPC: Network Identity (M1) --
    /// Request the network transport identity keypair from daemon-secrets.
    NetworkIdentityRequest,
    /// Response with the network identity keypair.
    NetworkIdentityResponse {
        /// X25519 private key (32 bytes) in ProtectedAlloc-backed memory.
        private_key: SensitiveBytes,
        /// X25519 public key (32 bytes).
        public_key: Vec<u8>,
    },

    // -- Vault Replication (M3) --
    /// A replicated vault log entry received from a network peer.
    VaultLogEntryReceived {
        profile_id: Uuid,
        entry_json: String,
    },
    /// Request vault log entries from daemon-secrets for replication serving.
    VaultReplicationPullRequest {
        profile_id: Uuid,
        #[serde(default)]
        since_watermark_json: Option<String>,
        max_entries: u32,
    },
    /// Response with vault log entries for replication.
    VaultReplicationPullResponse {
        profile_id: Uuid,
        entries_json: String,
        has_more: bool,
    },

    // -- RPC: Network Status (M2 CLI→daemon-network IPC) --
    /// Request daemon-network's current status (sessions, discovery, TOFU).
    NetworkStatusRequest,
    /// Response with daemon-network status.
    NetworkStatusResponse {
        /// Number of active peer sessions.
        active_sessions: u32,
        /// Number of TOFU-pinned peers.
        tofu_peers: u32,
        /// Number of TOFU fork-evidence log events.
        tofu_events: u32,
        /// Discovery dial queue depth.
        dial_queue_depth: u32,
        /// Listen port.
        listen_port: u16,
        /// Whether the daemon is enabled.
        enabled: bool,
    },

    /// Request daemon-network to dial a remote peer.
    NetworkDialRequest {
        /// Target address in `host:port` format.
        addr: String,
    },
    /// Response to a dial request.
    NetworkDialResponse {
        /// Whether the dial succeeded.
        success: bool,
        /// Session ID if established.
        #[serde(default)]
        session_id: Option<String>,
        /// Error message if failed.
        #[serde(default)]
        error: Option<String>,
    },

    /// Request discovery subsystem state.
    NetworkDiscoverRequest,
    /// Response with discovery state.
    NetworkDiscoverResponse {
        /// mDNS peers discovered on LAN.
        mdns_peers: u32,
        /// BEP-44 records published.
        bep44_published: bool,
        /// DNS SRV domains configured.
        dns_srv_domains: Vec<String>,
        /// Dial queue depth.
        dial_queue_depth: u32,
        /// SWIM cluster members.
        swim_members: u32,
    },

    /// Request daemon-network to reload bootstrap.json and DNS SRV config.
    NetworkDiscoveryReloadRequest,
    /// Response to discovery reload request.
    NetworkDiscoveryReloadResponse {
        /// Number of new peers added to the dial queue.
        added: u32,
    },

    /// Request to unpin a TOFU peer by public key hex.
    NetworkUnpinRequest {
        public_key_hex: String,
    },
    /// Response to unpin request.
    NetworkUnpinResponse {
        success: bool,
        #[serde(default)]
        error: Option<String>,
    },

    // Forward compatibility: unknown events deserialize to this variant.
    #[serde(other)]
    Unknown,
}

/// Implement `fmt::Debug` for `EventKind` with automatic redaction of sensitive variants.
///
/// **Sensitive variants** (containing passwords, secret values) are listed in the first section
/// with explicit `[REDACTED; N bytes]` substitution. **All other variants** are listed in the
/// second section and get standard `debug_struct` output generated by the macro.
///
/// Adding a new non-sensitive variant: add one line to the second section.
/// Adding a new sensitive variant: add to the first section with explicit redaction.
/// The compiler enforces exhaustiveness — forgetting a variant is a compile error.
macro_rules! impl_event_debug {
    (
        sensitive {
            $( $sens_variant:ident { $($sens_field:ident $( => $redact:tt)?),* } ),* $(,)?
        }
        transparent {
            $( $name:ident $({ $($field:ident),* })? ),* $(,)?
        }
    ) => {
        impl fmt::Debug for EventKind {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(
                        Self::$sens_variant { $($sens_field),* } => {
                            let mut s = f.debug_struct(stringify!($sens_variant));
                            $(
                                impl_event_debug!(@field s, $sens_field $( => $redact)?);
                            )*
                            s.finish()
                        }
                    )*
                    $(
                        Self::$name $({ $($field),* })? => {
                            let mut s = f.debug_struct(stringify!($name));
                            $( $(s.field(stringify!($field), $field);)* )?
                            s.finish()
                        }
                    )*
                }
            }
        }
    };
    // Field helper: redacted
    (@field $s:expr, $field:ident => REDACTED) => {
        $s.field(stringify!($field), &format_args!("[REDACTED; {} bytes]", $field.len()));
    };
    // Field helper: transparent (print as-is)
    (@field $s:expr, $field:ident) => {
        $s.field(stringify!($field), $field);
    };
}

impl_event_debug! {
    sensitive {
        SecretGetResponse { key, value => REDACTED, denial },
        SecretSet { profile, key, value => REDACTED },
        UnlockRequest { password => REDACTED, profile },
        SshUnlockRequest { master_key => REDACTED, profile, ssh_fingerprint },
        FactorSubmit { factor_id, key_material => REDACTED, profile, audit_metadata },
        NetworkIdentityResponse { private_key => REDACTED, public_key },
    }
    transparent {
        WindowFocused { window_id, app_id, workspace_id },
        WindowMoved { window_id, from_workspace, to_workspace },
        WorkspaceSwitched { from, to, monitor_id },
        LayoutChanged { workspace_id, layout_name },
        ProfileActivationBegun { target, trigger },
        ProfileActivated { target, duration_ms },
        ProfileDeactivationBegun { target },
        ProfileDeactivated { target, duration_ms },
        ProfileActivationFailed { target, reason },
        DefaultProfileChanged { previous, current },
        ContextChanged { changed_signals },
        ClipboardChanged { entry_id, sensitivity, content_type, profile_id },
        ClipboardEntryExpired { entry_id },
        ClipboardScopeSealed { profile_id },
        HotkeyFired { sequence, layer, action },
        LayerChanged { from, to, trigger_app },
        MacroTriggered { macro_id, expansion_preview },
        InputGrabRequest { requester },
        InputGrabResponse { success, error },
        InputGrabRelease { requester },
        InputKeyEvent { keyval, keycode, pressed, modifiers, unicode },
        SecretResolved { secret_ref, ttl_remaining_s },
        SecretExpired { secret_ref },
        SsoSessionExpired { profile_id, provider },
        AppLaunched { app_id, launch_action, profile_id },
        QuerySubmitted { query, result_count, latency_ms },
        DaemonStarted { daemon_id, version, capabilities },
        DaemonStopped { daemon_id, reason },
        KeyRotationRequest,
        KeyRotationRequestResponse { success, error },
        KeyRotationPending { daemon_name, new_pubkey, grace_period_s },
        KeyRotationComplete { daemon_name },
        ConfigReloaded { daemon_id, changed_keys },
        PolicyApplied { source, locked_keys },
        SecretGet { profile, key },
        SecretSetResponse { success, denial },
        SecretDelete { profile, key },
        SecretDeleteResponse { success, denial },
        SecretList { profile },
        SecretListResponse { keys, denial },
        SecretOperationAudit { action, profile, key, requester, requester_name, outcome },
        ProfileActivate { target, profile_name },
        ProfileActivateResponse { success },
        ProfileDeactivate { target, profile_name },
        ProfileDeactivateResponse { success },
        ProfileList,
        ProfileListResponse { profiles },
        SetDefaultProfile { profile_name },
        SetDefaultProfileResponse { success },
        StatusRequest,
        StatusResponse { active_profiles, default_profile, daemon_uptimes_ms, locked, lock_state },
        UnlockResponse { success, profile },
        UnlockRejected { reason, profile },
        LockRequest { profile },
        LockResponse { success, profiles_locked },
        SecretsStateRequest,
        SecretsStateResponse { locked, active_profiles, lock_state },
        WmListWindows,
        WmListWindowsResponse { windows },
        WmActivateWindow { window_id },
        WmActivateWindowResponse { success },
        WmActivateOverlay,
        WmActivateOverlayBackward,
        WmActivateOverlayLauncher,
        WmActivateOverlayLauncherBackward,
        WmOverlayShown,
        WmOverlayDismissed,
        LaunchQuery { query, max_results, profile },
        LaunchQueryResponse { results },
        LaunchExecute { entry_id, profile, tags, launch_args },
        LaunchExecuteResponse { pid, error, denial },
        ClipboardHistory { profile, limit },
        ClipboardHistoryResponse { entries },
        ClipboardClear { profile },
        ClipboardClearResponse { success },
        ClipboardGet { entry_id },
        ClipboardGetResponse { content, content_type },
        InputLayersList,
        InputLayersListResponse { layers },
        InputStatus,
        InputStatusResponse { active_layer, grabbed_devices, remapping_active },
        SnippetList { profile },
        SnippetListResponse { snippets },
        SnippetExpand { profile, trigger },
        SnippetExpandResponse { expanded },
        SnippetAdd { profile, trigger, template },
        SnippetAddResponse { success },
        AgentConnected { agent_id, agent_type, attestations },
        AgentDisconnected { agent_id, reason },
        InstallationCreated { id, org, machine_binding_present },
        ProfileIdMigrated { name, old_id, new_id },
        AuthorizationRequired { request_id, operation, missing_attestations, expires_at },
        AuthorizationGrant { request_id, delegator, scope, ttl_seconds, point_of_use_filter },
        AuthorizationDenied { request_id, reason },
        AuthorizationTimeout { request_id },
        DelegationRevoked { delegation_id, revoker, reason },
        HeartbeatRenewed { delegation_id, renewal_source, next_deadline },
        FederationSessionEstablished { session_id, remote_installation },
        FederationSessionTerminated { session_id, reason },
        PostureEvaluated { secure_boot, disk_encrypted, screen_locked, composite_score },
        FactorResponse { accepted, unlock_complete, remaining_factors, remaining_additional, profile, error },
        VaultAuthQuery { profile },
        VaultAuthQueryResponse { profile, enrolled_factors, auth_policy, partial_in_progress, received_factors },
        AccessDenied { reason },
        NetworkIdentityRequest,
        VaultLogEntryReceived { profile_id, entry_json },
        VaultReplicationPullRequest { profile_id, since_watermark_json, max_entries },
        VaultReplicationPullResponse { profile_id, entries_json, has_more },
        NetworkStatusRequest,
        NetworkStatusResponse { active_sessions, tofu_peers, tofu_events, dial_queue_depth, listen_port, enabled },
        NetworkDialRequest { addr },
        NetworkDialResponse { success, session_id, error },
        NetworkDiscoverRequest,
        NetworkDiscoverResponse { mdns_peers, bep44_published, dns_srv_domains, dial_queue_depth, swim_members },
        NetworkDiscoveryReloadRequest,
        NetworkDiscoveryReloadResponse { added },
        NetworkUnpinRequest { public_key_hex },
        NetworkUnpinResponse { success, error },
        Unknown,
    }
}
