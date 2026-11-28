//! The bus-facing state of daemon-profile: the handler for every message
//! addressed to it, the context engine, configuration reloads, and
//! periodic reconciliation with daemon-secrets.

use core_ipc::{BusServer, Message, MessageContext};
use core_layout::Layout;
use core_profile::{AuditAction, AuditLogger, ContextEngine, ContextSignal};
use core_types::{Daemon, DaemonId, EventKind, ProfileId, TrustProfileName};
use std::collections::HashSet;
use tokio::sync::mpsc;

use crate::activation::{Transition, TransitionError};
use crate::key_rotation::PendingRotation;
use crate::{DaemonTracker, KEY_ROTATION_GRACE};

/// The hash-chained audit log daemon-profile appends to.
pub(crate) type AuditLog = AuditLogger<std::io::BufWriter<std::fs::File>>;

/// The message in `frame` from a host channel, unless it is malformed
/// (logged) or `own` sent it. Host announcements exclude their publisher;
/// this check also prevents an explicitly unicasted self-message from looping.
pub(crate) fn decode_host_frame(frame: &[u8], own: DaemonId) -> Option<Message<EventKind>> {
    match core_ipc::decode_frame::<Message<EventKind>>(frame) {
        Ok(msg) => (msg.sender != own).then_some(msg),
        Err(e) => {
            tracing::warn!(error = %e, "malformed frame on host channel");
            None
        }
    }
}

/// Encode `reply` and unicast it to the connection that sent request
/// `msg_id`. Never broadcasts: the reply may carry secret values
/// (`SecretGetResponse`). A requester that disconnected before its reply
/// (it gave up waiting) is expected; a reply to a request the bus never
/// tracked is an error. Either way nothing is delivered.
pub(crate) async fn send_reply(
    bus: &BusServer,
    msg_id: &uuid::Uuid,
    mut reply: Message<EventKind>,
) {
    reply.verified_sender_name = Some(Daemon::Profile.name().into());
    let mut reply_bytes = match core_ipc::encode_frame(&reply) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = %e, %msg_id, "failed to encode response");
            return;
        }
    };
    match bus.take_pending_request(msg_id, &reply.payload).await {
        core_ipc::Requester::Connected(origin_conn) => {
            if !bus.send_to(origin_conn, &reply_bytes).await {
                tracing::warn!(
                    conn_id = origin_conn,
                    %msg_id,
                    "unicast response failed: connection gone or channel full"
                );
            }
        }
        core_ipc::Requester::Disconnected => {
            tracing::info!(%msg_id, "requester disconnected before its response; not delivered");
        }
        core_ipc::Requester::Unknown => {
            tracing::error!(
                %msg_id,
                "response to an untracked request -- dropping to prevent potential secret broadcast"
            );
        }
    }
    // The postcard buffer may hold serialized secret values.
    zeroize::Zeroize::zeroize(&mut reply_bytes);
}

/// Profile, lock, and key state served over the bus.
pub(crate) struct Hub {
    pub(crate) application: core_daemon::ConfigApplicationState,
    /// Daemon keypair locations.
    pub(crate) layout: Layout,
    pub(crate) bus: BusServer,
    /// daemon-profile's sender identity on the bus and the installation
    /// and agent identity its messages carry.
    pub(crate) ctx: MessageContext,
    pub(crate) audit: AuditLog,
    /// Shadow of daemon-secrets' authorized profiles, refreshed by
    /// reconciliation.
    pub(crate) active_profiles: HashSet<TrustProfileName>,
    /// Shadow of daemon-secrets' lock state.
    pub(crate) locked: bool,
    pub(crate) default_profile_name: TrustProfileName,
    /// The configured profile names that may be activated.
    pub(crate) config_profile_names: Vec<TrustProfileName>,
    pub(crate) install_ns: uuid::Uuid,
    /// Selects the default profile from context signals.
    pub(crate) context_engine: ContextEngine,
    pub(crate) daemon_tracker: DaemonTracker,
    /// Confirmed-RPC route for daemon-secrets' responses.
    pub(crate) confirm_tx: mpsc::Sender<Vec<u8>>,
    pub(crate) confirm_rx: mpsc::Receiver<Vec<u8>>,
    /// Signals the event loop to run key rotation phase 2.
    pub(crate) rotation_done_tx: mpsc::Sender<()>,
    /// The rotation between its phases, if one is.
    pub(crate) pending_rotation: Option<PendingRotation>,
}

impl Hub {
    /// Run key rotation phase 2 after the grace period, through the event
    /// loop's rotation channel.
    pub(crate) fn schedule_rotation_phase2(&self) {
        let tx = self.rotation_done_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(u64::from(
                KEY_ROTATION_GRACE,
            )))
            .await;
            if tx.send(()).await.is_err() {
                tracing::warn!("event loop gone, key rotation phase 2 not run");
            }
        });
    }

    /// Handle a frame from the host channel: a request is answered by
    /// unicast to its sender (a broadcast would leak secret values to
    /// non-requesting clients).
    pub(crate) async fn host_frame(&mut self, frame: &[u8]) {
        let Some(msg) = decode_host_frame(frame, self.ctx.sender) else {
            return;
        };
        if let Some(response) = self.handle(&msg).await {
            let reply = Message::new(&self.ctx, response, msg.security_level, self.bus.epoch())
                .with_correlation(msg.msg_id);
            send_reply(&self.bus, &msg.msg_id, reply).await;
        }
    }

    /// Apply `reload`: rebuild the context engine, the default profile, and
    /// the activatable profile names from its configuration, then
    /// acknowledge and announce it. Shared by the configuration watcher,
    /// SIGHUP (`systemctl reload`), and startup.
    pub(crate) async fn reload(&mut self, reload: core_daemon::Reload) {
        let previous = ProfileId::of_profile(&self.install_ns, self.default_profile_name.as_ref());
        let config = &reload.snapshot.config;
        self.context_engine = crate::context::context_engine(config, &self.install_ns);
        self.default_profile_name = config.global.default_profile.clone();
        self.config_profile_names = crate::context::profile_names(config);
        tracing::info!(
            default_profile = %self.default_profile_name,
            "context engine rebuilt from reloaded config"
        );
        if let Some(event) = reload.applied_event(self.ctx.sender) {
            self.announce(event).await;
            let current =
                ProfileId::of_profile(&self.install_ns, self.default_profile_name.as_ref());
            if current != previous {
                self.default_changed(previous, current).await;
            }
        }
    }

    /// Evaluate a context signal: a changed default profile is the default
    /// `status` reports, audited and announced.
    pub(crate) async fn context_changed(&mut self, signal: &ContextSignal) {
        let previous = self.context_engine.default_profile();
        let Some(current) = self
            .context_engine
            .evaluate(signal)
            .filter(|&current| current != previous)
        else {
            return;
        };
        tracing::info!(%previous, new_default = %current, ?signal, "default profile changed by context engine");
        if let Some(name) =
            crate::context::profile_named(&self.config_profile_names, &self.install_ns, current)
        {
            self.default_profile_name = name.clone();
        } else {
            tracing::error!(
                profile = %current,
                "context engine chose a profile that is not configured"
            );
        }
        self.default_changed(previous, current).await;
    }

    /// Audit and announce the default profile's change from `previous` to
    /// `current` (`DefaultProfileChanged`: daemon-clipboard files new
    /// entries under the default).
    async fn default_changed(&mut self, previous: ProfileId, current: ProfileId) {
        self.record(&AuditAction::DefaultProfileChanged { previous, current });
        self.announce(EventKind::DefaultProfileChanged { previous, current })
            .await;
    }

    /// Handle a message on the bus that daemon-profile is responsible for.
    ///
    /// Returns `Some(response_event)` for RPC requests, `None` for broadcast
    /// events.
    async fn handle(&mut self, msg: &Message<EventKind>) -> Option<EventKind> {
        match &msg.payload {
            EventKind::DaemonStarted { daemon_id, .. } => {
                self.daemon_started(msg, *daemon_id).await;
                None
            }
            EventKind::StatusRequest => Some(self.status().await),
            EventKind::ConfigStatusRequest {
                daemon: Daemon::Profile,
            } => match self.application.status() {
                Ok(status) => Some(EventKind::ConfigStatusResponse {
                    daemon: Daemon::Profile,
                    status,
                }),
                Err(error) => {
                    tracing::error!(%error, "configuration status unavailable");
                    None
                }
            },
            EventKind::ProfileList => Some(self.profile_list()),
            EventKind::ProfileActivate {
                profile_name,
                target,
            } => Some(EventKind::ProfileActivateResponse {
                success: self.activate(*target, profile_name).await,
            }),
            EventKind::ProfileDeactivate {
                profile_name,
                target,
            } => Some(EventKind::ProfileDeactivateResponse {
                success: self.deactivate(*target, profile_name).await,
            }),
            EventKind::SetDefaultProfile { profile_name } => {
                Some(EventKind::SetDefaultProfileResponse {
                    success: self.set_default(profile_name).await,
                })
            }
            EventKind::VaultUnlocked { .. } | EventKind::VaultsLocked { .. } => {
                self.lock_state_changed(msg);
                None
            }
            // Secret operation audit events from daemon-secrets, persisted in
            // the hash-chained audit log.
            EventKind::SecretOperationAudit {
                action,
                profile,
                key,
                requester,
                requester_name,
                outcome,
            } => {
                self.record(&AuditAction::SecretOperationAudited {
                    action: action.clone(),
                    profile: profile.clone(),
                    key: key.clone(),
                    requester: *requester,
                    requester_name: requester_name.clone(),
                    outcome: outcome.clone(),
                });
                None
            }
            EventKind::KeyRotationRequest => Some(self.rotate_on_request().await),
            // Every other event is addressed to another daemon.
            _ => None,
        }
    }

    /// A daemon announced itself as `announced_id`: a known name under a new
    /// id is a restart. Only the server-verified name from the Noise IK
    /// registry counts; self-declared capabilities are spoofable by any
    /// client.
    async fn daemon_started(&mut self, msg: &Message<EventKind>, announced_id: DaemonId) {
        let Some(name) = msg.verified_sender_name.as_deref() else {
            tracing::warn!(
                audit = "security",
                sender = %announced_id,
                "DaemonStarted from unverified sender — ignoring (no verified_sender_name)"
            );
            return;
        };
        if let Some(old_id) = self.daemon_tracker.track(name, announced_id) {
            self.daemon_restarted(name, old_id, announced_id).await;
        }
    }

    /// Every configured profile, with installation-scoped IDs matching the
    /// context engine's activation rules.
    fn profile_list(&self) -> EventKind {
        let profiles = self
            .config_profile_names
            .iter()
            .map(|name| core_types::ProfileSummary {
                id: ProfileId::of_profile(&self.install_ns, name.as_ref()),
                name: name.clone(),
                is_active: self.active_profiles.contains(name),
                is_default: *name == self.default_profile_name,
            })
            .collect();
        EventKind::ProfileListResponse { profiles }
    }

    /// Whether `profile_name` is configured; a request naming another is
    /// logged and refused.
    fn configured(&self, profile_name: &TrustProfileName, request: &str) -> bool {
        let configured = self.config_profile_names.contains(profile_name);
        if !configured {
            tracing::warn!(profile = %profile_name, request, "profile not in config");
        }
        configured
    }

    /// Activate a configured profile: whether it is now active.
    async fn activate(&mut self, target: ProfileId, profile_name: &TrustProfileName) -> bool {
        if let Err(error) = self.application.policy() {
            tracing::warn!(%error, %profile_name, "activation denied: policy unavailable");
            return false;
        }
        self.configured(profile_name, "activate")
            && self.apply(Transition::Activate, target, profile_name).await
    }

    /// Revoke access even after configuration removes the profile. The secrets
    /// daemon owns activation state, so a stale local shadow cannot veto revocation.
    async fn deactivate(&mut self, target: ProfileId, profile_name: &TrustProfileName) -> bool {
        self.apply(Transition::Deactivate, target, profile_name)
            .await
    }

    /// Make a configured profile the default: the context engine's default
    /// and the one `status` reports, audited and announced when it changed.
    async fn set_default(&mut self, profile_name: &TrustProfileName) -> bool {
        if !self.configured(profile_name, "set default") {
            return false;
        }
        tracing::info!(previous = %self.default_profile_name, new = %profile_name, "set default profile requested");
        self.default_profile_name = profile_name.clone();
        let current = ProfileId::of_profile(&self.install_ns, profile_name.as_ref());
        if let Some(previous) = self.context_engine.set_default(current) {
            self.default_changed(previous, current).await;
        }
        true
    }

    /// Update the shadow lock state from daemon-secrets' `VaultUnlocked` or
    /// `VaultsLocked`. Only the server-verified daemon-secrets identity
    /// counts; any other sender is ignored.
    fn lock_state_changed(&mut self, msg: &Message<EventKind>) {
        if msg.verified_sender_name.as_deref() != Some(Daemon::Secrets.name()) {
            tracing::warn!(
                audit = "security",
                sender = %msg.sender,
                "lock-state announcement from a sender other than daemon-secrets ignored"
            );
            return;
        }
        match &msg.payload {
            EventKind::VaultUnlocked { profile } => {
                self.locked = false; // At least one vault is unlocked.
                tracing::info!(%profile, "vault unlocked, shadow state updated");
            }
            EventKind::VaultsLocked { profiles } if profiles.is_empty() => {
                self.fail_closed();
                tracing::info!(
                    audit = "security",
                    "all vaults locked, active profiles cleared"
                );
            }
            EventKind::VaultsLocked { profiles } => {
                for profile in profiles {
                    self.active_profiles.remove(profile);
                }
                tracing::info!(audit = "security", ?profiles, "vault(s) locked");
            }
            _ => {}
        }
    }

    /// Run rotation phase 1 on request: the response, carrying the error.
    async fn rotate_on_request(&mut self) -> EventKind {
        tracing::info!(
            audit = "key-management",
            "on-demand key rotation requested via IPC"
        );
        let error = self.begin_key_rotation().await.err().map(|e| {
            tracing::error!(error = %e, "on-demand key rotation failed");
            format!("{e:#}")
        });
        EventKind::KeyRotationRequestResponse {
            success: error.is_none(),
            error,
        }
    }

    /// Apply `transition` to `profile_name` and update the shadow state:
    /// whether the profile is now in the requested state.
    ///
    /// When daemon-secrets did not confirm the transition, its state is
    /// unknown: the shadow state is reconciled with daemon-secrets'
    /// authoritative state, which then answers.
    async fn apply(
        &mut self,
        transition: Transition,
        target: ProfileId,
        profile_name: &TrustProfileName,
    ) -> bool {
        let wanted_active = transition == Transition::Activate;
        match self.transition(transition, target, profile_name).await {
            Ok(duration_ms) => {
                if wanted_active {
                    self.active_profiles.insert(profile_name.clone());
                } else {
                    self.active_profiles.remove(profile_name);
                }
                tracing::info!(profile = %profile_name, ?transition, duration_ms, "profile transition applied");
                true
            }
            // An authoritative refusal (daemon-secrets' state is unchanged;
            // `transition` announced and audited it) is a denial, logged
            // as this daemon's own policy denials are; only an unknown
            // outcome is a fault.
            Err(e @ TransitionError::Rejected) => {
                tracing::warn!(profile = %profile_name, ?transition, error = %e, "profile transition rejected");
                false
            }
            Err(e @ TransitionError::Unconfirmed(_)) => {
                tracing::error!(
                    profile = %profile_name,
                    ?transition,
                    error = %e,
                    "profile transition unconfirmed, reconciling with daemon-secrets"
                );
                if let Err(error) = self.reconcile_secrets_state().await {
                    tracing::warn!(%error, "vault inventory unavailable after transition");
                    return false;
                }
                self.active_profiles.contains(profile_name) == wanted_active
            }
        }
    }

    /// `name` reconnected with a new `DaemonId`: revoke its keys, issue a
    /// fresh keypair under the next generation, and announce it so the
    /// restarted daemon reconnects with the new key.
    async fn daemon_restarted(&mut self, name: &str, old_id: DaemonId, new_id: DaemonId) {
        tracing::warn!(
            audit = "security",
            event_type = "daemon-restart-detected",
            daemon_name = %name,
            old_id = %old_id,
            new_id = %new_id,
            "daemon restart detected — revoking old key and generating new keypair"
        );

        let Some(daemon) = crate::client_daemons().find(|known| known.name() == name) else {
            tracing::warn!(
                daemon = name,
                "restarted daemon is not a known daemon, no key issued"
            );
            return;
        };
        let security_level = daemon.clearance();

        // daemon-secrets restarts locked with no active profiles.
        if daemon == Daemon::Secrets {
            self.fail_closed();
            tracing::warn!(
                audit = "security",
                event_type = "daemon-secrets-restart",
                "daemon-secrets restarted — resetting lock state and clearing active profiles"
            );
        }

        let new_pubkey =
            match core_ipc::noise::issue_daemon_keypair(&self.layout, daemon.name()).await {
                Ok(public) => public,
                Err(e) => {
                    tracing::error!(error = %e, %daemon, "failed to issue revocation keypair");
                    return;
                }
            };

        // Revoke every key of the daemon (covers the dual-key state during
        // rotation) and register the new one under the next generation.
        let next_gen = {
            let mut reg = self.bus.registry_mut().await;
            let next_gen = reg
                .revoke_by_name(daemon.name())
                .map_or(0, |revoked| revoked.generation + 1);
            reg.register(daemon.name().into(), new_pubkey, security_level, next_gen);
            next_gen
        };
        tracing::info!(
            audit = "security",
            event_type = "key-revocation",
            %daemon,
            generation = next_gen,
            "old key revoked, new key registered"
        );
        self.record(&AuditAction::KeyRevoked {
            daemon_name: daemon.name().into(),
            reason: "crash-restart-detected".into(),
            generation: next_gen,
        });
        self.announce(EventKind::KeyRotationPending {
            daemon_name: daemon.name().into(),
            new_pubkey,
            grace_period_s: KEY_ROTATION_GRACE,
        })
        .await;
    }

    /// The status reply, from the shadow state after reconciling it with
    /// daemon-secrets' authoritative state, with daemon-secrets'
    /// per-profile lock state when it answered.
    async fn status(&mut self) -> EventKind {
        let lock_state = self.reconcile_secrets_state().await;
        let uptime_ms = u64::try_from(self.bus.epoch().elapsed().as_millis()).unwrap_or(u64::MAX);
        EventKind::StatusResponse {
            active_profiles: self.active_profiles.iter().cloned().collect(),
            default_profile: self.default_profile_name.clone(),
            daemon_uptimes_ms: vec![(self.ctx.sender, uptime_ms)],
            locked: self.locked,
            lock_state,
        }
    }

    /// Overwrite the shadow lock and active-profile state with
    /// daemon-secrets' authoritative state, returning its per-profile lock
    /// state. A daemon-secrets that cannot be reached or does not answer
    /// with its state fails closed: locked, no active profiles, and an explicit
    /// per-profile inventory error.
    pub(crate) async fn reconcile_secrets_state(
        &mut self,
    ) -> Result<std::collections::BTreeMap<TrustProfileName, bool>, String> {
        match self
            .confirmed_rpc(EventKind::SecretsStateRequest)
            .await
            .map(|response| response.payload)
        {
            Ok(EventKind::SecretsStateResponse {
                locked,
                active_profiles,
                lock_state,
            }) => {
                let authoritative: HashSet<TrustProfileName> =
                    active_profiles.into_iter().collect();
                if self.locked != locked {
                    tracing::warn!(
                        local_locked = self.locked,
                        authoritative_locked = locked,
                        "reconciliation: lock state discrepancy corrected"
                    );
                }
                if self.active_profiles != authoritative {
                    tracing::warn!(
                        local_profiles = ?self.active_profiles,
                        authoritative_profiles = ?authoritative,
                        "reconciliation: active profiles discrepancy corrected"
                    );
                }
                self.locked = locked;
                self.active_profiles = authoritative;
                lock_state
            }
            Ok(other) => {
                tracing::warn!(payload = ?other, "reconciliation: unexpected response, assuming locked");
                self.fail_closed();
                Err(format!("unexpected secrets state response: {other:?}"))
            }
            Err(e) => {
                tracing::warn!(error = %e, "reconciliation: daemon-secrets did not answer, assuming locked");
                self.fail_closed();
                Err(format!("daemon-secrets did not answer: {e}"))
            }
        }
    }

    /// Assume every vault locked and no profile authorized.
    fn fail_closed(&mut self) {
        self.locked = true;
        self.active_profiles.clear();
    }
}
