//! Context engine: evaluates activation rules against system signals.
//!
//! Runs inside daemon-profile. When a `ContextSignal` arrives (SSID change,
//! app focus, USB attach, etc.), the engine evaluates all profile activation
//! rules and determines which profile should be the default for new unscoped
//! launches. Changing the default does NOT deactivate other active profiles.

use core_types::ProfileId;

use crate::ContextSignal;

/// Activation rule for a profile. When all (or any, per combinator) conditions
/// match, the profile becomes a candidate for activation.
#[derive(Debug, Clone)]
pub struct ActivationRule {
    /// The signal type this rule matches against.
    pub trigger: RuleTrigger,
    /// The value to match (e.g., SSID name, app ID, USB vendor:product).
    pub value: String,
}

/// What kind of signal triggers this rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleTrigger {
    Ssid,
    AppFocus,
    UsbDevice,
    HardwareKey,
    TimeWindow,
    Geolocation,
}

/// How multiple rules combine for a single profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleCombinator {
    /// All rules must match.
    All,
    /// Any single rule matching is sufficient.
    Any,
}

/// A profile's activation configuration.
#[derive(Debug, Clone)]
pub struct ProfileActivation {
    pub profile_id: ProfileId,
    pub rules: Vec<ActivationRule>,
    pub combinator: RuleCombinator,
    /// Higher priority wins when multiple profiles match.
    pub priority: u32,
    /// Minimum milliseconds between default-profile changes to this profile (debounce).
    pub switch_delay_ms: u64,
}

/// Evaluates context signals against profile activation rules.
pub struct ContextEngine {
    profiles: Vec<ProfileActivation>,
    default_profile: ProfileId,
    last_switch: std::collections::HashMap<ProfileId, tokio::time::Instant>,
}

impl ContextEngine {
    #[must_use]
    pub fn new(profiles: Vec<ProfileActivation>, initial: ProfileId) -> Self {
        Self {
            profiles,
            default_profile: initial,
            last_switch: std::collections::HashMap::new(),
        }
    }

    /// Evaluate a signal and return a new default profile, if the signal
    /// triggers a change.
    ///
    /// Returns `None` if the default remains unchanged (current default still
    /// wins, no profile matches, or debounce prevents change).
    pub fn evaluate(&mut self, signal: &ContextSignal) -> Option<ProfileId> {
        let mut candidates: Vec<&ProfileActivation> = self
            .profiles
            .iter()
            .filter(|p| Self::matches_profile(p, signal))
            .collect();

        // Sort by priority descending (highest wins)
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

        let winner = candidates.first()?;

        // Already on this profile
        if winner.profile_id == self.default_profile {
            return None;
        }

        // Debounce check
        if let Some(last) = self.last_switch.get(&winner.profile_id)
            && last.elapsed().as_millis() < u128::from(winner.switch_delay_ms)
        {
            tracing::debug!(
                profile = %winner.profile_id,
                delay_ms = winner.switch_delay_ms,
                "default profile change debounced"
            );
            return None;
        }

        let target = winner.profile_id;
        self.last_switch.insert(target, tokio::time::Instant::now());
        self.default_profile = target;
        Some(target)
    }

    /// The current default profile for new unscoped launches.
    #[must_use]
    pub fn default_profile(&self) -> ProfileId {
        self.default_profile
    }

    fn matches_profile(profile: &ProfileActivation, signal: &ContextSignal) -> bool {
        let rule_matches: Vec<bool> = profile
            .rules
            .iter()
            .map(|rule| Self::rule_matches(rule, signal))
            .collect();

        match profile.combinator {
            RuleCombinator::All => rule_matches.iter().all(|&m| m),
            RuleCombinator::Any => rule_matches.iter().any(|&m| m),
        }
    }

    fn rule_matches(rule: &ActivationRule, signal: &ContextSignal) -> bool {
        match (&rule.trigger, signal) {
            (RuleTrigger::Ssid, ContextSignal::SsidChanged(ssid)) => rule.value == *ssid,
            (RuleTrigger::AppFocus, ContextSignal::AppFocused(app)) => {
                rule.value == app.to_string()
            }
            (RuleTrigger::UsbDevice, ContextSignal::UsbDeviceAttached(dev)) => rule.value == *dev,
            (RuleTrigger::HardwareKey, ContextSignal::HardwareKeyPresent(key)) => {
                rule.value == *key
            }
            (RuleTrigger::TimeWindow, ContextSignal::TimeWindowEntered(expr)) => {
                rule.value == *expr
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn pid(n: u128) -> ProfileId {
        ProfileId::from_uuid(Uuid::from_u128(n))
    }

    fn work_profile() -> ProfileActivation {
        ProfileActivation {
            profile_id: pid(1),
            rules: vec![ActivationRule {
                trigger: RuleTrigger::Ssid,
                value: "CorpWiFi".into(),
            }],
            combinator: RuleCombinator::Any,
            priority: 10,
            switch_delay_ms: 0,
        }
    }

    fn personal_profile() -> ProfileActivation {
        ProfileActivation {
            profile_id: pid(2),
            rules: vec![ActivationRule {
                trigger: RuleTrigger::Ssid,
                value: "HomeWiFi".into(),
            }],
            combinator: RuleCombinator::Any,
            priority: 5,
            switch_delay_ms: 0,
        }
    }

    #[test]
    fn ssid_triggers_default_profile_change() {
        let mut engine = ContextEngine::new(vec![work_profile(), personal_profile()], pid(2));
        let result = engine.evaluate(&ContextSignal::SsidChanged("CorpWiFi".into()));
        assert_eq!(result, Some(pid(1)));
    }

    #[test]
    fn no_switch_when_already_active() {
        let mut engine = ContextEngine::new(vec![work_profile()], pid(1));
        let result = engine.evaluate(&ContextSignal::SsidChanged("CorpWiFi".into()));
        assert_eq!(result, None);
    }

    #[test]
    fn no_match_returns_none() {
        let mut engine = ContextEngine::new(vec![work_profile()], pid(2));
        let result = engine.evaluate(&ContextSignal::SsidChanged("UnknownWiFi".into()));
        assert_eq!(result, None);
    }

    #[test]
    fn higher_priority_wins() {
        let mut high = work_profile();
        high.priority = 100;
        high.rules = vec![ActivationRule {
            trigger: RuleTrigger::Ssid,
            value: "SharedWiFi".into(),
        }];

        let mut low = personal_profile();
        low.rules = vec![ActivationRule {
            trigger: RuleTrigger::Ssid,
            value: "SharedWiFi".into(),
        }];

        let mut engine = ContextEngine::new(vec![low, high], pid(99));
        let result = engine.evaluate(&ContextSignal::SsidChanged("SharedWiFi".into()));
        assert_eq!(result, Some(pid(1))); // high priority = work profile
    }

    #[test]
    fn all_combinator_requires_all_rules() {
        let profile = ProfileActivation {
            profile_id: pid(1),
            rules: vec![
                ActivationRule {
                    trigger: RuleTrigger::Ssid,
                    value: "CorpWiFi".into(),
                },
                ActivationRule {
                    trigger: RuleTrigger::UsbDevice,
                    value: "yubikey:5".into(),
                },
            ],
            combinator: RuleCombinator::All,
            priority: 10,
            switch_delay_ms: 0,
        };

        let mut engine = ContextEngine::new(vec![profile], pid(2));
        // Only SSID matches — should NOT switch with All combinator
        let result = engine.evaluate(&ContextSignal::SsidChanged("CorpWiFi".into()));
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn debounce_prevents_rapid_switch() {
        let mut profile = work_profile();
        profile.switch_delay_ms = 5000; // 5 seconds

        let mut engine = ContextEngine::new(vec![profile, personal_profile()], pid(2));

        // First switch succeeds
        let r1 = engine.evaluate(&ContextSignal::SsidChanged("CorpWiFi".into()));
        assert_eq!(r1, Some(pid(1)));

        // Switch away
        engine.default_profile = pid(2);

        // Immediate re-switch debounced
        let r2 = engine.evaluate(&ContextSignal::SsidChanged("CorpWiFi".into()));
        assert_eq!(r2, None);
    }
}
