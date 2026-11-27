//! What daemon-profile derives from the configuration: the activatable
//! profile names and the context engine. Profile identity is
//! `ProfileId::of_profile`.

use core_profile::ContextEngine;
use core_profile::context::{ActivationRule, ProfileActivation, RuleCombinator, RuleTrigger};
use core_types::{ProfileId, TrustProfileName};

/// The configured profile names that are valid `TrustProfileName`s. An
/// invalid name is logged and excluded; it cannot be activated.
pub(crate) fn profile_names(config: &core_config::Config) -> Vec<TrustProfileName> {
    config
        .profiles
        .keys()
        .filter_map(|name| match TrustProfileName::try_from(name.as_str()) {
            Ok(profile) => Some(profile),
            Err(e) => {
                tracing::error!(profile = %name, error = %e, "invalid profile name in config, excluded");
                None
            }
        })
        .collect()
}

/// The name among `names` whose installation-scoped identity is `id`.
pub(crate) fn profile_named<'a>(
    names: &'a [TrustProfileName],
    install_ns: &uuid::Uuid,
    id: ProfileId,
) -> Option<&'a TrustProfileName> {
    names
        .iter()
        .find(|name| ProfileId::of_profile(install_ns, name.as_ref()) == id)
}

/// The context engine of `config`: each profile's activation rules, the
/// configured default profile as its default.
pub(crate) fn context_engine(
    config: &core_config::Config,
    install_ns: &uuid::Uuid,
) -> ContextEngine {
    let default_id = ProfileId::of_profile(install_ns, config.global.default_profile.as_ref());
    ContextEngine::new(activation_rules(config, install_ns, default_id), default_id)
}

/// Each profile's Wi-Fi, USB, time-window, and security-key triggers, its
/// position in the configuration as its priority; `default_id` alone when
/// the configuration defines no profiles.
fn activation_rules(
    config: &core_config::Config,
    install_ns: &uuid::Uuid,
    default_id: ProfileId,
) -> Vec<ProfileActivation> {
    let activation = |profile_id, rules, priority| ProfileActivation {
        profile_id,
        rules,
        combinator: RuleCombinator::Any,
        priority,
        switch_delay_ms: 0,
    };
    let activations: Vec<ProfileActivation> = config
        .profiles
        .iter()
        .zip(0u32..)
        .map(|((name, profile), priority)| {
            let act = &profile.activation;
            let rule = |trigger, value: &String| ActivationRule {
                trigger,
                value: value.clone(),
            };
            let security_key = String::from("present");
            let rules = act
                .wifi_ssids
                .iter()
                .map(|ssid| rule(RuleTrigger::Ssid, ssid))
                .chain(
                    act.usb_devices
                        .iter()
                        .map(|usb| rule(RuleTrigger::UsbDevice, usb)),
                )
                .chain(
                    act.time_rules
                        .iter()
                        .map(|time| rule(RuleTrigger::TimeWindow, time)),
                )
                .chain(
                    act.require_security_key
                        .then(|| rule(RuleTrigger::HardwareKey, &security_key)),
                )
                .collect();
            activation(ProfileId::of_profile(install_ns, name), rules, priority)
        })
        .collect();
    if activations.is_empty() {
        vec![activation(default_id, vec![], 0)]
    } else {
        activations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns() -> uuid::Uuid {
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, b"installation")
    }

    #[test]
    fn activation_rules_follow_each_profile_in_order() {
        let config: core_config::Config = toml::from_str(
            "[global]\ndefault_profile = \"home\"\n\
             [profiles.home]\n\
             [profiles.work.activation]\nwifi_ssids = [\"corp\"]\nrequire_security_key = true\n",
        )
        .unwrap();
        let default_id = ProfileId::of_profile(&ns(), "home");
        let rules = activation_rules(&config, &ns(), default_id);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].profile_id, default_id);
        assert!(rules[0].rules.is_empty());
        assert_eq!(rules[1].profile_id, ProfileId::of_profile(&ns(), "work"));
        assert_eq!(rules[1].priority, 1);
        let triggers: Vec<RuleTrigger> = rules[1].rules.iter().map(|r| r.trigger).collect();
        assert_eq!(triggers, [RuleTrigger::Ssid, RuleTrigger::HardwareKey]);
        assert_eq!(context_engine(&config, &ns()).default_profile(), default_id);
    }

    #[test]
    fn a_profile_id_names_its_configured_profile() {
        let names = [
            TrustProfileName::try_from("home").unwrap(),
            TrustProfileName::try_from("work").unwrap(),
        ];
        let work = ProfileId::of_profile(&ns(), "work");
        assert_eq!(profile_named(&names, &ns(), work), Some(&names[1]));
        let other = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, b"other");
        assert_eq!(
            profile_named(&names, &other, work),
            None,
            "another installation's identity names no profile here"
        );
    }

    #[test]
    fn invalid_profile_names_are_excluded() {
        let config: core_config::Config =
            toml::from_str("[profiles.work]\n[profiles.\"bad name\"]\n").unwrap();
        assert_eq!(
            profile_names(&config),
            [TrustProfileName::try_from("work").unwrap()]
        );
    }

    #[test]
    fn no_profiles_yields_the_default_alone() {
        let config = core_config::Config::default();
        let default_id = ProfileId::of_profile(&ns(), config.global.default_profile.as_ref());
        let rules = activation_rules(&config, &ns(), default_id);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].profile_id, default_id);
    }
}
