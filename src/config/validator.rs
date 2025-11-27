//! Configuration validation
//!
//! Validates configuration and reports issues.

use crate::config::Config;
use std::collections::HashMap;

/// Validation issue severity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Warning - configuration is valid but may have issues
    Warning,
    /// Error - configuration is invalid and must be fixed
    Error,
}

/// A configuration validation issue
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    /// Severity level of the issue
    pub severity: Severity,
    /// Human-readable description of the issue
    pub message: String,
}

impl ValidationIssue {
    /// Create a new warning issue
    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
        }
    }

    /// Create a new error issue
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
        }
    }
}

/// Configuration validator
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate configuration and return any issues
    pub fn validate(config: &Config) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        Self::validate_settings(&config.settings, &mut issues);
        Self::validate_keys(&config.keys, &mut issues);

        issues
    }

    /// Returns true if configuration is valid (no errors, warnings allowed).
    pub fn is_valid(config: &Config) -> bool {
        Self::validate(config)
            .iter()
            .all(|i| i.severity != Severity::Error)
    }

    fn validate_settings(settings: &crate::config::Settings, issues: &mut Vec<ValidationIssue>) {
        if settings.activation_delay > 5000 {
            issues.push(ValidationIssue::warning(
                "activation_delay > 5s is very slow",
            ));
        }

        if settings.border_width < 0.0 {
            issues.push(ValidationIssue::error("border_width cannot be negative"));
        }

        if settings.border_width > 100.0 {
            issues.push(ValidationIssue::warning(
                "border_width > 100px is unusually large",
            ));
        }
    }

    fn validate_keys(
        keys: &HashMap<String, crate::config::KeyBinding>,
        issues: &mut Vec<ValidationIssue>,
    ) {
        // Validates key names and bindings
        for (key, binding) in keys {
            if key.is_empty() {
                issues.push(ValidationIssue::error("Empty key name found"));
            }
            if key.len() > 1 {
                issues.push(ValidationIssue::warning(format!(
                    "Key '{}' should be a single character",
                    key
                )));
            }
            if binding.apps.is_empty() && binding.launch.is_none() {
                issues.push(ValidationIssue::warning(format!(
                    "Key '{}' has no apps and no launch command",
                    key
                )));
            }
        }

        // Detects duplicate app_ids across different keys
        let mut app_to_key: HashMap<String, String> = HashMap::new();
        for (key, binding) in keys {
            for app in &binding.apps {
                let app_lower = app.to_lowercase();
                if let Some(existing_key) = app_to_key.get(&app_lower) {
                    if existing_key != key {
                        issues.push(ValidationIssue::warning(format!(
                            "App '{}' is mapped to both '{}' and '{}'",
                            app, existing_key, key
                        )));
                    }
                } else {
                    app_to_key.insert(app_lower, key.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_default_config() {
        let config = Config::default();
        let issues = ConfigValidator::validate(&config);
        assert!(issues.is_empty(), "Default config should have no issues");
        assert!(ConfigValidator::is_valid(&config));
    }

    #[test]
    fn test_validate_slow_activation_delay() {
        let mut config = Config::default();
        config.settings.activation_delay = 10000;
        let issues = ConfigValidator::validate(&config);
        assert!(!issues.is_empty());
        assert_eq!(issues[0].severity, Severity::Warning);
    }

    #[test]
    fn test_validate_negative_border_width() {
        let mut config = Config::default();
        config.settings.border_width = -1.0;
        let issues = ConfigValidator::validate(&config);
        assert!(!issues.is_empty());
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(!ConfigValidator::is_valid(&config));
    }
}
