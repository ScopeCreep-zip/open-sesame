//! Key combinations a desktop shortcut is bound to: modifiers and one
//! key, written `alt+space` (`[global] launcher_key`, `sesame
//! setup-keybinding`). Parsed once here; each desktop backend renders it
//! in its own format (COSMIC's shortcut config, the XDG shortcut trigger
//! the `GlobalShortcuts` portal takes).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A shortcut modifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Modifier {
    /// The logo key (Super, Windows, Command).
    Super,
    /// Control.
    Ctrl,
    /// Alt.
    Alt,
    /// Shift.
    Shift,
}

impl Modifier {
    /// Every modifier, in rendering order.
    pub const ALL: [Self; 4] = [Self::Super, Self::Ctrl, Self::Alt, Self::Shift];

    /// The modifier a written name denotes (case-insensitive): `super`
    /// (`mod`, `logo`, `win`), `ctrl` (`control`), `alt`, `shift`.
    fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "super" | "mod" | "logo" | "win" => Some(Self::Super),
            "ctrl" | "control" => Some(Self::Ctrl),
            "alt" => Some(Self::Alt),
            "shift" => Some(Self::Shift),
            _ => None,
        }
    }

    /// The written name: `super`, `ctrl`, `alt`, `shift`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Super => "super",
            Self::Ctrl => "ctrl",
            Self::Alt => "alt",
            Self::Shift => "shift",
        }
    }

    /// The modifier as the XDG shortcuts specification writes it in a
    /// trigger: `LOGO`, `CTRL`, `ALT`, `SHIFT`.
    #[must_use]
    pub const fn xdg_name(self) -> &'static str {
        match self {
            Self::Super => "LOGO",
            Self::Ctrl => "CTRL",
            Self::Alt => "ALT",
            Self::Shift => "SHIFT",
        }
    }
}

/// Modifiers and one key. The key is an XKB keysym name (`space`, `Tab`,
/// `a`), kept as written.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyCombo {
    /// Sorted, without repeats.
    modifiers: Vec<Modifier>,
    key: String,
}

impl KeyCombo {
    /// The modifiers, in rendering order.
    #[must_use]
    pub fn modifiers(&self) -> &[Modifier] {
        &self.modifiers
    }

    /// The key's keysym name.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// This combination with Shift added (the backward variant).
    #[must_use]
    pub fn with_shift(&self) -> Self {
        let mut modifiers = self.modifiers.clone();
        if !modifiers.contains(&Modifier::Shift) {
            modifiers.push(Modifier::Shift);
            modifiers.sort();
        }
        Self {
            modifiers,
            key: self.key.clone(),
        }
    }

    /// The trigger the XDG shortcuts specification defines, as the
    /// `GlobalShortcuts` portal takes it for `preferred_trigger`:
    /// `ALT+space`, `LOGO+SHIFT+Tab`.
    #[must_use]
    pub fn xdg_trigger(&self) -> String {
        self.modifiers
            .iter()
            .map(|m| m.xdg_name())
            .chain(std::iter::once(self.key.as_str()))
            .collect::<Vec<_>>()
            .join("+")
    }
}

impl FromStr for KeyCombo {
    type Err = crate::Error;

    /// Parse `modifier+…+key`. An empty key or modifier, or a modifier
    /// outside [`Modifier`], is an error naming the accepted modifiers.
    fn from_str(combo: &str) -> Result<Self, Self::Err> {
        let invalid = |why: &str| {
            crate::Error::Config(format!(
                "key combo '{combo}' {why}; modifiers: super (mod, logo, win), ctrl (control), alt, shift"
            ))
        };
        let parts: Vec<&str> = combo.split('+').map(str::trim).collect();
        let Some((key, names)) = parts.split_last() else {
            return Err(invalid("is empty"));
        };
        if key.is_empty() {
            return Err(invalid("has no key"));
        }
        let mut modifiers = names
            .iter()
            .map(|name| {
                Modifier::from_name(name)
                    .ok_or_else(|| invalid(&format!("has an unknown modifier '{name}'")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        modifiers.sort();
        modifiers.dedup();
        Ok(Self {
            modifiers,
            key: (*key).to_owned(),
        })
    }
}

impl fmt::Display for KeyCombo {
    /// The written form: `alt+space`, `super+shift+Tab`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for modifier in &self.modifiers {
            write!(f, "{}+", modifier.name())?;
        }
        f.write_str(&self.key)
    }
}

impl Serialize for KeyCombo {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for KeyCombo {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let written = String::deserialize(deserializer)?;
        written.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn combo(written: &str) -> KeyCombo {
        written.parse().unwrap()
    }

    #[test]
    fn combos_parse_to_sorted_modifiers_and_a_key() {
        let c = combo("Shift + win + Tab");
        assert_eq!(c.modifiers(), [Modifier::Super, Modifier::Shift]);
        assert_eq!(c.key(), "Tab");
        assert_eq!(c.to_string(), "super+shift+Tab");
        assert_eq!(combo("alt+alt+space").modifiers(), [Modifier::Alt]);
        assert_eq!(combo("F12").modifiers(), []);
    }

    #[test]
    fn invalid_combos_name_the_accepted_modifiers() {
        for written in ["", "alt+", "hyper+space", "alt++space"] {
            let err = written.parse::<KeyCombo>().unwrap_err().to_string();
            assert!(err.contains("modifiers: super"), "{written}: {err}");
        }
    }

    #[test]
    fn the_xdg_trigger_uses_the_specification_names() {
        assert_eq!(combo("alt+space").xdg_trigger(), "ALT+space");
        assert_eq!(
            combo("ctrl+super+Tab").with_shift().xdg_trigger(),
            "LOGO+CTRL+SHIFT+Tab"
        );
        assert_eq!(combo("shift+a").with_shift(), combo("shift+a"));
    }

    #[test]
    fn combos_serialize_as_their_written_form() {
        #[derive(Serialize, Deserialize)]
        struct Holder {
            key: KeyCombo,
        }
        let holder: Holder = toml::from_str("key = \"Alt+space\"").unwrap();
        assert_eq!(holder.key, combo("alt+space"));
        assert_eq!(
            toml::to_string(&holder).unwrap().trim(),
            "key = \"alt+space\""
        );
        assert!(toml::from_str::<Holder>("key = \"meta+x\"").is_err());
    }
}
