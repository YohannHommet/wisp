//! A public eight-digit discovery identifier followed by four secret words.
//! Only the identifier is advertised. No password-derived value leaves PAKE.

use anyhow::{bail, Result};
use rand::{seq::IndexedRandom, Rng};
use std::{fmt, str::FromStr};

static WORDS: &[&str] = &[
    "amber", "anchor", "aurora", "basil", "beacon", "birch", "bison", "bloom", "borealis",
    "breeze", "bronze", "canyon", "cedar", "cinder", "citrus", "cobalt", "comet", "copper",
    "coral", "cosmos", "crater", "crimson", "crystal", "dawn", "delta", "drift", "dune", "ember",
    "fable", "falcon", "fern", "flint", "flux", "forest", "garnet", "glade", "glow", "granite",
    "harbor", "haven", "horizon", "indigo", "ivory", "jade", "jasper", "juniper", "kelp", "lagoon",
    "lantern", "lichen", "lotus", "lumen", "lunar", "maple", "marble", "meadow", "meteor", "mica",
    "mist", "moss", "nebula", "nectar", "nimbus", "north", "oasis", "ochre", "onyx", "opal",
    "orbit", "otter", "pebble", "petal", "photon", "pine", "pixel", "plasma", "pollen", "prism",
    "pulse", "quartz", "quasar", "raven", "reef", "ripple", "river", "rune", "sable", "saffron",
    "sage", "sapphire", "saturn", "shadow", "shale", "shore", "signal", "silver", "slate", "solar",
    "spark", "spruce", "stellar", "stone", "summit", "tahoe", "thistle", "tidal", "tiger", "topaz",
    "tundra", "umbra", "valley", "velvet", "vesper", "violet", "vortex", "willow", "wisp",
    "zenith", "zephyr", "zircon",
];

/// A single-use pairing code. Debug output deliberately redacts the password.
#[derive(Clone)]
pub struct PairingCode(String);

impl PairingCode {
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut value = format!("{:08}", rng.random_range(0..100_000_000u32));
        for _ in 0..4 {
            value.push('-');
            value.push_str(WORDS.choose(&mut rng).expect("nonempty word list"));
        }
        Self(value)
    }

    pub fn locator(&self) -> &str {
        &self.0[..8]
    }

    /// Expose only when sharing with the receiver or supplying the PAKE password.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingCode")
            .field("locator", &self.locator())
            .finish_non_exhaustive()
    }
}

impl FromStr for PairingCode {
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<Self> {
        let value = input.trim().to_ascii_lowercase();
        let parts: Vec<_> = value.split('-').collect();
        if parts.len() != 5
            || parts[0].len() != 8
            || !parts[0].bytes().all(|b| b.is_ascii_digit())
            || parts[1..].iter().any(|word| !WORDS.contains(word))
        {
            bail!("invalid code: copy the eight-digit identifier and four words from Wisp 0.2 or newer");
        }
        Ok(Self(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_roundtrip_and_keep_secrets_out_of_debug() {
        for _ in 0..100 {
            let code = PairingCode::generate();
            let parsed: PairingCode = code.expose().parse().unwrap();
            assert_eq!(parsed.expose(), code.expose());
            assert!(!format!("{code:?}").contains(code.expose()));
        }
        let unique: std::collections::HashSet<_> = WORDS.iter().collect();
        assert_eq!(unique.len(), WORDS.len());
        assert_eq!(WORDS.len(), 120);
    }

    #[test]
    fn discovery_identifier_is_independent_of_password() {
        let a: PairingCode = "12345678-amber-river-moss-lunar".parse().unwrap();
        let b: PairingCode = "12345678-tiger-saturn-fern-ivory".parse().unwrap();
        assert_eq!(a.locator(), b.locator());
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn normalizes_pasted_codes_and_rejects_old_or_malformed_codes() {
        let parsed: PairingCode = "  12345678-AMBER-RIVER-MOSS-LUNAR\n".parse().unwrap();
        assert_eq!(parsed.expose(), "12345678-amber-river-moss-lunar");
        for value in [
            "",
            "7-tiger-saturn",
            "../../etc/passwd",
            "12345678-amber-river-moss-unknown",
            "12345678-amber-river-moss-lunar-extra",
        ] {
            assert!(value.parse::<PairingCode>().is_err());
        }
    }
}
