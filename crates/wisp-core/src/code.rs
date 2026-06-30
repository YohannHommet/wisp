//! Short, human-friendly pairing codes: `<number>-<word>-<word>`.
//!
//! In Phase 1 the code identifies a transfer advertised over mDNS. In Phase 2
//! it becomes the password of a PAKE (SPAKE2), so the wordlist is chosen to be
//! short, unambiguous, and easy to read aloud.

use rand::seq::IndexedRandom;

/// Curated, evocative, low-confusion wordlist (light / nature / space themed).
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

/// Generate a fresh pairing code, e.g. `7-tiger-saturn`.
pub fn generate() -> String {
    let mut rng = rand::rng();
    let n: u16 = rand::random_range(0..1000);
    let w1 = WORDS.choose(&mut rng).copied().unwrap_or("wisp");
    let mut w2 = WORDS.choose(&mut rng).copied().unwrap_or("spark");
    if w2 == w1 {
        w2 = WORDS.choose(&mut rng).copied().unwrap_or("spark");
    }
    format!("{n}-{w1}-{w2}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_has_three_parts() {
        let c = generate();
        let parts: Vec<&str> = c.split('-').collect();
        assert_eq!(
            parts.len(),
            3,
            "code `{c}` should have 3 dash-separated parts"
        );
        assert!(
            parts[0].parse::<u16>().is_ok(),
            "first part should be a number"
        );
    }

    #[test]
    fn codes_vary() {
        // Extremely unlikely to collide across 50 draws if entropy is sane.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            seen.insert(generate());
        }
        assert!(
            seen.len() > 40,
            "expected mostly-unique codes, got {}",
            seen.len()
        );
    }
}
