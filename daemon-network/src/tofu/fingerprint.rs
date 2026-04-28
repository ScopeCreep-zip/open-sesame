//! Public key fingerprint encoding for human-readable display.
//!
//! PGP word list encoding produces two words per byte (even/odd position),
//! making fingerprints speakable for out-of-band verification over voice.
//! Numeric SAS produces a 6-digit code for quick visual confirmation.
//!
//! Hex display is supported but NOT recommended for user-facing UI per
//! Dechand et al. USENIX Security 2016 (partial-preimage vulnerability).

/// PGP even-position words (byte value → word at even index).
#[allow(dead_code)] // Used by CLI (sesame network peers) and tests; not called from daemon binary.
const PGP_EVEN: [&str; 256] = [
    "aardvark", "absurd", "accrue", "acme", "adrift", "adult", "afflict", "ahead",
    "aimless", "algol", "allow", "alone", "ammo", "ancient", "apple", "artist",
    "assume", "athens", "atlas", "aztec", "baboon", "backfield", "backward", "banjo",
    "beaming", "bedlamp", "beehive", "beeswax", "befriend", "belfast", "berserk", "billiard",
    "bison", "blackjack", "blockade", "blowtorch", "bluebird", "bombast", "bookshelf", "brackish",
    "breadline", "breakup", "brickyard", "briefcase", "burbank", "button", "buzzard", "cement",
    "chairlift", "chatter", "checkup", "chessman", "chisel", "choking", "chopper", "christmas",
    "clamshell", "classic", "cleanup", "clockwork", "cobra", "commence", "concert", "cowbell",
    "crackdown", "cranky", "crowfoot", "crucial", "crumpled", "crusade", "cubic", "dashboard",
    "deadbolt", "deckhand", "dogsled", "dragnet", "drainage", "dreadful", "drifter", "dropout",
    "drumbeat", "drunken", "dupont", "dwelling", "eating", "edict", "egghead", "eightball",
    "endorse", "endow", "enlist", "erase", "escape", "exceed", "eyeglass", "eyetooth",
    "facet", "fairway", "fallout", "flagpole", "flatfoot", "flytrap", "fracture", "framework",
    "freedom", "frighten", "gazelle", "geiger", "glitter", "glucose", "goggles", "goldfish",
    "gremlin", "guidance", "hamlet", "highchair", "hockey", "indoors", "indulge", "inverse",
    "involve", "island", "jawbone", "keyboard", "kickoff", "kiwi", "klaxon", "locale",
    "lockup", "merit", "minnow", "miser", "mohawk", "mural", "music", "necklace",
    "neptune", "newborn", "nightbird", "oakland", "obtuse", "offload", "optic", "orca",
    "payday", "peachy", "pheasant", "physique", "playhouse", "pluto", "preclude", "prefer",
    "preshrunk", "printer", "prowler", "pupil", "puppy", "python", "quadrant", "quiver",
    "quota", "ragtime", "ratchet", "rebirth", "reform", "regain", "reindeer", "rematch",
    "repay", "retouch", "revenge", "reward", "rhythm", "ribcage", "ringbolt", "robust",
    "rocker", "ruffled", "sailboat", "sawdust", "scallion", "scenic", "scorecard", "scotland",
    "seabird", "select", "sentence", "shadow", "shamrock", "showgirl", "skullcap", "skydive",
    "slingshot", "slowdown", "snapline", "snapshot", "snowcap", "snowslide", "solo", "southward",
    "soybean", "spaniel", "spearhead", "spellbound", "spheroid", "spigot", "spindle", "spyglass",
    "stagehand", "stagnate", "stairway", "standard", "stapler", "steamship", "sterling", "stockman",
    "stopwatch", "stormy", "sugar", "surmount", "suspense", "sweatband", "swelter", "tactics",
    "talon", "tapeworm", "tempest", "tiger", "tissue", "tonic", "topmost", "tracker",
    "transit", "trauma", "treadmill", "trojan", "trouble", "tumor", "tunnel", "tycoon",
    "uncut", "unearth", "unify", "unkind", "until", "upward", "urban", "vengeance",
    "verdict", "viking", "viper", "vocal", "vulture", "waffle", "wallet", "watchword",
];

/// PGP odd-position words (byte value → word at odd index).
#[allow(dead_code)] // Used by CLI (sesame network peers) and tests; not called from daemon binary.
const PGP_ODD: [&str; 256] = [
    "adroitness", "adviser", "aftermath", "aggregate", "alkali", "almighty", "amulet", "amusement",
    "antenna", "applicant", "apollo", "armistice", "article", "asteroid", "atlantic", "atmosphere",
    "autopsy", "babylon", "backwater", "barbecue", "barometer", "bathrobe", "beaverton", "bedrock",
    "befuddle", "bellwether", "benchmark", "bikini", "blemish", "bodyguard", "bookseller", "borderline",
    "bottomless", "bradbury", "bravado", "brazilian", "breakaway", "burlington", "businessman", "butterfat",
    "camelot", "candidate", "cannonball", "capricorn", "caravan", "caretaker", "celebrate", "cellulose",
    "certify", "chambermaid", "cherokee", "chicago", "clergyman", "coherence", "combustion", "commando",
    "company", "component", "condition", "consensus", "converge", "corporate", "corrosion", "councilman",
    "crossover", "crucifix", "cumbersome", "customer", "dakota", "decadence", "december", "decimal",
    "designing", "detector", "diploma", "disaster", "disbelief", "disruptive", "distortion", "document",
    "embezzle", "enchanting", "enrollment", "enterprise", "equation", "equipment", "escapade", "ethernet",
    "eureka", "evidence", "examinee", "exodus", "fascinate", "filament", "finicky", "forever",
    "fortitude", "frequency", "gadgetry", "galveston", "getaway", "glossary", "goliath", "graduate",
    "gravity", "guitarist", "hamburger", "hamilton", "handiwork", "hazardous", "headwaters", "hemisphere",
    "hesitate", "hideaway", "holiness", "hurricane", "hydraulic", "hypnotic", "impetus", "inception",
    "indecent", "infancy", "inferno", "informant", "insincere", "insurgent", "integrate", "intention",
    "inventive", "istanbul", "Jamaica", "Jupiter", "leprosy", "letterhead", "liberty", "maritime",
    "matchmaker", "maverick", "medusa", "megaton", "microscope", "microwave", "midsummer", "millionaire",
    "miracle", "misnomer", "molasses", "molecule", "montana", "monument", "mosquito", "narrative",
    "nebula", "newsletter", "norwegian", "october", "ohio", "onlooker", "opulent", "orlando",
    "outfielder", "pacific", "pandemic", "pandora", "paperweight", "paragon", "paragraph", "paramount",
    "passenger", "pedigree", "pegasus", "penetrate", "perceptive", "performance", "pharmacy", "pineapple",
    "playmate", "plywood", "pneumonia", "politician", "pompadour", "populace", "portfolio", "potato",
    "processor", "prodigy", "professor", "propellant", "prosper", "publisher", "pugnacious", "pyramid",
    "quantity", "racketeer", "rebellion", "recipe", "renegade", "resistor", "retirement", "retrieval",
    "retrospect", "revenue", "revival", "revolver", "sandalwood", "sardonic", "saturday", "savagery",
    "scavenger", "sensation", "september", "sequence", "shanghai", "simulated", "singular", "skirmish",
    "sociable", "souvenir", "specialist", "speculate", "stethoscope", "stupendous", "subscriber", "subterfuge",
    "suggestion", "supernova", "surrender", "suspicious", "sympathy", "tambourine", "telephone", "therapist",
    "tobacco", "tolerance", "tomorrow", "torpedo", "tradition", "travesty", "trombonist", "truncated",
    "typewriter", "ultimate", "undaunted", "underfoot", "unicorn", "uninstall", "universe", "unravel",
    "upcoming", "vacancy", "vagabond", "vertigo", "virginia", "visitor", "vocalist", "voyager",
];

/// Encode a public key fingerprint as PGP word list words.
///
/// Each byte maps to a word: even-indexed bytes use `PGP_EVEN`, odd-indexed
/// use `PGP_ODD`. Returns space-separated lowercase words.
#[must_use]
#[allow(dead_code)] // Used by CLI and tests.
pub fn pgp_words(key: &[u8]) -> String {
    let mut words = Vec::with_capacity(key.len());
    for (i, &byte) in key.iter().enumerate() {
        if i % 2 == 0 {
            words.push(PGP_EVEN[byte as usize]);
        } else {
            words.push(PGP_ODD[byte as usize]);
        }
    }
    words.join(" ")
}

/// Encode a public key as a colon-separated hex fingerprint.
#[must_use]
#[allow(dead_code)] // Used by CLI and tests.
pub fn hex_fingerprint(key: &[u8]) -> String {
    key.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Compute a 6-digit numeric Short Authentication String from two public keys.
///
/// Both parties compute `BLAKE3(sort(key_a, key_b))` and take the first 4 bytes
/// as a big-endian u32, then `% 1_000_000` for a 6-digit code. Canonical ordering
/// ensures both sides produce the same code regardless of who is initiator.
#[must_use]
#[allow(dead_code)] // Used by CLI and tests.
pub fn numeric_sas(key_a: &[u8; 32], key_b: &[u8; 32]) -> String {
    let (first, second) = if key_a <= key_b {
        (key_a, key_b)
    } else {
        (key_b, key_a)
    };
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(first);
    input.extend_from_slice(second);
    let hash = blake3::hash(&input);
    let bytes = hash.as_bytes();
    let n = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    format!("{:06}", n % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pgp_words_produces_correct_count() {
        let key = [0u8; 32];
        let words = pgp_words(&key);
        assert_eq!(words.split(' ').count(), 32);
    }

    #[test]
    fn pgp_words_even_odd_differ() {
        // Byte 0x00 at even position vs odd position should produce different words.
        let even = PGP_EVEN[0];
        let odd = PGP_ODD[0];
        assert_ne!(even, odd);
    }

    #[test]
    fn pgp_words_deterministic() {
        let key = [0xAB; 32];
        assert_eq!(pgp_words(&key), pgp_words(&key));
    }

    #[test]
    fn hex_fingerprint_format() {
        let key = [0xAB, 0xCD, 0xEF];
        assert_eq!(hex_fingerprint(&key), "ab:cd:ef");
    }

    #[test]
    fn numeric_sas_six_digits() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        let sas = numeric_sas(&a, &b);
        assert_eq!(sas.len(), 6);
        assert!(sas.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn numeric_sas_symmetric() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        assert_eq!(numeric_sas(&a, &b), numeric_sas(&b, &a));
    }

    #[test]
    fn numeric_sas_different_keys_different_codes() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        let c = [0x03; 32];
        // Very likely different (1 in 1M chance of collision).
        assert_ne!(numeric_sas(&a, &b), numeric_sas(&a, &c));
    }

    #[test]
    fn pgp_word_tables_complete() {
        // Both tables must have exactly 256 non-empty entries.
        assert_eq!(PGP_EVEN.len(), 256);
        assert_eq!(PGP_ODD.len(), 256);
        for (i, w) in PGP_EVEN.iter().enumerate() {
            assert!(!w.is_empty(), "PGP_EVEN[{i}] is empty");
        }
        for (i, w) in PGP_ODD.iter().enumerate() {
            assert!(!w.is_empty(), "PGP_ODD[{i}] is empty");
        }
    }
}
