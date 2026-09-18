#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::{Component, Path};
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = text.parse::<wisp_core::PairingCode>();
        let safe = wisp_core::sanitize(text);
        let mut components = Path::new(&safe).components();
        assert!(matches!(components.next(), Some(Component::Normal(_))));
        assert!(components.next().is_none());
        assert!(!safe.contains(['/', '\\']));
        assert!(!safe.chars().any(char::is_control));
        assert!(!safe.ends_with([' ', '.']));
        assert!(safe.len() <= 181);
    }
});
