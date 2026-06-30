#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz metadata parsing and validation
    if let Ok(json_str) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<serde_json::Value>(json_str);
    }

    // 2. Fuzz code commitment index boundary safety
    if let Ok(code_str) = std::str::from_utf8(data) {
        let _ = wisp_core::code_commitment(code_str);
    }

    // 3. Fuzz path sanitizer for directory traversal escapes
    if let Ok(raw_name) = std::str::from_utf8(data) {
        let sanitized = wisp_core::sanitize(raw_name);
        
        let base = Path::new("/base/dir");
        let combined = base.join(&sanitized);
        
        // Assert that the sanitized filename is strictly confined to the base destination directory
        assert!(
            combined.starts_with(base),
            "Directory traversal escape detected! Input: {:?}, Sanitized: {:?}, Combined: {:?}",
            raw_name,
            sanitized,
            combined
        );
    }
});
