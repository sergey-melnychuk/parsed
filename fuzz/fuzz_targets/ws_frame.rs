#![no_main]

use libfuzzer_sys::fuzz_target;
use parsed::ws::{FrameConfig, frame_matcher, parse_frame_ref};

mod common;

fuzz_target!(|data: &[u8]| {
    let cfg = FrameConfig {
        max_payload: 1 << 16,
        ..FrameConfig::default()
    };
    if let Some((input, Ok(frame))) = common::check(|| frame_matcher(cfg), data) {
        let (zero_copy, _) = parse_frame_ref(input, &cfg).expect("zero-copy parse");
        assert_eq!(zero_copy.into_owned(), frame);
        assert_eq!(
            frame.encode().expect("parsed frame encodes").len() <= input.len(),
            true
        );
    }
});
