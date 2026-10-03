#![no_main]

use libfuzzer_sys::fuzz_target;
use parsed::http::{Config, parse_response_ref, response_matcher};

mod common;

fuzz_target!(|data: &[u8]| {
    let Some((&method, data)) = data.split_first() else {
        return;
    };
    let method = ["GET", "HEAD", "CONNECT", "POST"][method as usize % 4];
    let cfg = Config {
        max_head: 1024,
        max_headers: 16,
        max_body: 4096,
        ..Config::default()
    };
    if let Some((input, Ok(res))) = common::check(|| response_matcher(cfg, method), data) {
        let (zero_copy, _) =
            parse_response_ref(input, method, true, &cfg).expect("zero-copy parse");
        assert_eq!(zero_copy.into_owned(), res);
    }
});
