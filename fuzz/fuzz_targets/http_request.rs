#![no_main]

use libfuzzer_sys::fuzz_target;
use parsed::http::{Config, parse_request_ref, request_matcher};

mod common;

fuzz_target!(|data: &[u8]| {
    let cfg = Config {
        max_head: 1024,
        max_headers: 16,
        max_body: 4096,
        ..Config::default()
    };
    if let Some((input, Ok(req))) = common::check(|| request_matcher(cfg), data) {
        // the zero-copy parser agrees
        let (zero_copy, _) = parse_request_ref(input, &cfg).expect("zero-copy parse");
        assert_eq!(zero_copy.into_owned(), req);
        // what was parsed can be encoded again
        req.encode().expect("parsed request encodes");
    }
});
