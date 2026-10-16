#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    argus_core::fuzzing::parse_file(data);
});
