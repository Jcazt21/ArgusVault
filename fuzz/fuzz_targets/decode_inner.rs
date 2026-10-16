#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    argus_core::fuzzing::decode_inner(data);
});
