#![forbid(unsafe_code)]
#![allow(missing_docs)]
//! Replays the `exports` fuzz seeds, and short generated inputs, through the
//! same harness that the fuzz target runs.

use std::path::Path;

use rustleaks_ffi::harness::exercise;

#[test]
fn exports_fuzz_seeds_replay() {
    let seeds = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/exports");
    let mut count = 0;
    for entry in std::fs::read_dir(&seeds).expect("seed folder") {
        let path = entry.unwrap().path();
        exercise(&std::fs::read(&path).unwrap());
        count += 1;
    }
    assert!(count >= 3, "{count} seeds");
}

#[test]
fn short_generated_inputs_keep_the_contract() {
    // A small linear congruential generator gives the same inputs on every
    // run.
    let mut state = 0x2545_f491_u32;
    for length in 0..96 {
        let input = (0..length)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                state.to_be_bytes()[0]
            })
            .collect::<Vec<_>>();
        exercise(&input);
    }
}
