use std::collections::BTreeMap;
use std::convert::Infallible;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::regex::GoRegex;

use super::{NONE, piece_end, rank, token_count};

fn count(secret: &[u8]) -> Option<usize> {
    token_count(secret, &mut || Ok::<(), Infallible>(())).unwrap()
}

fn vocabulary() -> BTreeMap<Vec<u8>, u32> {
    include_str!("../../../../data/cl100k_base.tiktoken")
        .lines()
        .map(|line| {
            let (token, rank) = line.split_once(' ').unwrap();
            (STANDARD.decode(token).unwrap(), rank.parse().unwrap())
        })
        .collect()
}

// This reference uses the complete source vocabulary and recomputes all pair
// ranks after each merge. It shares neither reduced data nor cached ranks with
// production. Stable (rank, position) ordering implements the source tie rule.
fn reference(secret: &[u8], vocabulary: &BTreeMap<Vec<u8>, u32>, splitter: &GoRegex) -> usize {
    splitter
        .find_all(secret)
        .into_iter()
        .map(|span| {
            let piece = &secret[span.start..span.end];
            if vocabulary.contains_key(piece) {
                return 1;
            }
            let mut parts = piece.iter().map(|byte| vec![*byte]).collect::<Vec<_>>();
            while let Some((_, position)) = parts
                .windows(2)
                .enumerate()
                .filter_map(|(index, pair)| {
                    let joined = [pair[0].as_slice(), pair[1].as_slice()].concat();
                    vocabulary.get(&joined).map(|rank| (*rank, index))
                })
                .min()
            {
                let right = parts.remove(position + 1);
                parts[position].extend(right);
            }
            parts.len()
        })
        .sum()
}

#[test]
fn independent_integer_boundary_is_24_reject_and_25_accept() {
    // vck -> v,ck (rank ck=377 < vc=7513); each remaining regex piece is
    // a direct whole-vocabulary hit. These counts were specified before code.
    for (secret, expected) in [
        (
            b"vck_01234567890123456789012345678901234567890123456789012345",
            22,
        ),
        (
            b"vck_0123456789012a456789012345678901234567890123456789012345",
            23,
        ),
        (
            b"vck_0123456789012a45678901234567B901234567890123456789012345",
            24,
        ),
        (
            b"vck_0123456789012a45678901234567B90123456789012d456789012345",
            25,
        ),
        (
            b"vck_0123456789012a45678901234567B90123456789012d45678901E345",
            26,
        ),
    ] {
        assert_eq!(count(secret), Some(expected));
        assert_eq!(
            super::accepts(secret, &mut || Ok::<(), Infallible>(())).unwrap(),
            expected > 24
        );
    }
}

#[test]
fn every_byte_at_every_position_obeys_the_fixed_ascii_domain() {
    let mut secret = [b'A'; 60];
    secret[..4].copy_from_slice(b"vck_");
    for position in 0..60 {
        let original = secret[position];
        for byte in 0..=255_u8 {
            secret[position] = byte;
            let valid = match position {
                0 => byte.eq_ignore_ascii_case(&b'v'),
                1 => byte.eq_ignore_ascii_case(&b'c'),
                2 => byte.eq_ignore_ascii_case(&b'k'),
                3 => byte == b'_',
                _ => byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'),
            };
            assert_eq!(
                count(&secret).is_some(),
                valid,
                "position {position}, byte {byte}"
            );
        }
        secret[position] = original;
    }
    assert_eq!(count(&secret[..59]), None);
    assert_eq!(count(&[secret.as_slice(), b"A"].concat()), None);
}

#[test]
fn ordered_splitter_keeps_punctuation_runs_and_three_digit_groups() {
    for (input, expected) in [
        ("vck_Ab12", vec!["vck", "_Ab", "12"]),
        ("vck__Ab12", vec!["vck", "__", "Ab", "12"]),
        ("vck_-Ab12", vec!["vck", "_-", "Ab", "12"]),
        ("vck_Ab-CD1234", vec!["vck", "_Ab", "-CD", "123", "4"]),
    ] {
        let mut position = 0;
        let mut actual = Vec::new();
        while position < input.len() {
            let end = piece_end(input.as_bytes(), position);
            actual.push(&input[position..end]);
            position = end;
        }
        assert_eq!(actual, expected);
    }
}

#[test]
fn reduced_data_matches_every_reachable_multibyte_source_entry() {
    let source = vocabulary();
    assert_eq!(source.len(), 100_256);
    let domain = GoRegex::compile(
        r"\A(?:[A-Za-z]{1,56}|_[A-Za-z]{1,56}|-[A-Za-z]{1,54}|[0-9]{1,3}|[-_]{1,56}|_[-_]{56})\z",
    )
    .unwrap();
    let mut relevant = 0;
    for (token, &source_rank) in &source {
        if token.len() > 1 && !token.iter().all(u8::is_ascii_digit) && domain.is_match(token) {
            relevant += 1;
            assert_eq!(rank(token), source_rank);
        }
    }
    assert_eq!(relevant, 34_471);
    assert_eq!(rank(b"vck"), NONE);
    assert_eq!(rank(b"ck"), 377);
    assert_eq!(rank(b"vc"), 7513);
}

#[test]
fn full_source_reference_covers_mixed_prefixes_alphabets_and_merges() {
    let source = vocabulary();
    let splitter = GoRegex::compile(r"[-_]?[A-Za-z]+|[0-9]{1,3}|[-_]+").unwrap();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    for prefix in [
        b"vck_", b"vcK_", b"vCk_", b"vCK_", b"Vck_", b"VcK_", b"VCk_", b"VCK_",
    ] {
        for &byte in alphabet {
            let mut secret = [byte; 60];
            secret[..4].copy_from_slice(prefix);
            assert_eq!(count(&secret), Some(reference(&secret, &source, &splitter)));
        }
    }
    // Deterministic synthetic carriers include long letter runs, repeated pairs
    // (equal-rank ties), punctuation boundaries and absent vocabulary pieces.
    for carrier in [
        b"authentication".as_slice(),
        b"abababab",
        b"___abc--XYZ",
        b"0123_ab-AB",
        alphabet,
    ] {
        for shift in 0..carrier.len() {
            let mut secret = [0_u8; 60];
            secret[..4].copy_from_slice(b"vCk_");
            for (index, byte) in secret[4..].iter_mut().enumerate() {
                *byte = carrier[(index + shift) % carrier.len()];
            }
            assert_eq!(count(&secret), Some(reference(&secret, &source, &splitter)));
        }
    }
}

#[test]
fn work_is_bounded_and_interrupts_piece_and_merge_steps() {
    let mut secret = [b'Q'; 60];
    secret[..4].copy_from_slice(b"vck_");
    let mut units = 0;
    let expected = token_count(&secret, &mut || {
        units += 1;
        Ok::<(), usize>(())
    })
    .unwrap();
    // <=60 pieces and <=59 total merge-search iterations plus domain check.
    assert!(units > 4 && units <= 121);
    for limit in 0..units {
        let mut used = 0;
        assert_eq!(
            token_count(&secret, &mut || {
                if used == limit {
                    return Err(limit);
                }
                used += 1;
                Ok(())
            }),
            Err(limit)
        );
        assert_eq!(used, limit);
    }
    assert_eq!(expected, count(&secret));
}
