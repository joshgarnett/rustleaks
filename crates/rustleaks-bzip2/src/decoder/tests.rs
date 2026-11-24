use std::cmp::Ordering;
use std::io;

use super::{block_input_bound, Decoder, ReadState};
use crate::block::tests::decode;
use crate::block::{combine_crc, BLOCK_MAGIC, FINAL_MAGIC};
use crate::crc::Hasher;
use crate::header::Header;

const SINGLE_BLOCK_TEXT: &[u8] = b"rustleaks combined crc test\n";
const TEXT_AFTER_NOISE: &[u8] = b"rustleaks text after the noise\n";

#[test]
fn decodes_incompressible_block_larger_than_block_size() {
    let mut input = pseudo_random_bytes(0x5eed_1234_abcd_0001, 99_900);
    input.extend_from_slice(TEXT_AFTER_NOISE);
    let stream = encode_stream(1, &[&input]);
    // The block holds about 9 bits for each input byte, so it is larger than
    // the 100,000 byte block size of level 1.
    assert!(stream.len() > 110_000, "stream is {} bytes", stream.len());

    assert_eq!(decode(&stream, 7).unwrap(), input);
    assert_eq!(decode(&stream, 4096).unwrap(), input);
}

#[test]
fn test_encoder_output_decodes_for_short_text() {
    let stream = encode_stream(1, &[SINGLE_BLOCK_TEXT]);
    assert_eq!(decode(&stream, 3).unwrap(), SINGLE_BLOCK_TEXT);
    assert_eq!(decode(&encode_stream(9, &[]), 3).unwrap(), b"");
    let stream = encode_stream(9, &[b"first block\n", b"second block\n"]);
    assert_eq!(decode(&stream, 5).unwrap(), b"first block\nsecond block\n");
}

#[test]
fn rejects_empty_input() {
    for input in [&b""[..], b"BZh"] {
        let error = decode(input, 16).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(
            error.to_string(),
            "bzip2 input is empty or shorter than its header"
        );
    }
}

#[test]
fn input_buffer_stays_below_twice_the_block_bound() {
    let bound = block_input_bound(&Header::parse(*b"BZh1").unwrap());
    let one_block = encode_stream(1, &[SINGLE_BLOCK_TEXT]).len();
    let two_blocks = encode_stream(1, &[SINGLE_BLOCK_TEXT; 2]).len();
    let copies = 4 * bound / (two_blocks - one_block);
    let input = encode_stream(1, &vec![SINGLE_BLOCK_TEXT; copies]);

    let mut remaining = &input[..];
    let mut decoder = Decoder::new();
    let mut output = Vec::new();
    let mut buffer = [0; 1024];
    let mut largest = 0;
    loop {
        match decoder.read(&mut buffer).unwrap() {
            ReadState::NeedsWrite(space) => {
                let count = space.min(remaining.len());
                decoder.write(&remaining[..count]);
                remaining = &remaining[count..];
                largest = largest.max(decoder.in_buf.len());
            }
            ReadState::Read(count) => output.extend_from_slice(&buffer[..count]),
            ReadState::Eof => break,
        }
    }

    assert_eq!(output, SINGLE_BLOCK_TEXT.repeat(copies));
    assert!(input.len() > 3 * bound);
    assert!(
        largest <= 2 * bound,
        "buffered {} bytes, bound {}",
        largest,
        bound
    );
}

#[test]
fn block_input_bound_covers_worst_case_block() {
    for level in 1..=9_u8 {
        let header = Header::parse([b'B', b'Z', b'h', b'0' + level]).unwrap();
        let max_blocksize = header.max_blocksize() as usize;
        // Bits of the fixed block fields, at most 32,767 selectors of 6 bits,
        // 6 tables of 258 lengths of 39 bits, `max_blocksize + 1` symbols of
        // 20 bits, and the 8 bytes the cached bit reader looks ahead.
        let fixed_bits = 48 + 32 + 1 + 24 + 16 + 256 + 3 + 15 + 6 * 5;
        let worst_bits = fixed_bits + 32_767 * 6 + 6 * 258 * 39 + (max_blocksize + 1) * 20;
        let worst_bytes = worst_bits.div_ceil(8) + 8;
        assert!(block_input_bound(&header) >= worst_bytes, "level {}", level);
    }
}

/// Returns `len` bytes from a xorshift64 generator.
fn pseudo_random_bytes(mut state: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_be_bytes()[0]
        })
        .collect()
}

/// Writes one bzip2 stream with one block for each item of `blocks`.
///
/// The encoder is small and slow. It uses two equal Huffman tables with
/// fixed code lengths: RUNA and RUNB take 2 bits and the other symbols share
/// the other half of the code space. Random bytes then take about 9 bits
/// each, so their block is larger than the input.
fn encode_stream(level: u8, blocks: &[&[u8]]) -> Vec<u8> {
    let mut out = BitWriter::default();
    out.bits(
        32,
        u64::from(u32::from_be_bytes([b'B', b'Z', b'h', b'0' + level])),
    );
    let mut combined_crc = 0;
    for data in blocks {
        let block_crc = encode_block(&mut out, 100_000 * usize::from(level), data);
        combined_crc = combine_crc(combined_crc, block_crc);
    }
    out.bits(48, FINAL_MAGIC);
    out.bits(32, u64::from(combined_crc));
    out.finish()
}

/// Writes one block for `data` and returns its CRC.
fn encode_block(out: &mut BitWriter, max_blocksize: usize, data: &[u8]) -> u32 {
    let block = run_length_encode(data);
    // bzip2 leaves 19 bytes of the block size unused.
    assert!(
        !block.is_empty() && block.len() <= max_blocksize - 19,
        "block must hold 1 to max_blocksize - 19 bytes"
    );
    let mut hasher = Hasher::new();
    hasher.update(data);
    let block_crc = hasher.finalize();

    let (last, orig_ptr) = burrows_wheeler(&block);
    out.bits(48, BLOCK_MAGIC);
    out.bits(32, u64::from(block_crc));
    out.bits(1, 0);
    out.bits(24, orig_ptr as u64);

    let mut in_use = [false; 256];
    for &byte in &block {
        in_use[usize::from(byte)] = true;
    }
    for range in in_use.chunks(16) {
        out.bits(1, u64::from(range.contains(&true)));
    }
    for range in in_use.chunks(16) {
        if range.contains(&true) {
            for &used in range {
                out.bits(1, u64::from(used));
            }
        }
    }

    let symbols = move_to_front_runs(&last, &in_use);
    let alpha_size = in_use.iter().filter(|&&used| used).count() + 2;
    let lengths = code_lengths(alpha_size);
    let codes = canonical_codes(&lengths);

    out.bits(3, 2);
    let selectors = symbols.len().div_ceil(50);
    out.bits(15, selectors as u64);
    for _ in 0..selectors {
        out.bits(1, 0);
    }
    for _ in 0..2 {
        let mut current = lengths[0];
        out.bits(5, u64::from(current));
        for &length in &lengths {
            while current < length {
                out.bits(2, 0b10);
                current += 1;
            }
            while current > length {
                out.bits(2, 0b11);
                current -= 1;
            }
            out.bits(1, 0);
        }
    }
    for symbol in symbols {
        let symbol = usize::from(symbol);
        out.bits(lengths[symbol], u64::from(codes[symbol]));
    }
    block_crc
}

/// Replaces each run of 4 to 255 equal bytes with 4 bytes and a count.
fn run_length_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut index = 0;
    while index < data.len() {
        let byte = data[index];
        let mut run = 1;
        while index + run < data.len() && data[index + run] == byte && run < 255 {
            run += 1;
        }
        if run >= 4 {
            out.extend_from_slice(&[byte; 4]);
            out.push((run - 4) as u8);
        } else {
            out.extend(std::iter::repeat_n(byte, run));
        }
        index += run;
    }
    out
}

/// Returns the last column of the sorted rotations and the row of the input.
fn burrows_wheeler(block: &[u8]) -> (Vec<u8>, usize) {
    let len = block.len();
    let mut rows: Vec<usize> = (0..len).collect();
    rows.sort_by(|&left, &right| {
        (0..len)
            .map(|offset| block[(left + offset) % len].cmp(&block[(right + offset) % len]))
            .find(|ordering| *ordering != Ordering::Equal)
            .unwrap_or(Ordering::Equal)
    });
    let orig_ptr = rows.iter().position(|&row| row == 0).unwrap();
    let last = rows
        .iter()
        .map(|&row| block[(row + len - 1) % len])
        .collect();
    (last, orig_ptr)
}

/// Applies move-to-front and encodes zero runs as RUNA (0) and RUNB (1).
/// A value `n` above zero becomes symbol `n + 1`, and the last symbol is the
/// end of block.
fn move_to_front_runs(last: &[u8], in_use: &[bool; 256]) -> Vec<u16> {
    let mut order: Vec<u8> = (0..=255)
        .filter(|&byte| in_use[usize::from(byte)])
        .collect();
    let end_of_block = order.len() as u16 + 1;
    let mut symbols = Vec::new();
    let mut zeros = 0_usize;
    for &byte in last {
        let position = order.iter().position(|&value| value == byte).unwrap();
        if position == 0 {
            zeros += 1;
            continue;
        }
        push_zero_run(&mut symbols, &mut zeros);
        order.remove(position);
        order.insert(0, byte);
        symbols.push(position as u16 + 1);
    }
    push_zero_run(&mut symbols, &mut zeros);
    symbols.push(end_of_block);
    symbols
}

fn push_zero_run(symbols: &mut Vec<u16>, zeros: &mut usize) {
    if *zeros == 0 {
        return;
    }
    let mut run = *zeros - 1;
    loop {
        symbols.push((run & 1) as u16);
        if run < 2 {
            break;
        }
        run = (run - 2) / 2;
    }
    *zeros = 0;
}

/// Gives RUNA and RUNB 2 bits each. The other `n` symbols fill the other half
/// of the code space with lengths `d + 1` and `d + 2`, where `2^d <= n`.
fn code_lengths(alpha_size: usize) -> Vec<u8> {
    let others = alpha_size - 2;
    let depth = others.ilog2() as u8;
    let short = (1_usize << (depth + 1)) - others;
    let mut lengths = vec![2, 2];
    lengths.extend((0..others).map(|index| if index < short { depth + 1 } else { depth + 2 }));
    lengths
}

/// Assigns canonical codes in order of length, then symbol, as bzip2 does.
fn canonical_codes(lengths: &[u8]) -> Vec<u32> {
    let mut codes = vec![0; lengths.len()];
    let mut code = 0_u32;
    for length in 1..=20 {
        for (symbol, &symbol_length) in lengths.iter().enumerate() {
            if symbol_length == length {
                codes[symbol] = code;
                code += 1;
            }
        }
        code <<= 1;
    }
    codes
}

#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    current: u8,
    used: u8,
}

impl BitWriter {
    /// Writes the low `count` bits of `value`, most significant bit first.
    fn bits(&mut self, count: u8, value: u64) {
        for bit in (0..count).rev() {
            self.current = (self.current << 1) | ((value >> bit) & 1) as u8;
            self.used += 1;
            if self.used == 8 {
                self.bytes.push(self.current);
                self.current = 0;
                self.used = 0;
            }
        }
    }

    /// Pads the last byte with zero bits.
    fn finish(mut self) -> Vec<u8> {
        if self.used > 0 {
            self.bytes.push(self.current << (8 - self.used));
        }
        self.bytes
    }
}
