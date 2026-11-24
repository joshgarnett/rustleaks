//! Search for the x86 CALL (0xE8) and JMP (0xE9) opcodes that the E8 and
//! E8E9 filters rewrite.

/// Returns the position of the first byte in `data[start..end]` that equals
/// 0xE8 after `cmp_mask` is applied. A mask of 0xFF finds only 0xE8, and 0xFE
/// also finds 0xE9. `end` is clamped to the length of `data`.
pub(crate) fn next_x86_opcode(
    data: &[u8],
    start: usize,
    end: usize,
    cmp_mask: u8,
) -> Option<usize> {
    let end = end.min(data.len());
    data.get(start..end)?
        .iter()
        .position(|&byte| byte & cmp_mask == 0xe8)
        .map(|offset| start + offset)
}

#[cfg(test)]
mod tests {
    use super::next_x86_opcode;

    #[test]
    fn x86_opcode_scan_finds_e8_and_e8e9() {
        let mut data = vec![0x41u8; 96];
        for pos in [0, 31, 32, 33, 63, 64, 91] {
            data[pos] = 0xe8;
        }
        data[47] = 0xe9;

        for &include_e9 in &[false, true] {
            let cmp_mask = if include_e9 { 0xfe } else { 0xff };
            let mut pos = 0usize;
            let mut found = Vec::new();
            while let Some(next) = next_x86_opcode(&data, pos, data.len() - 4, cmp_mask) {
                found.push(next);
                pos = next + 1;
            }

            let expected: Vec<_> = data
                .iter()
                .take(data.len() - 4)
                .enumerate()
                .filter_map(|(pos, &byte)| (byte & cmp_mask == 0xe8).then_some(pos))
                .collect();
            assert_eq!(found, expected);
        }
    }

    #[test]
    fn x86_opcode_scan_clamps_the_end_to_the_data() {
        let data = [0x41, 0xe8];
        assert_eq!(next_x86_opcode(&data, 0, 10, 0xff), Some(1));
        assert_eq!(next_x86_opcode(&data, 2, 10, 0xff), None);
        assert_eq!(next_x86_opcode(&data, 3, 1, 0xff), None);
    }
}
