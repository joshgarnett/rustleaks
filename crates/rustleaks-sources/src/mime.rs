//! Top-level MIME classification compatible with h2non/filetype v1.1.3.
//!
//! The pinned upstream compatibility behavior observes whether the first
//! matching type's top-level MIME is
//! `application`. All matchers within one upstream category share a top-level
//! type, so category precedence is sufficient and avoids reproducing Go map
//! iteration order that is unobservable to this decision.

pub(crate) fn is_application(data: &[u8]) -> bool {
    if application(data) {
        return true;
    }
    if image(data) || video(data) || audio(data) {
        return false;
    }
    font(data) || document(data) || archive(data)
}

fn prefix(data: &[u8], expected: &[u8]) -> bool {
    data.starts_with(expected)
}

fn application(data: &[u8]) -> bool {
    let wasm = data.len() >= 8 && prefix(data, b"\0asm\x01\0\0\0");
    let dex_file = data.len() > 36 && prefix(data, b"dex\n") && data[36] == 0x70;
    let optimized_dex_file = data.len() > 100
        && prefix(data, b"dey\n")
        && data[40..].len() > 36
        && prefix(&data[40..], b"dex\n")
        && data[76] == 0x70;
    wasm || dex_file || optimized_dex_file
}

fn image(data: &[u8]) -> bool {
    let jpeg = data.len() > 2 && prefix(data, &[0xff, 0xd8, 0xff]);
    let jpeg2000 = data.len() > 12
        && prefix(
            data,
            &[
                0, 0, 0, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a, 0,
            ],
        );
    let png = data.len() > 3 && prefix(data, b"\x89PNG");
    let gif = data.len() > 2 && prefix(data, b"GIF");
    let webp = data.len() > 11 && &data[8..12] == b"WEBP";
    let tiff_header = data.len() > 10 && (prefix(data, b"II*\0") || prefix(data, b"MM\0*"));
    let bmp = data.len() > 1 && prefix(data, b"BM");
    let jxr = data.len() > 2 && prefix(data, b"II\xbc");
    let psd = data.len() > 3 && prefix(data, b"8BPS");
    let ico = data.len() > 3 && prefix(data, b"\0\0\x01\0");
    let dwg = data.len() > 3 && prefix(data, b"AC10");
    jpeg || jpeg2000
        || png
        || gif
        || webp
        || tiff_header
        || bmp
        || jxr
        || psd
        || ico
        || heif(data)
        || dwg
}

fn heif(data: &[u8]) -> bool {
    if data.len() < 16 || &data[4..8] != b"ftyp" {
        return false;
    }
    let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if length > data.len() || length < 16 {
        return false;
    }
    let major = &data[8..12];
    if major == b"heic" {
        return true;
    }
    (major == b"mif1" || major == b"msf1")
        && data[16..length]
            .chunks_exact(4)
            .any(|brand| brand == b"heic")
}

fn video(data: &[u8]) -> bool {
    let m4v_brand = data.len() > 10 && &data[4..11] == b"ftypM4V";
    let matroska = data.len() > 3
        && prefix(data, b"\x1a\x45\xdf\xa3")
        && (contains_ebml_type(data, b"matroska") || contains_ebml_type(data, b"webm"));
    let quicktime_container = data.len() > 15
        && ((prefix(data, b"\0\0\0\x14") && &data[4..8] == b"ftyp")
            || &data[4..8] == b"moov"
            || &data[4..8] == b"mdat"
            || &data[12..16] == b"mdat");
    let avi = data.len() > 10 && prefix(data, b"RIFF") && &data[8..11] == b"AVI";
    let wmv = data.len() > 9 && prefix(data, b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9");
    let mpeg = data.len() > 3 && prefix(data, b"\0\0\x01") && (0xb0..=0xbf).contains(&data[3]);
    let flv = data.len() > 3 && prefix(data, b"FLV\x01");
    let three_gp = data.len() > 10 && &data[4..11] == b"ftyp3gp";
    let mp4 = data.len() > 11
        && &data[4..8] == b"ftyp"
        && matches!(
            &data[8..12],
            b"avc1"
                | b"dash"
                | b"iso2"
                | b"iso3"
                | b"iso4"
                | b"iso5"
                | b"iso6"
                | b"isom"
                | b"mmp4"
                | b"mp41"
                | b"mp42"
                | b"mp4v"
                | b"mp71"
                | b"MSNV"
                | b"NDAS"
                | b"NDSC"
                | b"NSDC"
                | b"NDSH"
                | b"NDSM"
                | b"NDSP"
                | b"NDSS"
                | b"NDXC"
                | b"NDXH"
                | b"NDXM"
                | b"NDXP"
                | b"NDXS"
                | b"F4V "
                | b"F4P "
        );
    m4v_brand || matroska || quicktime_container || avi || wmv || mpeg || flv || three_gp || mp4
}

fn contains_ebml_type(data: &[u8], kind: &[u8]) -> bool {
    let limit = data.len().min(4096);
    data[..limit]
        .windows(kind.len())
        .position(|window| window == kind)
        .is_some_and(|index| index >= 3 && data[index - 3..index - 1] == [0x42, 0x82])
}

fn audio(data: &[u8]) -> bool {
    let midi = data.len() > 3 && prefix(data, b"MThd");
    let mp3 = data.len() > 2 && (prefix(data, b"ID3") || prefix(data, b"\xff\xfb"));
    let m4a = data.len() > 10 && (&data[4..11] == b"ftypM4A" || prefix(data, b"M4A "));
    let ogg = data.len() > 3 && prefix(data, b"OggS");
    let flac = data.len() > 3 && prefix(data, b"fLaC");
    let wav = data.len() > 11 && prefix(data, b"RIFF") && &data[8..12] == b"WAVE";
    let amr = data.len() > 11 && prefix(data, b"#!AMR\n");
    let aac = data.len() > 1 && (prefix(data, b"\xff\xf1") || prefix(data, b"\xff\xf9"));
    let aiff = data.len() > 11 && prefix(data, b"FORM") && &data[8..12] == b"AIFF";
    midi || mp3 || m4a || ogg || flac || wav || amr || aac || aiff
}

fn font(data: &[u8]) -> bool {
    let woff = data.len() > 7 && prefix(data, b"wOFF\0\x01\0\0");
    let woff2 = data.len() > 7 && prefix(data, b"wOF2\0\x01\0\0");
    let ttf = data.len() > 4 && prefix(data, b"\0\x01\0\0\0");
    let otf = data.len() > 4 && prefix(data, b"OTTO\0");
    woff || woff2 || ttf || otf
}

fn document(data: &[u8]) -> bool {
    // All legacy OLE and OOXML document matchers have application MIME types.
    let legacy_ole = prefix(data, b"\xd0\xcf\x11\xe0")
        && (data.len() <= 513
            || matches!(&data[512..514], b"\xec\xa5" | b"\x09\x08" | b"\xa0\x46"));
    legacy_ole
        || (prefix(data, b"PK\x03\x04")
            && (data.windows(5).any(|value| value == b"word/")
                || data.windows(4).any(|value| value == b"ppt/")
                || data.windows(3).any(|value| value == b"xl/")))
}

fn archive(data: &[u8]) -> bool {
    prefix(data, b"PK\x03\x04")
        || prefix(data, b"PK\x05\x06")
        || prefix(data, b"PK\x07\x08")
        || (data.len() > 261 && &data[257..262] == b"ustar")
        || (data.len() > 6 && prefix(data, b"Rar!\x1a\x07") && matches!(data[6], 0 | 1))
        || prefix(data, b"\x1f\x8b\x08")
        || prefix(data, b"BZh")
        || prefix(data, b"7z\xbc\xaf'\x1c")
        || prefix(data, b"\xfd7zXZ\0")
        || zstd(data)
        || prefix(data, b"%PDF")
        || prefix(data, b"MZ")
        || (data.len() > 2 && matches!(data[0], b'C' | b'F') && &data[1..3] == b"WS")
        || prefix(data, b"{\\rtf")
        || (data.len() > 35
            && &data[34..36] == b"LP"
            && matches!(
                &data[8..11],
                b"\x02\x00\x01" | b"\x01\x00\x00" | b"\x02\x00\x02"
            ))
        || prefix(data, b"%!")
        || prefix(data, b"SQLi")
        || prefix(data, b"NES\x1a")
        || prefix(data, b"Cr24")
        || prefix(data, b"MSCF")
        || prefix(data, b"ISc(")
        || prefix(data, b"!<arch>\ndebian-binary")
        || prefix(data, b"!<arch>")
        || prefix(data, b"\x1f\xa0")
        || prefix(data, b"\x1f\x9d")
        || prefix(data, b"LZIP")
        || (data.len() > 96 && prefix(data, b"\xed\xab\xee\xdb"))
        || (data.len() > 52 && prefix(data, b"\x7fELF"))
        || (data.len() > 131 && &data[128..132] == b"DICM")
        || (data.len() > 32_773 && &data[32_769..32_774] == b"CD001")
        || macho(data)
}

fn zstd(data: &[u8]) -> bool {
    let mut remaining = data;
    loop {
        if prefix(remaining, b"\x28\xb5\x2f\xfd") {
            return true;
        }
        if remaining.len() < 8 {
            return false;
        }
        let magic = u32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]);
        if magic & 0xffff_fff0 != 0x184d_2a50 {
            return false;
        }
        let payload =
            u32::from_le_bytes([remaining[4], remaining[5], remaining[6], remaining[7]]) as usize;
        let Some(next) = 8_usize.checked_add(payload) else {
            return false;
        };
        let Some(tail) = remaining.get(next..) else {
            return false;
        };
        remaining = tail;
    }
}

fn macho(data: &[u8]) -> bool {
    data.len() > 3
        && matches!(
            &data[..4],
            b"\xfe\xed\xfa\xcf"
                | b"\xfe\xed\xfa\xce"
                | b"\xbe\xba\xfe\xca"
                | b"\xcf\xfa\xed\xfe"
                | b"\xce\xfa\xed\xfe"
                | b"\xca\xfe\xba\xbe"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_application_but_not_image_magic() {
        assert!(is_application(b"%PDF-1.7"));
        assert!(is_application(b"PK\x03\x04payload"));
        assert!(!is_application(b"\x89PNGpayload"));
        assert!(!is_application(b"ordinary text"));
    }
}
