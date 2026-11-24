use std::io::Read;

use lzma_rust2::{
    Lzma2Reader, LzmaReader,
    filter::{bcj::BcjReader, delta::DeltaReader},
    lzma_get_memory_usage_by_props, lzma2_get_memory_usage,
};
use rustleaks_bzip2::DecoderReader as Bzip2Decoder;

use crate::codec::{
    brotli::BrotliDecoder,
    deflate::DeflateDecoder,
    lz4::Lz4Decoder,
    zstd::{ZstdBuffers, ZstdDecoder},
};
use crate::{archive::EncoderMethod, block::Block, block::Coder, error::Error};

/// Working memory of one Zstandard coder: its part of the shared history
/// and its own fixed buffers.
pub(crate) struct ZstdSlot<'b> {
    pub(crate) history: &'b mut [u8],
    pub(crate) buffers: &'b mut ZstdBuffers,
}

/// Buffers for the Zstandard coders of one block, taken in decoder order.
pub(crate) type ZstdPool<'b> = std::vec::IntoIter<ZstdSlot<'b>>;

/// Working memory of the Zstandard coders, kept from block to block.
///
/// Blocks are decoded one after another, so each block reuses the memory of
/// the block before it. The history is allocated and zeroed once, when the
/// first block with a Zstandard coder needs it, and never holds more than
/// the memory limit. Each decoder writes a history byte before it reads it,
/// so bytes left from an earlier block are never read.
#[derive(Default)]
pub(crate) struct ZstdBufferCache {
    history: Vec<u8>,
    buffers: Vec<ZstdBuffers>,
}

impl ZstdBufferCache {
    /// Returns working memory for the Zstandard coders in `block`.
    ///
    /// All Zstandard decoders of a block are open at the same time, so they
    /// share the memory limit equally.
    pub(crate) fn for_block(
        &mut self,
        block: &Block,
        memory_limit_kb: usize,
    ) -> Result<ZstdPool<'_>, Error> {
        let count = block
            .coders
            .iter()
            .filter(|coder| coder.encoder_method_id() == EncoderMethod::ID_ZSTD)
            .count();
        let mut slots = Vec::new();
        if count == 0 {
            return Ok(slots.into_iter());
        }
        let overflow = || Error::other("7z decoder memory limit overflow");
        let history_len = (memory_limit_kb / count)
            .checked_mul(1024)
            .ok_or_else(overflow)?;
        let total = history_len.checked_mul(count).ok_or_else(overflow)?;
        if let Some(missing) = total.checked_sub(self.history.len()).filter(|&n| n > 0) {
            self.history
                .try_reserve_exact(missing)
                .map_err(|_| Error::other("unable to allocate the 7z Zstandard history buffer"))?;
            self.history.resize(total, 0);
        }
        if let Some(missing) = count.checked_sub(self.buffers.len()).filter(|&n| n > 0) {
            self.buffers
                .try_reserve_exact(missing)
                .map_err(|_| Error::other("unable to allocate the 7z Zstandard buffer table"))?;
            for _ in 0..missing {
                self.buffers.push(ZstdBuffers::new()?);
            }
        }
        slots
            .try_reserve_exact(count)
            .map_err(|_| Error::other("unable to allocate the 7z Zstandard buffer table"))?;
        let mut history = &mut self.history[..total];
        for buffers in &mut self.buffers[..count] {
            let (own, rest) = std::mem::take(&mut history).split_at_mut(history_len);
            history = rest;
            slots.push(ZstdSlot {
                history: own,
                buffers,
            });
        }
        Ok(slots.into_iter())
    }
}

pub enum Decoder<'b, R: Read> {
    Copy(R),
    Lzma(Box<LzmaReader<R>>),
    Lzma2(Box<Lzma2Reader<R>>),
    Bcj(BcjReader<R>),
    Delta(DeltaReader<R>),
    Brotli(Box<BrotliDecoder<R>>),
    Bzip2(Bzip2Decoder<R>),
    Deflate(Box<DeflateDecoder<R>>),
    Lz4(Lz4Decoder<R>),
    Zstd(Box<ZstdDecoder<'b, R>>),
}

impl<R: Read> Read for Decoder<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Decoder::Copy(r) => r.read(buf),
            Decoder::Lzma(r) => r.read(buf),
            Decoder::Lzma2(r) => r.read(buf),
            Decoder::Bcj(r) => r.read(buf),
            Decoder::Delta(r) => r.read(buf),
            Decoder::Brotli(r) => r.read(buf),
            Decoder::Bzip2(r) => r.read(buf),
            Decoder::Deflate(r) => r.read(buf),
            Decoder::Lz4(r) => r.read(buf),
            Decoder::Zstd(r) => r.read(buf),
        }
    }
}

pub fn add_decoder<'b, I: Read>(
    input: I,
    uncompressed_len: usize,
    coder: &Coder,
    max_mem_limit_kb: usize,
    zstd: &mut ZstdPool<'b>,
) -> Result<Decoder<'b, I>, Error> {
    let method = EncoderMethod::by_id(coder.encoder_method_id());
    let method = if let Some(m) = method {
        m
    } else {
        let id: String = coder
            .encoder_method_id()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        return Err(Error::UnsupportedCompressionMethod(format!("id {id}")));
    };
    match method.id() {
        EncoderMethod::ID_COPY => Ok(Decoder::Copy(input)),
        EncoderMethod::ID_LZMA => {
            // One byte of literal and position bits, then a 32-bit dictionary size.
            let &[props, d0, d1, d2, d3, ..] = coder.properties.as_slice() else {
                return Err(Error::other("LZMA properties too short"));
            };
            let dict_size = u32::from_le_bytes([d0, d1, d2, d3]);
            let mem_size = usize::try_from(
                lzma_get_memory_usage_by_props(dict_size, props)
                    .map_err(|error| Error::other(error.to_string()))?,
            )
            .map_err(|_| Error::other("LZMA memory usage does not fit usize"))?;
            if mem_size > max_mem_limit_kb {
                return Err(Error::MaxMemLimited {
                    max_kb: max_mem_limit_kb,
                    actual_kb: mem_size,
                });
            }
            let lz =
                LzmaReader::new_with_props(input, uncompressed_len as _, props, dict_size, None)?;
            Ok(Decoder::Lzma(Box::new(lz)))
        }
        EncoderMethod::ID_LZMA2 => {
            let dic_size = get_lzma2_dic_size(coder)?;
            let mem_size = lzma2_get_memory_usage(dic_size) as usize;
            if mem_size > max_mem_limit_kb {
                return Err(Error::MaxMemLimited {
                    max_kb: max_mem_limit_kb,
                    actual_kb: mem_size,
                });
            }

            Ok(Decoder::Lzma2(Box::new(Lzma2Reader::new(
                input, dic_size, None,
            ))))
        }
        EncoderMethod::ID_BROTLI => {
            let de = BrotliDecoder::new(input, 4096)?;
            Ok(Decoder::Brotli(Box::new(de)))
        }
        EncoderMethod::ID_BZIP2 => {
            let de = Bzip2Decoder::new(input);
            Ok(Decoder::Bzip2(de))
        }
        EncoderMethod::ID_DEFLATE => {
            let de = DeflateDecoder::new(input);
            Ok(Decoder::Deflate(Box::new(de)))
        }
        EncoderMethod::ID_LZ4 => {
            let de = Lz4Decoder::new(input)?;
            Ok(Decoder::Lz4(de))
        }
        EncoderMethod::ID_ZSTD => {
            let slot = zstd
                .next()
                .ok_or_else(|| Error::other("no buffers for a 7z Zstandard coder"))?;
            let de = ZstdDecoder::new(input, uncompressed_len, slot)?;
            Ok(Decoder::Zstd(Box::new(de)))
        }
        EncoderMethod::ID_BCJ_X86 => {
            let de = BcjReader::new_x86(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_ARM => {
            let de = BcjReader::new_arm(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_ARM64 => {
            let de = BcjReader::new_arm64(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_ARM_THUMB => {
            let de = BcjReader::new_arm_thumb(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_PPC => {
            let de = BcjReader::new_ppc(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_IA64 => {
            let de = BcjReader::new_ia64(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_SPARC => {
            let de = BcjReader::new_sparc(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_BCJ_RISCV => {
            let de = BcjReader::new_riscv(input, 0);
            Ok(Decoder::Bcj(de))
        }
        EncoderMethod::ID_DELTA => {
            let d = if coder.properties.is_empty() {
                1
            } else {
                coder.properties[0].wrapping_add(1)
            };
            let de = DeltaReader::new(input, d as usize);
            Ok(Decoder::Delta(de))
        }
        _ => Err(Error::UnsupportedCompressionMethod(
            method.name().to_string(),
        )),
    }
}

fn get_lzma2_dic_size(coder: &Coder) -> Result<u32, Error> {
    if coder.properties.is_empty() {
        return Err(Error::other("LZMA2 properties too short"));
    }
    let dict_size_bits = 0xFF & coder.properties[0] as u32;
    if (dict_size_bits & (!0x3F)) != 0 {
        return Err(Error::other("Unsupported LZMA2 property bits"));
    }
    if dict_size_bits > 40 {
        return Err(Error::other("Dictionary larger than 4GiB maximum size"));
    }
    if dict_size_bits == 40 {
        return Ok(0xFFFFFFFF);
    }
    let size = (2 | (dict_size_bits & 0x1)) << (dict_size_bits / 2 + 11);
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coder(method: &[u8], properties: Vec<u8>) -> Coder {
        let mut coder = Coder::default();
        coder.id_size = method.len();
        coder.num_in_streams = 1;
        coder.num_out_streams = 1;
        coder.properties = properties;
        coder.decompression_method_id_mut().copy_from_slice(method);
        coder
    }

    #[test]
    fn rejects_lzma_dictionary_above_memory_limit() {
        let mut properties = vec![0x5d];
        properties.extend_from_slice(&(1024_u32 * 1024).to_le_bytes());
        let result = add_decoder(
            &[][..],
            1,
            &coder(EncoderMethod::ID_LZMA, properties),
            1,
            &mut Vec::new().into_iter(),
        );
        assert!(matches!(result, Err(Error::MaxMemLimited { .. })));
    }

    #[test]
    fn rejects_lzma2_dictionary_above_memory_limit() {
        let result = add_decoder(
            &[][..],
            1,
            &coder(EncoderMethod::ID_LZMA2, vec![20]),
            1,
            &mut Vec::new().into_iter(),
        );
        assert!(matches!(result, Err(Error::MaxMemLimited { .. })));
    }

    fn zstd_block(count: usize) -> Block {
        let mut block = Block::default();
        for _ in 0..count {
            block.coders.push(coder(EncoderMethod::ID_ZSTD, Vec::new()));
        }
        block.coders.push(coder(EncoderMethod::ID_COPY, Vec::new()));
        block
    }

    fn history_lens(cache: &mut ZstdBufferCache, count: usize, limit_kb: usize) -> Vec<usize> {
        let slots = cache.for_block(&zstd_block(count), limit_kb).unwrap();
        slots.map(|slot| slot.history.len()).collect()
    }

    #[test]
    fn zstd_history_is_allocated_once_and_shared_by_the_coders_of_a_block() {
        const LIMIT_KB: usize = 1024;
        let mut cache = ZstdBufferCache::default();
        assert!(history_lens(&mut cache, 0, LIMIT_KB).is_empty());
        assert!(cache.history.is_empty());

        assert_eq!(history_lens(&mut cache, 1, LIMIT_KB), [1024 * 1024]);
        let start = cache.history.as_ptr();
        // Later blocks reuse the history without allocating or zeroing it.
        for _ in 0..3 {
            assert_eq!(history_lens(&mut cache, 1, LIMIT_KB), [1024 * 1024]);
            assert_eq!(cache.history.as_ptr(), start);
        }
        // Coders of one block split the limit, inside the same allocation.
        assert_eq!(
            history_lens(&mut cache, 2, LIMIT_KB),
            [512 * 1024, 512 * 1024]
        );
        assert_eq!(history_lens(&mut cache, 3, LIMIT_KB), [341 * 1024; 3]);
        assert_eq!(cache.history.as_ptr(), start);
        assert_eq!(cache.history.len(), 1024 * 1024);
        assert_eq!(cache.buffers.len(), 3);
        // Less than 1 KiB for each coder leaves every history empty.
        assert_eq!(history_lens(&mut cache, 2, 1), [0, 0]);
    }

    #[test]
    fn rejects_short_lzma_properties() {
        for properties in [vec![], vec![0x5d, 0, 0, 1]] {
            let result = add_decoder(
                &[][..],
                1,
                &coder(EncoderMethod::ID_LZMA, properties),
                64 * 1024,
                &mut Vec::new().into_iter(),
            );
            assert!(
                matches!(&result, Err(Error::Other(message)) if message == "LZMA properties too short")
            );
        }
    }
}
