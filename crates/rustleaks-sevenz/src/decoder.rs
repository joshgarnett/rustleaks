use std::io::{self, Cursor, Read};

use lzma_rust2::{
    Lzma2Reader, LzmaReader,
    filter::{bcj::BcjReader, delta::DeltaReader},
    lzma_get_memory_usage_by_props, lzma2_get_memory_usage,
};
use rustleaks_bzip2::DecoderReader as Bzip2Decoder;

use crate::codec::{brotli::BrotliDecoder, deflate::DeflateDecoder, lz4::Lz4Decoder};
use crate::{ByteReader, archive::EncoderMethod, block::Coder, error::Error};

pub enum Decoder<R: Read> {
    Copy(R),
    Lzma(Box<LzmaReader<R>>),
    Lzma2(Box<Lzma2Reader<R>>),
    Bcj(BcjReader<R>),
    Delta(DeltaReader<R>),
    Brotli(Box<BrotliDecoder<R>>),
    Bzip2(Bzip2Decoder<R>),
    Deflate(Box<DeflateDecoder<R>>),
    Lz4(Lz4Decoder<R>),
    Buffered(Cursor<Vec<u8>>),
}

impl<R: Read> Read for Decoder<R> {
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
            Decoder::Buffered(r) => r.read(buf),
        }
    }
}

pub fn add_decoder<I: Read>(
    input: I,
    uncompressed_len: usize,
    coder: &Coder,
    max_mem_limit_kb: usize,
) -> Result<Decoder<I>, Error> {
    let method = EncoderMethod::by_id(coder.encoder_method_id());
    let method = if let Some(m) = method {
        m
    } else {
        return Err(Error::UnsupportedCompressionMethod(format!(
            "{:?}",
            coder.encoder_method_id()
        )));
    };
    match method.id() {
        EncoderMethod::ID_COPY => Ok(Decoder::Copy(input)),
        EncoderMethod::ID_LZMA => {
            let dict_size = get_lzma_dic_size(coder)?;
            if coder.properties.is_empty() {
                return Err(Error::Other("LZMA properties too short".into()));
            }
            let props = coder.properties[0];
            let mem_size = usize::try_from(
                lzma_get_memory_usage_by_props(dict_size, props)
                    .map_err(|error| Error::other(error.to_string()))?,
            )
            .map_err(|_| Error::other("LZMA memory usage does not fit usize"))?;
            if mem_size > max_mem_limit_kb {
                return Err(Error::MaxMemLimited {
                    max_kb: max_mem_limit_kb,
                    actaul_kb: mem_size,
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
                    actaul_kb: mem_size,
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
            let output = crate::codec::zstd::decode(input, uncompressed_len, max_mem_limit_kb)?;
            Ok(Decoder::Buffered(Cursor::new(output)))
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

fn get_lzma_dic_size(coder: &Coder) -> io::Result<u32> {
    let mut props = &coder.properties[1..5];
    props.read_u32()
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
        let result = add_decoder(&[][..], 1, &coder(EncoderMethod::ID_LZMA, properties), 1);
        assert!(matches!(result, Err(Error::MaxMemLimited { .. })));
    }

    #[test]
    fn rejects_lzma2_dictionary_above_memory_limit() {
        let result = add_decoder(&[][..], 1, &coder(EncoderMethod::ID_LZMA2, vec![20]), 1);
        assert!(matches!(result, Err(Error::MaxMemLimited { .. })));
    }
}
