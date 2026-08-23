use std::io::Read;

use crate::Error;

const COPY_BUFFER_SIZE: usize = 8 * 1024;

pub(crate) fn decode(
    mut input: impl Read,
    uncompressed_len: usize,
    memory_limit_kb: usize,
) -> Result<Vec<u8>, Error> {
    let memory_limit = memory_limit_kb
        .checked_mul(1024)
        .ok_or_else(|| Error::other("7z decoder memory limit overflow"))?;
    let mut compressed = Vec::new();
    let mut buffer = [0; COPY_BUFFER_SIZE];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if compressed
            .len()
            .checked_add(count)
            .is_none_or(|size| size > memory_limit)
        {
            return Err(Error::MaxMemLimited {
                max_kb: memory_limit_kb,
                actaul_kb: compressed.len().saturating_add(count).div_ceil(1024),
            });
        }
        compressed
            .try_reserve(count)
            .map_err(|_| Error::other("unable to allocate the 7z Zstandard input buffer"))?;
        compressed.extend_from_slice(&buffer[..count]);
    }

    let mut history = try_zeroed(memory_limit, "Zstandard history")?;
    let mut block = try_zeroed(zstd_zero::MAX_BLOCK_SIZE, "Zstandard block scratch")?;
    let mut literals = try_zeroed(zstd_zero::MAX_BLOCK_SIZE, "Zstandard literal scratch")?;
    let mut decoder = zstd_zero::Decoder::new(zstd_zero::DecoderBuffers {
        history: &mut history,
        block: &mut block,
        literals: &mut literals,
    });
    let mut output = Vec::new();
    output
        .try_reserve_exact(uncompressed_len)
        .map_err(|_| Error::other("unable to allocate the 7z Zstandard output buffer"))?;
    let mut append = |bytes: &[u8]| -> Result<(), Error> {
        if output
            .len()
            .checked_add(bytes.len())
            .is_none_or(|size| size > uncompressed_len)
        {
            return Err(Error::other(
                "Zstandard output exceeds the 7z-declared unpack size",
            ));
        }
        output
            .try_reserve(bytes.len())
            .map_err(|_| Error::other("unable to grow the 7z Zstandard output buffer"))?;
        output.extend_from_slice(bytes);
        Ok(())
    };
    decoder
        .push(&compressed, &mut append)
        .map_err(stream_error)?;
    decoder.finish_with(&mut append).map_err(stream_error)?;
    if output.len() != uncompressed_len {
        return Err(Error::other(format!(
            "Zstandard output size mismatch: expected {uncompressed_len}, got {}",
            output.len()
        )));
    }
    Ok(output)
}

fn try_zeroed(size: usize, label: &'static str) -> Result<Vec<u8>, Error> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(size)
        .map_err(|_| Error::other(format!("unable to allocate the 7z {label} buffer")))?;
    value.resize(size, 0);
    Ok(value)
}

fn stream_error(error: zstd_zero::StreamError<Error>) -> Error {
    match error {
        zstd_zero::StreamError::Output(error) => error,
        zstd_zero::StreamError::Decode(error) => {
            Error::other(format!("Zstandard decode failed: {error}"))
        }
        zstd_zero::StreamError::DecoderStalled => {
            Error::other("Zstandard decoder stopped making progress")
        }
    }
}
