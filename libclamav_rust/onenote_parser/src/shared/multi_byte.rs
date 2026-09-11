//! Multi-byte encoding/decoding
//!
//! Following the multi-byte encoding described in [\[MS-ISF\]] (sections _Multi-byte Encoding of
//! Signed Numbers_ and _Sizes of Tags and Numbers_).
//!
//! [\[MS-ISF\]]: https://docs.microsoft.com/en-us/uwp/specifications/ink-serialized-format

use crate::errors::{ErrorKind, Result};
use crate::reader::{reserve_collection, Reader};
use std::{convert::TryFrom, mem::size_of};

pub(crate) fn decode_signed(input: &[u8]) -> Result<Vec<i64>> {
    let values = decode(input)?;
    let mut output = Vec::new();
    reserve_collection(&mut output, values.len())?;
    for value in values {
        reserve_collection(&mut output, 1)?;
        output.push({
            let shifted = (value >> 1) as i64;

            if value & 0x1 == 0x1 {
                -shifted
            } else {
                shifted
            }
        });
    }
    Ok(output)
}

fn decode(input: &[u8]) -> Result<Vec<u64>> {
    let mut output = Vec::new();

    // Decode the multi-byte data length
    let (length, offset) = decode_uint(input)?;

    // The length is actually a signed value so we need to remove the sign bit
    // (see also `decode_signed`). This may not be the case for unsigned multi-byte blobs
    // but for ink data it's always signed so this should be safe for now.
    let length = usize::try_from(length >> 1).map_err(|_| ErrorKind::CollectionLimit {
        requested: usize::MAX,
        max: Reader::MAX_COLLECTION_BYTES,
    })?;
    let requested = length
        .checked_mul(size_of::<u64>())
        .ok_or(ErrorKind::CollectionLimit {
            requested: usize::MAX,
            max: Reader::MAX_COLLECTION_BYTES,
        })?;
    if requested > Reader::MAX_COLLECTION_BYTES {
        return Err(ErrorKind::CollectionLimit {
            requested,
            max: Reader::MAX_COLLECTION_BYTES,
        }
        .into());
    }
    output
        .try_reserve_exact(length)
        .map_err(|_| ErrorKind::AllocationFailed { requested })?;

    // Decode the remaining data
    let mut index = offset;
    for _ in 0..length {
        let data = input.get(index..).ok_or_else(|| {
            ErrorKind::MalformedOneNoteFileData("ink path offset exceeds input".into())
        })?;
        let (value, offset) = decode_uint(data)?;

        output.push(value);
        index = index.checked_add(offset).ok_or_else(|| {
            ErrorKind::MalformedOneNoteFileData("ink path offset overflow".into())
        })?;
    }

    Ok(output)
}

fn decode_uint(data: &[u8]) -> Result<(u64, usize)> {
    let mut value: u64 = 0;
    let mut count = 0;

    for byte in data {
        let flag = byte & 0x80 == 0x80;
        if count == 10 || (count == 9 && *byte > 1) {
            return Err(ErrorKind::MalformedOneNoteFileData(
                "ink path multi-byte integer is too wide".into(),
            )
            .into());
        }
        value |= (*byte as u64 & 0x7F) << (count * 7);

        count += 1;

        if !flag {
            return Ok((value, count));
        }
    }

    Err(ErrorKind::MalformedOneNoteFileData(
        "ink path multi-byte integer is truncated".into(),
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::decode_signed;

    #[test]
    fn decode_signed_accepts_a_single_zero() {
        assert_eq!(decode_signed(&[2, 0]).unwrap(), vec![0]);
    }

    #[test]
    fn decode_signed_rejects_a_truncated_declared_value() {
        assert!(decode_signed(&[6]).is_err());
    }

    #[test]
    fn decode_signed_rejects_a_truncated_varint() {
        assert!(decode_signed(&[0x80]).is_err());
    }
}
