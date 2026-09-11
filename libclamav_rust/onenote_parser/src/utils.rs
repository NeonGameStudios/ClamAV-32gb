use crate::errors::{ErrorKind, Result};
use crate::reader::{reserve_collection, Reader};

pub(crate) trait Utf16ToString {
    fn utf16_to_string(&self) -> Result<String>;
}

impl Utf16ToString for &[u8] {
    fn utf16_to_string(&self) -> Result<String> {
        utf16_to_string_bounded(self, Reader::MAX_COLLECTION_BYTES)
    }
}

fn utf16_to_string_bounded(data: &[u8], max_bytes: usize) -> Result<String> {
    if data.len() % 2 != 0 {
        return Err(ErrorKind::MalformedOneNoteFileData(
            "UTF-16 string has an odd byte length".into(),
        )
        .into());
    }

    let mut units = Vec::new();
    reserve_collection(&mut units, data.len() / 2)?;
    for value in data.chunks_exact(2) {
        units.push(u16::from_le_bytes([value[0], value[1]]));
    }

    let decoded_units = units.iter().copied().take_while(|value| *value != 0);
    let mut output_len = 0usize;
    for value in std::char::decode_utf16(decoded_units.clone()) {
        let value = value.map_err(|_| {
            ErrorKind::MalformedOneNoteFileData("invalid UTF-16 string".into())
        })?;
        output_len = output_len
            .checked_add(value.len_utf8())
            .ok_or(ErrorKind::CollectionLimit {
                requested: usize::MAX,
                max: max_bytes,
            })?;
        if output_len > max_bytes {
            return Err(ErrorKind::CollectionLimit {
                requested: output_len,
                max: max_bytes,
            }
            .into());
        }
    }

    let mut output = String::new();
    output
        .try_reserve_exact(output_len)
        .map_err(|_| ErrorKind::AllocationFailed { requested: output_len })?;
    for value in std::char::decode_utf16(units.iter().copied().take_while(|value| *value != 0)) {
        output.push(value.map_err(|_| {
            ErrorKind::MalformedOneNoteFileData("invalid UTF-16 string".into())
        })?);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{utf16_to_string_bounded, Utf16ToString};

    #[test]
    fn utf16_conversion_rejects_odd_byte_length() {
        let data: &[u8] = &[0x41];

        assert!(data.utf16_to_string().is_err());
    }

    #[test]
    fn utf16_conversion_rejects_unpaired_surrogate() {
        let data: &[u8] = &[0x00, 0xD8];

        assert!(data.utf16_to_string().is_err());
    }

    #[test]
    fn utf16_conversion_truncates_at_the_first_nul() {
        let data: &[u8] = &[b'A', 0, 0, 0, b'B', 0];

        assert_eq!(data.utf16_to_string().unwrap(), "A");
    }

    #[test]
    fn utf16_conversion_preserves_collection_limit_error() {
        let error = utf16_to_string_bounded(&[b'A', 0, b'B', 0], 1).unwrap_err();

        assert!(error.is_resource_limit());
    }
}
