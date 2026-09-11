use crate::errors::{ErrorKind, Result};
use crate::one::property::PropertyType;
use crate::onestore::object::Object;
use crate::reader::{copy_bytes, Reader};
use crate::shared::guid::Guid;
use crate::utils::Utf16ToString;
use std::mem::size_of;

pub(crate) fn parse_bool(prop_type: PropertyType, object: &Object) -> Result<Option<bool>> {
    let value = match object.props().get(prop_type) {
        Some(value) => value.to_bool().ok_or_else(|| {
            ErrorKind::MalformedOneNoteFileData("bool value is not a bool".into())
        })?,
        None => return Ok(None),
    };

    Ok(Some(value))
}

pub(crate) fn parse_u8(prop_type: PropertyType, object: &Object) -> Result<Option<u8>> {
    let value = match object.props().get(prop_type) {
        Some(value) => value
            .to_u8()
            .ok_or_else(|| ErrorKind::MalformedOneNoteFileData("u8 value is not a u8".into()))?,
        None => return Ok(None),
    };

    Ok(Some(value))
}

pub(crate) fn parse_u16(prop_type: PropertyType, object: &Object) -> Result<Option<u16>> {
    let value = match object.props().get(prop_type) {
        Some(value) => value
            .to_u16()
            .ok_or_else(|| ErrorKind::MalformedOneNoteFileData("u16 value is not a u16".into()))?,
        None => return Ok(None),
    };

    Ok(Some(value))
}

pub(crate) fn parse_u32(prop_type: PropertyType, object: &Object) -> Result<Option<u32>> {
    let value = match object.props().get(prop_type) {
        Some(value) => value
            .to_u32()
            .ok_or_else(|| ErrorKind::MalformedOneNoteFileData("u32 value is not a u32".into()))?,
        None => return Ok(None),
    };

    Ok(Some(value))
}

// Not used at the moment
//
// pub(crate) fn parse_u64(prop_type: PropertyType, object: &Object) -> Result<Option<u64>> {
//     object
//         .props()
//         .get(prop_type)
//         .map(|value| {
//             value
//                 .to_u64()
//                 .ok_or_else(|| ErrorKind::MalformedOneNoteFileData("u64 value is not a u64".into()))
//         })
//         .transpose()
//         .map_err(|e| e.into())
// }

pub(crate) fn parse_f32(prop_type: PropertyType, object: &Object) -> Result<Option<f32>> {
    let value = match object.props().get(prop_type) {
        Some(value) => value.to_u32().ok_or_else(|| {
            ErrorKind::MalformedOneNoteFileData("float value is not a u32".into())
        })?,
        None => return Ok(None),
    };

    Ok(Some(f32::from_le_bytes(value.to_le_bytes())))
}

pub(crate) fn parse_vec(prop_type: PropertyType, object: &Object) -> Result<Option<Vec<u8>>> {
    let data = match object.props().get(prop_type) {
        Some(value) => value
            .to_vec()
            .ok_or_else(|| ErrorKind::MalformedOneNoteFileData("vec value is not a vec".into()))?,
        None => return Ok(None),
    };

    Ok(Some(copy_bytes(data)?))
}

pub(crate) fn parse_vec_u16(prop_type: PropertyType, object: &Object) -> Result<Option<Vec<u16>>> {
    let data = match object.props().get(prop_type) {
        Some(value) => value.to_vec().ok_or_else(|| {
            ErrorKind::MalformedOneNoteFileData("vec u16 value is not a vec".into())
        })?,
        None => return Ok(None),
    };

    if data.len() % 2 != 0 {
        return Err(ErrorKind::MalformedOneNoteFileData(
            "u16 vector has an odd byte length".into(),
        )
        .into());
    }

    let mut vec = reserve_collection::<u16>(data.len() / 2)?;
    for value in data.chunks_exact(2) {
        vec.push(u16::from_le_bytes([value[0], value[1]]));
    }

    Ok(Some(vec))
}

pub(crate) fn parse_vec_u32(prop_type: PropertyType, object: &Object) -> Result<Option<Vec<u32>>> {
    let data = match object.props().get(prop_type) {
        Some(value) => value
            .to_vec()
            .ok_or_else(|| ErrorKind::MalformedOneNoteFileData("vec value is not a vec".into()))?,
        None => return Ok(None),
    };

    if data.len() % 4 != 0 {
        return Err(ErrorKind::MalformedOneNoteFileData(
            "u32 vector is not aligned".into(),
        )
        .into());
    }

    let mut vec = reserve_collection::<u32>(data.len() / 4)?;
    for value in data.chunks_exact(4) {
        vec.push(u32::from_le_bytes([value[0], value[1], value[2], value[3]]));
    }

    Ok(Some(vec))
}

fn reserve_collection<T>(count: usize) -> Result<Vec<T>> {
    let requested = count
        .checked_mul(size_of::<T>())
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

    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ErrorKind::AllocationFailed { requested })?;
    Ok(values)
}

pub(crate) fn parse_ascii(prop_type: PropertyType, object: &Object) -> Result<Option<String>> {
    let data = match object.props().get(prop_type) {
        Some(value) => value.to_vec().ok_or_else(|| {
            ErrorKind::MalformedOneNoteFileData("ascii value is not a vec".into())
        })?,
        None => return Ok(None),
    };

    let text = decode_latin1_bounded(data, Reader::MAX_COLLECTION_BYTES)?;

    Ok(Some(text))
}

fn decode_latin1_bounded(data: &[u8], max_bytes: usize) -> Result<String> {
    let output_len = data.iter().try_fold(0usize, |length, byte| {
        length
            .checked_add(if *byte < 0x80 { 1 } else { 2 })
            .ok_or(ErrorKind::CollectionLimit {
                requested: usize::MAX,
                max: max_bytes,
            })
    })?;
    if output_len > max_bytes {
        return Err(ErrorKind::CollectionLimit {
            requested: output_len,
            max: max_bytes,
        }
        .into());
    }

    let mut output = String::new();
    output
        .try_reserve_exact(output_len)
        .map_err(|_| ErrorKind::AllocationFailed {
            requested: output_len,
        })?;
    for byte in data {
        output.push(char::from(*byte));
    }

    Ok(output)
}

pub(crate) fn parse_string(prop_type: PropertyType, object: &Object) -> Result<Option<String>> {
    let data = match object.props().get(prop_type) {
        Some(value) => value
            .to_vec()
            .ok_or_else(|| ErrorKind::MalformedOneNoteFileData("vec value is not a vec".into()))?,
        None => return Ok(None),
    };

    // Utf16ToString already classifies malformed input separately from the
    // parser-owned collection/allocation limits. Preserve that distinction so
    // a bounded refusal remains visible to the application instead of being
    // relabeled as ordinary malformed content.
    let text = data.utf16_to_string()?;

    Ok(Some(text))
}

pub(crate) fn parse_guid(prop_type: PropertyType, object: &Object) -> Result<Option<Guid>> {
    let data = match object.props().get(prop_type) {
        Some(value) => value
            .to_vec()
            .ok_or_else(|| ErrorKind::MalformedOneNoteFileData("guid value is not a vec".into()))?,
        None => return Ok(None),
    };

    Ok(Some(Guid::parse(&mut Reader::new(data))?))
}

#[cfg(test)]
mod tests {
    use super::{decode_latin1_bounded, reserve_collection};
    use crate::reader::Reader;
    use std::mem::size_of;

    #[test]
    fn reserve_collection_rejects_over_budget() {
        let count = Reader::MAX_COLLECTION_BYTES / size_of::<u32>() + 1;
        let error = reserve_collection::<u32>(count).unwrap_err();

        assert!(error.is_resource_limit());
    }

    #[test]
    fn latin1_conversion_is_bounded_and_preserves_byte_values() {
        assert_eq!(
            decode_latin1_bounded(&[b'A', 0x80, 0xFF], 8).unwrap(),
            "A\u{0080}\u{00FF}"
        );
        assert!(decode_latin1_bounded(&[0xFF], 1).is_err());
    }
}
