use crate::errors::{ErrorKind, Result};
use crate::Reader;

/// A compact unsigned 64-bit integer.
///
/// The first byte encodes the total width of the integer. If the first byte is zero, there is no
/// further data and the integer value is zero. Otherwise the index of the lowest bit with value 1
/// of the first byte indicates the width of the remaining integer data:
/// If the lowest bit is set, the integer data is 1 byte wide; if the second bit is set, the
/// integer data is 2 bytes wide etc.   
///
/// See [\[MS-FSSHTTPB\] 2.2.1.1].
///
/// [\[MS-FSSHTTPB\] 2.2.1.1]: https://docs.microsoft.com/en-us/openspecs/sharepoint_protocols/ms-fsshttpb/8eb74ebe-81d1-4569-a29a-308a6128a52f
#[derive(Debug)]
pub(crate) struct CompactU64(u64);

impl CompactU64 {
    pub(crate) fn value(&self) -> u64 {
        self.0
    }

    pub(crate) fn parse(reader: Reader) -> Result<CompactU64> {
        let first_byte = reader
            .bytes()?
            .first()
            .copied()
            .ok_or(ErrorKind::UnexpectedEof)?;

        if first_byte == 0 {
            reader.advance(1)?;

            return Ok(CompactU64(0));
        }

        if first_byte & 1 != 0 {
            return Ok(CompactU64((reader.get_u8()? >> 1) as u64));
        }

        if first_byte & 2 != 0 {
            return Ok(CompactU64((reader.get_u16()? >> 2) as u64));
        }

        if first_byte & 4 != 0 {
            let bytes = reader.peek(3)?;

            let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]);

            reader.advance(3)?;

            return Ok(CompactU64((value >> 3) as u64));
        }

        if first_byte & 8 != 0 {
            let bytes = reader.peek(4)?;

            let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

            reader.advance(4)?;

            return Ok(CompactU64((value >> 4) as u64));
        }

        if first_byte & 16 != 0 {
            let bytes = reader.peek(5)?;

            let value =
                u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], 0, 0, 0]);

            reader.advance(5)?;

            return Ok(CompactU64(value >> 5));
        }

        if first_byte & 32 != 0 {
            let bytes = reader.peek(6)?;

            let value = u64::from_le_bytes([
                first_byte, bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], 0, 0,
            ]);

            reader.advance(6)?;

            return Ok(CompactU64(value >> 6));
        }

        if first_byte & 64 != 0 {
            let bytes = reader.peek(7)?;

            let value = u64::from_le_bytes([
                first_byte, bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], 0,
            ]);

            reader.advance(7)?;

            return Ok(CompactU64(value >> 7));
        }

        if first_byte & 128 != 0 {
            reader.advance(1)?;

            return Ok(CompactU64(reader.get_u64()?));
        }

        Err(ErrorKind::MalformedFssHttpBData(
            format!("unexpected compact u64 type: {:x}", first_byte).into(),
        )
        .into())
    }
}

#[cfg(test)]
mod test {
    use crate::fsshttpb::data::compact_u64::CompactU64;
    use crate::reader::Reader;

    #[test]
    fn test_zero() {
        assert_eq!(
            CompactU64::parse(&mut Reader::new(&[0u8])).unwrap().value(),
            0
        );
    }

    #[test]
    fn test_all_supported_widths() {
        let cases = [
            (1usize, 0x55u64),
            (2, 0x1234),
            (3, 0x12345),
            (4, 0x1234567),
            (5, 0x123456789),
            (6, 0x123456789a),
            (7, 0x123456789ab),
            (8, u64::MAX),
        ];

        for (width, expected) in cases {
            let encoded = if width == 8 {
                let mut encoded = vec![0x80];
                encoded.extend_from_slice(&expected.to_le_bytes());
                encoded
            } else {
                let value = (expected << width) | (1u64 << (width - 1));
                value.to_le_bytes()[..width].to_vec()
            };

            assert_eq!(
                CompactU64::parse(&mut Reader::new(&encoded))
                    .unwrap()
                    .value(),
                expected,
                "compact-u64 width {width}"
            );
        }
    }
}
