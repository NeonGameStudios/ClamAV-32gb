use crate::errors::{ErrorKind, Result};
use crate::fsshttpb::data::compact_u64::CompactU64;
use crate::fsshttpb::data::exguid::ExGuid;
use crate::fsshttpb::data::object_types::ObjectType;
use crate::fsshttpb::data::stream_object::ObjectHeader;
use crate::fsshttpb::data_element::DataElement;
use crate::reader::ReaderBlob;
use crate::Reader;

fn validate_fragment_range(size: u64, offset: u64, length: u64) -> Result<()> {
    let end = offset.checked_add(length).ok_or_else(|| {
        ErrorKind::MalformedFssHttpBData("data element fragment range overflows".into())
    })?;
    if end > size {
        return Err(ErrorKind::MalformedFssHttpBData(
            "data element fragment range exceeds its declared size".into(),
        )
        .into());
    }
    Ok(())
}

/// A data element fragment.
///
/// See [\[MS-FSSHTTPB\] 2.2.1.12.7].
///
/// [\[MS-FSSHTTPB\] 2.2.1.12.7]: https://docs.microsoft.com/en-us/openspecs/sharepoint_protocols/ms-fsshttpb/9a860e3b-cf61-484b-8ee3-d875afaf7a05
#[derive(Debug)]
pub(crate) struct DataElementFragment {
    pub(crate) id: ExGuid,
    pub(crate) size: u64,
    pub(crate) chunk_reference: DataElementFragmentChunkReference,
    pub(crate) data: ReaderBlob,
}

#[derive(Debug)]
pub(crate) struct DataElementFragmentChunkReference {
    pub(crate) offset: u64,
    pub(crate) length: u64,
}

impl DataElement {
    /// Parse a data element fragment.
    ///
    /// See [\[MS-FSSHTTPB\] 2.2.1.12.7]
    ///
    /// [\[MS-FSSHTTPB\] 2.2.1.12.7]: https://docs.microsoft.com/en-us/openspecs/sharepoint_protocols/ms-fsshttpb/9a860e3b-cf61-484b-8ee3-d875afaf7a05
    pub(crate) fn parse_data_element_fragment(reader: Reader) -> Result<DataElementFragment> {
        ObjectHeader::try_parse(reader, ObjectType::DataElementFragment)?;

        let id = ExGuid::parse(reader)?;
        let size = CompactU64::parse(reader)?.value();
        let offset = CompactU64::parse(reader)?.value();
        let length = CompactU64::parse(reader)?.value();

        validate_fragment_range(size, offset, length)?;
        let data = reader.read_blob(length)?;

        ObjectHeader::try_parse_end_8(reader, ObjectType::DataElement)?;

        let chunk_reference = DataElementFragmentChunkReference { offset, length };
        let fragment = DataElementFragment {
            id,
            size,
            chunk_reference,
            data,
        };

        Ok(fragment)
    }
}

#[cfg(test)]
mod tests {
    use super::validate_fragment_range;
    use crate::fsshttpb::data_element::DataElement;
    use crate::reader::{Reader, ReaderBlob};
    use std::io::{Cursor, Read};

    #[test]
    fn fragment_range_accepts_a_chunk_inside_the_declared_element() {
        assert!(validate_fragment_range(128, 64, 64).is_ok());
    }

    #[test]
    fn fragment_range_rejects_a_chunk_beyond_the_declared_element() {
        assert!(validate_fragment_range(128, 96, 33).is_err());
    }

    #[test]
    fn fragment_range_rejects_offset_overflow() {
        assert!(validate_fragment_range(u64::MAX, u64::MAX, 1).is_err());
    }

    #[test]
    fn fragment_parse_reads_only_the_declared_chunk() {
        let total_size = (256 * 1024 * 1024 + 8) as u64;
        let offset = (256 * 1024 * 1024 + 7) as u64;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&((0x06A_u32 << 3) | 0x2).to_le_bytes());
        encoded.push(0); // nil outer ExGuid
        for value in [total_size, offset, 1] {
            encoded.push(0x80); // compact-u64 64-bit form
            encoded.extend_from_slice(&value.to_le_bytes());
        }
        encoded.push(0xA5);
        encoded.push((0x01u8 << 2) | 0x1); // Data Element End.

        let fragment = DataElement::parse_data_element_fragment(&mut Reader::new(&encoded))
            .expect("small late fragment should parse");

        assert_eq!(fragment.size, total_size);
        assert_eq!(fragment.chunk_reference.offset, offset);
        assert_eq!(fragment.chunk_reference.length, 1);
        let mut data = Vec::new();
        fragment
            .data
            .open_reader()
            .expect("fragment data should be readable")
            .read_to_end(&mut data)
            .expect("fragment data should be complete");
        assert_eq!(data, vec![0xA5]);
    }

    #[test]
    fn fragment_parse_spools_stream_payload_in_refill_sized_chunks() {
        let payload = (0..(Reader::REFILL_SIZE + 17))
            .map(|value| (value % 251) as u8)
            .collect::<Vec<_>>();
        let total_size = payload.len() as u64;
        let offset = 0u64;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&((0x06A_u32 << 3) | 0x2).to_le_bytes());
        encoded.push(0); // nil outer ExGuid
        for value in [total_size, offset, total_size] {
            encoded.push(0x80); // compact-u64 64-bit form
            encoded.extend_from_slice(&value.to_le_bytes());
        }
        encoded.extend_from_slice(&payload);
        encoded.push((0x01u8 << 2) | 0x1); // Data Element End.

        let fragment = DataElement::parse_data_element_fragment(&mut Reader::from_reader(
            Cursor::new(encoded),
        ))
        .expect("stream-backed fragment should parse");

        match &fragment.data {
            ReaderBlob::Spool(spool) => assert_eq!(spool.length(), payload.len() as u64),
            ReaderBlob::Memory(_) => panic!("stream-backed fragments must use a private spool"),
        }

        let mut data = Vec::new();
        fragment
            .data
            .open_reader()
            .expect("fragment spool should open")
            .read_to_end(&mut data)
            .expect("fragment spool should be readable");
        assert_eq!(data, payload);
    }

    #[test]
    fn fragment_parse_rejects_a_missing_data_element_end() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&((0x06A_u32 << 3) | 0x2).to_le_bytes());
        encoded.push(0); // nil outer ExGuid
        encoded.push(0); // zero total size
        encoded.push(0); // zero chunk offset
        encoded.push(0); // zero chunk length

        assert!(DataElement::parse_data_element_fragment(&mut Reader::new(&encoded)).is_err());
    }
}
