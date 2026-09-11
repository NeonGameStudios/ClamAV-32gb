use crate::errors::{ErrorKind, Result};
use crate::fsshttpb::data::exguid::ExGuid;
use crate::fsshttpb::data::object_types::ObjectType;
use crate::fsshttpb::data::stream_object::ObjectHeader;
use crate::fsshttpb::data_element::DataElementPackage;
use crate::shared::guid::Guid;
use crate::Reader;

/// A OneNote file packaged in FSSHTTPB format.
///
/// See [\[MS-ONESTORE\] 2.8.1]
///
/// [\[MS-ONESTORE\] 2.8.1]: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/a2f046ea-109a-49c4-912d-dc2888cf0565
#[derive(Debug)]
pub(crate) struct OneStorePackaging {
    pub(crate) file_type: Guid,
    pub(crate) file: Guid,
    pub(crate) legacy_file_version: Guid,
    pub(crate) file_format: Guid,
    pub(crate) storage_index: ExGuid,
    pub(crate) cell_schema: Guid,
    pub(crate) data_element_package: DataElementPackage,
}

impl OneStorePackaging {
    pub(crate) fn parse(reader: Reader) -> Result<OneStorePackaging> {
        let file_type = Guid::parse(reader)?;
        let file = Guid::parse(reader)?;
        let legacy_file_version = Guid::parse(reader)?;
        let file_format = Guid::parse(reader)?;

        validate_packaging_guids(file_type, file_format)?;

        if reader.get_u32()? != 0 {
            return Err(ErrorKind::MalformedFssHttpBData("invalid padding data".into()).into());
        }

        ObjectHeader::try_parse_32(reader, ObjectType::OneNotePackaging)?;

        let storage_index = ExGuid::parse(reader)?;
        let cell_schema = Guid::parse(reader)?;
        validate_cell_schema(cell_schema)?;

        let data_element_package = DataElementPackage::parse(reader)?;

        ObjectHeader::try_parse_end_16(reader, ObjectType::OneNotePackaging)?;

        Ok(OneStorePackaging {
            file_type,
            file,
            legacy_file_version,
            file_format,
            storage_index,
            cell_schema,
            data_element_package,
        })
    }
}

fn validate_packaging_guids(file_type: Guid, file_format: Guid) -> Result<()> {
    if file_type != file_type_guid() {
        return Err(ErrorKind::MalformedOneStoreData("invalid file type GUID".into()).into());
    }

    if file_format != file_format_guid() {
        return Err(ErrorKind::MalformedOneStoreData("invalid file format GUID".into()).into());
    }

    Ok(())
}

fn file_type_guid() -> Guid {
    Guid::from_str("7B5C52E4-D88C-4DA7-AEB1-5378D02996D3").unwrap()
}

fn file_format_guid() -> Guid {
    Guid::from_str("638DE92F-A6D4-4BC1-9A36-B3FC2511A5B7").unwrap()
}

fn validate_cell_schema(cell_schema: Guid) -> Result<()> {
    if cell_schema != section_schema_guid() && cell_schema != toc_schema_guid() {
        return Err(ErrorKind::MalformedOneStoreData(
            "invalid cell schema GUID".into(),
        )
        .into());
    }

    Ok(())
}

fn section_schema_guid() -> Guid {
    Guid::from_str("1F937CB4-B26F-445F-B9F8-17E20160E461").unwrap()
}

fn toc_schema_guid() -> Guid {
    Guid::from_str("E4DBFD38-E5C7-408B-A8A1-0E7B421E1F5F").unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append_guid(bytes: &mut Vec<u8>, guid: Guid) {
        let value = guid.0.as_bytes();
        bytes.extend_from_slice(&[
            value[3], value[2], value[1], value[0], value[5], value[4], value[7], value[6],
            value[8], value[9], value[10], value[11], value[12], value[13], value[14], value[15],
        ]);
    }

    fn minimal_packaging(file: Guid, legacy_file_version: Guid, cell_schema: Guid) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_guid(&mut bytes, file_type_guid());
        append_guid(&mut bytes, file);
        append_guid(&mut bytes, legacy_file_version);
        append_guid(&mut bytes, file_format_guid());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        // Packaging Start: 32-bit header, compound OneNote packaging object.
        bytes.extend_from_slice(&((0x7Au32 << 3) | 0x6).to_le_bytes());
        bytes.push(0); // Null storage-index ExGuid.
        append_guid(&mut bytes, cell_schema);

        // Empty Data Element Package.
        bytes.extend_from_slice(&((0x15u16 << 3) | 0x4).to_le_bytes());
        bytes.push(0);
        bytes.push((0x15u8 << 2) | 0x1);

        // Packaging End: 16-bit end header for OneNote packaging.
        bytes.extend_from_slice(&0x1EBu16.to_le_bytes());
        bytes
    }

    #[test]
    fn accepts_distinct_file_and_legacy_version_guids() {
        let file = Guid::from_str("11111111-2222-3333-4444-555555555555").unwrap();
        let legacy_file_version = Guid::from_str("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE").unwrap();

        let bytes = minimal_packaging(
            file,
            legacy_file_version,
            section_schema_guid(),
        );
        let parsed = OneStorePackaging::parse(&mut crate::reader::Reader::new(&bytes))
        .expect("valid packaging with independent identity and version GUIDs");

        assert_eq!(parsed.file, file);
        assert_eq!(parsed.legacy_file_version, legacy_file_version);
    }

    #[test]
    fn rejects_invalid_fixed_packaging_guids() {
        assert!(validate_packaging_guids(Guid::nil(), Guid::nil()).is_err());
        assert!(validate_packaging_guids(
            file_type_guid(),
            Guid::nil(),
        )
        .is_err());
    }

    #[test]
    fn rejects_unknown_cell_schema_guid() {
        let bytes = minimal_packaging(
            Guid::from_str("11111111-2222-3333-4444-555555555555").unwrap(),
            Guid::from_str("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE").unwrap(),
            Guid::nil(),
        );

        assert!(OneStorePackaging::parse(&mut crate::reader::Reader::new(&bytes)).is_err());
    }
}
