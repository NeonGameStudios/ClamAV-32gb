use crate::errors::Result;
use crate::fsshttpb::data::cell_id::CellId;
use crate::fsshttpb::data::exguid::ExGuid;
use crate::fsshttpb::data::object_types::ObjectType;
use crate::fsshttpb::data::stream_object::ObjectHeader;
use crate::fsshttpb::data_element::DataElement;
use crate::shared::guid::Guid;
use crate::Reader;
use std::collections::HashMap;
use std::hash::Hash;

fn insert_unique<K: Eq + Hash, V>(
    values: &mut HashMap<K, V>,
    key: K,
    value: V,
) -> Result<()> {
    if values.contains_key(&key) {
        return Err(crate::errors::ErrorKind::MalformedFssHttpBData(
            "duplicate storage manifest root".into(),
        )
        .into());
    }

    values.insert(key, value);
    Ok(())
}

/// A storage manifest.
///
/// See [\[MS-FSSHTTPB\] 2.2.1.12.3]
///
/// [\[MS-FSSHTTPB\] 2.2.1.12.3]: https://docs.microsoft.com/en-us/openspecs/sharepoint_protocols/ms-fsshttpb/a681199b-45f3-4378-b929-fb13e674ac5c
#[derive(Debug)]
pub(crate) struct StorageManifest {
    pub(crate) id: Guid,
    pub(crate) roots: HashMap<ExGuid, CellId>,
}

impl DataElement {
    pub(crate) fn parse_storage_manifest(reader: Reader) -> Result<StorageManifest> {
        ObjectHeader::try_parse_16(reader, ObjectType::StorageManifest)?;

        let id = Guid::parse(reader)?;

        let mut roots = HashMap::new();

        loop {
            if ObjectHeader::has_end_8(reader, ObjectType::DataElement)? {
                break;
            }

            ObjectHeader::try_parse_16(reader, ObjectType::StorageManifestRoot)?;

            reader.reserve_next_map(&mut roots)?;

            let root_manifest = ExGuid::parse(reader)?;
            let cell = CellId::parse(reader)?;

            insert_unique(&mut roots, root_manifest, cell)?;
        }

        ObjectHeader::try_parse_end_8(reader, ObjectType::DataElement)?;

        Ok(StorageManifest { id, roots })
    }
}

#[cfg(test)]
mod tests {
    use super::insert_unique;
    use std::collections::HashMap;

    #[test]
    fn duplicate_storage_manifest_root_is_rejected() {
        let mut values = HashMap::new();
        insert_unique(&mut values, 7u8, 1u8).unwrap();

        assert!(insert_unique(&mut values, 7u8, 2u8).is_err());
        assert_eq!(values.get(&7), Some(&1));
    }
}
