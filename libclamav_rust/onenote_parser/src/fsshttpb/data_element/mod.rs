use crate::errors::{ErrorKind, Result};
use crate::fsshttpb::data::compact_u64::CompactU64;
use crate::fsshttpb::data::exguid::ExGuid;
use crate::fsshttpb::data::object_types::ObjectType;
use crate::fsshttpb::data::serial_number::SerialNumber;
use crate::fsshttpb::data::stream_object::ObjectHeader;
use crate::fsshttpb::data_element::data_element_fragment::DataElementFragment;
use crate::fsshttpb::data_element::object_data_blob::ObjectDataBlob;
use crate::fsshttpb::data_element::object_group::ObjectGroup;
use crate::fsshttpb::data_element::revision_manifest::RevisionManifest;
use crate::fsshttpb::data_element::storage_index::StorageIndex;
use crate::fsshttpb::data_element::storage_manifest::StorageManifest;
use crate::reader::collect_results;
use crate::Reader;
use std::collections::HashMap;
use std::hash::Hash;
use std::fmt::Debug;

pub(crate) mod cell_manifest;
pub(crate) mod data_element_fragment;
pub(crate) mod object_data_blob;
pub(crate) mod object_group;
pub(crate) mod revision_manifest;
pub(crate) mod storage_index;
pub(crate) mod storage_manifest;

/// A FSSHTTPB data element package.
///
/// See [\[MS-FSSHTTPB\] 2.2.1.12].
///
/// [\[MS-FSSHTTPB\] 2.2.1.12]: https://docs.microsoft.com/en-us/openspecs/sharepoint_protocols/ms-fsshttpb/99a25464-99b5-4262-a964-baabed2170eb
#[derive(Debug)]
pub(crate) struct DataElementPackage {
    pub(crate) storage_indexes: HashMap<ExGuid, StorageIndex>,
    pub(crate) storage_manifests: HashMap<ExGuid, StorageManifest>,
    pub(crate) cell_manifests: HashMap<ExGuid, ExGuid>,
    pub(crate) revision_manifests: HashMap<ExGuid, RevisionManifest>,
    pub(crate) object_groups: HashMap<ExGuid, ObjectGroup>,
    pub(crate) data_element_fragments: HashMap<ExGuid, DataElementFragment>,
    pub(crate) object_data_blobs: HashMap<ExGuid, ObjectDataBlob>,
}

fn insert_unique<K: Eq + Hash, V>(
    values: &mut HashMap<K, V>,
    key: K,
    value: V,
) -> Result<()> {
    if values.contains_key(&key) {
        return Err(ErrorKind::MalformedFssHttpBData(
            "duplicate data element identifier".into(),
        )
        .into());
    }

    values.insert(key, value);

    Ok(())
}

impl DataElementPackage {
    pub(crate) fn parse(reader: Reader) -> Result<DataElementPackage> {
        ObjectHeader::try_parse_16(reader, ObjectType::DataElementPackage)?;

        if reader.get_u8()? != 0 {
            return Err(ErrorKind::MalformedFssHttpBData("invalid padding byte".into()).into());
        }

        let mut package = DataElementPackage {
            storage_indexes: Default::default(),
            storage_manifests: Default::default(),
            cell_manifests: Default::default(),
            revision_manifests: Default::default(),
            object_groups: Default::default(),
            data_element_fragments: Default::default(),
            object_data_blobs: Default::default(),
        };

        loop {
            if ObjectHeader::has_end_8(reader, ObjectType::DataElementPackage)? {
                break;
            }

            DataElement::parse(reader, &mut package)?
        }

        ObjectHeader::try_parse_end_8(reader, ObjectType::DataElementPackage)?;

        Ok(package)
    }

    /// Look up the object groups referenced by a cell.
    pub(crate) fn find_objects(
        &self,
        cell: ExGuid,
        storage_index: &StorageIndex,
    ) -> Result<Vec<&ObjectGroup>> {
        let revision_id = self
            .find_cell_revision_id(cell)
            .ok_or_else(|| ErrorKind::MalformedFssHttpBData("cell revision id not found".into()))?;
        let revision_mapping_id = storage_index
            .find_revision_mapping_id(revision_id)
            .ok_or_else(|| {
                ErrorKind::MalformedFssHttpBData("revision mapping id not found".into())
            })?;
        let revision_manifest = self
            .find_revision_manifest(revision_mapping_id)
            .ok_or_else(|| {
                ErrorKind::MalformedFssHttpBData("revision manifest not found".into())
            })?;

        collect_results(revision_manifest.group_references.iter().map(|reference| {
            self.find_object_group(*reference).ok_or_else(|| {
                ErrorKind::MalformedFssHttpBData("object group not found".into()).into()
            })
        }))
    }

    /// Look up a blob by its ID.
    pub(crate) fn find_blob(&self, id: ExGuid) -> Option<&[u8]> {
        self.object_data_blobs.get(&id).map(|blob| blob.value())
    }

    /// Look up the storage index referenced by the packaging header.
    pub(crate) fn find_storage_index(&self, id: ExGuid) -> Option<&StorageIndex> {
        self.storage_indexes.get(&id)
    }

    /// Resolve the storage manifest through the storage-index mapping.
    pub(crate) fn find_storage_manifest(
        &self,
        storage_index: &StorageIndex,
    ) -> Result<Option<&StorageManifest>> {
        match storage_index.manifest_mappings.as_slice() {
            [] => match self.storage_manifests.len() {
                0 => Ok(None),
                1 => Ok(self.storage_manifests.values().next()),
                _ => Err(ErrorKind::MalformedFssHttpBData(
                    "storage manifest is ambiguous without a mapping".into(),
                )
                .into()),
            },
            [mapping] => Ok(self.storage_manifests.get(&mapping.mapping_id)),
            _ => Err(ErrorKind::MalformedFssHttpBData(
                "multiple storage manifest mappings are not supported".into(),
            )
            .into()),
        }
    }

    /// Look up a cell revision ID by the cell's manifest ID.
    pub(crate) fn find_cell_revision_id(&self, id: ExGuid) -> Option<ExGuid> {
        self.cell_manifests.get(&id).copied()
    }

    /// Look up a revision manifest by its ID.
    pub(crate) fn find_revision_manifest(&self, id: ExGuid) -> Option<&RevisionManifest> {
        self.revision_manifests.get(&id)
    }

    /// Look up an object group by its ID.
    pub(crate) fn find_object_group(&self, id: ExGuid) -> Option<&ObjectGroup> {
        self.object_groups.get(&id)
    }
}

/// A parser for a single data element.
///
/// See [\[MS-FSSHTTPB\] 2.2.1.12.1]
///
/// [\[MS-FSSHTTPB\] 2.2.1.12.1]: https://docs.microsoft.com/en-us/openspecs/sharepoint_protocols/ms-fsshttpb/f0901ac0-4f26-413f-805b-a6830781f64c
#[derive(Debug)]
pub(crate) struct DataElement;

impl DataElement {
    pub(crate) fn parse(reader: Reader, package: &mut DataElementPackage) -> Result<()> {
        ObjectHeader::try_parse_16(reader, ObjectType::DataElement)?;

        let id = ExGuid::parse(reader)?;
        let _serial = SerialNumber::parse(reader)?;
        let element_type = CompactU64::parse(reader)?;

        match element_type.value() {
            0x01 => {
                reader.reserve_next_map(&mut package.storage_indexes)?;
                insert_unique(
                    &mut package.storage_indexes,
                    id,
                    Self::parse_storage_index(reader)?,
                )?;
            }
            0x02 => {
                reader.reserve_next_map(&mut package.storage_manifests)?;
                insert_unique(
                    &mut package.storage_manifests,
                    id,
                    Self::parse_storage_manifest(reader)?,
                )?;
            }
            0x03 => {
                reader.reserve_next_map(&mut package.cell_manifests)?;
                insert_unique(
                    &mut package.cell_manifests,
                    id,
                    Self::parse_cell_manifest(reader)?,
                )?;
            }
            0x04 => {
                reader.reserve_next_map(&mut package.revision_manifests)?;
                insert_unique(
                    &mut package.revision_manifests,
                    id,
                    Self::parse_revision_manifest(reader)?,
                )?;
            }
            0x05 => {
                reader.reserve_next_map(&mut package.object_groups)?;
                insert_unique(
                    &mut package.object_groups,
                    id,
                    Self::parse_object_group(reader)?,
                )?;
            }
            0x06 => {
                reader.reserve_next_map(&mut package.data_element_fragments)?;
                insert_unique(
                    &mut package.data_element_fragments,
                    id,
                    Self::parse_data_element_fragment(reader)?,
                )?;
            }
            0x0A => {
                reader.reserve_next_map(&mut package.object_data_blobs)?;
                insert_unique(
                    &mut package.object_data_blobs,
                    id,
                    Self::parse_object_data_blob(reader)?,
                )?;
            }
            x => {
                return Err(ErrorKind::MalformedFssHttpBData(
                    format!("invalid element type: 0x{:X}", x).into(),
                )
                .into())
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{insert_unique, DataElementPackage};
    use crate::fsshttpb::data::exguid::ExGuid;
    use crate::fsshttpb::data_element::storage_index::{
        StorageIndex, StorageIndexManifestMapping,
    };
    use crate::fsshttpb::data_element::storage_manifest::StorageManifest;
    use crate::fsshttpb::data::serial_number::SerialNumber;
    use crate::shared::guid::Guid;
    use std::collections::HashMap;

    #[test]
    fn duplicate_data_element_identifier_is_rejected() {
        let mut values = HashMap::new();
        insert_unique(&mut values, 7u8, 1u8).unwrap();

        assert!(insert_unique(&mut values, 7u8, 2u8).is_err());
        assert_eq!(values.get(&7), Some(&1));
    }

    #[test]
    fn storage_index_lookup_uses_the_packaging_reference() {
        let first_id = ExGuid {
            guid: Guid::nil(),
            value: 1,
        };
        let selected_id = ExGuid {
            guid: Guid::nil(),
            value: 2,
        };
        let mut storage_indexes = HashMap::new();
        storage_indexes.insert(
            first_id,
            StorageIndex {
                manifest_mappings: Vec::new(),
                cell_mappings: HashMap::new(),
                revision_mappings: HashMap::new(),
            },
        );
        storage_indexes.insert(
            selected_id,
            StorageIndex {
                manifest_mappings: Vec::new(),
                cell_mappings: HashMap::new(),
                revision_mappings: HashMap::new(),
            },
        );

        let package = DataElementPackage {
            storage_indexes,
            storage_manifests: HashMap::new(),
            cell_manifests: HashMap::new(),
            revision_manifests: HashMap::new(),
            object_groups: HashMap::new(),
            data_element_fragments: HashMap::new(),
            object_data_blobs: HashMap::new(),
        };

        let selected = package
            .find_storage_index(selected_id)
            .expect("referenced storage index should be found");
        assert!(std::ptr::eq(
            selected,
            package.storage_indexes.get(&selected_id).unwrap()
        ));
        assert!(!std::ptr::eq(
            selected,
            package.storage_indexes.get(&first_id).unwrap()
        ));
    }

    #[test]
    fn storage_manifest_lookup_uses_the_index_mapping() {
        let mapped_id = ExGuid {
            guid: Guid::nil(),
            value: 2,
        };
        let other_id = ExGuid {
            guid: Guid::nil(),
            value: 3,
        };
        let index = StorageIndex {
            manifest_mappings: vec![StorageIndexManifestMapping {
                mapping_id: mapped_id,
                serial: SerialNumber {
                    guid: Guid::nil(),
                    serial: 1,
                },
            }],
            cell_mappings: HashMap::new(),
            revision_mappings: HashMap::new(),
        };
        let mut manifests = HashMap::new();
        manifests.insert(
            mapped_id,
            StorageManifest {
                id: Guid::nil(),
                roots: HashMap::new(),
            },
        );
        manifests.insert(
            other_id,
            StorageManifest {
                id: Guid::nil(),
                roots: HashMap::new(),
            },
        );
        let package = DataElementPackage {
            storage_indexes: HashMap::new(),
            storage_manifests: manifests,
            cell_manifests: HashMap::new(),
            revision_manifests: HashMap::new(),
            object_groups: HashMap::new(),
            data_element_fragments: HashMap::new(),
            object_data_blobs: HashMap::new(),
        };

        let selected = package
            .find_storage_manifest(&index)
            .unwrap()
            .expect("mapped storage manifest should be found");
        assert!(std::ptr::eq(
            selected,
            package.storage_manifests.get(&mapped_id).unwrap()
        ));
    }

    #[test]
    fn storage_manifest_lookup_rejects_ambiguous_unmapped_manifests() {
        let mut manifests = HashMap::new();
        for value in [1, 2] {
            manifests.insert(
                ExGuid {
                    guid: Guid::nil(),
                    value,
                },
                StorageManifest {
                    id: Guid::nil(),
                    roots: HashMap::new(),
                },
            );
        }
        let package = DataElementPackage {
            storage_indexes: HashMap::new(),
            storage_manifests: manifests,
            cell_manifests: HashMap::new(),
            revision_manifests: HashMap::new(),
            object_groups: HashMap::new(),
            data_element_fragments: HashMap::new(),
            object_data_blobs: HashMap::new(),
        };
        let index = StorageIndex {
            manifest_mappings: Vec::new(),
            cell_mappings: HashMap::new(),
            revision_mappings: HashMap::new(),
        };

        assert!(package.find_storage_manifest(&index).is_err());
    }
}
