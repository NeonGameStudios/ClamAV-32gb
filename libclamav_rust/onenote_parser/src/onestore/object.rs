use crate::errors::{ErrorKind, Result};
use crate::fsshttpb::data::exguid::ExGuid;
use crate::fsshttpb::data_element::object_data_blob::ObjectDataBlob;
use crate::fsshttpb::data_element::object_group::ObjectGroupData;
use crate::fsshttpb::packaging::OneStorePackaging;
use crate::onestore::mapping_table::MappingTable;
use crate::onestore::object_space::GroupData;
use crate::onestore::types::jcid::JcId;
use crate::onestore::types::object_prop_set::ObjectPropSet;
use crate::reader::reserve_collection;

fn validate_reference_stream_lengths(
    object_count: usize,
    object_reference_count: usize,
    context_count: usize,
    context_reference_count: usize,
    object_space_count: usize,
    object_space_reference_count: usize,
) -> Result<()> {
    if object_count != object_reference_count
        || context_count != context_reference_count
        || object_space_count != object_space_reference_count
    {
        return Err(ErrorKind::MalformedOneStoreData(
            "object/reference stream array sizes do not match".into(),
        )
        .into());
    }

    Ok(())
}

/// A OneNote data object.
///
/// See [\[MS-ONESTOR\] 2.1.5] and [\[MS-ONESTOR\] 2.7.6]
///
/// [\[MS-ONESTOR\] 2.1.5]: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/ce60b62f-82e5-401a-bf2c-3255457732ad
/// [\[MS-ONESTOR\] 2.7.6]: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/b4270940-827e-468b-bf42-2c7afee23740
#[derive(Debug, Clone)]
pub(crate) struct Object<'a> {
    pub(crate) context_id: ExGuid,

    pub(crate) jc_id: JcId,
    pub(crate) props: ObjectPropSet,
    pub(crate) file_data: Option<&'a ObjectDataBlob>,
    pub(crate) mapping: MappingTable,
}

#[derive(Debug, Copy, Clone)]
enum Partition {
    Metadata = 4,
    ObjectData = 1,
    FileData = 2,
}

impl<'a> Object<'a> {
    pub(crate) fn id(&self) -> JcId {
        self.jc_id
    }

    pub(crate) fn context_id(&self) -> ExGuid {
        self.context_id
    }

    pub(crate) fn props(&self) -> &ObjectPropSet {
        &self.props
    }

    pub(crate) fn file_data(&self) -> Option<&ObjectDataBlob> {
        self.file_data
    }

    pub(crate) fn mapping(&self) -> &MappingTable {
        &self.mapping
    }
}

impl<'a> Object<'a> {
    pub(crate) fn parse<'b>(
        object_id: ExGuid,
        context_id: ExGuid,
        object_space_id: ExGuid,
        objects: &'b GroupData,
        packaging: &'a OneStorePackaging,
    ) -> Result<Object<'a>> {
        let metadata_object = Object::find_object(object_id, Partition::Metadata, objects)
            .ok_or_else(|| ErrorKind::MalformedOneStoreData("object metadata is missing".into()))?;
        let data_object = Object::find_object(object_id, Partition::ObjectData, objects)
            .ok_or_else(|| ErrorKind::MalformedOneStoreData("object data is missing".into()))?;

        // Parse metadata

        let metadata = if let ObjectGroupData::Object { data, .. } = metadata_object {
            data
        } else {
            return Err(ErrorKind::MalformedOneStoreData(
                "object metadata it not an object".into(),
            )
            .into());
        };

        let mut metadata_reader = metadata.open_reader_with_spool_options()?;
        let jc_id = JcId::parse(&mut metadata_reader)?;

        // Parse data

        let (data, object_refs, referenced_cells) =
            if let ObjectGroupData::Object { group, cells, data } = data_object {
                (data, group, cells)
            } else {
                return Err(ErrorKind::MalformedOneStoreData(
                    "object data it not an object".into(),
                )
                .into());
            };

        let mut data_reader = data.open_reader_with_spool_options()?;
        let props = ObjectPropSet::parse(&mut data_reader)?;

        // Parse file data

        let file_data = Object::find_blob_id(object_id, objects)?
            .map(|blob_id| {
                packaging
                    .data_element_package
                    .find_blob(blob_id)
                    .ok_or_else(|| ErrorKind::MalformedOneStoreData("blob not found".into()))
            })
            .transpose()?;

        let mut context_refs = Vec::new();
        let mut object_space_refs = Vec::new();
        reserve_collection(&mut context_refs, referenced_cells.len())?;
        reserve_collection(&mut object_space_refs, referenced_cells.len())?;
        for id in referenced_cells {
            if id.1 == object_space_id {
                context_refs.push(id.0);
            } else {
                object_space_refs.push(*id);
            }
        }

        validate_reference_stream_lengths(
            props.object_ids().len(),
            object_refs.len(),
            props.context_ids().len(),
            context_refs.len(),
            props.object_space_ids().len(),
            object_space_refs.len(),
        )?;

        let mapping_objects = props
            .object_ids()
            .iter()
            .copied()
            .zip(object_refs.iter().copied());

        let mapping_contexts = props.context_ids().iter().copied().zip(context_refs);

        let mapping_object_spaces = props
            .object_space_ids()
            .iter()
            .copied()
            .zip(object_space_refs);

        let mapping = MappingTable::from_entries(
            mapping_objects.chain(mapping_contexts),
            mapping_object_spaces,
        )?;

        Ok(Object {
            context_id,
            jc_id,
            props,
            file_data,
            mapping,
        })
    }

    fn find_object<'b>(
        id: ExGuid,
        partition_id: Partition,
        objects: &'b GroupData,
    ) -> Option<&'b ObjectGroupData> {
        objects.get(&(id, partition_id as u64)).cloned()
    }

    fn find_blob_id(id: ExGuid, objects: &'a GroupData) -> Result<Option<ExGuid>> {
        Self::find_object(id, Partition::FileData, objects)
            .map(|object| match object {
                ObjectGroupData::BlobReference { blob, .. } => Ok(*blob),
                _ => {
                    Err(ErrorKind::MalformedOneStoreData("blob object is not a blob".into()).into())
                }
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::validate_reference_stream_lengths;

    #[test]
    fn reference_stream_lengths_accept_matching_kinds() {
        assert!(validate_reference_stream_lengths(1, 1, 2, 2, 3, 3).is_ok());
    }

    #[test]
    fn reference_stream_lengths_reject_swapped_kinds() {
        // A total-count check alone would accept this malformed mapping and
        // zip each compact-ID stream with the wrong kind of CellId.
        assert!(validate_reference_stream_lengths(1, 1, 2, 3, 3, 2).is_err());
    }

    #[test]
    fn reference_stream_lengths_reject_a_short_kind() {
        assert!(validate_reference_stream_lengths(1, 1, 0, 0, 1, 0).is_err());
    }

    #[test]
    fn reference_stream_lengths_reject_surplus_object_ids() {
        assert!(validate_reference_stream_lengths(2, 1, 0, 0, 0, 0).is_err());
    }
}
