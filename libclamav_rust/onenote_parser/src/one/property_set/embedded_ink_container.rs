use crate::errors::{ErrorKind, Result};
use crate::one::property::object_reference::{validate_reference_range, ObjectReference};
use crate::one::property::object_space_reference::{
    validate_reference_range as validate_object_space_reference_range, ObjectSpaceReference,
};
use crate::one::property::{simple, PropertyType};
use crate::onestore::object::Object;
use crate::onestore::types::compact_id::CompactId;
use crate::onestore::types::jcid::JcId;
use crate::onestore::types::object_prop_set::ObjectPropSet;
use crate::onestore::types::prop_set::PropertySet;
use crate::onestore::types::property::PropertyId;
use crate::reader::reserve_collection;

/// An embedded ink handwriting container.
#[derive(Debug)]
pub(crate) struct Data {
    pub(crate) space_width: Option<f32>,
    pub(crate) space_height: Option<f32>,

    pub(crate) start_x: Option<f32>,
    pub(crate) start_y: Option<f32>,
    pub(crate) height: Option<f32>,
    pub(crate) width: Option<f32>,
    pub(crate) offset_horiz: Option<f32>,
    pub(crate) offset_vert: Option<f32>,
}

impl Data {
    pub(crate) fn parse(object: &Object) -> Result<Option<Vec<Data>>> {
        let (prop_id, prop_sets) = match object.props().get(PropertyType::TextRunData) {
            Some(value) => value.to_property_values().ok_or_else(|| {
                ErrorKind::MalformedOneNoteFileData(
                    "embedded ink container is not a property values list".into(),
                )
            })?,
            None => return Ok(None),
        };

        let mut data = Vec::new();
        reserve_collection(&mut data, prop_sets.len())?;
        for props in prop_sets {
            let object = Self::parse_object(object, prop_id, props)?;
            data.push(Self::parse_data(object)?);
        }

        Ok(Some(data))
    }

    fn parse_object<'a>(
        object: &'a Object,
        prop_id: PropertyId,
        props: &PropertySet,
    ) -> Result<Object<'a>> {
        Ok(Object {
            context_id: object.context_id,
            jc_id: JcId(prop_id.value()),
            props: ObjectPropSet {
                object_ids: Self::get_object_ids(props, object)?,
                object_space_ids: Self::get_object_space_ids(props, object)?,
                context_ids: vec![],
                properties: props.clone(),
            },
            file_data: None,
            mapping: object.mapping.clone(),
        })
    }

    fn parse_data(object: Object) -> Result<Data> {
        let space_width = simple::parse_f32(PropertyType::EmbeddedInkSpaceWidth, &object)?;
        let space_height = simple::parse_f32(PropertyType::EmbeddedInkSpaceHeight, &object)?;

        let start_x = simple::parse_f32(PropertyType::EmbeddedInkStartX, &object)?;
        let start_y = simple::parse_f32(PropertyType::EmbeddedInkStartY, &object)?;
        let height = simple::parse_f32(PropertyType::EmbeddedInkHeight, &object)?;
        let width = simple::parse_f32(PropertyType::EmbeddedInkWidth, &object)?;
        let offset_horiz = simple::parse_f32(PropertyType::EmbeddedInkOffsetHoriz, &object)?;
        let offset_vert = simple::parse_f32(PropertyType::EmbeddedInkOffsetVert, &object)?;

        let data = Data {
            space_width,
            space_height,
            start_x,
            start_y,
            height,
            width,
            offset_horiz,
            offset_vert,
        };

        Ok(data)
    }

    fn get_object_ids(props: &PropertySet, object: &Object) -> Result<Vec<CompactId>> {
        let offset = ObjectReference::get_offset(PropertyType::TextRunData, object)?;
        let count = ObjectReference::count_references(props.values())?;
        let end = validate_reference_range(offset, count, object.props.object_ids.len())?;
        let mut object_ids = Vec::new();
        reserve_collection(&mut object_ids, count)?;
        for id in &object.props.object_ids[offset..end] {
            object_ids.push(*id);
        }
        Ok(object_ids)
    }

    fn get_object_space_ids(props: &PropertySet, object: &Object) -> Result<Vec<CompactId>> {
        let offset = ObjectSpaceReference::get_offset(PropertyType::TextRunData, object)?;
        let count = ObjectSpaceReference::count_references(props.values())?;
        let object_space_stream = &object.props.object_space_ids;
        let end = validate_object_space_reference_range(offset, count, object_space_stream.len())?;
        let mut object_space_ids = Vec::new();
        reserve_collection(&mut object_space_ids, count)?;
        for id in &object_space_stream[offset..end] {
            object_space_ids.push(*id);
        }
        Ok(object_space_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::Data;
    use crate::fsshttpb::data::cell_id::CellId;
    use crate::fsshttpb::data::exguid::ExGuid;
    use crate::one::property::PropertyType;
    use crate::onestore::mapping_table::MappingTable;
    use crate::onestore::object::Object;
    use crate::onestore::types::compact_id::CompactId;
    use crate::onestore::types::jcid::JcId;
    use crate::onestore::types::object_prop_set::ObjectPropSet;
    use crate::onestore::types::prop_set::PropertySet;
    use crate::onestore::types::property::PropertyId;
    use crate::shared::guid::Guid;
    use crate::reader::Reader as RawReader;

    fn compact_id(value: u32) -> CompactId {
        CompactId::parse(&mut RawReader::new(&value.to_le_bytes())).expect("compact ID")
    }

    #[test]
    fn object_space_reference_extraction_uses_object_space_stream() {
        let mut parent_bytes = Vec::new();
        parent_bytes.extend_from_slice(&1u16.to_le_bytes());
        parent_bytes.extend_from_slice(&(PropertyType::TextRunData as u32).to_le_bytes());
        parent_bytes.extend_from_slice(&1u32.to_le_bytes());
        parent_bytes.extend_from_slice(&0u32.to_le_bytes());
        parent_bytes.extend_from_slice(&1u16.to_le_bytes());
        parent_bytes.extend_from_slice(&0x2800_0000u32.to_le_bytes());

        let properties = PropertySet::parse(&mut RawReader::new(&parent_bytes))
            .expect("parent property set");
        let (_, property_sets) = properties
            .get(PropertyId::new(PropertyType::TextRunData as u32))
            .and_then(|value| value.to_property_values())
            .expect("text-run property values");
        let child_properties = &property_sets[0];
        let object = Object {
            context_id: ExGuid::from_guid(Guid::nil(), 0),
            jc_id: JcId(0),
            props: ObjectPropSet {
                object_ids: vec![compact_id(0x0000_0201)],
                object_space_ids: vec![compact_id(0x0000_0403)],
                context_ids: Vec::new(),
                properties: properties.clone(),
            },
            file_data: None,
            mapping: MappingTable::from_entries(
                std::iter::empty::<(CompactId, ExGuid)>(),
                std::iter::empty::<(CompactId, CellId)>(),
            )
            .expect("empty mapping table"),
        };

        let extracted = Data::get_object_space_ids(child_properties, &object)
            .expect("object-space IDs");

        assert_eq!(extracted, vec![compact_id(0x0000_0403)]);
    }

    #[test]
    fn object_space_reference_extraction_rejects_a_short_stream() {
        let mut parent_bytes = Vec::new();
        parent_bytes.extend_from_slice(&1u16.to_le_bytes());
        parent_bytes.extend_from_slice(&(PropertyType::TextRunData as u32).to_le_bytes());
        parent_bytes.extend_from_slice(&1u32.to_le_bytes());
        parent_bytes.extend_from_slice(&0u32.to_le_bytes());
        parent_bytes.extend_from_slice(&1u16.to_le_bytes());
        parent_bytes.extend_from_slice(&0x2800_0000u32.to_le_bytes());

        let properties = PropertySet::parse(&mut RawReader::new(&parent_bytes))
            .expect("parent property set");
        let (_, property_sets) = properties
            .get(PropertyId::new(PropertyType::TextRunData as u32))
            .and_then(|value| value.to_property_values())
            .expect("text-run property values");
        let child_properties = &property_sets[0];
        let object = Object {
            context_id: ExGuid::from_guid(Guid::nil(), 0),
            jc_id: JcId(0),
            props: ObjectPropSet {
                object_ids: vec![compact_id(0x0000_0201)],
                object_space_ids: Vec::new(),
                context_ids: Vec::new(),
                properties: properties.clone(),
            },
            file_data: None,
            mapping: MappingTable::from_entries(
                std::iter::empty::<(CompactId, ExGuid)>(),
                std::iter::empty::<(CompactId, CellId)>(),
            )
            .expect("empty mapping table"),
        };

        assert!(Data::get_object_space_ids(child_properties, &object).is_err());
    }
}
