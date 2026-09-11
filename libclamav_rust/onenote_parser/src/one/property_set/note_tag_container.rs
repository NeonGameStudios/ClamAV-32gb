use crate::errors::{ErrorKind, Result};
use crate::fsshttpb::data::exguid::ExGuid;
use crate::one::property::note_tag::ActionItemStatus;
use crate::one::property::object_reference::{validate_reference_range, ObjectReference};
use crate::one::property::object_space_reference::{
    validate_reference_range as validate_object_space_reference_range, ObjectSpaceReference,
};
use crate::one::property::time::Time;
use crate::one::property::PropertyType;
use crate::onestore::object::Object;
use crate::onestore::types::compact_id::CompactId;
use crate::onestore::types::jcid::JcId;
use crate::onestore::types::object_prop_set::ObjectPropSet;
use crate::onestore::types::prop_set::PropertySet;
use crate::onestore::types::property::PropertyId;
use crate::reader::reserve_collection;

/// A note tag state container.
///
/// See [\[MS-ONE\] 2.2.88].
///
/// [\[MS-ONE\] 2.2.88]: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-one/a9938236-87f8-41b1-81f3-5f760e1247b8
#[derive(Debug)]
pub(crate) struct Data {
    pub(crate) definition: Option<ExGuid>,
    pub(crate) created_at: Time,
    pub(crate) completed_at: Option<Time>,
    pub(crate) item_status: ActionItemStatus,
}

impl Data {
    pub(crate) fn parse(object: &Object) -> Result<Option<Vec<Data>>> {
        let (prop_id, prop_sets) = match object.props().get(PropertyType::NoteTags) {
            Some(value) => value.to_property_values().ok_or_else(|| {
                ErrorKind::MalformedOneNoteFileData(
                    "note tag state is not a property values list".into(),
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

    fn parse_data(object: Object) -> Result<Data> {
        let definition = ObjectReference::parse(PropertyType::NoteTagDefinitionOid, &object)?;

        let created_at = Time::parse(PropertyType::NoteTagCreated, &object)?.ok_or_else(|| {
            ErrorKind::MalformedOneNoteFileData("note tag has no created at time".into())
        })?;

        let completed_at = Time::parse(PropertyType::NoteTagCompleted, &object)?;

        let item_status = ActionItemStatus::parse(&object)?.ok_or_else(|| {
            ErrorKind::MalformedOneNoteFileData("note tag container has no item status".into())
        })?;

        Ok(Data {
            definition,
            created_at,
            completed_at,
            item_status,
        })
    }

    fn parse_object<'a>(
        object: &'a Object,
        id: PropertyId,
        props: &PropertySet,
    ) -> Result<Object<'a>> {
        Ok(Object {
            context_id: object.context_id,
            jc_id: JcId(id.value()),
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

    fn get_object_ids(props: &PropertySet, object: &Object) -> Result<Vec<CompactId>> {
        let offset = ObjectReference::get_offset(PropertyType::NoteTags, object)?;
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
        let offset = ObjectSpaceReference::get_offset(PropertyType::NoteTags, object)?;
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
