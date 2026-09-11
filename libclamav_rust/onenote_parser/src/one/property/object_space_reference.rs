use crate::errors::{ErrorKind, Result};
use crate::fsshttpb::data::cell_id::CellId;
use crate::one::property::references::References;
use crate::one::property::PropertyType;
use crate::onestore::object::Object;
use crate::onestore::types::compact_id::CompactId;
use crate::onestore::types::property::PropertyValue;
use crate::reader::reserve_collection;
use std::convert::TryFrom;

/// A generic object space reference.
///
/// This allows for all sorts of object space references (e.g. sections referencing their pages).
/// It implements parsing these references from the OneStore mapping table.
pub(crate) struct ObjectSpaceReference;

impl ObjectSpaceReference {
    pub(crate) fn parse_vec(
        prop_type: PropertyType,
        object: &Object,
    ) -> Result<Option<Vec<CellId>>> {
        // Determine the number of object space references
        let count = match object.props().get(prop_type) {
            Some(prop) => prop.to_object_space_ids().ok_or_else(|| {
                ErrorKind::MalformedOneNoteFileData(
                    "object space reference array is not a object id array".into(),
                )
            })?,
            None => return Ok(None),
        };

        // Determine offset for the property for which we want to look up the object space
        // reference
        let offset = Self::get_offset(prop_type, object)?;

        let references = object.props().object_space_ids();

        // Look up the object space references by offset/count and resolve them
        let count = usize::try_from(count).map_err(|_| {
            ErrorKind::MalformedOneNoteFileData(
                "object space reference count does not fit usize".into(),
            )
        })?;
        let end = validate_reference_range(offset, count, references.len())?;
        let mut object_space_ids = Vec::new();
        reserve_collection(&mut object_space_ids, count)?;
        for (index, id) in references[offset..end].iter().enumerate() {
            object_space_ids.push(Self::resolve_id(index + offset, id, object)?);
        }

        Ok(Some(object_space_ids))
    }

    pub(crate) fn get_offset(prop_type: PropertyType, object: &Object) -> Result<usize> {
        let predecessors = References::get_predecessors(prop_type, object)?;
        let offset = Self::count_references(predecessors)?;

        Ok(offset)
    }

    pub(crate) fn count_references<'a>(
        props: impl Iterator<Item = &'a PropertyValue>,
    ) -> Result<usize> {
        let mut pending: Vec<&PropertyValue> = Vec::new();
        for value in props {
            reserve_collection(&mut pending, 1)?;
            pending.push(value);
        }

        let mut total = 0usize;
        while let Some(value) = pending.pop() {
            match value {
                PropertyValue::ObjectSpaceId => {
                    total = total.checked_add(1).ok_or_else(|| {
                        crate::errors::Error::from(ErrorKind::MalformedOneNoteFileData(
                            "object space reference count overflow".into(),
                        ))
                    })?;
                }
                PropertyValue::ObjectSpaceIds(c) => {
                    let count = usize::try_from(*c).map_err(|_| {
                        ErrorKind::MalformedOneNoteFileData(
                            "object space reference count does not fit usize".into(),
                        )
                    })?;
                    total = total.checked_add(count).ok_or_else(|| {
                        crate::errors::Error::from(ErrorKind::MalformedOneNoteFileData(
                            "object space reference count overflow".into(),
                        ))
                    })?;
                }
                PropertyValue::PropertyValues(_, sets) => {
                    for set in sets {
                        for nested in set.values() {
                            reserve_collection(&mut pending, 1)?;
                            pending.push(nested);
                        }
                    }
                }
                PropertyValue::PropertySet(set) => {
                    for nested in set.values() {
                        reserve_collection(&mut pending, 1)?;
                        pending.push(nested);
                    }
                }
                _ => {}
            }
        }

        Ok(total)
    }

    fn resolve_id(index: usize, id: &CompactId, object: &Object) -> Result<CellId> {
        object
            .mapping()
            .get_object_space(index, *id)
            .ok_or_else(|| ErrorKind::MalformedOneNoteFileData("id not defined in mapping".into()))
            .map_err(|e| e.into())
    }
}

pub(crate) fn validate_reference_range(offset: usize, count: usize, available: usize) -> Result<usize> {
    let end = offset.checked_add(count).ok_or_else(|| {
        ErrorKind::MalformedOneNoteFileData("object space reference range overflow".into())
    })?;
    if end > available {
        return Err(ErrorKind::MalformedOneNoteFileData(
            "object space reference array exceeds object-space-id stream".into(),
        )
        .into());
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::validate_reference_range;
    use super::ObjectSpaceReference;
    use crate::onestore::types::property::PropertyValue;
    use std::convert::TryFrom;

    #[test]
    fn reference_range_rejects_missing_ids() {
        assert!(validate_reference_range(0, 1, 0).is_err());
    }

    #[test]
    fn reference_range_rejects_overflow() {
        assert!(validate_reference_range(usize::MAX, 1, usize::MAX).is_err());
    }

    #[test]
    fn reference_count_uses_checked_usize_conversion() {
        let values = [PropertyValue::ObjectSpaceIds(u32::MAX)];

        assert_eq!(
            ObjectSpaceReference::count_references(values.iter()).unwrap(),
            usize::try_from(u32::MAX).unwrap()
        );
    }
}
