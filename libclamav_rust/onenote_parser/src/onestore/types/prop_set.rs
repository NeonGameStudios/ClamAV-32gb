use crate::errors::{ErrorKind, Result};
use crate::onestore::types::property::{PropertyId, PropertyValue};
use crate::Reader;
use std::collections::HashMap;

/// A property set.
///
/// See [\[MS-ONESTORE\] 2.6.7].
///
/// [\[MS-ONESTORE\] 2.6.7]: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/88a64c18-f815-4ebc-8590-ddd432024ab9
#[derive(Debug, Clone)]
pub(crate) struct PropertySet {
    values: HashMap<u32, (usize, PropertyValue)>,
}

impl PropertySet {
    pub(crate) fn parse(reader: Reader) -> Result<PropertySet> {
        Self::parse_at_depth(reader, 0)
    }

    pub(crate) fn parse_at_depth(reader: Reader, depth: usize) -> Result<PropertySet> {
        crate::reader::Reader::check_recursion_depth(depth)?;
        let count = reader.get_u16()? as u64;
        let count = reader.checked_collection_count::<PropertyId>(count)?;

        let mut property_ids = Vec::new();
        reader.reserve_vec(&mut property_ids, count)?;
        for _ in 0..count {
            property_ids.push(PropertyId::parse(reader)?);
        }

        let mut values = HashMap::new();
        reader.reserve_map(&mut values, count)?;
        for (idx, id) in property_ids.into_iter().enumerate() {
            let key = id.id();
            if values.contains_key(&key) {
                return Err(ErrorKind::MalformedOneStoreData(
                    "duplicate property identifier".into(),
                )
                .into());
            }
            values.insert(key, (idx, PropertyValue::parse_at_depth(id, reader, depth)?));
        }

        Ok(PropertySet { values })
    }

    pub(crate) fn get(&self, id: PropertyId) -> Option<&PropertyValue> {
        self.values.get(&id.id()).map(|(_, value)| value)
    }

    pub(crate) fn index(&self, id: PropertyId) -> Option<usize> {
        self.values.get(&id.id()).map(|(index, _)| index).copied()
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &PropertyValue> {
        self.values.values().map(|(_, value)| value)
    }

    pub(crate) fn values_with_index(&self) -> impl Iterator<Item = &(usize, PropertyValue)> {
        self.values.values()
    }
}

#[cfg(test)]
mod tests {
    use super::PropertySet;
    use crate::reader::Reader;
    use crate::one::property::object_reference::ObjectReference;
    use crate::one::property::object_space_reference::ObjectSpaceReference;
    use crate::onestore::types::property::PropertyValue;
    use std::collections::HashMap;

    #[test]
    fn duplicate_property_identifier_is_rejected() {
        let property_id = (1u32 << 26) | 7;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&property_id.to_le_bytes());
        bytes.extend_from_slice(&property_id.to_le_bytes());

        assert!(PropertySet::parse(&mut Reader::new(&bytes)).is_err());
    }

    #[test]
    fn nested_property_set_reference_counting_does_not_recurse() {
        let mut object_value = PropertyValue::ObjectId;
        let mut object_space_value = PropertyValue::ObjectSpaceId;

        for index in 0..2048u32 {
            let mut object_values = HashMap::new();
            object_values.insert(index, (0, object_value));
            object_value = PropertyValue::PropertySet(PropertySet {
                values: object_values,
            });

            let mut object_space_values = HashMap::new();
            object_space_values.insert(index, (0, object_space_value));
            object_space_value = PropertyValue::PropertySet(PropertySet {
                values: object_space_values,
            });
        }

        assert_eq!(
            ObjectReference::count_references(std::iter::once(&object_value)).unwrap(),
            1
        );
        assert_eq!(
            ObjectSpaceReference::count_references(std::iter::once(&object_space_value)).unwrap(),
            1
        );
    }
}
