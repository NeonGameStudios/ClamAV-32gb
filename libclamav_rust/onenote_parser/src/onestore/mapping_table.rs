use crate::errors::{ErrorKind, Result};
use crate::fsshttpb::data::cell_id::CellId;
use crate::fsshttpb::data::exguid::ExGuid;
use crate::onestore::types::compact_id::CompactId;
use crate::reader::Reader;
use std::collections::HashMap;
use std::hash::Hash;
use std::mem::size_of;

/// The ID mapping table for an object.
///
/// The specification isn't really clear on how the mapping table works. According to the spec,
/// the mapping table maps from `CompactId`s to `ExGuid`s for objects and `CellId`s for object
/// spaces. BUT while it specifies how to build the mapping table, it doesn't mention how it
/// is used. From testing it looks like there cases where a single `CompactId` maps to *multiple*
/// `ExGuid`s/`CellId`s. In this case we will use the table _index_ as a fallback.
///
/// See [\[MS-ONESTORE\] 2.7.8].
///
/// [\[MS-ONESTORE\] 2.7.8]: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/c2e58ac6-7a86-4009-a1e4-4a84cd21508f
#[derive(Debug, Clone)]
pub(crate) struct MappingTable {
    objects: HashMap<CompactId, Vec<(usize, ExGuid)>>,
    object_spaces: HashMap<CompactId, Vec<(usize, CellId)>>,
}

impl MappingTable {
    pub(crate) fn from_entries<
        I: Iterator<Item = (CompactId, ExGuid)>,
        J: Iterator<Item = (CompactId, CellId)>,
    >(
        objects: I,
        object_spaces: J,
    ) -> Result<MappingTable> {
        let mut objects_map: HashMap<CompactId, Vec<(usize, ExGuid)>> = HashMap::new();
        for (i, (cid, id)) in objects.enumerate() {
            reserve_next_map(&mut objects_map)?;
            let entries = objects_map.entry(cid).or_default();
            reserve_next_vec(entries)?;
            entries.push((i, id));
        }

        let mut object_spaces_map: HashMap<CompactId, Vec<(usize, CellId)>> = HashMap::new();
        for (i, (cid, id)) in object_spaces.enumerate() {
            reserve_next_map(&mut object_spaces_map)?;
            let entries = object_spaces_map.entry(cid).or_default();
            reserve_next_vec(entries)?;
            entries.push((i, id));
        }

        Ok(MappingTable {
            objects: objects_map,
            object_spaces: object_spaces_map,
        })
    }

    pub(crate) fn get_object(&self, index: usize, cid: CompactId) -> Option<ExGuid> {
        self.get(index, cid, &self.objects)
    }

    pub(crate) fn get_object_space(&self, index: usize, cid: CompactId) -> Option<CellId> {
        self.get(index, cid, &self.object_spaces)
    }

    fn get<T: Copy>(
        &self,
        index: usize,
        cid: CompactId,
        table: &HashMap<CompactId, Vec<(usize, T)>>,
    ) -> Option<T> {
        if let Some(entries) = table.get(&cid) {
            // Only one entry: return it!
            if let [(_, id)] = &**entries {
                return Some(*id);
            }

            // Find entry with matching table index
            if let Some((_, id)) = entries.iter().find(|(i, _)| *i == index) {
                return Some(*id);
            }
        }

        None
    }
}

fn reserve_next_vec<T>(values: &mut Vec<T>) -> Result<()> {
    let next = values.len().checked_add(1).ok_or(ErrorKind::CollectionLimit {
        requested: usize::MAX,
        max: Reader::MAX_COLLECTION_BYTES,
    })?;
    let requested = next
        .checked_mul(size_of::<T>())
        .ok_or(ErrorKind::CollectionLimit {
            requested: usize::MAX,
            max: Reader::MAX_COLLECTION_BYTES,
        })?;
    if requested > Reader::MAX_COLLECTION_BYTES {
        return Err(ErrorKind::CollectionLimit {
            requested,
            max: Reader::MAX_COLLECTION_BYTES,
        }
        .into());
    }
    values
        .try_reserve(1)
        .map_err(|_| ErrorKind::AllocationFailed { requested })?;
    Ok(())
}

fn reserve_next_map<K: Eq + Hash, V>(values: &mut HashMap<K, V>) -> Result<()> {
    let next = values.len().checked_add(1).ok_or(ErrorKind::CollectionLimit {
        requested: usize::MAX,
        max: Reader::MAX_COLLECTION_BYTES,
    })?;
    let requested = next
        .checked_mul(size_of::<(K, V)>())
        .ok_or(ErrorKind::CollectionLimit {
            requested: usize::MAX,
            max: Reader::MAX_COLLECTION_BYTES,
        })?;
    if requested > Reader::MAX_COLLECTION_BYTES {
        return Err(ErrorKind::CollectionLimit {
            requested,
            max: Reader::MAX_COLLECTION_BYTES,
        }
        .into());
    }
    values
        .try_reserve(1)
        .map_err(|_| ErrorKind::AllocationFailed { requested })?;
    Ok(())
}
