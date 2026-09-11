use crate::errors::{ErrorKind, Result};
use crate::fsshttpb::data::cell_id::CellId;
use crate::fsshttpb::data::exguid::ExGuid;
use crate::fsshttpb::data_element::object_group::ObjectGroupData;
use crate::fsshttpb::data_element::storage_index::{StorageIndex, StorageIndexCellMapping};
use crate::fsshttpb::packaging::OneStorePackaging;
use crate::onestore::object::Object;
use crate::onestore::revision::Revision;
use crate::onestore::revision_role::RevisionRole;
use crate::reader::{reserve_collection_set, Reader};
use std::collections::{HashMap, HashSet};

pub(crate) type GroupData<'a> = HashMap<(ExGuid, u64), &'a ObjectGroupData>;

/// A OneNote object space.
///
/// Typically this is a section's metadata or a page and its content.
///
/// See [\[MS-ONESTOR\] 2.1.4]
///
/// [\[MS-ONESTOR\] 2.1.4]: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/1329433f-02a5-4e83-ab41-80d57ade38d9
#[derive(Debug)]
pub(crate) struct ObjectSpace<'a> {
    id: ExGuid,
    context: ExGuid,
    roots: HashMap<RevisionRole, ExGuid>,
    objects: HashMap<ExGuid, Object<'a>>,
}

impl<'a, 'b> ObjectSpace<'a> {
    pub(crate) fn get_object(&self, id: ExGuid) -> Option<&Object> {
        self.objects.get(&id)
    }

    pub(crate) fn content_root(&self) -> Option<ExGuid> {
        self.roots.get(&RevisionRole::DefaultContent).copied()
    }

    pub(crate) fn metadata_root(&self) -> Option<ExGuid> {
        self.roots.get(&RevisionRole::Metadata).copied()
    }

    pub(crate) fn parse(
        mapping: &'a StorageIndexCellMapping,
        storage_index: &'a StorageIndex,
        packaging: &'a OneStorePackaging,
        revision_cache: &'b mut HashMap<CellId, Revision<'a>>,
    ) -> Result<(CellId, ObjectSpace<'a>)> {
        let cell_id = mapping.cell_id;

        let context_id = cell_id.0;
        let object_space_id = cell_id.1;

        let cell_manifest_id = ObjectSpace::find_cell_manifest_id(mapping.id, packaging)
            .ok_or_else(|| ErrorKind::MalformedOneStoreData("cell manifest id not found".into()))?;
        let revision_manifest_id = storage_index
            .find_revision_mapping_id(cell_manifest_id)
            .ok_or_else(|| {
                ErrorKind::MalformedOneStoreData("no revision manifest id found".into())
            })?;

        let mut objects = HashMap::new();
        let mut roots = HashMap::new();

        let mut rev_id = Some(revision_manifest_id);
        let mut visited_revisions = HashSet::new();
        let mut revision_depth = 0;

        while let Some(revision_manifest_id) = rev_id {
            Reader::check_recursion_depth(revision_depth)?;
            if visited_revisions.contains(&revision_manifest_id) {
                return Err(ErrorKind::MalformedOneStoreData(
                    "revision manifest chain contains a cycle".into(),
                )
                .into());
            }
            reserve_collection_set(&mut visited_revisions, 1)?;
            visited_revisions.insert(revision_manifest_id);
            revision_depth += 1;

            let base_rev_id = Revision::parse(
                revision_manifest_id,
                context_id,
                object_space_id,
                storage_index,
                packaging,
                revision_cache,
                &mut objects,
                &mut roots,
            )?;

            rev_id = base_rev_id;
        }

        let space = ObjectSpace {
            id: object_space_id,
            context: context_id,
            roots,
            objects,
        };

        Ok((cell_id, space))
    }

    fn find_cell_manifest_id(
        cell_manifest_id: ExGuid,
        packaging: &'a OneStorePackaging,
    ) -> Option<ExGuid> {
        packaging
            .data_element_package
            .cell_manifests
            .get(&cell_manifest_id)
            .copied()
    }
}
