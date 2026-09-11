use crate::errors::{ErrorKind, Result};
use crate::fsshttpb::data::cell_id::CellId;
use crate::fsshttpb::data::exguid::ExGuid;
use crate::fsshttpb::data_element::storage_index::StorageIndex;
use crate::fsshttpb::packaging::OneStorePackaging;
use crate::onestore::object::Object;
use crate::onestore::object_space::GroupData;
use crate::onestore::revision_role::RevisionRole;
use crate::reader::{reserve_collection, reserve_collection_map, reserve_collection_set};
use std::collections::{HashMap, HashSet};

/// A OneNote file revision.
///
/// See [\[MS-ONESTOR\] 2.1.8]
///
/// [\[MS-ONESTOR\] 2.1.8]: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/a8ca2a90-d92a-4cf7-bf68-ed18ae476a11
#[derive(Debug, Clone)]
pub(crate) struct Revision<'a> {
    objects: HashMap<ExGuid, Object<'a>>,
    roots: HashMap<RevisionRole, ExGuid>,
}

fn insert_root_if_absent(
    roots: &mut HashMap<RevisionRole, ExGuid>,
    role: RevisionRole,
    object_id: ExGuid,
) -> Result<bool> {
    if roots.contains_key(&role) {
        return Ok(false);
    }

    reserve_collection_map(roots, 1)?;
    roots.insert(role, object_id);
    Ok(true)
}

fn insert_declared_root(
    declared_roles: &mut HashSet<RevisionRole>,
    roots: &mut HashMap<RevisionRole, ExGuid>,
    role: RevisionRole,
    object_id: ExGuid,
) -> Result<()> {
    reserve_collection_set(declared_roles, 1)?;
    if !declared_roles.insert(role) {
        return Err(ErrorKind::MalformedOneStoreData(
            "duplicate root role in revision manifest".into(),
        )
        .into());
    }

    insert_root_if_absent(roots, role, object_id)?;
    Ok(())
}

impl<'a, 'b> Revision<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn parse(
        revision_manifest_id: ExGuid,
        context_id: ExGuid,
        object_space_id: ExGuid,
        storage_index: &'a StorageIndex,
        packaging: &'a OneStorePackaging,
        revision_cache: &'b mut HashMap<CellId, Revision<'a>>,
        objects: &'b mut HashMap<ExGuid, Object<'a>>,
        roots: &'b mut HashMap<RevisionRole, ExGuid>,
    ) -> Result<Option<ExGuid>> {
        let revision_manifest = packaging
            .data_element_package
            .find_revision_manifest(revision_manifest_id)
            .ok_or_else(|| {
                ErrorKind::MalformedOneStoreData("revision manifest not found".into())
            })?;

        let base_rev = revision_manifest
            .base_rev_id
            .as_option()
            .map(|mapping_id| {
                storage_index
                    .find_revision_mapping_id(mapping_id)
                    .ok_or_else(|| {
                        ErrorKind::MalformedOneStoreData("revision mapping not found".into())
                    })
            })
            .transpose()?;

        if let Some(rev) = revision_cache.get(&CellId(context_id, revision_manifest.rev_id)) {
            for (role, object_id) in rev.roots.iter() {
                insert_root_if_absent(roots, *role, *object_id)?;
            }
            for (object_id, object) in rev.objects.iter() {
                if objects.contains_key(object_id) {
                    continue;
                }
                reserve_collection_map(objects, 1)?;
                objects.insert(*object_id, object.clone());
            }

            return Ok(base_rev);
        }

        let mut declared_roles = HashSet::new();
        for root in revision_manifest.root_declare.iter() {
            let role = RevisionRole::parse(root.root_id)?;
            insert_declared_root(&mut declared_roles, roots, role, root.object_id)?;
        }

        for group_id in revision_manifest.group_references.iter() {
            Self::parse_group(context_id, *group_id, object_space_id, packaging, objects)?
        }

        Ok(base_rev)
    }

    fn parse_group(
        context_id: ExGuid,
        group_id: ExGuid,
        object_space_id: ExGuid,
        packaging: &'a OneStorePackaging,
        objects: &'b mut HashMap<ExGuid, Object<'a>>,
    ) -> Result<()> {
        let group = packaging
            .data_element_package
            .find_object_group(group_id)
            .ok_or_else(|| ErrorKind::MalformedOneStoreData("object group not found".into()))?;

        if group.declarations.len() != group.objects.len() {
            return Err(ErrorKind::MalformedOneStoreData(
                "object declaration/data counts do not match".into(),
            )
            .into());
        }

        let mut object_ids = Vec::new();
        reserve_collection(&mut object_ids, group.declarations.len())?;
        let mut group_objects: GroupData = HashMap::new();
        reserve_collection_map(&mut group_objects, group.declarations.len())?;
        for (decl, data) in group.declarations.iter().zip(group.objects.iter()) {
            object_ids.push(decl.object_id());
            if group_objects
                .insert((decl.object_id(), decl.partition_id()), data)
                .is_some()
            {
                return Err(ErrorKind::MalformedOneStoreData(
                    "duplicate object group declaration key".into(),
                )
                .into());
            }
        }

        for object_id in object_ids {
            if objects.contains_key(&object_id) {
                continue;
            }

            let object = Object::parse(
                object_id,
                context_id,
                object_space_id,
                &group_objects,
                packaging,
            )?;

            reserve_collection_map(objects, 1)?;
            objects.insert(object_id, object);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{insert_declared_root, insert_root_if_absent};
    use crate::onestore::revision_role::RevisionRole;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn base_revision_root_cannot_replace_newer_root() {
        let newer = exguid!({{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}, 1});
        let older = exguid!({{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}, 2});
        let mut roots = HashMap::new();

        assert!(insert_root_if_absent(
            &mut roots,
            RevisionRole::DefaultContent,
            newer,
        )
        .unwrap());
        assert!(!insert_root_if_absent(
            &mut roots,
            RevisionRole::DefaultContent,
            older,
        )
        .unwrap());
        assert_eq!(roots.get(&RevisionRole::DefaultContent), Some(&newer));
    }

    #[test]
    fn duplicate_root_role_in_one_revision_is_rejected() {
        let first = exguid!({{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}, 1});
        let second = exguid!({{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}, 2});
        let mut declared_roles = HashSet::new();
        let mut roots = HashMap::new();

        insert_declared_root(
            &mut declared_roles,
            &mut roots,
            RevisionRole::Metadata,
            first,
        )
        .unwrap();
        assert!(insert_declared_root(
            &mut declared_roles,
            &mut roots,
            RevisionRole::Metadata,
            second,
        )
        .is_err());
        assert_eq!(roots.get(&RevisionRole::Metadata), Some(&first));
    }
}
