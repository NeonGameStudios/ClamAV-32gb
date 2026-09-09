use crate::errors::{ErrorKind, Result};
use crate::fsshttpb::data::exguid::ExGuid;
use crate::one::property_set::toc_container;
use crate::onenote::section::SectionEntry;
use crate::onestore::object_space::ObjectSpace;
use crate::reader::reserve_collection;

/// A OneNote notebook.
#[derive(Clone, Debug)]
pub struct Notebook {
    pub(crate) entries: Vec<SectionEntry>,
}

impl Notebook {
    /// The section entries of this notebook.
    pub fn entries(&self) -> &[SectionEntry] {
        &self.entries
    }
}

pub(crate) fn parse_toc(space: &ObjectSpace) -> Result<Vec<String>> {
    let content_id = space
        .content_root()
        .ok_or_else(|| ErrorKind::MalformedOneNoteData("notebook has no content root".into()))?;

    let mut toc = parse_toc_entry(content_id, space)?;
    toc.sort_unstable_by_key(|(ordering_id, _)| *ordering_id);
    toc.dedup_by(|(_, a), (_, b)| a == b);

    let mut entries = Vec::new();
    for (_, name) in toc {
        reserve_collection(&mut entries, 1)?;
        entries.push(name);
    }

    Ok(entries)
}

fn parse_toc_entry(content_id: ExGuid, space: &ObjectSpace) -> Result<Vec<(u32, String)>> {
    let content = space.get_object(content_id).ok_or_else(|| {
        ErrorKind::MalformedOneNoteData("notebook content root is missing".into())
    })?;

    let toc = toc_container::parse(content)?;

    if let Some(name) = toc.filename {
        let ordering_id = toc
            .ordering_id
            .ok_or_else(|| ErrorKind::MalformedOneNoteData("section has no order id".into()))?;

        Ok(vec![(ordering_id, name)])
    } else {
        let mut children = Vec::new();
        for content_id in toc.children {
            let entries = parse_toc_entry(content_id, space)?;
            reserve_collection(&mut children, entries.len())?;
            children.extend(entries);
        }

        Ok(children)
    }
}
