use crate::errors::{ErrorKind, Result};
use crate::fsshttpb::data::exguid::ExGuid;
use crate::one::property::layout_alignment::LayoutAlignment;
use crate::one::property::object_reference::ObjectReference;
use crate::one::property::time::Time;
use crate::one::property::{simple, PropertyType};
use crate::one::property_set::note_tag_container::Data as NoteTagData;
use crate::one::property_set::PropertySetId;
use crate::onestore::object::Object;
use crate::reader::reserve_collection;

/// A table.
///
/// See [\[MS-ONE\] 2.2.26].
///
/// [\[MS-ONE\] 2.2.26]: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-one/9046980a-2410-4b2d-8a35-ec06e55648e0
#[derive(Debug)]
pub(crate) struct Data {
    pub(crate) last_modified: Time,
    pub(crate) rows: Vec<ExGuid>,
    pub(crate) row_count: u32,
    pub(crate) col_count: u32,
    pub(crate) cols_locked: Vec<u8>,
    pub(crate) col_widths: Vec<f32>,
    pub(crate) borders_visible: bool,
    pub(crate) layout_alignment_in_parent: Option<LayoutAlignment>,
    pub(crate) layout_alignment_self: Option<LayoutAlignment>,
    pub(crate) note_tags: Vec<NoteTagData>,
}

pub(crate) fn parse(object: &Object) -> Result<Data> {
    if object.id() != PropertySetId::TableNode.as_jcid() {
        return Err(ErrorKind::MalformedOneNoteFileData(
            format!("unexpected object type: 0x{:X}", object.id().0).into(),
        )
        .into());
    }

    let last_modified = Time::parse(PropertyType::LastModifiedTime, object)?.ok_or_else(|| {
        ErrorKind::MalformedOneNoteFileData("table has no last modified time".into())
    })?;
    let rows = ObjectReference::parse_vec(PropertyType::ElementChildNodes, object)?
        .ok_or_else(|| ErrorKind::MalformedOneNoteFileData("table has no rows".into()))?;
    let row_count = simple::parse_u32(PropertyType::RowCount, object)?
        .ok_or_else(|| ErrorKind::MalformedOneNoteFileData("table has no row count".into()))?;
    let col_count = simple::parse_u32(PropertyType::ColumnCount, object)?
        .ok_or_else(|| ErrorKind::MalformedOneNoteFileData("table has no col count".into()))?;
    let cols_locked = simple::parse_vec(PropertyType::TableColumnsLocked, object)?
        .map(|value| {
            let mut cols_locked = Vec::new();
            let values = value.into_iter().skip(1);
            reserve_collection(&mut cols_locked, values.size_hint().0)?;
            for value in values {
                reserve_collection(&mut cols_locked, 1)?;
                cols_locked.push(value);
            }
            Ok::<Vec<u8>, crate::errors::Error>(cols_locked)
        })
        .transpose()?
        .unwrap_or_default();
    let col_widths = simple::parse_vec(PropertyType::TableColumnWidths, object)?
        .map(|value| {
            let value = value.get(1..).ok_or_else(|| {
                ErrorKind::MalformedOneNoteFileData("table column widths are empty".into())
            })?;
            if value.len() % 4 != 0 {
                return Err(ErrorKind::MalformedOneNoteFileData(
                    "table column widths are not aligned".into(),
                )
                .into());
            }
            let mut col_widths = Vec::new();
            reserve_collection(&mut col_widths, value.len() / 4)?;
            for chunk in value.chunks_exact(4) {
                reserve_collection(&mut col_widths, 1)?;
                col_widths.push(f32::from_le_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3],
                ]));
            }
            Ok::<Vec<f32>, crate::errors::Error>(col_widths)
        })
        .transpose()?
        .unwrap_or_default();
    let borders_visible =
        simple::parse_bool(PropertyType::TableBordersVisible, object)?.unwrap_or(true);
    let layout_alignment_in_parent =
        LayoutAlignment::parse(PropertyType::LayoutAlignmentInParent, object)?;
    let layout_alignment_self = LayoutAlignment::parse(PropertyType::LayoutAlignmentSelf, object)?;

    let note_tags = NoteTagData::parse(object)?.unwrap_or_default();

    let data = Data {
        last_modified,
        rows,
        row_count,
        col_count,
        cols_locked,
        col_widths,
        borders_visible,
        layout_alignment_in_parent,
        layout_alignment_self,
        note_tags,
    };

    Ok(data)
}
