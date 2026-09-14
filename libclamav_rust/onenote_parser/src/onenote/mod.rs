use crate::errors::{ErrorKind, Result};
use crate::fsshttpb::packaging::OneStorePackaging;
use crate::onenote::notebook::Notebook;
use crate::onenote::section::{Section, SectionEntry, SectionGroup};
use crate::onestore::parse_store;
use crate::reader::{reserve_collection, BlobSpoolBudget, Reader};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

pub(crate) mod content;
pub(crate) mod embedded_file;
pub(crate) mod iframe;
pub(crate) mod image;
pub(crate) mod ink;
pub(crate) mod list;
pub(crate) mod note_tag;
pub(crate) mod notebook;
pub(crate) mod outline;
pub(crate) mod page;
pub(crate) mod page_content;
pub(crate) mod page_series;
pub(crate) mod rich_text;
pub(crate) mod section;
pub(crate) mod table;

/// The OneNote file parser.
pub struct Parser;

fn resolve_toc_path(base_dir: &Path, name: &str) -> Result<PathBuf> {
    let relative = Path::new(name);
    if name.is_empty()
        || relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::Prefix(_)
                    | Component::RootDir
                    | Component::CurDir
                    | Component::ParentDir
            )
        })
    {
        return Err(ErrorKind::MalformedOneNoteFileData(
            "table of contents entry is not a safe relative path".into(),
        )
        .into());
    }
    Ok(base_dir.join(relative))
}

impl Parser {
    /// Create a new OneNote file parser.
    pub fn new() -> Parser {
        Parser {}
    }

    /// Parse a OneNote notebook.
    ///
    /// The `path` argument must point to a `.onetoc2` file. This will parse the
    /// table of contents of the notebook as well as all contained
    /// sections from the folder that the table of contents file is in.
    pub fn parse_notebook(&mut self, path: &Path) -> Result<Notebook> {
        self.parse_notebook_at_depth(path, 0)
    }

    fn parse_notebook_at_depth(&mut self, path: &Path, depth: usize) -> Result<Notebook> {
        Reader::check_recursion_depth(depth)?;
        let file = File::open(path)?;
        let packaging = OneStorePackaging::parse(&mut Reader::from_reader(file))?;
        if packaging.cell_schema != guid!({E4DBFD38-E5C7-408B-A8A1-0E7B421E1F5F}) {
            return Err(ErrorKind::NotATocFile {
                file: path.to_string_lossy().to_string(),
            }
            .into());
        }
        let store = parse_store(&packaging)?;

        if store.schema_guid() != guid!({E4DBFD38-E5C7-408B-A8A1-0E7B421E1F5F}) {
            return Err(ErrorKind::NotATocFile {
                file: path.to_string_lossy().to_string(),
            }
            .into());
        }

        let base_dir = path.parent().ok_or_else(|| {
            ErrorKind::MalformedOneNoteFileData("notebook path has no parent directory".into())
        })?;
        let mut sections = Vec::new();
        for name in notebook::parse_toc(store.data_root())? {
            let section_path = resolve_toc_path(base_dir, &name)?;

            if section_path.ends_with("OneNote_RecycleBin") {
                continue;
            }

            let metadata = match std::fs::symlink_metadata(&section_path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // Deleted sections can remain in a notebook TOC. Preserve
                    // the upstream compatibility behavior for that case, but
                    // do not hide permission or other metadata failures.
                    continue;
                }
                Err(error) => return Err(error.into()),
            };

            let entry = if metadata.is_file() {
                self.parse_section(&section_path).map(SectionEntry::Section)?
            } else if metadata.is_dir() {
                self.parse_section_group(&section_path, depth)
                    .map(SectionEntry::SectionGroup)?
            } else {
                return Err(ErrorKind::MalformedOneNoteFileData(
                    "table of contents entry is neither a section file nor a section group".into(),
                )
                .into());
            };
            reserve_collection(&mut sections, 1)?;
            sections.push(entry);
        }

        Ok(Notebook { entries: sections })
    }

    /// Parse a OneNote section buffer.
    ///
    /// The `data` argument must contain a OneNote section.
    pub fn parse_section_buffer(&mut self, data: &[u8], file_name: &Path) -> Result<Section> {
        let packaging = OneStorePackaging::parse(&mut Reader::new(data))?;
        if packaging.cell_schema != guid!({1F937CB4-B26F-445F-B9F8-17E20160E461}) {
            return Err(ErrorKind::NotASectionFile {
                file: file_name.to_string_lossy().into_owned(),
            }
            .into());
        }
        let store = parse_store(&packaging)?;

        if store.schema_guid() != guid!({1F937CB4-B26F-445F-B9F8-17E20160E461}) {
            return Err(ErrorKind::NotASectionFile {
                file: file_name.to_string_lossy().into_owned(),
            }
            .into());
        }

        section::parse_section(
            store,
            file_name.to_string_lossy().into_owned(),
        )
    }

    /// Parse a OneNote section from a bounded sequential reader.
    ///
    /// Unlike [`Parser::parse_section_buffer`], this method never asks the
    /// caller for a whole-file slice. The parser still materializes the
    /// format objects required to build a [`Section`], but source bytes are
    /// fetched incrementally from `reader`.
    pub fn parse_section_reader<R: Read>(
        &mut self,
        reader: R,
        file_name: &Path,
    ) -> Result<Section> {
        let mut reader = Reader::from_reader(reader);
        let packaging = OneStorePackaging::parse(&mut reader)?;
        if packaging.cell_schema != guid!({1F937CB4-B26F-445F-B9F8-17E20160E461}) {
            return Err(ErrorKind::NotASectionFile {
                file: file_name.to_string_lossy().into_owned(),
            }
            .into());
        }
        let store = parse_store(&packaging)?;

        if store.schema_guid() != guid!({1F937CB4-B26F-445F-B9F8-17E20160E461}) {
            return Err(ErrorKind::NotASectionFile {
                file: file_name.to_string_lossy().into_owned(),
            }
            .into());
        }

        section::parse_section(
            store,
            file_name.to_string_lossy().into_owned(),
        )
    }

    /// Scan a section from a bounded sequential reader and stream each
    /// embedded file to the callback. The callback owns the attachment
    /// consumption window: returning `false` stops traversal after the
    /// current attachment without treating that as a parser error.
    pub fn scan_section_reader<R, F>(
        &mut self,
        reader: R,
        file_name: &Path,
        callback: F,
    ) -> Result<()>
    where
        R: Read,
        F: FnMut(Option<&str>, &mut dyn Read) -> bool,
    {
        self.scan_section_reader_with_budget(reader, file_name, None, None, callback)
    }

    /// Scan a section from a bounded sequential reader while accounting
    /// parser-owned object-data spools against a caller-provided temporary
    /// budget. Spools are created below `spool_directory` when supplied.
    pub fn scan_section_reader_with_budget<R, F>(
        &mut self,
        reader: R,
        file_name: &Path,
        spool_directory: Option<&Path>,
        budget: Option<Box<dyn BlobSpoolBudget>>,
        mut callback: F,
    ) -> Result<()>
    where
        R: Read,
        F: FnMut(Option<&str>, &mut dyn Read) -> bool,
    {
        let budget = budget.map(Rc::from);
        let mut reader = Reader::from_reader_with_options(
            reader,
            Reader::MAX_MATERIALIZED_BYTES,
            spool_directory.map(Path::to_path_buf),
            budget,
        );
        let packaging = OneStorePackaging::parse(&mut reader)?;
        if packaging.cell_schema != guid!({1F937CB4-B26F-445F-B9F8-17E20160E461}) {
            return Err(ErrorKind::NotASectionFile {
                file: file_name.to_string_lossy().into_owned(),
            }
            .into());
        }
        let store = parse_store(&packaging)?;

        if store.schema_guid() != guid!({1F937CB4-B26F-445F-B9F8-17E20160E461}) {
            return Err(ErrorKind::NotASectionFile {
                file: file_name.to_string_lossy().into_owned(),
            }
            .into());
        }

        section::scan_attachments(&store, &mut callback)?;
        Ok(())
    }

    /// Parse a OneNote section file.
    ///
    /// The `path` argument must point to a `.one` file that contains a
    /// OneNote section.
    pub fn parse_section(&mut self, path: &Path) -> Result<Section> {
        let file = File::open(path)?;
        let packaging = OneStorePackaging::parse(&mut Reader::from_reader(file))?;
        if packaging.cell_schema != guid!({1F937CB4-B26F-445F-B9F8-17E20160E461}) {
            return Err(ErrorKind::NotASectionFile {
                file: path.to_string_lossy().to_string(),
            }
            .into());
        }
        let store = parse_store(&packaging)?;

        if store.schema_guid() != guid!({1F937CB4-B26F-445F-B9F8-17E20160E461}) {
            return Err(ErrorKind::NotASectionFile {
                file: path.to_string_lossy().to_string(),
            }
            .into());
        }

        section::parse_section(
            store,
            path.file_name()
                .ok_or_else(|| {
                    ErrorKind::MalformedOneNoteFileData("section path has no file name".into())
                })?
                .to_string_lossy()
                .to_string(),
        )
    }

    fn parse_section_group(&mut self, path: &Path, depth: usize) -> Result<SectionGroup> {
        let display_name = path
            .file_name()
            .ok_or_else(|| {
                ErrorKind::MalformedOneNoteFileData(
                    "section-group path has no file name".into(),
                )
            })?
            .to_string_lossy()
            .to_string();

        for entry in path.read_dir()? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            let is_toc = entry
                .path()
                .extension()
                .map(|ext| ext == OsStr::new("onetoc2"))
                .unwrap_or_default();

            if is_toc && file_type.is_file() {
                return self
                    .parse_notebook_at_depth(&entry.path(), depth + 1)
                    .map(|group| SectionGroup {
                        display_name,
                        entries: group.entries,
                    });
            }
        }

        Err(ErrorKind::TocFileMissing {
            dir: path.as_os_str().to_string_lossy().into_owned(),
        }
        .into())
    }

}

#[cfg(test)]
mod tests {
    use super::resolve_toc_path;
    use std::path::Path;

    #[test]
    fn toc_path_accepts_a_plain_relative_name() {
        assert_eq!(
            resolve_toc_path(Path::new("/tmp/notebook"), "section.one").unwrap(),
            Path::new("/tmp/notebook/section.one")
        );
    }

    #[test]
    fn toc_path_rejects_absolute_and_parent_entries() {
        for name in [
            "",
            "/tmp/outside.one",
            "../outside.one",
            "group/../outside.one",
            ".",
        ] {
            assert!(resolve_toc_path(Path::new("/tmp/notebook"), name).is_err());
        }
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}
