/*
 *  Onenote document parser to extract embedded files.
 *
 *  Copyright (C) 2023-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Micah Snyder
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

use std::{
    convert::TryInto,
    io,
    mem, panic,
    path::{Path, PathBuf},
};

use hex_literal::hex;
use log::debug;
use onenote_parser;

/// Error enumerates all possible errors returned by this library.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid format")]
    Format,

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Failed to open file: {0}, {1}")]
    FailedToOpen(PathBuf, String),

    #[error("Failed to get size for file: {0}")]
    FailedToGetFileSize(PathBuf),

    #[error("{0} parameter is NULL")]
    NullParam(&'static str),

    #[error("No more files to extract")]
    NoMoreFiles,

    #[error("Unable to parse OneNote file")]
    Parse,

    #[error("OneNote input read failed: {0}")]
    ReadFailure(String),

    #[error("OneNote input read timed out: {0}")]
    Timeout(String),

    #[error("OneNote attachment sink failed: {0}")]
    Sink(String),

    #[error("Failed to parse OneNote file due to a panic in the onenote_parser library")]
    OneNoteParserPanic,
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Struct representing a file extracted from a OneNote document.
///
/// This owned compatibility representation is used by the iterator and
/// `from_bytes` APIs. The scanner-facing `scan_bytes` API deliberately uses a
/// borrowed callback so an attachment can be written to its bounded spool
/// without first allocating a second whole-member `Vec<u8>`.
pub struct ExtractedFile {
    pub name: Option<String>,
    pub data: Vec<u8>,
}

/// Struct used for a file handle for our OneNote parser.
/// This struct is used to keep track of state for our iterator to work through the document extracting each file.
/// There are three different ways we keep track of state depending on the file format and the way in which the file was opened.
#[derive(Default)]
pub struct OneNote<'a> {
    embedded_files: Vec<ExtractedFile>,
    remaining_vec: Option<Vec<u8>>,
    remaining: Option<&'a [u8]>,
}

// https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/8806fd18-6735-4874-b111-227b83eaac26
#[repr(packed)]
#[allow(dead_code)]
struct FileDataHeader {
    guid_header: [u8; 16],
    cb_length: u64,
    unused: u32,
    reserved: u64,
}
const SIZE_OF_FILE_DATA_HEADER: usize = mem::size_of::<FileDataHeader>();

// Hex sequence identifying the start of a file data store object.
const FILE_DATA_STORE_OBJECT: &[u8] = &hex!("e716e3bd65261145a4c48d4d0b7a9eac");

// Hex sequence identifying the start of a OneNote file.
const ONE_MAGIC: &[u8] = &hex!("e4525c7b8cd8a74daeb15378d02996d3");

/// A sink for the reader-based legacy OneNote extractor. The sink receives
/// one attachment at a time and must not retain the complete root document.
pub trait LegacyAttachmentSink {
    fn begin(&mut self) -> Result<(), Error>;
    fn write(&mut self, data: &[u8]) -> Result<(), Error>;
    fn finish(&mut self) -> Result<(), Error>;
    fn abort(&mut self) {}
}

fn reader_error(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        Error::Parse
    } else if error.kind() == io::ErrorKind::TimedOut {
        Error::Timeout(error.to_string())
    } else {
        Error::ReadFailure(error.to_string())
    }
}

pub fn is_legacy_magic(data: &[u8]) -> bool {
    data.get(..ONE_MAGIC.len()) == Some(ONE_MAGIC)
}

fn scan_legacy_bytes<F>(data: &[u8], callback: &mut F) -> Result<(), Error>
where
    F: FnMut(Option<&str>, &[u8]) -> bool,
{
    let mut cursor = 0usize;
    loop {
        let Some(relative) = find_bytes(&data[cursor..], FILE_DATA_STORE_OBJECT) else {
            break;
        };
        let header_start = cursor.checked_add(relative).ok_or(Error::Format)?;
        let data_length_end = header_start.checked_add(20).ok_or(Error::Format)?;
        let header_end = header_start
            .checked_add(SIZE_OF_FILE_DATA_HEADER)
            .ok_or(Error::Format)?;
        if data_length_end > data.len() || header_end > data.len() {
            return Err(Error::Parse);
        }

        let data_length = u32::from_le_bytes(
            data[header_start + 16..data_length_end]
                .try_into()
                .map_err(|_| Error::Parse)?,
        );
        let data_length = usize::try_from(data_length).map_err(|_| Error::Format)?;
        let data_end = header_end.checked_add(data_length).ok_or(Error::Format)?;
        if data_end > data.len() {
            return Err(Error::Parse);
        }

        if !callback(None, &data[header_end..data_end]) {
            break;
        }
        cursor = data_end;
    }

    Ok(())
}

/// Scan the legacy OneNote layout from a seekable reader. The format stores a
/// fixed marker, a packed header containing a 32-bit payload length, and the
/// payload itself. Marker search and payload transfer are chunked so a large
/// root document or attachment never becomes one contiguous allocation.
pub fn scan_legacy_reader<R, S>(reader: &mut R, file_len: u64, sink: &mut S) -> Result<(), Error>
where
    R: std::io::Read + std::io::Seek,
    S: LegacyAttachmentSink,
{
    use std::io::{Read, Seek, SeekFrom};

    let mut magic = [0u8; ONE_MAGIC.len()];
    reader
        .seek(SeekFrom::Start(0))
        .map_err(reader_error)?;
    reader.read_exact(&mut magic).map_err(reader_error)?;
    if !is_legacy_magic(&magic) {
        return Err(Error::Format);
    }

    const CHUNK: usize = 1024 * 1024;
    let overlap = FILE_DATA_STORE_OBJECT.len().saturating_sub(1);
    let mut scan_buffer = vec![0u8; CHUNK + overlap];
    let mut scan_start = ONE_MAGIC.len() as u64;

    while scan_start < file_len {
        reader
            .seek(SeekFrom::Start(scan_start))
            .map_err(reader_error)?;
        let mut valid = 0usize;
        while valid < scan_buffer.len() {
            let read = reader
                .read(&mut scan_buffer[valid..])
                .map_err(reader_error)?;
            if read == 0 {
                break;
            }
            valid += read;
        }
        if valid == 0 {
            break;
        }

        let Some(relative) = find_bytes(&scan_buffer[..valid], FILE_DATA_STORE_OBJECT) else {
            if valid <= overlap {
                break;
            }
            scan_start = scan_start.saturating_add((valid - overlap) as u64);
            continue;
        };

        let header_start = scan_start
            .checked_add(relative as u64)
            .ok_or(Error::Format)?;
        let header_end = header_start
            .checked_add(SIZE_OF_FILE_DATA_HEADER as u64)
            .ok_or(Error::Format)?;
        if header_end > file_len {
            return Err(Error::Parse);
        }

        let mut header = [0u8; SIZE_OF_FILE_DATA_HEADER];
        reader
            .seek(SeekFrom::Start(header_start))
            .map_err(reader_error)?;
        reader.read_exact(&mut header).map_err(reader_error)?;
        let data_length = u32::from_le_bytes(
            header[16..20].try_into().map_err(|_| Error::Parse)?,
        ) as u64;
        let data_end = header_end.checked_add(data_length).ok_or(Error::Format)?;
        if data_end > file_len {
            return Err(Error::Parse);
        }

        sink.begin()?;
        if let Err(error) = reader.seek(SeekFrom::Start(header_end)) {
            sink.abort();
            return Err(reader_error(error));
        }
        let mut remaining = data_length;
        let mut payload = [0u8; CHUNK];
        while remaining != 0 {
            let requested = remaining.min(payload.len() as u64) as usize;
            let read = match reader.read(&mut payload[..requested]) {
                Ok(read) => read,
                Err(error) => {
                    sink.abort();
                    return Err(reader_error(error));
                }
            };
            if read == 0 {
                sink.abort();
                return Err(Error::Parse);
            }
            if let Err(err) = sink.write(&payload[..read]) {
                sink.abort();
                return Err(err);
            }
            remaining -= read as u64;
        }
        if let Err(err) = sink.finish() {
            sink.abort();
            return Err(err);
        }
        scan_start = data_end;
    }

    Ok(())
}

impl<'a> OneNote<'a> {
    /// Parse a OneNote document while handing each extracted attachment to
    /// the caller immediately. Attachment bytes are borrowed from the root
    /// input and must be consumed before the callback returns. This keeps the
    /// scanner path bounded by its destination spool rather than allocating a
    /// second whole-member buffer.
    pub fn scan_bytes<F>(data: &[u8], filename: &Path, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(Option<&str>, &[u8]) -> bool,
    {
        fn parse_section_buffer<F>(
            data: &[u8],
            filename: &Path,
            callback: &mut F,
        ) -> Result<(), Error>
        where
            F: FnMut(Option<&str>, &[u8]) -> bool,
        {
            let mut parser = onenote_parser::Parser::new();
            let section = parser
                .parse_section_buffer(data, filename)
                .map_err(|_| Error::Parse)?;
            'page_series: for page_series in section.page_series().iter() {
                for page in page_series.pages().iter() {
                    for page_content in page.contents().iter() {
                        if let Some(page_outline) = page_content.outline() {
                            for outline_item in page_outline.items().iter() {
                                for &outline_element in outline_item.element().iter() {
                                    for content in outline_element.contents().iter() {
                                        if let Some(embedded_file) = content.embedded_file() {
                                            let name = if embedded_file.filename().is_empty() {
                                                None
                                            } else {
                                                Some(embedded_file.filename())
                                            };
                                            if !callback(name, embedded_file.data()) {
                                                break 'page_series;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(())
        }

        let modern = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            parse_section_buffer(data, filename, &mut callback)
        }));

        match modern {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(_)) => {}
            Err(_) => return Err(Error::OneNoteParserPanic),
        }

        let file_magic = data.get(0..16).ok_or(Error::Format)?;
        if file_magic != ONE_MAGIC {
            return Err(Error::Format);
        }

        if find_bytes(data, FILE_DATA_STORE_OBJECT).is_none() {
            return Err(Error::Parse);
        }

        scan_legacy_bytes(data, &mut callback)
    }

    /// Open a OneNote document given a slice bytes.
    pub fn from_bytes(data: &'a [u8], filename: &Path) -> Result<OneNote<'a>, Error> {
        debug!(
            "Inspecting OneNote file for attachments from in-memory buffer of size {}-bytes named {}\n",
            data.len(), filename.to_string_lossy()
        );

        fn parse_section_buffer(data: &[u8], filename: &Path) -> Result<Vec<ExtractedFile>, Error> {
            let mut embedded_files: Vec<ExtractedFile> = vec![];
            let mut parser = onenote_parser::Parser::new();

            if let Ok(section) = parser.parse_section_buffer(data, filename) {
                // file appears to be OneStore 2.8 `.one` file.
                section.page_series().iter().for_each(|page_series| {
                    page_series.pages().iter().for_each(|page| {
                        page.contents().iter().for_each(|page_content| {
                            if let Some(page_outline) = page_content.outline() {
                                page_outline.items().iter().for_each(|outline_item| {
                                    outline_item.element().iter().for_each(|&outline_element| {
                                        outline_element.contents().iter().for_each(|content| {
                                            if let Some(embedded_file) = content.embedded_file() {
                                                let data = embedded_file.data();
                                                let name = embedded_file.filename();

                                                // If name is empty, set to None.
                                                let name = if name.is_empty() {
                                                    debug!("Found unnamed attached file of size {}-bytes", data.len());
                                                    None
                                                } else {
                                                    debug!("Found attached file '{}' of size {}-bytes", name, data.len());
                                                    Some(name.to_string())
                                                };

                                                embedded_files.push(ExtractedFile {
                                                    name,
                                                    data: data.to_vec(),
                                                });
                                            }
                                        });
                                    });
                                });
                            }
                        });
                    });
                });
            } else {
                return Err(Error::Parse);
            }

            Ok(embedded_files)
        }

        // Try to parse the section buffer using the onenote_parser crate.
        // Attempt to catch panics in case the parser encounter unexpected issues.
        let result_result = panic::catch_unwind(|| -> Result<Vec<ExtractedFile>, Error> {
            parse_section_buffer(data, filename)
        });

        // Check if it panicked. If no panic, grab the parse result.
        let result = result_result.map_err(|_| Error::OneNoteParserPanic)?;

        if let Ok(embedded_files) = result {
            // Successfully parsed the OneNote file with the onenote_parser crate.
            Ok(OneNote {
                embedded_files,
                ..Default::default()
            })
        } else {
            debug!("Unable to parse OneNote file with onenote_parser crate. Trying a different method known to work with older office 2010 OneNote files to extract attachments.");

            let embedded_files: Vec<ExtractedFile> = vec![];

            // Verify that the OneNote document file magic is correct.
            // We don't check this for the onenote_parser crate because it does this for us, and may add support for newer OneNote file formats in the future.
            let file_magic = data.get(0..16).ok_or(Error::Format)?;
            if file_magic != ONE_MAGIC {
                return Err(Error::Format);
            }

            Ok(OneNote {
                embedded_files,
                remaining: Some(data),
                ..Default::default()
            })
        }
    }

    /// Open a OneNote document given the document was provided as a slice of bytes.
    pub fn next_file(&mut self) -> Option<ExtractedFile> {
        debug!("Looking to extract file from OneNote section...");

        let mut file_data: Option<Vec<u8>> = None;

        let remaining = if let Some(remaining_in) = self.remaining {
            let remaining = if let Some(pos) = find_bytes(remaining_in, FILE_DATA_STORE_OBJECT) {
                let (_, remaining) = remaining_in.split_at(pos);
                // Found file data store object.
                remaining
            } else {
                return None;
            };

            let data_length = if let Some(x) = remaining.get(16..20) {
                u32::from_le_bytes(x.try_into().unwrap()) as u64
            } else {
                return None;
            };

            let data: &[u8] = remaining
                .get(SIZE_OF_FILE_DATA_HEADER..SIZE_OF_FILE_DATA_HEADER + data_length as usize)?;

            file_data = Some(data.to_vec());

            Some(&remaining[SIZE_OF_FILE_DATA_HEADER + (data_length as usize)..remaining.len()])
        } else {
            None
        };

        self.remaining = remaining;

        file_data.map(|data| ExtractedFile { data, name: None })
    }

    /// Get the next file from the OneNote document using the method required for when we've read the file into a Vec.
    pub fn next_file_vec(&mut self) -> Option<ExtractedFile> {
        debug!("Looking to extract file from OneNote section...");

        let mut file_data: Option<Vec<u8>> = None;

        self.remaining_vec = if let Some(ref remaining_vec) = self.remaining_vec {
            let remaining = if let Some(pos) = find_bytes(remaining_vec, FILE_DATA_STORE_OBJECT) {
                let (_, remaining) = remaining_vec.split_at(pos);
                // Found file data store object.
                remaining
            } else {
                return None;
            };

            let data_length = if let Some(x) = remaining.get(16..20) {
                u32::from_le_bytes(x.try_into().unwrap()) as u64
            } else {
                return None;
            };

            let data: &[u8] = remaining
                .get(SIZE_OF_FILE_DATA_HEADER..SIZE_OF_FILE_DATA_HEADER + data_length as usize)?;

            file_data = Some(data.to_vec());

            Some(Vec::from(
                &remaining[SIZE_OF_FILE_DATA_HEADER + (data_length as usize)..remaining.len()],
            ))
        } else {
            None
        };

        file_data.map(|data| ExtractedFile { data, name: None })
    }

    /// Get the next file from the OneNote document using the method required for the onenote_parser crate.
    pub fn next_file_parser(&mut self) -> Option<ExtractedFile> {
        self.embedded_files.pop()
    }
}

impl<'a> Iterator for OneNote<'a> {
    type Item = ExtractedFile;

    fn next(&mut self) -> Option<ExtractedFile> {
        // Find the next embedded file
        if self.remaining.is_some() {
            // Data stored in a slice.
            self.next_file()
        } else if self.remaining_vec.is_some() {
            // Data stored in a Vec.
            self.next_file_vec()
        } else if !self.embedded_files.is_empty() {
            // Data stored in a Vec.
            self.next_file_parser()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, Read, Seek, SeekFrom};

    struct FailingReader {
        inner: Cursor<Vec<u8>>,
        fail_at: u64,
    }

    impl Read for FailingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.inner.position() >= self.fail_at {
                return Err(io::Error::new(io::ErrorKind::Other, "synthetic read failure"));
            }
            self.inner.read(buffer)
        }
    }

    impl Seek for FailingReader {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            self.inner.seek(from)
        }
    }

    struct CollectSink {
        files: Vec<Vec<u8>>,
        current: Vec<u8>,
        fail_writes: bool,
        aborted: bool,
    }

    impl CollectSink {
        fn new() -> Self {
            Self {
                files: Vec::new(),
                current: Vec::new(),
                fail_writes: false,
                aborted: false,
            }
        }
    }

    impl LegacyAttachmentSink for CollectSink {
        fn begin(&mut self) -> Result<(), Error> {
            self.current.clear();
            Ok(())
        }

        fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            if self.fail_writes {
                return Err(Error::Sink("synthetic sink failure".to_owned()));
            }
            self.current.extend_from_slice(data);
            Ok(())
        }

        fn finish(&mut self) -> Result<(), Error> {
            self.files.push(std::mem::take(&mut self.current));
            Ok(())
        }

        fn abort(&mut self) {
            self.aborted = true;
            self.current.clear();
        }
    }

    fn legacy_fixture(payload: &[u8]) -> Vec<u8> {
        let mut fixture = ONE_MAGIC.to_vec();
        fixture.extend_from_slice(FILE_DATA_STORE_OBJECT);
        fixture.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        fixture.extend_from_slice(&[0u8; 16]);
        fixture.extend_from_slice(payload);
        fixture
    }

    #[test]
    fn legacy_scan_borrows_attachment_bytes() {
        let fixture = legacy_fixture(b"attachment");
        let mut seen = Vec::new();

        scan_legacy_bytes(&fixture, &mut |name, data| {
            assert!(name.is_none());
            seen.extend_from_slice(data);
            true
        })
        .expect("legacy fixture should parse");

        assert_eq!(seen, b"attachment");
    }

    #[test]
    fn legacy_scan_rejects_truncated_attachment() {
        let mut fixture = legacy_fixture(b"attachment");
        fixture.truncate(fixture.len() - 1);

        assert!(matches!(
            scan_legacy_bytes(&fixture, &mut |_name, _data| true),
            Err(Error::Parse)
        ));
    }

    #[test]
    fn scan_bytes_rejects_modern_parse_failure_without_legacy_record() {
        assert!(matches!(
            OneNote::scan_bytes(ONE_MAGIC, Path::new("malformed.one"), |_name, _data| true),
            Err(Error::Parse)
        ));
    }

    #[test]
    fn legacy_reader_streams_attachment_chunks() {
        let payload = vec![b'x'; 1024 * 1024 + 17];
        let fixture = legacy_fixture(&payload);
        let mut reader = Cursor::new(fixture.clone());
        let mut sink = CollectSink::new();

        scan_legacy_reader(&mut reader, fixture.len() as u64, &mut sink)
            .expect("legacy reader fixture should parse");

        assert_eq!(sink.files, vec![payload]);
        assert!(!sink.aborted);
    }

    #[test]
    fn legacy_reader_finds_marker_across_scan_window_boundary() {
        let payload = b"boundary attachment";
        let mut fixture = ONE_MAGIC.to_vec();
        fixture.extend(std::iter::repeat(0u8).take(1024 * 1024 + 5));
        fixture.extend_from_slice(FILE_DATA_STORE_OBJECT);
        fixture.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        fixture.extend_from_slice(&[0u8; 16]);
        fixture.extend_from_slice(payload);

        let mut reader = Cursor::new(fixture.clone());
        let mut sink = CollectSink::new();
        scan_legacy_reader(&mut reader, fixture.len() as u64, &mut sink)
            .expect("boundary fixture should parse");

        assert_eq!(sink.files, vec![payload.to_vec()]);
    }

    #[test]
    fn legacy_reader_aborts_after_sink_failure() {
        let fixture = legacy_fixture(b"attachment");
        let mut reader = Cursor::new(fixture.clone());
        let mut sink = CollectSink {
            fail_writes: true,
            ..CollectSink::new()
        };

        assert!(matches!(
            scan_legacy_reader(&mut reader, fixture.len() as u64, &mut sink),
            Err(Error::Sink(_))
        ));
        assert!(sink.aborted);
        assert!(sink.files.is_empty());
    }

    #[test]
    fn legacy_reader_preserves_source_read_failure() {
        let fixture = legacy_fixture(b"attachment");
        let mut reader = FailingReader {
            inner: Cursor::new(fixture.clone()),
            fail_at: ONE_MAGIC.len() as u64,
        };
        let mut sink = CollectSink::new();

        assert!(matches!(
            scan_legacy_reader(&mut reader, fixture.len() as u64, &mut sink),
            Err(Error::ReadFailure(_))
        ));
        assert!(sink.files.is_empty());
        assert!(!sink.aborted);
    }
}
