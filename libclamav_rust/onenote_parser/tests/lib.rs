use insta::assert_debug_snapshot;
use onenote_parser::Parser;
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
};

struct ShortReader {
    data: Vec<u8>,
    offset: usize,
}

impl ShortReader {
    fn new(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }
}

impl Read for ShortReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.offset == self.data.len() {
            return Ok(0);
        }
        let count = output
            .len()
            .min(self.data.len() - self.offset)
            .min(3);
        output[..count].copy_from_slice(&self.data[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

struct PaddedReader {
    data: Vec<u8>,
    offset: u64,
    total_len: u64,
}

impl PaddedReader {
    fn new(data: Vec<u8>, total_len: u64) -> Self {
        assert!(total_len >= data.len() as u64);
        Self {
            data,
            offset: 0,
            total_len,
        }
    }
}

impl Read for PaddedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.offset == self.total_len {
            return Ok(0);
        }
        let count = output
            .len()
            .min((self.total_len - self.offset) as usize);
        if self.offset < self.data.len() as u64 {
            let source_start = self.offset as usize;
            let source_count = count.min(self.data.len() - source_start);
            output[..source_count]
                .copy_from_slice(&self.data[source_start..source_start + source_count]);
            output[source_count..count].fill(0);
        } else {
            output[..count].fill(0);
        }
        self.offset += count as u64;
        Ok(count)
    }
}

#[test]
fn test_parse_section() {
    let path = PathBuf::from("tests/samples/New Section 1.one");

    let mut parser = Parser::new();
    assert_debug_snapshot!(parser.parse_section(&path).unwrap());
}

#[test]
fn test_parse_notebook() {
    let path = PathBuf::from("tests/samples/Open Notebook.onetoc2");

    let mut parser = Parser::new();
    assert_debug_snapshot!(parser.parse_notebook(&path).unwrap());
}

#[test]
fn test_parse_section_reader_matches_buffer_with_short_reads() {
    let path = PathBuf::from("tests/samples/New Section 1.one");
    let data = std::fs::read(&path).unwrap();
    let file_name = Path::new("New Section 1.one");

    let mut buffer_parser = Parser::new();
    let buffer_section = buffer_parser
        .parse_section_buffer(&data, file_name)
        .unwrap();

    let mut reader_parser = Parser::new();
    let reader_section = reader_parser
        .parse_section_reader(ShortReader::new(data), file_name)
        .unwrap();

    assert_eq!(format!("{buffer_section:?}"), format!("{reader_section:?}"));
}

#[test]
fn test_parse_section_reader_accepts_logical_input_above_former_cap() {
    let path = PathBuf::from("tests/samples/New Section 1.one");
    let data = std::fs::read(&path).unwrap();
    let total_len = 256 * 1024 * 1024 + 1;

    let mut parser = Parser::new();
    let section = parser
        .parse_section_reader(
            PaddedReader::new(data, total_len),
            Path::new("New Section 1.one"),
        )
        .unwrap();

    assert_eq!(section.display_name(), "New Section 1");
}
