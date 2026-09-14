/*
 *  ALZ archive extraction.
 *
 *  Copyright (C) 2024-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Andy Ragusa
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

/*
#![warn(
    clippy::all,
    clippy::restriction,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
)]
*/

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};
use bzip2_rs::DecoderReader;
use flate2::read::DeflateDecoder;
use log::debug;

/// File header
const ALZ_FILE_HEADER: u32 = 0x015a_4c41;
/// Local file header
const ALZ_LOCAL_FILE_HEADER: u32 = 0x015a_4c42;
/// Central directory header
const ALZ_CENTRAL_DIRECTORY_HEADER: u32 = 0x015a_4c43;
/// End of Central directory header
const ALZ_END_OF_CENTRAL_DIRECTORY_HEADER: u32 = 0x025a_4c43;

const ALZ_COMP_NOCOMP: u8 = 0;
const ALZ_COMP_BZIP2: u8 = 1;
const ALZ_COMP_DEFLATE: u8 = 2;
const MIN_SCANNED_FILE_SIZE: usize = 5;

/// Error enumerates all possible errors returned by this library.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error parsing ALZ archive: {0}")]
    Parse(&'static str),

    #[error("Unrecognized sig: '{0}'")]
    UnrecognizedSig(String),

    #[error("Unsupported ALZ feature: {0}")]
    UnsupportedFeature(&'static str),

    #[error("Failed to extract file")]
    Extract,

    #[error("Failed to allocate extracted file")]
    Alloc,

    #[error("Extracted file exceeds scan limits")]
    ScanLimitExceeded(u64),

    #[error("Stopped ALZ archive traversal")]
    Stop,

    #[error("Failed to read field: {0}")]
    Read(&'static str),

    #[error("Failed to read field from the fmap backing store: {0}")]
    ReadFailure(&'static str),

    #[error("Timed out while reading field: {0}")]
    Timeout(&'static str),
}

fn classify_read_error(err: io::Error, field: &'static str) -> Error {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        Error::Parse(field)
    } else if err.kind() == io::ErrorKind::TimedOut {
        Error::Timeout(field)
    } else if crate::fmap::is_read_failure(&err) {
        Error::ReadFailure(field)
    } else {
        Error::Read(field)
    }
}

fn classify_extraction_read_error(err: io::Error, field: &'static str) -> Error {
    if err.kind() == io::ErrorKind::TimedOut {
        Error::Timeout(field)
    } else if crate::fmap::is_read_failure(&err) {
        Error::ReadFailure(field)
    } else {
        Error::Extract
    }
}

/*
 * DecoderReader may read up to 1024 bytes ahead of the logical end of a
 * bzip2 stream and keeps those bytes in its private decoder buffer. Keep one
 * byte of the bounded ALZ input outside that decoder until the decoder asks
 * for more input. This preserves bulk reads while making an EOF decision
 * observable: a decoder that finishes while the lookahead or source remains
 * has not consumed the complete declared compressed extent.
 */
struct Bzip2ExactReader<R> {
    reader: R,
    ready: [u8; 8192],
    ready_start: usize,
    ready_len: usize,
    pending: Option<u8>,
    source_exhausted: bool,
}

impl<R> Bzip2ExactReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            ready: [0; 8192],
            ready_start: 0,
            ready_len: 0,
            pending: None,
            source_exhausted: false,
        }
    }

    fn refill(&mut self) -> io::Result<()>
    where
        R: Read,
    {
        self.ready_start = 0;
        self.ready_len = 0;

        if self.source_exhausted && self.pending.is_none() {
            return Ok(());
        }

        let pending = self.pending.take();
        let mut fetched = [0u8; 8192];
        let mut fetched_len = 0usize;
        while fetched_len < 2 && !self.source_exhausted {
            let read = self.reader.read(&mut fetched[fetched_len..])?;
            if read == 0 {
                self.source_exhausted = true;
                break;
            }
            fetched_len += read;
        }

        let mut ready_len = 0usize;
        if let Some(byte) = pending {
            self.ready[ready_len] = byte;
            ready_len += 1;
        }

        if self.source_exhausted {
            self.ready[ready_len..ready_len + fetched_len]
                .copy_from_slice(&fetched[..fetched_len]);
            ready_len += fetched_len;
        } else {
            self.ready[ready_len..ready_len + fetched_len - 1]
                .copy_from_slice(&fetched[..fetched_len - 1]);
            ready_len += fetched_len - 1;
            self.pending = Some(fetched[fetched_len - 1]);
        }

        self.ready_len = ready_len;
        Ok(())
    }

    fn is_fully_consumed(&self) -> bool {
        self.source_exhausted && self.pending.is_none() && self.ready_len == 0
    }
}

impl<R: Read> Read for Bzip2ExactReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let mut written = 0usize;
        while written < buffer.len() {
            if self.ready_len == 0 {
                self.refill()?;
                if self.ready_len == 0 {
                    break;
                }
            }

            let count = self.ready_len.min(buffer.len() - written);
            let end = self.ready_start + count;
            buffer[written..written + count]
                .copy_from_slice(&self.ready[self.ready_start..end]);
            self.ready_start = end;
            self.ready_len -= count;
            written += count;
        }

        Ok(written)
    }
}

fn alz_crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    crc
}

#[cfg(test)]
fn alz_crc32(data: &[u8]) -> u32 {
    !alz_crc32_update(!0u32, data)
}

struct AlzLocalFileHeaderHead {
    file_name_length: u16,

    file_attribute: u8,

    file_time_date: u32,

    file_descriptor: u8,

    unknown: u8,
}

const ALZ_ENCR_HEADER_LEN: u32 = 12;

struct AlzLocalFileHeader {
    head: AlzLocalFileHeaderHead,

    compression_method: u8,
    unknown: u8,
    file_crc: u32,

    /* Can be smaller sizes, depending on file_descriptor/0x10 .*/
    compressed_size: u64,
    uncompressed_size: u64,

    file_name: String,

    enc_chk: [u8; ALZ_ENCR_HEADER_LEN as usize],

    start_of_compressed_data: u64,
    compressed_data_is_within_bounds: bool,
}

#[allow(dead_code)]
enum AlzFileAttribute {
    Readonly = 0x1,
    Hidden = 0x2,
    Directory = 0x10,
    File = 0x20,
}

impl AlzLocalFileHeader {
    const fn is_encrypted(&self) -> bool {
        0 != (self.head.file_descriptor & 0x1)
    }

    const fn is_data_descriptor(&self) -> bool {
        0 != (self.head.file_descriptor & 0x8)
    }

    const fn is_directory(&self) -> bool {
        0 != ((AlzFileAttribute::Directory as u8) & self.head.file_attribute)
    }

    const fn _is_file(&self) -> bool {
        0 != ((AlzFileAttribute::File as u8) & self.head.file_attribute)
    }

    const fn _is_readonly(&self) -> bool {
        0 != ((AlzFileAttribute::Readonly as u8) & self.head.file_attribute)
    }

    const fn _is_hidden(&self) -> bool {
        0 != ((AlzFileAttribute::Hidden as u8) & self.head.file_attribute)
    }

    const fn scan_limit_size_hint(&self) -> u64 {
        if self.compressed_size == 0 {
            return 0;
        }

        let size_hint = if self.compression_method == ALZ_COMP_NOCOMP {
            self.compressed_size
        } else if self.uncompressed_size <= MIN_SCANNED_FILE_SIZE as u64 {
            MIN_SCANNED_FILE_SIZE as u64 + 1
        } else {
            self.uncompressed_size
        };

        if size_hint == 0 && self.compressed_size > 0 {
            1
        } else {
            size_hint
        }
    }

    const fn is_known_scan_limit_exempt(&self) -> bool {
        self.compression_method == ALZ_COMP_NOCOMP
            && self.compressed_size <= MIN_SCANNED_FILE_SIZE as u64
    }

    const fn is_empty_stored_member(&self) -> bool {
        self.compression_method == ALZ_COMP_NOCOMP
            && self.compressed_size == 0
            && self.uncompressed_size == 0
    }

    const fn has_valid_compressed_size(&self) -> bool {
        self.compressed_size != 0
            || (self.compression_method == ALZ_COMP_NOCOMP && self.uncompressed_size == 0)
    }

    const fn has_valid_directory_sizes(&self) -> bool {
        self.compressed_size == 0 && self.uncompressed_size == 0
    }

    const fn has_valid_compressed_data_bounds(&self) -> bool {
        self.compressed_data_is_within_bounds
    }

    fn _dump(&self) {
        println!(
            "self.start_of_compressed_data = {}",
            self.start_of_compressed_data
        );

        println!(
            "self.head.file_name_length = {:x}",
            self.head.file_name_length
        );
        println!(
            "self.head.file_attribute = {:02x}",
            self.head.file_attribute
        );
        println!("self.head.file_time_date = {:x}", self.head.file_time_date);
        println!(
            "self.head.file_descriptor = {:x}",
            self.head.file_descriptor
        );
        println!("self.head.unknown = {:x}", self.head.unknown);

        println!("self.compression_method = {:x}", self.compression_method);
        println!("self.unknown = {:x}", self.unknown);
        println!("self.file_crc = {:x}", self.file_crc);
        println!("self.compressed_size = {:x}", self.compressed_size);
        println!("self.uncompressed_size = {:x}", self.uncompressed_size);

        println!("self.file_name = {}", self.file_name);

        print!("self.enc_chk = ");
        for i in 0..ALZ_ENCR_HEADER_LEN {
            if 0 != i {
                print!(" ");
            }
            print!("{}", self.enc_chk[i as usize]);
        }
        println!();

        println!("is_encrypted = {}", self.is_encrypted());
        println!("is_data_descriptor = {}", self.is_data_descriptor());

        println!();
    }

    pub const fn new() -> Self {
        Self {
            head: AlzLocalFileHeaderHead {
                file_name_length: 0,
                file_attribute: 0,
                file_time_date: 0,
                file_descriptor: 0,
                unknown: 0,
            },

            compression_method: 0,
            unknown: 0,
            file_crc: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            file_name: String::new(),
            enc_chk: [0; ALZ_ENCR_HEADER_LEN as usize],
            start_of_compressed_data: 0,
            compressed_data_is_within_bounds: true,
        }
    }

    pub fn parse<R: Read + Seek>(&mut self, reader: &mut R, source_len: u64) -> Result<(), Error> {
        self.head.file_name_length = reader
            .read_u16::<LittleEndian>()
            .map_err(|err| classify_read_error(err, "file_name_length"))?;
        self.head.file_attribute = reader
            .read_u8()
            .map_err(|err| classify_read_error(err, "file_attribute"))?;
        self.head.file_time_date = reader
            .read_u32::<LittleEndian>()
            .map_err(|err| classify_read_error(err, "file_time_date"))?;
        self.head.file_descriptor = reader
            .read_u8()
            .map_err(|err| classify_read_error(err, "file_descriptor"))?;
        self.head.unknown = reader
            .read_u8()
            .map_err(|err| classify_read_error(err, "unknown u8"))?;

        if 0 == self.head.file_name_length {
            return Err(Error::Parse("File Name Length is zero"));
        }

        let byte_len = self.head.file_descriptor / 0x10;
        if byte_len > 0 {
            self.compression_method = reader
                .read_u8()
                .map_err(|err| classify_read_error(err, "compression_method"))?;
            self.unknown = reader
                .read_u8()
                .map_err(|err| classify_read_error(err, "unknown u8"))?;
            self.file_crc = reader
                .read_u32::<LittleEndian>()
                .map_err(|err| classify_read_error(err, "file_crc"))?;

            match byte_len {
                1 => {
                    self.compressed_size = u64::from(
                        reader
                            .read_u8()
                            .map_err(|err| classify_read_error(err, "compressed_size"))?,
                    );
                    self.uncompressed_size = u64::from(
                        reader
                            .read_u8()
                            .map_err(|err| classify_read_error(err, "uncompressed_size"))?,
                    );
                }
                2 => {
                    self.compressed_size = u64::from(
                        reader
                            .read_u16::<LittleEndian>()
                            .map_err(|err| classify_read_error(err, "compressed_size"))?,
                    );
                    self.uncompressed_size = u64::from(
                        reader
                            .read_u16::<LittleEndian>()
                            .map_err(|err| classify_read_error(err, "uncompressed_size"))?,
                    );
                }
                4 => {
                    self.compressed_size = u64::from(
                        reader
                            .read_u32::<LittleEndian>()
                            .map_err(|err| classify_read_error(err, "compressed_size"))?,
                    );
                    self.uncompressed_size = u64::from(
                        reader
                            .read_u32::<LittleEndian>()
                            .map_err(|err| classify_read_error(err, "uncompressed_size"))?,
                    );
                }
                8 => {
                    self.compressed_size = reader
                        .read_u64::<LittleEndian>()
                        .map_err(|err| classify_read_error(err, "compressed_size"))?;
                    self.uncompressed_size = reader
                        .read_u64::<LittleEndian>()
                        .map_err(|err| classify_read_error(err, "uncompressed_size"))?;
                }
                _ => return Err(Error::Parse("Unsupported File Descriptor")),
            }
        }

        let mut filename = vec![0u8; usize::from(self.head.file_name_length)];
        reader
            .read_exact(&mut filename)
            .map_err(|err| classify_read_error(err, "file name"))?;

        self.file_name = String::from_utf8_lossy(&filename).into_owned();

        if self.is_encrypted() {
            reader
                .read_exact(&mut self.enc_chk)
                .map_err(|err| classify_read_error(err, "encrypted buffer"))?;
        }

        self.start_of_compressed_data = reader
            .stream_position()
            .map_err(|err| classify_read_error(err, "compressed data offset"))?;
        let end_of_compressed_data = self
            .start_of_compressed_data
            .checked_add(self.compressed_size)
            .ok_or(Error::Parse("Invalid compressed data length"))?;

        self.compressed_data_is_within_bounds = end_of_compressed_data <= source_len;

        reader
            .seek(SeekFrom::Start(end_of_compressed_data))
            .map_err(|err| classify_read_error(err, "compressed data seek"))?;

        Ok(())
    }

    pub fn is_supported(&self) -> Result<(), Error> {
        if self.is_encrypted() {
            return Err(Error::UnsupportedFeature("Encryption Unsupported"));
        }

        if self.is_data_descriptor() {
            return Err(Error::UnsupportedFeature(
                "Data Descriptors are Unsupported",
            ));
        }

        self.check_compression_supported()
    }

    fn check_compression_supported(&self) -> Result<(), Error> {
        match self.compression_method {
            ALZ_COMP_NOCOMP | ALZ_COMP_BZIP2 | ALZ_COMP_DEFLATE => {}
            _ => return Err(Error::UnsupportedFeature("Compression Method Unsupported")),
        }

        Ok(())
    }

    fn extract_file_deflate_reader_until_eof<R: Read>(
        &mut self,
        decompressor: &mut R,
        sink: &mut impl ExtractSink,
        max_extracted_size: u64,
    ) -> Result<(), Error> {
        sink.begin(Some(&self.file_name))?;
        let mut output_size = 0u64;
        let mut crc = !0u32;
        let mut buffer = [0u8; 8192];

        loop {
            let len = match decompressor.read(&mut buffer) {
                Ok(len) => len,
                Err(err) => {
                    debug!("Unable to decompress deflate data");
                    let extraction_error =
                        classify_extraction_read_error(err, "compressed member data");
                    if matches!(extraction_error, Error::Extract) {
                        sink.finish_partial()?;
                    } else {
                        sink.abort();
                    }
                    return Err(extraction_error);
                }
            };
            if len == 0 {
                break;
            }

            let needed = output_size
                .checked_add(u64::try_from(len).map_err(|_| Error::Extract)?)
                .ok_or(Error::Extract)?;
            if needed > max_extracted_size {
                /* The quota boundary is not a complete member boundary, but
                 * the available prefix still needs to be inspected. Preserve
                 * the limit result after scanning the bounded prefix. */
                let prefix_len = usize::try_from(
                    max_extracted_size.saturating_sub(output_size),
                )
                .unwrap_or(len)
                .min(len);
                if prefix_len != 0 {
                    sink.write(&buffer[..prefix_len])?;
                }
                sink.finish_partial()?;
                return Err(Error::ScanLimitExceeded(needed));
            }

            sink.write(&buffer[..len])?;
            crc = alz_crc32_update(crc, &buffer[..len]);
            output_size = needed;
        }

        if output_size != self.uncompressed_size {
            debug!(
                "ALZ file {:?} produced {} bytes, expected {} bytes",
                self.file_name, output_size, self.uncompressed_size
            );
            sink.finish_partial()?;
            return Err(Error::Extract);
        }

        let actual_crc = !crc;
        if actual_crc != self.file_crc {
            debug!(
                "ALZ file {:?} has CRC {:08x}, expected {:08x}",
                self.file_name,
                actual_crc,
                self.file_crc,
            );
            sink.finish_partial()?;
            return Err(Error::Extract);
        }

        Ok(())
    }

    /*
     * This has no header/checksum validation.
     */
    fn extract_file_deflate<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        sink: &mut impl ExtractSink,
        max_extracted_size: u64,
    ) -> Result<(), Error> {
        reader
            .seek(SeekFrom::Start(self.start_of_compressed_data))
            .map_err(|err| classify_extraction_read_error(err, "compressed data seek"))?;
        let mut bounded = reader.take(self.compressed_size);
        let mut decompressor = DeflateDecoder::new(&mut bounded);
        self.extract_file_deflate_reader_until_eof(&mut decompressor, sink, max_extracted_size)?;
        if decompressor.total_in() != self.compressed_size {
            debug!(
                "ALZ file {:?} left {} declared deflate bytes unconsumed",
                self.file_name,
                self.compressed_size.saturating_sub(decompressor.total_in()),
            );
            sink.finish_partial()?;
            return Err(Error::Extract);
        }

        sink.finish()
    }

    fn extract_file_nocomp<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        sink: &mut impl ExtractSink,
        max_extracted_size: u64,
    ) -> Result<(), Error> {
        if self.compressed_size != self.uncompressed_size {
            debug!("Uncompressed file has different lengths for compressed vs uncompressed, using the stored size");
        }

        reader
            .seek(SeekFrom::Start(self.start_of_compressed_data))
            .map_err(|err| classify_extraction_read_error(err, "compressed data seek"))?;
        let mut bounded = reader.take(self.compressed_size);
        sink.begin(Some(&self.file_name))?;
        let mut output_size = 0u64;
        let mut crc = !0u32;
        let mut buffer = [0u8; 8192];
        loop {
            let len = match bounded.read(&mut buffer) {
                Ok(len) => len,
                Err(err) => {
                    let extraction_error =
                        classify_extraction_read_error(err, "stored member data");
                    if matches!(extraction_error, Error::Extract) {
                        sink.finish_partial()?;
                    } else {
                        sink.abort();
                    }
                    return Err(extraction_error);
                }
            };
            if len == 0 {
                break;
            }

            let needed = output_size
                .checked_add(u64::try_from(len).map_err(|_| Error::Extract)?)
                .ok_or(Error::Extract)?;
            if needed > max_extracted_size {
                /* The quota boundary is not a complete member boundary, but
                 * the available prefix still needs to be inspected. Preserve
                 * the limit result after scanning the bounded prefix. */
                let prefix_len = usize::try_from(
                    max_extracted_size.saturating_sub(output_size),
                )
                .unwrap_or(len)
                .min(len);
                if prefix_len != 0 {
                    sink.write(&buffer[..prefix_len])?;
                }
                sink.finish_partial()?;
                return Err(Error::ScanLimitExceeded(needed));
            }

            sink.write(&buffer[..len])?;
            crc = alz_crc32_update(crc, &buffer[..len]);
            output_size = needed;
        }

        if bounded.limit() != 0 {
            sink.finish_partial()?;
            return Err(Error::Extract);
        }

        if output_size != self.uncompressed_size {
            debug!(
                "ALZ file {:?} produced {} bytes, expected {} bytes",
                self.file_name, output_size, self.uncompressed_size
            );
            sink.finish_partial()?;
            return Err(Error::Extract);
        }

        let actual_crc = !crc;
        if actual_crc != self.file_crc {
            debug!(
                "ALZ file {:?} has CRC {:08x}, expected {:08x}",
                self.file_name, actual_crc, self.file_crc
            );
            sink.finish_partial()?;
            return Err(Error::Extract);
        }

        sink.finish()
    }

    fn extract_file_bzip2<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        sink: &mut impl ExtractSink,
        max_extracted_size: u64,
    ) -> Result<(), Error> {
        reader
            .seek(SeekFrom::Start(self.start_of_compressed_data))
            .map_err(|err| classify_extraction_read_error(err, "compressed data seek"))?;
        let mut bounded = reader.take(self.compressed_size);
        let mut exact_reader = Bzip2ExactReader::new(&mut bounded);
        let mut decompressor = DecoderReader::new(&mut exact_reader);
        self.extract_file_deflate_reader_until_eof(&mut decompressor, sink, max_extracted_size)?;
        drop(decompressor);

        if !exact_reader.is_fully_consumed() {
            debug!(
                "ALZ file {:?} left declared bzip2 bytes unconsumed",
                self.file_name
            );
            sink.finish_partial()?;
            return Err(Error::Extract);
        }

        sink.finish()
    }

    fn extract_file<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        sink: &mut impl ExtractSink,
        max_extracted_size: u64,
    ) -> Result<(), Error> {
        match self.compression_method {
            ALZ_COMP_NOCOMP => self.extract_file_nocomp(reader, sink, max_extracted_size),
            ALZ_COMP_BZIP2 => self.extract_file_bzip2(reader, sink, max_extracted_size),
            ALZ_COMP_DEFLATE => self.extract_file_deflate(reader, sink, max_extracted_size),
            _ => Err(Error::Extract),
        }
    }
}

/*TODO: Merge this with the onenote extracted_file struct, and use the same one everywhere.*/
pub struct ExtractedFile {
    pub name: Option<String>,
    pub data: Vec<u8>,
}

/// Receives one extracted member incrementally. Implementations must not
/// assume that a member arrives as one contiguous allocation.
pub trait ExtractSink {
    fn begin(&mut self, name: Option<&str>) -> Result<(), Error>;
    fn write(&mut self, data: &[u8]) -> Result<(), Error>;
    fn finish(&mut self) -> Result<(), Error>;
    fn finish_partial(&mut self) -> Result<(), Error> {
        let result = self.finish();
        if result.is_ok() {
            self.discard_empty_member();
        }
        result
    }
    fn discard_empty_member(&mut self) {}
    fn last_size(&self) -> u64 {
        0
    }
    fn abort(&mut self) {}
}

impl ExtractSink for Vec<ExtractedFile> {
    fn begin(&mut self, name: Option<&str>) -> Result<(), Error> {
        self.try_reserve(1).map_err(|_| Error::Alloc)?;
        self.push(ExtractedFile {
            name: name.map(str::to_owned),
            data: Vec::new(),
        });
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        let file = self.last_mut().ok_or(Error::Extract)?;
        file.data.try_reserve(data.len()).map_err(|_| Error::Alloc)?;
        file.data.extend_from_slice(data);
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn discard_empty_member(&mut self) {
        if self.last().map_or(false, |file| file.data.is_empty()) {
            self.pop();
        }
    }

    fn last_size(&self) -> u64 {
        self.last()
            .and_then(|file| u64::try_from(file.data.len()).ok())
            .unwrap_or(0)
    }

    fn abort(&mut self) {
        self.pop();
    }
}

struct CallbackExtractSink<F> {
    callback: F,
    current: Option<ExtractedFile>,
    last_size: u64,
}

impl<F> ExtractSink for CallbackExtractSink<F>
where
    F: FnMut(ExtractedFile) -> Result<(), Error>,
{
    fn begin(&mut self, name: Option<&str>) -> Result<(), Error> {
        self.last_size = 0;
        self.current = Some(ExtractedFile {
            name: name.map(str::to_owned),
            data: Vec::new(),
        });
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        let file = self.current.as_mut().ok_or(Error::Extract)?;
        file.data.try_reserve(data.len()).map_err(|_| Error::Alloc)?;
        file.data.extend_from_slice(data);
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Error> {
        if let Some(file) = self.current.take() {
            self.last_size = u64::try_from(file.data.len()).map_err(|_| Error::Extract)?;
            if !file.data.is_empty() {
                (self.callback)(file)?;
            }
        }
        Ok(())
    }

    fn abort(&mut self) {
        self.current = None;
    }

    fn last_size(&self) -> u64 {
        self.last_size
    }
}

pub struct AlzFileMetadata<'a> {
    pub file_name: &'a str,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub is_directory: bool,
    pub is_encrypted: bool,
    pub file_crc: u32,
    pub filepos: usize,
}

pub struct AlzExtractionLimits {
    pub max_file_size: u64,
    pub max_total_size: u64,
    pub max_files_remaining: usize,
}

pub enum AlzExtractionDecision {
    Extract(AlzExtractionLimits),
    Skip,
    Stop,
}

fn alz_total_size_exceeds_limit(current: u64, next: u64, limit: u64) -> bool {
    current > limit || next > limit.saturating_sub(current)
}

#[derive(Default)]
pub struct Alz {
    pub embedded_files: Vec<ExtractedFile>,
    pub file_limit_exceeded_size: Option<u64>,
    pub total_limit_exceeded_size: Option<u64>,
    pub file_count_limit_exceeded: bool,
    extracted_size: u64,
    scan_counted_files: usize,
    parse_error: bool,
    unsupported_feature: bool,
}

impl<'aa> Alz {
    /* Check for the ALZ file header. */
    #[allow(clippy::unused_self)]
    fn is_alz<R: Read>(&self, reader: &mut R) -> Result<bool, Error> {
        match reader.read_u32::<LittleEndian>() {
            Ok(n) => Ok(ALZ_FILE_HEADER == n),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
            Err(err) => Err(classify_read_error(err, "ALZ file header")),
        }
    }

    fn parse_local_fileheader<R, F>(
        &mut self,
        reader: &mut R,
        source_len: u64,
        filepos: &mut usize,
        should_extract: &mut F,
        sink: &mut impl ExtractSink,
    ) -> Result<(), Error>
    where
        R: Read + Seek,
        F: FnMut(&AlzFileMetadata<'_>) -> AlzExtractionDecision,
    {
        let mut local_fileheader = AlzLocalFileHeader::new();

        local_fileheader.parse(reader, source_len)?;

        let metadata_filepos = *filepos;
        *filepos = metadata_filepos.saturating_add(1);

        /* The is_file flag doesn't appear to always be set, so we'll just assume it's a file if
         * it's not marked as a directory.*/
        let metadata = AlzFileMetadata {
            file_name: &local_fileheader.file_name,
            compressed_size: local_fileheader.compressed_size,
            uncompressed_size: local_fileheader.uncompressed_size,
            is_directory: local_fileheader.is_directory(),
            is_encrypted: local_fileheader.is_encrypted(),
            file_crc: local_fileheader.file_crc,
            filepos: metadata_filepos,
        };

        let extraction_decision = should_extract(&metadata);
        if matches!(extraction_decision, AlzExtractionDecision::Stop) {
            return Err(Error::Stop);
        }

        if !local_fileheader.has_valid_compressed_size() {
            return Err(Error::Parse(
                "Compressed data is empty for a non-empty or compressed member",
            ));
        }

        if local_fileheader.is_directory() && !local_fileheader.has_valid_directory_sizes() {
            return Err(Error::Parse("Directory member declares file data"));
        }

        if !local_fileheader.is_directory() {
            let AlzExtractionDecision::Extract(limits) = extraction_decision else {
                if !local_fileheader.has_valid_compressed_data_bounds() {
                    return Err(Error::Parse("Invalid compressed data length"));
                }

                return Ok(());
            };

            let support_error = local_fileheader.is_supported().err();
            if let Some(err) = support_error {
                if !local_fileheader.has_valid_compressed_data_bounds() {
                    return Err(Error::Parse("Invalid compressed data length"));
                }

                debug!("{err}");
                self.unsupported_feature = true;
                return Ok(());
            }

            let base_extracted_size = self.extracted_size;
            let max_total_remaining = limits.max_total_size.saturating_sub(base_extracted_size);
            let max_extracted_size = limits.max_file_size.min(max_total_remaining);
            if self.scan_counted_files >= limits.max_files_remaining
                && !local_fileheader.is_known_scan_limit_exempt()
            {
                debug!(
                    "ALZ file {:?} skipped because the file count limit was reached.",
                    local_fileheader.file_name
                );
                self.file_count_limit_exceeded = true;
                return Err(Error::Stop);
            }

            if !local_fileheader.has_valid_compressed_data_bounds() {
                return Err(Error::Parse("Invalid compressed data length"));
            }

            let max_extracted_size = if local_fileheader.is_known_scan_limit_exempt() {
                local_fileheader.compressed_size
            } else if max_extracted_size <= MIN_SCANNED_FILE_SIZE as u64 {
                0
            } else {
                max_extracted_size
            };

            /* A valid empty stored member still needs to reach the sink: the
             * scanner-facing sink charges its zero-byte nested descriptor to
             * the inclusive MaxFiles budget. Other zero-output decisions are
             * genuine size-budget skips and must remain deferred. */
            if max_extracted_size == 0 && !local_fileheader.is_empty_stored_member() {
                debug!(
                    "ALZ file {:?} skipped because the extraction size budget is exhausted.",
                    local_fileheader.file_name
                );

                let needed = local_fileheader.scan_limit_size_hint();
                if needed > limits.max_file_size
                    && self
                        .file_limit_exceeded_size
                        .map_or(true, |current| current < needed)
                {
                    self.file_limit_exceeded_size = Some(needed);
                }

                let total_needed = base_extracted_size.saturating_add(needed);
                if alz_total_size_exceeds_limit(
                    base_extracted_size,
                    needed,
                    limits.max_total_size,
                )
                    && self
                        .total_limit_exceeded_size
                        .map_or(true, |current| current < total_needed)
                {
                    self.total_limit_exceeded_size = Some(total_needed);
                }

                return Ok(());
            }

            let extraction_result = local_fileheader.extract_file(reader, sink, max_extracted_size);
            let data_end = local_fileheader
                .start_of_compressed_data
                .checked_add(local_fileheader.compressed_size)
                .ok_or(Error::Parse("Invalid compressed data length"))?;
            reader
                .seek(SeekFrom::Start(data_end))
                .map_err(|err| classify_read_error(err, "compressed data seek"))?;

            match extraction_result {
                Ok(()) => {
                    self.account_extracted(sink);
                    sink.discard_empty_member();
                }
                Err(Error::ScanLimitExceeded(needed)) => {
                    debug!(
                        "ALZ file {:?} exceeded extraction size limits; the bounded partial content was scanned.",
                        local_fileheader.file_name
                    );
                    if needed > limits.max_file_size
                        && self
                            .file_limit_exceeded_size
                            .map_or(true, |current| current < needed)
                    {
                        self.file_limit_exceeded_size = Some(needed);
                    }

                    let total_needed = base_extracted_size.saturating_add(needed);
                    if alz_total_size_exceeds_limit(
                        base_extracted_size,
                        needed,
                        limits.max_total_size,
                    )
                        && self
                            .total_limit_exceeded_size
                            .map_or(true, |current| current < total_needed)
                    {
                        self.total_limit_exceeded_size = Some(total_needed);
                    }
                }
                Err(Error::Extract) => {
                    debug!(
                        "Failed to extract ALZ file {:?}. Continuing with next entry.",
                        local_fileheader.file_name
                    );
                    self.parse_error = true;
                }
                Err(err) => return Err(err),
            }

        } else if !local_fileheader.has_valid_compressed_data_bounds() {
            return Err(Error::Parse("Invalid compressed data length"));
        }

        Ok(())
    }

    fn account_extracted<S: ExtractSink>(&mut self, sink: &S) {
        let size = sink.last_size();
        if size > MIN_SCANNED_FILE_SIZE as u64 {
            /* Tiny members are deliberately exempt from both the extracted
             * file count and the shared logical-content budget. Keep this
             * consistent with is_known_scan_limit_exempt(), so a sequence of
             * tiny metadata members cannot consume the budget needed for a
             * substantive member later in the archive. */
            self.scan_counted_files = self.scan_counted_files.saturating_add(1);
            self.extracted_size = self.extracted_size.saturating_add(size);
        }
    }

    #[allow(clippy::unused_self)]
    fn parse_central_directoryheader<R: Read>(
        &self,
        reader: &mut R,
    ) -> Result<bool, Error> {
        /*
         * This is ignored in unalz (UnAlz.cpp ReadCentralDirectoryStructure).
         *
         * It actually reads 12 bytes, and I think it happens to work because EOF is hit on the next
         * read, which it does not consider an error.
         */
        match reader.read_u64::<LittleEndian>() {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
            Err(err) => Err(classify_read_error(err, "central directory header")),
        }
    }

    #[must_use]
    pub const fn new() -> Self {
        Self {
            embedded_files: Vec::new(),
            file_limit_exceeded_size: None,
            total_limit_exceeded_size: None,
            file_count_limit_exceeded: false,
            extracted_size: 0,
            scan_counted_files: 0,
            parse_error: false,
            unsupported_feature: false,
        }
    }

    pub const fn has_parse_error(&self) -> bool {
        self.parse_error
    }

    pub const fn has_unsupported_feature(&self) -> bool {
        self.unsupported_feature
    }

    /// # Errors
    /// Will return `Error::Parse` if file headers are not correct or are inconsistent.
    pub fn from_bytes(bytes: &'aa [u8]) -> Result<Self, Error> {
        Self::from_bytes_with_filter(bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: usize::MAX,
            })
        })
    }

    /// # Errors
    /// Will return `Error::Parse` if file headers are not correct or are inconsistent.
    pub fn from_bytes_with_filter<F>(bytes: &'aa [u8], mut should_extract: F) -> Result<Self, Error>
    where
        F: FnMut(&AlzFileMetadata<'_>) -> AlzExtractionDecision,
    {
        let mut embedded_files = Vec::new();
        let mut alz = Self::parse_with_sink(
            Cursor::new(bytes),
            &mut should_extract,
            &mut embedded_files,
        )?;
        alz.embedded_files = embedded_files;
        Ok(alz)
    }

    /// Parse an ALZ archive while delivering each extracted member to the
    /// caller immediately. The sink may stop traversal with `Error::Stop`;
    /// the caller can use that to preserve a scan result without retaining
    /// already-processed members.
    pub fn from_bytes_with_filter_stream<F, S>(
        bytes: &'aa [u8],
        mut should_extract: F,
        sink: &mut S,
    ) -> Result<Self, Error>
    where
        F: FnMut(&AlzFileMetadata<'_>) -> AlzExtractionDecision,
        S: FnMut(ExtractedFile) -> Result<(), Error>,
    {
        let mut callback_sink = CallbackExtractSink {
            callback: sink,
            current: None,
            last_size: 0,
        };
        Self::parse_with_sink(
            Cursor::new(bytes),
            &mut should_extract,
            &mut callback_sink,
        )
    }

    /// Parse an ALZ archive from a bounded reader and deliver each member in
    /// chunks. The reader is never converted into a whole-input slice.
    pub fn from_reader_with_filter_stream<R, F, S>(
        reader: R,
        mut should_extract: F,
        sink: &mut S,
    ) -> Result<Self, Error>
    where
        R: Read + Seek,
        F: FnMut(&AlzFileMetadata<'_>) -> AlzExtractionDecision,
        S: ExtractSink,
    {
        Self::parse_with_sink(reader, &mut should_extract, sink)
    }

    fn parse_with_sink<R, F, S>(
        mut reader: R,
        should_extract: &mut F,
        sink: &mut S,
    ) -> Result<Self, Error>
    where
        R: Read + Seek,
        F: FnMut(&AlzFileMetadata<'_>) -> AlzExtractionDecision,
        S: ExtractSink,
    {
        let source_len = reader
            .seek(SeekFrom::End(0))
            .map_err(|err| classify_read_error(err, "source length"))?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|err| classify_read_error(err, "source rewind"))?;

        let mut alz: Self = Self::new();
        let mut filepos: usize = 1;
        let mut saw_end_marker = false;
        let mut stopped_early = false;

        if !alz.is_alz(&mut reader)? {
            return Err(Error::Parse("No ALZ file header"));
        }

        //What these bytes are supposed to be in unspecified, but they need to be there.
        reader
            .read_u32::<LittleEndian>()
            .map_err(|err| classify_read_error(err, "ALZ header padding"))?;

        loop {
            let sig = match reader.read_u32::<LittleEndian>() {
                Ok(sig) => sig,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                    if !stopped_early {
                        alz.parse_error = true;
                    }
                    break;
                }
                Err(err) => return Err(classify_read_error(err, "archive signature")),
            };

            match sig {
                ALZ_LOCAL_FILE_HEADER => {
                    match alz.parse_local_fileheader(
                        &mut reader,
                        source_len,
                        &mut filepos,
                        should_extract,
                        sink,
                    ) {
                        Ok(()) => {}
                        Err(Error::Stop) => {
                            stopped_early = true;
                            break;
                        }
                        Err(Error::Alloc) => return Err(Error::Alloc),
                        Err(err @ (Error::Read(_)
                        | Error::ReadFailure(_)
                        | Error::Timeout(_))) => return Err(err),
                        Err(err) => {
                            if filepos == 1 {
                                return Err(err);
                            }

                            debug!("Failed to parse ALZ local file header: {err}");
                            alz.parse_error = true;
                            break;
                        }
                    }
                    continue;
                }
                ALZ_CENTRAL_DIRECTORY_HEADER => {
                    match alz.parse_central_directoryheader(&mut reader)? {
                        true => continue,
                        false => {}
                    }
                }
                ALZ_END_OF_CENTRAL_DIRECTORY_HEADER => {
                    saw_end_marker = true;
                    break;
                    /*This is the end, nothing really to do here.*/
                }
                _ => {
                    #[allow(clippy::uninlined_format_args)]
                    let err = Error::UnrecognizedSig(format!("{:x}", sig));
                    if filepos == 1 {
                        return Err(err);
                    }

                    debug!("Failed to parse ALZ archive: {err}");
                    alz.parse_error = true;
                    break;
                }
            }
        }

        if saw_end_marker {
            let end_position = reader
                .stream_position()
                .map_err(|err| classify_read_error(err, "archive end position"))?;
            if end_position != source_len {
                debug!(
                    "ALZ archive has {} trailing bytes after its end marker",
                    source_len.saturating_sub(end_position),
                );
                alz.parse_error = true;
            }
        }

        if !saw_end_marker && !stopped_early {
            alz.parse_error = true;
        }

        Ok(alz)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct FmapFailureReader {
        inner: Cursor<Vec<u8>>,
        fail_at: u64,
    }

    impl Read for FmapFailureReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }

            let position = self.inner.position();
            if position >= self.fail_at {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    crate::fmap::Error::ReadFailure(
                        usize::try_from(position).unwrap(),
                        buf.len(),
                        self.inner.get_ref().len(),
                    ),
                ));
            }

            let available = usize::try_from(self.fail_at - position)
                .unwrap()
                .min(buf.len());
            self.inner.read(&mut buf[..available])
        }
    }

    impl Seek for FmapFailureReader {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    fn append_local_file(
        alz: &mut Vec<u8>,
        name: &str,
        compression_method: u8,
        uncompressed_size: u8,
        data: &[u8],
    ) {
        append_local_entry(
            alz,
            name,
            AlzFileAttribute::File as u8,
            0x10,
            compression_method,
            uncompressed_size,
            data,
        );
    }

    fn append_local_entry(
        alz: &mut Vec<u8>,
        name: &str,
        file_attribute: u8,
        file_descriptor: u8,
        compression_method: u8,
        uncompressed_size: u8,
        data: &[u8],
    ) {
        let compressed_size = u8::try_from(data.len()).unwrap();
        append_local_entry_with_sizes(
            alz,
            name,
            file_attribute,
            file_descriptor,
            compression_method,
            compressed_size,
            uncompressed_size,
            data,
        );
    }

    fn append_local_entry_with_sizes(
        alz: &mut Vec<u8>,
        name: &str,
        file_attribute: u8,
        file_descriptor: u8,
        compression_method: u8,
        compressed_size: u8,
        uncompressed_size: u8,
        data: &[u8],
    ) {
        let name = name.as_bytes();
        let name_len = u16::try_from(name.len()).unwrap();
        let file_crc = match compression_method {
            ALZ_COMP_NOCOMP => alz_crc32(data),
            ALZ_COMP_BZIP2 => {
                let mut decoder = DecoderReader::new(data);
                let mut decoded = Vec::new();
                decoder
                    .read_to_end(&mut decoded)
                    .map_or(0, |_| alz_crc32(&decoded))
            }
            ALZ_COMP_DEFLATE => {
                let mut decoder = DeflateDecoder::new(data);
                let mut decoded = Vec::new();
                decoder
                    .read_to_end(&mut decoded)
                    .map_or(0, |_| alz_crc32(&decoded))
            }
            _ => 0,
        };

        alz.extend_from_slice(&ALZ_LOCAL_FILE_HEADER.to_le_bytes());
        alz.extend_from_slice(&name_len.to_le_bytes());
        alz.push(file_attribute);
        alz.extend_from_slice(&0u32.to_le_bytes());
        alz.push(file_descriptor);
        alz.push(0);
        alz.push(compression_method);
        alz.push(0);
        alz.extend_from_slice(&file_crc.to_le_bytes());
        alz.push(compressed_size);
        alz.push(uncompressed_size);
        alz.extend_from_slice(name);
        if file_descriptor & 0x01 != 0 {
            alz.extend_from_slice(&[0; ALZ_ENCR_HEADER_LEN as usize]);
        }
        alz.extend_from_slice(data);
    }

    fn extraction_limits() -> AlzExtractionLimits {
        AlzExtractionLimits {
            max_file_size: u64::MAX,
            max_total_size: u64::MAX,
            max_files_remaining: usize::MAX,
        }
    }

    #[test]
    fn reader_stream_preserves_in_range_header_read_failure() {
        let reader = FmapFailureReader {
            inner: Cursor::new(ALZ_FILE_HEADER.to_le_bytes().to_vec()),
            fail_at: 0,
        };
        let mut files = Vec::new();

        let result = Alz::from_reader_with_filter_stream(
            reader,
            |_| AlzExtractionDecision::Extract(extraction_limits()),
            &mut files,
        );

        assert!(matches!(result, Err(Error::ReadFailure("ALZ file header"))));
    }

    #[test]
    fn reader_stream_preserves_in_range_member_read_failure() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "reader.txt", ALZ_COMP_NOCOMP, 4, b"read");
        let member_data_start = u64::try_from(bytes.len() - 4).unwrap();
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let reader = FmapFailureReader {
            inner: Cursor::new(bytes),
            fail_at: member_data_start,
        };
        let mut files = Vec::new();

        let result = Alz::from_reader_with_filter_stream(
            reader,
            |_| AlzExtractionDecision::Extract(extraction_limits()),
            &mut files,
        );

        assert!(matches!(result, Err(Error::ReadFailure("stored member data"))));
        assert!(files.is_empty());
    }

    #[test]
    fn reader_stream_path_preserves_member_output() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "reader.txt", ALZ_COMP_NOCOMP, 4, b"read");
        append_local_file(&mut bytes, "reader-2.txt", ALZ_COMP_NOCOMP, 5, b"again");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut files = Vec::new();
        let alz = Alz::from_reader_with_filter_stream(
            Cursor::new(bytes),
            |_| AlzExtractionDecision::Extract(extraction_limits()),
            &mut files,
        )
        .unwrap();

        assert!(!alz.has_parse_error());
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name.as_deref(), Some("reader.txt"));
        assert_eq!(files[0].data, b"read");
        assert_eq!(files[1].name.as_deref(), Some("reader-2.txt"));
        assert_eq!(files[1].data, b"again");
    }

    #[test]
    fn reader_stream_path_requires_end_marker() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        let mut files = Vec::new();
        let alz = Alz::from_reader_with_filter_stream(
            Cursor::new(bytes),
            |_| AlzExtractionDecision::Extract(extraction_limits()),
            &mut files,
        )
        .unwrap();

        assert!(alz.has_parse_error());
    }

    #[test]
    fn trailing_bytes_after_end_marker_are_fail_visible() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "payload.txt", ALZ_COMP_NOCOMP, 7, b"payload");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());
        bytes.push(0xde);

        let mut files = Vec::new();
        let alz = Alz::from_reader_with_filter_stream(
            Cursor::new(bytes),
            |_| AlzExtractionDecision::Extract(extraction_limits()),
            &mut files,
        )
        .unwrap();

        assert!(alz.has_parse_error());
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name.as_deref(), Some("payload.txt"));
        assert_eq!(files[0].data, b"payload");
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn alz_crc32_matches_known_payload() {
        assert_eq!(alz_crc32(b"test file 0"), 0xfa05_aa4a);
    }

    fn bzip2_truncated_after_output() -> Vec<u8> {
        vec![
            0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xe5, 0x69, 0x95, 0xee,
            0x00, 0x00, 0x01, 0x17, 0x80, 0x00, 0x02, 0x02, 0x00, 0x44, 0x00, 0x2e, 0x24, 0x9c,
            0x20, 0x20, 0x00, 0x31, 0x4c, 0x00, 0x01, 0x4d, 0x31, 0x32, 0x7a, 0x9b, 0x41, 0xa9,
            0x5d, 0x57, 0xa3, 0xe0, 0x0b, 0x2c, 0x6f, 0x98, 0x2e, 0xe4, 0x8a, 0x70, 0xa1,
        ]
    }

    #[test]
    fn extraction_error_does_not_stop_later_entries() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_BZIP2: u8 = 1;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "bad.bz2", ALZ_COMP_BZIP2, 1, &[0]);
        append_local_file(&mut bytes, "good.txt", ALZ_COMP_NOCOMP, 4, b"good");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("good.txt"));
        assert_eq!(alz.embedded_files[0].data, b"good");
    }

    #[test]
    fn bzip2_error_preserves_output_produced_before_error() {
        const ALZ_COMP_BZIP2: u8 = 1;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(
            &mut bytes,
            "truncated.bz2",
            ALZ_COMP_BZIP2,
            18,
            &bzip2_truncated_after_output(),
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("truncated.bz2"));
        assert!(!alz.embedded_files[0].data.is_empty());
    }

    #[test]
    fn bzip2_complete_stream_consumes_exact_extent() {
        let compressed = hex::decode(
            "425a6839314159265359ba10c2c4000001918040003424c03020002201a1ea10030dd85601c8f177245385090ba10c2c40",
        )
        .unwrap();
        let mut exact_reader = Bzip2ExactReader::new(compressed.as_slice());
        let mut decompressor = DecoderReader::new(&mut exact_reader);
        let mut output = Vec::new();
        decompressor.read_to_end(&mut output).unwrap();
        drop(decompressor);

        assert_eq!(output, b"bzip payload");
        assert!(exact_reader.is_fully_consumed());
    }

    #[test]
    fn bzip2_trailing_compressed_bytes_are_rejected_after_scan() {
        const ALZ_COMP_BZIP2: u8 = 1;

        let mut compressed = hex::decode(
            "425a6839314159265359ba10c2c4000001918040003424c03020002201a1ea10030dd85601c8f177245385090ba10c2c40",
        )
        .unwrap();
        compressed.push(0xde);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(
            &mut bytes,
            "trailing.bz2",
            ALZ_COMP_BZIP2,
            u8::try_from(compressed.len()).unwrap(),
            &compressed,
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].data, b"bzip payload");
        assert!(alz.has_parse_error());
    }

    #[test]
    fn deflate_error_preserves_output_produced_before_error() {
        struct ErrorAfterOutput {
            output: Option<Vec<u8>>,
        }

        let payload = vec![b'A'; 9000];
        let mut reader = ErrorAfterOutput {
            output: Some(payload.clone()),
        };
        impl Read for ErrorAfterOutput {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let Some(output) = self.output.take() else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "corrupt deflate stream",
                    ));
                };

                let len = output.len().min(buf.len());
                buf[..len].copy_from_slice(&output[..len]);
                self.output = if len < output.len() {
                    Some(output[len..].to_vec())
                } else {
                    None
                };

                Ok(len)
            }
        }

        let mut header = AlzLocalFileHeader::new();
        header.file_name = "corrupt.deflate".to_owned();
        let mut files = Vec::new();

        assert!(matches!(
            header.extract_file_deflate_reader_until_eof(&mut reader, &mut files, u64::MAX),
            Err(Error::Extract)
        ));

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name.as_deref(), Some("corrupt.deflate"));
        assert_eq!(files[0].data, payload);
    }

    #[test]
    fn later_parse_error_preserves_earlier_extracted_entries() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "good.txt", ALZ_COMP_NOCOMP, 4, b"good");
        bytes.extend_from_slice(&ALZ_LOCAL_FILE_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert!(alz.has_parse_error());
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("good.txt"));
        assert_eq!(alz.embedded_files[0].data, b"good");
    }

    #[test]
    fn invalid_payload_bounds_reports_metadata_before_parse_error() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_entry_with_sizes(
            &mut bytes,
            "secret.txt",
            AlzFileAttribute::File as u8,
            0x11,
            ALZ_COMP_NOCOMP,
            10,
            10,
            b"x",
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |entry| {
            metadata.push((
                entry.file_name.to_owned(),
                entry.filepos,
                entry.is_encrypted,
            ));
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert_eq!(metadata, vec![("secret.txt".to_owned(), 1, true)]);
        assert!(alz.has_parse_error());
        assert!(alz.embedded_files.is_empty());
    }

    #[test]
    fn directory_payload_is_fail_visible_after_metadata() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_entry(
            &mut bytes,
            "dir/",
            AlzFileAttribute::Directory as u8,
            0x10,
            ALZ_COMP_NOCOMP,
            1,
            b"x",
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |entry| {
            metadata.push((
                entry.file_name.to_owned(),
                entry.compressed_size,
                entry.uncompressed_size,
                entry.is_directory,
            ));
            AlzExtractionDecision::Skip
        })
        .unwrap();

        assert_eq!(metadata, vec![("dir/".to_owned(), 1, 1, true)]);
        assert!(alz.has_parse_error());
        assert!(alz.embedded_files.is_empty());
    }

    #[test]
    fn deflate_limit_uses_decompressed_size_not_header() {
        const ALZ_COMP_DEFLATE: u8 = 2;
        let payload = vec![b'A'; 1024];
        let compressed = raw_deflate(&payload);
        assert!(compressed.len() <= u8::MAX.into());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "big.txt", ALZ_COMP_DEFLATE, 1, &compressed);
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: 64,
                max_total_size: u64::MAX,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.file_limit_exceeded_size, Some(payload.len() as u64));
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].data, vec![b'A'; 64]);
    }

    #[test]
    fn total_limit_uses_checked_remaining_budget() {
        assert!(alz_total_size_exceeds_limit(u64::MAX, 1, u64::MAX));
        assert!(alz_total_size_exceeds_limit(5, 1, 5));
        assert!(!alz_total_size_exceeds_limit(4, 1, 5));
    }

    #[test]
    fn stored_output_size_mismatch_is_rejected_after_scanning_partial() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_entry_with_sizes(
            &mut bytes,
            "wrong-size.txt",
            AlzFileAttribute::File as u8,
            0x10,
            ALZ_COMP_NOCOMP,
            4,
            5,
            b"four",
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert!(alz.has_parse_error());
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].data, b"four");
    }

    #[test]
    fn stored_crc_mismatch_is_rejected_after_scanning_partial() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "bad.txt", ALZ_COMP_NOCOMP, 3, b"bad");
        bytes[23..27].copy_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert!(alz.has_parse_error());
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].data, b"bad");
    }

    #[test]
    fn deflate_output_size_mismatch_is_rejected_after_scanning_partial() {
        const ALZ_COMP_DEFLATE: u8 = 2;
        let payload = b"deflate payload";
        let compressed = raw_deflate(payload);
        assert!(compressed.len() <= u8::MAX.into());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_entry_with_sizes(
            &mut bytes,
            "wrong-deflate-size.txt",
            AlzFileAttribute::File as u8,
            0x10,
            ALZ_COMP_DEFLATE,
            u8::try_from(compressed.len()).unwrap(),
            u8::try_from(payload.len() - 1).unwrap(),
            &compressed,
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert!(alz.has_parse_error());
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].data, payload);
    }

    #[test]
    fn deflate_trailing_compressed_bytes_are_rejected_after_scan() {
        const ALZ_COMP_DEFLATE: u8 = 2;
        let payload = b"deflate payload";
        let mut compressed = raw_deflate(payload);
        compressed.push(0);
        assert!(compressed.len() <= u8::MAX.into());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_entry_with_sizes(
            &mut bytes,
            "trailing-deflate.bin",
            AlzFileAttribute::File as u8,
            0x10,
            ALZ_COMP_DEFLATE,
            u8::try_from(compressed.len()).unwrap(),
            u8::try_from(payload.len()).unwrap(),
            &compressed,
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert!(alz.has_parse_error());
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].data, payload);
    }

    #[test]
    fn total_limit_does_not_set_per_file_limit() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        let payload = vec![b'A'; 60];

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(
            &mut bytes,
            "a",
            ALZ_COMP_NOCOMP,
            payload.len() as u8,
            &payload,
        );
        append_local_file(
            &mut bytes,
            "b",
            ALZ_COMP_NOCOMP,
            payload.len() as u8,
            &payload,
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: 64,
                max_total_size: 100,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.file_limit_exceeded_size, None);
        assert_eq!(alz.total_limit_exceeded_size, Some(120));
        assert_eq!(alz.embedded_files.len(), 2);
        assert_eq!(alz.embedded_files[0].data.len(), 60);
        assert_eq!(alz.embedded_files[1].data.len(), 40);
    }

    #[test]
    fn exhausted_total_limit_skips_later_extraction() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 6,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, Some(12));
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn successful_empty_member_does_not_double_count_previous_output() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "empty.txt", ALZ_COMP_NOCOMP, 0, b"");
        append_local_file(&mut bytes, "third.txt", ALZ_COMP_NOCOMP, 6, b"third!");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 12,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, None);
        assert_eq!(alz.embedded_files.len(), 2);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[1].name.as_deref(), Some("third.txt"));
    }

    #[test]
    fn exhausted_total_limit_uses_stored_size_for_nocomp() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 0, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 6,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, Some(12));
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn exhausted_total_limit_records_compressed_entry_with_zero_declared_size() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_DEFLATE: u8 = 2;

        let compressed = raw_deflate(b"second");
        assert!(compressed.len() <= u8::MAX.into());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_DEFLATE, 0, &compressed);
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 6,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, Some(12));
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn zero_compressed_nonzero_declared_size_is_parse_error() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_DEFLATE: u8 = 2;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "empty.deflate", ALZ_COMP_DEFLATE, 6, b"");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 6,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, None);
        assert!(alz.has_parse_error());
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn zero_compressed_deflate_member_is_parse_error() {
        const ALZ_COMP_DEFLATE: u8 = 2;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "empty.deflate", ALZ_COMP_DEFLATE, 0, b"");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert!(alz.has_parse_error());
        assert!(alz.embedded_files.is_empty());
    }

    #[test]
    fn tiny_stored_file_bypasses_partial_size_budget() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "tiny.txt", ALZ_COMP_NOCOMP, 5, b"tiny!");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: 4,
                max_total_size: 4,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.file_limit_exceeded_size, None);
        assert_eq!(alz.total_limit_exceeded_size, None);
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("tiny.txt"));
        assert_eq!(alz.embedded_files[0].data, b"tiny!");
    }

    #[test]
    fn total_limit_skips_extraction_when_remaining_budget_is_tiny() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 10,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, Some(12));
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn total_limit_records_compressed_entry_when_remaining_budget_is_tiny() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_DEFLATE: u8 = 2;

        let compressed = raw_deflate(b"second");
        assert!(compressed.len() <= u8::MAX.into());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_DEFLATE, 1, &compressed);
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 10,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, Some(12));
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn exhausted_total_limit_does_not_record_unsupported_method() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_UNSUPPORTED: u8 = 99;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(
            &mut bytes,
            "unsupported.bin",
            ALZ_COMP_UNSUPPORTED,
            6,
            b"second",
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 6,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, None);
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn unsupported_method_is_recorded_for_scanner_admission() {
        const ALZ_COMP_UNSUPPORTED: u8 = 99;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(
            &mut bytes,
            "unsupported.bin",
            ALZ_COMP_UNSUPPORTED,
            6,
            b"second",
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert!(alz.has_unsupported_feature());
        assert!(alz.embedded_files.is_empty());
    }

    #[test]
    fn unsupported_method_with_invalid_payload_bounds_reports_parse_error() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_UNSUPPORTED: u8 = 99;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_entry_with_sizes(
            &mut bytes,
            "unsupported.bin",
            AlzFileAttribute::File as u8,
            0x10,
            ALZ_COMP_UNSUPPORTED,
            10,
            10,
            b"x",
        );
        append_local_file(&mut bytes, "later.txt", ALZ_COMP_NOCOMP, 6, b"later!");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(extraction_limits())
        })
        .unwrap();

        assert_eq!(metadata_names, vec!["unsupported.bin".to_owned()]);
        assert!(alz.has_parse_error());
        assert!(alz.embedded_files.is_empty());
    }

    #[test]
    fn queued_file_limit_ignores_unsupported_entries() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_entry(
            &mut bytes,
            "encrypted.bin",
            AlzFileAttribute::File as u8,
            0x11,
            ALZ_COMP_NOCOMP,
            6,
            b"second",
        );
        append_local_entry(
            &mut bytes,
            "descriptor.bin",
            AlzFileAttribute::File as u8,
            0x18,
            ALZ_COMP_NOCOMP,
            5,
            b"third",
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: 1,
            })
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec![
                "first.txt".to_owned(),
                "encrypted.bin".to_owned(),
                "descriptor.bin".to_owned()
            ]
        );
        assert!(!alz.file_count_limit_exceeded);
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn total_limit_ignores_tiny_members() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "tiny1.txt", ALZ_COMP_NOCOMP, 1, b"t");
        append_local_file(&mut bytes, "tiny2.txt", ALZ_COMP_NOCOMP, 1, b"u");
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let alz = Alz::from_bytes_with_filter(&bytes, |_| {
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: 6,
                max_files_remaining: usize::MAX,
            })
        })
        .unwrap();

        assert_eq!(alz.total_limit_exceeded_size, Some(12));
        assert_eq!(alz.embedded_files.len(), 3);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("tiny1.txt"));
        assert_eq!(alz.embedded_files[0].data, b"t");
        assert_eq!(alz.embedded_files[1].name.as_deref(), Some("tiny2.txt"));
        assert_eq!(alz.embedded_files[1].data, b"u");
        assert_eq!(alz.embedded_files[2].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[2].data, b"first!");
    }

    #[test]
    fn queued_file_limit_skips_later_extraction() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        append_local_file(&mut bytes, "third.txt", ALZ_COMP_NOCOMP, 6, b"third!");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: 1,
            })
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec!["first.txt".to_owned(), "second.txt".to_owned()]
        );
        assert!(alz.file_count_limit_exceeded);
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn queued_file_limit_stops_before_later_invalid_payload_bounds() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_entry_with_sizes(
            &mut bytes,
            "truncated.txt",
            AlzFileAttribute::File as u8,
            0x10,
            ALZ_COMP_NOCOMP,
            10,
            10,
            b"x",
        );
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: 1,
            })
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec!["first.txt".to_owned(), "truncated.txt".to_owned()]
        );
        assert!(alz.file_count_limit_exceeded);
        assert!(!alz.has_parse_error());
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn queued_file_limit_ignores_tiny_members() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "tiny.txt", ALZ_COMP_NOCOMP, 1, b"t");
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: 1,
            })
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec![
                "tiny.txt".to_owned(),
                "first.txt".to_owned(),
                "second.txt".to_owned()
            ]
        );
        assert!(alz.file_count_limit_exceeded);
        assert_eq!(alz.embedded_files.len(), 2);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("tiny.txt"));
        assert_eq!(alz.embedded_files[0].data, b"t");
        assert_eq!(alz.embedded_files[1].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[1].data, b"first!");
    }

    #[test]
    fn queued_file_limit_allows_tiny_current_member() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "tiny.txt", ALZ_COMP_NOCOMP, 1, b"t");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: 1,
            })
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec!["first.txt".to_owned(), "tiny.txt".to_owned()]
        );
        assert!(!alz.file_count_limit_exceeded);
        assert_eq!(alz.embedded_files.len(), 2);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
        assert_eq!(alz.embedded_files[1].name.as_deref(), Some("tiny.txt"));
        assert_eq!(alz.embedded_files[1].data, b"t");
    }

    #[test]
    fn queued_file_limit_does_not_trust_compressed_tiny_hint() {
        const ALZ_COMP_NOCOMP: u8 = 0;
        const ALZ_COMP_DEFLATE: u8 = 2;

        let compressed = raw_deflate(b"second");
        assert!(compressed.len() <= u8::MAX.into());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 6, b"first!");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_DEFLATE, 0, &compressed);
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Extract(AlzExtractionLimits {
                max_file_size: u64::MAX,
                max_total_size: u64::MAX,
                max_files_remaining: 1,
            })
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec!["first.txt".to_owned(), "second.txt".to_owned()]
        );
        assert!(alz.file_count_limit_exceeded);
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first!");
    }

    #[test]
    fn stop_decision_stops_archive_traversal() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 5, b"first");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Stop
        })
        .unwrap();

        assert!(alz.embedded_files.is_empty());
        assert_eq!(metadata_names, vec!["first.txt".to_owned()]);
    }

    #[test]
    fn stop_decision_runs_for_directory_entries() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_entry(
            &mut bytes,
            "dir/",
            AlzFileAttribute::Directory as u8,
            0x10,
            ALZ_COMP_NOCOMP,
            0,
            b"",
        );
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 5, b"first");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            AlzExtractionDecision::Stop
        })
        .unwrap();

        assert!(alz.embedded_files.is_empty());
        assert_eq!(metadata_names, vec!["dir/".to_owned()]);
    }

    #[test]
    fn stop_decision_preserves_earlier_extracted_entries() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 5, b"first");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_names = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_names.push(metadata.file_name.to_owned());
            if metadata.file_name == "second.txt" {
                AlzExtractionDecision::Stop
            } else {
                AlzExtractionDecision::Extract(extraction_limits())
            }
        })
        .unwrap();

        assert_eq!(
            metadata_names,
            vec!["first.txt".to_owned(), "second.txt".to_owned()]
        );
        assert_eq!(alz.embedded_files.len(), 1);
        assert_eq!(alz.embedded_files[0].name.as_deref(), Some("first.txt"));
        assert_eq!(alz.embedded_files[0].data, b"first");
    }

    #[test]
    fn metadata_file_positions_are_one_based_and_include_skipped_entries() {
        const ALZ_COMP_NOCOMP: u8 = 0;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ALZ_FILE_HEADER.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        append_local_entry(
            &mut bytes,
            "dir/",
            AlzFileAttribute::Directory as u8,
            0x10,
            ALZ_COMP_NOCOMP,
            0,
            b"",
        );
        append_local_entry(
            &mut bytes,
            "encrypted.bin",
            AlzFileAttribute::File as u8,
            0x11,
            ALZ_COMP_NOCOMP,
            0,
            b"",
        );
        append_local_file(&mut bytes, "first.txt", ALZ_COMP_NOCOMP, 5, b"first");
        append_local_file(&mut bytes, "second.txt", ALZ_COMP_NOCOMP, 6, b"second");
        bytes.extend_from_slice(&ALZ_END_OF_CENTRAL_DIRECTORY_HEADER.to_le_bytes());

        let mut metadata_positions = Vec::new();
        let alz = Alz::from_bytes_with_filter(&bytes, |metadata| {
            metadata_positions.push((
                metadata.file_name.to_owned(),
                metadata.filepos,
                metadata.is_encrypted,
                metadata.is_directory,
            ));
            AlzExtractionDecision::Skip
        })
        .unwrap();

        assert!(alz.embedded_files.is_empty());
        assert_eq!(
            metadata_positions,
            vec![
                ("dir/".to_owned(), 1, false, true),
                ("encrypted.bin".to_owned(), 2, true, false),
                ("first.txt".to_owned(), 3, false, false),
                ("second.txt".to_owned(), 4, false, false),
            ]
        );
    }
}
