/*
 *  Rust equivalent of libclamav's scanners.c module
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
    ffi::{c_char, CStr, CString},
    io::Read,
    panic,
    path::Path,
    ptr::null_mut,
};

use delharc::LhaDecodeReader;
use libc::c_void;
use log::{debug, error, warn};

use crate::{
    alz::{Alz, AlzExtractionDecision, AlzExtractionLimits, Error as AlzError, ExtractSink},
    ctx,
    fmap::{FMap, FMapReader},
    sys,
    onenote::{self, OneNote},
    sys::{
        cl_error_t, cl_error_t_CL_EFORMAT, cl_error_t_CL_EMAXFILES, cl_error_t_CL_EMAXSIZE,
        cl_error_t_CL_EMEM, cl_error_t_CL_EPARSE, cl_error_t_CL_ERROR, cl_error_t_CL_ERESOURCE,
        cl_error_t_CL_ESEEK, cl_error_t_CL_ETMPFILE, cl_error_t_CL_EUNLINK, cl_error_t_CL_EWRITE,
        cl_error_t_CL_SUCCESS, cl_error_t_CL_VIRUS, cli_ctx, cli_magic_scan_buff,
    },
    util::{
        append_potentially_unwanted_if_heur_exceedsmax, check_scan_limits, check_scan_time_limit,
        scan_archive_metadata, HEURISTICS_LIMITS_EXCEEDED_MAX_FILES,
        HEURISTICS_LIMITS_EXCEEDED_MAX_SCAN_SIZE,
    },
};

unsafe fn parser_failure(
    ctx: *mut cli_ctx,
    parser: &str,
    status: cl_error_t,
    err: impl std::fmt::Display,
) -> cl_error_t {
    error!("{parser} parser stopped before inspection completed: {err}");
    sys::emax_reached(ctx);
    (*ctx).scan_incomplete = true;
    status
}

unsafe fn parser_input_failure(ctx: *mut cli_ctx, parser: &str, err: impl std::fmt::Display) -> cl_error_t {
    parser_failure(ctx, parser, cl_error_t_CL_EPARSE, err)
}

/// Rust wrapper of libclamav's cli_magic_scan_buff() function.
/// Use magic sigs to identify the file type and then scan it.
///
/// # Safety
///
/// The ctx pointer must be valid.
pub unsafe fn magic_scan(ctx: *mut cli_ctx, buf: &[u8], name: Option<String>) -> cl_error_t {
    let ptr = buf.as_ptr();
    let len = buf.len();

    if 0 == len {
        return cl_error_t_CL_SUCCESS;
    }

    match &name {
        Some(name) => debug!("Scanning {}-byte file named {:?}.", len, name),
        None => debug!("Scanning {}-byte unnamed file.", len),
    }

    // Convert name to a C string.
    let name = name.unwrap_or_default();

    let name_ptr: *mut c_char = match CString::new(name) {
        Ok(name_cstr) => {
            // into_raw() so name_cstr doesn't get dropped and
            // we don't do an unsafe deref of the pointer.
            name_cstr.into_raw()
        }
        Err(_) => null_mut(),
    };

    let ret = unsafe { cli_magic_scan_buff(ptr as *const c_void, len, ctx, name_ptr, 0) };
    if ret != cl_error_t_CL_SUCCESS {
        debug!("cli_magic_scan_buff returned error: {}", ret);
    }

    // Okay now safe to drop the name CString.
    if !name_ptr.is_null() {
        let _ = unsafe { CString::from_raw(name_ptr) };
    }

    ret
}

/// Disk-backed output used by Rust decoders. The reservation is held for the
/// complete lifetime of the spool, including the child scan, so parser
/// output and nested parser temporary files share the same budget.
struct TempSpool {
    ctx: *mut cli_ctx,
    fd: libc::c_int,
    path: CString,
    reserved: u64,
    written: u64,
}

impl TempSpool {
    unsafe fn new(ctx: *mut cli_ctx, expected_size: u64) -> Result<Self, cl_error_t> {
        let status = sys::cli_scan_reserve_temporary(ctx, expected_size);
        if status != cl_error_t_CL_SUCCESS {
            return Err(status);
        }

        let mut raw_name = null_mut();
        let mut fd = -1;
        let status = sys::cli_gentempfd(
            if (*ctx).this_layer_tmpdir.is_null() {
                std::ptr::null()
            } else {
                (*ctx).this_layer_tmpdir
            },
            &mut raw_name,
            &mut fd,
        );
        if status != cl_error_t_CL_SUCCESS || raw_name.is_null() || fd < 0 {
            if fd >= 0 {
                libc::close(fd);
            }
            if !raw_name.is_null() {
                libc::free(raw_name.cast());
            }
            sys::cli_scan_release_temporary(ctx, expected_size);
            return Err(if status == cl_error_t_CL_SUCCESS {
                cl_error_t_CL_ETMPFILE
            } else {
                status
            });
        }

        let path = CStr::from_ptr(raw_name).to_owned();
        libc::free(raw_name.cast());
        Ok(Self {
            ctx,
            fd,
            path,
            reserved: expected_size,
            written: 0,
        })
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), cl_error_t> {
        let requested = u64::try_from(bytes.len()).map_err(|_| cl_error_t_CL_ERESOURCE)?;
        let available = self.reserved.saturating_sub(self.written);
        if requested > available {
            let additional = requested.saturating_sub(available);
            let status = unsafe { sys::cli_scan_reserve_temporary(self.ctx, additional) };
            if status != cl_error_t_CL_SUCCESS {
                return Err(status);
            }
            self.reserved = self.reserved.saturating_add(additional);
        }

        let mut offset = 0usize;
        while offset < bytes.len() {
            let written = unsafe {
                libc::write(
                    self.fd,
                    bytes[offset..].as_ptr().cast(),
                    bytes.len() - offset,
                )
            };
            if written <= 0 {
                return Err(cl_error_t_CL_EWRITE);
            }
            offset = offset.saturating_add(written as usize);
        }
        self.written = self.written.saturating_add(requested);
        Ok(())
    }

    unsafe fn scan(&mut self, name: Option<&str>) -> cl_error_t {
        if libc::lseek(self.fd, 0, libc::SEEK_SET) < 0 {
            return parser_failure(
                self.ctx,
                "Rust temporary spool",
                cl_error_t_CL_ESEEK,
                "temporary spool could not be rewound before nested scanning",
            );
        }
        let name = name.and_then(|value| CString::new(value).ok());
        sys::cli_magic_scan_desc_type_reserved(
            self.fd,
            self.path.as_ptr(),
            self.ctx,
            0,
            name.as_ref().map_or(std::ptr::null(), |value| value.as_ptr()),
            0,
        )
    }

    unsafe fn mark_cleanup_failure(&self, status: cl_error_t, reason: &str) {
        let _ = parser_failure(self.ctx, "Rust temporary spool", status, reason);
    }

    unsafe fn release_reservation(&mut self) {
        if self.reserved != 0 {
            sys::cli_scan_release_temporary(self.ctx, self.reserved);
            self.reserved = 0;
        }
    }
}

impl Drop for TempSpool {
    fn drop(&mut self) {
        unsafe {
            if self.fd >= 0 {
                if libc::close(self.fd) != 0 {
                    self.mark_cleanup_failure(
                        cl_error_t_CL_EWRITE,
                        "temporary spool could not be closed",
                    );
                }
                self.fd = -1;
            }

            let keep_tmp = !(*self.ctx).engine.is_null()
                && (*(*self.ctx).engine).keeptmp != 0;
            if !keep_tmp
                && sys::cli_unlink(self.path.as_ptr()) != cl_error_t_CL_SUCCESS
            {
                self.mark_cleanup_failure(
                    cl_error_t_CL_EUNLINK,
                    "temporary spool could not be removed",
                );
            }

            self.release_reservation();
        }
    }
}

struct AlzScanSink {
    ctx: *mut cli_ctx,
    spool: Option<TempSpool>,
    name: Option<String>,
    last_size: u64,
    scan_result: cl_error_t,
}

impl AlzScanSink {
    fn new(ctx: *mut cli_ctx) -> Self {
        Self {
            ctx,
            spool: None,
            name: None,
            last_size: 0,
            scan_result: cl_error_t_CL_SUCCESS,
        }
    }

    fn record_failure(&mut self, status: cl_error_t, reason: &str) -> AlzError {
        self.abort();
        self.scan_result = unsafe { parser_failure(self.ctx, "ALZ", status, reason) };
        AlzError::Stop
    }
}

impl ExtractSink for AlzScanSink {
    fn begin(&mut self, name: Option<&str>) -> Result<(), AlzError> {
        self.abort();
        self.last_size = 0;
        self.name = name.map(str::to_owned);
        self.spool = match unsafe { TempSpool::new(self.ctx, 0) } {
            Ok(spool) => Some(spool),
            Err(status) => return Err(self.record_failure(status, "member temporary spool reservation failed")),
        };
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<(), AlzError> {
        let status = match self.spool.as_mut() {
            Some(spool) => spool.write_all(data),
            None => Err(cl_error_t_CL_EWRITE),
        };
        if let Err(status) = status {
            return Err(self.record_failure(status, "member temporary spool write failed"));
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), AlzError> {
        let Some(mut spool) = self.spool.take() else {
            return Err(self.record_failure(cl_error_t_CL_EWRITE, "member spool was not started"));
        };
        let name = self.name.take();
        self.last_size = spool.written;
        if spool.written == 0 {
            return Ok(());
        }

        let ret = unsafe { spool.scan(name.as_deref()) };
        if ret != cl_error_t_CL_SUCCESS {
            self.scan_result = ret;
            return Err(AlzError::Stop);
        }
        Ok(())
    }

    fn last_size(&self) -> u64 {
        self.last_size
    }

    fn abort(&mut self) {
        self.spool.take();
        self.name = None;
    }
}

struct OneNoteScanSink {
    ctx: *mut cli_ctx,
    spool: Option<TempSpool>,
    scan_result: cl_error_t,
}

impl OneNoteScanSink {
    fn new(ctx: *mut cli_ctx) -> Self {
        Self {
            ctx,
            spool: None,
            scan_result: cl_error_t_CL_SUCCESS,
        }
    }

    fn record_failure(&mut self, status: cl_error_t, reason: &str) -> onenote::Error {
        self.abort();
        self.scan_result = unsafe { parser_failure(self.ctx, "OneNote", status, reason) };
        onenote::Error::Sink(reason.to_owned())
    }
}

impl onenote::LegacyAttachmentSink for OneNoteScanSink {
    fn begin(&mut self) -> Result<(), onenote::Error> {
        self.abort();
        self.spool = match unsafe { TempSpool::new(self.ctx, 0) } {
            Ok(spool) => Some(spool),
            Err(status) => {
                return Err(self.record_failure(
                    status,
                    "attachment temporary spool reservation failed",
                ));
            }
        };
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<(), onenote::Error> {
        let status = match self.spool.as_mut() {
            Some(spool) => spool.write_all(data),
            None => Err(cl_error_t_CL_EWRITE),
        };
        if let Err(status) = status {
            return Err(self.record_failure(
                status,
                "attachment temporary spool write failed",
            ));
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), onenote::Error> {
        let Some(mut spool) = self.spool.take() else {
            return Err(self.record_failure(
                cl_error_t_CL_EWRITE,
                "attachment spool was not started",
            ));
        };
        if spool.written == 0 {
            return Ok(());
        }

        let ret = unsafe { spool.scan(None) };
        if ret != cl_error_t_CL_SUCCESS {
            self.scan_result = ret;
            return Err(onenote::Error::Sink(
                "attachment scan returned a non-success status".to_owned(),
            ));
        }
        Ok(())
    }

    fn abort(&mut self) {
        self.spool.take();
    }
}

/// Read-only view of a disk-backed parser input. The mapping is deliberately
/// created only after the source has been copied through FMapReader and is
/// released before the root temporary reservation is dropped.
struct MappedInput {
    address: *mut c_void,
    length: usize,
}

impl MappedInput {
    unsafe fn new(fd: libc::c_int, length: usize) -> Result<Self, cl_error_t> {
        if length == 0 {
            return Ok(Self {
                address: null_mut(),
                length: 0,
            });
        }
        if length > isize::MAX as usize {
            return Err(cl_error_t_CL_ERESOURCE);
        }

        let address = libc::mmap(
            null_mut(),
            length,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            0,
        );
        if address == libc::MAP_FAILED {
            return Err(cl_error_t_CL_EMEM);
        }

        Ok(Self { address, length })
    }

    fn as_slice(&self) -> &[u8] {
        if self.length == 0 {
            return &[];
        }

        unsafe { std::slice::from_raw_parts(self.address.cast(), self.length) }
    }
}

impl Drop for MappedInput {
    fn drop(&mut self) {
        if self.length != 0 {
            unsafe {
                libc::munmap(self.address, self.length);
            }
        }
    }
}

/// Copy a source fmap through a bounded reader into a temporary file. This
/// keeps the parser's large-input residency accounted and avoids asking the
/// fmap layer to prefault the entire source in one operation.
unsafe fn spool_fmap(ctx: *mut cli_ctx, fmap: &FMap) -> Result<TempSpool, cl_error_t> {
    let expected_size = u64::try_from(fmap.len()).map_err(|_| cl_error_t_CL_ERESOURCE)?;
    let mut spool = TempSpool::new(ctx, expected_size)?;
    let mut reader = FMapReader::new(fmap);
    let mut buffer = [0u8; 1024 * 1024];
    let mut copied = 0u64;

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| cl_error_t_CL_EREAD)?;
        if read == 0 {
            break;
        }
        spool.write_all(&buffer[..read])?;
        copied = copied.saturating_add(read as u64);
    }

    if copied != expected_size {
        return Err(cl_error_t_CL_EREAD);
    }

    Ok(spool)
}

/// Scan a OneNote file for attachments
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[no_mangle]
pub unsafe extern "C" fn scan_onenote(ctx: *mut cli_ctx) -> cl_error_t {
    let fmap = match ctx::current_fmap(ctx) {
        Ok(fmap) => fmap,
        Err(e) => {
            return parser_failure(ctx, "OneNote", cl_error_t_CL_ERROR, e);
        }
    };

    let mut reader = FMapReader::new(&fmap);
    let mut prefix = [0u8; 16];
    if let Err(err) = reader.read_exact(&mut prefix) {
        return parser_failure(ctx, "OneNote", cl_error_t_CL_EPARSE, err);
    }
    if onenote::is_legacy_magic(&prefix) {
        let file_len = match u64::try_from(fmap.len()) {
            Ok(size) => size,
            Err(_) => {
                return parser_failure(
                    ctx,
                    "OneNote",
                    cl_error_t_CL_ERESOURCE,
                    "OneNote input size is not representable in the 64-bit accounting domain",
                );
            }
        };
        let mut sink = OneNoteScanSink::new(ctx);
        let parse_result = onenote::scan_legacy_reader(&mut reader, file_len, &mut sink);
        if sink.scan_result != cl_error_t_CL_SUCCESS {
            return sink.scan_result;
        }
        return match parse_result {
            Ok(()) => cl_error_t_CL_SUCCESS,
            Err(err) => parser_failure(ctx, "OneNote", cl_error_t_CL_EPARSE, err),
        };
    }

    let root_spool = match spool_fmap(ctx, &fmap) {
        Ok(spool) => spool,
        Err(status) => return parser_failure(ctx, "OneNote", status, "root temporary spool could not be populated"),
    };

    let mapped = match MappedInput::new(root_spool.fd, fmap.len()) {
        Ok(mapped) => mapped,
        Err(status) => return parser_failure(ctx, "OneNote", status, "root temporary spool mapping failed"),
    };
    let mut scan_result = cl_error_t_CL_SUCCESS;

    let parse_result = OneNote::scan_bytes(mapped.as_slice(), Path::new(fmap.name()), |name, data| {
        debug!(
            "Extracted {}-byte attachment with name: {:?}",
            data.len(),
            name
        );

        let expected_size = match u64::try_from(data.len()) {
            Ok(size) => size,
            Err(_) => {
                scan_result = parser_failure(
                    ctx,
                    "OneNote",
                    cl_error_t_CL_ERESOURCE,
                    "attachment size does not fit the 64-bit accounting domain",
                );
                return false;
            }
        };
        let mut attachment_spool = match TempSpool::new(ctx, expected_size) {
            Ok(spool) => spool,
            Err(status) => {
                scan_result = parser_failure(ctx, "OneNote", status, "attachment temporary spool reservation failed");
                return false;
            }
        };
        if let Err(status) = attachment_spool.write_all(data) {
            scan_result = parser_failure(ctx, "OneNote", status, "attachment temporary spool write failed");
            return false;
        }

        let ret = attachment_spool.scan(name);
        if ret != cl_error_t_CL_SUCCESS {
            scan_result = ret;
            return false;
        }

        true
    });

    if scan_result != cl_error_t_CL_SUCCESS {
        return scan_result;
    }

    match parse_result {
        Ok(()) => cl_error_t_CL_SUCCESS,
        Err(err) => parser_failure(ctx, "OneNote", cl_error_t_CL_EPARSE, err),
    }
}

/// Scan the contents of a LHA or LZH archive
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[no_mangle]
pub unsafe extern "C" fn scan_lha_lzh(ctx: *mut cli_ctx) -> cl_error_t {
    let fmap = match ctx::current_fmap(ctx) {
        Ok(fmap) => fmap,
        Err(e) => {
            return parser_failure(ctx, "LHA/LZH", cl_error_t_CL_ERROR, e);
        }
    };

    // Try to parse the LHA/LZH file data using the delharc crate.
    debug!("Attempting to parse the LHA/LZH file data using the delharc crate.");

    // Attempt to catch panics in case the parser encounter unexpected issues.
    let result_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        LhaDecodeReader::new(FMapReader::new(&fmap))
    }));

    // Check if it panicked. If no panic, grab the parse result.
    let result = match result_result {
        Ok(result) => result,
        Err(_) => {
            return parser_failure(
                ctx,
                "LHA/LZH",
                cl_error_t_CL_EFORMAT,
                "decoder panicked while opening the archive",
            );
        }
    };

    // Check if any issue opening the archive.
    let mut decoder = match result {
        Ok(result) => result,
        Err(err) => {
            return parser_failure(ctx, "LHA/LZH", cl_error_t_CL_EFORMAT, err);
        }
    };

    debug!("Opened the LHA/LZH archive");

    let mut index: usize = 0;
    loop {
        // Check if we've already exceeded the limits and should bail out.
        let ret = check_scan_limits("LHA", ctx, 0, 0, 0);
        if ret != cl_error_t_CL_SUCCESS {
            debug!("Exceeded scan limits. Bailing out.");
            return ret;
        }

        // Get the file header.
        let header = decoder.header();

        let filepath = header.parse_pathname();
        let filename = filepath.to_string_lossy();
        if header.is_directory() {
            debug!("Skipping directory {filename}");
        } else {
            debug!("Found file in LHA archive: {filename}");

            // Scan the archive metadata first.
            if scan_archive_metadata(
                ctx,
                &filename,
                header.compressed_size as usize,
                header.original_size as usize,
                false,
                index,
                header.file_crc as i32,
            ) != cl_error_t_CL_SUCCESS
            {
                debug!("Extracted file '{filename}' would exceed size limits. Skipping.");
            } else {
                // Check if scanning the next file would exceed the limits and should be skipped.
                if check_scan_limits("LHA", ctx, header.original_size, 0, 0)
                    != cl_error_t_CL_SUCCESS
                {
                    debug!("Extracted file '{filename}' would exceed size limits. Skipping.");
                } else if !decoder.is_decoder_supported() {
                    return parser_failure(
                        ctx,
                        "LHA/LZH",
                        cl_error_t_CL_EFORMAT,
                        "member compression method is unsupported",
                    );
                } else {
                    let expected_size = header.original_size;
                    let mut spool = match TempSpool::new(ctx, expected_size) {
                        Ok(spool) => spool,
                        Err(status) => return parser_failure(ctx, "LHA/LZH", status, "member spool reservation failed"),
                    };
                    let mut bytes_read = 0u64;
                    let mut buffer = [0u8; 1024 * 1024];
                    loop {
                        match decoder.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(read) => {
                                if let Err(status) = spool.write_all(&buffer[..read]) {
                                    return parser_failure(ctx, "LHA/LZH", status, "member output exceeded its declared size or could not be written");
                                }
                                bytes_read = bytes_read.saturating_add(read as u64);
                            }
                            Err(err) => {
                                return parser_failure(
                                    ctx,
                                    "LHA/LZH",
                                    cl_error_t_CL_EFORMAT,
                                    format!("member read failed: {err}"),
                                );
                            }
                        }
                    }

                    if bytes_read != expected_size {
                        return parser_failure(
                            ctx,
                            "LHA/LZH",
                            cl_error_t_CL_EFORMAT,
                            format!("member decoder returned {bytes_read} bytes for a declared size of {expected_size} bytes"),
                        );
                    }

                    if bytes_read > 0 {
                        debug!("Read {bytes_read} bytes from file {filename} in the LHA archive.");

                        // Verify the CRC check *after* reading the file.
                        match decoder.crc_check() {
                            Ok(crc) => debug!("CRC check passed for LHA/LZH member; CRC: {crc}"),
                            Err(err) => {
                                return parser_failure(
                                    ctx,
                                    "LHA/LZH",
                                    cl_error_t_CL_EFORMAT,
                                    format!("member CRC check failed: {err}"),
                                );
                            }
                        }

                        let ret = spool.scan(Some(&filename));
                        if ret != cl_error_t_CL_SUCCESS {
                            debug!("spooled LHA member scan returned error: {}", ret);
                            return ret;
                        }
                    } else {
                        debug!("Read zero-byte file.");
                    }
                }
            }

            index += 1;
        }

        // Get the next file.
        match decoder.next_file() {
            Ok(true) => {
                debug!("Found another file in the archive!");
            }
            Ok(false) => {
                debug!("No more files in the archive.");
                break;
            }
            Err(err) => {
                return parser_failure(ctx, "LHA/LZH", cl_error_t_CL_EFORMAT, err);
            }
        }
    }

    cl_error_t_CL_SUCCESS
}

unsafe fn alz_extraction_limits(ctx: *mut cli_ctx) -> AlzExtractionLimits {
    if ctx.is_null() || (*ctx).engine.is_null() {
        return AlzExtractionLimits {
            max_file_size: u64::MAX,
            max_total_size: u64::MAX,
            max_files_remaining: usize::MAX,
        };
    }

    let engine = &*(*ctx).engine;
    let max_files_remaining = if engine.maxfiles == 0 {
        usize::MAX
    } else {
        usize::try_from(engine.maxfiles.saturating_sub((*ctx).scannedfiles)).unwrap_or(usize::MAX)
    };

    AlzExtractionLimits {
        max_file_size: if engine.maxfilesize == 0 {
            u64::MAX
        } else {
            engine.maxfilesize
        },
        max_total_size: if engine.maxscansize == 0 {
            u64::MAX
        } else {
            engine.maxscansize.saturating_sub((*ctx).scansize)
        },
        max_files_remaining,
    }
}

fn handle_alz_metadata_scan_result(
    file_name: &str,
    metadata_ret: cl_error_t,
    alz_metadata_ret: &mut cl_error_t,
) -> bool {
    match metadata_ret {
        ret if ret == cl_error_t_CL_SUCCESS => true,
        ret if ret == cl_error_t_CL_EFORMAT => {
            debug!(
                "ALZ file {:?} metadata scan failed with {}. Continuing extraction.",
                file_name, metadata_ret
            );
            true
        }
        ret if ret == cl_error_t_CL_VIRUS => {
            *alz_metadata_ret = metadata_ret;
            debug!(
                "ALZ file {:?} metadata did not pass scan checks. Skipping extraction.",
                file_name
            );
            false
        }
        _ => {
            *alz_metadata_ret = metadata_ret;
            debug!(
                "ALZ file {:?} metadata scan failed with {}. Aborting extraction.",
                file_name, metadata_ret
            );
            false
        }
    }
}

fn handle_alz_metadata_limit_result(
    limit_ret: cl_error_t,
    alz_metadata_ret: &mut cl_error_t,
) -> bool {
    match limit_ret {
        ret if ret == cl_error_t_CL_SUCCESS => true,
        ret if ret == cl_error_t_CL_EMAXFILES => false,
        _ => {
            *alz_metadata_ret = limit_ret;
            false
        }
    }
}

fn alz_metadata_size(size: u64) -> Option<usize> {
    usize::try_from(size).ok()
}

fn handle_alz_metadata_directory_limit_result(
    limit_ret: cl_error_t,
    alz_metadata_ret: &mut cl_error_t,
) -> bool {
    match limit_ret {
        ret if ret == cl_error_t_CL_SUCCESS => true,
        _ => {
            *alz_metadata_ret = limit_ret;
            false
        }
    }
}

/// Scan an Alz file for attachments
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[no_mangle]
pub unsafe extern "C" fn cli_scanalz(ctx: *mut cli_ctx) -> cl_error_t {
    let fmap = match ctx::current_fmap(ctx) {
        Ok(fmap) => fmap,
        Err(e) => {
            return parser_failure(ctx, "ALZ", cl_error_t_CL_ERROR, e);
        }
    };

    let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;
    let mut sink = AlzScanSink::new(ctx);
    let alz_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        Alz::from_reader_with_filter_stream(FMapReader::new(&fmap), |metadata| {
            if alz_metadata_ret != cl_error_t_CL_SUCCESS {
                return AlzExtractionDecision::Stop;
            }

            if metadata.is_directory {
                let limit_ret = check_scan_time_limit(ctx);
                if !handle_alz_metadata_directory_limit_result(limit_ret, &mut alz_metadata_ret) {
                    debug!("Exceeded scan limits. Bailing out.");
                    return AlzExtractionDecision::Stop;
                }

                return AlzExtractionDecision::Skip;
            }

            let limit_ret = check_scan_limits("ALZ", ctx, 0, 0, 0);
            if !handle_alz_metadata_limit_result(limit_ret, &mut alz_metadata_ret) {
                debug!("Exceeded scan limits. Bailing out.");
                return AlzExtractionDecision::Stop;
            }

            match (
                alz_metadata_size(metadata.compressed_size),
                alz_metadata_size(metadata.uncompressed_size),
            ) {
                (Some(compressed_size), Some(uncompressed_size)) => {
                    let metadata_ret = scan_archive_metadata(
                        ctx,
                        metadata.file_name,
                        compressed_size,
                        uncompressed_size,
                        metadata.is_encrypted,
                        metadata.filepos,
                        metadata.file_crc as i32,
                    );
                    if !handle_alz_metadata_scan_result(
                        metadata.file_name,
                        metadata_ret,
                        &mut alz_metadata_ret,
                    ) {
                        return AlzExtractionDecision::Stop;
                    }
                }
                _ => {
                    debug!(
                        "ALZ file {:?} metadata size does not fit platform size_t. Skipping metadata scan.",
                        metadata.file_name
                    );
                }
            }

            AlzExtractionDecision::Extract(alz_extraction_limits(ctx))
        }, &mut sink)
    }));

    if sink.scan_result != cl_error_t_CL_SUCCESS {
        return sink.scan_result;
    }

    let alz = match alz_result {
        Ok(Ok(x)) => x,
        Ok(Err(AlzError::Alloc)) => {
            debug!("Failed to allocate memory when parsing ALZ archive");
            return parser_failure(
                ctx,
                "ALZ",
                cl_error_t_CL_EMEM,
                "archive parser allocation failed",
            );
        }
        Ok(Err(err)) => {
            return parser_failure(ctx, "ALZ", cl_error_t_CL_EFORMAT, err);
        }
        Err(_) => {
            return parser_failure(
                ctx,
                "ALZ",
                cl_error_t_CL_EFORMAT,
                "parser panicked while reading the archive",
            );
        }
    };

    if alz_metadata_ret != cl_error_t_CL_SUCCESS {
        return alz_metadata_ret;
    }

    if let Some(needed) = alz.file_limit_exceeded_size {
        let ret = check_scan_limits("ALZ", ctx, needed, 0, 0);
        if ret != cl_error_t_CL_SUCCESS && ret != cl_error_t_CL_EMAXSIZE {
            return ret;
        }
    }

    if alz.total_limit_exceeded_size.is_some() {
        append_potentially_unwanted_if_heur_exceedsmax(
            ctx,
            HEURISTICS_LIMITS_EXCEEDED_MAX_SCAN_SIZE,
            cl_error_t_CL_EMAXSIZE,
        );
    }

    if alz.file_count_limit_exceeded {
        append_potentially_unwanted_if_heur_exceedsmax(
            ctx,
            HEURISTICS_LIMITS_EXCEEDED_MAX_FILES,
            cl_error_t_CL_EMAXFILES,
        );
    }

    if alz.has_parse_error() {
        return parser_failure(
            ctx,
            "ALZ",
            cl_error_t_CL_EFORMAT,
            "archive parser reported an incomplete or malformed member",
        );
    }

    cl_error_t_CL_SUCCESS
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::cl_error_t_CL_ETIMEOUT;

    #[test]
    fn alz_metadata_scan_success_continues() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(handle_alz_metadata_scan_result(
            "entry",
            cl_error_t_CL_SUCCESS,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_SUCCESS);
    }

    #[test]
    fn alz_metadata_scan_format_error_continues() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(handle_alz_metadata_scan_result(
            "entry",
            cl_error_t_CL_EFORMAT,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_SUCCESS);
    }

    #[test]
    fn alz_metadata_scan_virus_stops() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(!handle_alz_metadata_scan_result(
            "entry",
            cl_error_t_CL_VIRUS,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_VIRUS);
    }

    #[test]
    fn alz_metadata_scan_hard_error_stops() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(!handle_alz_metadata_scan_result(
            "entry",
            cl_error_t_CL_EMEM,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_EMEM);
    }

    #[test]
    fn alz_metadata_limit_success_continues() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(handle_alz_metadata_limit_result(
            cl_error_t_CL_SUCCESS,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_SUCCESS);
    }

    #[test]
    fn alz_metadata_limit_failure_stops_without_terminal_status() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(!handle_alz_metadata_limit_result(
            cl_error_t_CL_EMAXFILES,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_SUCCESS);
    }

    #[test]
    fn alz_metadata_limit_hard_failure_stops_with_terminal_status() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(!handle_alz_metadata_limit_result(
            cl_error_t_CL_ETIMEOUT,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_ETIMEOUT);
    }

    #[test]
    fn alz_metadata_directory_limit_success_continues() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(handle_alz_metadata_directory_limit_result(
            cl_error_t_CL_SUCCESS,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_SUCCESS);
    }

    #[test]
    fn alz_metadata_directory_limit_hard_failure_stops_with_terminal_status() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(!handle_alz_metadata_directory_limit_result(
            cl_error_t_CL_ETIMEOUT,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_ETIMEOUT);
    }

    #[test]
    fn alz_metadata_size_rejects_platform_overflow() {
        assert_eq!(alz_metadata_size(42), Some(42usize));
        assert_eq!(alz_metadata_size(usize::MAX as u64), Some(usize::MAX));

        #[cfg(target_pointer_width = "32")]
        assert_eq!(alz_metadata_size(u64::from(u32::MAX) + 1), None);

        #[cfg(target_pointer_width = "64")]
        assert_eq!(alz_metadata_size(u64::MAX), Some(usize::MAX));
    }
}
