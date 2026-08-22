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
    io::{self, Read},
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
    onenote::{self, LegacyAttachmentSink, OneNote},
    sys::{
        cl_error_t, cl_error_t_CL_EFORMAT, cl_error_t_CL_EMAXFILES, cl_error_t_CL_EMAXSIZE,
        cl_error_t_CL_EMEM, cl_error_t_CL_EREAD, cl_error_t_CL_EPARSE, cl_error_t_CL_ERROR,
        cl_error_t_CL_ETIMEOUT, cl_error_t_CL_ERESOURCE,
        cl_error_t_CL_ESEEK, cl_error_t_CL_ETMPFILE, cl_error_t_CL_EUNPACK, cl_error_t_CL_EUNLINK,
        cl_error_t_CL_EWRITE,
        cl_error_t_CL_BREAK, cl_error_t_CL_SUCCESS, cl_error_t_CL_VIRUS, cli_ctx, cli_magic_scan_buff,
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
    let reason: &[u8] = if status == cl_error_t_CL_ERESOURCE {
        b"Rust parser resource admission failed\0"
    } else if status == cl_error_t_CL_EPARSE || status == cl_error_t_CL_EFORMAT {
        b"Rust parser reported malformed or incomplete input\0"
    } else {
        b"Rust parser inspection was incomplete\0"
    };
    sys::cli_mark_scan_incomplete(ctx, reason.as_ptr().cast());
    status
}

unsafe fn parser_input_failure(ctx: *mut cli_ctx, parser: &str, err: impl std::fmt::Display) -> cl_error_t {
    parser_failure(ctx, parser, cl_error_t_CL_EPARSE, err)
}

fn rust_reader_status(err: &io::Error, fallback: cl_error_t) -> cl_error_t {
    if err.kind() == io::ErrorKind::TimedOut {
        cl_error_t_CL_ETIMEOUT
    } else {
        fallback
    }
}

/// Decode or otherwise produce a child through a bounded reader and scan it
/// from a quota-accounted temporary spool.  The reservation remains held
/// through the nested scan so child parser scratch space cannot hide behind
/// an uncharged in-memory buffer.
pub(crate) unsafe fn scan_reader_via_temp_spool<R: Read>(
    ctx: *mut cli_ctx,
    reader: &mut R,
    parser: &str,
) -> cl_error_t {
    let mut spool = match TempSpool::new(ctx, 0) {
        Ok(spool) => spool,
        Err(status) => return parser_failure(ctx, parser, status, "temporary spool reservation failed"),
    };
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let deadline_status = check_scan_time_limit(ctx);
        if deadline_status != cl_error_t_CL_SUCCESS {
            return parser_failure(ctx, parser, deadline_status, "reader reached the configured time limit");
        }
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(err) => return parser_failure(ctx, parser, cl_error_t_CL_EREAD, err),
        };
        if read == 0 {
            break;
        }
        if let Err(status) = spool.write_all(&buffer[..read]) {
            return parser_failure(ctx, parser, status, "temporary spool write failed");
        }
    }

    if spool.written == 0 {
        return cl_error_t_CL_SUCCESS;
    }

    let status = spool.scan(None);
    if status != cl_error_t_CL_SUCCESS {
        debug!("{parser} temporary-spool child scan returned error: {status}");
    }
    status
}

fn lha_output_chunk_fits(written: u64, declared: u64, chunk_len: usize) -> bool {
    let chunk_len = match u64::try_from(chunk_len) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let remaining = match declared.checked_sub(written) {
        Some(value) => value,
        None => return false,
    };
    chunk_len <= remaining
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
        let new_written = self
            .written
            .checked_add(requested)
            .ok_or(cl_error_t_CL_ERESOURCE)?;
        let available = self
            .reserved
            .checked_sub(self.written)
            .ok_or(cl_error_t_CL_ERESOURCE)?;
        let additional = requested.saturating_sub(available);
        if additional != 0 {
            let new_reserved = self
                .reserved
                .checked_add(additional)
                .ok_or(cl_error_t_CL_ERESOURCE)?;
            let status = unsafe { sys::cli_scan_reserve_temporary(self.ctx, additional) };
            if status != cl_error_t_CL_SUCCESS {
                return Err(status);
            }
            self.reserved = new_reserved;
        }

        let deadline_status = unsafe { check_scan_time_limit(self.ctx) };
        if deadline_status != cl_error_t_CL_SUCCESS {
            if additional != 0 {
                unsafe { sys::cli_scan_release_temporary(self.ctx, additional) };
                self.reserved -= additional;
            }
            return Err(deadline_status);
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
        self.written = new_written;
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
        let deadline_status = check_scan_time_limit(self.ctx);
        if deadline_status != cl_error_t_CL_SUCCESS {
            return Err(self.record_failure(
                deadline_status,
                "member output reached the configured time limit",
            ));
        }
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
    attachments_seen: bool,
}

impl OneNoteScanSink {
    fn new(ctx: *mut cli_ctx) -> Self {
        Self {
            ctx,
            spool: None,
            scan_result: cl_error_t_CL_SUCCESS,
            attachments_seen: false,
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
        self.attachments_seen = true;
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
        let deadline_status = check_scan_time_limit(self.ctx);
        if deadline_status != cl_error_t_CL_SUCCESS {
            return Err(self.record_failure(
                deadline_status,
                "attachment output reached the configured time limit",
            ));
        }
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
    let mut reader = FMapReader::new_with_context(fmap, ctx);
    let mut buffer = [0u8; 1024 * 1024];
    let mut copied = 0u64;

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|err| rust_reader_status(&err, cl_error_t_CL_EREAD))?;
        if read == 0 {
            break;
        }
        spool.write_all(&buffer[..read])?;
        copied = copied
            .checked_add(read as u64)
            .ok_or(cl_error_t_CL_EREAD)?;
    }

    if copied != expected_size {
        return Err(cl_error_t_CL_EREAD);
    }

    Ok(spool)
}

fn onenote_modern_parser_admitted(input_len: usize) -> bool {
    input_len <= FMap::WHOLE_INPUT_MAX
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

    let mut reader = FMapReader::new_with_context(&fmap, ctx);
    let mut prefix = [0u8; 16];
    if fmap.len() < prefix.len() {
        return parser_failure(
            ctx,
            "OneNote",
            cl_error_t_CL_EPARSE,
            "OneNote input ended before its fixed prefix was complete",
        );
    }
    if let Err(err) = reader.read_exact(&mut prefix) {
        return parser_failure(ctx, "OneNote", rust_reader_status(&err, cl_error_t_CL_EREAD), err);
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
        if let Some(status) = reader.deadline_status() {
            return parser_failure(ctx, "OneNote", status, "reader reached the configured time limit");
        }
        if sink.attachments_seen {
            return match parse_result {
                Ok(()) => cl_error_t_CL_SUCCESS,
                Err(err) => parser_failure(ctx, "OneNote", cl_error_t_CL_EPARSE, err),
            };
        }
        if let Err(err) = parse_result {
            return parser_failure(ctx, "OneNote", cl_error_t_CL_EPARSE, err);
        }
        /* The legacy magic is shared by newer section files. If no legacy
         * attachment record was found, let the modern parser inspect the
         * complete root instead of treating the input as an empty legacy
         * document. */
    }

    /* The modern third-party parser still accepts only a borrowed whole-file
     * slice. Keep that API boundary explicit: large modern documents must not
     * be staged and mapped as though they were reader-backed. The bounded
     * legacy extractor above remains available for legacy documents. */
    if !onenote_modern_parser_admitted(fmap.len()) {
        return parser_failure(
            ctx,
            "OneNote",
            cl_error_t_CL_ERESOURCE,
            "OneNote modern whole-input parser exceeds the bounded parser cap",
        );
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
        let deadline_status = check_scan_time_limit(ctx);
        if deadline_status != cl_error_t_CL_SUCCESS {
            scan_result = parser_failure(
                ctx,
                "OneNote",
                deadline_status,
                "attachment output reached the configured time limit",
            );
            return false;
        }
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
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| unsafe {
        scan_lha_lzh_inner(ctx)
    }));

    match result {
        Ok(status) => status,
        Err(_) => parser_failure(
            ctx,
            "LHA/LZH",
            cl_error_t_CL_EFORMAT,
            "decoder panicked while scanning the archive",
        ),
    }
}

unsafe fn scan_lha_lzh_inner(ctx: *mut cli_ctx) -> cl_error_t {
    let fmap = match ctx::current_fmap(ctx) {
        Ok(fmap) => fmap,
        Err(e) => {
            return parser_failure(ctx, "LHA/LZH", cl_error_t_CL_ERROR, e);
        }
    };

    // Try to parse the LHA/LZH file data using the delharc crate.
    debug!("Attempting to parse the LHA/LZH file data using the delharc crate.");

    let mut decoder = match LhaDecodeReader::new(FMapReader::new_with_context(&fmap, ctx)) {
        Ok(result) => result,
        Err(err) => {
            let status = check_scan_time_limit(ctx);
            return parser_failure(
                ctx,
                "LHA/LZH",
                if status == cl_error_t_CL_ETIMEOUT {
                    status
                } else {
                    cl_error_t_CL_EFORMAT
                },
                err,
            );
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

            let compressed_size = match usize::try_from(header.compressed_size) {
                Ok(size) => size,
                Err(_) => {
                    return parser_failure(
                        ctx,
                        "LHA/LZH",
                        cl_error_t_CL_ERESOURCE,
                        "compressed member size is not representable on this platform",
                    );
                }
            };
            let original_size = match usize::try_from(header.original_size) {
                Ok(size) => size,
                Err(_) => {
                    return parser_failure(
                        ctx,
                        "LHA/LZH",
                        cl_error_t_CL_ERESOURCE,
                        "uncompressed member size is not representable on this platform",
                    );
                }
            };

            // Scan the archive metadata first. A callback result is not a
            // size-limit hint: propagate detections, cancellation, and
            // callback failures instead of silently skipping the member.
            let metadata_status = scan_archive_metadata(
                ctx,
                &filename,
                compressed_size,
                original_size,
                false,
                index,
                header.file_crc as i32,
            );
            if metadata_status != cl_error_t_CL_SUCCESS {
                if metadata_status == cl_error_t_CL_VIRUS || metadata_status == cl_error_t_CL_BREAK {
                    return metadata_status;
                }
                return parser_failure(
                    ctx,
                    "LHA/LZH",
                    metadata_status,
                    format!("archive metadata scan failed with status {metadata_status}"),
                );
            }

            // A member that cannot be admitted is required content that was
            // not inspected. Do not skip it and let the archive normalize to
            // a clean result.
            let limit_status = check_scan_limits("LHA", ctx, header.original_size, 0, 0);
            if limit_status != cl_error_t_CL_SUCCESS {
                return parser_failure(
                    ctx,
                    "LHA/LZH",
                    limit_status,
                    format!("LHA member exceeds configured scan limits with status {limit_status}"),
                );
            }

            if !decoder.is_decoder_supported() {
                return parser_failure(
                    ctx,
                    "LHA/LZH",
                    cl_error_t_CL_EFORMAT,
                    "member compression method is unsupported",
                );
            }

            let expected_size = header.original_size;
            let mut spool = match TempSpool::new(ctx, expected_size) {
                Ok(spool) => spool,
                Err(status) => return parser_failure(ctx, "LHA/LZH", status, "member spool reservation failed"),
            };
            let mut bytes_read = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let deadline_status = check_scan_time_limit(ctx);
                if deadline_status != cl_error_t_CL_SUCCESS {
                    return parser_failure(
                        ctx,
                        "LHA/LZH",
                        deadline_status,
                        "decoder output reached the configured time limit",
                    );
                }
                match decoder.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        if !lha_output_chunk_fits(bytes_read, expected_size, read) {
                            return parser_failure(
                                ctx,
                                "LHA/LZH",
                                cl_error_t_CL_EFORMAT,
                                "member decoder exceeded its declared output size",
                            );
                        }
                        let read_u64 = match u64::try_from(read) {
                            Ok(value) => value,
                            Err(_) => {
                                return parser_failure(
                                    ctx,
                                    "LHA/LZH",
                                    cl_error_t_CL_ERESOURCE,
                                    "member decoder output size is not representable",
                                );
                            }
                        };
                        if let Err(status) = spool.write_all(&buffer[..read]) {
                            return parser_failure(ctx, "LHA/LZH", status, "member output exceeded its declared size or could not be written");
                        }
                        bytes_read = match bytes_read.checked_add(read_u64) {
                            Some(value) => value,
                            None => {
                                return parser_failure(
                                    ctx,
                                    "LHA/LZH",
                                    cl_error_t_CL_ERESOURCE,
                                    "member output size accounting overflowed",
                                );
                            }
                        };
                    }
                    Err(err) => {
                        let status = check_scan_time_limit(ctx);
                        return parser_failure(
                            ctx,
                            "LHA/LZH",
                            if status == cl_error_t_CL_ETIMEOUT {
                                status
                            } else {
                                cl_error_t_CL_EFORMAT
                            },
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

            if bytes_read > 0 {
                debug!("Read {bytes_read} bytes from file {filename} in the LHA archive.");

                let ret = spool.scan(Some(&filename));
                if ret != cl_error_t_CL_SUCCESS {
                    debug!("spooled LHA member scan returned error: {}", ret);
                    return ret;
                }
            } else {
                debug!("Read zero-byte file.");
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
                let status = check_scan_time_limit(ctx);
                return parser_failure(
                    ctx,
                    "LHA/LZH",
                    if status == cl_error_t_CL_ETIMEOUT {
                        status
                    } else {
                        cl_error_t_CL_EFORMAT
                    },
                    err,
                );
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
                "ALZ file {:?} metadata scan failed with {}. Aborting extraction.",
                file_name, metadata_ret
            );
            *alz_metadata_ret = ret;
            false
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
    if limit_ret == cl_error_t_CL_SUCCESS {
        true
    } else {
        /* A MaxFiles admission failure means this required member was not
         * inspected. Return it from the Rust parser as well as leaving the
         * shared C context incomplete; do not rely on outer unwinding to
         * manufacture the non-clean result. */
        *alz_metadata_ret = limit_ret;
        false
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
        Alz::from_reader_with_filter_stream(FMapReader::new_with_context(&fmap, ctx), |metadata| {
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
                    alz_metadata_ret = parser_failure(
                        ctx,
                        "ALZ",
                        cl_error_t_CL_ERESOURCE,
                        format!(
                            "member metadata size for {:?} is not representable on this platform",
                            metadata.file_name
                        ),
                    );
                    return AlzExtractionDecision::Stop;
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
        Ok(Err(AlzError::Read(field))) => {
            let status = check_scan_time_limit(ctx);
            return parser_failure(
                ctx,
                "ALZ",
                if status == cl_error_t_CL_ETIMEOUT {
                    status
                } else {
                    cl_error_t_CL_EREAD
                },
                field,
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

    if alz.has_unsupported_feature() {
        return parser_failure(
            ctx,
            "ALZ",
            cl_error_t_CL_EUNPACK,
            "archive contains an encrypted or unsupported member feature",
        );
    }

    if let Some(needed) = alz.file_limit_exceeded_size {
        let ret = check_scan_limits("ALZ", ctx, needed, 0, 0);
        if ret != cl_error_t_CL_SUCCESS {
            return ret;
        }
    }

    if alz.total_limit_exceeded_size.is_some() {
        append_potentially_unwanted_if_heur_exceedsmax(
            ctx,
            HEURISTICS_LIMITS_EXCEEDED_MAX_SCAN_SIZE,
            cl_error_t_CL_EMAXSIZE,
        );
        return cl_error_t_CL_EMAXSIZE;
    }

    if alz.file_count_limit_exceeded {
        append_potentially_unwanted_if_heur_exceedsmax(
            ctx,
            HEURISTICS_LIMITS_EXCEEDED_MAX_FILES,
            cl_error_t_CL_EMAXFILES,
        );
        return cl_error_t_CL_EMAXFILES;
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
    fn alz_metadata_scan_format_error_stops() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(!handle_alz_metadata_scan_result(
            "entry",
            cl_error_t_CL_EFORMAT,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_EFORMAT);
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
    fn alz_metadata_limit_failure_is_fail_visible() {
        let mut alz_metadata_ret = cl_error_t_CL_SUCCESS;

        assert!(!handle_alz_metadata_limit_result(
            cl_error_t_CL_EMAXFILES,
            &mut alz_metadata_ret,
        ));
        assert_eq!(alz_metadata_ret, cl_error_t_CL_EMAXFILES);
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

    #[test]
    fn lha_output_chunk_rejects_decoder_overflow() {
        assert!(lha_output_chunk_fits(0, 64, 64));
        assert!(lha_output_chunk_fits(32, 64, 32));
        assert!(!lha_output_chunk_fits(65, 64, 0));
        assert!(!lha_output_chunk_fits(64, 64, 1));
        assert!(!lha_output_chunk_fits(u64::MAX, u64::MAX, 1));
    }

    #[test]
    fn rust_reader_timeout_status_is_preserved() {
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "deadline");
        let read_error = io::Error::new(io::ErrorKind::Other, "read");

        assert_eq!(
            rust_reader_status(&timeout, cl_error_t_CL_EREAD),
            cl_error_t_CL_ETIMEOUT
        );
        assert_eq!(
            rust_reader_status(&read_error, cl_error_t_CL_EREAD),
            cl_error_t_CL_EREAD
        );
    }

    #[test]
    fn onenote_modern_parser_rejects_inputs_above_whole_input_cap() {
        assert!(onenote_modern_parser_admitted(FMap::WHOLE_INPUT_MAX));
        assert!(!onenote_modern_parser_admitted(
            FMap::WHOLE_INPUT_MAX.saturating_add(1)
        ));
    }
}
