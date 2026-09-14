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
    cell::Cell,
    ffi::{c_char, c_void, CStr, CString},
    io::{self, Read},
    panic,
    path::{Path, PathBuf},
    ptr::null_mut,
    rc::Rc,
};

use delharc::{LhaDecodeReader, LhaError};
use log::{debug, error};

use crate::{
    alz::{Alz, AlzExtractionDecision, AlzExtractionLimits, Error as AlzError, ExtractSink},
    ctx,
    fmap::{is_read_failure, FMap, FMapReader},
    sys,
    onenote::{self, LegacyAttachmentSink, OneNote},
    sys::{
        cl_error_t, cl_error_t_CL_EFORMAT, cl_error_t_CL_EMAXFILES, cl_error_t_CL_EMAXSIZE,
        cl_error_t_CL_EMEM, cl_error_t_CL_EREAD, cl_error_t_CL_EPARSE,
        cl_error_t_CL_ETIMEOUT, cl_error_t_CL_ERESOURCE,
        cl_error_t_CL_ESEEK, cl_error_t_CL_ETMPFILE, cl_error_t_CL_EUNPACK, cl_error_t_CL_EUNLINK,
        cl_error_t_CL_EWRITE,
        cl_error_t_CL_BREAK, cl_error_t_CL_CLEAN, cl_error_t_CL_ENULLARG, cl_error_t_CL_SUCCESS,
        cl_error_t_CL_VERIFIED,
        cl_error_t_CL_VIRUS,
        cli_ctx, cli_magic_scan_buff,
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

unsafe fn rust_reconcile_status(ctx: *mut cli_ctx, status: cl_error_t) -> cl_error_t {
    if !ctx.is_null()
        && (status == cl_error_t_CL_SUCCESS || status == cl_error_t_CL_CLEAN)
        && (*ctx).scan_incomplete
    {
        return cl_error_t_CL_EPARSE;
    }

    status
}

fn rust_reader_status(err: &io::Error, fallback: cl_error_t) -> cl_error_t {
    if err.kind() == io::ErrorKind::TimedOut {
        cl_error_t_CL_ETIMEOUT
    } else if is_read_failure(err) {
        cl_error_t_CL_EREAD
    } else {
        fallback
    }
}

struct OneNoteParserSpoolBudget {
    ctx: *mut cli_ctx,
}

impl onenote_parser::BlobSpoolBudget for OneNoteParserSpoolBudget {
    fn reserve(&self, bytes: u64) -> bool {
        if self.ctx.is_null() {
            return false;
        }
        let status = unsafe { sys::cli_scan_reserve_temporary(self.ctx, bytes) };
        status == cl_error_t_CL_SUCCESS
    }

    fn release(&self, bytes: u64) {
        if !self.ctx.is_null() {
            unsafe { sys::cli_scan_release_temporary(self.ctx, bytes) };
        }
    }
}

const LHA_HEADER_ALLOCATION_LIMIT: usize = 1024 * 1024 * 1024;

fn lha_pathname_input_within_allocation_limit(filename_len: usize, extra_headers_len: usize) -> bool {
    let input_len = match filename_len.checked_add(extra_headers_len) {
        Some(value) => value,
        None => return false,
    };
    match input_len.checked_mul(3) {
        Some(value) => value <= LHA_HEADER_ALLOCATION_LIMIT,
        None => false,
    }
}

fn lha_error_status(err: &LhaError<io::Error>, fallback: cl_error_t) -> cl_error_t {
    match err {
        LhaError::Io(io_err) => rust_reader_status(io_err, fallback),
        LhaError::ResourceLimit(_) => cl_error_t_CL_ERESOURCE,
        LhaError::MemoryAllocation(_) => cl_error_t_CL_EMEM,
        _ => fallback,
    }
}

fn spool_write_is_interrupted(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EINTR)
}

fn merge_cleanup_status(status: cl_error_t, cleanup_status: cl_error_t) -> cl_error_t {
    if cleanup_status == cl_error_t_CL_SUCCESS {
        return status;
    }
    if status == cl_error_t_CL_SUCCESS
        || status == cl_error_t_CL_VERIFIED
        || status == cl_error_t_CL_BREAK
    {
        return cleanup_status;
    }
    status
}

fn onenote_error_status(err: &onenote::Error) -> cl_error_t {
    if matches!(err, onenote::Error::ResourceLimit(_)) {
        cl_error_t_CL_ERESOURCE
    } else if matches!(err, onenote::Error::ReadFailure(_)) {
        cl_error_t_CL_EREAD
    } else if matches!(err, onenote::Error::Timeout(_)) {
        cl_error_t_CL_ETIMEOUT
    } else {
        cl_error_t_CL_EPARSE
    }
}

fn onenote_legacy_fallback_allowed(err: &onenote::Error, prefix: &[u8]) -> bool {
    matches!(err, onenote::Error::Format | onenote::Error::Parse)
        && onenote::is_legacy_magic(prefix)
}

fn rust_context_error_status(err: &ctx::Error) -> cl_error_t {
    match err {
        ctx::Error::NullPointer(_) => cl_error_t_CL_ENULLARG,
        ctx::Error::BadMap(crate::fmap::Error::ReadFailure(_, _, _)) => cl_error_t_CL_EREAD,
        _ => cl_error_t_CL_EPARSE,
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
            Err(err) => {
                return parser_failure(ctx, parser, rust_reader_status(&err, cl_error_t_CL_EREAD), err);
            }
        };
        if read == 0 {
            break;
        }
        if let Err(status) = spool.write_all(&buffer[..read]) {
            return parser_failure(ctx, parser, status, "temporary spool write failed");
        }
    }

    /* An empty reader result is still a logical extracted child. Route it
     * through descriptor admission so inclusive MaxFiles accounting,
     * cache-taint propagation, and the owning layer's sticky status remain
     * visible just as they are for a non-empty child. */
    let status = unsafe { spool.scan(None) };
    if status != cl_error_t_CL_SUCCESS {
        debug!("{parser} temporary-spool child scan returned error: {status}");
    }
    spool.finish_cleanup(status, parser)
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

fn lha_member_range_end(start: u64, length: u64, map_len: u64) -> Option<u64> {
    start.checked_add(length).filter(|end| *end <= map_len)
}

/// Track the source position while delharc owns the bounded fmap reader.
/// delharc's `next_file()` skips any unused compressed bytes internally, so
/// the scanner needs the position after each parsed header to validate the
/// next member's declared compressed range before decoding or skipping it.
struct LhaPositionReader<'a> {
    inner: FMapReader<'a>,
    position: Rc<Cell<u64>>,
}

impl<'a> LhaPositionReader<'a> {
    fn new(fmap: &'a FMap, ctx: *mut cli_ctx, position: Rc<Cell<u64>>) -> Self {
        Self {
            inner: FMapReader::new_with_context(fmap, ctx),
            position,
        }
    }
}

impl Read for LhaPositionReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        let position = self
            .position
            .get()
            .checked_add(u64::try_from(read).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "LHA source position overflow")
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "LHA source position overflow"))?;
        self.position.set(position);
        Ok(read)
    }
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
    cleaned: bool,
}

impl TempSpool {
    const WRITE_CHUNK: usize = 64 * 1024;

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
            cleaned: false,
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
            let deadline_status = unsafe { check_scan_time_limit(self.ctx) };
            if deadline_status != cl_error_t_CL_SUCCESS {
                if additional != 0 {
                    unsafe { sys::cli_scan_release_temporary(self.ctx, additional) };
                    self.reserved -= additional;
                }
                return Err(deadline_status);
            }

            let write_len = (bytes.len() - offset).min(Self::WRITE_CHUNK);
            let written = unsafe {
                libc::write(
                    self.fd,
                    bytes[offset..].as_ptr().cast(),
                    write_len,
                )
            };
            if written < 0 {
                let err = io::Error::last_os_error();
                if spool_write_is_interrupted(&err) {
                    continue;
                }
                if additional != 0 {
                    unsafe { sys::cli_scan_release_temporary(self.ctx, additional) };
                    self.reserved -= additional;
                }
                return Err(cl_error_t_CL_EWRITE);
            }
            if written == 0 {
                if additional != 0 {
                    unsafe { sys::cli_scan_release_temporary(self.ctx, additional) };
                    self.reserved -= additional;
                }
                return Err(cl_error_t_CL_EWRITE);
            }
            offset = offset.saturating_add(written as usize);

            let deadline_status = unsafe { check_scan_time_limit(self.ctx) };
            if deadline_status != cl_error_t_CL_SUCCESS {
                if additional != 0 {
                    unsafe { sys::cli_scan_release_temporary(self.ctx, additional) };
                    self.reserved -= additional;
                }
                return Err(deadline_status);
            }
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

    unsafe fn cleanup(&mut self) -> cl_error_t {
        if self.cleaned {
            return cl_error_t_CL_SUCCESS;
        }

        let mut status = cl_error_t_CL_SUCCESS;

        if self.fd >= 0 {
            if libc::close(self.fd) != 0 {
                status = cl_error_t_CL_EWRITE;
            }
            self.fd = -1;
        }

        let keep_tmp = !(*self.ctx).engine.is_null()
            && (*(*self.ctx).engine).keeptmp != 0;
        if !keep_tmp
            && sys::cli_unlink(self.path.as_ptr()) != cl_error_t_CL_SUCCESS
            && status == cl_error_t_CL_SUCCESS
        {
            status = cl_error_t_CL_EUNLINK;
        }

        self.release_reservation();
        self.cleaned = true;
        status
    }

    unsafe fn finish_cleanup(&mut self, status: cl_error_t, parser: &str) -> cl_error_t {
        let cleanup_status = self.cleanup();
        if cleanup_status == cl_error_t_CL_SUCCESS {
            return status;
        }

        let cleanup_status = parser_failure(
            self.ctx,
            parser,
            cleanup_status,
            "temporary spool cleanup failed",
        );
        merge_cleanup_status(status, cleanup_status)
    }
}

impl Drop for TempSpool {
    fn drop(&mut self) {
        unsafe {
            let status = self.cleanup();
            if status != cl_error_t_CL_SUCCESS {
                self.mark_cleanup_failure(
                    status,
                    if status == cl_error_t_CL_EWRITE {
                        "temporary spool could not be closed"
                    } else {
                        "temporary spool could not be removed"
                    },
                );
            }
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
        let deadline_status = unsafe { check_scan_time_limit(self.ctx) };
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
        /* Empty ALZ members are still logical children. Let the descriptor
         * ingress charge the zero-byte nested scan to MaxFiles instead of
         * silently bypassing the inclusive root/child accounting. */
        let ret = unsafe { spool.scan(name.as_deref()) };
        let ret = unsafe { spool.finish_cleanup(ret, "ALZ") };
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
        let deadline_status = unsafe { check_scan_time_limit(self.ctx) };
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
        /* Legacy OneNote attachments are logical children even when empty;
         * send the zero-byte spool through descriptor admission so MaxFiles
         * accounting and sticky completion status remain visible. */
        let ret = unsafe { spool.scan(None) };
        let ret = unsafe { spool.finish_cleanup(ret, "OneNote") };
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

/// Scan a OneNote file for attachments
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[no_mangle]
pub unsafe extern "C" fn scan_onenote(ctx: *mut cli_ctx) -> cl_error_t {
    if ctx.is_null() {
        return cl_error_t_CL_ENULLARG;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| unsafe {
        scan_onenote_inner(ctx)
    }));

    let status = match result {
        Ok(status) => status,
        Err(_) => parser_failure(
            ctx,
            "OneNote",
            cl_error_t_CL_EFORMAT,
            "parser panicked while reading the document",
        ),
    };

    rust_reconcile_status(ctx, status)
}

unsafe fn scan_onenote_inner(ctx: *mut cli_ctx) -> cl_error_t {

    let fmap = match ctx::current_fmap(ctx) {
        Ok(fmap) => fmap,
        Err(e) => {
            return parser_failure(ctx, "OneNote", rust_context_error_status(&e), e);
        }
    };
    if (*ctx).engine.is_null() {
        return cl_error_t_CL_ENULLARG;
    }
    if (*ctx).options.is_null() {
        return cl_error_t_CL_ENULLARG;
    }

    let mut prefix_reader = FMapReader::new_with_context(&fmap, ctx);
    let mut prefix = [0u8; 16];
    if fmap.len() < prefix.len() {
        return parser_failure(
            ctx,
            "OneNote",
            cl_error_t_CL_EPARSE,
            "OneNote input ended before its fixed prefix was complete",
        );
    }
    if let Err(err) = prefix_reader.read_exact(&mut prefix) {
        return parser_failure(ctx, "OneNote", rust_reader_status(&err, cl_error_t_CL_EREAD), err);
    }
    let mut scan_result = cl_error_t_CL_SUCCESS;
    let modern_reader = FMapReader::new_with_context(&fmap, ctx);

    let spool_directory = if (*ctx).this_layer_tmpdir.is_null() {
        None
    } else {
        Some(PathBuf::from(
            CStr::from_ptr((*ctx).this_layer_tmpdir)
                .to_string_lossy()
                .into_owned(),
        ))
    };
    let parse_result = OneNote::scan_reader_streaming_with_budget(
        modern_reader,
        Path::new(fmap.name()),
        spool_directory.as_deref(),
        Some(Box::new(OneNoteParserSpoolBudget { ctx })),
        |name, reader| {
            debug!(
                "Extracting streamed OneNote attachment with name: {:?}",
                name
            );

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
            let mut attachment_spool = match TempSpool::new(ctx, 0) {
                Ok(spool) => spool,
                Err(status) => {
                    scan_result = parser_failure(
                        ctx,
                        "OneNote",
                        status,
                        "attachment temporary spool reservation failed",
                    );
                    return false;
                }
            };

            let mut buffer = [0u8; TempSpool::WRITE_CHUNK];
            loop {
                let read = match reader.read(&mut buffer) {
                    Ok(read) => read,
                    Err(error) => {
                        scan_result = parser_failure(
                            ctx,
                            "OneNote",
                            rust_reader_status(&error, cl_error_t_CL_EREAD),
                            error,
                        );
                        return false;
                    }
                };
                if read == 0 {
                    break;
                }
                if let Err(status) = attachment_spool.write_all(&buffer[..read]) {
                    scan_result = parser_failure(
                        ctx,
                        "OneNote",
                        status,
                        "attachment temporary spool write failed",
                    );
                    return false;
                }
            }

            let ret = attachment_spool.scan(name);
            let ret = attachment_spool.finish_cleanup(ret, "OneNote");
            if ret != cl_error_t_CL_SUCCESS {
                scan_result = ret;
                return false;
            }

            true
        },
    );

    if scan_result != cl_error_t_CL_SUCCESS {
        return scan_result;
    }

    let modern_error = match parse_result {
        Ok(()) => return cl_error_t_CL_SUCCESS,
        Err(err) => err,
    };

    /* Modern parsing must get first refusal. The legacy marker is shared by
     * newer section files, so scanning for legacy records first can turn a
     * valid modern document containing coincidental marker bytes into a false
     * attachment or a malformed result. Fall back only for the same
     * format/parse failures accepted by the byte-slice compatibility API. */
    if !onenote_legacy_fallback_allowed(&modern_error, &prefix) {
        return parser_failure(
            ctx,
            "OneNote",
            onenote_error_status(&modern_error),
            modern_error,
        );
    }

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
    let mut reader = FMapReader::new_with_context(&fmap, ctx);
    let mut sink = OneNoteScanSink::new(ctx);
    let legacy_result = onenote::scan_legacy_reader(&mut reader, file_len, &mut sink);
    if sink.scan_result != cl_error_t_CL_SUCCESS {
        return sink.scan_result;
    }
    if let Some(status) = reader.deadline_status() {
        return parser_failure(ctx, "OneNote", status, "reader reached the configured time limit");
    }
    if sink.attachments_seen {
        return match legacy_result {
            Ok(()) => cl_error_t_CL_SUCCESS,
            Err(err) => parser_failure(ctx, "OneNote", onenote_error_status(&err), err),
        };
    }

    match legacy_result {
        Ok(()) => parser_failure(
            ctx,
            "OneNote",
            onenote_error_status(&modern_error),
            modern_error,
        ),
        Err(err) => parser_failure(ctx, "OneNote", onenote_error_status(&err), err),
    }
}

/// Scan the contents of a LHA or LZH archive
///
/// # Safety
///
/// Must be a valid ctx pointer.
#[no_mangle]
pub unsafe extern "C" fn scan_lha_lzh(ctx: *mut cli_ctx) -> cl_error_t {
    if ctx.is_null() {
        return cl_error_t_CL_ENULLARG;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| unsafe {
        scan_lha_lzh_inner(ctx)
    }));

    let status = match result {
        Ok(status) => status,
        Err(_) => parser_failure(
            ctx,
            "LHA/LZH",
            cl_error_t_CL_EFORMAT,
            "decoder panicked while scanning the archive",
        ),
    };

    rust_reconcile_status(ctx, status)
}

unsafe fn scan_lha_lzh_inner(ctx: *mut cli_ctx) -> cl_error_t {
    let fmap = match ctx::current_fmap(ctx) {
        Ok(fmap) => fmap,
        Err(e) => {
            return parser_failure(ctx, "LHA/LZH", rust_context_error_status(&e), e);
        }
    };
    if (*ctx).engine.is_null() {
        return cl_error_t_CL_ENULLARG;
    }
    if (*ctx).options.is_null() {
        return cl_error_t_CL_ENULLARG;
    }

    // Try to parse the LHA/LZH file data using the delharc crate.
    debug!("Attempting to parse the LHA/LZH file data using the delharc crate.");

    let source_position = Rc::new(Cell::new(0u64));
    let mut decoder = match LhaDecodeReader::new_with_allocation_limit(
        LhaPositionReader::new(&fmap, ctx, source_position.clone()),
        LHA_HEADER_ALLOCATION_LIMIT,
    ) {
        Ok(result) => result,
        Err(err) => {
            let lha_err: LhaError<io::Error> = err.into();
            let status = check_scan_time_limit(ctx);
            return parser_failure(
                ctx,
                "LHA/LZH",
                if status != cl_error_t_CL_SUCCESS {
                    status
                } else {
                    lha_error_status(&lha_err, cl_error_t_CL_EFORMAT)
                },
                lha_err,
            );
        }
    };

    debug!("Opened the LHA/LZH archive");

    let mut member_data_start = source_position.get();
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

        let fmap_len = match u64::try_from(fmap.len()) {
            Ok(value) => value,
            Err(_) => {
                return parser_failure(
                    ctx,
                    "LHA/LZH",
                    cl_error_t_CL_ERESOURCE,
                    "fmap length is not representable in the 64-bit archive coordinate space",
                );
            }
        };
        let member_data_end = match lha_member_range_end(
            member_data_start,
            header.compressed_size,
            fmap_len,
        ) {
            Some(end) => end,
            None => {
                return parser_failure(
                    ctx,
                    "LHA/LZH",
                    cl_error_t_CL_EPARSE,
                    "member compressed range exceeds the input map",
                );
            }
        };

        if !lha_pathname_input_within_allocation_limit(
            header.filename.len(),
            header.extra_headers.len(),
        ) {
            return parser_failure(
                ctx,
                "LHA/LZH",
                cl_error_t_CL_ERESOURCE,
                "member pathname exceeds the individual allocation boundary",
            );
        }

        let filepath = header.parse_pathname();
        let filename = filepath.to_string_lossy();
        if header.is_directory() {
            if header.compressed_size != 0 || header.original_size != 0 {
                return parser_failure(
                    ctx,
                    "LHA/LZH",
                    cl_error_t_CL_EPARSE,
                    "directory member declares file data",
                );
            }
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
                    cl_error_t_CL_EUNPACK,
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
                        let io_err: io::Error = err.into();
                        let status = check_scan_time_limit(ctx);
                        return parser_failure(
                            ctx,
                            "LHA/LZH",
                            if status != cl_error_t_CL_SUCCESS {
                                status
                            } else {
                                rust_reader_status(&io_err, cl_error_t_CL_EFORMAT)
                            },
                            format!("member read failed: {io_err}"),
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

            debug!("Read {bytes_read} bytes from file {filename} in the LHA archive.");

            let ret = spool.scan(Some(&filename));
            let ret = spool.finish_cleanup(ret, "LHA/LZH");
            if ret != cl_error_t_CL_SUCCESS {
                debug!("spooled LHA member scan returned error: {}", ret);
                return ret;
            }

            index += 1;
        }

        // Get the next file.
        match decoder.next_file() {
            Ok(true) => {
                debug!("Found another file in the archive!");
                member_data_start = source_position.get();
            }
            Ok(false) => {
                let expected_position = match member_data_end.checked_add(1) {
                    Some(position) => position,
                    None => {
                        return parser_failure(
                            ctx,
                            "LHA/LZH",
                            cl_error_t_CL_ERESOURCE,
                            "archive terminator position overflowed",
                        );
                    }
                };
                if source_position.get() != expected_position {
                    return parser_failure(
                        ctx,
                        "LHA/LZH",
                        cl_error_t_CL_EPARSE,
                        "archive ended without the required zero terminator",
                    );
                }
                debug!("No more files in the archive.");
                break;
            }
            Err(err) => {
                let lha_err: LhaError<io::Error> = err.into();
                let status = check_scan_time_limit(ctx);
                return parser_failure(
                    ctx,
                    "LHA/LZH",
                    if status != cl_error_t_CL_SUCCESS {
                        status
                    } else {
                        lha_error_status(&lha_err, cl_error_t_CL_EFORMAT)
                    },
                    lha_err,
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
    if ctx.is_null() {
        return cl_error_t_CL_ENULLARG;
    }

    let fmap = match ctx::current_fmap(ctx) {
        Ok(fmap) => fmap,
        Err(e) => {
            return parser_failure(ctx, "ALZ", rust_context_error_status(&e), e);
        }
    };
    if (*ctx).engine.is_null() {
        return cl_error_t_CL_ENULLARG;
    }
    if (*ctx).options.is_null() {
        return cl_error_t_CL_ENULLARG;
    }

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
        Ok(Err(AlzError::ReadFailure(field))) => {
            return parser_failure(ctx, "ALZ", cl_error_t_CL_EREAD, field);
        }
        Ok(Err(AlzError::Timeout(field))) => {
            return parser_failure(ctx, "ALZ", cl_error_t_CL_ETIMEOUT, field);
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

    rust_reconcile_status(ctx, cl_error_t_CL_SUCCESS)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::{
        cl_error_t_CL_BREAK, cl_error_t_CL_EPARSE, cl_error_t_CL_EREAD,
        cl_error_t_CL_ETIMEOUT, cl_error_t_CL_ENULLARG, cl_error_t_CL_EUNLINK,
        cl_error_t_CL_EWRITE, cl_error_t_CL_VERIFIED,
    };

    #[test]
    fn rust_spool_cleanup_status_is_fail_visible() {
        assert_eq!(
            merge_cleanup_status(cl_error_t_CL_SUCCESS, cl_error_t_CL_EWRITE),
            cl_error_t_CL_EWRITE
        );
        assert_eq!(
            merge_cleanup_status(cl_error_t_CL_VERIFIED, cl_error_t_CL_EUNLINK),
            cl_error_t_CL_EUNLINK
        );
        assert_eq!(
            merge_cleanup_status(cl_error_t_CL_BREAK, cl_error_t_CL_EWRITE),
            cl_error_t_CL_EWRITE
        );
        assert_eq!(
            merge_cleanup_status(cl_error_t_CL_VIRUS, cl_error_t_CL_EWRITE),
            cl_error_t_CL_VIRUS
        );
        assert_eq!(
            merge_cleanup_status(cl_error_t_CL_EPARSE, cl_error_t_CL_EUNLINK),
            cl_error_t_CL_EPARSE
        );
        assert_eq!(
            merge_cleanup_status(cl_error_t_CL_EWRITE, cl_error_t_CL_EUNLINK),
            cl_error_t_CL_EWRITE
        );
        assert_eq!(
            merge_cleanup_status(cl_error_t_CL_BREAK, cl_error_t_CL_SUCCESS),
            cl_error_t_CL_BREAK
        );
    }

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
    fn lha_member_range_rejects_truncation_and_overflow() {
        assert!(lha_member_range_end(0, 0, 0).is_some());
        assert!(lha_member_range_end(60, 0, 60).is_some());
        assert!(lha_member_range_end(60, 1, 60).is_none());
        assert!(lha_member_range_end(u64::MAX, 1, u64::MAX).is_none());
    }

    #[test]
    fn lha_pathname_admission_rejects_expansion_overflow() {
        let input_limit = LHA_HEADER_ALLOCATION_LIMIT / 3;

        assert!(lha_pathname_input_within_allocation_limit(input_limit, 0));
        assert!(!lha_pathname_input_within_allocation_limit(input_limit + 1, 0));
        assert!(!lha_pathname_input_within_allocation_limit(usize::MAX, 1));
        assert!(!lha_pathname_input_within_allocation_limit(0, input_limit + 1));
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
    fn rust_context_error_status_preserves_failure_class() {
        assert_eq!(
            rust_context_error_status(&ctx::Error::NullPointer("ctx")),
            cl_error_t_CL_ENULLARG
        );
        assert_eq!(
            rust_context_error_status(&ctx::Error::NullParam("recursion_stack")),
            cl_error_t_CL_EPARSE
        );
        assert_eq!(
            rust_context_error_status(&ctx::Error::BadMap(
                crate::fmap::Error::ReadFailure(128, 64, 4096),
            )),
            cl_error_t_CL_EREAD
        );
        assert_eq!(
            rust_context_error_status(&ctx::Error::Format),
            cl_error_t_CL_EPARSE
        );
    }

    #[test]
    fn onenote_fallback_is_limited_to_shared_magic_format_failures() {
        let magic = [
            0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d, 0xae, 0xb1, 0x53, 0x78, 0xd0, 0x29,
            0x96, 0xd3,
        ];

        assert!(onenote_legacy_fallback_allowed(
            &onenote::Error::Parse,
            &magic,
        ));
        assert!(!onenote_legacy_fallback_allowed(
            &onenote::Error::ResourceLimit("bounded parser payload".to_owned()),
            &magic,
        ));
        assert!(!onenote_legacy_fallback_allowed(
            &onenote::Error::Parse,
            b"not-onenote-magic",
        ));
    }

    #[test]
    fn rust_parser_status_reconciles_sticky_clean_completion() {
        let mut ctx: cli_ctx = unsafe { std::mem::zeroed() };

        assert_eq!(
            unsafe { rust_reconcile_status(&mut ctx, cl_error_t_CL_SUCCESS) },
            cl_error_t_CL_SUCCESS
        );

        ctx.scan_incomplete = true;
        assert_eq!(
            unsafe { rust_reconcile_status(&mut ctx, cl_error_t_CL_CLEAN) },
            cl_error_t_CL_EPARSE
        );
        assert_eq!(
            unsafe { rust_reconcile_status(&mut ctx, cl_error_t_CL_VIRUS) },
            cl_error_t_CL_VIRUS
        );
        assert_eq!(
            unsafe { rust_reconcile_status(&mut ctx, cl_error_t_CL_EREAD) },
            cl_error_t_CL_EREAD
        );
        assert_eq!(
            unsafe { rust_reconcile_status(null_mut(), cl_error_t_CL_SUCCESS) },
            cl_error_t_CL_SUCCESS
        );
    }

    #[test]
    fn rust_spool_write_retries_interrupted_syscalls() {
        assert!(spool_write_is_interrupted(&io::Error::from_raw_os_error(libc::EINTR)));
        assert!(!spool_write_is_interrupted(&io::Error::from_raw_os_error(libc::EIO)));
    }

    #[test]
    fn rust_fmap_callback_failure_status_is_preserved() {
        let fmap_error = io::Error::new(
            io::ErrorKind::Other,
            crate::fmap::Error::ReadFailure(128, 64, 4096),
        );

        assert_eq!(
            rust_reader_status(&fmap_error, cl_error_t_CL_EFORMAT),
            cl_error_t_CL_EREAD
        );
    }

}
