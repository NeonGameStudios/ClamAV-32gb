/*
 *  Assorted utility functions and macros.
 *
 *  Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Scott Hutton
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

use std::{ffi::CStr, fs::File, os::raw::c_char};

use glob::glob;
use log::{debug, error, warn};

use crate::{ffi_error, ffi_util::FFIError, sys, validate_str_param};

extern "C" {
    fn cli_checktimelimit(ctx: *mut sys::cli_ctx) -> sys::cl_error_t;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Glob pattern error: {0}")]
    GlobPatternError(#[from] glob::PatternError),

    #[error("Glob error: {0}")]
    GlobError(#[from] glob::GlobError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Obtain a std::fs::File from an i32 in a platform-independent manner.
///
/// On Unix-like platforms, this is done with File::from_raw_fd().
/// On Windows, this is done through the `libc` crate's `get_osfhandle()` function.
/// All other platforms will panic!()
pub fn file_from_fd_or_handle(fd: i32) -> File {
    #[cfg(unix)]
    {
        use std::os::unix::io::FromRawFd;
        unsafe { File::from_raw_fd(fd) }
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::{FromRawHandle, RawHandle};
        unsafe {
            let handle = libc::get_osfhandle(fd);
            File::from_raw_handle(handle as RawHandle)
        }
    }

    #[cfg(not(any(windows, unix)))]
    compile_error!("implemented only for unix and windows targets")
}

/// Get a string from a pointer.
///
/// # Safety
///
/// The caller is responsible for making sure the lifetime of the pointer
/// exceeds the lifetime of the output string.
///
/// ptr must be a valid pointer to a C string.
pub unsafe fn str_from_ptr(
    ptr: *const ::std::os::raw::c_char,
) -> Result<Option<&'static str>, std::str::Utf8Error> {
    if ptr.is_null() {
        return Ok(None);
    }

    Some(unsafe { CStr::from_ptr(ptr) }.to_str()).transpose()
}

/// Check scan limits in case we need to abort the scan.
///
/// # Safety
///
/// ctx must be a valid pointer to a clamav scan context structure
///
pub unsafe fn check_scan_limits(
    module_name: &str,
    ctx: *mut sys::cli_ctx,
    need1: u64,
    need2: u64,
    need3: u64,
) -> sys::cl_error_t {
    let module_name = match std::ffi::CString::new(module_name) {
        Ok(name) => name,
        Err(_) => {
            error!("Invalid module_name: {:?}", module_name);
            return sys::cl_error_t_CL_EFORMAT;
        }
    };

    unsafe { sys::cli_checklimits(module_name.as_ptr(), ctx, need1, need2, need3) }
}

/// Check only the scan time limit in case we need to abort the scan.
///
/// # Safety
///
/// ctx must be a valid pointer to a clamav scan context structure
///
pub unsafe fn check_scan_time_limit(ctx: *mut sys::cli_ctx) -> sys::cl_error_t {
    unsafe { cli_checktimelimit(ctx) }
}

pub const HEURISTICS_LIMITS_EXCEEDED_MAX_SCAN_SIZE: &[u8] =
    b"Heuristics.Limits.Exceeded.MaxScanSize\0";
pub const HEURISTICS_LIMITS_EXCEEDED_MAX_FILES: &[u8] = b"Heuristics.Limits.Exceeded.MaxFiles\0";

fn archive_metadata_filepos(filepos: usize) -> Option<u32> {
    u32::try_from(filepos).ok()
}

/// Append an exceeds-max heuristic alert or metadata entry.
///
/// The C evidence store retains the original `virname` pointer, so the alert
/// name must have static lifetime rather than temporary Rust string storage.
///
/// # Safety
///
/// ctx must be a valid pointer to a clamav scan context structure.
/// virname must point to a static NUL-terminated C string.
///
pub unsafe fn append_potentially_unwanted_if_heur_exceedsmax(
    ctx: *mut sys::cli_ctx,
    virname: &'static [u8],
    limit_result: sys::cl_error_t,
) {
    debug_assert_eq!(virname.last(), Some(&0));

    unsafe {
        sys::cli_append_potentially_unwanted_if_heur_exceedsmax(
            ctx,
            virname.as_ptr().cast(),
            limit_result,
        );
    }
}

/// Scan archive metadata.
///
/// # Safety
///
/// ctx must be a valid pointer to a clamav scan context structure
///
pub unsafe fn scan_archive_metadata(
    ctx: *mut sys::cli_ctx,
    filename: &str,
    filesize_compressed: usize,
    filesize_original: usize,
    is_encrypted: bool,
    filepos: usize,
    res1: i32,
) -> sys::cl_error_t {
    let filepos = match archive_metadata_filepos(filepos) {
        Some(filepos) => filepos,
        None => {
            /* The legacy metadata callback exposes the member index as a
             * 32-bit value. Do not silently wrap a large Rust-side index and
             * publish metadata for the wrong member. */
            unsafe {
                sys::cli_mark_scan_incomplete(
                    ctx,
                    b"archive metadata member index exceeds the 32-bit callback range\0"
                        .as_ptr()
                        .cast(),
                );
            }
            return sys::cl_error_t_CL_ERESOURCE;
        }
    };
    let module_name = match std::ffi::CString::new(filename) {
        Ok(name) => name,
        Err(_) => {
            debug!("Invalid archive metadata filename: {:?}", filename);
            return sys::cl_error_t_CL_EFORMAT;
        }
    };

    unsafe {
        sys::cli_matchmeta(
            ctx,
            module_name.as_ptr(),
            filesize_compressed,
            filesize_original,
            i32::from(is_encrypted),
            filepos,
            res1,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{archive_metadata_filepos, glob_rm, mkdir_w32, FFIError};
    use std::ffi::CString;

    #[test]
    fn archive_metadata_filepos_rejects_narrowing() {
        assert_eq!(archive_metadata_filepos(0), Some(0));
        assert_eq!(archive_metadata_filepos(u32::MAX as usize), Some(u32::MAX));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(archive_metadata_filepos(u32::MAX as usize + 1), None);
    }

    #[test]
    fn glob_pattern_errors_are_fail_visible() {
        let pattern = CString::new("[unterminated").unwrap();
        let mut error: *mut FFIError = std::ptr::null_mut();

        let result = unsafe { glob_rm(pattern.as_ptr(), &mut error) };

        assert!(!result);
        assert!(!error.is_null());
        unsafe { crate::ffi_util::ffierror_free(error) };
    }

    #[test]
    fn glob_null_error_output_is_fail_visible() {
        let pattern = CString::new("[unterminated").unwrap();

        let result = unsafe { glob_rm(pattern.as_ptr(), std::ptr::null_mut()) };

        assert!(!result);
    }

    #[test]
    fn mkdir_null_path_is_fail_visible() {
        let mut error: *mut FFIError = std::ptr::null_mut();

        let result = unsafe { mkdir_w32(std::ptr::null(), &mut error) };

        assert!(!result);
        assert!(!error.is_null());
        unsafe { crate::ffi_util::ffierror_free(error) };
    }

    #[test]
    fn mkdir_null_error_output_is_fail_visible() {
        let result = unsafe { mkdir_w32(std::ptr::null(), std::ptr::null_mut()) };

        assert!(!result);
    }
}

/// C interface to delete files using a glob pattern.
///
/// # Safety
///
/// No parameters may be NULL.
#[export_name = "glob_rm"]
pub unsafe extern "C" fn glob_rm(glob_str: *const c_char, err: *mut *mut FFIError) -> bool {
    if err.is_null() {
        warn!("err is NULL");
        return false;
    }

    let glob_str = validate_str_param!(glob_str, err = err);

    let paths = match glob(glob_str) {
        Ok(paths) => paths,
        Err(e) => return ffi_error!(err = err, e),
    };

    for entry in paths {
        match entry {
            Ok(path) => {
                debug!("Deleting: {path:?}");
                if let Err(e) = std::fs::remove_file(&path) {
                    warn!("Failed to delete file: {path:?}");
                    return ffi_error!(err = err, Error::IoError(e));
                }
            }
            Err(e) => {
                return ffi_error!(err = err, Error::GlobError(e));
            }
        }
    }

    true
}

/// C interface to create a directory
///
/// # Safety
///
/// No parameters may be NULL.
#[export_name = "mkdir_w32"]
pub unsafe extern "C" fn mkdir_w32(path: *const c_char, err: *mut *mut FFIError) -> bool {
    if err.is_null() {
        warn!("err is NULL");
        return false;
    }

    let path = validate_str_param!(path, err = err);

    if let Err(e) = std::fs::create_dir_all(&path) {
        warn!("Failed to create directory: {path:?}");
        return ffi_error!(err = err, Error::IoError(e));
    }

    true
}
