/*
 *  Rust interface for libclamav FMap module
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
    convert::TryFrom,
    io::{self, ErrorKind, Read, Seek, SeekFrom},
};

use log::debug;

use crate::{
    sys,
    util::{check_scan_time_limit, str_from_ptr},
};

const RUST_FMAP_TIME_LIMIT_REASON: &[u8] = b"Rust fmap reader reached the configured time limit\0";

/// Error enumerates all possible errors returned by this library.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("{0} parameter is NULL")]
    NullParam(&'static str),

    #[error("Offset {0} and length {1} not contained in FMap of size {2}")]
    NotContained(usize, usize, usize),

    #[error("Whole-input parser request of {0} bytes exceeds the bounded parser cap of {1} bytes")]
    WholeInputTooLarge(usize, usize),

    #[error("FMap pointer not initialized: {0}")]
    UninitializedPtr(&'static str),

    #[error("Attempted to create Rust FMap interface from NULL pointer")]
    Null,
}

/// A bounded `Read + Seek` view over a C fmap.
///
/// The adapter only borrows one small fmap window at a time.  It is intended
/// for parser APIs that need a reader but must not receive a whole-file slice
/// for a multi-gigabyte input.  The bytes are copied into the caller's
/// buffer, then the fmap window is released immediately.
pub struct FMapReader<'a> {
    map: &'a FMap,
    position: u64,
    scan_ctx: Option<*mut sys::cli_ctx>,
    deadline_status: Option<sys::cl_error_t>,
}

impl<'a> FMapReader<'a> {
    const MAX_READ_CHUNK: usize = 1024 * 1024;

    pub fn new(map: &'a FMap) -> Self {
        Self {
            map,
            position: 0,
            scan_ctx: None,
            deadline_status: None,
        }
    }

    /// Create a reader that checks the shared C scan deadline before every
    /// fmap read and seek. The context-free constructor remains available for
    /// parser/library callers that do not own a scan context.
    pub fn new_with_context(map: &'a FMap, scan_ctx: *mut sys::cli_ctx) -> Self {
        Self {
            map,
            position: 0,
            scan_ctx: (!scan_ctx.is_null()).then_some(scan_ctx),
            deadline_status: None,
        }
    }

    fn check_scan_deadline(&mut self) -> io::Result<()> {
        if let Some(status) = self.deadline_status {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                format!("Rust fmap reader stopped with status {status}"),
            ));
        }

        if let Some(scan_ctx) = self.scan_ctx {
            let status = unsafe { check_scan_time_limit(scan_ctx) };
            if status != sys::cl_error_t_CL_SUCCESS {
                self.deadline_status = Some(status);
                unsafe {
                    sys::cli_mark_scan_incomplete(
                        scan_ctx,
                        RUST_FMAP_TIME_LIMIT_REASON.as_ptr().cast(),
                    );
                }
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "Rust fmap reader reached the configured time limit",
                ));
            }
        }

        Ok(())
    }

    pub fn deadline_status(&self) -> Option<sys::cl_error_t> {
        self.deadline_status
    }

    fn read_window(&mut self, at: usize, dst: &mut [u8]) -> io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }

        let need_fn = match unsafe { (*self.map.fmap_ptr).need } {
            Some(ptr) => ptr,
            None => {
                return Err(io::Error::new(
                    ErrorKind::Unsupported,
                    Error::UninitializedPtr("need()"),
                ));
            }
        };

        let requested = dst.len().min(Self::MAX_READ_CHUNK);
        let ptr = unsafe { need_fn(self.map.fmap_ptr, at, requested, 1) } as *const u8;
        if ptr.is_null() {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                Error::NotContained(at, requested, self.map.len()),
            ));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(ptr, dst.as_mut_ptr(), requested);
            if let Some(unneed_fn) = (*self.map.fmap_ptr).unneed_off {
                unneed_fn(self.map.fmap_ptr, at, requested);
            }
        }

        Ok(requested)
    }

    fn checked_position(base: u64, offset: i64) -> io::Result<u64> {
        let next = i128::from(base) + i128::from(offset);
        if next < 0 || next > i128::from(u64::MAX) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "fmap seek would overflow the 64-bit coordinate space",
            ));
        }
        Ok(next as u64)
    }
}

impl Read for FMapReader<'_> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if !dst.is_empty() {
            self.check_scan_deadline()?;
        }

        let len = self.map.len() as u64;
        if self.position >= len || dst.is_empty() {
            return Ok(0);
        }

        let remaining = len - self.position;
        let requested = (dst.len() as u64).min(remaining) as usize;
        let at = usize::try_from(self.position).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "fmap offset is not representable on this platform",
            )
        })?;
        let read = self.read_window(at, &mut dst[..requested])?;
        self.position = self.position.checked_add(read as u64).ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidInput, "fmap position overflow")
        })?;
        Ok(read)
    }
}

impl Seek for FMapReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.check_scan_deadline()?;

        let next = match from {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(offset) => Self::checked_position(self.position, offset)?,
            SeekFrom::End(offset) => Self::checked_position(self.map.len() as u64, offset)?,
        };
        self.position = next;
        Ok(next)
    }
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct FMap {
    fmap_ptr: *mut sys::cl_fmap_t,
}

impl TryFrom<*mut sys::cl_fmap_t> for FMap {
    type Error = Error;

    fn try_from(value: *mut sys::cl_fmap_t) -> Result<Self, Self::Error> {
        if value.is_null() {
            return Err(Error::Null);
        }

        Ok(FMap { fmap_ptr: value })
    }
}

impl<'a> FMap {
    /* These parsers require a borrowed slice for their third-party Rust API.
     * Keep that requirement from turning a 32 GiB fmap into a whole-input
     * prefault/lock operation. Larger recognized inputs fail visibly at the
     * parser boundary and remain available to the ordinary mapped matcher. */
    pub const WHOLE_INPUT_MAX: usize = 256 * 1024 * 1024;

    /// Simple wrapper around C FMAP module's fmap.need() method.
    pub fn need_off(&'a self, at: usize, len: usize) -> Result<&'a [u8], Error> {
        let fmap_size = unsafe { *self.fmap_ptr }.len;

        if at > fmap_size || len > fmap_size - at {
            debug!(
                "need_off at {:?} len {:?} is outside fmap size {:?}",
                at, len, fmap_size
            );
            return Err(Error::NotContained(at, len, fmap_size));
        }
        if len == 0 {
            return Ok(&[]);
        }

        // Get the need() method function pointer from the fmap.
        let need_fn = match unsafe { *self.fmap_ptr }.need {
            Some(ptr) => ptr,
            None => return Err(Error::UninitializedPtr("need()")),
        };

        let ptr: *const u8 = unsafe { need_fn(self.fmap_ptr, at, len, 1) } as *const u8;

        if ptr.is_null() {
            debug!(
                "need_off at {:?} len {:?} for fmap size {:?} returned NULL",
                at, len, fmap_size
            );
            return Err(Error::NotContained(at, len, fmap_size));
        }

        let slice: &[u8] = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(slice)
    }

    pub fn len(&self) -> usize {
        unsafe { (*self.fmap_ptr).len }
    }

    pub fn whole_input(&'a self) -> Result<&'a [u8], Error> {
        let len = self.len();
        if len > Self::WHOLE_INPUT_MAX {
            return Err(Error::WholeInputTooLarge(len, Self::WHOLE_INPUT_MAX));
        }

        self.need_off(0, len)
    }

    pub fn is_empty(&self) -> bool {
        unsafe { (*self.fmap_ptr).len == 0 }
    }

    pub fn name(&self) -> &'static str {
        unsafe {
            str_from_ptr((*self.fmap_ptr).name)
                .unwrap_or(Some("<invalid-utf8>"))
                .unwrap_or("<unnamed>")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ptr, sync::{atomic::{AtomicUsize, Ordering}, Mutex}};

    static NEED_CALLS: AtomicUsize = AtomicUsize::new(0);
    static UNNEED_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NEED_TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn null_need(
        _map: *mut sys::cl_fmap_t,
        _at: usize,
        _len: usize,
        _lock: std::os::raw::c_int,
    ) -> *const std::os::raw::c_void {
        NEED_CALLS.fetch_add(1, Ordering::Relaxed);
        ptr::null()
    }

    unsafe extern "C" fn memory_need(
        map: *mut sys::cl_fmap_t,
        at: usize,
        len: usize,
        _lock: std::os::raw::c_int,
    ) -> *const std::os::raw::c_void {
        let raw = &*map;
        if at.checked_add(len).is_none() || at + len > raw.len || raw.data.is_null() {
            return ptr::null();
        }
        (raw.data as *const u8).add(at) as *const std::os::raw::c_void
    }

    unsafe extern "C" fn count_unneed(
        _map: *mut sys::cl_fmap_t,
        _at: usize,
        _len: usize,
    ) {
        UNNEED_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn whole_input_rejects_oversized_maps_before_residency_request() {
        let _guard = NEED_TEST_LOCK.lock().expect("need test lock");
        NEED_CALLS.store(0, Ordering::Relaxed);
        let mut raw: sys::cl_fmap_t = unsafe { std::mem::zeroed() };
        raw.len = FMap::WHOLE_INPUT_MAX + 1;
        raw.need = Some(null_need);
        let map = FMap::try_from(&mut raw as *mut sys::cl_fmap_t).expect("fmap wrapper");

        assert!(matches!(map.whole_input(), Err(Error::WholeInputTooLarge(_, _))));
        assert_eq!(NEED_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn need_failure_is_reported_as_a_bounded_error() {
        let _guard = NEED_TEST_LOCK.lock().expect("need test lock");
        NEED_CALLS.store(0, Ordering::Relaxed);
        let mut raw: sys::cl_fmap_t = unsafe { std::mem::zeroed() };
        raw.len = 4096;
        raw.need = Some(null_need);
        let map = FMap::try_from(&mut raw as *mut sys::cl_fmap_t).expect("fmap wrapper");

        assert!(matches!(map.need_off(128, 64), Err(Error::NotContained(128, 64, 4096))));
        assert_eq!(NEED_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn need_off_rejects_out_of_bounds_before_callback() {
        let _guard = NEED_TEST_LOCK.lock().expect("need test lock");
        NEED_CALLS.store(0, Ordering::Relaxed);
        let mut raw: sys::cl_fmap_t = unsafe { std::mem::zeroed() };
        raw.len = 4096;
        raw.need = Some(null_need);
        let map = FMap::try_from(&mut raw as *mut sys::cl_fmap_t).expect("fmap wrapper");

        assert!(matches!(map.need_off(4097, 0), Err(Error::NotContained(4097, 0, 4096))));
        assert!(matches!(map.need_off(4090, 7), Err(Error::NotContained(4090, 7, 4096))));
        assert!(map.need_off(4096, 0).expect("empty fmap window").is_empty());
        assert_eq!(NEED_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn reader_copies_bounded_windows_and_releases_each_window() {
        let _guard = NEED_TEST_LOCK.lock().expect("need test lock");
        UNNEED_CALLS.store(0, Ordering::Relaxed);
        let data: Vec<u8> = (0..64).map(|value| value as u8).collect();
        let mut raw: sys::cl_fmap_t = unsafe { std::mem::zeroed() };
        raw.len = data.len();
        raw.data = data.as_ptr() as *const std::os::raw::c_void;
        raw.need = Some(memory_need);
        raw.unneed_off = Some(count_unneed);
        let map = FMap::try_from(&mut raw as *mut sys::cl_fmap_t).expect("fmap wrapper");

        let mut reader = FMapReader::new(&map);
        let mut output = [0u8; 12];
        reader.read_exact(&mut output).expect("read fmap data");
        assert_eq!(output, data[..12]);
        assert_eq!(reader.seek(SeekFrom::Start(40)).expect("seek"), 40);
        let mut tail = [0u8; 24];
        reader.read_exact(&mut tail).expect("read tail");
        assert_eq!(tail, data[40..]);
        assert_eq!(reader.read(&mut [0u8; 1]).expect("eof read"), 0);
        assert_eq!(UNNEED_CALLS.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn reader_rejects_negative_seek_without_changing_position() {
        let _guard = NEED_TEST_LOCK.lock().expect("need test lock");
        let mut raw: sys::cl_fmap_t = unsafe { std::mem::zeroed() };
        raw.len = 8;
        let map = FMap::try_from(&mut raw as *mut sys::cl_fmap_t).expect("fmap wrapper");
        let mut reader = FMapReader::new(&map);

        assert!(reader.seek(SeekFrom::Current(-1)).is_err());
        assert_eq!(reader.stream_position().expect("position"), 0);
    }
}
