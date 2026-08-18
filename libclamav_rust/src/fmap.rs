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

use std::convert::TryFrom;

use log::debug;

use crate::{sys, util::str_from_ptr};

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
        // Get the need() method function pointer from the fmap.
        let need_fn = match unsafe { *self.fmap_ptr }.need {
            Some(ptr) => ptr,
            None => return Err(Error::UninitializedPtr("need()")),
        };

        let ptr: *const u8 = unsafe { need_fn(self.fmap_ptr, at, len, 1) } as *const u8;

        if ptr.is_null() {
            let fmap_size = unsafe { *self.fmap_ptr }.len;
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
}
