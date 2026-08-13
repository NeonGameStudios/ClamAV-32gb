/*
 *  libclamav features written in Rust
 *
 *  Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Micah Snyder, Mickey Sola
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

/// cbindgen:ignore
pub mod sys;

pub mod alz;
pub mod cdiff;
pub mod codesign;
pub mod css_image_extract;
pub mod ctx;
pub mod cvd;
pub mod evidence;
pub mod ffi_util;
pub mod fmap;
pub mod fuzzy_hash;
pub mod logging;
pub mod onenote;
pub mod scanners;
pub mod util;

#[cfg(all(test, target_pointer_width = "64"))]
mod ffi_layout_tests {
    use super::sys;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn widened_matcher_ffi_layout_matches_c() {
        assert_eq!(size_of::<sys::cli_ac_patt>(), 160);
        assert_eq!(align_of::<sys::cli_ac_patt>(), 8);
        assert_eq!(offset_of!(sys::cli_ac_patt, offdata), 104);

        assert_eq!(size_of::<sys::cli_bm_patt>(), 96);
        assert_eq!(align_of::<sys::cli_bm_patt>(), 8);
        assert_eq!(offset_of!(sys::cli_bm_patt, offdata), 24);

        assert_eq!(size_of::<sys::cli_pcre_meta>(), 136);
        assert_eq!(align_of::<sys::cli_pcre_meta>(), 8);
        assert_eq!(offset_of!(sys::cli_pcre_meta, offdata), 64);

        assert_eq!(size_of::<sys::cli_lsig_tdb>(), 144);
        assert_eq!(align_of::<sys::cli_lsig_tdb>(), 8);
        assert_eq!(offset_of!(sys::cli_lsig_tdb, filesize_range), 16);
        assert_eq!(offset_of!(sys::cli_lsig_tdb, filesize), 80);

        assert_eq!(size_of::<sys::cl_fmap>(), 312);
        assert_eq!(align_of::<sys::cl_fmap>(), 8);
        assert_eq!(offset_of!(sys::cl_fmap, aging_owner), 80);
        assert_eq!(offset_of!(sys::cl_fmap, offset), 96);
        assert_eq!(offset_of!(sys::cl_fmap, bitmap), 288);
    }
}
