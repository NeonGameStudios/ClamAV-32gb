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

use std::{convert::TryInto, path::PathBuf, slice};

use crate::{fmap::FMap, sys::cli_ctx, util::str_from_ptr};

/// Error enumerates all possible errors returned by this library.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid format")]
    Format,

    #[error("Invalid NULL pointer: {0}")]
    NullPointer(&'static str),

    #[error("{0} parameter is NULL")]
    NullParam(&'static str),

    #[error("No more files to extract")]
    NoMoreFiles,

    #[error("Invalid FMap: {0}")]
    BadMap(#[from] crate::fmap::Error),

    #[error("String not UTF8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

/// Get the ctx.target_filepath as an Option<'str>
///
/// # Safety
///
/// Must be a valid ctx pointer.
pub unsafe fn target_filepath(ctx: *mut cli_ctx) -> Result<Option<PathBuf>, Error> {
    if ctx.is_null() {
        return Err(Error::NullPointer("ctx"));
    }

    Ok(str_from_ptr(unsafe { *ctx }.target_filepath)
        .map_err(Error::Utf8)?
        .map(PathBuf::from))
}

/// Get the fmap for the current layer.
///
/// # Safety
///
/// Must be a valid ctx pointer.
pub unsafe fn current_fmap(ctx: *mut cli_ctx) -> Result<FMap, Error> {
    if ctx.is_null() {
        return Err(Error::NullPointer("ctx"));
    }

    let ctx_ref = unsafe { &*ctx };
    if ctx_ref.recursion_stack.is_null() {
        return Err(Error::NullParam("recursion_stack"));
    }

    let recursion_stack_size = ctx_ref.recursion_stack_size as usize;
    let recursion_level = ctx_ref.recursion_level as usize;
    if recursion_stack_size == 0 || recursion_level >= recursion_stack_size {
        return Err(Error::Format);
    }

    let recursion_stack = unsafe {
        slice::from_raw_parts(ctx_ref.recursion_stack, recursion_stack_size)
    };

    let current_level = recursion_stack[recursion_level];

    current_level.fmap.try_into().map_err(Error::BadMap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::{cli_ctx, cli_scan_layer_t};

    #[test]
    fn current_fmap_rejects_missing_recursion_stack() {
        let mut ctx: cli_ctx = unsafe { std::mem::zeroed() };

        let result = unsafe { current_fmap(&mut ctx) };

        assert!(matches!(result, Err(Error::NullParam("recursion_stack"))));
    }

    #[test]
    fn current_fmap_rejects_recursion_level_outside_stack() {
        let mut layers: [cli_scan_layer_t; 1] = unsafe { std::mem::zeroed() };
        let mut ctx: cli_ctx = unsafe { std::mem::zeroed() };
        ctx.recursion_stack = layers.as_mut_ptr();
        ctx.recursion_stack_size = layers.len() as u32;
        ctx.recursion_level = layers.len() as u32;

        let result = unsafe { current_fmap(&mut ctx) };

        assert!(matches!(result, Err(Error::Format)));
    }
}
