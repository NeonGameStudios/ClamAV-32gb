/*
 *  Fuzzy hash implementations, matching, and signature support
 *
 *  Copyright (C) 2022-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Micah Snyder, Mickey Sola, Scott Hutton
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
    collections::HashMap,
    convert::{TryFrom, TryInto},
    ffi::CStr,
    io::{self, BufReader},
    mem::ManuallyDrop,
    os::raw::c_char,
    panic, slice,
};

use image::{
    imageops::FilterType::Lanczos3, DynamicImage, ImageBuffer, ImageDecoder, ImageReader, Luma,
    Pixel, Rgb,
};
use log::{debug, error, warn};
use num_traits::{NumCast, ToPrimitive, Zero};
use rustdct::DctPlanner;
use transpose::transpose;

use crate::{ffi_error, ffi_util::FFIError, rrf_call, sys, validate_str_param};

const IMAGE_FUZZY_HASH_LEN: usize = 8;

/// Error enumerates all possible errors returned by this library.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid format")]
    Format,

    #[error("Unknown algorithm: {0}")]
    UnknownAlgorithm(String),

    #[error("Failed to convert hamming distance to unsigned 32bit integer: {0}")]
    FormatHammingDistance(String),

    #[error("Invalid hamming distance: {0}")]
    InvalidHammingDistance(u32),

    #[error("Invalid hash: {0}")]
    FormatHashBytes(String),

    #[error("Failed to load image: {0}")]
    ImageLoad(image::ImageError),

    #[error("Failed to load image due to bug in image decoder")]
    ImageLoadPanic(),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("{0} parameter is NULL")]
    NullParam(&'static str),

    #[error("Image reader failed: {0}")]
    ImageReader(#[source] io::Error),

    #[error("Image decoder exceeded the configured contiguous budget: {0}")]
    ContiguousBudget(sys::cl_error_t),

    #[error("Failed to allocate image fuzzy hash signature metadata")]
    Allocation,

    #[error("{0} hash must be {1} characters in length")]
    InvalidHashLength(&'static str, usize),
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct ImageFuzzyHash {
    bytes: [u8; 8],
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub enum FuzzyHash {
    Image(ImageFuzzyHash),
}

impl TryFrom<&str> for ImageFuzzyHash {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 16 {
            return Err(Error::InvalidHashLength("ImageFuzzyHash", 16));
        }

        let mut hashbytes = [0; 8];
        if hex::decode_to_slice(value, &mut hashbytes).is_ok() {
            Ok(ImageFuzzyHash { bytes: hashbytes })
        } else {
            Err(Error::FormatHashBytes(value.to_string()))
        }
    }
}

impl std::fmt::Display for FuzzyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FuzzyHash::Image(hash_bytes) => {
                write!(f, "{}", hex::encode(hash_bytes.bytes))
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct FuzzyHashMap {
    hashmap: HashMap<FuzzyHash, Vec<FuzzyHashMeta>>,
}

#[derive(Debug, Copy, Clone)]
pub struct FuzzyHashMeta {
    lsigid: u32,
    subsigid: u32,
    hamming_distance: u32,
}

/// Initialize the hashmap
#[no_mangle]
pub extern "C" fn fuzzy_hashmap_new() -> sys::fuzzyhashmap_t {
    Box::into_raw(Box::<FuzzyHashMap>::default()) as sys::fuzzyhashmap_t
}

/// Free the hashmap
#[no_mangle]
pub extern "C" fn fuzzy_hash_free_hashmap(fuzzy_hashmap: sys::fuzzyhashmap_t) {
    if fuzzy_hashmap.is_null() {
        warn!("Attempted to free a NULL hashmap pointer. Please report this at: https://github.com/Cisco-Talos/clamav/issues");
    } else {
        let _ = unsafe { Box::from_raw(fuzzy_hashmap as *mut FuzzyHashMap) };
    }
}

/// C interface for FuzzyHashMap::check().
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// No parameters may be NULL
#[export_name = "fuzzy_hash_check"]
pub unsafe extern "C" fn _fuzzy_hash_check(
    fuzzy_hashmap: sys::fuzzyhashmap_t,
    mdata: *mut sys::cli_ac_data,
    image_fuzzy_hash: sys::image_fuzzy_hash_t,
) -> bool {
    if fuzzy_hashmap.is_null() || mdata.is_null() {
        return false;
    }
    let hash_bytes = image_fuzzy_hash.hash;

    let hashmap = ManuallyDrop::new(Box::from_raw(fuzzy_hashmap as *mut FuzzyHashMap));

    debug!(
        "Checking image fuzzy hash '{}' for signature match",
        hex::encode(hash_bytes)
    );

    for meta in hashmap.check(hash_bytes) {
        sys::lsig_increment_subsig_match(mdata, meta.lsigid, meta.subsigid);
    }

    true
}

/// C interface for FuzzyHashMap::load_subsignature().
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// `hexsig` and `err` must not be NULL
#[export_name = "fuzzy_hash_load_subsignature"]
pub unsafe extern "C" fn _fuzzy_hash_load_subsignature(
    fuzzy_hashmap: sys::fuzzyhashmap_t,
    hexsig: *const c_char,
    lsig_id: u32,
    subsig_id: u32,
    err: *mut *mut FFIError,
) -> bool {
    if err.is_null() {
        error!("err is NULL");
        return false;
    }
    if fuzzy_hashmap.is_null() {
        return ffi_error!(err = err, Error::NullParam("fuzzy_hashmap"));
    }
    let hexsig = validate_str_param!(hexsig, err = err);

    let mut hashmap = ManuallyDrop::new(Box::from_raw(fuzzy_hashmap as *mut FuzzyHashMap));

    rrf_call!(
        err = err,
        hashmap.load_subsignature(hexsig, lsig_id, subsig_id)
    )
}

/// C interface for fuzzy_hash_calculate_image().
/// Handles all the unsafe ffi stuff.
///
/// # Safety
///
/// `file_bytes` and `hash_out` must not be NULL
#[export_name = "fuzzy_hash_calculate_image"]
pub unsafe extern "C" fn _fuzzy_hash_calculate_image(
    file_bytes: *const u8,
    file_size: usize,
    hash_out: *mut u8,
    hash_out_len: usize,
    err: *mut *mut FFIError,
) -> bool {
    if err.is_null() {
        error!("err is NULL");
        return false;
    }
    if hash_out.is_null() {
        return ffi_error!(err = err, Error::NullParam("hash_out"));
    }
    if hash_out_len < IMAGE_FUZZY_HASH_LEN {
        return ffi_error!(
            err = err,
            Error::InvalidParameter(format!(
                "hash_bytes output parameter too small to hold the hash: {} < {}",
                hash_out_len, IMAGE_FUZZY_HASH_LEN
            ))
        );
    }

    let buffer = if file_bytes.is_null() {
        return ffi_error!(err = err, Error::NullParam("file_bytes"));
    } else if file_size > isize::MAX as usize {
        return ffi_error!(
            err = err,
            Error::InvalidParameter(format!(
                "file_bytes input is too large for a Rust slice: {} > {}",
                file_size,
                isize::MAX
            ))
        );
    } else {
        slice::from_raw_parts(file_bytes, file_size)
    };

    let hash_result = fuzzy_hash_calculate_image(buffer);
    let hash_bytes = match hash_result {
        Ok(hash) => hash,
        Err(error) => return ffi_error!(err = err, error),
    };

    if hash_bytes.len() > IMAGE_FUZZY_HASH_LEN || hash_out_len < hash_bytes.len() {
        return ffi_error!(
            err = err,
            Error::InvalidParameter(format!(
                "hash_bytes output parameter too small to hold the hash: {} < {}",
                hash_out_len,
                hash_bytes.len()
            ))
        );
    }

    hash_out.copy_from(hash_bytes.as_ptr(), hash_bytes.len());

    true
}

/// Calculate an image fuzzy hash from a bounded fmap reader.
///
/// The encoded source is read through `FMapReader` in bounded windows. Only
/// the image decoder's declared output working set is admitted to the shared
/// contiguous budget; the encoded source itself is never borrowed as one
/// whole-file slice.
fn fuzzy_hash_calculate_image_reader_inner(
    fmap: &crate::fmap::FMap,
    scan_ctx: *mut sys::cli_ctx,
) -> Result<Vec<u8>, Error> {
    if scan_ctx.is_null() {
        return Err(Error::NullParam("scan_ctx"));
    }

    let reader = ImageReader::new(BufReader::new(crate::fmap::FMapReader::new_with_context(
        fmap, scan_ctx,
    )))
    .with_guessed_format()
    .map_err(Error::ImageReader)?;
    let decoder = reader.into_decoder().map_err(Error::ImageLoad)?;

    /*
     * The fuzzy calculation can retain the decoded image while it creates a
     * temporary RGB image and a grayscale image.  A multiplier based only on
     * `total_bytes()` under-reserves low-width formats such as L8: their
     * decoded buffer is small, but the RGB conversion still needs three bytes
     * per pixel.  Derive the conversion working set from the pixel count and
     * keep a fixed allowance for the 32x32 resize/DCT buffers. This remains
     * independent of the encoded source length.
     */
    const TRANSFORM_OVERHEAD: u64 = 1024 * 1024;
    let decoded_bytes: u64 = decoder.total_bytes();
    let pixel_count = (decoder.dimensions().0 as u64)
        .checked_mul(decoder.dimensions().1 as u64)
        .ok_or(Error::ContiguousBudget(sys::cl_error_t_CL_ERESOURCE))?;
    let conversion_bytes = pixel_count
        .checked_mul(4)
        .ok_or(Error::ContiguousBudget(sys::cl_error_t_CL_ERESOURCE))?;
    let working_set = decoded_bytes
        .checked_add(conversion_bytes)
        .and_then(|bytes| bytes.checked_add(TRANSFORM_OVERHEAD))
        .ok_or(Error::ContiguousBudget(sys::cl_error_t_CL_ERESOURCE))?;

    let status = unsafe { sys::cli_scan_reserve_contiguous(scan_ctx, working_set) };
    if status != sys::cl_error_t_CL_SUCCESS {
        return Err(Error::ContiguousBudget(status));
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        DynamicImage::from_decoder(decoder)
            .map_err(Error::ImageLoad)
            .and_then(calculate_fuzzy_hash_from_image)
    }));
    unsafe { sys::cli_scan_release_contiguous(scan_ctx, working_set) };
    match result {
        Ok(result) => result,
        Err(_) => Err(Error::ImageLoadPanic()),
    }
}

fn fuzzy_hash_reader_status(error: &Error) -> sys::cl_error_t {
    fn io_status(error: &io::Error) -> sys::cl_error_t {
        if error.kind() == io::ErrorKind::TimedOut {
            sys::cl_error_t_CL_ETIMEOUT
        } else if crate::fmap::is_read_failure(error) {
            sys::cl_error_t_CL_EREAD
        } else {
            sys::cl_error_t_CL_EPARSE
        }
    }

    match error {
        Error::ContiguousBudget(status) => *status,
        Error::ImageReader(error) => io_status(error),
        Error::ImageLoad(image::ImageError::IoError(error)) => io_status(error),
        Error::ImageLoad(image::ImageError::Limits(_)) => sys::cl_error_t_CL_ERESOURCE,
        _ => sys::cl_error_t_CL_EPARSE,
    }
}

/// C interface for calculating an image fuzzy hash from a fmap.
///
/// Unlike `fuzzy_hash_calculate_image`, this entry point does not create a
/// Rust slice over the encoded input. It is used by the scanner for image
/// layers that may be larger than the ordinary contiguous source limit.
///
/// # Safety
///
/// `fmap`, `scan_ctx`, `hash_out`, and `err` must be valid pointers. The fmap
/// and scan context remain owned by the caller for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn fuzzy_hash_calculate_image_fmap(
    fmap: *mut sys::fmap_t,
    scan_ctx: *mut sys::cli_ctx,
    hash_out: *mut u8,
    hash_out_len: usize,
    err: *mut *mut FFIError,
) -> sys::cl_error_t {
    if err.is_null() {
        error!("err is NULL");
        return sys::cl_error_t_CL_ENULLARG;
    }
    if hash_out.is_null() {
        *err = Box::into_raw(Box::new(Error::NullParam("hash_out").into()));
        return sys::cl_error_t_CL_ENULLARG;
    }
    if hash_out_len < IMAGE_FUZZY_HASH_LEN {
        *err = Box::into_raw(Box::new(Error::InvalidParameter(format!(
            "hash_bytes output parameter too small to hold the hash: {} < {}",
            hash_out_len, IMAGE_FUZZY_HASH_LEN
        ))
        .into()));
        return sys::cl_error_t_CL_EARG;
    }

    let fmap = match crate::fmap::FMap::try_from(fmap) {
        Ok(fmap) => fmap,
        Err(error) => {
            *err = Box::into_raw(Box::new(Error::InvalidParameter(error.to_string()).into()));
            return sys::cl_error_t_CL_ENULLARG;
        }
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        fuzzy_hash_calculate_image_reader_inner(&fmap, scan_ctx)
    }));
    let result = match result {
        Ok(result) => result,
        Err(_) => Err(Error::ImageLoadPanic()),
    };

    match result {
        Ok(hash_bytes) => {
            hash_out.copy_from(hash_bytes.as_ptr(), hash_bytes.len());
            sys::cl_error_t_CL_SUCCESS
        }
        Err(error) => {
            let status = fuzzy_hash_reader_status(&error);
            *err = Box::into_raw(Box::new(error.into()));
            status
        }
    }
}

impl FuzzyHashMap {
    /// Check for fuzzy hash matches.
    ///
    /// The signature distance is the Hamming distance between the eight-byte
    /// image hashes, measured in differing bits. Exact matches are looked up
    /// directly; nonzero-distance signatures are checked against the
    /// same bounded map without materializing image data or an unbounded
    /// candidate table.
    pub fn check(&self, hash: [u8; 8]) -> impl Iterator<Item = &FuzzyHashMeta> + '_ {
        let exact_matches = self
            .hashmap
            .get(&FuzzyHash::Image(ImageFuzzyHash { bytes: hash }))
            .into_iter()
            .flat_map(|meta_vec| meta_vec.iter());

        let nearby_matches = self
            .hashmap
            .iter()
            .filter_map(move |(candidate, meta_vec)| {
                let FuzzyHash::Image(candidate) = candidate;
                if candidate.bytes == hash {
                    return None;
                }

                let distance = candidate
                    .bytes
                    .iter()
                    .zip(hash.iter())
                    .map(|(candidate, actual)| (*candidate ^ *actual).count_ones())
                    .sum::<u32>();

                Some(
                    meta_vec
                        .iter()
                        .filter(move |meta| distance <= meta.hamming_distance),
                )
            })
            .flatten();

        exact_matches.chain(nearby_matches)
    }

    /// Load a fuzzy hash subsignature
    /// Parse a fuzzy hash logical sig subsignature.
    /// Add the fuzzy hash to the matcher so it can be matched.
    pub fn load_subsignature(
        &mut self,
        hexsig: &str,
        lsig_id: u32,
        subsig_id: u32,
    ) -> Result<(), Error> {
        let mut hexsig_split = hexsig.split('#');

        let algorithm = match hexsig_split.next() {
            Some(x) => x,
            None => return Err(Error::Format),
        };

        let hash = match hexsig_split.next() {
            Some(x) => x,
            None => return Err(Error::Format),
        };

        let distance: u32 = match hexsig_split.next() {
            Some(x) => match x.parse::<u32>() {
                Ok(n) => n,
                Err(_) => {
                    return Err(Error::FormatHammingDistance(x.to_string()));
                }
            },
            None => 0,
        };

        if hexsig_split.next().is_some() {
            return Err(Error::Format);
        }

        let max_hamming_distance = (IMAGE_FUZZY_HASH_LEN * u8::BITS as usize) as u32;
        if distance > max_hamming_distance {
            return Err(Error::InvalidHammingDistance(distance));
        }

        match algorithm {
            "fuzzy_img" => {
                // Convert the hash string to an image fuzzy hash bytes struct
                let image_fuzzy_hash = hash
                    .try_into()
                    .map_err(|e| Error::FormatHashBytes(format!("{}: {}", e, hash)))?;

                let fuzzy_hash = FuzzyHash::Image(image_fuzzy_hash);

                let meta: FuzzyHashMeta = FuzzyHashMeta {
                    lsigid: lsig_id,
                    subsigid: subsig_id,
                    hamming_distance: distance,
                };

                /*
                 * Signature loading happens across an FFI boundary.  A normal
                 * HashMap::entry().or_default().push() may panic when either
                 * container grows, which would abort the caller instead of
                 * returning a database-load error.  Reserve both containers
                 * before mutating them so allocation failure remains visible to
                 * the C loader through the existing Result/FFIError path.
                 */
                self.hashmap
                    .try_reserve(1)
                    .map_err(|_| Error::Allocation)?;
                let metadata = self.hashmap.entry(fuzzy_hash).or_default();
                metadata
                    .try_reserve(1)
                    .map_err(|_| Error::Allocation)?;
                metadata.push(meta);

                Ok(())
            }
            _ => {
                error!("Unknown fuzzy hash algorithm: {}", algorithm);
                Err(Error::UnknownAlgorithm(algorithm.to_string()))
            }
        }
    }
}

/// Given a buffer and size, generate an image fuzzy hash
///
/// This algorithm attempts to reproduce the results of the `phash()` function
/// from the Python `imagehash` package.
///
/// # Notes
///
/// 1) I found that `image.grayscale() uses different RGB coefficients than
/// the python `image.convert("L"). The docs for PIL.Image.convert() state:
///
///     When translating a color image to greyscale (mode "L"),
///     the library uses the ITU-R 601-2 luma transform::
///
///         L = R * 299/1000 + G * 587/1000 + B * 114/1000
///
/// You can get near-identical** grayscale results by making a clone (or forking)
/// the image-rs crate, and changing the coefficients to match those above:
///
///     diff --git a/src/color.rs b/src/color.rs
///     index 78b5c587..92c99337 100644
///     --- a/src/color.rs
///     +++ b/src/color.rs
///     @@ -462,7 +462,7 @@ where
///      }
///
///      /// Coefficients to transform from sRGB to a CIE Y (luminance) value.
///     -const SRGB_LUMA: [f32; 3] = [0.2126, 0.7152, 0.0722];
///     +const SRGB_LUMA: [f32; 3] = [0.299, 0.587, 0.114];
///
///      #[inline]
///      fn rgb_to_luma<T: Primitive>(rgb: &[T]) -> T {
///
/// **Note that I say "near-identical" because rounding
/// appears to be slightly different and values are sometimes off-by-one.
///
/// This change doesn't appear to be required to match the phash_simple()
/// function, but to match the phash() function where the median is used instead
/// of the mean -- this change is required.
///
/// 2) scipy.fftpack.dct behaves differently on twodimensional arrays than
///    single-dimensional arrays.
///    See https://docs.scipy.org/doc/scipy/reference/generated/scipy.fftpack.dct.html:
///
///     Note the optional "axis" argument:
///         Axis along which the dct is computed; the default is over the last axis
///         (i.e., axis=-1).
///
/// For the Python `imagehash` package:
/// - The `phash_simple()` function is doing a DCT-2 transform on a 2-dimensional
///   32x32 array which means, just on the 2nd axis (just the rows).
/// - The `phash()` function is doing a 2D DCT-2 transform, by running the DCT-2 on
///   both X and Y axis, which is the same as transposing before or after each
///   DCT-2 call.
///
/// 3) I observed that the DCT2 results from Python are consistently 2x greater
///    than those from Rust. If I multiply every value by 2 after running the DCT,
///    then the results are the same.
///
/// 4) We need to get a subset of the 2-D array representing the lower
///    frequencies of the image, the same way the Python implementation does it.
///
/// The way the python implementation does this is with this line:
/// ```python
/// dctlowfreq = dct[:hash_size, :hash_size]
/// ```
///
/// You can't actually do that with a Python array of arrays... this is numpy
/// 2-D array manipulation magic, where you can index 2-D arrays in slices.
/// It works like this:
/// ```ipython3
/// In [0]: x = [[0, 1, 2, 3, 4], [4, 5, 6, 7, 8], [8, 9, 10, 11, 12], [12, 13, 14, 15, 16], [16, 17, 18, 19, 20]]
/// In [1]: h = 3
/// In [2]: n = np.asarray(x)
/// In [3]: lf = n[:h, 1:h+1]
/// In [4]: n
/// array([[ 0,  1,  2,  3,  4],
///        [ 4,  5,  6,  7,  8],
///        [ 8,  9, 10, 11, 12],
///        [12, 13, 14, 15, 16],
///        [16, 17, 18, 19, 20]])
///
/// In [5]: lf
/// array([[ 0,  1,  2],
///        [ 4,  5,  6],
///        [ 8,  9, 10]])
/// ```
///
/// We can do something similar, manually, to get the low-frequency selection.
///
/// param: hash_out is an output variable
/// param: hash_out_len indicates the size of the hash_out buffer
pub fn fuzzy_hash_calculate_image(buffer: &[u8]) -> Result<Vec<u8>, Error> {
    // Load image and attempt to catch panics in case the decoders encounter unexpected issues
    let result = panic::catch_unwind(|| -> Result<DynamicImage, Error> {
        let image = image::load_from_memory(buffer).map_err(Error::ImageLoad)?;
        Ok(image)
    });

    let og_image = match result {
        Ok(image) => image?,
        Err(_) => return Err(Error::ImageLoadPanic()),
    };

    calculate_fuzzy_hash_from_image(og_image)
}

fn calculate_fuzzy_hash_from_image(og_image: DynamicImage) -> Result<Vec<u8>, Error> {

    // Drop the alpha channel (if exists).
    let buff_rgb8 = og_image.to_rgb8();

    // Convert image to grayscale.
    let buff_luma8 = grayscale(&buff_rgb8);

    // Convert back to a DynamicImage type so we can resize it.
    let image_gs = DynamicImage::ImageLuma8(buff_luma8);

    // Shrink to a 32x32 (1024 pixel) image.
    let image_small = image::DynamicImage::resize_exact(&image_gs, 32, 32, Lanczos3);

    // Convert the data to a Vec of floats.
    let mut imgbuff_f32 = image_small.to_luma32f().into_raw();

    //
    // Compute a 2D DCT-2 in-place.
    //
    let dct2 = DctPlanner::new().plan_dct2(32);

    // Use a scratch space so we can transpose and run DCT's without allocating any extra space.
    // We'll switch back and forth between the buffer for the original small image (buffer1) and the scratch buffer (buffer2).
    let buffer1: &mut [f32] = imgbuff_f32.as_mut_slice();
    let buffer2: &mut [f32] = &mut [0.0; 1024];

    // Transpose the image so we can run DCT on the X axis (columns) first.
    transpose(buffer1, buffer2, 32, 32);

    // Run DCT2 on the columns.
    for (row_in, row_out) in buffer2.chunks_mut(32).zip(buffer1.chunks_mut(32)) {
        dct2.process_dct2_with_scratch(row_in, row_out);
    }
    // Multiply each value x2, to match results from scipy.fftpack.dct() implementation.
    // Note: Unsure why this is required, but it is.
    buffer2.iter_mut().for_each(|f| *f *= 2.0);

    // Transpose the image back so we can run DCT on the Y axis (rows).
    transpose(buffer2, buffer1, 32, 32);

    // Run DCT2 on the rows.
    for (row_in, row_out) in buffer1.chunks_mut(32).zip(buffer2.chunks_mut(32)) {
        dct2.process_dct2_with_scratch(row_in, row_out);
    }
    // Multiply each value x2, to match results from scipy.fftpack.dct() implementation.
    // Note: Unsure why this is required, but it is.
    buffer1.iter_mut().for_each(|f| *f *= 2.0);

    //
    // Construct a DCT low frequency vector using the top-left most 8x8 values of the 32x32 DCT array.
    //
    let dct_low_freq = buffer1
        // 2D array is 32-elements wide.
        .chunks(32)
        // Grab the first 8 rows.
        .take(8)
        // But only take the first 8 elements (columns) from each row.
        .flat_map(|chunk| chunk.chunks(8).take(1))
        // Flatten the 8x8 selection down to a vector of floats.
        .flatten()
        .copied()
        .collect::<Vec<f32>>();

    // Calculate average (median) of the DCT low frequency vector.
    let mut dct_low_freq_copy = dct_low_freq.clone();
    dct_low_freq_copy.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median: f32 = (dct_low_freq_copy[31] + dct_low_freq_copy[32]) / 2.0;

    // Construct hash vector by reducing DCT values to 1 or 0 by comparing terms vs median.
    let hashvec: Vec<u64> = dct_low_freq
        .into_iter()
        .map(|x| if x > median { 1 } else { 0 })
        .collect();

    // Construct hash vec<u8> from bits.
    let hash_bytes: Vec<u8> = hashvec
        .chunks(8)
        .map(|chunk| {
            let chunk = chunk.to_owned();
            chunk
                .iter()
                .rev()
                .enumerate()
                .fold(None, |accum, (n, val)| {
                    accum.or(Some(0)).map(|accum| accum | ((*val as u8) << n))
                })
        })
        .take_while(|x| x.is_some())
        .flatten()
        .collect();

    debug!("Image hash: {}", hex::encode(&hash_bytes));

    Ok(hash_bytes)
}

/// Use these instead:
///         L = R * 299/1000 + G * 587/1000 + B * 114/1000
const SRGB_LUMA: [f32; 3] = [299.0 / 1000.0, 587.0 / 1000.0, 114.0 / 1000.0];

#[inline]
fn rgb_to_luma(rgb: &[u8]) -> u8 {
    let l = SRGB_LUMA[0] * rgb[0].to_f32().unwrap()
        + SRGB_LUMA[1] * rgb[1].to_f32().unwrap()
        + SRGB_LUMA[2] * rgb[2].to_f32().unwrap();
    NumCast::from(l.round()).unwrap()
}

/// Convert the supplied image to grayscale. Alpha channel is discarded.
///
/// This is a customized implementation of the grayscale feature from the `image` crate.
/// This allows us to:
/// - use RGB->LUMA constants that match those used by the Python Pillow package.
/// - round the luma floating point value to the nearest integer rather than truncating.
///
/// See also: https://github.com/image-rs/image/issues/1554
fn grayscale(image: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> ImageBuffer<Luma<u8>, Vec<u8>> {
    let (width, height) = image.dimensions();
    let mut out = ImageBuffer::new(width, height);

    for y in 0..height {
        for x in 0..width {
            let pixel = image.get_pixel(x, y);

            let mut pix = Luma([Zero::zero()]);
            let gray = pix.channels_mut();
            let rgb = pixel.channels();
            gray[0] = rgb_to_luma(rgb);

            let pixel = Luma::from_slice(gray); //.into_color(); // no-op for luma->luma

            out.put_pixel(x, y, *pixel);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn fuzzy_hash_check_rejects_null_state() {
        let hash = sys::image_fuzzy_hash { hash: [0; 8] };

        assert!(!unsafe { _fuzzy_hash_check(std::ptr::null_mut(), std::ptr::null_mut(), hash) });
    }

    #[test]
    fn fuzzy_hash_check_rejects_null_matcher_data() {
        let hash = sys::image_fuzzy_hash { hash: [0; 8] };
        let hashmap = fuzzy_hashmap_new();

        assert!(!unsafe { _fuzzy_hash_check(hashmap, std::ptr::null_mut(), hash) });
        fuzzy_hash_free_hashmap(hashmap);
    }

    #[test]
    fn fuzzy_hash_load_rejects_null_map_with_error() {
        let signature = CString::new("fuzzy_img#0000000000000000#0").expect("C string");
        let mut error: *mut FFIError = std::ptr::null_mut();

        assert!(!unsafe {
            _fuzzy_hash_load_subsignature(
                std::ptr::null_mut(),
                signature.as_ptr(),
                0,
                0,
                &mut error,
            )
        });
        assert!(!error.is_null());
        unsafe { crate::ffi_util::ffierror_free(error) };
    }

    #[test]
    fn fuzzy_hash_load_rejects_null_signature_with_error() {
        let hashmap = fuzzy_hashmap_new();
        let mut error: *mut FFIError = std::ptr::null_mut();

        assert!(!unsafe {
            _fuzzy_hash_load_subsignature(
                hashmap,
                std::ptr::null(),
                0,
                0,
                &mut error,
            )
        });
        assert!(!error.is_null());
        unsafe { crate::ffi_util::ffierror_free(error) };
        fuzzy_hash_free_hashmap(hashmap);
    }

    #[test]
    fn fuzzy_hash_map_loads_and_finds_exact_image_hashes() {
        let mut hashmap = FuzzyHashMap::default();

        hashmap
            .load_subsignature("fuzzy_img#0000000000000000#0", 17, 23)
            .expect("valid image fuzzy signature");

        let matches: Vec<_> = hashmap.check([0; 8]).collect();
        assert!(!matches.is_empty(), "exact hash match");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].lsigid, 17);
        assert_eq!(matches[0].subsigid, 23);
    }

    #[test]
    fn fuzzy_hash_map_loads_multiple_metadata_records_for_one_hash() {
        let mut hashmap = FuzzyHashMap::default();

        hashmap
            .load_subsignature("fuzzy_img#0000000000000000#0", 17, 23)
            .expect("first valid image fuzzy signature");
        hashmap
            .load_subsignature("fuzzy_img#0000000000000000#1", 19, 29)
            .expect("second valid image fuzzy signature");

        let matches: Vec<_> = hashmap.check([0; 8]).collect();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].lsigid, 17);
        assert_eq!(matches[0].subsigid, 23);
        assert_eq!(matches[1].lsigid, 19);
        assert_eq!(matches[1].subsigid, 29);
    }

    #[test]
    fn fuzzy_hash_map_matches_within_declared_hamming_distance() {
        let mut hashmap = FuzzyHashMap::default();

        hashmap
            .load_subsignature("fuzzy_img#0000000000000000#1", 17, 23)
            .expect("valid nonzero image fuzzy distance");

        let one_bit: Vec<_> = hashmap
            .check([1, 0, 0, 0, 0, 0, 0, 0])
            .collect();
        assert_eq!(one_bit.len(), 1);
        assert_eq!(one_bit[0].lsigid, 17);
        assert_eq!(one_bit[0].subsigid, 23);
        assert!(hashmap
            .check([3, 0, 0, 0, 0, 0, 0, 0])
            .next()
            .is_none());
    }

    #[test]
    fn fuzzy_hash_map_rejects_distance_above_hash_width() {
        let mut hashmap = FuzzyHashMap::default();

        assert!(matches!(
            hashmap.load_subsignature("fuzzy_img#0000000000000000#65", 17, 23),
            Err(Error::InvalidHammingDistance(65))
        ));
    }

    #[test]
    fn fuzzy_hash_map_rejects_extra_signature_fields() {
        let mut hashmap = FuzzyHashMap::default();

        assert!(matches!(
            hashmap.load_subsignature("fuzzy_img#0000000000000000#0#extra", 17, 23),
            Err(Error::Format)
        ));
    }

    #[test]
    fn fuzzy_hash_calculation_rejects_null_error_output() {
        let mut output = [0u8; 8];

        assert!(!unsafe {
            _fuzzy_hash_calculate_image(
                std::ptr::null(),
                0,
                output.as_mut_ptr(),
                output.len(),
                std::ptr::null_mut(),
            )
        });
    }

    #[test]
    fn fuzzy_hash_calculation_rejects_short_output_before_decoding() {
        static VALID_IMAGE: &[u8] = &[
            b'G', b'I', b'F', b'8', b'9', b'a',
            0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
            0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x02, 0x02, 0x44, 0x01, 0x00,
            0x3b,
        ];
        let mut output = [0u8; IMAGE_FUZZY_HASH_LEN - 1];
        let mut error: *mut FFIError = std::ptr::null_mut();

        assert!(!unsafe {
            _fuzzy_hash_calculate_image(
                VALID_IMAGE.as_ptr(),
                VALID_IMAGE.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut error,
            )
        });
        assert!(!error.is_null());
        unsafe { crate::ffi_util::ffierror_free(error) };
    }

    #[test]
    fn fuzzy_hash_calculation_accepts_valid_image() {
        static VALID_IMAGE: &[u8] = &[
            b'G', b'I', b'F', b'8', b'9', b'a',
            0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
            0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x02, 0x02, 0x44, 0x01, 0x00,
            0x3b,
        ];
        let mut output = [0u8; IMAGE_FUZZY_HASH_LEN];
        let mut error: *mut FFIError = std::ptr::null_mut();

        assert!(unsafe {
            _fuzzy_hash_calculate_image(
                VALID_IMAGE.as_ptr(),
                VALID_IMAGE.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut error,
            )
        });
        assert!(error.is_null());
    }

    #[test]
    fn fuzzy_hash_calculation_rejects_invalid_image_with_error() {
        let input = b"not an image";
        let mut output = [0u8; IMAGE_FUZZY_HASH_LEN];
        let mut error: *mut FFIError = std::ptr::null_mut();

        assert!(!unsafe {
            _fuzzy_hash_calculate_image(
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut error,
            )
        });
        assert!(!error.is_null());
        unsafe { crate::ffi_util::ffierror_free(error) };
    }
}
