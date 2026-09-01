/*
 *  Copyright (C) 2019-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  EGG is an archive format created by ESTsoft used by their ALZip
 *  archiving software.
 *
 *  This software is written from scratch based solely from ESTsoft's
 *  file format documentation and from testing with EGG format archives.
 *  ESTsoft's "unEGG" module was not used in the creation of this capability
 *  in order to avoid to licensing restrictions on the ESTsoft "unEGG" module.
 *
 *  EGG structure:
 *
 *     |-----------------------------------------------------|------|
 *     | EGG Header                                          |  1   |
 *     |-----------------------------------------------------|------|
 *     | Extra Field 1:                                      |      |
 *     |   Split Compression                                 |      |
 *     |   Solid Compression                                 | 0~N  |
 *     |   Global Encryption Header                          |      |
 *     |---------------------------------------|------|------|------|
 *     | File Header                           |  1   |      |      |
 *     |---------------------------------------|------|      |      |
 *     | Extra Field 2:                        |      |      |      |
 *     |   Filename Header                     |      | 1~N  |      |
 *     |   Comment Header                      | 0~N  |      |      |
 *     |   Windows File Information            |      |      |      |
 *     |   Posix File Information              |      |      | 0~N  |
 *     |   Encrypt Header                      |      |      |      |
 *     |---------------------------------------|------|------|      |
 *     | Block Header                          |  1   |      |      |
 *     |---------------------------------------|------|      |      |
 *     | Extra Field 3:                        | 0~N  | 0~N  |      |
 *     |---------------------------------------|------|      |      |
 *     | Compressed Data                       |  1   |      |      |
 *     |---------------------------------------|------|------|------|
 *     | Extra Field 4:                                      |      |
 *     |   Archive Comment Header                            | 0~N  |
 *     |-----------------------------------------------------|------|
 *
 *  Authors: Valerie Snyder
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdint.h>
#include <inttypes.h>
#include <wchar.h>
#include <locale.h>
#include <zlib.h>
#include <bzlib.h>

#include "lzma_iface.h"

#include "egg.h"
#include "entconv.h"
#include "str.h"

#ifndef WCHAR
typedef uint16_t WCHAR;
#endif

/*
 * All EGG struct variables are little-endian.
 */

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

/*
 * general defines
 */
#define EOFARC 0x08E28222 /* Signals end of each header, or end of archive. */
// #define EOFAR_ 0x2282E208
/*
 * egg_header
 */
#define EGG_HEADER_MAGIC 0x41474745
#define EGG_HEADER_VERSION 0x0100

typedef uint32_t magic32_t;

typedef struct __attribute__((packed)) {
    magic32_t magic;    /* 0x41474745 */
    uint16_t version;   /* 0x0100 */
    uint32_t header_id; /* Random number of the program (Cannot be 0) */
    uint32_t reserved;  /* 0x00000000 */
} egg_header;

/*
 * file_header
 */
#define FILE_HEADER_MAGIC 0x0A8590E3

typedef struct __attribute__((packed)) {
    magic32_t magic;      /* 0x0A8590E3 */
    uint32_t file_id;     /* Unique value for each header (Includes 0) */
    uint64_t file_length; /* Total size of the file */
} file_header;

/*
 * block_header
 * Note: split block of files exceeding 4G
 */
#define BLOCK_HEADER_MAGIC 0x02B50C13
#define BLOCK_HEADER_COMPRESS_ALGORITHM_STORE 0
#define BLOCK_HEADER_COMPRESS_ALGORITHM_DEFLATE 1
#define BLOCK_HEADER_COMPRESS_ALGORITHM_BZIP2 2
#define BLOCK_HEADER_COMPRESS_ALGORITHM_AZO 3
#define BLOCK_HEADER_COMPRESS_ALGORITHM_LZMA 4

typedef struct __attribute__((packed)) {
    magic32_t magic;            /* 0x02B50C13 */
    uint8_t compress_algorithm; /* compress method algorithm number */
    uint8_t compress_hint;      /* compress method hint */
    uint32_t uncompress_size;   /* size of the block before compressed */
    uint32_t compress_size;     /* size of the block after compressed */
    uint32_t crc32;             /* CRC value of the block */
} block_header;

/*
 * extra_field
 *
 * The extra_field is followed by a uint16_t or uint32_t depending on the bit_flag.
 * This describes the size of the following data.
 * In this way, an unexpected header can still be parsed.
 * Headers that make use of the extra_field:
 *  - windows_file_information header
 *  - posix_file_information header
 *  - encrypt header
 *  - filename header
 *  - comment header
 *  - split_compression header
 *  - solid_compression header
 */
#define EXTRA_FIELD_FLAGS_SIZE_IS_2BYTES 0x00
#define EXTRA_FIELD_FLAGS_SIZE_IS_4BYTES 0x01

typedef struct __attribute__((packed)) {
    magic32_t magic;
    uint8_t bit_flag; /* the size field following bit_flag depends if bit_flag bit 1: */
} extra_field;        /*    0 (uint16_t) */
                      /*    1 (uint32_t) */

/*
 * Extra field: encrypt
 *
 * The encrypt_header is followed by:
 *  1) dummy data (size bytes)
 *
 * Note: Inserted in Extra Field 2 (optional, depending on KeyBase, AES, or LEA)
 */
#define ENCRYPT_HEADER_MAGIC 0x08D1470F
#define ENCRYPT_HEADER_ENCRYPT_METHOD_XOR 0x00
#define ENCRYPT_HEADER_ENCRYPT_METHOD_AES128 0x01
#define ENCRYPT_HEADER_ENCRYPT_METHOD_AES256 0x02
#define ENCRYPT_HEADER_ENCRYPT_METHOD_LEA128 0x10
#define ENCRYPT_HEADER_ENCRYPT_METHOD_LEA256 0x20

typedef struct __attribute__((packed)) {
    uint8_t aes_header[10]; /* AES/LEA Header */
    uint8_t aes_footer[10]; /* AES/LEA Footer */
} aes_lea_128;

typedef struct __attribute__((packed)) {
    uint8_t aes_header[18]; /* AES/LEA header */
    uint8_t aes_footer[10]; /* AES/LEA footer */
} aes_lea_256;

typedef struct __attribute__((packed)) {
    uint8_t verify_data[12]; /* KeyBase encryption verification data */
    uint32_t crc32;          /* KeyBase partial block CRC */
} zip2_xor_keybase;

typedef struct __attribute__((packed)) {
    uint8_t encrypt_method; /* See above encrypt method #defines */
} encrypt_header;

/*
 * Extra field: windows_file_information
 */
#define WINDOWS_INFO_MAGIC 0x2C86950B
#define WINDOWS_INFO_ATTRIBUTE_READONLY 0x01
#define WINDOWS_INFO_ATTRIBUTE_HIDDEN 0x02
#define WINDOWS_INFO_ATTRIBUTE_SYSTEM_FILE 0x04
#define WINDOWS_INFO_ATTRIBUTE_LINK_FILE 0x10 /* junction file */
#define WINDOWS_INFO_ATTRIBUTE_DIRECTORY 0x40

typedef struct __attribute__((packed)) {
    uint64_t last_modified_time; /* "100-Nanosecond Time" since the Windows Epoch (00:00:00 UTC, January 1, 1601) */
    uint8_t attribute;           /* See above attribute #defines */
} windows_file_information;

/*
 * Extra field: posix_file_information
 */
#define POSIX_INFO_MAGIC 0x1EE922E5
#define POSIX_INFO_MODE_FILETYPE_BITMASK 0x0170000  /* bitmask for the file type bitfields */
#define POSIX_INFO_MODE_SOCKET 0x0140000            /* socket */
#define POSIX_INFO_MODE_SYM_LINK 0x0120000          /* symbolic link */
#define POSIX_INFO_MODE_REG_FILE 0x0100000          /* regular file */
#define POSIX_INFO_MODE_BLOCK_DEVICE 0x0060000      /* block device */
#define POSIX_INFO_MODE_DIRECTORY 0x0040000         /* directory */
#define POSIX_INFO_MODE_CHAR_DEVICE 0x0020000       /* character device */
#define POSIX_INFO_MODE_FIFO 0x0010000              /* FIFO */
#define POSIX_INFO_MODE_SET_UID_BIT 0x0004000       /* set UID bit */
#define POSIX_INFO_MODE_SET_GROUPID_BIT 0x0002000   /* set-group-ID bit (see below) */
#define POSIX_INFO_MODE_STICKY_BIT 0x0001000        /* sticky bit (see below) */
#define POSIX_INFO_MODE_PERM_OWNER_MASK 0x00700     /* mask for file owner permissions */
#define POSIX_INFO_MODE_PERM_OWNER_READ 0x00400     /* owner has read permission */
#define POSIX_INFO_MODE_PERM_OWNER_WRITE 0x00200    /* owner has write permission */
#define POSIX_INFO_MODE_PERM_OWNER_EXECUTE 0x00100  /* owner has execute permission */
#define POSIX_INFO_MODE_PERM_GROUP_MASK 0x00070     /* mask for group permissions */
#define POSIX_INFO_MODE_PERM_GROUP_READ 0x00040     /* group has read permission */
#define POSIX_INFO_MODE_PERM_GROUP_WRITE 0x00020    /* group has write permission */
#define POSIX_INFO_MODE_PERM_GROUP_EXECUTE 0x00010  /* group has execute permission */
#define POSIX_INFO_MODE_PERM_OTHERS_MASK 0x00007    /* mask for permissions for others (not in group) */
#define POSIX_INFO_MODE_PERM_OTHERS_READ 0x00004    /* others have read permission */
#define POSIX_INFO_MODE_PERM_OTHERS_WRITE 0x00002   /* others have write permission */
#define POSIX_INFO_MODE_PERM_OTHERS_EXECUTE 0x00001 /* others have execute permission*/

typedef struct __attribute__((packed)) {
    uint32_t mode;               /* see above mode #defines */
    uint32_t uid;                /*  */
    uint32_t gid;                /*  */
    uint64_t last_modified_time; /* "Second Time" since the Unix Epoch (00:00:00 UTC, January 1, 1970) */
} posix_file_information;

/*
 * Extra field: dummy_header
 *
 * The dummy header extra_info is followed by:
 *  1) dummy data (size bytes)
 *
 * Note: No need to consider if the size is too small to fit the dummy header because it can be distinguished by size calculation.
 */
#define DUMMY_HEADER_MAGIC 0x07463307

/*
 * Extra field: filename
 *
 * The filename extra_field is followed by:
 *  1) uint16_t locale IFF bit_flag is NOT unicode (UCS-2 LE)
 *  1) uint32_t parent_path_id IFF bit_flag is relative.
 *     parent_path_id will be the ID of a file possessing the parent path.
 *  2) name buffer (size bytes minus above optional fields)
 */
#define FILENAME_HEADER_MAGIC 0x0A8591AC
#define FILENAME_HEADER_FLAGS_ENCRYPT 0x04
#define FILENAME_HEADER_FLAGS_MULTIBYTE_CODEPAGE_INSTEAD_OF_UTF8 0x08
#define FILENAME_HEADER_FLAGS_RELATIVE_PATH_INSTEAD_OF_ABSOLUTE 0x10
#define FILENAME_HEADER_LOCALE_USE_SYSTEM 0
#define FILENAME_HEADER_LOCALE_JAPANESE 932 /* Shift-JIS */
#define FILENAME_HEADER_LOCALE_KOREAN 949

// typedef struct __attribute__((packed)) {
//     (optional) uint16_t locale
//     (optional) uint32_t parent_path_id
//     uint8_t name_data [extra_field->size - sizeof(locale) - sizeof(parent_path_id)]
// } filename_header;

/*
 * Extra field: comment
 *
 * The comment extra_field is followed by:
 *  1) comment of size "N", exclude NULL character.
 */
#define COMMENT_HEADER_MAGIC 0x04C63672
#define COMMENT_HEADER_FLAGS_ENCRYPT 0x04
#define COMMENT_HEADER_FLAGS_MULTIBYTE_CODEPAGE_INSTEAD_OF_UTF8 0x08

/*
 * Extra field: split compression
 */
#define SPLIT_COMPRESSION_MAGIC 0x24F5A262

typedef struct __attribute__((packed)) {
    uint32_t prev_file_id; /* ID of previous file, 0 if first */
    uint32_t next_file_id; /* ID of next file, 0 if last */
} split_compression;

/*
 * Extra field: solid compression
 */
#define SOLID_COMPRESSION_MAGIC 0x24E5A060

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

typedef struct {
    char* name_utf8;
    uint32_t parent_path_id;
} egg_filename;

typedef struct {
    size_t offset;
    size_t length;
    uint16_t codepage;
} egg_metadata_range;

typedef struct {
    encrypt_header* header; /* Global Encryption Header */
    union {
        aes_lea_128* al128;
        aes_lea_256* al256;
        zip2_xor_keybase* xor ;
    } encrypt_al;
} egg_encrypt;

typedef struct {
    block_header* blockHeader;
    size_t compressedDataOffset;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint8_t compressionAlgorithm;
} egg_block;

typedef struct {
    file_header* file;
    egg_filename filename;
    windows_file_information* windowsFileInformation;
    posix_file_information* posixFileInformation;
    egg_encrypt* encrypt;
    uint64_t nBlocks;
    egg_block** blocks;
    uint64_t nComments;
    char** comments;
} egg_file;

typedef struct {
    fmap_t* map;
    cli_ctx* ctx;
    size_t offset;
    uint64_t fileExtractionIndex;
    int bSolid; /* Solid == all files compressed together. */
    int bSplit; /* Split == multiple files make up single archive. */
    split_compression* splitInfo;
    egg_encrypt* encrypt;
    uint64_t nFiles;
    egg_file** files;
    uint64_t nBlocks;
    egg_block** blocks;
    uint64_t nComments;
    char** comments;
    uint64_t nMetadataRanges;
    egg_metadata_range* metadataRanges;
    uint64_t metadataRangesReserved;
} egg_handle;

static cl_error_t egg_checktimelimit(const egg_handle* handle)
{
    cl_error_t status;

    if (handle == NULL || handle->ctx == NULL)
        return CL_SUCCESS;

    status = cli_checktimelimit(handle->ctx);
    if (status != CL_SUCCESS)
        cli_mark_scan_incomplete(handle->ctx, "EGG traversal reached the configured time limit");

    return status;
}

static cl_error_t egg_add_metadata_range(egg_handle* handle, size_t offset, size_t length,
                                         uint16_t codepage)
{
    egg_metadata_range* ranges;
    egg_metadata_range* range;
    size_t old_size;
    size_t new_size;
    uint64_t growth;
    cl_error_t status;

    if (handle == NULL || length == 0 || offset > handle->map->len ||
        length > handle->map->len - offset)
        return CL_EARG;
    if (handle->nMetadataRanges >= CLI_MAX_ALLOCATION / sizeof(*handle->metadataRanges))
        return CL_EMAXSIZE;

    old_size = sizeof(*handle->metadataRanges) * (size_t)handle->nMetadataRanges;
    new_size = sizeof(*handle->metadataRanges) * (size_t)(handle->nMetadataRanges + 1);
    growth   = (uint64_t)(new_size - old_size);

    if (handle->ctx != NULL) {
        status = cli_scan_reserve_contiguous(handle->ctx, growth);
        if (status != CL_SUCCESS)
            return status;
    }

    ranges = cli_max_realloc(handle->metadataRanges,
                             new_size);
    if (ranges == NULL) {
        if (handle->ctx != NULL)
            cli_scan_release_contiguous(handle->ctx, growth);
        return CL_EMEM;
    }
    handle->metadataRanges = ranges;
    handle->metadataRangesReserved += growth;

    range           = &handle->metadataRanges[handle->nMetadataRanges++];
    range->offset   = offset;
    range->length   = length;
    range->codepage = codepage;
    return CL_SUCCESS;
}

static const uint8_t* egg_read_range(egg_handle* handle, size_t offset, size_t length, cl_error_t* status,
                                     const char* truncated_reason, const char* read_failure_reason)
{
    const uint8_t* data;

    if (handle == NULL || handle->map == NULL || length == 0 || offset > handle->map->len ||
        length > handle->map->len - offset) {
        if (status != NULL)
            *status = CL_EPARSE;
        if (handle != NULL && handle->ctx != NULL)
            cli_mark_scan_incomplete(handle->ctx, truncated_reason);
        return NULL;
    }

    data = (const uint8_t*)fmap_need_off_once(handle->map, offset, length);
    if (data == NULL) {
        if (status != NULL)
            *status = CL_EREAD;
        if (handle->ctx != NULL)
            cli_mark_scan_incomplete(handle->ctx, read_failure_reason);
        return NULL;
    }

    if (status != NULL)
        *status = CL_SUCCESS;
    return data;
}

static const uint8_t* egg_read_fixed_range(egg_handle* handle, size_t offset, size_t length, cl_error_t* status)
{
    return egg_read_range(handle, offset, length, status,
                          "EGG fixed metadata is truncated",
                          "EGG fixed metadata could not be read completely");
}

static const uint8_t* egg_read_extra_range(egg_handle* handle, size_t offset, size_t length, cl_error_t* status)
{
    return egg_read_range(handle, offset, length, status,
                          "EGG extra-field data is truncated",
                          "EGG extra-field data could not be read completely");
}

static bool egg_extra_span_present(egg_handle* handle, size_t offset, size_t length, cl_error_t* status)
{
    if (handle == NULL || handle->map == NULL || offset > handle->map->len ||
        length > handle->map->len - offset) {
        if (status != NULL)
            *status = CL_EPARSE;
        if (handle != NULL && handle->ctx != NULL)
            cli_mark_scan_incomplete(handle->ctx, "EGG extra-field data is truncated");
        return false;
    }

    if (status != NULL)
        *status = CL_SUCCESS;
    return true;
}

#define EGG_VALIDATE_HANDLE(h) \
    ((!handle || !handle->map || (handle->offset > handle->map->len)) ? CL_EARG : CL_SUCCESS)

const char* getEncryptName(uint8_t method)
{
    const char* encryptName = NULL;

    switch (method) {
        case ENCRYPT_HEADER_ENCRYPT_METHOD_XOR:
            encryptName = "XOR";
            break;
        case ENCRYPT_HEADER_ENCRYPT_METHOD_AES128:
            encryptName = "AES 128";
            break;
        case ENCRYPT_HEADER_ENCRYPT_METHOD_LEA128:
            encryptName = "LEA 128";
            break;
        case ENCRYPT_HEADER_ENCRYPT_METHOD_AES256:
            encryptName = "AES 256";
            break;
        case ENCRYPT_HEADER_ENCRYPT_METHOD_LEA256:
            encryptName = "LEA 256";
            break;
        default:
            encryptName = "<unknown method>";
    }

    return encryptName;
}

const char* getMagicHeaderName(uint32_t magic)
{
    const char* magicName = NULL;

    switch (magic) {
        case EGG_HEADER_MAGIC:
            magicName = "EGG_HEADER_MAGIC";
            break;
        case FILE_HEADER_MAGIC:
            magicName = "FILE_HEADER_MAGIC";
            break;
        case BLOCK_HEADER_MAGIC:
            magicName = "BLOCK_HEADER_MAGIC";
            break;
        case ENCRYPT_HEADER_MAGIC:
            magicName = "ENCRYPT_HEADER_MAGIC";
            break;
        case WINDOWS_INFO_MAGIC:
            magicName = "WINDOWS_INFO_MAGIC";
            break;
        case POSIX_INFO_MAGIC:
            magicName = "POSIX_INFO_MAGIC";
            break;
        case DUMMY_HEADER_MAGIC:
            magicName = "DUMMY_HEADER_MAGIC";
            break;
        case FILENAME_HEADER_MAGIC:
            magicName = "FILENAME_HEADER_MAGIC";
            break;
        case COMMENT_HEADER_MAGIC:
            magicName = "COMMENT_HEADER_MAGIC";
            break;
        case SPLIT_COMPRESSION_MAGIC:
            magicName = "SPLIT_COMPRESSION_MAGIC";
            break;
        case SOLID_COMPRESSION_MAGIC:
            magicName = "SOLID_COMPRESSION_MAGIC";
            break;
        default:
            magicName = "<unknown header magic>";
    }

    return magicName;
}

static void egg_free_encrypt(egg_encrypt* encryptInfo)
{
    free(encryptInfo);
}

static cl_error_t egg_parse_encrypt_header(const uint8_t* index, size_t size, egg_encrypt** encryptInfo)
{
    /*
     * The EGG specification (last updated 2016) for the encrypt header is not accurate.
     * The following describes my findings of the actual format for the encrypt header.
     *
     * The significant discrepancy is that the Size includes the size of the header itself, not just the data following it.
     * No other extra_field header's size field includes the size of itself.
     * This must be accounted for by the caller of this function (see the "Fudge factor" comments where this function is used).
     *
     *     |---------------|---------|------------------------------------------------------------------------------------------------------------|
     *     | Magic(ENCRYP) |    4    |    0x08D1470F                                                                                              |
     *     |---------------|---------|------------------------------------------------------------------------------------------------------------|
     *     | Bit flag      |    1    |    0                                                                                                       |
     *     |---------------|---------|------------------------------------------------------------------------------------------------------------|
     *     | Size          |    2    | sizeof( Magic ) + sizeof( Bit flag ) + sizeof( Size ) + sizeof( Encrypt Method ) + sizeof( Method Header ) |
     *     |---------------|---------|---|--------------------------------------------------------------------------------------------------------|
     *     | Encrypt       |    1    | 0 | KeyBase (XOR)                                                                                          |
     *     | Method        |         |---|--------------------------------------------------------------------------------------------------------|
     *     |               |         | 1 | AES128                                                                                                 |
     *     |               |         |---|--------------------------------------------------------------------------------------------------------|
     *     |               |         | 2 | AES256                                                                                                 |
     *     |               |         |---|--------------------------------------------------------------------------------------------------------|
     *     |               |         | 5 | LEA128                                                                                                 |
     *     |               |         |---|--------------------------------------------------------------------------------------------------------|
     *     |               |         | 6 | LEA256                                                                                                 |
     *     |---------------|---------|---|--------------------------------------------------------------------------------------------------------|
     *
     * Depending on the Method (XOR / AES/LEA128 / AES/LEA256) The above will be followed by one of the following Method Headers:
     *
     *   XOR (KeyBase):
     *     |---------------|---------|------------------------------------------------------------------------------------------------------------|
     *     | verify Data   |   12    |   Encryption Verification Data                                                                             |
     *     |---------------|---------|------------------------------------------------------------------------------------------------------------|
     *     | CRC32         |    4    |   Partial Block CRC                                                                                        |
     *     |---------------|---------|------------------------------------------------------------------------------------------------------------|
     *
     *   AES / LEA 128
     *     |---------------|---------|------------------------------------------------------------------------------------------------------------|
     *     | Magic(ENCRYP) |   10    |   AES/LEA Header                                                                                           |
     *     |---------------|---------|------------------------------------------------------------------------------------------------------------|
     *     | Magic(ENCRYP) |   10    |   AES/LEA Footer                                                                                           |
     *     |---------------|---------|------------------------------------------------------------------------------------------------------------|
     *
     *   AES / LEA 256
     *     |---------------|---------|------------------------------------------------------------------------------------------------------------|
     *     | Magic(ENCRYP) |   18    |   AES/LEA Header                                                                                           |
     *     |---------------|---------|------------------------------------------------------------------------------------------------------------|
     *     | Magic(ENCRYP) |   10    |   AES/LEA Footer                                                                                           |
     *     |---------------|---------|------------------------------------------------------------------------------------------------------------|
     */
    cl_error_t status    = CL_EPARSE;
    egg_encrypt* encrypt = NULL;

    if (!index || 0 == size || !encryptInfo) {
        cli_errmsg("egg_parse_encrypt_header: Invalid args.\n");
        status = CL_EARG;
        goto done;
    }

    *encryptInfo = NULL;

    cli_dbgmsg("egg_parse_encrypt_header: Encrypted archive.\n");
    cli_dbgmsg("egg_parse_encrypt_header: size of encrypt extra_field data: %zu\n", size);

    if (size < sizeof(encrypt_header)) {
        cli_warnmsg("egg_parse_encrypt_header: Encrypt header size too small (%zu < %zu)\n", size, sizeof(encrypt_header));
        goto done;
    }

    encrypt = (egg_encrypt*)calloc(1, sizeof(egg_encrypt));
    if (NULL == encrypt) {
        cli_errmsg("egg_parse_encrypt_header: Failed to allocate memory for egg_encrypt.\n");
        status = CL_EMEM;
        goto done;
    }

    encrypt->header = (encrypt_header*)index;

    cli_dbgmsg("egg_parse_encrypt_header: encrypt_header->encrypt_method: %02x (%s)\n", encrypt->header->encrypt_method, getEncryptName(encrypt->header->encrypt_method));

    index += sizeof(encrypt_header);
    size -= sizeof(encrypt_header);

    if (ENCRYPT_HEADER_ENCRYPT_METHOD_XOR == encrypt->header->encrypt_method) {
        if (size != sizeof(zip2_xor_keybase)) {
            cli_warnmsg("egg_parse_encrypt_header: Encrypt header size for XOR is different than expected (%zu != %zu)\n", size, sizeof(zip2_xor_keybase));
            goto done;
        }

        encrypt->encrypt_al.xor = (zip2_xor_keybase*)index;

        cli_dbgmsg("egg_parse_encrypt_header: encrypt_header->crc32:          %08x\n", le32_to_host(encrypt->encrypt_al.xor->crc32));
    } else {
        /*
         * For AES/LEA, the additional information is found inside of embedded extra field.
         */
        switch (encrypt->header->encrypt_method) {
            case ENCRYPT_HEADER_ENCRYPT_METHOD_AES128:
            case ENCRYPT_HEADER_ENCRYPT_METHOD_LEA128: {
                if (size < sizeof(aes_lea_128)) {
                    cli_warnmsg("egg_parse_encrypt_header: Encrypt header size for AES/LEA128 is different than expected (%zu != %zu)\n", size, sizeof(aes_lea_128));
                    goto done;
                }

                encrypt->encrypt_al.al128 = (aes_lea_128*)index;

                index += sizeof(aes_lea_128);
                size -= sizeof(aes_lea_128);
                break;
            }
            case ENCRYPT_HEADER_ENCRYPT_METHOD_AES256:
            case ENCRYPT_HEADER_ENCRYPT_METHOD_LEA256: {
                if (size < sizeof(aes_lea_256)) {
                    cli_warnmsg("egg_parse_encrypt_header: Encrypt header size for AES/LEA256 is different than expected (%zu != %zu)\n", size, sizeof(aes_lea_256));
                    goto done;
                }

                encrypt->encrypt_al.al256 = (aes_lea_256*)index;

                index += sizeof(aes_lea_256);
                size -= sizeof(aes_lea_256);
                break;
            }
            default: {
                cli_warnmsg("egg_parse_encrypt_header: Unknown encrypt method: %d\n", encrypt->header->encrypt_method);
                goto done;
            }
        }
    }

    *encryptInfo = encrypt;
    encrypt      = NULL;

    status = CL_SUCCESS;

done:
    if (NULL != encrypt) {
        egg_free_encrypt(encrypt);
    }

    return status;
}

static cl_error_t egg_parse_encrypt_header_bounded(egg_handle* handle, size_t offset, size_t size,
                                                   egg_encrypt** encryptInfo)
{
    const uint8_t* index;
    const encrypt_header* header;
    size_t required;
    cl_error_t status = CL_EPARSE;

    if (handle == NULL || encryptInfo == NULL || size < sizeof(encrypt_header))
        return CL_EPARSE;
    if (!egg_extra_span_present(handle, offset, size, &status))
        return status;

    index = egg_read_extra_range(handle, offset, sizeof(encrypt_header), &status);
    if (index == NULL)
        return status;

    header   = (const encrypt_header*)index;
    required = sizeof(encrypt_header);
    switch (header->encrypt_method) {
        case ENCRYPT_HEADER_ENCRYPT_METHOD_XOR:
            required += sizeof(zip2_xor_keybase);
            if (size != required)
                return CL_EPARSE;
            break;
        case ENCRYPT_HEADER_ENCRYPT_METHOD_AES128:
        case ENCRYPT_HEADER_ENCRYPT_METHOD_LEA128:
            required += sizeof(aes_lea_128);
            if (size < required)
                return CL_EPARSE;
            break;
        case ENCRYPT_HEADER_ENCRYPT_METHOD_AES256:
        case ENCRYPT_HEADER_ENCRYPT_METHOD_LEA256:
            required += sizeof(aes_lea_256);
            if (size < required)
                return CL_EPARSE;
            break;
        default:
            break;
    }

    index = egg_read_extra_range(handle, offset, required, &status);
    if (index == NULL)
        return status;
    return egg_parse_encrypt_header(index, size, encryptInfo);
}

static cl_error_t egg_parse_comment_header(const uint8_t* index, size_t size, extra_field* extraField, char** commentInfo)
{
    cl_error_t status = CL_EPARSE;

    char* comment_utf8       = NULL;
    size_t comment_utf8_size = 0;

    if (!index || 0 == size || !extraField || !commentInfo) {
        cli_errmsg("egg_parse_comment_headers: Invalid args!\n");
        return CL_EARG;
    }

    *commentInfo = NULL;

    if (extraField->bit_flag & COMMENT_HEADER_FLAGS_ENCRYPT) {
        /*
         * comment is encrypted, nothing to be done.
         */
        status = CL_EUNPACK;
        goto done;
    }

    /*
     * Store comment as UTF-8 string.
     */
    if (extraField->bit_flag & COMMENT_HEADER_FLAGS_MULTIBYTE_CODEPAGE_INSTEAD_OF_UTF8) {
        /*
         * Unlike with filenames, the multibyte string codepage (or "locale") is not present in comment headers.
         * Try conversion with CODEPAGE_UTF8.
         */
        if (CL_SUCCESS != cli_codepage_to_utf8((char*)index, size, CODEPAGE_UTF8, &comment_utf8, &comment_utf8_size)) {
            cli_dbgmsg("egg_parse_comment_header: failed to convert codepage \"0\" to UTF-8\n");
            status = CL_EUNPACK;
            goto done;
        }
    } else {
        /* Should already be UTF-8. Use as-is.. */
        comment_utf8 = CLI_STRNDUP((char*)index, size);
        if (NULL == comment_utf8) {
            cli_dbgmsg("egg_parse_comment_header: failed to allocate comment buffer.\n");
            status = CL_EMEM;
            goto done;
        }
    }
    cli_dbgmsg("egg_parse_comment_header: comment:          %s\n", comment_utf8);

    *commentInfo = comment_utf8;
    comment_utf8 = NULL;

    status = CL_SUCCESS;

done:
    if (NULL != comment_utf8) {
        free(comment_utf8);
    }

    return status;
}

static void egg_free_egg_block(egg_block* block)
{
    free(block);
}

static cl_error_t egg_parse_block_headers(egg_handle* handle, egg_block** block)
{
    cl_error_t status = CL_EPARSE;

    egg_block* eggBlock       = NULL;
    block_header* blockHeader = NULL;
    uint32_t magic            = 0;
    const uint8_t* index      = 0;

    if (!handle || !block) {
        cli_errmsg("egg_parse_block_headers: Invalid args!\n");
        return CL_EARG;
    }

    *block = NULL;

    if (CL_SUCCESS != EGG_VALIDATE_HANDLE(handle)) {
        cli_errmsg("egg_parse_block_headers: Invalid handle values!\n");
        status = CL_EARG;
        goto done;
    }

    /*
     * 1st:
     *   Block headers must start with the block_header.
     */
    index = egg_read_fixed_range(handle, handle->offset, sizeof(block_header), &status);
    if (!index) {
        cli_dbgmsg("egg_parse_block_headers: File buffer too small to contain block header.\n");
        goto done;
    }

    eggBlock = (egg_block*)calloc(1, sizeof(egg_block));
    if (NULL == eggBlock) {
        cli_errmsg("egg_parse_block_headers: Failed to allocate memory for egg_block.\n");
        status = CL_EMEM;
        goto done;
    }

    blockHeader           = (block_header*)index;
    eggBlock->blockHeader = blockHeader;

    if (BLOCK_HEADER_MAGIC != le32_to_host(blockHeader->magic)) {
        cli_dbgmsg("egg_parse_block_headers: Invalid block header magic: %08x.\n", le32_to_host(blockHeader->magic));
        goto done;
    }

    cli_dbgmsg("egg_parse_block_headers: block_header->magic:              %08x (%s)\n", le32_to_host(blockHeader->magic), getMagicHeaderName(le32_to_host(blockHeader->magic)));
    cli_dbgmsg("egg_parse_block_headers: block_header->compress_algorithm: %08x\n", blockHeader->compress_algorithm);
    cli_dbgmsg("egg_parse_block_headers: block_header->compress_hint:      %08x\n", blockHeader->compress_hint);
    cli_dbgmsg("egg_parse_block_headers: block_header->uncompress_size:    %08x\n", le32_to_host(blockHeader->uncompress_size));
    cli_dbgmsg("egg_parse_block_headers: block_header->compress_size:      %08x\n", le32_to_host(blockHeader->compress_size));
    cli_dbgmsg("egg_parse_block_headers: block_header->crc32:              %08x\n", le32_to_host(blockHeader->crc32));

    eggBlock->compressionAlgorithm = blockHeader->compress_algorithm;
    eggBlock->compressedSize       = le32_to_host(blockHeader->compress_size);
    eggBlock->uncompressedSize     = le32_to_host(blockHeader->uncompress_size);

    if (0 == eggBlock->compressedSize) {
        cli_warnmsg("egg_parse_block_headers: Empty block!\n");
    }

    handle->offset += sizeof(block_header);

    /*
     * 2nd:
     *   After the block_header, the following extra field headers may be present:
     *      a) EOFARC
     */

    index = egg_read_fixed_range(handle, handle->offset, sizeof(magic32_t), &status);
    if (!index) {
        cli_dbgmsg("egg_parse_block_headers: File buffer too small to contain end of archive magic bytes.\n");
        goto done;
    }

    magic = (uint32_t)cli_readint32(index);
    if (EOFARC != magic) {
        cli_dbgmsg("egg_parse_block_headers: EOFARC missing after block header.  Found these bytes instead: %08x. (%s)\n", magic, getMagicHeaderName(magic));
        goto done;
    }
    cli_dbgmsg("egg_parse_block_headers: End of block header.\n");
    handle->offset += sizeof(magic32_t);

    /*
     * Compressed data should follow the Block Header.
     */
    if (handle->offset > handle->map->len || eggBlock->compressedSize > handle->map->len - handle->offset) {
        cli_dbgmsg("egg_parse_block_headers: File buffer too small to contain block compressed data.\n");
        goto done;
    }
    eggBlock->compressedDataOffset = handle->offset;
    handle->offset += eggBlock->compressedSize;

    *block   = eggBlock;
    eggBlock = NULL;

    status = CL_SUCCESS;

done:
    if (NULL != eggBlock) {
        egg_free_egg_block(eggBlock);
    }

    return status;
}

static void egg_free_egg_file(egg_file* file)
{
    uint32_t i = 0;

    if (NULL != file->filename.name_utf8) {
        free(file->filename.name_utf8);
        file->filename.name_utf8 = NULL;
    }
    if (NULL != file->encrypt) {
        free(file->encrypt);
        file->encrypt = NULL;
    }
    if (NULL != file->blocks) {
        for (i = 0; i < file->nBlocks; i++) {
            egg_free_egg_block(file->blocks[i]);
            file->blocks[i] = NULL;
        }
        free(file->blocks);
        file->blocks = NULL;
    }
    if (NULL != file->comments) {
        for (i = 0; i < file->nComments; i++) {
            free(file->comments[i]);
            file->comments[i] = NULL;
        }
        free(file->comments);
        file->comments = NULL;
    }

    free(file);
}

static cl_error_t egg_parse_archive_extra_field(egg_handle* handle)
{
    cl_error_t status = CL_EPARSE;

    const uint8_t* index    = NULL;
    extra_field extraFieldStorage;
    extra_field* extraField = NULL;
    uint32_t magic          = 0;
    uint32_t size           = 0;
    size_t size_field_size  = 0;
    size_t payload_offset   = 0;
    size_t payload_size     = 0;

    if (!handle) {
        cli_errmsg("egg_parse_archive_extra_field: Invalid args!\n");
        return CL_EARG;
    }

    if (CL_SUCCESS != EGG_VALIDATE_HANDLE(handle)) {
        cli_errmsg("egg_parse_comment_headers: Invalid handle values!\n");
        status = CL_EARG;
        goto done;
    }

    index = egg_read_extra_range(handle, handle->offset, sizeof(extra_field), &status);
    if (!index) {
        cli_dbgmsg("egg_parse_archive_extra_field: File buffer too small to contain extra_field header.\n");
        goto done;
    }

    memcpy(&extraFieldStorage, index, sizeof(extraFieldStorage));
    extraField = &extraFieldStorage;

    cli_dbgmsg("egg_parse_archive_extra_field: extra_field->magic:    %08x (%s)\n", le32_to_host(extraField->magic), getMagicHeaderName(le32_to_host(extraField->magic)));
    cli_dbgmsg("egg_parse_archive_extra_field: extra_field->bit_flag: %02x\n", extraField->bit_flag);

    handle->offset += sizeof(extra_field);

    if (extraField->bit_flag & EXTRA_FIELD_FLAGS_SIZE_IS_4BYTES) {
        /* size is uint32_t */
        index = egg_read_extra_range(handle, handle->offset, sizeof(uint32_t), &status);
        if (!index) {
            cli_dbgmsg("egg_parse_archive_extra_field: File buffer too small to contain extra_field header.\n");
            goto done;
        }

        size = (uint32_t)cli_readint32(index);

        handle->offset += sizeof(uint32_t);
        size_field_size = sizeof(uint32_t);
    } else {
        /* size is uint16_t */
        index = egg_read_extra_range(handle, handle->offset, sizeof(uint16_t), &status);
        if (!index) {
            cli_dbgmsg("egg_parse_archive_extra_field: File buffer too small to contain extra_field header.\n");
            goto done;
        }

        size = (uint16_t)cli_readint16(index);

        handle->offset += sizeof(uint16_t);
        size_field_size = sizeof(uint16_t);
    }

    cli_dbgmsg("egg_parse_archive_extra_field: extra_field->size:     %u\n", size);

    magic          = le32_to_host(extraField->magic);
    payload_offset = handle->offset;
    payload_size   = size;
    if (magic == ENCRYPT_HEADER_MAGIC) {
        size_t header_size = sizeof(extra_field) + size_field_size;

        if (payload_size < header_size) {
            cli_warnmsg("egg_parse_archive_extra_field: encryption header size underflow\n");
            status = CL_EFORMAT;
            goto done;
        }
        payload_size -= header_size;
    }
    if (!egg_extra_span_present(handle, payload_offset, payload_size, &status))
        goto done;

    status = CL_EFORMAT;
    switch (magic) {
        case SOLID_COMPRESSION_MAGIC: {
            /*
             * Solid archive is an archive packed with a special compression method,
             * which treats several or all files within the archive as one continuous data stream.
             */
            cli_dbgmsg("egg_parse_archive_extra_field: Solid archive. Several or all files within the archive treated as one continuous data stream.\n");

            if (0 != handle->bSolid) {
                cli_warnmsg("egg_parse_archive_extra_field: Encountered more than 1 Solid extra_field!\n");
                goto done;
            }
            handle->bSolid = 1;
            break;
        }
        case SPLIT_COMPRESSION_MAGIC: {
            /*
             * Split archives are single archives split into multiple .egg volumes.
             *
             * It is the first file if previous file’s ID is 0, and is the last file
             * if next file’s ID is 0.
             *
             * Header and Extra Field shouldn’t be cut when split compressing.
             * Compressed Block Data can be saved cut.
             * If header is excluded from the split size, insert Dummy Extra Field.
             *
             * If file compression ratio not applied when split compressing, modify
             * Magic of the header into Dummy Header or Skip Header (0xFFFF0000)
             * so it can be skipped.
             */
            split_compression* split = NULL;

            if (0 != handle->bSplit) {
                cli_warnmsg("egg_parse_archive_extra_field: Encountered more than 1 Split extra_field!\n");
                goto done;
            }
            handle->bSplit = 1;
            cli_warnmsg("egg_parse_archive_extra_field: Split archive. Split archives are single archives split into multiple .egg volumes.\n");

            if (sizeof(split_compression) != payload_size) {
                cli_dbgmsg("egg_parse_archive_extra_field: size in extra_field is different than size of split_compression (%zu != %zu).\n", sizeof(split_compression), payload_size);
            } else {
                index = egg_read_extra_range(handle, payload_offset, sizeof(split_compression), &status);
                if (!index) {
                    cli_dbgmsg("egg_parse_archive_extra_field: File buffer too small to contain split compression header.\n");
                    goto done;
                }

                split = (split_compression*)index;

                handle->splitInfo = split;

                cli_dbgmsg("egg_parse_archive_extra_field: split_compression->prev_file_id: %08x\n", le32_to_host(split->prev_file_id));
                cli_dbgmsg("egg_parse_archive_extra_field: split_compression->next_file_id: %08x\n", le32_to_host(split->next_file_id));
            }
            break;
        }
        case ENCRYPT_HEADER_MAGIC: {
            /*
             * EGG files may have a global encryption header.
             * It is unclear if this means each file is encrypted, or that additional
             * data beyond the file contents is encrypted.
             */
            if (NULL != handle->encrypt) {
                cli_warnmsg("egg_parse_archive_extra_field: Encountered more than 1 encrypt_header!\n");
                goto done;
            }

            if (CL_SUCCESS != (status = egg_parse_encrypt_header_bounded(handle, payload_offset,
                                                                         payload_size, &handle->encrypt))) {
                cli_errmsg("egg_parse_archive_extra_field: Failed to parse encryption headers.\n");
                goto done;
            }
            break;
        }
        default: {
            cli_dbgmsg("egg_parse_archive_extra_field: unexpected header magic:    %08x (%s)\n", magic, getMagicHeaderName(magic));
        }
    }

    handle->offset = payload_offset + payload_size;

    status = CL_SUCCESS;

done:

    return status;
}

static void print_posix_info_mode(uint32_t mode)
{
    /* File type flags */
    if (mode & POSIX_INFO_MODE_REG_FILE) {
        printf("-");
    } else if (mode & POSIX_INFO_MODE_DIRECTORY) {
        printf("d");
    } else if (mode & POSIX_INFO_MODE_CHAR_DEVICE) {
        printf("c");
    } else if (mode & POSIX_INFO_MODE_BLOCK_DEVICE) {
        printf("s");
    } else if (mode & POSIX_INFO_MODE_SOCKET) {
        printf("s");
    } else if (mode & POSIX_INFO_MODE_FIFO) {
        printf("p");
    } else if (mode & POSIX_INFO_MODE_SYM_LINK) {
        printf("l");
    }
    /* Owner/Group/Other permissions */
    if (mode & POSIX_INFO_MODE_PERM_OWNER_READ) {
        printf("r");
    } else {
        printf("-");
    }
    if (mode & POSIX_INFO_MODE_PERM_OWNER_WRITE) {
        printf("w");
    } else {
        printf("-");
    }
    if (mode & POSIX_INFO_MODE_SET_UID_BIT) {
        printf("s");
    } else if (mode & POSIX_INFO_MODE_PERM_OWNER_EXECUTE) {
        printf("x");
    } else {
        printf("-");
    }
    if (mode & POSIX_INFO_MODE_PERM_GROUP_READ) {
        printf("r");
    } else {
        printf("-");
    }
    if (mode & POSIX_INFO_MODE_PERM_GROUP_WRITE) {
        printf("w");
    } else {
        printf("-");
    }
    if (mode & POSIX_INFO_MODE_SET_UID_BIT) {
        printf("s");
    }
    if (mode & POSIX_INFO_MODE_SET_GROUPID_BIT) {
        printf("s");
    }
    if (mode & POSIX_INFO_MODE_PERM_GROUP_EXECUTE) {
        printf("x");
    } else {
        printf("-");
    }
    if (mode & POSIX_INFO_MODE_PERM_OTHERS_READ) {
        printf("r");
    } else {
        printf("-");
    }
    if (mode & POSIX_INFO_MODE_PERM_OTHERS_WRITE) {
        printf("w");
    } else {
        printf("-");
    }
    if (mode & POSIX_INFO_MODE_PERM_OTHERS_EXECUTE) {
        printf("x");
    } else {
        printf("-");
    }
    /* Sticky Bit */
    if (mode & POSIX_INFO_MODE_STICKY_BIT)
        printf("t");
    printf("\n");
}

static cl_error_t egg_parse_file_extra_field(egg_handle* handle, egg_file* eggFile)
{
    cl_error_t status = CL_EPARSE;

    const uint8_t* index     = NULL;
    extra_field extraFieldStorage;
    extra_field* extraField  = NULL;
    uint32_t magic           = 0;
    uint32_t size            = 0;
    size_t size_field_size   = 0;
    size_t payload_offset    = 0;
    size_t payload_size      = 0;

    if (!handle || !eggFile) {
        cli_errmsg("egg_parse_file_extra_field: Invalid args!\n");
        return CL_EARG;
    }

    if (CL_SUCCESS != EGG_VALIDATE_HANDLE(handle)) {
        cli_errmsg("egg_parse_file_extra_field: Invalid handle values!\n");
        status = CL_EARG;
        goto done;
    }

    index = egg_read_extra_range(handle, handle->offset, sizeof(extra_field), &status);
    if (!index) {
        cli_dbgmsg("egg_parse_file_extra_field: File buffer too small to contain extra_field header.\n");
        goto done;
    }

    memcpy(&extraFieldStorage, index, sizeof(extraFieldStorage));
    extraField = &extraFieldStorage;

    cli_dbgmsg("egg_parse_file_extra_field: extra_field->magic:    %08x (%s)\n", le32_to_host(extraField->magic), getMagicHeaderName(le32_to_host(extraField->magic)));
    cli_dbgmsg("egg_parse_file_extra_field: extra_field->bit_flag: %02x\n", extraField->bit_flag);

    handle->offset += sizeof(extra_field);

    if (extraField->bit_flag & EXTRA_FIELD_FLAGS_SIZE_IS_4BYTES) {
        /* size is uint32_t */
        index = egg_read_extra_range(handle, handle->offset, sizeof(uint32_t), &status);
        if (!index) {
            cli_dbgmsg("egg_parse_file_extra_field: File buffer too small to contain extra_field header.\n");
            goto done;
        }

        size = (uint32_t)cli_readint32(index);

        handle->offset += sizeof(uint32_t);
        size_field_size = sizeof(uint32_t);
    } else {
        /* size is uint16_t */
        index = egg_read_extra_range(handle, handle->offset, sizeof(uint16_t), &status);
        if (!index) {
            cli_dbgmsg("egg_parse_file_extra_field: File buffer too small to contain extra_field header.\n");
            goto done;
        }

        size = (uint16_t)cli_readint16(index);

        handle->offset += sizeof(uint16_t);
        size_field_size = sizeof(uint16_t);
    }

    cli_dbgmsg("egg_parse_file_extra_field: extra_field->size:     %u\n", size);

    magic          = le32_to_host(extraField->magic);
    payload_offset = handle->offset;
    payload_size   = size;
    if (magic == ENCRYPT_HEADER_MAGIC) {
        size_t header_size = sizeof(extra_field) + size_field_size;

        if (payload_size < header_size) {
            cli_warnmsg("egg_parse_file_extra_field: encryption header size underflow\n");
            status = CL_EFORMAT;
            goto done;
        }
        payload_size -= header_size;
    }
    if (!egg_extra_span_present(handle, payload_offset, payload_size, &status))
        goto done;
    status = CL_EFORMAT;
    switch (magic) {
        case FILENAME_HEADER_MAGIC: {
            /*
             * File Filename Header
             */
            uint16_t codepage       = 0; /* Windows code page https://docs.microsoft.com/en-us/windows/desktop/Intl/code-page-identifiers) */
            size_t name_offset      = payload_offset;
            size_t name_size        = 0;
            size_t remaining_size   = payload_size;

            char* name_utf8       = NULL;
            size_t name_utf8_size = 0;

            if (NULL != eggFile->filename.name_utf8) {
                cli_warnmsg("egg_parse_file_extra_field: Encountered more than 1 filename_header!\n");
                goto done;
            }

            if (extraField->bit_flag & FILENAME_HEADER_FLAGS_ENCRYPT)
                cli_dbgmsg("egg_parse_file_extra_field: filename_header->bit_flag: encrypted\n");
            else
                cli_dbgmsg("egg_parse_file_extra_field: filename_header->bit_flag: not encrypted\n");

            if (extraField->bit_flag & FILENAME_HEADER_FLAGS_ENCRYPT) {
                if (handle->ctx != NULL)
                    cli_mark_scan_incomplete(handle->ctx, "EGG encrypted filename prevents metadata inspection");
                status = CL_EUNPACK;
                goto done;
            }

            if (extraField->bit_flag & FILENAME_HEADER_FLAGS_RELATIVE_PATH_INSTEAD_OF_ABSOLUTE)
                cli_dbgmsg("egg_parse_file_extra_field: filename_header->bit_flag: relative-path\n");
            else
                cli_dbgmsg("egg_parse_file_extra_field: filename_header->bit_flag: absolute-path\n");

            if (extraField->bit_flag & FILENAME_HEADER_FLAGS_MULTIBYTE_CODEPAGE_INSTEAD_OF_UTF8)
                cli_dbgmsg("egg_parse_file_extra_field: filename_header->bit_flag: Windows Multibyte + codepage\n");
            else
                cli_dbgmsg("egg_parse_file_extra_field: filename_header->bit_flag: UTF-8\n");

            if (extraField->bit_flag & FILENAME_HEADER_FLAGS_MULTIBYTE_CODEPAGE_INSTEAD_OF_UTF8) {
                /* Utf-8 - header will include locale */
                /* Check that the size is big enough */
                if (remaining_size < sizeof(uint16_t)) {
                    cli_dbgmsg("egg_parse_file_extra_field: size too small for locale information.\n");
                    goto done;
                }
                index = egg_read_extra_range(handle, name_offset, sizeof(uint16_t), &status);
                if (index == NULL)
                    goto done;
                codepage = (uint16_t)cli_readint16(index);
                cli_dbgmsg("egg_parse_file_extra_field: filename_header->codepage:       %u\n", codepage);
                name_offset += sizeof(uint16_t);
                remaining_size -= sizeof(uint16_t);
            }

            if (extraField->bit_flag & FILENAME_HEADER_FLAGS_RELATIVE_PATH_INSTEAD_OF_ABSOLUTE) {
                /* header will include parent_path_id */
                /* Check that the size is big enough */
                if (remaining_size < sizeof(uint32_t)) {
                    cli_dbgmsg("egg_parse_file_extra_field: size too small for parent_path_id.\n");
                    goto done;
                }
                index = egg_read_extra_range(handle, name_offset, sizeof(uint32_t), &status);
                if (index == NULL)
                    goto done;
                eggFile->filename.parent_path_id = (uint32_t)cli_readint32(index);
                cli_dbgmsg("egg_parse_file_extra_field: filename_header->parent_path_id: %u\n", eggFile->filename.parent_path_id);
                name_offset += sizeof(uint32_t);
                remaining_size -= sizeof(uint32_t);
            }

            if (remaining_size == 0) {
                cli_dbgmsg("egg_parse_file_extra_field: size too small for name string.\n");
                goto done;
            }
            name_size = remaining_size;

            if (0 == codepage)
                codepage = CODEPAGE_UTF8;
            status = egg_add_metadata_range(handle, name_offset, name_size, codepage);
            if (status != CL_SUCCESS)
                goto done;

            if (name_size > CLI_MAX_ALLOCATION) {
                if (handle->ctx == NULL) {
                    cli_warnmsg("egg_parse_file_extra_field: filename exceeds legacy string-metadata limit\n");
                    status = CL_EMAXSIZE;
                    goto done;
                }

                eggFile->filename.name_utf8 = cli_genfname(NULL);
                if (eggFile->filename.name_utf8 == NULL) {
                    status = CL_EMEM;
                    goto done;
                }
                cli_dbgmsg("egg_parse_file_extra_field: retained bounded generated name for oversized filename metadata\n");
                break;
            }

            index = egg_read_extra_range(handle, name_offset, name_size, &status);
            if (!index) {
                cli_dbgmsg("egg_parse_file_extra_field: File buffer too small to contain name string.\n");
                goto done;
            }

            /*
             * Store name as UTF-8 string.
             */
            if (extraField->bit_flag & FILENAME_HEADER_FLAGS_MULTIBYTE_CODEPAGE_INSTEAD_OF_UTF8) {
                /* Convert ANSI codepage to UTF-8. EGG format explicitly supports:
                 * - 949 (Korean Unified Code)
                 * - 932 (Japanese Shift-JIS) */
                if (CL_SUCCESS != cli_codepage_to_utf8((char*)index, name_size, codepage, &name_utf8, &name_utf8_size)) {
                    cli_dbgmsg("egg_parse_file_extra_field: failed to convert codepage %u to UTF-8\n", codepage);
                    name_utf8 = cli_genfname(NULL);
                }
            } else {
                /* Should already be UTF-8. Use as-is.. */
                name_utf8 = CLI_STRNDUP((char*)index, name_size);
                if (NULL == name_utf8) {
                    cli_dbgmsg("egg_parse_file_extra_field: failed to allocate name buffer.\n");
                    status = CL_EMEM;
                    goto done;
                }
            }
            eggFile->filename.name_utf8 = name_utf8;

            cli_dbgmsg("egg_parse_file_extra_field: filename_header->name: %s\n", eggFile->filename.name_utf8);

            break;
        }
        case COMMENT_HEADER_MAGIC: {
            /*
             * File Comment Header
             */
            cl_error_t retval = CL_EPARSE;
            char* comment     = NULL;

            if (extraField->bit_flag & COMMENT_HEADER_FLAGS_ENCRYPT) {
                if (handle->ctx != NULL)
                    cli_mark_scan_incomplete(handle->ctx, "EGG encrypted file comment prevents metadata inspection");
                status = CL_EUNPACK;
                goto done;
            }

            status = egg_add_metadata_range(handle, payload_offset, payload_size, CODEPAGE_UTF8);
            if (status != CL_SUCCESS)
                goto done;

            if (handle->ctx != NULL && payload_size > CLI_MAX_ALLOCATION)
                break;
            if (payload_size > CLI_MAX_ALLOCATION) {
                cli_warnmsg("egg_parse_file_extra_field: file comment exceeds legacy string-metadata limit\n");
                status = CL_EMAXSIZE;
                goto done;
            }

            index = egg_read_extra_range(handle, payload_offset, payload_size, &status);
            if (!index) {
                cli_dbgmsg("egg_parse_file_extra_field: File buffer too small to contain comment fields.\n");
                goto done;
            }

            if (CL_SUCCESS != (retval = egg_parse_comment_header(index, payload_size, extraField, &comment))) {
                cli_dbgmsg("egg_parse_file_extra_field: Issue parsing comment header. Error code: %u\n", retval);
                status = retval;
                goto done;
            } else if (comment == NULL) {
                cli_errmsg("egg_parse_file_extra_field: Logic error! Successfully parsed comment header,"
                           " but did not return egg_comment information!\n");
                goto done;
            } else {
                /*
                 * Comment found. Add comment to our list.
                 */
                if (eggFile->nComments >= CLI_MAX_ALLOCATION / sizeof(char*)) {
                    free(comment);
                    status = CL_EMAXSIZE;
                    goto done;
                }
                CLI_MAX_REALLOC_OR_GOTO_DONE(eggFile->comments,
                                             sizeof(char*) * (size_t)(eggFile->nComments + 1),
                                             free(comment),
                                             status = CL_EMEM);
                eggFile->comments[eggFile->nComments] = comment;
                eggFile->nComments++;
            }
            break;
        }
        case ENCRYPT_HEADER_MAGIC: {
            /*
             * File Encryption Header.
             */
            if (NULL != eggFile->encrypt) {
                cli_warnmsg("egg_parse_file_extra_field: Encountered more than 1 encrypt_header!\n");
                goto done;
            }

            if (CL_SUCCESS != (status = egg_parse_encrypt_header_bounded(handle, payload_offset,
                                                                         payload_size, &eggFile->encrypt))) {
                cli_errmsg("egg_parse_file_extra_field: Failed to parse encrypt_header.\n");
                goto done;
            }
            break;
        }
        case WINDOWS_INFO_MAGIC: {
            windows_file_information* windowsFileInformation = NULL;

            if (NULL != eggFile->windowsFileInformation) {
                cli_warnmsg("egg_parse_file_extra_field: Encountered more than 1 windows_file_information!\n");
                goto done;
            }

            if (payload_size < sizeof(windows_file_information)) {
                cli_warnmsg("egg_parse_file_extra_field: windows_file_information is truncated by its declared size!\n");
                status = CL_EFORMAT;
                goto done;
            }
            if (sizeof(windows_file_information) != payload_size) {
                cli_warnmsg("egg_parse_file_extra_field: Invalid size of windows_file_information!\n");
            }

            index = egg_read_extra_range(handle, payload_offset, sizeof(windows_file_information), &status);
            if (!index) {
                cli_dbgmsg("egg_parse_file_extra_field: File buffer too small to contain windows info.\n");
                goto done;
            }

            windowsFileInformation          = (windows_file_information*)index;
            eggFile->windowsFileInformation = windowsFileInformation;

            cli_dbgmsg("egg_parse_file_extra_field: windows_file_information->last_modified_time:   %016" PRIx64 "\n", le64_to_host(windowsFileInformation->last_modified_time));
            cli_dbgmsg("egg_parse_file_extra_field: windows_file_information->attribute:            %08x\n", windowsFileInformation->attribute);
            break;
        }
        case POSIX_INFO_MAGIC: {
            posix_file_information* posixFileInformation = NULL;

            if (NULL != eggFile->posixFileInformation) {
                cli_warnmsg("egg_parse_file_extra_field: Encountered more than 1 posix_file_information!\n");
                goto done;
            }

            if (payload_size < sizeof(posix_file_information)) {
                cli_warnmsg("egg_parse_file_extra_field: posix_file_information is truncated by its declared size!\n");
                status = CL_EFORMAT;
                goto done;
            }
            if (sizeof(posix_file_information) != payload_size) {
                cli_warnmsg("egg_parse_file_extra_field: Invalid size of posix_file_information!\n");
            }

            index = egg_read_extra_range(handle, payload_offset, sizeof(posix_file_information), &status);
            if (!index) {
                cli_dbgmsg("egg_parse_file_extra_field: File buffer too small to contain posix info.\n");
                goto done;
            }

            posixFileInformation          = (posix_file_information*)index;
            eggFile->posixFileInformation = posixFileInformation;

            cli_dbgmsg("egg_parse_file_extra_field: posix_file_information->mode:                 %08x ", le32_to_host(posixFileInformation->mode));
            if (UNLIKELY(cli_debug_flag)) {
                print_posix_info_mode(posixFileInformation->mode);
            }

            cli_dbgmsg("egg_parse_file_extra_field: posix_file_information->uid:                  %08x\n", le32_to_host(posixFileInformation->uid));
            cli_dbgmsg("egg_parse_file_extra_field: posix_file_information->gid:                  %08x\n", le32_to_host(posixFileInformation->gid));
            cli_dbgmsg("egg_parse_file_extra_field: posix_file_information->last_modified_time:   %016" PRIx64 "\n", le64_to_host(posixFileInformation->last_modified_time));
            break;
        }
        case FILE_HEADER_MAGIC: {
            if (handle->bSolid) {
                cli_dbgmsg("egg_parse_file_extra_field: Solid archive - on to next file header.\n");
            } else {
                cli_warnmsg("egg_parse_file_extra_field: Missing EOFARC in non-solid/standard archive.\n");
            }
            break;
        }
        default: {
            cli_dbgmsg("egg_parse_file_extra_field: unexpected header magic:    %08x (%s)\n", magic, getMagicHeaderName(magic));
        }
    }

    handle->offset = payload_offset + payload_size;

    status = CL_SUCCESS;

done:

    return status;
}

static cl_error_t egg_parse_file_headers(egg_handle* handle, egg_file** file)
{
    cl_error_t status = CL_EPARSE;
    cl_error_t retval;

    egg_file* eggFile       = NULL;
    file_header* fileHeader = NULL;
    uint32_t magic          = 0;
    const uint8_t* index    = 0;
    bool headers_complete   = false;

    if (!handle || !file) {
        cli_errmsg("egg_parse_file_headers: Invalid args!\n");
        return CL_EARG;
    }

    *file = NULL;

    if (CL_SUCCESS != EGG_VALIDATE_HANDLE(handle)) {
        cli_errmsg("egg_parse_file_headers: Invalid handle values!\n");
        status = CL_EARG;
        goto done;
    }

    /*
     * 1st:
     *   File headers must start with the file_header.
     */
    index = egg_read_fixed_range(handle, handle->offset, sizeof(file_header), &status);
    if (!index) {
        cli_dbgmsg("egg_parse_file_headers: File buffer too small to contain file header.\n");
        goto done;
    }

    eggFile = (egg_file*)calloc(1, sizeof(egg_file));
    if (NULL == eggFile) {
        cli_errmsg("egg_parse_file_headers: Failed to allocate memory for egg_file.\n");
        status = CL_EMEM;
        goto done;
    }

    fileHeader    = (file_header*)index;
    eggFile->file = fileHeader;

    if (FILE_HEADER_MAGIC != le32_to_host(fileHeader->magic)) {
        cli_dbgmsg("egg_parse_file_headers: Invalid file header magic: %08x (%s).\n", le32_to_host(fileHeader->magic), getMagicHeaderName(le32_to_host(fileHeader->magic)));
        goto done;
    }

    cli_dbgmsg("egg_parse_file_headers: file_header->magic:       %08x (%s)\n", le32_to_host(fileHeader->magic), getMagicHeaderName(le32_to_host(fileHeader->magic)));
    cli_dbgmsg("egg_parse_file_headers: file_header->file_id:     %08x\n", le32_to_host(fileHeader->file_id));
    cli_dbgmsg("egg_parse_file_headers: file_header->file_length: %016" PRIx64 " (%" PRIu64 ")\n",
               le64_to_host(fileHeader->file_length),
               le64_to_host(fileHeader->file_length));

    if (0 == le64_to_host(fileHeader->file_length)) {
        cli_dbgmsg("egg_parse_file_headers: Empty file!\n");
    }

    handle->offset += sizeof(file_header);

    /*
     * 2nd:
     *   After the file_header, the following extra field headers may be present:
     *      a) filename_header
     *      b) comment_header
     *      c) windows_file_information
     *      d) posix_file_information
     *      e) encrypt_header
     *      f) EOFARC
     */

    while (handle->map->len > handle->offset) {

        if (CL_SUCCESS != (status = egg_checktimelimit(handle)))
            goto done;

        /* Get the next magic32_t */
        index = egg_read_fixed_range(handle, handle->offset, sizeof(magic32_t), &status);
        if (!index) {
            cli_dbgmsg("egg_parse_file_headers: File buffer too small to contain end of archive magic bytes.\n");
            goto done;
        }

        magic = (uint32_t)cli_readint32(index);

        if (EOFARC == magic) {
            /*
             * File headers should conclude with EOFARC magic bytes.
             */
            handle->offset += sizeof(magic32_t);

            cli_dbgmsg("egg_parse_file_headers: End of archive headers.\n");
            headers_complete = true;
            break; /* Break out of the loop */
        } else {
            /*
             * Parse extra fields.
             */
            retval = egg_parse_file_extra_field(handle, eggFile);
            if (CL_SUCCESS != retval) {
                cli_dbgmsg("egg_parse_file_headers: Failed to parse archive header, magic: %08x (%s)\n", magic, getMagicHeaderName(magic));
                status = retval;
                goto done;
            }
        }
    }

    if (!headers_complete) {
        cli_dbgmsg("egg_parse_file_headers: file header did not terminate with EOFARC\n");
        status = CL_EFORMAT;
        goto done;
    }

    *file   = eggFile;
    eggFile = NULL;

    status = CL_SUCCESS;

done:
    if (NULL != eggFile) {
        egg_free_egg_file(eggFile);
    }

    return status;
}

static void egg_free_egg_handle(egg_handle* handle)
{
    uint32_t i = 0;

    if (NULL == handle) {
        return;
    }

    if (NULL != handle->encrypt) {
        egg_free_encrypt(handle->encrypt);
        handle->encrypt = NULL;
    }
    if (NULL != handle->files) {
        for (i = 0; i < handle->nFiles; i++) {
            egg_free_egg_file(handle->files[i]);
            handle->files[i] = NULL;
        }
        free(handle->files);
        handle->files = NULL;
    }
    if (NULL != handle->blocks) {
        for (i = 0; i < handle->nBlocks; i++) {
            egg_free_egg_block(handle->blocks[i]);
            handle->blocks[i] = NULL;
        }
        free(handle->blocks);
        handle->blocks = NULL;
    }
    if (NULL != handle->comments) {
        for (i = 0; i < handle->nComments; i++) {
            free(handle->comments[i]);
            handle->comments[i] = NULL;
        }
        free(handle->comments);
        handle->comments = NULL;
    }
    free(handle->metadataRanges);
    handle->metadataRanges  = NULL;
    handle->nMetadataRanges = 0;
    if (handle->ctx != NULL && handle->metadataRangesReserved != 0)
        cli_scan_release_contiguous(handle->ctx, handle->metadataRangesReserved);
    handle->metadataRangesReserved = 0;
    free(handle);
}

static cl_error_t egg_parse_archive_headers(egg_handle* handle)
{
    cl_error_t status = CL_EPARSE;
    cl_error_t retval;

    egg_header* eggHeader = NULL;
    uint32_t magic        = 0;
    const uint8_t* index  = 0;
    bool headers_complete = false;

    if (!handle) {
        cli_errmsg("egg_parse_archive_headers: Invalid args!\n");
        return CL_EARG;
    }

    if (CL_SUCCESS != EGG_VALIDATE_HANDLE(handle)) {
        cli_errmsg("egg_parse_archive_headers: Invalid handle values!\n");
        status = CL_EARG;
        goto done;
    }

    /*
     * 1st:
     *   Archive headers begins with the egg_header.
     */

    index = egg_read_fixed_range(handle, handle->offset, sizeof(egg_header), &status);
    if (!index) {
        cli_dbgmsg("egg_parse_archive_headers: File buffer too small to contain egg_header.\n");
        goto done;
    }

    eggHeader = (egg_header*)index;

    if (EGG_HEADER_MAGIC != le32_to_host(eggHeader->magic)) {
        cli_dbgmsg("egg_parse_archive_headers: Invalid egg header magic: %08x.\n", le32_to_host(eggHeader->magic));
        goto done;
    }

    cli_dbgmsg("egg_parse_archive_headers: egg_header->magic:     %08x (%s)\n", le32_to_host(eggHeader->magic), getMagicHeaderName(le32_to_host(eggHeader->magic)));
    cli_dbgmsg("egg_parse_archive_headers: egg_header->version:   %04x\n", le16_to_host(eggHeader->version));
    cli_dbgmsg("egg_parse_archive_headers: egg_header->header_id: %08x\n", le32_to_host(eggHeader->header_id));
    cli_dbgmsg("egg_parse_archive_headers: egg_header->reserved:  %08x\n", le32_to_host(eggHeader->reserved));

    if (EGG_HEADER_VERSION != le16_to_host(eggHeader->version) ||
        le32_to_host(eggHeader->header_id) == 0 ||
        le32_to_host(eggHeader->reserved) != 0) {
        cli_dbgmsg("egg_parse_archive_headers: Unsupported or malformed EGG archive header fields.\n");
        if (handle->ctx != NULL)
            cli_mark_scan_incomplete(handle->ctx, "EGG archive header fields are unsupported or malformed");
        status = CL_EPARSE;
        goto done;
    }

    handle->offset += sizeof(egg_header);

    /*
     * 2nd:
     *   Egg Header may be followed by:
     *      a) split_compression header  and/or
     *      b) solid_compression
     *      c) global encryption header
     *      d) EOFARC
     */

    while (handle->map->len > handle->offset) {

        if (CL_SUCCESS != (status = egg_checktimelimit(handle)))
            goto done;

        /* Get the next magic32_t */
        index = egg_read_fixed_range(handle, handle->offset, sizeof(magic32_t), &status);
        if (!index) {
            cli_dbgmsg("egg_parse_archive_headers: File buffer too small to contain end of archive magic bytes.\n");
            goto done;
        }

        magic = (uint32_t)cli_readint32(index);

        if (EOFARC == magic) {
            /*
             * Archive headers should conclude with EOFARC magic bytes.
             */
            handle->offset += sizeof(magic32_t);

            cli_dbgmsg("egg_parse_archive_headers: End of archive headers.\n");
            headers_complete = true;
            break; /* Break out of the loop */
        } else {
            /*
             * Parse extra fields.
             */
            retval = egg_parse_archive_extra_field(handle);
            if (CL_SUCCESS != retval) {
                cli_dbgmsg("egg_parse_archive_headers: Failed to parse archive header, magic: %08x (%s)\n", magic, getMagicHeaderName(magic));
                status = retval;
                goto done;
            }
        }
    }

    if (!headers_complete) {
        cli_dbgmsg("egg_parse_archive_headers: archive header did not terminate with EOFARC\n");
        status = CL_EFORMAT;
        goto done;
    }

    status = CL_SUCCESS;

done:
    return status;
}

cl_error_t cli_egg_header_check(fmap_t* map, size_t offset)
{
    const uint8_t* index;
    const egg_header* header;
    uint64_t remaining;

    if (!map)
        return CL_ENULLARG;

    remaining = (offset <= map->len) ? (uint64_t)(map->len - offset) : 0;
    if (remaining < sizeof(egg_header))
        return CL_EFORMAT;

    index = (const uint8_t*)fmap_need_off_once(map, offset, sizeof(egg_header));
    if (!index)
        return CL_EREAD;

    header = (const egg_header*)index;
    if (EGG_HEADER_MAGIC != le32_to_host(header->magic))
        return CL_EFORMAT;

    if (EGG_HEADER_VERSION != le16_to_host(header->version) ||
        le32_to_host(header->header_id) == 0 ||
        le32_to_host(header->reserved) != 0)
        return CL_EPARSE;

    return CL_SUCCESS;
}

cl_error_t cli_egg_sfx_header_check(cli_ctx *ctx, size_t offset)
{
    cl_error_t status;

    if (ctx == NULL)
        return CL_ENULLARG;
    if (ctx->fmap == NULL) {
        cli_mark_scan_incomplete(ctx, "EGG SFX header input map is unavailable");
        return CL_EPARSE;
    }

    status = cli_egg_header_check(ctx->fmap, offset);
    if ((status == CL_SUCCESS || status == CL_CLEAN) && ctx->scan_incomplete)
        return CL_EPARSE;

    return status;
}

cl_error_t cli_egg_open_ex(fmap_t* map, void** hArchive, char*** comments, uint32_t* nComments, cli_ctx* ctx)
{
    cl_error_t status = CL_EPARSE;
    cl_error_t retval;
    egg_handle* handle    = NULL;
    uint32_t magic        = 0;
    const uint8_t* index  = 0;
    bool archive_complete = false;

    if (!map || !hArchive || !comments || !nComments) {
        cli_errmsg("cli_egg_open: Invalid args!\n");
        return CL_EARG;
    }

    *hArchive  = NULL;
    *comments  = NULL;
    *nComments = 0;

    handle = (egg_handle*)calloc(1, sizeof(egg_handle));
    if (NULL == handle) {
        cli_errmsg("cli_egg_open: Failed to allocate memory for egg_handle.\n");
        status = CL_EMEM;
        goto done;
    }
    handle->map    = map;
    handle->ctx    = ctx;
    handle->offset = 0;

    if (CL_SUCCESS != (status = egg_checktimelimit(handle)))
        goto done;

    /*
     * 1st:
     *   Parse the archive headers.
     */
    if (CL_SUCCESS != (retval = egg_parse_archive_headers(handle))) {
        cli_warnmsg("cli_egg_open: Failed to parse archive headers!\n");
        status = retval;
        goto done;
    }

    /*
     * 2nd:
     *   Archive headers may be followed by:
     *      a) 0+ file headers
     *      b) 0+ block headers
     *      c) 0+ archive comment headers
     */
    while (CL_SUCCESS == retval) {

        if (CL_SUCCESS != (status = egg_checktimelimit(handle)))
            goto done;

        /* Get the next magic32_t */
        index = egg_read_fixed_range(handle, handle->offset, sizeof(magic32_t), &status);
        if (!index) {
            cli_dbgmsg("cli_egg_open: No more data in archive.\n");
            status = CL_EFORMAT;
            goto done;
        }

        magic = (uint32_t)cli_readint32(index);

        if (EOFARC == magic) {
            /*
             * Archive headers should conclude with EOFARC magic bytes.
             */
            handle->offset += sizeof(magic32_t);
            archive_complete = true;

            if (handle->map->len > handle->offset) {
                cli_warnmsg("Apparent end to EGG archive, but an addition %zu bytes of data exists in the file!\n",
                            handle->map->len - handle->offset);
            } else {
                cli_dbgmsg("cli_egg_open: Successfully indexed EGG archive!\n");
            }

            break; /* Break out of the loop */
        } else if (FILE_HEADER_MAGIC == magic) {
            /*
             * Archive File Header
             */
            egg_file* found_file = NULL;
            if (CL_SUCCESS != (retval = egg_parse_file_headers(handle, &found_file))) {
                cli_dbgmsg("cli_egg_open: Issue parsing file header. Error code: %u\n", retval);
                status = retval;
                goto done;
            } else if (found_file == NULL) {
                cli_errmsg("cli_egg_open: Logic error! Successfully parsed file headers,"
                           " but did not return egg_file information!\n");
                goto done;
            } else {
                /* Add file to list. */
                if (handle->nFiles >= CLI_MAX_ALLOCATION / sizeof(egg_file*)) {
                    egg_free_egg_file(found_file);
                    status = CL_EMAXSIZE;
                    goto done;
                }
                CLI_MAX_REALLOC_OR_GOTO_DONE(handle->files,
                                             sizeof(egg_file*) * (size_t)(handle->nFiles + 1),
                                             egg_free_egg_file(found_file),
                                             status = CL_EMEM);
                handle->files[handle->nFiles] = found_file;
                handle->nFiles++;
            }
        } else if (BLOCK_HEADER_MAGIC == magic) {
            /*
             * Archive Block Header
             */
            egg_block* found_block = NULL;
            if (CL_SUCCESS != (retval = egg_parse_block_headers(handle, &found_block))) {
                cli_dbgmsg("cli_egg_open: Issue parsing block header. Error code: %u\n", retval);
                status = retval;
                goto done;
            } else if (found_block == NULL) {
                cli_errmsg("cli_egg_open: Logic error! Successfully parsed block headers,"
                           " but did not return egg_block information!\n");
                goto done;
            } else {
                /* Add block to list. */
                if (handle->bSolid) {
                    if (handle->nBlocks >= CLI_MAX_ALLOCATION / sizeof(egg_block*)) {
                        egg_free_egg_block(found_block);
                        status = CL_EMAXSIZE;
                        goto done;
                    }
                    CLI_MAX_REALLOC_OR_GOTO_DONE(handle->blocks,
                                                 sizeof(egg_block*) * (size_t)(handle->nBlocks + 1),
                                                 egg_free_egg_block(found_block),
                                                 status = CL_EMEM);
                    handle->blocks[handle->nBlocks] = found_block;
                    handle->nBlocks++;
                } else {
                    egg_file* eggFile = NULL;
                    /*
                     * Associate block with most recently added file.
                     */
                    if (handle->nFiles == 0) {
                        cli_dbgmsg("cli_egg_open: No file found for block in non-solid archive.\n");
                        // TODO: create an unnamed block.
                        egg_free_egg_block(found_block);
                    } else {
                        eggFile = handle->files[handle->nFiles - 1];

                        if (eggFile->nBlocks >= CLI_MAX_ALLOCATION / sizeof(egg_block*)) {
                            egg_free_egg_block(found_block);
                            status = CL_EMAXSIZE;
                            goto done;
                        }
                        CLI_MAX_REALLOC_OR_GOTO_DONE(eggFile->blocks,
                                                     sizeof(egg_block*) * (size_t)(eggFile->nBlocks + 1),
                                                     egg_free_egg_block(found_block),
                                                     status = CL_EMEM);
                        eggFile->blocks[eggFile->nBlocks] = found_block;
                        eggFile->nBlocks++;
                    }
                }
            }
        } else if (COMMENT_HEADER_MAGIC == magic) {
            /*
             * Parse extra field for archive comment header.
             */
            extra_field extraFieldStorage;
            extra_field* extraField = NULL;
            char* comment           = NULL;
            uint32_t size           = 0;

            index = egg_read_extra_range(handle, handle->offset, sizeof(extra_field), &status);
            if (!index) {
                cli_dbgmsg("cli_egg_open: File buffer too small to contain extra_field header.\n");
                goto done;
            }

            memcpy(&extraFieldStorage, index, sizeof(extraFieldStorage));
            extraField = &extraFieldStorage;

            cli_dbgmsg("cli_egg_open: archive comment extra_field->magic:    %08x (%s)\n", le32_to_host(extraField->magic), getMagicHeaderName(le32_to_host(extraField->magic)));
            cli_dbgmsg("cli_egg_open: archive comment extra_field->bit_flag: %02x\n", extraField->bit_flag);

            handle->offset += sizeof(extra_field);

            if (extraField->bit_flag & EXTRA_FIELD_FLAGS_SIZE_IS_4BYTES) {
                /* size is uint32_t */
                index = egg_read_extra_range(handle, handle->offset, sizeof(uint32_t), &status);
                if (!index) {
                    cli_dbgmsg("cli_egg_open: File buffer too small to contain archive comment extra_field header.\n");
                    goto done;
                }

                size = (uint32_t)cli_readint32(index);

                handle->offset += sizeof(uint32_t);
            } else {
                /* size is uint16_t */
                index = egg_read_extra_range(handle, handle->offset, sizeof(uint16_t), &status);
                if (!index) {
                    cli_dbgmsg("cli_egg_open: File buffer too small to contain archive comment extra_field header.\n");
                    goto done;
                }

                size = (uint16_t)cli_readint16(index);

                handle->offset += sizeof(uint16_t);
            }

            cli_dbgmsg("cli_egg_open: archive comment extra_field->size:     %u\n", size);

            if (!egg_extra_span_present(handle, handle->offset, size, &status))
                goto done;

            if (extraField->bit_flag & COMMENT_HEADER_FLAGS_ENCRYPT) {
                if (handle->ctx != NULL)
                    cli_mark_scan_incomplete(handle->ctx, "EGG encrypted archive comment prevents metadata inspection");
                status = CL_EUNPACK;
                goto done;
            }

            status = egg_add_metadata_range(handle, handle->offset, size, CODEPAGE_UTF8);
            if (status != CL_SUCCESS)
                goto done;

            if (handle->ctx != NULL && size > CLI_MAX_ALLOCATION) {
                handle->offset += size;
                continue;
            }
            if (size > CLI_MAX_ALLOCATION) {
                cli_warnmsg("cli_egg_open: archive comment exceeds legacy string-metadata limit\n");
                status = CL_EMAXSIZE;
                goto done;
            }

            index = egg_read_extra_range(handle, handle->offset, size, &status);
            if (!index) {
                cli_dbgmsg("cli_egg_open: File buffer too small to contain extra_field header.\n");
                goto done;
            }

            if (CL_SUCCESS != (retval = egg_parse_comment_header(index, size, extraField, &comment))) {
                cli_dbgmsg("cli_egg_open: Issue parsing comment header. Error code: %u\n", retval);
                status = retval;
                goto done;
            } else {
                /*
                 * Success?
                 */
                if (comment == NULL) {
                    /* Uh... no. */
                    cli_errmsg("cli_egg_open: Logic error! Successfully parsed comment header,"
                               " but did not return egg_comment information!\n");
                    goto done;
                } else {
                    /*
                     * Comment found. Add comment to our list.
                     */
                    if (handle->nComments >= CLI_MAX_ALLOCATION / sizeof(char*)) {
                        free(comment);
                        status = CL_EMAXSIZE;
                        goto done;
                    }
                    CLI_MAX_REALLOC_OR_GOTO_DONE(handle->comments,
                                                 sizeof(char*) * (size_t)(handle->nComments + 1),
                                                 free(comment),
                                                 status = CL_EMEM);
                    handle->comments[handle->nComments] = comment;
                    handle->nComments++;
                }
            }
            handle->offset += size;

        } else {
            cli_dbgmsg("cli_egg_open: unexpected header magic:               %08x (%s)\n", magic, getMagicHeaderName(magic));
            status = CL_EPARSE;
            goto done;
        }
    }

    if (!archive_complete) {
        cli_warnmsg("cli_egg_open: Archive index did not terminate with EOFARC.\n");
        status = CL_EFORMAT;
        goto done;
    }

    if (CL_SUCCESS != retval) {
        if (CL_BREAK == retval) {
            /* End of archive. */
            if ((handle->bSplit) && (handle->splitInfo->next_file_id != 0))
                cli_warnmsg("cli_egg_open: Abrupt end to EGG volume!\n");
            else
                cli_dbgmsg("cli_egg_open: End of EGG volume in split archive.\n");
        } else {
            /* Something went wrong. */
            cli_warnmsg("cli_egg_open: Failed to parse file headers!\n");
        }
    }

    *comments        = handle->comments;
    handle->comments = NULL;

    *nComments = handle->nComments;

    *hArchive = handle;
    handle    = NULL;

    status = CL_SUCCESS;

done:
    if (NULL != handle) {
        egg_free_egg_handle(handle);
    }
    return status;
}

cl_error_t cli_egg_open(fmap_t* map, void** hArchive, char*** comments, uint32_t* nComments)
{
    return cli_egg_open_ex(map, hArchive, comments, nComments, NULL);
}

cl_error_t cli_egg_metadata_range(void* hArchive, uint64_t index, size_t* offset,
                                  size_t* length, uint16_t* codepage)
{
    egg_handle* handle = hArchive;
    egg_metadata_range* range;

    if (handle == NULL || offset == NULL || length == NULL || codepage == NULL)
        return CL_EARG;
    if (CL_SUCCESS != EGG_VALIDATE_HANDLE(handle))
        return CL_EARG;
    if (index >= handle->nMetadataRanges)
        return CL_BREAK;

    range     = &handle->metadataRanges[index];
    *offset   = range->offset;
    *length   = range->length;
    *codepage = range->codepage;
    return CL_SUCCESS;
}

cl_error_t cli_egg_peek_file_header(void* hArchive, cl_egg_metadata* file_metadata)
{
    cl_error_t status  = CL_EPARSE;
    egg_handle* handle = NULL;
    egg_file* currFile = NULL;

    if (!hArchive || !file_metadata) {
        cli_errmsg("cli_egg_peek_file_header: Invalid args!\n");
        return CL_EARG;
    }

    handle = (egg_handle*)hArchive;
    if (CL_SUCCESS != EGG_VALIDATE_HANDLE(handle)) {
        cli_errmsg("cli_egg_peek_file_header: Invalid handle values!\n");
        status = CL_EARG;
        goto done;
    }

    memset(file_metadata, 0, sizeof(cl_egg_metadata));

    if (handle->fileExtractionIndex >= handle->nFiles) {
        status = CL_BREAK;
        goto done;
    }

    currFile = handle->files[handle->fileExtractionIndex];
    if (NULL == currFile) {
        cli_errmsg("cli_egg_peek_file_header: invalid egg_file pointer!\n");
        goto done;
    }

    if (NULL == currFile->file) {
        cli_errmsg("cli_egg_peek_file_header: egg_file is missing file header!\n");
        goto done;
    }

    if (NULL == currFile->filename.name_utf8) {
        cli_errmsg("cli_egg_extract_file: egg_file is missing filename!\n");
        goto done;
    }

    if (handle->bSolid) {
        /*
         * TODO: Add support for extracting files from solid archives.
         *
         * See the comments in cli_egg_extract_file() for more details.
         */
        file_metadata->pack_size   = 0;
        file_metadata->unpack_size = le64_to_host(currFile->file->file_length);
    } else {
        uint64_t i = 0;
        if (!currFile->blocks) {
            cli_dbgmsg("cli_egg_peek_file_header: Empty file!\n");
        }
        for (i = 0; i < currFile->nBlocks; i++) {
            egg_block* currBlock = currFile->blocks[i];

            if (CL_SUCCESS != (status = egg_checktimelimit(handle)))
                goto done;

            if (!currBlock->blockHeader) {
                cli_errmsg("cli_egg_peek_file_header: egg_block missing block_header!\n");
                goto done;
            }
            if (currBlock->compressedSize > UINT64_MAX - file_metadata->pack_size ||
                currBlock->uncompressedSize > UINT64_MAX - file_metadata->unpack_size) {
                cli_warnmsg("cli_egg_peek_file_header: block size accounting overflowed\n");
                status = CL_EFORMAT;
                goto done;
            }
            file_metadata->pack_size += currBlock->compressedSize;
            file_metadata->unpack_size += currBlock->uncompressedSize;
        }
        if (file_metadata->unpack_size != le64_to_host(currFile->file->file_length)) {
            cli_warnmsg("cli_egg_peek_file_header: sum of block uncompress_size's does not match listed file_length!\n");
            status = CL_EFORMAT;
            goto done;
        }
    }

    file_metadata->filename = strdup(currFile->filename.name_utf8);
    if (file_metadata->filename == NULL) {
        status = CL_EMEM;
        goto done;
    }

    if (NULL != currFile->encrypt)
        file_metadata->encrypted = 1;

    if (currFile->posixFileInformation && currFile->posixFileInformation->mode & POSIX_INFO_MODE_DIRECTORY)
        file_metadata->is_dir = 1;
    else if (currFile->windowsFileInformation && currFile->windowsFileInformation->attribute & WINDOWS_INFO_ATTRIBUTE_DIRECTORY)
        file_metadata->is_dir = 1;

    status = CL_SUCCESS;
done:
    return status;
}

#define EGG_STREAM_CHUNK (64U * 1024U)

typedef struct {
    cli_egg_write_callback write;
    void* opaque;
    uint64_t expected;
    uint64_t written;
    uint32_t checksum;
} egg_stream_output;

static cl_error_t egg_stream_emit(egg_stream_output* output, const unsigned char* data, size_t length)
{
    cl_error_t status;

    if (length == 0)
        return CL_SUCCESS;

    if (output == NULL || output->write == NULL || output->written > output->expected ||
        (uint64_t)length > output->expected - output->written)
        return CL_EFORMAT;

    status = output->write(output->opaque, data, length);
    if (status != CL_SUCCESS)
        return status;

    output->checksum = (uint32_t)crc32(output->checksum, data, (uInt)length);
    output->written += (uint64_t)length;
    return CL_SUCCESS;
}

static uint32_t egg_crc32(const void* data, size_t length)
{
    const uint8_t* bytes = data;
    uLong checksum       = crc32(0L, Z_NULL, 0);

    while (length != 0) {
        uInt chunk = length > UINT_MAX ? UINT_MAX : (uInt)length;

        checksum = crc32(checksum, bytes, chunk);
        bytes += chunk;
        length -= chunk;
    }
    return (uint32_t)checksum;
}

static cl_error_t egg_check_block_crc(const egg_handle* handle, const egg_block* block,
                                      uint32_t checksum)
{
    if (handle == NULL || block == NULL || block->blockHeader == NULL)
        return CL_EARG;
    if (checksum == le32_to_host(block->blockHeader->crc32))
        return CL_SUCCESS;
    if (handle->ctx != NULL)
        cli_mark_scan_incomplete(handle->ctx, "EGG block CRC-32 did not match decoded output");
    return CL_EUNPACK;
}

static cl_error_t egg_stream_read(const egg_handle* handle, const egg_block* block,
                                  size_t* input_offset, unsigned char* buffer,
                                  size_t* buffer_length)
{
    size_t available;
    size_t chunk;
    size_t offset;

    if (handle == NULL || handle->map == NULL || block == NULL || input_offset == NULL ||
        buffer == NULL || buffer_length == NULL || *input_offset > (size_t)block->compressedSize)
        return CL_EARG;

    available = (size_t)block->compressedSize - *input_offset;
    if (available == 0) {
        *buffer_length = 0;
        return CL_SUCCESS;
    }

    chunk  = (available < (size_t)EGG_STREAM_CHUNK) ? available : (size_t)EGG_STREAM_CHUNK;
    offset = block->compressedDataOffset;
    if (offset > handle->map->len || *input_offset > handle->map->len - offset ||
        chunk > handle->map->len - offset - *input_offset) {
        if (handle->ctx != NULL)
            cli_mark_scan_incomplete(handle->ctx, "EGG compressed stream is truncated");
        return CL_EPARSE;
    }

    if (fmap_readn(handle->map, buffer, offset + *input_offset, chunk) != chunk) {
        if (handle->ctx != NULL)
            cli_mark_scan_incomplete(handle->ctx, "EGG compressed stream could not be read completely");
        return CL_EREAD;
    }

    *input_offset += chunk;
    *buffer_length = chunk;
    return CL_SUCCESS;
}

static cl_error_t egg_stream_store(const egg_handle* handle, const egg_block* block,
                                   egg_stream_output* output)
{
    unsigned char buffer[EGG_STREAM_CHUNK];
    size_t input_offset = 0;
    size_t buffer_length;
    cl_error_t status;

    if (block->compressedSize != block->uncompressedSize)
        return CL_EFORMAT;

    while (input_offset < (size_t)block->compressedSize) {
        status = egg_checktimelimit(handle);
        if (status != CL_SUCCESS)
            return status;
        status = egg_stream_read(handle, block, &input_offset, buffer, &buffer_length);
        if (status != CL_SUCCESS)
            return status;
        if (buffer_length == 0)
            return CL_EREAD;

        status = egg_stream_emit(output, buffer, buffer_length);
        if (status != CL_SUCCESS)
            return status;
    }

    return (output->written == output->expected) ? CL_SUCCESS : CL_EFORMAT;
}

static cl_error_t egg_stream_deflate(const egg_handle* handle, const egg_block* block,
                                     egg_stream_output* output)
{
    unsigned char input[EGG_STREAM_CHUNK];
    unsigned char decoded[EGG_STREAM_CHUNK];
    size_t input_offset = 0;
    size_t input_length = 0;
    size_t produced;
    z_stream stream;
    int initialized = 0;
    int zstat;
    cl_error_t status = CL_EUNPACK;

    memset(&stream, 0, sizeof(stream));
    if (inflateInit2(&stream, -15) != Z_OK)
        return CL_EMEM;
    initialized = 1;

    for (;;) {
        status = egg_checktimelimit(handle);
        if (status != CL_SUCCESS)
            goto done;
        if (stream.avail_in == 0 && input_offset < (size_t)block->compressedSize) {
            status = egg_stream_read(handle, block, &input_offset, input, &input_length);
            if (status != CL_SUCCESS)
                goto done;
            stream.next_in  = input;
            stream.avail_in = (uInt)input_length;
        }

        stream.next_out  = decoded;
        stream.avail_out = (uInt)sizeof(decoded);
        {
            uInt before_in  = stream.avail_in;
            uInt before_out = stream.avail_out;

            zstat    = inflate(&stream, Z_NO_FLUSH);
            produced = sizeof(decoded) - stream.avail_out;

            status = egg_stream_emit(output, decoded, produced);
            if (status != CL_SUCCESS)
                goto done;

            if (zstat == Z_STREAM_END) {
                if (stream.avail_in != 0 || input_offset < (size_t)block->compressedSize) {
                    status = CL_EFORMAT;
                    goto done;
                }
                status = (output->written == output->expected) ? CL_SUCCESS : CL_EFORMAT;
                goto done;
            }

            if (zstat != Z_OK && zstat != Z_BUF_ERROR) {
                status = CL_EUNPACK;
                goto done;
            }

            if (before_in == stream.avail_in && before_out == stream.avail_out &&
                input_offset >= (size_t)block->compressedSize) {
                status = CL_EUNPACK;
                goto done;
            }
        }
    }

done:
    if (initialized)
        (void)inflateEnd(&stream);
    return status;
}

static cl_error_t egg_stream_bzip2(const egg_handle* handle, const egg_block* block,
                                   egg_stream_output* output)
{
    unsigned char input[EGG_STREAM_CHUNK];
    unsigned char decoded[EGG_STREAM_CHUNK];
    size_t input_offset = 0;
    size_t input_length = 0;
    size_t produced;
    bz_stream stream;
    int initialized = 0;
    int bzstat;
    cl_error_t status = CL_EUNPACK;

    memset(&stream, 0, sizeof(stream));
    if (BZ2_bzDecompressInit(&stream, 0, 0) != BZ_OK)
        return CL_EMEM;
    initialized = 1;

    for (;;) {
        status = egg_checktimelimit(handle);
        if (status != CL_SUCCESS)
            goto done;
        if (stream.avail_in == 0 && input_offset < (size_t)block->compressedSize) {
            status = egg_stream_read(handle, block, &input_offset, input, &input_length);
            if (status != CL_SUCCESS)
                goto done;
            stream.next_in  = (char*)input;
            stream.avail_in = (unsigned int)input_length;
        }

        stream.next_out  = (char*)decoded;
        stream.avail_out = (unsigned int)sizeof(decoded);
        {
            unsigned int before_in  = stream.avail_in;
            unsigned int before_out = stream.avail_out;

            bzstat   = BZ2_bzDecompress(&stream);
            produced = sizeof(decoded) - stream.avail_out;

            status = egg_stream_emit(output, decoded, produced);
            if (status != CL_SUCCESS)
                goto done;

            if (bzstat == BZ_STREAM_END) {
                if (stream.avail_in != 0 || input_offset < (size_t)block->compressedSize) {
                    status = CL_EFORMAT;
                    goto done;
                }
                status = (output->written == output->expected) ? CL_SUCCESS : CL_EFORMAT;
                goto done;
            }

            if (bzstat != BZ_OK) {
                status = CL_EUNPACK;
                goto done;
            }

            if (before_in == stream.avail_in && before_out == stream.avail_out &&
                input_offset >= (size_t)block->compressedSize) {
                status = CL_EUNPACK;
                goto done;
            }
        }
    }

done:
    if (initialized)
        (void)BZ2_bzDecompressEnd(&stream);
    return status;
}

static cl_error_t egg_stream_lzma(const egg_handle* handle, const egg_block* block,
                                  egg_stream_output* output)
{
    unsigned char input[EGG_STREAM_CHUNK];
    unsigned char decoded[EGG_STREAM_CHUNK];
    size_t input_offset = 0;
    size_t input_length = 0;
    size_t produced;
    struct CLI_LZMA stream;
    uint64_t declared_size = UINT64_MAX;
    bool decoder_ready       = false;
    bool decoder_initialized = false;
    int lzmastat;
    cl_error_t status = CL_EUNPACK;

    memset(&stream, 0, sizeof(stream));

    for (;;) {
        status = egg_checktimelimit(handle);
        if (status != CL_SUCCESS)
            goto done;
        if (stream.avail_in == 0 && input_offset < (size_t)block->compressedSize) {
            status = egg_stream_read(handle, block, &input_offset, input, &input_length);
            if (status != CL_SUCCESS)
                goto done;
            stream.next_in  = input;
            stream.avail_in = input_length;
        }

        if (!decoder_ready) {
            lzmastat = cli_LzmaInit(&stream, 0);
            if (lzmastat != LZMA_RESULT_OK) {
                status = CL_EUNPACK;
                goto done;
            }
            if (!stream.freeme) {
                if (stream.avail_in == 0 && input_offset >= (size_t)block->compressedSize) {
                    status = CL_EUNPACK;
                    goto done;
                }
                continue;
            }

            decoder_ready = true;
            decoder_initialized = true;
            declared_size = stream.usize;
            if (declared_size != UINT64_MAX && declared_size != block->uncompressedSize) {
                status = CL_EFORMAT;
                goto done;
            }
        }

        stream.next_out  = decoded;
        stream.avail_out = sizeof(decoded);
        {
            SizeT before_in  = stream.avail_in;
            SizeT before_out = stream.avail_out;

            lzmastat = cli_LzmaDecode(&stream);
            produced = sizeof(decoded) - stream.avail_out;

            status = egg_stream_emit(output, decoded, produced);
            if (status != CL_SUCCESS)
                goto done;

            if (lzmastat == LZMA_STREAM_END) {
                if (stream.avail_in != 0 || input_offset < (size_t)block->compressedSize) {
                    status = CL_EFORMAT;
                    goto done;
                }
                status = (output->written == output->expected) ? CL_SUCCESS : CL_EFORMAT;
                goto done;
            }

            if (lzmastat != LZMA_RESULT_OK) {
                status = CL_EUNPACK;
                goto done;
            }

            if (before_in == stream.avail_in && before_out == stream.avail_out &&
                input_offset >= (size_t)block->compressedSize) {
                status = CL_EUNPACK;
                goto done;
            }
        }
    }

done:
    if (decoder_initialized)
        cli_LzmaShutdown(&stream);
    return status;
}

static cl_error_t egg_stream_block(const egg_handle* handle, const egg_block* block,
                                   egg_stream_output* output)
{
    cl_error_t status;

    if (handle == NULL || block == NULL || output == NULL || block->blockHeader == NULL ||
        block->compressedSize == 0)
        return CL_EFORMAT;

    output->checksum = (uint32_t)crc32(0L, Z_NULL, 0);
    switch (block->compressionAlgorithm) {
        case BLOCK_HEADER_COMPRESS_ALGORITHM_STORE:
            status = egg_stream_store(handle, block, output);
            break;
        case BLOCK_HEADER_COMPRESS_ALGORITHM_DEFLATE:
            status = egg_stream_deflate(handle, block, output);
            break;
        case BLOCK_HEADER_COMPRESS_ALGORITHM_BZIP2:
            status = egg_stream_bzip2(handle, block, output);
            break;
        case BLOCK_HEADER_COMPRESS_ALGORITHM_LZMA:
            status = egg_stream_lzma(handle, block, output);
            break;
        case BLOCK_HEADER_COMPRESS_ALGORITHM_AZO:
            return CL_EUNPACK;
        default:
            return CL_EFORMAT;
    }

    if (status != CL_SUCCESS)
        return status;
    return egg_check_block_crc(handle, block, output->checksum);
}

cl_error_t cli_egg_extract_file_stream(void* hArchive, cli_egg_write_callback write,
                                       void* opaque, const char** filename,
                                       uint64_t* output_length)
{
    cl_error_t status  = CL_EPARSE;
    egg_handle* handle = NULL;
    egg_file* currFile = NULL;
    uint64_t extracted = 0;
    uint64_t file_length;
    uint64_t i;

    if (hArchive == NULL || write == NULL || filename == NULL || output_length == NULL)
        return CL_EARG;

    *filename      = NULL;
    *output_length = 0;
    handle         = (egg_handle*)hArchive;

    if (CL_SUCCESS != EGG_VALIDATE_HANDLE(handle) || handle->fileExtractionIndex >= handle->nFiles)
        goto done;

    currFile = handle->files[handle->fileExtractionIndex];
    if (currFile == NULL || currFile->file == NULL || currFile->filename.name_utf8 == NULL)
        goto done;

    if (handle->bSolid) {
        cli_warnmsg("cli_egg_extract_file_stream: solid EGG extraction is unsupported\n");
        status = CL_EUNPACK;
        goto done;
    }

    file_length = le64_to_host(currFile->file->file_length);
    if ((currFile->nBlocks == 0 && file_length != 0) ||
        (currFile->nBlocks != 0 && currFile->blocks == NULL))
        goto done;

    for (i = 0; i < currFile->nBlocks; i++) {
        egg_block* block = currFile->blocks[i];
        egg_stream_output output;

        if (CL_SUCCESS != (status = egg_checktimelimit(handle)))
            goto done;

        if (block == NULL || block->blockHeader == NULL || block->compressedSize == 0 ||
            block->compressedDataOffset > handle->map->len ||
            block->compressedSize > handle->map->len - block->compressedDataOffset)
            goto done;

        if (extracted > UINT64_MAX - block->uncompressedSize)
            goto done;

        memset(&output, 0, sizeof(output));
        output.write    = write;
        output.opaque   = opaque;
        output.expected = block->uncompressedSize;

        status = egg_stream_block(handle, block, &output);
        if (status != CL_SUCCESS)
            goto done;

        extracted += output.written;
    }

    if (extracted != file_length)
        goto done;

    *filename = strdup(currFile->filename.name_utf8);
    if (*filename == NULL) {
        status = CL_EMEM;
        goto done;
    }

    *output_length = extracted;
    status         = CL_SUCCESS;

done:
    if (handle != NULL)
        handle->fileExtractionIndex += 1;
    if (status != CL_SUCCESS) {
        free((void*)*filename);
        *filename      = NULL;
        *output_length = 0;
    }
    return status;
}

cl_error_t cli_egg_deflate_decompress(char* compressed, size_t compressed_size, char** decompressed, size_t* decompressed_size)
{
    cl_error_t status = CL_EPARSE;

    uint8_t* decoded = NULL;
    uint32_t declen = 0, capacity = 0;

    z_stream stream;
    int stream_initialized = 0;
    int zstat;

    if (NULL == compressed || compressed_size == 0 || NULL == decompressed || NULL == decompressed_size) {
        cli_errmsg("cli_egg_deflate_decompress: Invalid args!\n");
        status = CL_EARG;
        goto done;
    }
    if (compressed_size > CLI_MAX_ALLOCATION || compressed_size > UINT_MAX) {
        status = CL_EMAXSIZE;
        goto done;
    }

    *decompressed      = NULL;
    *decompressed_size = 0;

    if (!(decoded = (uint8_t*)calloc(BUFSIZ, sizeof(uint8_t)))) {
        cli_errmsg("cli_egg_deflate_decompress: cannot allocate memory for decompressed output\n");
        status = CL_EMEM;
        goto done;
    }

    capacity = BUFSIZ;

    memset(&stream, 0, sizeof(stream));
    stream.next_in   = (Bytef*)compressed;
    stream.avail_in  = compressed_size;
    stream.next_out  = (Bytef*)decoded;
    stream.avail_out = BUFSIZ;

    zstat = inflateInit2(&stream, -15);
    if (zstat != Z_OK) {
        cli_warnmsg("cli_egg_deflate_decompress: inflateInit failed\n");
        status = CL_EMEM;
        goto done;
    }
    stream_initialized = 1;

    /* initial inflate */
    zstat = inflate(&stream, Z_NO_FLUSH);

    /* check if nothing written whatsoever */
    if ((zstat != Z_OK) && (stream.avail_out == BUFSIZ)) {
        /* Inflation failed */
        cli_errmsg("cli_egg_deflate_decompress: failed to decompress data\n");
        status = CL_EPARSE;
        goto done;
    }

    while (zstat == Z_OK) {
        /* extend output capacity if needed,*/
        if (stream.avail_out == 0) {
            if (capacity > CLI_MAX_ALLOCATION - BUFSIZ) {
                status = CL_EMAXSIZE;
                goto done;
            }
            CLI_MAX_REALLOC_OR_GOTO_DONE(decoded, capacity + BUFSIZ,
                                         cli_errmsg("cli_egg_deflate_decompress: cannot reallocate memory for decompressed output\n"),
                                         status = CL_EMEM);
            stream.next_out  = decoded + capacity;
            stream.avail_out = BUFSIZ;
            declen += BUFSIZ;
            capacity += BUFSIZ;
        }

        /* continue inflation */
        {
            uInt before_in  = stream.avail_in;
            uInt before_out = stream.avail_out;
            zstat           = inflate(&stream, Z_NO_FLUSH);
            if (zstat == Z_OK && before_in == stream.avail_in && before_out == stream.avail_out) {
                zstat = Z_BUF_ERROR;
            }
        }
    }

    /* add end fragment to decoded length */
    declen += (BUFSIZ - stream.avail_out);

    /* error handling */
    switch (zstat) {
        case Z_STREAM_END:
            cli_dbgmsg("cli_egg_deflate_decompress: decompressed %lu bytes from %lu total bytes (%lu bytes remaining)\n",
                       (unsigned long)declen, (unsigned long)(compressed_size), (unsigned long)(stream.avail_in));
            break;

        /* potentially fatal - *mostly* ignored as per older version */
        case Z_STREAM_ERROR:
        case Z_NEED_DICT:
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
        default:
            if (stream.msg)
                cli_dbgmsg("cli_egg_deflate_decompress: after decompressing %lu bytes, got error \"%s\"\n",
                           (unsigned long)declen, stream.msg);
            else
                cli_dbgmsg("cli_egg_deflate_decompress: after decompressing %lu bytes, got error %d\n",
                           (unsigned long)declen, zstat);

            status = (zstat == Z_MEM_ERROR) ? CL_EMEM : CL_EUNPACK;
            goto done;
    }

    *decompressed = (char*)decoded;
    decoded       = NULL;

    *decompressed_size = declen;

    status = CL_SUCCESS;

done:

    if (stream_initialized) {
        (void)inflateEnd(&stream);
    }

    if (NULL != decoded) {
        free(decoded);
    }

    return status;
}

cl_error_t cli_egg_bzip2_decompress(char* compressed, size_t compressed_size, char** decompressed, size_t* decompressed_size)
{
    cl_error_t status = CL_EPARSE;

    char* decoded   = NULL;
    uint32_t declen = 0, capacity = 0;

    bz_stream stream;
    int stream_initialized = 0;
    int bzstat;

    if (NULL == compressed || compressed_size == 0 || NULL == decompressed || NULL == decompressed_size) {
        cli_errmsg("cli_egg_bzip2_decompress: Invalid args!\n");
        status = CL_EARG;
        goto done;
    }
    if (compressed_size > CLI_MAX_ALLOCATION || compressed_size > UINT_MAX) {
        status = CL_EMAXSIZE;
        goto done;
    }

    *decompressed      = NULL;
    *decompressed_size = 0;

    if (!(decoded = (char*)calloc(BUFSIZ, sizeof(Bytef)))) {
        cli_errmsg("cli_egg_bzip2_decompress: cannot allocate memory for decompressed output\n");
        status = CL_EMEM;
        goto done;
    }

    capacity = BUFSIZ;

    memset(&stream, 0, sizeof(stream));
    stream.next_in   = compressed;
    stream.avail_in  = compressed_size;
    stream.next_out  = decoded;
    stream.avail_out = BUFSIZ;

    if (BZ_OK != (bzstat = BZ2_bzDecompressInit(&stream, 0, 0))) {
        cli_warnmsg("cli_egg_bzip2_decompress: bzinit failed\n");
        status = CL_EMEM;
        goto done;
    }
    stream_initialized = 1;

    /* initial inflate */
    bzstat = BZ2_bzDecompress(&stream);

    /* check if nothing written whatsoever */
    if ((bzstat != BZ_OK) && (stream.avail_out == BUFSIZ)) {
        /* Inflation failed */
        cli_errmsg("cli_egg_bzip2_decompress: failed to decompress data\n");
        status = CL_EPARSE;
        goto done;
    }

    while (bzstat == BZ_OK) {
        /* extend output capacity if needed,*/
        if (stream.avail_out == 0) {
            if (capacity > CLI_MAX_ALLOCATION - BUFSIZ) {
                status = CL_EMAXSIZE;
                goto done;
            }
            CLI_MAX_REALLOC_OR_GOTO_DONE(decoded, capacity + BUFSIZ,
                                         cli_errmsg("cli_egg_bzip2_decompress: cannot reallocate memory for decompressed output\n");
                                         status = CL_EMEM);
            stream.next_out  = decoded + capacity;
            stream.avail_out = BUFSIZ;
            declen += BUFSIZ;
            capacity += BUFSIZ;
        }

        /* continue inflation */
        {
            unsigned int before_in  = stream.avail_in;
            unsigned int before_out = stream.avail_out;
            bzstat                  = BZ2_bzDecompress(&stream);
            if (bzstat == BZ_OK && before_in == stream.avail_in && before_out == stream.avail_out)
                bzstat = BZ_DATA_ERROR;
        }
    }

    /* add end fragment to decoded length */
    declen += (BUFSIZ - stream.avail_out);

    /* error handling */
    switch (bzstat) {
        case BZ_STREAM_END:
            cli_dbgmsg("cli_egg_bzip2_decompress: decompressed %lu bytes from %lu total bytes (%lu bytes remaining)\n",
                       (unsigned long)declen, (unsigned long)(compressed_size), (unsigned long)(stream.avail_in));
            break;

        /* potentially fatal */
        case BZ_DATA_ERROR:
        case BZ_MEM_ERROR:
        default:
            cli_dbgmsg("cli_egg_bzip2_decompress: after decompressing %lu bytes, got error %d\n",
                       (unsigned long)declen, bzstat);

            status = (bzstat == BZ_MEM_ERROR) ? CL_EMEM : CL_EUNPACK;
            goto done;
    }

    *decompressed = (char*)decoded;
    decoded       = NULL;

    *decompressed_size = declen;

    status = CL_SUCCESS;

done:

    if (stream_initialized)
        (void)BZ2_bzDecompressEnd(&stream);

    if (NULL != decoded) {
        free(decoded);
    }

    return status;
}

cl_error_t cli_egg_lzma_decompress(char* compressed, size_t compressed_size, char** decompressed, size_t* decompressed_size)
{
    cl_error_t status = CL_EPARSE;

    uint8_t* decoded = NULL;
    uint32_t declen = 0, capacity = 0;

    struct CLI_LZMA stream;
    int stream_initialized = 0;
    int lzmastat;

    if (NULL == compressed || compressed_size == 0 || NULL == decompressed || NULL == decompressed_size) {
        cli_errmsg("cli_egg_lzma_decompress: Invalid args!\n");
        status = CL_EARG;
        goto done;
    }
    if (compressed_size > CLI_MAX_ALLOCATION || compressed_size > UINT_MAX) {
        status = CL_EMAXSIZE;
        goto done;
    }

    *decompressed      = NULL;
    *decompressed_size = 0;

    if (!(decoded = (uint8_t*)calloc(BUFSIZ, sizeof(char)))) {
        cli_errmsg("cli_egg_lzma_decompress: cannot allocate memory for decompressed output\n");
        status = CL_EMEM;
        goto done;
    }

    capacity = BUFSIZ;

    memset(&stream, 0, sizeof(stream));
    stream.next_in   = (Bytef*)compressed;
    stream.avail_in  = compressed_size;
    stream.next_out  = (Bytef*)decoded;
    stream.avail_out = BUFSIZ;

    lzmastat = cli_LzmaInit(&stream, 0);
    if (lzmastat != LZMA_RESULT_OK) {
        cli_warnmsg("cli_egg_lzma_decompress: inflateInit failed\n");
        status = CL_EMEM;
        goto done;
    }
    stream_initialized = 1;

    /* initial inflate */
    lzmastat = cli_LzmaDecode(&stream);

    /* check if nothing written whatsoever */
    if ((lzmastat != LZMA_RESULT_OK) && (stream.avail_out == BUFSIZ)) {
        /* Inflation failed */
        cli_errmsg("cli_egg_lzma_decompress: failed to decompress data\n");
        status = CL_EPARSE;
        goto done;
    }

    while (lzmastat == LZMA_RESULT_OK) {
        /* extend output capacity if needed,*/
        if (stream.avail_out == 0) {
            if (capacity > CLI_MAX_ALLOCATION - BUFSIZ) {
                status = CL_EMAXSIZE;
                goto done;
            }
            CLI_MAX_REALLOC_OR_GOTO_DONE(decoded, capacity + BUFSIZ,
                                         cli_errmsg("cli_egg_lzma_decompress: cannot reallocate memory for decompressed output\n");
                                         status = CL_EMEM);
            stream.next_out  = decoded + capacity;
            stream.avail_out = BUFSIZ;
            declen += BUFSIZ;
            capacity += BUFSIZ;
        }

        /* continue inflation */
        {
            SizeT before_in  = stream.avail_in;
            SizeT before_out = stream.avail_out;
            lzmastat         = cli_LzmaDecode(&stream);
            if (lzmastat == LZMA_RESULT_OK && before_in == stream.avail_in && before_out == stream.avail_out)
                lzmastat = LZMA_RESULT_DATA_ERROR;
        }
    }

    /* add end fragment to decoded length */
    declen += (BUFSIZ - stream.avail_out);

    /* error handling */
    switch (lzmastat) {
        case LZMA_STREAM_END:
            cli_dbgmsg("cli_egg_lzma_decompress: decompressed %lu bytes from %lu total bytes (%lu bytes remaining)\n",
                       (unsigned long)declen, (unsigned long)(compressed_size), (unsigned long)(stream.avail_in));
            break;

        /* potentially fatal */
        case LZMA_RESULT_DATA_ERROR:
        default:
            cli_dbgmsg("cli_egg_lzma_decompress: after decompressing %lu bytes, got error %d\n",
                       (unsigned long)declen, lzmastat);

            status = CL_EUNPACK;
            goto done;
    }

    *decompressed = (char*)decoded;
    decoded       = NULL;

    *decompressed_size = declen;

    status = CL_SUCCESS;

done:

    if (stream_initialized) {
        (void)cli_LzmaShutdown(&stream);
    }

    if (NULL != decoded) {
        free(decoded);
    }

    return status;
}

cl_error_t cli_egg_extract_file(void* hArchive, const char** filename, const char** output_buffer, size_t* output_buffer_length)
{
    cl_error_t status          = CL_EPARSE;
    egg_handle* handle         = NULL;
    egg_file* currFile         = NULL;
    char* decompressed         = NULL;
    uint64_t decompressed_size = 0;
    uint64_t i                 = 0;

    if (!hArchive || !filename || !output_buffer || !output_buffer_length) {
        cli_errmsg("cli_egg_extract_file: Invalid args!\n");
        status = CL_EARG;
        goto done;
    }

    *filename             = NULL;
    *output_buffer        = NULL;
    *output_buffer_length = 0;

    handle = (egg_handle*)hArchive;
    if (CL_SUCCESS != EGG_VALIDATE_HANDLE(handle)) {
        cli_errmsg("cli_egg_extract_file: Invalid handle values!\n");
        status = CL_EARG;
        goto done;
    }

    if (handle->fileExtractionIndex >= handle->nFiles) {
        cli_errmsg("cli_egg_extract_file: File index exceeds number of files in archive!\n");
        goto done;
    }

    currFile = handle->files[handle->fileExtractionIndex];
    if (NULL == currFile) {
        cli_errmsg("cli_egg_extract_file: invalid egg_file pointer!\n");
        goto done;
    }

    if (NULL == currFile->file) {
        cli_errmsg("cli_egg_extract_file: egg_file is missing file header!\n");
        goto done;
    }

    if (NULL == currFile->filename.name_utf8) {
        cli_errmsg("cli_egg_extract_file: egg_file is missing filename!\n");
        goto done;
    }

    if (handle->bSolid) {
        /*
         * TODO: Add support for extracting files from solid archives.
         *
         * For solid archives, the blocks are shared between all of the files.
         * To unpack them, we'd have to identify which block(s) each file would
         * be associated with.
         *
         * Then in theory a single file could be extracted without decompressing
         * all of the blocks at the same time.
         *
         * To be efficient about it, a block could have some sort of ref count
         * or list of associated files. Then during extraction, the decompressed
         * data for each block that is shared between files is not freed until
         * all of the files associated with that block have been extracted.
         */
        cli_warnmsg("cli_egg_extract_file: solid EGG extraction is unsupported\n");
        status = CL_EUNPACK;
        goto done;
    } else {
        const uint64_t file_length = le64_to_host(currFile->file->file_length);

        if (file_length > CLI_MAX_ALLOCATION) {
            status = CL_EMAXSIZE;
            goto done;
        }
        if ((currFile->nBlocks == 0 && file_length != 0) ||
            (currFile->nBlocks != 0 && currFile->blocks == NULL)) {
            cli_warnmsg("cli_egg_extract_file: file block table is inconsistent with file length\n");
            status = CL_EFORMAT;
            goto done;
        }
        if (currFile->nBlocks == 0) {
            cli_dbgmsg("cli_egg_extract_file: Empty file!\n");
        }

        for (i = 0; i < currFile->nBlocks; i++) {
            egg_block* currBlock = currFile->blocks[i];
            cl_error_t retval    = CL_EPARSE;
            const char* compressedData;
            uint64_t next_size;

            if (CL_SUCCESS != (status = egg_checktimelimit(handle)))
                goto done;

            if (NULL == currBlock || NULL == currBlock->blockHeader) {
                cli_errmsg("cli_egg_extract_file: current egg_block missing header!\n");
                status = CL_EFORMAT;
                goto done;
            }
            if (decompressed_size > CLI_MAX_ALLOCATION || currBlock->compressedSize == 0) {
                status = (decompressed_size > CLI_MAX_ALLOCATION) ? CL_EMAXSIZE : CL_EFORMAT;
                goto done;
            }
            if (currBlock->compressedSize > CLI_MAX_ALLOCATION ||
                currBlock->uncompressedSize > CLI_MAX_ALLOCATION) {
                cli_warnmsg("cli_egg_extract_file: block exceeds the bounded contiguous decoder limit\n");
                status = CL_EMAXSIZE;
                goto done;
            }
            compressedData = (const char*)egg_read_range(handle,
                                                        currBlock->compressedDataOffset,
                                                        currBlock->compressedSize,
                                                        &status,
                                                        "EGG compressed block is truncated",
                                                        "EGG compressed block could not be read completely");
            if (compressedData == NULL) {
                cli_warnmsg("cli_egg_extract_file: compressed block could not be read completely\n");
                goto done;
            }
            switch (currBlock->compressionAlgorithm) {
                case BLOCK_HEADER_COMPRESS_ALGORITHM_STORE: {
                    /*
                     * No compression. Woohoo!
                     */
                    if (currBlock->compressedSize == 0) {
                        cli_warnmsg("cli_egg_extract_file: blockHeader compress_size is 0!\n");
                        status = CL_EFORMAT;
                        goto done;
                    } else if (currBlock->compressedSize != currBlock->uncompressedSize) {
                        cli_warnmsg("cli_egg_extract_file: blockHeader compress_size != uncompress_size!\n");
                        status = CL_EFORMAT;
                        goto done;
                    }

                    if (currBlock->compressedSize > CLI_MAX_ALLOCATION - decompressed_size) {
                        status = CL_EMAXSIZE;
                        goto done;
                    }
                    next_size = decompressed_size + currBlock->compressedSize;
                    CLI_MAX_REALLOC_OR_GOTO_DONE(decompressed, (size_t)next_size,
                                                 cli_errmsg("cli_egg_extract_file: Failed to allocate %" PRIu64 " bytes for decompressed file!\n",
                                                            next_size),
                                                 status = CL_EMEM);

                    memcpy(decompressed + decompressed_size, compressedData, currBlock->compressedSize);
                    decompressed_size = next_size;

                    if (CL_SUCCESS != (retval = egg_check_block_crc(handle, currBlock,
                                                                      egg_crc32(decompressed +
                                                                                    decompressed_size - currBlock->compressedSize,
                                                                                currBlock->compressedSize)))) {
                        status = retval;
                        goto done;
                    }

                    retval = CL_SUCCESS;
                    break;
                }
                case BLOCK_HEADER_COMPRESS_ALGORITHM_DEFLATE: {
                    char* decompressed_block       = NULL;
                    size_t decompressed_block_size = 0;

                    if (CL_SUCCESS != (retval = cli_egg_deflate_decompress((char*)compressedData,
                                                                           currBlock->compressedSize,
                                                                           &decompressed_block,
                                                                           &decompressed_block_size))) {
                        /* Failed to decompress block */
                        cli_warnmsg("Failed to decompress RFC 1951 deflate compressed block\n");
                        status = retval;
                        goto done;
                    }
                    if (decompressed_block_size != currBlock->uncompressedSize) {
                        free(decompressed_block);
                        status = CL_EFORMAT;
                        goto done;
                    }
                    if (CL_SUCCESS != (retval = egg_check_block_crc(handle, currBlock,
                                                                      egg_crc32(decompressed_block,
                                                                                decompressed_block_size)))) {
                        free(decompressed_block);
                        status = retval;
                        goto done;
                    }
                    /* Decompressed block. Add it to the file data */
                    if (decompressed_block_size > CLI_MAX_ALLOCATION - decompressed_size) {
                        free(decompressed_block);
                        status = CL_EMAXSIZE;
                        goto done;
                    }
                    next_size = decompressed_size + decompressed_block_size;
                    CLI_MAX_REALLOC_OR_GOTO_DONE(decompressed, (size_t)next_size,
                                                 cli_errmsg("cli_egg_extract_file: Failed to allocate %" PRIu64 " bytes for decompressed file!\n",
                                                            next_size),
                                                 free(decompressed_block),
                                                 status = CL_EMEM);

                    memcpy(decompressed + decompressed_size, decompressed_block, decompressed_block_size);
                    decompressed_size = next_size;

                    free(decompressed_block);

                    retval = CL_SUCCESS;
                    break;
                }
                case BLOCK_HEADER_COMPRESS_ALGORITHM_BZIP2: {
                    char* decompressed_block       = NULL;
                    size_t decompressed_block_size = 0;

                    if (CL_SUCCESS != (retval = cli_egg_bzip2_decompress((char*)compressedData,
                                                                         currBlock->compressedSize,
                                                                         &decompressed_block,
                                                                         &decompressed_block_size))) {
                        /* Failed to decompress block */
                        cli_warnmsg("Failed to decompress BZIP2 compressed block\n");
                        status = retval;
                        goto done;
                    }
                    if (decompressed_block_size != currBlock->uncompressedSize) {
                        free(decompressed_block);
                        status = CL_EFORMAT;
                        goto done;
                    }
                    if (CL_SUCCESS != (retval = egg_check_block_crc(handle, currBlock,
                                                                      egg_crc32(decompressed_block,
                                                                                decompressed_block_size)))) {
                        free(decompressed_block);
                        status = retval;
                        goto done;
                    }
                    /* Decompressed block. Add it to the file data */
                    if (decompressed_block_size > CLI_MAX_ALLOCATION - decompressed_size) {
                        free(decompressed_block);
                        status = CL_EMAXSIZE;
                        goto done;
                    }
                    next_size = decompressed_size + decompressed_block_size;
                    CLI_MAX_REALLOC_OR_GOTO_DONE(decompressed, (size_t)next_size,
                                                 cli_errmsg("cli_egg_extract_file: Failed to allocate %" PRIu64 " bytes for decompressed file!\n",
                                                            next_size),
                                                 free(decompressed_block),
                                                 status = CL_EMEM);

                    memcpy(decompressed + decompressed_size, decompressed_block, decompressed_block_size);
                    decompressed_size = next_size;

                    free(decompressed_block);

                    retval = CL_SUCCESS;
                    break;
                }
                case BLOCK_HEADER_COMPRESS_ALGORITHM_AZO: {
                    cli_warnmsg("cli_egg_extract_file: AZO decompression not yet supported.\n");
                    status = CL_EUNPACK;
                    goto done;
                    // break;
                }
                case BLOCK_HEADER_COMPRESS_ALGORITHM_LZMA: {
                    cli_warnmsg("cli_egg_extract_file: LZMA decompression not yet supported.\n");
                    status = CL_EUNPACK;
                    goto done;
                    // char* decompressed_block       = NULL;
                    // size_t decompressed_block_size = 0;

                    // if (CL_SUCCESS != cli_egg_lzma_decompress(currBlock->compressedData,
                    //                                       currBlock->blockHeader->compress_size,
                    //                                       &decompressed_block,
                    //                                       &decompressed_block_size)) {
                    //     /* Failed to decompress block */
                    //     cli_warnmsg("Failed to decompress LZMA compressed block\n");
                    //     goto done;
                    // }
                    // /* Decompressed block. Add it to the file data */
                    // CLI_SAFER_REALLOC_OR_GOTO_DONE(decompressed,
                    //                   (size_t)decompressed_size + decompressed_block_size,
                    //                   cli_errmsg("cli_egg_extract_file: Failed to allocate %" PRIu64 " bytes for decompressed file!\n",
                    //                              decompressed_size),
                    //                   free(decompressed_block),
                    //                   status = CL_EMEM);

                    // memcpy(decompressed + decompressed_size, decompressed_block, decompressed_block_size);
                    // decompressed_size += decompressed_block_size;

                    // free(decompressed_block);

                    // retval = CL_SUCCESS;
                    // break;
                }
                default: {
                    cli_errmsg("cli_egg_extract_file: unknown compression algorithm: %d!\n",
                               currBlock->compressionAlgorithm);
                    status = CL_EFORMAT;
                    goto done;
                }
            }

            if (CL_SUCCESS != retval) {
                cli_warnmsg("cli_egg_extract_file: Unable to decompress file: %s\n",
                            currFile->filename.name_utf8);
            }

            if ((i == currFile->nBlocks - 1) &&                                     // last block ?
                (decompressed_size != file_length)) {                               // right amount of data ?
                cli_warnmsg("cli_egg_extract_file: alleged filesize (%" PRIu64 ") != actual filesize (%" PRIu64 ")!\n",
                            file_length,
                            decompressed_size);
                status = CL_EFORMAT;
                goto done;
            }
        }
    }

    cli_dbgmsg("cli_egg_extract_file: File extracted: %s\n", currFile->filename.name_utf8);
    *filename = strdup(currFile->filename.name_utf8);

    *output_buffer = decompressed;
    decompressed   = NULL;

    *output_buffer_length = decompressed_size;

    status = CL_SUCCESS;

done:
    if (NULL != handle) {
        handle->fileExtractionIndex += 1;
    }

    if (NULL != decompressed) {
        free(decompressed);
    }

    return status;
}

cl_error_t cli_egg_skip_file(void* hArchive)
{
    cl_error_t status  = CL_EPARSE;
    egg_handle* handle = NULL;

    if (!hArchive) {
        cli_errmsg("cli_egg_skip_file: Invalid args!\n");
        return CL_EARG;
    }

    handle = (egg_handle*)hArchive;
    if (CL_SUCCESS != EGG_VALIDATE_HANDLE(handle)) {
        cli_errmsg("cli_egg_skip_file: Invalid handle values!\n");
        status = CL_EARG;
        goto done;
    }

    if (CL_SUCCESS != (status = egg_checktimelimit(handle)))
        goto done;

    if (handle->fileExtractionIndex >= handle->nFiles) {
        cli_warnmsg("cli_egg_skip_file: File index exceeds number of files in archive!\n");
        status = CL_BREAK;
        goto done;
    }

    handle->fileExtractionIndex += 1;
    if (handle->fileExtractionIndex >= handle->nFiles) {
        status = CL_BREAK;
    }

    cli_dbgmsg("cli_egg_skip_file: File skipped.\n");

    status = CL_SUCCESS;
done:
    return status;
}

void cli_egg_close(void* hArchive)
{
    egg_handle* handle = NULL;

    if (!hArchive) {
        cli_errmsg("cli_egg_close: Invalid args.\n");
        return;
    }

    handle = (egg_handle*)hArchive;

    egg_free_egg_handle(handle);

    return;
}
