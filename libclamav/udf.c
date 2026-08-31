/*
 *  Copyright (C) 2023-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Author: Andy Ragusa
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

#include <string.h>

#include "clamav.h"
#include "scanners.h"
#include "udf.h"
#include "fmap.h"
#include "str.h"
#include "entconv.h"
#include "hashtab.h"

typedef enum {
    INVALID_DESCRIPTOR                          = 0,
    PRIMARY_VOLUME_DESCRIPTOR                   = 1,
    IMPLEMENTATION_USE_VOLUME_DESCRIPTOR        = 4,
    LOGICAL_VOLUME_DESCRIPTOR                   = 6,
    PARTITION_DESCRIPTOR                        = 5,
    UNALLOCATED_SPACE_DESCRIPTOR                = 7,
    TERMINATING_DESCRIPTOR                      = 8,
    LOGICAL_VOLUME_INTEGRITY_DESCRIPTOR         = 9,
    ANCHOR_VOLUME_DESCRIPTOR_DESCRIPTOR_POINTER = 2,
    FILE_SET_DESCRIPTOR                         = 256,
    FILE_IDENTIFIER_DESCRIPTOR                  = 257,
    FILE_ENTRY_DESCRIPTOR                       = 261,
    EXTENDED_FILE_ENTRY_DESCRIPTOR              = 266
} tag_identifier;

static tag_identifier getDescriptorTagId(DescriptorTag *tag)
{
    return le16_to_host(tag->tagId);
}

static uint16_t udf_descriptor_crc16(const uint8_t *data, size_t length)
{
    uint16_t crc = 0;
    size_t i;

    for (i = 0; i < length; i++) {
        unsigned int bit;

        crc ^= (uint16_t)data[i] << 8;
        for (bit = 0; bit < 8; bit++) {
            if (crc & UINT16_C(0x8000))
                crc = (uint16_t)((crc << 1) ^ UINT16_C(0x1021));
            else
                crc = (uint16_t)(crc << 1);
        }
    }

    return crc;
}

static cl_error_t udf_validate_descriptor_tag(cli_ctx *ctx, const DescriptorTag *tag,
                                              size_t descriptor_size, size_t descriptor_offset,
                                              bool validate_location)
{
    const uint8_t *tag_bytes = (const uint8_t *)tag;
    uint16_t version;
    uint16_t declared_crc;
    uint16_t crc_length;
    uint8_t checksum = 0;
    size_t i;

    if (tag == NULL || descriptor_size < sizeof(*tag)) {
        cli_mark_scan_incomplete(ctx, "UDF descriptor tag is incomplete");
        return CL_EPARSE;
    }

    version = le16_to_host(tag->descriptorVersion);
    if (version != 2U && version != 3U) {
        cli_mark_scan_incomplete(ctx, "UDF descriptor tag version is unsupported");
        return CL_EPARSE;
    }
    if (tag->reserved != 0) {
        cli_mark_scan_incomplete(ctx, "UDF descriptor tag reserved byte is invalid");
        return CL_EPARSE;
    }

    for (i = 0; i < sizeof(*tag); i++) {
        if (i != offsetof(DescriptorTag, checksum))
            checksum = (uint8_t)(checksum + tag_bytes[i]);
    }
    if (checksum != tag->checksum) {
        cli_mark_scan_incomplete(ctx, "UDF descriptor tag checksum is invalid");
        return CL_EPARSE;
    }

    crc_length   = le16_to_host(tag->descriptorCRCLength);
    declared_crc = le16_to_host(tag->descriptorCRC);
    if (crc_length > descriptor_size - sizeof(*tag)) {
        cli_mark_scan_incomplete(ctx, "UDF descriptor CRC range is invalid");
        return CL_EPARSE;
    }
    if (crc_length == 0) {
        if (declared_crc != 0) {
            cli_mark_scan_incomplete(ctx, "UDF zero-length descriptor CRC is invalid");
            return CL_EPARSE;
        }
    } else if (udf_descriptor_crc16(tag_bytes + sizeof(*tag), crc_length) != declared_crc) {
        cli_mark_scan_incomplete(ctx, "UDF descriptor CRC is invalid");
        return CL_EPARSE;
    }

    if (validate_location) {
        size_t logical_sector;

        if (descriptor_offset % VOLUME_DESCRIPTOR_SIZE != 0) {
            cli_mark_scan_incomplete(ctx, "UDF descriptor tag location is invalid");
            return CL_EPARSE;
        }
        logical_sector = descriptor_offset / VOLUME_DESCRIPTOR_SIZE;
        if (logical_sector > UINT32_MAX || le32_to_host(tag->tagLocation) != logical_sector) {
            cli_mark_scan_incomplete(ctx, "UDF descriptor tag location does not match its sector");
            return CL_EPARSE;
        }
    }

    return CL_SUCCESS;
}

static bool isDirectory(FileIdentifierDescriptor *fid)
{
    return (0 != (fid->characteristics & 2));
}

#define UDF_COPY_CHUNK_SIZE (64U * 1024U)

typedef struct {
    size_t offset;
    size_t length;
} udf_extent;

static cl_error_t udf_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t ret = cli_checktimelimit(ctx);

    if (ret != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return ret;
}

static cl_error_t writeWholeFile(cli_ctx *ctx, const char *const fileName, fmap_t *map, const udf_extent *extents,
                                 size_t extent_count, uint64_t dataLen)
{
    int fd     = -1;
    char *tmpf = NULL;
    uint8_t buffer[UDF_COPY_CHUNK_SIZE];
    uint64_t copied             = 0;
    uint64_t temporary_reserved = 0;
    size_t i;

    cl_error_t status = CL_ETMPFILE;

    if (0 == dataLen || NULL == map || NULL == extents || 0 == extent_count) {
        cli_warnmsg("writeWholeFile: Invalid arguments\n");
        status = CL_EARG;
        goto done;
    }

    if (cli_scan_reserve_temporary(ctx, dataLen) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "UDF file extent exceeds temporary storage limits");
        status = CL_ERESOURCE;
        goto done;
    }
    temporary_reserved = (uint64_t)dataLen;

    status = udf_checktimelimit(ctx, "UDF file extent temporary admission reached the configured time limit");
    if (status != CL_SUCCESS)
        goto done;

    /* Not sure if I care about the name that is actually created. */
    if (cli_gentempfd_with_prefix(ctx->this_layer_tmpdir, fileName, &tmpf, &fd) != CL_SUCCESS) {
        cli_warnmsg("writeWholeFile: Can't create temp file\n");
        cli_mark_scan_incomplete(ctx, "UDF temporary output could not be created");
        status = CL_ETMPFILE;
        goto done;
    }

    for (i = 0; i < extent_count; i++) {
        size_t extent_copied = 0;

        if (extents[i].offset > map->len || extents[i].length > map->len - extents[i].offset) {
            cli_warnmsg("writeWholeFile: Invalid UDF extent range\n");
            cli_mark_scan_incomplete(ctx, "UDF file extent is outside the input map");
            status = CL_EPARSE;
            goto done;
        }

        while (extent_copied < extents[i].length) {
            size_t chunk = MIN(sizeof(buffer), extents[i].length - extent_copied);

            status = cli_checktimelimit(ctx);
            if (status != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "UDF file extent scan timed out");
                goto done;
            }
            if (fmap_readn(map, buffer, extents[i].offset + extent_copied, chunk) != chunk) {
                cli_warnmsg("writeWholeFile: Can't read the complete UDF extent\n");
                cli_mark_scan_incomplete(ctx, "UDF file extent could not be read completely");
                status = CL_EREAD;
                goto done;
            }
            status = udf_checktimelimit(ctx, "UDF file extent output reached the configured time limit");
            if (status != CL_SUCCESS)
                goto done;
            if (cli_writen(fd, buffer, chunk) != chunk) {
                cli_warnmsg("writeWholeFile: Can't write to file %s\n", tmpf);
                cli_mark_scan_incomplete(ctx, "UDF file extent could not be written completely");
                status = CL_EWRITE;
                goto done;
            }
            extent_copied += chunk;
            copied += chunk;
        }
    }

    if (copied != dataLen) {
        cli_warnmsg("writeWholeFile: UDF extent lengths did not match the aggregate length\n");
        cli_mark_scan_incomplete(ctx, "UDF extent length accounting failed");
        status = CL_EPARSE;
        goto done;
    }

    status = cli_magic_scan_desc_type_reserved(fd, tmpf, ctx, CL_TYPE_ANY, fileName, LAYER_ATTRIBUTES_NONE);

done:
    if (-1 != fd) {
        if (close(fd) != 0) {
            cli_mark_scan_incomplete(ctx, "UDF temporary output could not be closed");
            status = cli_merge_cleanup_status(status, CL_EWRITE);
        }
        fd = -1;
    }
    if (!ctx->engine->keeptmp) {
        if (NULL != tmpf) {
            if (cli_unlink(tmpf)) {
                cli_mark_scan_incomplete(ctx, "UDF temporary output could not be removed");
                status = cli_merge_cleanup_status(status, CL_EUNLINK);
            }
        }
    }

    CLI_FREE_AND_SET_NULL(tmpf);

    if (temporary_reserved)
        cli_scan_release_temporary(ctx, temporary_reserved);

    return status;
}

static cl_error_t getUDFExtentRange(cli_ctx *ctx, PartitionDescriptor *pPartitionDescriptor,
                                    LogicalVolumeDescriptor *pLogicalVolumeDescriptor, const void *allocation_descriptor,
                                    uint16_t icbFlags, udf_extent *extent)
{
    size_t length                      = 0;
    uint32_t partitionStartingLocation = 0;
    uint32_t partitionLength           = 0;
    uint32_t logicalBlockSize          = 0;
    uint64_t offset64                  = 0;
    uint64_t partitionOffset           = 0;
    uint64_t extentOffset              = 0;
    uint32_t rawLength                 = 0;
    uint32_t extentType                = 0;
    uint32_t extentBlock               = 0;
    uint32_t recordedLength            = 0;
    uint32_t extentInformationLength = 0;
    bool hasRecordedLength           = false;
    bool hasInformationLength        = false;

    if (NULL == ctx || NULL == ctx->fmap || NULL == pPartitionDescriptor || NULL == pLogicalVolumeDescriptor ||
        NULL == allocation_descriptor || NULL == extent) {
        return CL_EARG;
    }

    partitionStartingLocation = le32_to_host(pPartitionDescriptor->partitionStartingLocation);
    partitionLength           = le32_to_host(pPartitionDescriptor->partitionLength);
    logicalBlockSize           = le32_to_host(pLogicalVolumeDescriptor->logicalBlockSize);

    switch (icbFlags & 7U) {
        case 0: {
            const short_ad *shortDesc = (const short_ad *)allocation_descriptor;

            extentBlock = le32_to_host(shortDesc->position);
            rawLength   = le32_to_host(shortDesc->length);
        } break;
        case 1: {
            const long_ad *longDesc = (const long_ad *)allocation_descriptor;

            extentBlock = le32_to_host(longDesc->extentLocation.blockNumber);
            rawLength   = le32_to_host(longDesc->length);

            if (le16_to_host(longDesc->extentLocation.partitionReferenceNumber) != le16_to_host(pPartitionDescriptor->partitionNumber)) {
                cli_warnmsg("extractFile: Unable to extract the files because the Partition Descriptor Reference Numbers don't match\n");
                cli_mark_scan_incomplete(ctx, "UDF allocation descriptor partition reference does not match");
                return CL_EPARSE;
            }
        } break;
        case 2: {
            const ext_ad *extDesc = (const ext_ad *)allocation_descriptor;

            extentBlock              = le32_to_host(extDesc->extentLocation.blockNumber);
            rawLength                = le32_to_host(extDesc->extentLen);
            recordedLength           = le32_to_host(extDesc->recordedLen);
            extentInformationLength = le32_to_host(extDesc->infoLen);
            hasRecordedLength       = true;
            hasInformationLength    = true;

            if (le16_to_host(extDesc->extentLocation.partitionReferenceNumber) != le16_to_host(pPartitionDescriptor->partitionNumber)) {
                cli_warnmsg("extractFile: Unable to extract the files because the Partition Descriptor Reference Numbers don't match\n");
                cli_mark_scan_incomplete(ctx, "UDF allocation descriptor partition reference does not match");
                return CL_EPARSE;
            }
        } break;
        default:
            cli_warnmsg("extractFile: Embedded or unknown allocation descriptor type is unsupported.\n");
            cli_mark_scan_incomplete(ctx, "UDF allocation descriptor type is unsupported");
            return CL_EUNPACK;
    }

    extentType = rawLength >> 30;
    length     = rawLength & UINT32_C(0x3fffffff);
    if (extentType != 0) {
        cli_warnmsg("extractFile: UDF extent is not recorded and allocated data.\n");
        cli_mark_scan_incomplete(ctx, "UDF non-recorded or continuation extent is unsupported");
        return CL_EUNPACK;
    }
    if (hasRecordedLength) {
        if (recordedLength > length) {
            cli_warnmsg("extractFile: Recorded length exceeds the UDF extent length.\n");
            cli_mark_scan_incomplete(ctx, "UDF recorded length exceeds its extent");
            return CL_EPARSE;
        }
        if (hasInformationLength && recordedLength != extentInformationLength) {
            cli_warnmsg("extractFile: UDF extended allocation descriptor requires an unsupported transformation.\n");
            cli_mark_scan_incomplete(ctx, "UDF extended allocation descriptor transformation is unsupported");
            return CL_EUNPACK;
        }
        length = recordedLength;
    }

    if (logicalBlockSize == 0) {
        cli_warnmsg("extractFile: Logical block size is zero.\n");
        cli_mark_scan_incomplete(ctx, "UDF logical block size is invalid");
        return CL_EPARSE;
    }

    extentOffset    = (uint64_t)extentBlock * logicalBlockSize;
    if (extentOffset > (uint64_t)partitionLength * logicalBlockSize ||
        length > (uint64_t)partitionLength * logicalBlockSize - extentOffset) {
        cli_warnmsg("extractFile: Allocation descriptor extent exceeds the UDF partition.\n");
        cli_mark_scan_incomplete(ctx, "UDF file extent is outside the declared partition");
        return CL_EPARSE;
    }

    extent->offset = 0;
    extent->length = length;
    if (0 == length)
        return CL_SUCCESS;

    partitionOffset = (uint64_t)partitionStartingLocation * logicalBlockSize;
    if (UINT64_MAX - partitionOffset < extentOffset) {
        cli_warnmsg("extractFile: Allocation descriptor offset arithmetic overflowed.\n");
        cli_mark_scan_incomplete(ctx, "UDF file extent offset overflowed");
        return CL_EPARSE;
    }
    offset64 = partitionOffset + extentOffset;

    if (offset64 > SIZE_MAX || (size_t)offset64 > ctx->fmap->len || length > ctx->fmap->len - (size_t)offset64) {
        cli_warnmsg("extractFile: Allocation descriptor extent exceeds the fmap range.\n");
        cli_mark_scan_incomplete(ctx, "UDF file extent is outside the input map");
        return CL_EPARSE;
    }
    extent->offset = (size_t)offset64;

    return CL_SUCCESS;
}

static cl_error_t extractFile(cli_ctx *ctx, PartitionDescriptor *pPartitionDescriptor, LogicalVolumeDescriptor *pLogicalVolumeDescriptor,
                              void *allocation_descriptor,
                              size_t allocation_descriptor_len,
                              uint16_t icbFlags, uint64_t information_length,
                              FileIdentifierDescriptor *fileIdentifierDescriptor)
{
    cl_error_t ret = CL_EPARSE;
    udf_extent *extents = NULL;
    size_t descriptor_size;
    size_t extent_count;
    size_t i;
    uint64_t total_length = 0;

    if (isDirectory(fileIdentifierDescriptor)) {
        cli_warnmsg("extractFile: UDF directory traversal is unsupported.\n");
        cli_mark_scan_incomplete(ctx, "UDF directory traversal is unsupported");
        ret = CL_EUNPACK;
        goto done;
    }

    switch (icbFlags & 7U) {
        case 0:
            descriptor_size = sizeof(short_ad);
            break;
        case 1:
            descriptor_size = sizeof(long_ad);
            break;
        case 2:
            descriptor_size = sizeof(ext_ad);
            break;
        default:
            cli_warnmsg("extractFile: Embedded or unknown allocation descriptor type is unsupported.\n");
            cli_mark_scan_incomplete(ctx, "UDF allocation descriptor type is unsupported");
            return CL_EUNPACK;
    }

    if (0 == allocation_descriptor_len) {
        if (0 != information_length) {
            cli_warnmsg("extractFile: UDF allocation extents do not match the declared information length.\n");
            cli_mark_scan_incomplete(ctx, "UDF allocation extents do not match declared information length");
            ret = CL_EPARSE;
            goto done;
        }
        ret = CL_SUCCESS;
        goto done;
    }

    if (allocation_descriptor_len % descriptor_size != 0) {
        cli_warnmsg("extractFile: Allocation Descriptor Length is not aligned to its descriptor type.\n");
        cli_mark_scan_incomplete(ctx, "UDF allocation descriptor length is not aligned");
        ret = CL_EPARSE;
        goto done;
    }

    extent_count = allocation_descriptor_len / descriptor_size;
    if (extent_count > SIZE_MAX / sizeof(*extents)) {
        cli_warnmsg("extractFile: Too many UDF allocation descriptors.\n");
        cli_mark_scan_incomplete(ctx, "UDF allocation descriptor list is too large");
        ret = CL_EMEM;
        goto done;
    }

    extents = cli_max_calloc(extent_count, sizeof(*extents));
    if (NULL == extents) {
        cli_mark_scan_incomplete(ctx, "UDF allocation descriptor list could not be allocated");
        ret = CL_EMEM;
        goto done;
    }

    for (i = 0; i < extent_count; i++) {
        ret = udf_checktimelimit(ctx, "UDF allocation-descriptor traversal reached the configured time limit");
        if (ret != CL_SUCCESS)
            goto done;

        ret = getUDFExtentRange(ctx, pPartitionDescriptor, pLogicalVolumeDescriptor,
                                (const uint8_t *)allocation_descriptor + (i * descriptor_size), icbFlags, &extents[i]);
        if (ret != CL_SUCCESS)
            goto done;

        if (total_length > UINT64_MAX - extents[i].length) {
            cli_warnmsg("extractFile: Aggregate UDF extent length overflowed.\n");
            cli_mark_scan_incomplete(ctx, "UDF aggregate extent length overflowed");
            ret = CL_EPARSE;
            goto done;
        }
        total_length += extents[i].length;
    }

    if (total_length != information_length) {
        cli_warnmsg("extractFile: UDF allocation extents do not match the declared information length.\n");
        cli_mark_scan_incomplete(ctx, "UDF allocation extents do not match declared information length");
        ret = CL_EPARSE;
        goto done;
    }

    if (0 == total_length) {
        ret = CL_SUCCESS;
        goto done;
    }

    ret = cli_checklimits("UDF", ctx, total_length, 0, 0);
    if (ret != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "UDF file extent exceeds configured scan limits");
        goto done;
    }

    ret = writeWholeFile(ctx, "", ctx->fmap, extents, extent_count, total_length);

done:
    CLI_FREE_AND_SET_NULL(extents);
    return ret;
}

static cl_error_t parseFileEntryDescriptor(cli_ctx *ctx, FileEntryDescriptor *fed, PartitionDescriptor *pPartitionDescriptor, LogicalVolumeDescriptor *pLogicalVolumeDescriptor, FileIdentifierDescriptor *fileIdentifierDescriptor)
{
    cl_error_t ret              = CL_EPARSE;
    uint16_t tagId              = getDescriptorTagId(&fed->tag);
    void *allocation_descriptor = NULL;

    size_t file_entry_descriptor_size;
    size_t allocation_descriptor_len;

    if (FILE_ENTRY_DESCRIPTOR != tagId) {
        cli_warnmsg("parseFileEntryDescriptor: Tag ID of 0x%x does not match File Entry Descriptor.\n", tagId);
        goto done;
    }

    tagId = getDescriptorTagId(&fileIdentifierDescriptor->tag);
    if (FILE_IDENTIFIER_DESCRIPTOR != tagId) {
        cli_warnmsg("parseFileEntryDescriptor: Tag ID of 0x%x does not match File Identifier Descriptor.\n", tagId);
        goto done;
    }

    // Calculate pointer for the allocation descriptor.
    // The allocation descriptors are the last bytes of the Extended File Entry.
    // See Section 14.17 in https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf
    if (!getFileEntryDescriptorSize(fed, &file_entry_descriptor_size)) {
        cli_mark_scan_incomplete(ctx, "UDF file-entry descriptor size overflowed");
        ret = CL_EFORMAT;
        goto done;
    }
    allocation_descriptor_len  = le32_to_host(fed->allocationDescLen);

    if (allocation_descriptor_len > file_entry_descriptor_size) {
        cli_dbgmsg("parseFileEntryDescriptor: Allocation Descriptor Length is greater than the File Entry Descriptor Size.\n");
        cli_mark_scan_incomplete(ctx, "UDF allocation descriptor length is invalid");
        goto done;
    }
    allocation_descriptor = (void *)((uint8_t *)fed + (file_entry_descriptor_size - allocation_descriptor_len));

    // The Allocation Descriptor was taken from the end of the  File Entry Descriptor.
    // We already verified that the File Entry Descriptor is within the fmap,
    // so it's safe to say the Allocation Descriptor is also within the fmap.
    // No need to use an `fmap_need...()` function here.

    // Extract the file.
    ret = extractFile(ctx, pPartitionDescriptor, pLogicalVolumeDescriptor,
                      allocation_descriptor,
                      allocation_descriptor_len,
                      le16_to_host(fed->icbTag.flags), le64_to_host(fed->infoLength), fileIdentifierDescriptor);
    if (CL_SUCCESS != ret) {
        cli_dbgmsg("parseFileEntryDescriptor: Failed to extract file.\n");
        goto done;
    }
done:
    return ret;
}

/* A File Identifier Descriptor names the ICB that describes its file.  For a
 * direct File Entry, the descriptor tag records the same partition-relative
 * logical block location.  The scanner collects FIDs and File Entries from
 * separate bounded runs, so list position is not an authoritative pairing. */
static bool fileEntryMatchesIdentifier(const FileEntryDescriptor *fed,
                                       const FileIdentifierDescriptor *fid,
                                       const PartitionDescriptor *partition)
{
    return le32_to_host(fed->tag.tagLocation) ==
               le32_to_host(fid->icb.extentLocation.blockNumber) &&
           le16_to_host(partition->partitionNumber) ==
               le16_to_host(fid->icb.extentLocation.partitionReferenceNumber);
}

/*
// Uncomment for debugging.
static void dumpTag (DescriptorTag *dt)
{
    fprintf(stderr, "TagId = %d (0x%x)\n", dt->tagId, dt->tagId);
    fprintf(stderr, "Version = %d (0x%x)\n", dt->descriptorVersion, dt->descriptorVersion);
    fprintf(stderr, "Checksum = %d (0x%x)\n", dt->checksum, dt->checksum);
    fprintf(stderr, "Serial Number = %d (0x%x)\n", dt->serialNumber, dt->serialNumber);

    fprintf(stderr, "Descriptor CRC = %d (0x%x)\n", dt->descriptorCRC, dt->descriptorCRC);
    fprintf(stderr, "Descriptor CRC Length = %d (0x%x)\n", dt->descriptorCRCLength, dt->descriptorCRCLength);
    fprintf(stderr, "Tag Location = %d (0x%x)\n", dt->tagLocation, dt->tagLocation);
}
*/

#define NUM_GENERIC_VOLUME_DESCRIPTORS 3

/* fmap_need_off() uses NULL for both an unavailable range and a failed
 * backing read.  Keep those cases distinct while the descriptor helpers walk
 * a UDF volume so an operational failure cannot be reported as a malformed
 * volume. */
static const void *udf_need_off(cli_ctx *ctx, size_t offset, size_t length, cl_error_t *read_status)
{
    const void *ptr;

    if (read_status != NULL)
        *read_status = CL_EPARSE;
    if (ctx == NULL || ctx->fmap == NULL || length == 0 || offset > ctx->fmap->len ||
        length > ctx->fmap->len - offset)
        return NULL;

    ptr = fmap_need_off(ctx->fmap, offset, length);

    if (NULL == ptr) {
        if (read_status != NULL)
            *read_status = CL_EREAD;
    } else if (read_status != NULL) {
        *read_status = CL_SUCCESS;
    }

    return ptr;
}

/* If this function fails, idx will not be updated */
static bool skipEmptyDescriptors(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp, cl_error_t *read_status)
{
    bool ret        = false;
    uint8_t *buffer = NULL;
    size_t idx      = *idxp;
    bool allzeros   = true;
    size_t i;

    while (1) {
        if (udf_checktimelimit(ctx, "UDF empty-descriptor traversal reached the configured time limit") != CL_SUCCESS) {
            *read_status = CL_ETIMEOUT;
            goto done;
        }

        buffer = (uint8_t *)udf_need_off(ctx, idx, VOLUME_DESCRIPTOR_SIZE, read_status);
        if (NULL == buffer) {
            goto done;
        }

        allzeros = true;
        for (i = 0; i < VOLUME_DESCRIPTOR_SIZE; i++) {
            if (0 != buffer[i]) {
                allzeros = false;
                break;
            }
        }
        if (!allzeros) {
            fmap_unneed_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
            buffer = NULL;
            break;
        }
        fmap_unneed_off(ctx->fmap, idx, VOLUME_DESCRIPTOR_SIZE);
        buffer = NULL;
        if (idx > SIZE_MAX - VOLUME_DESCRIPTOR_SIZE)
            goto done;
        idx += VOLUME_DESCRIPTOR_SIZE;
    }

    ret = true;
done:

    *idxp        = idx;
    *lastOffsetp = idx;

    return ret;
}

/* Skip past all the empty descriptors and find the PrimaryVolumeDescriptor.
 * Return error if the next non-empty descriptor is not a PrimaryVolumeDescriptor. */
static PrimaryVolumeDescriptor *getPrimaryVolumeDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp,
                                                           cl_error_t *read_status)
{
    PrimaryVolumeDescriptor *test = NULL;
    PrimaryVolumeDescriptor *ret  = NULL;
    size_t idx                    = *idxp;
    size_t lastOffset             = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp, read_status)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (PrimaryVolumeDescriptor *)udf_need_off(ctx, idx, VOLUME_DESCRIPTOR_SIZE, read_status);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (PRIMARY_VOLUME_DESCRIPTOR != getDescriptorTagId(&test->tag) ||
        CL_SUCCESS != udf_validate_descriptor_tag(ctx, &test->tag, VOLUME_DESCRIPTOR_SIZE, idx, true)) {
        fmap_unneed_ptr(ctx->fmap, test, VOLUME_DESCRIPTOR_SIZE);
        goto done;
    }

    idx += VOLUME_DESCRIPTOR_SIZE;
    ret = test;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

/* Skip past all the empty descriptors and find the ImplementationUseVolumeDescriptor.
 * Return error if the next non-empty descriptor is not an ImplementationUseVolumeDescriptor. */
static ImplementationUseVolumeDescriptor *getImplementationUseVolumeDescriptor(cli_ctx *ctx, size_t *idxp,
                                                                                 size_t *lastOffsetp,
                                                                                 cl_error_t *read_status)
{
    ImplementationUseVolumeDescriptor *test = NULL;
    ImplementationUseVolumeDescriptor *ret  = NULL;
    size_t idx                              = *idxp;
    size_t lastOffset                       = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp, read_status)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (ImplementationUseVolumeDescriptor *)udf_need_off(ctx, idx, VOLUME_DESCRIPTOR_SIZE, read_status);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (IMPLEMENTATION_USE_VOLUME_DESCRIPTOR != getDescriptorTagId(&test->tag) ||
        CL_SUCCESS != udf_validate_descriptor_tag(ctx, &test->tag, VOLUME_DESCRIPTOR_SIZE, idx, true)) {
        fmap_unneed_ptr(ctx->fmap, test, VOLUME_DESCRIPTOR_SIZE);
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

/* Skip past all the empty descriptors and find the LogicalVolumeDescriptor.
 * Return error if the next non-empty descriptor is not a LogicalVolumeDescriptor. */
static LogicalVolumeDescriptor *getLogicalVolumeDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp,
                                                           cl_error_t *read_status)
{
    LogicalVolumeDescriptor *ret  = NULL;
    LogicalVolumeDescriptor *test = NULL;
    size_t idx                    = *idxp;
    size_t lastOffset             = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp, read_status)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (LogicalVolumeDescriptor *)udf_need_off(ctx, idx, VOLUME_DESCRIPTOR_SIZE, read_status);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (LOGICAL_VOLUME_DESCRIPTOR != getDescriptorTagId(&test->tag) ||
        CL_SUCCESS != udf_validate_descriptor_tag(ctx, &test->tag, VOLUME_DESCRIPTOR_SIZE, idx, true)) {
        fmap_unneed_ptr(ctx->fmap, test, VOLUME_DESCRIPTOR_SIZE);
        goto done;
    }

    idx += VOLUME_DESCRIPTOR_SIZE;
    ret = test;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

/* Skip past all the empty descriptors and find the PartitionDescriptor.
 * Return error if the next non-empty descriptor is not a PartitionDescriptor. */
static PartitionDescriptor *getPartitionDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp,
                                                    cl_error_t *read_status)
{
    PartitionDescriptor *ret  = NULL;
    PartitionDescriptor *test = NULL;
    size_t idx                = *idxp;
    size_t lastOffset         = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp, read_status)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (PartitionDescriptor *)udf_need_off(ctx, idx, VOLUME_DESCRIPTOR_SIZE, read_status);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (PARTITION_DESCRIPTOR != getDescriptorTagId(&test->tag) ||
        CL_SUCCESS != udf_validate_descriptor_tag(ctx, &test->tag, VOLUME_DESCRIPTOR_SIZE, idx, true)) {
        fmap_unneed_ptr(ctx->fmap, test, VOLUME_DESCRIPTOR_SIZE);
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

/* Skip past all the empty descriptors and find the UnallocatedSpaceDescriptor.
 * Return error if the next non-empty descriptor is not a UnallocatedSpaceDescriptor. */
static UnallocatedSpaceDescriptor *getUnallocatedSpaceDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp,
                                                                  cl_error_t *read_status)
{
    UnallocatedSpaceDescriptor *ret  = NULL;
    UnallocatedSpaceDescriptor *test = NULL;
    size_t idx                       = *idxp;
    size_t lastOffset                = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp, read_status)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (UnallocatedSpaceDescriptor *)udf_need_off(ctx, idx, VOLUME_DESCRIPTOR_SIZE, read_status);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (UNALLOCATED_SPACE_DESCRIPTOR != getDescriptorTagId(&test->tag) ||
        CL_SUCCESS != udf_validate_descriptor_tag(ctx, &test->tag, VOLUME_DESCRIPTOR_SIZE, idx, true)) {
        fmap_unneed_ptr(ctx->fmap, test, VOLUME_DESCRIPTOR_SIZE);
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

/* Skip past all the empty descriptors and find the TerminatingDescriptor.
 * Return error if the next non-empty descriptor is not a TerminatingDescriptor. */
static TerminatingDescriptor *getTerminatingDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp,
                                                       cl_error_t *read_status)
{
    TerminatingDescriptor *ret  = NULL;
    TerminatingDescriptor *test = NULL;
    size_t idx                  = *idxp;
    size_t lastOffset           = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp, read_status)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (TerminatingDescriptor *)udf_need_off(ctx, idx, VOLUME_DESCRIPTOR_SIZE, read_status);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (TERMINATING_DESCRIPTOR != getDescriptorTagId(&test->tag) ||
        CL_SUCCESS != udf_validate_descriptor_tag(ctx, &test->tag, VOLUME_DESCRIPTOR_SIZE, idx, true)) {
        fmap_unneed_ptr(ctx->fmap, test, VOLUME_DESCRIPTOR_SIZE);
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

/* Skip past all the empty descriptors and find the LogicalVolumeIntegrityDescriptor.
 * Return error if the next non-empty descriptor is not a LogicalVolumeIntegrityDescriptor. */
static LogicalVolumeIntegrityDescriptor *getLogicalVolumeIntegrityDescriptor(cli_ctx *ctx, size_t *idxp,
                                                                              size_t *lastOffsetp,
                                                                              cl_error_t *read_status)
{
    LogicalVolumeIntegrityDescriptor *ret  = NULL;
    LogicalVolumeIntegrityDescriptor *test = NULL;
    size_t idx                             = *idxp;
    size_t lastOffset                      = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp, read_status)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (LogicalVolumeIntegrityDescriptor *)udf_need_off(ctx, idx, VOLUME_DESCRIPTOR_SIZE, read_status);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (LOGICAL_VOLUME_INTEGRITY_DESCRIPTOR != getDescriptorTagId(&test->tag) ||
        CL_SUCCESS != udf_validate_descriptor_tag(ctx, &test->tag, VOLUME_DESCRIPTOR_SIZE, idx, true)) {
        fmap_unneed_ptr(ctx->fmap, test, VOLUME_DESCRIPTOR_SIZE);
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

/* Skip past all the empty descriptors and find the AnchorVolumeDescriptor.
 * Return error if the next non-empty descriptor is not an AnchorVolumeDescriptor. */
static AnchorVolumeDescriptorPointer *getAnchorVolumeDescriptorPointer(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp,
                                                                        cl_error_t *read_status)
{
    AnchorVolumeDescriptorPointer *ret  = NULL;
    AnchorVolumeDescriptorPointer *test = NULL;
    size_t idx                          = *idxp;
    size_t lastOffset                   = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp, read_status)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (AnchorVolumeDescriptorPointer *)udf_need_off(ctx, idx, VOLUME_DESCRIPTOR_SIZE, read_status);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (ANCHOR_VOLUME_DESCRIPTOR_DESCRIPTOR_POINTER != getDescriptorTagId(&test->tag) ||
        CL_SUCCESS != udf_validate_descriptor_tag(ctx, &test->tag, VOLUME_DESCRIPTOR_SIZE, idx, true)) {
        fmap_unneed_ptr(ctx->fmap, test, VOLUME_DESCRIPTOR_SIZE);
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

/* Skip past all the empty descriptors and find the FileSetDescriptor.
 * Return error if the next non-empty descriptor is not a FileSetDescriptor. */
static FileSetDescriptor *getFileSetDescriptor(cli_ctx *ctx, size_t *idxp, size_t *lastOffsetp, cl_error_t *read_status)
{
    FileSetDescriptor *ret  = NULL;
    FileSetDescriptor *test = NULL;
    size_t idx              = *idxp;
    size_t lastOffset       = *lastOffsetp;

    if (!skipEmptyDescriptors(ctx, idxp, lastOffsetp, read_status)) {
        goto done;
    }

    idx        = *idxp;
    lastOffset = *lastOffsetp;

    test = (FileSetDescriptor *)udf_need_off(ctx, idx, VOLUME_DESCRIPTOR_SIZE, read_status);
    if (NULL == test) {
        goto done;
    }
    lastOffset = idx;

    if (FILE_SET_DESCRIPTOR != getDescriptorTagId(&test->tag) ||
        CL_SUCCESS != udf_validate_descriptor_tag(ctx, &test->tag, VOLUME_DESCRIPTOR_SIZE, idx, false)) {
        fmap_unneed_ptr(ctx->fmap, test, VOLUME_DESCRIPTOR_SIZE);
        goto done;
    }

    ret = test;
    idx += VOLUME_DESCRIPTOR_SIZE;

done:
    *idxp        = idx;
    *lastOffsetp = lastOffset;

    return ret;
}

typedef struct {

    uint8_t **idxs;

    uint32_t cnt;

    uint32_t capacity;

} PointerList;
#define POINTER_LIST_INCREMENT 1024

static void freePointerList(PointerList *pl)
{
    uint32_t i;

    for (i = 0; i < pl->cnt; i++)
        CLI_FREE_AND_SET_NULL(pl->idxs[i]);
    CLI_FREE_AND_SET_NULL(pl->idxs);
    memset(pl, 0, sizeof(PointerList));
}

static cl_error_t initPointerList(PointerList *pl)
{
    cl_error_t ret    = CL_SUCCESS;
    uint32_t capacity = POINTER_LIST_INCREMENT;

    freePointerList(pl);
    CLI_CALLOC_OR_GOTO_DONE(pl->idxs, capacity, sizeof(uint8_t *),
                            cli_errmsg("initPointerList: Can't allocate memory\n"),
                            ret = CL_EMEM);

    pl->capacity = capacity;
done:
    return ret;
}

static cl_error_t insertPointer(PointerList *pl, const uint8_t *pointer, size_t size)
{
    cl_error_t ret = CL_SUCCESS;
    uint8_t *copy  = NULL;

    if (NULL == pointer || 0 == size || size > VOLUME_DESCRIPTOR_SIZE)
        return CL_EARG;

    if (pl->cnt >= pl->capacity) {
        if (pl->capacity > (CLI_MAX_ALLOCATION / sizeof(uint8_t *)) - POINTER_LIST_INCREMENT) {
            return CL_EMEM;
        }
        uint32_t newCapacity = pl->capacity + POINTER_LIST_INCREMENT;
        CLI_SAFER_REALLOC_OR_GOTO_DONE(pl->idxs, newCapacity * sizeof(uint8_t *),
                                       cli_errmsg("insertPointer: Can't allocate memory\n");
                                       ret = CL_EMEM);

        pl->capacity = newCapacity;
    }

    copy = cli_max_malloc(size);
    if (NULL == copy) {
        ret = CL_EMEM;
        goto done;
    }
    memcpy(copy, pointer, size);
    pl->idxs[pl->cnt++] = copy;

done:
    return ret;
}

static cl_error_t findFileIdentifiers(cli_ctx *ctx, const uint8_t *const input, PointerList *pfil)
{
    cl_error_t ret        = CL_SUCCESS;
    const uint8_t *buffer = input;
    uint16_t tagId        = getDescriptorTagId((DescriptorTag *)buffer);
    size_t bufUsed;
    size_t fidDescSize;

    ret = udf_checktimelimit(ctx, "UDF file-identifier traversal reached the configured time limit");
    if (ret != CL_SUCCESS)
        return ret;

    while (FILE_IDENTIFIER_DESCRIPTOR == tagId) {
        ret = udf_checktimelimit(ctx, "UDF file-identifier traversal reached the configured time limit");
        if (ret != CL_SUCCESS)
            break;

        /* This is how far into the Volume we already are. */
        bufUsed     = buffer - input;
        if (!getFileIdentifierDescriptorSize((FileIdentifierDescriptor *)buffer, &fidDescSize)) {
            cli_mark_scan_incomplete(ctx, "UDF file-identifier descriptor size overflowed");
            ret = CL_EFORMAT;
            break;
        }

        /* Check that it's safe to save the file identifier pointer for later use */
        if (bufUsed > VOLUME_DESCRIPTOR_SIZE || fidDescSize > VOLUME_DESCRIPTOR_SIZE - bufUsed) {
            cli_mark_scan_incomplete(ctx, "UDF file-identifier descriptor exceeds its volume block");
            ret = CL_EPARSE;
            break;
        }
        ret = udf_validate_descriptor_tag(ctx, (const DescriptorTag *)buffer,
                                          fidDescSize, 0, false);
        if (ret != CL_SUCCESS)
            break;

        /* Add the buffer to the list of file identifier pointers */
        if (CL_SUCCESS != (ret = insertPointer(pfil, buffer, fidDescSize))) {
            goto done;
        }

        /* Check that it's safe to read the TagID from the header of the next FileIdentifierDescriptor (if one exists) */
        if (FILE_IDENTIFIER_DESCRIPTOR_SIZE_KNOWN > VOLUME_DESCRIPTOR_SIZE - bufUsed - fidDescSize) {
            break;
        }

        buffer = buffer + fidDescSize;
        tagId  = getDescriptorTagId((DescriptorTag *)buffer);
    }

done:
    return ret;
}

static cl_error_t findFileEntries(cli_ctx *ctx, const uint8_t *const input, PointerList *pfil)
{
    cl_error_t ret        = CL_SUCCESS;
    const uint8_t *buffer = input;
    uint16_t tagId        = getDescriptorTagId((DescriptorTag *)buffer);
    size_t bufUsed;
    size_t fedDescSize;

    ret = udf_checktimelimit(ctx, "UDF file-entry traversal reached the configured time limit");
    if (ret != CL_SUCCESS)
        return ret;

    while (FILE_ENTRY_DESCRIPTOR == tagId) {
        ret = udf_checktimelimit(ctx, "UDF file-entry traversal reached the configured time limit");
        if (ret != CL_SUCCESS)
            break;

        /* This is how far into the Volume we already are. */
        bufUsed     = buffer - input;
        if (!getFileEntryDescriptorSize((FileEntryDescriptor *)buffer, &fedDescSize)) {
            cli_mark_scan_incomplete(ctx, "UDF file-entry descriptor size overflowed");
            ret = CL_EFORMAT;
            break;
        }

        /* Check that it's safe to save the file identifier pointer for later use */
        if (bufUsed > VOLUME_DESCRIPTOR_SIZE || fedDescSize > VOLUME_DESCRIPTOR_SIZE - bufUsed) {
            cli_mark_scan_incomplete(ctx, "UDF file-entry descriptor exceeds its volume block");
            ret = CL_EPARSE;
            break;
        }
        ret = udf_validate_descriptor_tag(ctx, (const DescriptorTag *)buffer,
                                          fedDescSize, 0, false);
        if (ret != CL_SUCCESS)
            break;

        /* Add the buffer to the list of file entry pointers */
        if (CL_SUCCESS != (ret = insertPointer(pfil, buffer, fedDescSize))) {
            goto done;
        }

        /* Check that it's safe to read the TagID from the header of the next FileEntryDescriptor (if one exists) */
        if (FILE_ENTRY_DESCRIPTOR_SIZE_KNOWN > VOLUME_DESCRIPTOR_SIZE - bufUsed - fedDescSize) {
            break;
        }

        buffer = buffer + fedDescSize;
        tagId  = getDescriptorTagId((DescriptorTag *)buffer);
    }

done:
    return ret;
}

cl_error_t cli_scanudf(cli_ctx *ctx, const size_t offset)
{
    cl_error_t ret                          = CL_SUCCESS;
    size_t idx                              = offset;
    size_t lastOffset                       = 0;
    size_t i                                = 0;
    PrimaryVolumeDescriptor *pvd            = NULL;
    GenericVolumeStructureDescriptor *gvsd  = NULL;
    ImplementationUseVolumeDescriptor *iuvd = NULL;
    LogicalVolumeDescriptor *lvd            = NULL;
    PartitionDescriptor *pd                 = NULL;
    LogicalVolumeDescriptor lvd_snapshot;
    PartitionDescriptor pd_snapshot;
    UnallocatedSpaceDescriptor *usd         = NULL;
    TerminatingDescriptor *td               = NULL;
    LogicalVolumeIntegrityDescriptor *lvid  = NULL;
    AnchorVolumeDescriptorPointer *avdp     = NULL;
    FileSetDescriptor *fsd                  = NULL;
    DescriptorTag *file_volume_tag          = NULL;
    cl_error_t read_status                  = CL_EPARSE;

    bool isInitialized             = false;
    bool completed_volume           = false;
    PointerList fileIdentifierList = {0};
    PointerList fileEntryList      = {0};

    if (ctx == NULL)
        return CL_ENULLARG;
    if (ctx->fmap == NULL) {
        cli_mark_scan_incomplete(ctx, "UDF input map is unavailable");
        return CL_EPARSE;
    }
    if (ctx->engine == NULL)
        return CL_ENULLARG;

    if (offset < 32768) {
        cli_mark_scan_incomplete(ctx, "UDF inspection started before the mandatory descriptor area");
        return CL_EPARSE; /* Need 16 sectors at least 2048 bytes long */
    }

    ret = udf_checktimelimit(ctx, "UDF inspection reached the configured time limit");
    if (ret != CL_SUCCESS)
        goto done;

    cli_dbgmsg("Scanning UDF file\n");

    for (i = 0; i < NUM_GENERIC_VOLUME_DESCRIPTORS; i++) {
        ret = udf_checktimelimit(ctx, "UDF generic volume descriptor traversal reached the configured time limit");
        if (ret != CL_SUCCESS)
            goto done;

        gvsd = (GenericVolumeStructureDescriptor *)udf_need_off(ctx, idx, sizeof(GenericVolumeStructureDescriptor), &read_status);
        if (NULL == gvsd) {
            if (CL_ETIMEOUT == read_status) {
                ret = CL_ETIMEOUT;
                goto done;
            }
            if (CL_EREAD == read_status) {
                cli_mark_scan_incomplete(ctx, "UDF generic volume descriptor area could not be read completely");
                ret = CL_EREAD;
            } else {
                // File isn't long enough to store the required generic volume structure descriptors at the given offset.
                cli_mark_scan_incomplete(ctx, "UDF generic volume descriptor area is incomplete");
                ret = CL_EPARSE;
            }
            goto done;
        }

        lastOffset = idx;

        if (0 == strncmp("BEA01", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "BEA01");
        } else if (0 == strncmp("BOOT2", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "BOOT2");
        } else if (0 == strncmp("CD001", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "CD001");
        } else if (0 == strncmp("CDW02", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "CDW02");
        } else if (0 == strncmp("NSR02", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "NSR02");
        } else if (0 == strncmp("NSR03", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "NSR03");
        } else if (0 == strncmp("TEA01", gvsd->standardIdentifier, 5)) {
            cli_dbgmsg("Found Standard Identifier '%s'\n", "TEA01");
        } else {
            cli_dbgmsg("Unknown Standard Identifier '%s'\n", gvsd->standardIdentifier);
            fmap_unneed_ptr(ctx->fmap, gvsd, sizeof(GenericVolumeStructureDescriptor));
            cli_mark_scan_incomplete(ctx, "UDF generic volume descriptor identifier is unsupported");
            ret = CL_EPARSE;
            goto done;
        }

        fmap_unneed_ptr(ctx->fmap, gvsd, sizeof(GenericVolumeStructureDescriptor));

        idx += sizeof(GenericVolumeStructureDescriptor);
    }

    while (1) {

        ret = udf_checktimelimit(ctx, "UDF volume descriptor traversal reached the configured time limit");
        if (ret != CL_SUCCESS)
            goto done;

        if (!isInitialized) {
            /* We don't use most of these descriptors, but verify they all exist because
             * they are part of a properly formatted udf file. */

            if (CL_SUCCESS != (ret = initPointerList(&fileIdentifierList))) {
                cli_dbgmsg("Failed to initialize fileIdentifierList\n");
                goto done;
            }

            if (CL_SUCCESS != (ret = initPointerList(&fileEntryList))) {
                cli_dbgmsg("Failed to initialize fileEntryList\n");
                goto done;
            }

            if (NULL == (pvd = getPrimaryVolumeDescriptor(ctx, &idx, &lastOffset, &read_status))) {
                cli_dbgmsg("Failed to get Primary Volume Descriptor\n");
                if (CL_ETIMEOUT == read_status) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
                if (CL_EREAD == read_status) {
                    cli_mark_scan_incomplete(ctx, "UDF primary volume descriptor could not be read completely");
                    ret = CL_EREAD;
                } else {
                    cli_mark_scan_incomplete(ctx, "UDF primary volume descriptor is incomplete");
                    ret = CL_EPARSE;
                }
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, pvd, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (iuvd = getImplementationUseVolumeDescriptor(ctx, &idx, &lastOffset, &read_status))) {
                cli_dbgmsg("Failed to get Implementation Use Volume Descriptor\n");
                if (CL_ETIMEOUT == read_status) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
                if (CL_EREAD == read_status) {
                    cli_mark_scan_incomplete(ctx, "UDF implementation-use descriptor could not be read completely");
                    ret = CL_EREAD;
                } else {
                    cli_mark_scan_incomplete(ctx, "UDF implementation-use descriptor is incomplete");
                    ret = CL_EPARSE;
                }
                goto done;
            }
            /* This descriptor is only validated here. Release its locked
             * view before continuing to inspect the volume. */
            fmap_unneed_ptr(ctx->fmap, iuvd, VOLUME_DESCRIPTOR_SIZE);
            iuvd = NULL;

            if (NULL == (lvd = getLogicalVolumeDescriptor(ctx, &idx, &lastOffset, &read_status))) {
                cli_dbgmsg("Failed to get Logical Volume Descriptor\n");
                if (CL_ETIMEOUT == read_status) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
                if (CL_EREAD == read_status) {
                    cli_mark_scan_incomplete(ctx, "UDF logical volume descriptor could not be read completely");
                    ret = CL_EREAD;
                } else {
                    cli_mark_scan_incomplete(ctx, "UDF logical volume descriptor is incomplete");
                    ret = CL_EPARSE;
                }
                goto done;
            }
            /* Snapshot metadata needed by extracted-file traversal, then
             * release the locked fmap view before nested parsing begins. */
            memcpy(&lvd_snapshot, lvd, sizeof(lvd_snapshot));
            fmap_unneed_ptr(ctx->fmap, lvd, VOLUME_DESCRIPTOR_SIZE);
            lvd = NULL;

            if (NULL == (pd = getPartitionDescriptor(ctx, &idx, &lastOffset, &read_status))) {
                cli_dbgmsg("Failed to get Partition Descriptor\n");
                if (CL_ETIMEOUT == read_status) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
                if (CL_EREAD == read_status) {
                    cli_mark_scan_incomplete(ctx, "UDF partition descriptor could not be read completely");
                    ret = CL_EREAD;
                } else {
                    cli_mark_scan_incomplete(ctx, "UDF partition descriptor is incomplete");
                    ret = CL_EPARSE;
                }
                goto done;
            }
            /* Snapshot metadata needed by extracted-file traversal, then
             * release the locked fmap view before nested parsing begins. */
            memcpy(&pd_snapshot, pd, sizeof(pd_snapshot));
            fmap_unneed_ptr(ctx->fmap, pd, VOLUME_DESCRIPTOR_SIZE);
            pd = NULL;

            if (NULL == (usd = getUnallocatedSpaceDescriptor(ctx, &idx, &lastOffset, &read_status))) {
                cli_dbgmsg("Failed to get Unallocated Space Descriptor\n");
                if (CL_ETIMEOUT == read_status) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
                if (CL_EREAD == read_status) {
                    cli_mark_scan_incomplete(ctx, "UDF unallocated-space descriptor could not be read completely");
                    ret = CL_EREAD;
                } else {
                    cli_mark_scan_incomplete(ctx, "UDF unallocated-space descriptor is incomplete");
                    ret = CL_EPARSE;
                }
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, usd, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (td = getTerminatingDescriptor(ctx, &idx, &lastOffset, &read_status))) {
                cli_dbgmsg("Failed to get Terminating Descriptor\n");
                if (CL_ETIMEOUT == read_status) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
                if (CL_EREAD == read_status) {
                    cli_mark_scan_incomplete(ctx, "UDF terminating descriptor could not be read completely");
                    ret = CL_EREAD;
                } else {
                    cli_mark_scan_incomplete(ctx, "UDF terminating descriptor is incomplete");
                    ret = CL_EPARSE;
                }
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, td, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (lvid = getLogicalVolumeIntegrityDescriptor(ctx, &idx, &lastOffset, &read_status))) {
                cli_dbgmsg("Failed to get Logical Volume Integrity Descriptor\n");
                if (CL_ETIMEOUT == read_status) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
                if (CL_EREAD == read_status) {
                    cli_mark_scan_incomplete(ctx, "UDF logical-volume-integrity descriptor could not be read completely");
                    ret = CL_EREAD;
                } else {
                    cli_mark_scan_incomplete(ctx, "UDF logical-volume-integrity descriptor is incomplete");
                    ret = CL_EPARSE;
                }
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, lvid, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (td = getTerminatingDescriptor(ctx, &idx, &lastOffset, &read_status))) {
                cli_dbgmsg("Failed to get Terminating Descriptor\n");
                if (CL_ETIMEOUT == read_status) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
                if (CL_EREAD == read_status) {
                    cli_mark_scan_incomplete(ctx, "UDF second terminating descriptor could not be read completely");
                    ret = CL_EREAD;
                } else {
                    cli_mark_scan_incomplete(ctx, "UDF second terminating descriptor is incomplete");
                    ret = CL_EPARSE;
                }
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, td, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (avdp = getAnchorVolumeDescriptorPointer(ctx, &idx, &lastOffset, &read_status))) {
                cli_dbgmsg("Failed to get Anchor Volume Descriptor Pointer\n");
                if (CL_ETIMEOUT == read_status) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
                if (CL_EREAD == read_status) {
                    cli_mark_scan_incomplete(ctx, "UDF anchor volume descriptor could not be read completely");
                    ret = CL_EREAD;
                } else {
                    cli_mark_scan_incomplete(ctx, "UDF anchor volume descriptor is incomplete");
                    ret = CL_EPARSE;
                }
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, avdp, VOLUME_DESCRIPTOR_SIZE);

            if (NULL == (fsd = getFileSetDescriptor(ctx, &idx, &lastOffset, &read_status))) {
                cli_dbgmsg("Failed to get File Set Descriptor\n");

                // The file set descriptor may come after an extended file entry descriptor.
                if (CL_ETIMEOUT == read_status) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
                if (CL_EREAD == read_status) {
                    cli_mark_scan_incomplete(ctx, "UDF file set descriptor could not be read completely");
                    ret = CL_EREAD;
                    goto done;
                }
                cli_mark_scan_incomplete(ctx, "UDF file set descriptor is missing or malformed");
                ret = CL_EPARSE;
                goto done;
            }
            fmap_unneed_ptr(ctx->fmap, fsd, VOLUME_DESCRIPTOR_SIZE);

            isInitialized = true;
        }

        /*
         * Find all of the file identifier descriptors and file entry descriptors.
         */

        // Need the entire volume descriptor. Each dispatch copies any state
        // it retains, so release this window before advancing to the next one.
        file_volume_tag = (DescriptorTag *)udf_need_off(ctx, idx, VOLUME_DESCRIPTOR_SIZE, &read_status);
        if (NULL == file_volume_tag) {
            cli_dbgmsg("Failed to get File Volume Tag\n");
            if (CL_ETIMEOUT == read_status) {
                ret = CL_ETIMEOUT;
                goto done;
            }
            if (CL_EREAD == read_status) {
                cli_mark_scan_incomplete(ctx, "UDF file volume descriptor could not be read completely");
                ret = CL_EREAD;
            } else {
                cli_mark_scan_incomplete(ctx, "UDF file volume descriptor is incomplete");
                ret = CL_EPARSE;
            }
            goto done;
        }
        lastOffset = idx;

        tag_identifier tagId = getDescriptorTagId(file_volume_tag);

        cli_dbgmsg("UDF Descriptor Tag ID: %d\n", tagId);

        if ((tagId == EXTENDED_FILE_ENTRY_DESCRIPTOR || tagId == TERMINATING_DESCRIPTOR) &&
            CL_SUCCESS != udf_validate_descriptor_tag(ctx, file_volume_tag,
                                                      VOLUME_DESCRIPTOR_SIZE, 0, false)) {
            ret = CL_EPARSE;
            goto done;
        }

        switch (tagId) {
            case FILE_IDENTIFIER_DESCRIPTOR: {
                cl_error_t temp = findFileIdentifiers(ctx, (const uint8_t *)file_volume_tag, &fileIdentifierList);
                if (CL_SUCCESS != temp) {
                    if (!ctx->scan_incomplete)
                        cli_mark_scan_incomplete(ctx, "UDF file-identifier descriptor indexing did not complete");
                    ret = temp;
                    goto done;
                }
                break;
            }

            case FILE_ENTRY_DESCRIPTOR: {
                cl_error_t temp = findFileEntries(ctx, (const uint8_t *)file_volume_tag, &fileEntryList);
                if (CL_SUCCESS != temp) {
                    if (!ctx->scan_incomplete)
                        cli_mark_scan_incomplete(ctx, "UDF file-entry descriptor indexing did not complete");
                    ret = temp;
                    goto done;
                }
                break;
            }

            case EXTENDED_FILE_ENTRY_DESCRIPTOR: {
                cli_warnmsg("cli_scanudf: Extended File Entry descriptors are unsupported\n");
                cli_mark_scan_incomplete(ctx, "UDF extended file entries are unsupported");
                ret = CL_EUNPACK;
                goto done;
            }

            case TERMINATING_DESCRIPTOR:
            case INVALID_DESCRIPTOR:
            default: {
                /* A non-file-entry block marks the end of the linear
                 * descriptor run. UDF does not encode a file count here, so
                 * the paired lists are the bounded set accumulated for this
                 * volume; invalid/terminating tags are valid payload-boundary
                 * markers as well as the historical default case. */

                cli_dbgmsg("cli_scanudf: Parsing %d file entries.\n", fileEntryList.cnt);

                /* Every file identifier must have a corresponding file entry.
                 * Scanning only the smaller list silently drops a required
                 * layer and can turn a malformed volume into a clean result. */
                if (fileEntryList.cnt != fileIdentifierList.cnt) {
                    cli_mark_scan_incomplete(ctx, "UDF file identifier and file entry counts do not match");
                    ret = CL_EPARSE;
                    goto done;
                }

                /* Dump all the files here. */
                size_t cnt = fileIdentifierList.cnt;

                for (i = 0; i < cnt; i++) {
                    size_t file_entry_index;
                    bool matched = false;

                    ret = udf_checktimelimit(ctx, "UDF file-entry scan traversal reached the configured time limit");
                    if (ret != CL_SUCCESS)
                        goto done;

                    for (file_entry_index = 0; file_entry_index < fileEntryList.cnt; file_entry_index++) {
                        if (fileEntryMatchesIdentifier(
                                (FileEntryDescriptor *)fileEntryList.idxs[file_entry_index],
                                (FileIdentifierDescriptor *)fileIdentifierList.idxs[i],
                                &pd_snapshot)) {
                            matched = true;
                            break;
                        }
                    }

                    if (!matched) {
                        cli_mark_scan_incomplete(ctx, "UDF file identifier ICB does not match a file entry");
                        ret = CL_EPARSE;
                        goto done;
                    }

                    ret = parseFileEntryDescriptor(ctx,
                                                   (FileEntryDescriptor *)fileEntryList.idxs[file_entry_index],
                                                   &pd_snapshot, &lvd_snapshot,
                                                   (FileIdentifierDescriptor *)fileIdentifierList.idxs[i]);
                    if (CL_SUCCESS != ret) {
                        cli_dbgmsg("cli_scanudf: Failed to extract or scan file %zu: %s\n", i, cl_strerror(ret));
                        goto done;
                    }
                }

                /*
                 * We're done with this volume. Release our pointers and free up our pointer lists.
                 * Start looking for the next volume.
                 */
                freePointerList(&fileIdentifierList);
                freePointerList(&fileEntryList);
                isInitialized = false;
                completed_volume = true;
                break;
            }
        }

        fmap_unneed_ptr(ctx->fmap, file_volume_tag, VOLUME_DESCRIPTOR_SIZE);
        file_volume_tag = NULL;

        if (idx > SIZE_MAX - VOLUME_DESCRIPTOR_SIZE) {
            cli_mark_scan_incomplete(ctx, "UDF descriptor offset overflowed");
            ret = CL_EFORMAT;
            goto done;
        }
        idx += VOLUME_DESCRIPTOR_SIZE;

        /* Once the paired file-identifier/file-entry run has been
         * materialized, the next non-file-entry block is the boundary between
         * descriptor content and the partition payload.  The old loop kept
         * treating that payload as another descriptor volume until the fmap
         * ended, so a valid clean UDF image was returned as CL_EPARSE.  A
         * primary-volume descriptor is the one supported signal for another
         * volume; otherwise the completed volume is a complete scan. */
        if (completed_volume) {
            DescriptorTag *next_tag;

            if (idx >= ctx->fmap->len) {
                ret = CL_SUCCESS;
                goto done;
            }

            next_tag = (DescriptorTag *)udf_need_off(ctx, idx, VOLUME_DESCRIPTOR_SIZE, &read_status);
            if (NULL == next_tag) {
                if (CL_EREAD == read_status) {
                    cli_mark_scan_incomplete(ctx, "UDF next-volume descriptor could not be read completely");
                    ret = CL_EREAD;
                } else {
                    cli_mark_scan_incomplete(ctx, "UDF next-volume descriptor is incomplete");
                    ret = CL_EPARSE;
                }
                goto done;
            }

            if (PRIMARY_VOLUME_DESCRIPTOR != getDescriptorTagId(next_tag)) {
                fmap_unneed_ptr(ctx->fmap, next_tag, VOLUME_DESCRIPTOR_SIZE);
                ret = CL_SUCCESS;
                goto done;
            }

            fmap_unneed_ptr(ctx->fmap, next_tag, VOLUME_DESCRIPTOR_SIZE);
            completed_volume = false;
        }
    }

done:
    freePointerList(&fileIdentifierList);
    freePointerList(&fileEntryList);

    if (NULL != iuvd) {
        fmap_unneed_ptr(ctx->fmap, iuvd, VOLUME_DESCRIPTOR_SIZE);
    }
    if (NULL != lvd) {
        fmap_unneed_ptr(ctx->fmap, lvd, VOLUME_DESCRIPTOR_SIZE);
    }
    if (NULL != pd) {
        fmap_unneed_ptr(ctx->fmap, pd, VOLUME_DESCRIPTOR_SIZE);
    }
    if (NULL != file_volume_tag) {
        fmap_unneed_ptr(ctx->fmap, file_volume_tag, VOLUME_DESCRIPTOR_SIZE);
    }

    return ret;
}
