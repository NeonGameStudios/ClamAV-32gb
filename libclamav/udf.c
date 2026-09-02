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
    VOLUME_DESCRIPTOR_POINTER                   = 3,
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
    cl_error_t temp_status;

    if (0 == dataLen || NULL == map || NULL == extents || 0 == extent_count) {
        cli_warnmsg("writeWholeFile: Invalid arguments\n");
        status = CL_EARG;
        goto done;
    }

    temp_status = cli_scan_reserve_temporary(ctx, dataLen);
    if (temp_status != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "UDF file extent exceeds temporary storage limits");
        status = temp_status;
        goto done;
    }
    temporary_reserved = (uint64_t)dataLen;

    status = udf_checktimelimit(ctx, "UDF file extent temporary admission reached the configured time limit");
    if (status != CL_SUCCESS)
        goto done;

    /* Not sure if I care about the name that is actually created. */
    temp_status = cli_gentempfd_with_prefix(ctx->this_layer_tmpdir, fileName, &tmpf, &fd);
    if (temp_status != CL_SUCCESS) {
        cli_warnmsg("writeWholeFile: Can't create temp file\n");
        cli_mark_scan_incomplete(ctx, "UDF temporary output could not be created");
        status = temp_status;
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

#define UDF_MAX_PARTITION_MAPS 64U
#define UDF_MAX_VISITED_ICBS 4096U
#define UDF_MAX_DIRECTORY_DEPTH 128U
#define UDF_MAX_ALLOCATION_EXTENTS 4096U

typedef struct {
    PartitionDescriptor descriptor;
    uint16_t actual_partition_number;
} udf_anchor_partition;

typedef struct {
    uint8_t logical_volume_descriptor[VOLUME_DESCRIPTOR_SIZE];
    udf_anchor_partition partitions[UDF_MAX_PARTITION_MAPS];
    size_t partition_count;
} udf_anchor_volume;

typedef struct {
    PartitionDescriptor descriptor;
    uint16_t map_index;
} udf_runtime_partition;

typedef struct {
    uint16_t map_index;
    uint32_t block_number;
} udf_visited_icb;

typedef struct {
    cli_ctx *ctx;
    LogicalVolumeDescriptor *logical_volume_descriptor;
    udf_runtime_partition partitions[UDF_MAX_PARTITION_MAPS];
    size_t partition_count;
    udf_visited_icb visited[UDF_MAX_VISITED_ICBS];
    size_t visited_count;
} udf_tree_context;

static const void *udf_need_off(cli_ctx *ctx, size_t offset, size_t length,
                                cl_error_t *read_status);

static cl_error_t udf_validate_partition_tag(cli_ctx *ctx, const DescriptorTag *tag,
                                             size_t descriptor_size, uint32_t block_number)
{
    cl_error_t ret;

    ret = udf_validate_descriptor_tag(ctx, tag, descriptor_size, 0, false);
    if (ret != CL_SUCCESS)
        return ret;

    if (le32_to_host(tag->tagLocation) != block_number) {
        cli_mark_scan_incomplete(ctx, "UDF partition descriptor tag location does not match its block");
        return CL_EPARSE;
    }

    return CL_SUCCESS;
}

static cl_error_t udf_copy_partition_block(udf_tree_context *tree,
                                            const udf_runtime_partition *partition,
                                            uint32_t block_number, uint8_t *block,
                                            const char *read_reason)
{
    uint32_t partition_start;
    uint32_t partition_length;
    uint64_t logical_block_offset;
    const uint8_t *view;
    cl_error_t read_status;

    if (tree == NULL || tree->ctx == NULL || tree->ctx->fmap == NULL ||
        tree->logical_volume_descriptor == NULL || partition == NULL || block == NULL)
        return CL_EARG;

    partition_start  = le32_to_host(partition->descriptor.partitionStartingLocation);
    partition_length = le32_to_host(partition->descriptor.partitionLength);
    if (block_number >= partition_length) {
        cli_mark_scan_incomplete(tree->ctx, "UDF partition block is outside the declared partition");
        return CL_EPARSE;
    }
    if (partition_start > UINT32_MAX - block_number) {
        cli_mark_scan_incomplete(tree->ctx, "UDF partition block offset overflowed");
        return CL_EFORMAT;
    }

    logical_block_offset = (uint64_t)(partition_start + block_number) *
                           le32_to_host(tree->logical_volume_descriptor->logicalBlockSize);
    if (logical_block_offset > SIZE_MAX ||
        logical_block_offset > tree->ctx->fmap->len ||
        VOLUME_DESCRIPTOR_SIZE > tree->ctx->fmap->len - (size_t)logical_block_offset) {
        cli_mark_scan_incomplete(tree->ctx, "UDF partition block is outside the input map");
        return CL_EPARSE;
    }

    view = (const uint8_t *)udf_need_off(tree->ctx, (size_t)logical_block_offset,
                                         VOLUME_DESCRIPTOR_SIZE, &read_status);
    if (view == NULL) {
        if (read_status == CL_EREAD)
            cli_mark_scan_incomplete(tree->ctx, read_reason);
        else
            cli_mark_scan_incomplete(tree->ctx, "UDF partition block is incomplete");
        return read_status;
    }

    memcpy(block, view, VOLUME_DESCRIPTOR_SIZE);
    fmap_unneed_ptr(tree->ctx->fmap, view, VOLUME_DESCRIPTOR_SIZE);
    return CL_SUCCESS;
}

static cl_error_t udf_collect_file_extents(cli_ctx *ctx, PartitionDescriptor *partition,
                                           LogicalVolumeDescriptor *logical_volume,
                                           const void *allocation_descriptor,
                                           size_t allocation_descriptor_len, uint16_t icb_flags,
                                           uint64_t information_length, udf_extent **extents_out,
                                           size_t *extent_count_out)
{
    size_t descriptor_size;
    size_t extent_count;
    size_t i;
    udf_extent *extents = NULL;
    uint64_t total_length = 0;
    cl_error_t ret;

    if (extents_out == NULL || extent_count_out == NULL)
        return CL_EARG;
    *extents_out       = NULL;
    *extent_count_out  = 0;

    switch (icb_flags & 7U) {
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
            cli_mark_scan_incomplete(ctx, "UDF allocation descriptor type is unsupported");
            return CL_EUNPACK;
    }

    if (allocation_descriptor_len == 0) {
        if (information_length != 0) {
            cli_mark_scan_incomplete(ctx, "UDF allocation extents do not match declared information length");
            return CL_EPARSE;
        }
        return CL_SUCCESS;
    }

    if (allocation_descriptor == NULL ||
        allocation_descriptor_len % descriptor_size != 0) {
        cli_mark_scan_incomplete(ctx, "UDF allocation descriptor length is not aligned");
        return CL_EPARSE;
    }

    extent_count = allocation_descriptor_len / descriptor_size;
    if (extent_count > UDF_MAX_ALLOCATION_EXTENTS ||
        extent_count > SIZE_MAX / sizeof(*extents)) {
        cli_mark_scan_incomplete(ctx, "UDF allocation descriptor list is too large");
        return CL_EUNPACK;
    }

    extents = cli_max_calloc(extent_count, sizeof(*extents));
    if (extents == NULL) {
        cli_mark_scan_incomplete(ctx, "UDF allocation descriptor list could not be allocated");
        return CL_EMEM;
    }

    for (i = 0; i < extent_count; i++) {
        const uint8_t *descriptor = (const uint8_t *)allocation_descriptor + (i * descriptor_size);

        ret = udf_checktimelimit(ctx, "UDF allocation-descriptor traversal reached the configured time limit");
        if (ret != CL_SUCCESS)
            goto done;

        if ((icb_flags & 7U) == 1U &&
            le16_to_host(((const long_ad *)descriptor)->extentLocation.partitionReferenceNumber) !=
                le16_to_host(partition->partitionNumber)) {
            cli_mark_scan_incomplete(ctx, "UDF cross-partition allocation descriptor is unsupported");
            ret = CL_EUNPACK;
            goto done;
        }
        if ((icb_flags & 7U) == 2U &&
            le16_to_host(((const ext_ad *)descriptor)->extentLocation.partitionReferenceNumber) !=
                le16_to_host(partition->partitionNumber)) {
            cli_mark_scan_incomplete(ctx, "UDF cross-partition allocation descriptor is unsupported");
            ret = CL_EUNPACK;
            goto done;
        }

        ret = getUDFExtentRange(ctx, partition, logical_volume,
                                descriptor, icb_flags, &extents[i]);
        if (ret != CL_SUCCESS)
            goto done;
        if (total_length > UINT64_MAX - extents[i].length) {
            cli_mark_scan_incomplete(ctx, "UDF aggregate extent length overflowed");
            ret = CL_EPARSE;
            goto done;
        }
        total_length += extents[i].length;
    }

    if (total_length != information_length) {
        cli_mark_scan_incomplete(ctx, "UDF allocation extents do not match declared information length");
        ret = CL_EPARSE;
        goto done;
    }

    *extents_out      = extents;
    *extent_count_out = extent_count;
    return CL_SUCCESS;

done:
    CLI_FREE_AND_SET_NULL(extents);
    return ret;
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

static cl_error_t udf_mark_icb_visited(udf_tree_context *tree, uint16_t map_index,
                                       uint32_t block_number, bool *already_visited)
{
    size_t i;

    if (tree == NULL || already_visited == NULL)
        return CL_EARG;
    *already_visited = false;

    for (i = 0; i < tree->visited_count; i++) {
        if (tree->visited[i].map_index == map_index &&
            tree->visited[i].block_number == block_number) {
            *already_visited = true;
            return CL_SUCCESS;
        }
    }
    if (tree->visited_count >= UDF_MAX_VISITED_ICBS) {
        cli_mark_scan_incomplete(tree->ctx, "UDF ICB traversal limit was exceeded");
        return CL_EUNPACK;
    }

    tree->visited[tree->visited_count].map_index    = map_index;
    tree->visited[tree->visited_count].block_number = block_number;
    tree->visited_count++;
    return CL_SUCCESS;
}

static cl_error_t udf_scan_icb(udf_tree_context *tree, uint16_t map_index,
                               uint32_t block_number, bool directory_hint,
                               FileIdentifierDescriptor *fid, size_t depth);

static cl_error_t udf_validate_icb_extent(udf_tree_context *tree,
                                          const long_ad *icb)
{
    uint32_t raw_length;
    uint32_t extent_type;
    uint32_t extent_length;
    uint16_t map_index;

    if (tree == NULL || icb == NULL)
        return CL_EARG;

    raw_length   = le32_to_host(icb->length);
    extent_type  = raw_length >> 30;
    extent_length = raw_length & UINT32_C(0x3fffffff);
    map_index     = le16_to_host(icb->extentLocation.partitionReferenceNumber);
    if (extent_type != 0) {
        cli_mark_scan_incomplete(tree->ctx, "UDF file identifier ICB extent type is unsupported");
        return CL_EUNPACK;
    }
    if (extent_length != VOLUME_DESCRIPTOR_SIZE) {
        cli_mark_scan_incomplete(tree->ctx, "UDF file identifier ICB extent length is unsupported");
        return CL_EUNPACK;
    }
    if (map_index >= tree->partition_count) {
        cli_mark_scan_incomplete(tree->ctx, "UDF file identifier ICB partition reference is invalid");
        return CL_EPARSE;
    }

    return CL_SUCCESS;
}

static cl_error_t udf_scan_directory_block(udf_tree_context *tree,
                                           uint32_t block_number, const uint8_t *block,
                                           size_t block_length, size_t depth,
                                           size_t *parent_count)
{
    size_t offset = 0;
    cl_error_t ret;

    while (offset < block_length) {
        const FileIdentifierDescriptor *fid;
        size_t fid_size;
        tag_identifier tag_id;
        uint8_t characteristics;
        size_t remaining = block_length - offset;

        ret = udf_checktimelimit(tree->ctx, "UDF directory traversal reached the configured time limit");
        if (ret != CL_SUCCESS)
            return ret;

        if (remaining < sizeof(DescriptorTag)) {
            while (offset < block_length) {
                if (block[offset++] != 0) {
                    cli_mark_scan_incomplete(tree->ctx, "UDF directory descriptor tail is malformed");
                    return CL_EPARSE;
                }
            }
            break;
        }

        fid = (const FileIdentifierDescriptor *)(block + offset);
        tag_id = getDescriptorTagId((DescriptorTag *)fid);
        if (tag_id == INVALID_DESCRIPTOR) {
            while (offset < block_length) {
                if (block[offset++] != 0) {
                    cli_mark_scan_incomplete(tree->ctx, "UDF directory descriptor tail is malformed");
                    return CL_EPARSE;
                }
            }
            break;
        }
        if (tag_id != FILE_IDENTIFIER_DESCRIPTOR) {
            cli_mark_scan_incomplete(tree->ctx, "UDF directory contains an unsupported descriptor");
            return CL_EUNPACK;
        }

        if (!getFileIdentifierDescriptorSize(fid, &fid_size) ||
            fid_size > remaining) {
            cli_mark_scan_incomplete(tree->ctx, "UDF file-identifier descriptor exceeds its directory block");
            return CL_EPARSE;
        }
        ret = udf_validate_partition_tag(tree->ctx, &fid->tag, fid_size, block_number);
        if (ret != CL_SUCCESS)
            return ret;
        ret = udf_validate_icb_extent(tree, &fid->icb);
        if (ret != CL_SUCCESS)
            return ret;

        characteristics = fid->characteristics;
        if ((characteristics & 4U) != 0) {
            if (parent_count != NULL)
                (*parent_count)++;
        } else {
            if (fid->fileIdentifierLength == 0) {
                cli_mark_scan_incomplete(tree->ctx, "UDF component file identifier is empty");
                return CL_EPARSE;
            }
            ret = udf_scan_icb(tree, le16_to_host(fid->icb.extentLocation.partitionReferenceNumber),
                               le32_to_host(fid->icb.extentLocation.blockNumber),
                               isDirectory((FileIdentifierDescriptor *)fid),
                               (FileIdentifierDescriptor *)fid, depth + 1);
            if (ret != CL_SUCCESS)
                return ret;
        }

        offset += fid_size;
    }

    return CL_SUCCESS;
}

static cl_error_t udf_scan_directory(udf_tree_context *tree,
                                     const udf_runtime_partition *partition,
                                     void *allocation_descriptor,
                                     size_t allocation_descriptor_len, uint16_t icb_flags,
                                     uint64_t information_length, size_t depth)
{
    udf_extent *extents = NULL;
    size_t extent_count = 0;
    size_t i;
    uint8_t block[VOLUME_DESCRIPTOR_SIZE];
    size_t parent_count = 0;
    cl_error_t ret;

    if (depth > UDF_MAX_DIRECTORY_DEPTH) {
        cli_mark_scan_incomplete(tree->ctx, "UDF directory traversal depth limit was exceeded");
        return CL_EUNPACK;
    }

    ret = udf_collect_file_extents(tree->ctx, (PartitionDescriptor *)&partition->descriptor,
                                   tree->logical_volume_descriptor, allocation_descriptor,
                                   allocation_descriptor_len, icb_flags, information_length,
                                   &extents, &extent_count);
    if (ret != CL_SUCCESS)
        return ret;
    if (information_length == 0) {
        CLI_FREE_AND_SET_NULL(extents);
        return CL_SUCCESS;
    }

    ret = cli_checklimits("UDF", tree->ctx, information_length, 0, 0);
    if (ret != CL_SUCCESS) {
        cli_mark_scan_incomplete(tree->ctx, "UDF directory extent exceeds configured scan limits");
        goto done;
    }

    for (i = 0; i < extent_count; i++) {
        size_t extent_offset = 0;
        uint32_t partition_start = le32_to_host(partition->descriptor.partitionStartingLocation);
        uint32_t logical_block_size = le32_to_host(tree->logical_volume_descriptor->logicalBlockSize);
        uint64_t partition_offset = (uint64_t)partition_start * logical_block_size;
        uint64_t relative_offset;

        if (extents[i].offset < partition_offset ||
            (uint64_t)extents[i].offset - partition_offset > UINT32_MAX * (uint64_t)logical_block_size) {
            cli_mark_scan_incomplete(tree->ctx, "UDF directory extent location is invalid");
            ret = CL_EPARSE;
            goto done;
        }
        relative_offset = (uint64_t)extents[i].offset - partition_offset;
        if (relative_offset % logical_block_size != 0) {
            cli_mark_scan_incomplete(tree->ctx, "UDF directory extent is not logically aligned");
            ret = CL_EPARSE;
            goto done;
        }
        if (extents[i].length % logical_block_size != 0) {
            cli_mark_scan_incomplete(tree->ctx, "UDF directory extent is not logically aligned");
            ret = CL_EPARSE;
            goto done;
        }

        while (extent_offset < extents[i].length) {
            size_t block_length = MIN((size_t)logical_block_size, extents[i].length - extent_offset);
            uint64_t block_number64 = relative_offset / logical_block_size +
                                      (extent_offset / logical_block_size);

            if (block_number64 > UINT32_MAX) {
                cli_mark_scan_incomplete(tree->ctx, "UDF directory block number overflowed");
                ret = CL_EFORMAT;
                goto done;
            }
            memset(block, 0, sizeof(block));
            if (block_length > sizeof(block) ||
                fmap_readn_full(tree->ctx->fmap, block, extents[i].offset + extent_offset,
                                block_length) != block_length) {
                cli_mark_scan_incomplete(tree->ctx, "UDF directory extent could not be read completely");
                ret = CL_EREAD;
                goto done;
            }
            ret = udf_scan_directory_block(tree, (uint32_t)block_number64,
                                           block, block_length, depth, &parent_count);
            if (ret != CL_SUCCESS)
                goto done;
            extent_offset += block_length;
        }
    }

    if (parent_count == 0) {
        cli_mark_scan_incomplete(tree->ctx, "UDF directory has no parent identifier");
        ret = CL_EPARSE;
        goto done;
    }
    if (parent_count != 1) {
        cli_mark_scan_incomplete(tree->ctx, "UDF directory has multiple parent identifiers");
        ret = CL_EPARSE;
        goto done;
    }
    ret = CL_SUCCESS;

done:
    CLI_FREE_AND_SET_NULL(extents);
    return ret;
}

static cl_error_t udf_scan_icb(udf_tree_context *tree, uint16_t map_index,
                               uint32_t block_number, bool directory_hint,
                               FileIdentifierDescriptor *fid, size_t depth)
{
    uint8_t block[VOLUME_DESCRIPTOR_SIZE];
    const FileEntryDescriptor *fed;
    const udf_runtime_partition *partition;
    void *allocation_descriptor;
    size_t descriptor_size;
    uint32_t allocation_descriptor_length;
    uint16_t icb_flags;
    bool already_visited;
    tag_identifier tag_id;
    cl_error_t ret;

    if (tree == NULL || tree->ctx == NULL ||
        map_index >= tree->partition_count)
        return CL_EARG;
    if (depth > UDF_MAX_DIRECTORY_DEPTH) {
        cli_mark_scan_incomplete(tree->ctx, "UDF directory traversal depth limit was exceeded");
        return CL_EUNPACK;
    }

    ret = udf_mark_icb_visited(tree, map_index, block_number, &already_visited);
    if (ret != CL_SUCCESS || already_visited)
        return ret;
    ret = udf_checktimelimit(tree->ctx, "UDF ICB traversal reached the configured time limit");
    if (ret != CL_SUCCESS)
        return ret;

    partition = &tree->partitions[map_index];
    ret = udf_copy_partition_block(tree, partition, block_number, block,
                                   "UDF ICB could not be read completely");
    if (ret != CL_SUCCESS)
        return ret;

    tag_id = getDescriptorTagId((DescriptorTag *)block);
    if (tag_id == EXTENDED_FILE_ENTRY_DESCRIPTOR) {
        cli_mark_scan_incomplete(tree->ctx, "UDF extended file entries are unsupported");
        return CL_EUNPACK;
    }
    if (tag_id != FILE_ENTRY_DESCRIPTOR) {
        cli_mark_scan_incomplete(tree->ctx, "UDF ICB does not contain a file entry");
        return CL_EPARSE;
    }

    fed = (const FileEntryDescriptor *)block;
    if (!getFileEntryDescriptorSize(fed, &descriptor_size) ||
        descriptor_size > VOLUME_DESCRIPTOR_SIZE) {
        cli_mark_scan_incomplete(tree->ctx, "UDF file-entry descriptor exceeds its logical block");
        return CL_EPARSE;
    }
    ret = udf_validate_partition_tag(tree->ctx, &fed->tag, descriptor_size, block_number);
    if (ret != CL_SUCCESS)
        return ret;

    if (directory_hint != (fed->icbTag.fileType == 4U)) {
        cli_mark_scan_incomplete(tree->ctx, "UDF file identifier directory type disagrees with its file entry");
        return CL_EPARSE;
    }
    if (!directory_hint && fed->icbTag.fileType != 5U) {
        cli_mark_scan_incomplete(tree->ctx, "UDF ICB file type is unsupported");
        return CL_EUNPACK;
    }
    allocation_descriptor_length = le32_to_host(fed->allocationDescLen);
    if (allocation_descriptor_length > descriptor_size) {
        cli_mark_scan_incomplete(tree->ctx, "UDF file-entry allocation descriptor length is invalid");
        return CL_EPARSE;
    }
    allocation_descriptor = (uint8_t *)block + descriptor_size - allocation_descriptor_length;
    icb_flags = le16_to_host(fed->icbTag.flags);

    if (directory_hint) {
        return udf_scan_directory(tree, partition,
                                  allocation_descriptor, allocation_descriptor_length,
                                  icb_flags, le64_to_host(fed->infoLength), depth);
    }
    ret = extractFile(tree->ctx, (PartitionDescriptor *)&partition->descriptor,
                      tree->logical_volume_descriptor, allocation_descriptor,
                      allocation_descriptor_length, icb_flags,
                      le64_to_host(fed->infoLength), fid);
    return ret;
}

static const udf_anchor_partition *udf_find_anchor_partition(const udf_anchor_volume *volume,
                                                             uint16_t partition_number)
{
    size_t i;

    for (i = 0; i < volume->partition_count; i++) {
        if (volume->partitions[i].actual_partition_number == partition_number)
            return &volume->partitions[i];
    }
    return NULL;
}

static cl_error_t udf_scan_anchor_tree(cli_ctx *ctx, const udf_anchor_volume *volume)
{
    udf_tree_context tree;
    const LogicalVolumeDescriptor *lvd;
    const uint8_t *map_data;
    size_t map_table_length;
    size_t map_count;
    size_t map_offset;
    size_t i;
    long_ad fsd_extent;
    uint32_t fsd_extent_type;
    uint32_t fsd_extent_length;
    uint16_t fsd_map_index;
    uint32_t fsd_block;
    uint8_t block[VOLUME_DESCRIPTOR_SIZE];
    const FileSetDescriptor *fsd;
    size_t fsd_descriptor_size = sizeof(FileSetDescriptor);
    cl_error_t ret;

    if (ctx == NULL || volume == NULL)
        return CL_EARG;
    lvd = (const LogicalVolumeDescriptor *)volume->logical_volume_descriptor;
    if (le32_to_host(lvd->logicalBlockSize) != VOLUME_DESCRIPTOR_SIZE) {
        cli_mark_scan_incomplete(ctx, "UDF logical block size is unsupported");
        return CL_EUNPACK;
    }

    map_table_length = le32_to_host(lvd->mapTableLength);
    map_count        = le32_to_host(lvd->numPartitionMaps);
    map_offset       = offsetof(LogicalVolumeDescriptor, partitionMaps);
    if (map_count == 0 || map_count > UDF_MAX_PARTITION_MAPS ||
        map_table_length == 0 || map_table_length > VOLUME_DESCRIPTOR_SIZE - map_offset) {
        cli_mark_scan_incomplete(ctx, "UDF partition map table is invalid");
        return CL_EPARSE;
    }
    if (map_count > map_table_length / 2U) {
        cli_mark_scan_incomplete(ctx, "UDF partition map count is invalid");
        return CL_EPARSE;
    }

    memset(&tree, 0, sizeof(tree));
    tree.ctx = ctx;
    tree.logical_volume_descriptor = (LogicalVolumeDescriptor *)lvd;
    map_data = (const uint8_t *)lvd + map_offset;
    for (i = 0; i < map_count; i++) {
        uint8_t map_type;
        uint8_t map_length;
        uint16_t map_volume_sequence;
        uint16_t partition_number;
        const udf_anchor_partition *source_partition;

        if (map_table_length < 2) {
            cli_mark_scan_incomplete(ctx, "UDF partition map table is truncated");
            return CL_EPARSE;
        }
        map_type   = map_data[0];
        map_length = map_data[1];
        if (map_length < 2 || map_length > map_table_length) {
            cli_mark_scan_incomplete(ctx, "UDF partition map length is invalid");
            return CL_EPARSE;
        }
        if (map_type != 1 || map_length != 6) {
            cli_mark_scan_incomplete(ctx, "UDF partition map type is unsupported");
            return CL_EUNPACK;
        }
        if (map_length > map_table_length || map_data + map_length > (const uint8_t *)lvd + map_offset + map_table_length) {
            cli_mark_scan_incomplete(ctx, "UDF partition map exceeds its table");
            return CL_EPARSE;
        }

        partition_number = (uint16_t)map_data[4] | ((uint16_t)map_data[5] << 8);
        map_volume_sequence = (uint16_t)map_data[2] | ((uint16_t)map_data[3] << 8);
        source_partition = udf_find_anchor_partition(volume, partition_number);
        if (source_partition == NULL) {
            cli_mark_scan_incomplete(ctx, "UDF partition map has no matching partition descriptor");
            return CL_EPARSE;
        }
        if (map_volume_sequence !=
            (uint16_t)le32_to_host(source_partition->descriptor.volumeDescriptorSequenceNumber)) {
            cli_mark_scan_incomplete(ctx, "UDF partition map volume sequence does not match its descriptor");
            return CL_EPARSE;
        }
        memcpy(&tree.partitions[tree.partition_count].descriptor,
               &source_partition->descriptor, sizeof(PartitionDescriptor));
        tree.partitions[tree.partition_count].map_index =
            (uint16_t)tree.partition_count;
        tree.partitions[tree.partition_count].descriptor.partitionNumber =
            (uint16_t)tree.partition_count;
        tree.partition_count++;

        map_data += map_length;
        map_table_length -= map_length;
    }
    if (map_table_length != 0) {
        cli_mark_scan_incomplete(ctx, "UDF partition map table has trailing bytes");
        return CL_EPARSE;
    }

    memcpy(&fsd_extent, lvd->logicalVolumeContentsUse, sizeof(fsd_extent));
    fsd_extent_type   = le32_to_host(fsd_extent.length) >> 30;
    fsd_extent_length = le32_to_host(fsd_extent.length) & UINT32_C(0x3fffffff);
    fsd_map_index     = le16_to_host(fsd_extent.extentLocation.partitionReferenceNumber);
    fsd_block         = le32_to_host(fsd_extent.extentLocation.blockNumber);
    if (fsd_extent_type != 0) {
        cli_mark_scan_incomplete(ctx, "UDF file-set descriptor extent type is unsupported");
        return CL_EUNPACK;
    }
    if (fsd_extent_length != VOLUME_DESCRIPTOR_SIZE ||
        fsd_map_index >= tree.partition_count) {
        cli_mark_scan_incomplete(ctx, "UDF fragmented file-set descriptor sequence is unsupported");
        return CL_EPARSE;
    }

    ret = udf_copy_partition_block(&tree, &tree.partitions[fsd_map_index], fsd_block, block,
                                   "UDF file-set descriptor could not be read completely");
    if (ret != CL_SUCCESS)
        return ret;
    fsd = (const FileSetDescriptor *)block;
    if (getDescriptorTagId((DescriptorTag *)block) != FILE_SET_DESCRIPTOR) {
        cli_mark_scan_incomplete(ctx, "UDF file-set descriptor is missing or malformed");
        return CL_EPARSE;
    }
    ret = udf_validate_partition_tag(ctx, &fsd->tag, fsd_descriptor_size, fsd_block);
    if (ret != CL_SUCCESS)
        return ret;

    if ((le32_to_host(fsd->rootDirectoryICB.length) >> 30) != 0 ||
        (le32_to_host(fsd->rootDirectoryICB.length) & UINT32_C(0x3fffffff)) != VOLUME_DESCRIPTOR_SIZE) {
        cli_mark_scan_incomplete(ctx, "UDF root directory ICB extent is invalid");
        return CL_EPARSE;
    }
    if (le32_to_host(fsd->nextExtent.length) != 0 ||
        le32_to_host(fsd->nextExtent.extentLocation.blockNumber) != 0 ||
        le16_to_host(fsd->nextExtent.extentLocation.partitionReferenceNumber) != 0) {
        cli_mark_scan_incomplete(ctx, "UDF fragmented file-set descriptor sequence is unsupported");
        return CL_EUNPACK;
    }
    if (le16_to_host(fsd->rootDirectoryICB.extentLocation.partitionReferenceNumber) >= tree.partition_count) {
        cli_mark_scan_incomplete(ctx, "UDF root directory ICB partition reference is invalid");
        return CL_EPARSE;
    }

    return udf_scan_icb(&tree,
                        le16_to_host(fsd->rootDirectoryICB.extentLocation.partitionReferenceNumber),
                        le32_to_host(fsd->rootDirectoryICB.extentLocation.blockNumber),
                        true, NULL, 0);
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

/* Copy one complete logical sector while keeping fmap ownership local to the
 * read. The caller can therefore validate and retain descriptor metadata
 * without pinning the source page through later traversal. */
static cl_error_t udf_copy_descriptor_block(cli_ctx *ctx, size_t offset, uint8_t *block,
                                            const char *read_reason)
{
    const uint8_t *view;
    cl_error_t read_status;

    view = (const uint8_t *)udf_need_off(ctx, offset, VOLUME_DESCRIPTOR_SIZE, &read_status);
    if (view == NULL) {
        if (read_status == CL_EREAD)
            cli_mark_scan_incomplete(ctx, read_reason);
        else
            cli_mark_scan_incomplete(ctx, "UDF descriptor block is incomplete");
        return read_status;
    }

    memcpy(block, view, VOLUME_DESCRIPTOR_SIZE);
    fmap_unneed_ptr(ctx->fmap, view, VOLUME_DESCRIPTOR_SIZE);
    return CL_SUCCESS;
}

static cl_error_t udf_scan_anchor_tree(cli_ctx *ctx, const udf_anchor_volume *volume);

/* Walk an Anchor Volume Descriptor Pointer's main sequence and, after
 * validating its required metadata, scan the bounded root ICB tree. The
 * historical linear scanner remains below for compact legacy fixtures. */
static cl_error_t udf_scan_anchor_volume(cli_ctx *ctx, const size_t offset)
{
    const size_t anchor_offset = 256U * VOLUME_DESCRIPTOR_SIZE;
    uint8_t block[VOLUME_DESCRIPTOR_SIZE];
    udf_anchor_volume volume;
    size_t sequence_offset;
    size_t sequence_length;
    uint64_t sequence_offset64;
    uint64_t sequence_length64;
    uint32_t main_location;
    uint32_t main_length;
    bool have_pvd = false;
    bool have_pd  = false;
    bool have_lvd = false;
    bool have_terminator = false;
    uint32_t lvd_sequence_number = 0;
    uint32_t main_extent_type;
    size_t cursor;
    size_t end;
    cl_error_t ret;

    memset(&volume, 0, sizeof(volume));

    /* The file-type signature is defined at sector 16. If the caller found a
     * signature elsewhere, this path cannot safely reinterpret tag locations
     * in the volume's sector namespace. Leave that old admission path to its
     * established explicit result. */
    if (offset != UDF_EMPTY_LEN || ctx == NULL || ctx->fmap == NULL ||
        anchor_offset > ctx->fmap->len ||
        VOLUME_DESCRIPTOR_SIZE > ctx->fmap->len - anchor_offset)
        return CL_BREAK;

    ret = udf_copy_descriptor_block(ctx, anchor_offset, block,
                                    "UDF anchor descriptor could not be read completely");
    if (ret != CL_SUCCESS)
        return ret;

    if (getDescriptorTagId((DescriptorTag *)block) != ANCHOR_VOLUME_DESCRIPTOR_DESCRIPTOR_POINTER)
        return CL_BREAK;

    ret = udf_validate_descriptor_tag(ctx, (const DescriptorTag *)block,
                                      VOLUME_DESCRIPTOR_SIZE, anchor_offset, true);
    if (ret != CL_SUCCESS)
        return ret;

    main_length   = le32_to_host(((AnchorVolumeDescriptorPointer *)block)->mainVolumeDescriptorSequence.extentLength);
    main_location = le32_to_host(((AnchorVolumeDescriptorPointer *)block)->mainVolumeDescriptorSequence.extentLocation);
    main_extent_type = main_length >> 30;
    main_length &= UINT32_C(0x3fffffff);
    if (main_extent_type != 0) {
        cli_mark_scan_incomplete(ctx, "UDF main descriptor sequence extent type is unsupported");
        return CL_EUNPACK;
    }
    if (main_length == 0 || main_length % VOLUME_DESCRIPTOR_SIZE != 0) {
        cli_mark_scan_incomplete(ctx, "UDF main descriptor sequence extent is invalid");
        return CL_EPARSE;
    }

    sequence_offset64 = (uint64_t)main_location * VOLUME_DESCRIPTOR_SIZE;
    sequence_length64 = main_length;
    if (sequence_offset64 > SIZE_MAX || sequence_length64 > SIZE_MAX ||
        sequence_offset64 > ctx->fmap->len ||
        sequence_length64 > (uint64_t)ctx->fmap->len - sequence_offset64) {
        cli_mark_scan_incomplete(ctx, "UDF main descriptor sequence is outside the input map");
        return CL_EPARSE;
    }
    sequence_offset = (size_t)sequence_offset64;
    sequence_length = (size_t)sequence_length64;
    end             = sequence_offset + sequence_length;

    for (cursor = sequence_offset; cursor < end; cursor += VOLUME_DESCRIPTOR_SIZE) {
        tag_identifier tag_id;

        ret = udf_checktimelimit(ctx, "UDF main descriptor sequence traversal reached the configured time limit");
        if (ret != CL_SUCCESS)
            return ret;

        ret = udf_copy_descriptor_block(ctx, cursor, block,
                                        "UDF main descriptor sequence could not be read completely");
        if (ret != CL_SUCCESS)
            return ret;

        ret = udf_validate_descriptor_tag(ctx, (const DescriptorTag *)block,
                                          VOLUME_DESCRIPTOR_SIZE, cursor, true);
        if (ret != CL_SUCCESS)
            return ret;

        tag_id = getDescriptorTagId((DescriptorTag *)block);
        switch (tag_id) {
            case PRIMARY_VOLUME_DESCRIPTOR:
                if (!have_pvd) {
                    have_pvd = true;
                }
                break;

            case PARTITION_DESCRIPTOR:
                {
                    uint16_t actual_partition_number = le16_to_host(((PartitionDescriptor *)block)->partitionNumber);
                    uint32_t sequence_number = le32_to_host(((PartitionDescriptor *)block)->volumeDescriptorSequenceNumber);
                    size_t partition_index;
                    bool replaced = false;

                    for (partition_index = 0; partition_index < volume.partition_count; partition_index++) {
                        if (volume.partitions[partition_index].actual_partition_number == actual_partition_number) {
                            if (sequence_number >= le32_to_host(volume.partitions[partition_index].descriptor.volumeDescriptorSequenceNumber))
                                memcpy(&volume.partitions[partition_index].descriptor, block, sizeof(PartitionDescriptor));
                            replaced = true;
                            break;
                        }
                    }
                    if (!replaced) {
                        if (volume.partition_count >= UDF_MAX_PARTITION_MAPS) {
                            cli_mark_scan_incomplete(ctx, "UDF partition descriptor table is too large");
                            return CL_EUNPACK;
                        }
                        memcpy(&volume.partitions[volume.partition_count].descriptor, block,
                               sizeof(PartitionDescriptor));
                        volume.partitions[volume.partition_count].actual_partition_number = actual_partition_number;
                        volume.partition_count++;
                    }
                    have_pd = true;
                }
                break;

            case LOGICAL_VOLUME_DESCRIPTOR:
                if (!have_lvd ||
                    le32_to_host(((LogicalVolumeDescriptor *)block)->volumeDescriptorSequenceNumber) >=
                        lvd_sequence_number) {
                    memcpy(volume.logical_volume_descriptor, block, VOLUME_DESCRIPTOR_SIZE);
                    lvd_sequence_number = le32_to_host(((LogicalVolumeDescriptor *)block)->volumeDescriptorSequenceNumber);
                    have_lvd = true;
                }
                break;

            case IMPLEMENTATION_USE_VOLUME_DESCRIPTOR:
            case UNALLOCATED_SPACE_DESCRIPTOR:
                break;

            case TERMINATING_DESCRIPTOR:
                have_terminator = true;
                cursor = end - VOLUME_DESCRIPTOR_SIZE;
                break;

            case VOLUME_DESCRIPTOR_POINTER:
                cli_mark_scan_incomplete(ctx, "UDF descriptor sequence pointers are unsupported");
                return CL_EUNPACK;

            default:
                cli_mark_scan_incomplete(ctx, "UDF main descriptor sequence contains an unsupported descriptor");
                return CL_EUNPACK;
        }
    }

    if (!have_terminator) {
        cli_mark_scan_incomplete(ctx, "UDF main descriptor sequence has no terminator");
        return CL_EPARSE;
    }
    if (!have_pvd || !have_pd || !have_lvd) {
        cli_mark_scan_incomplete(ctx, "UDF main descriptor sequence is missing a required descriptor");
        return CL_EPARSE;
    }

    return udf_scan_anchor_tree(ctx, &volume);
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
    if (!ctx->options)
        return CL_ENULLARG;

    if (offset < 32768) {
        cli_mark_scan_incomplete(ctx, "UDF inspection started before the mandatory descriptor area");
        return CL_EPARSE; /* Need 16 sectors at least 2048 bytes long */
    }

    ret = udf_checktimelimit(ctx, "UDF inspection reached the configured time limit");
    if (ret != CL_SUCCESS)
        goto done;

    ret = udf_scan_anchor_volume(ctx, offset);
    if (ret != CL_BREAK) {
        if ((ret == CL_SUCCESS || ret == CL_CLEAN) && ctx->scan_incomplete)
            ret = CL_EPARSE;
        return ret;
    }

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

    if ((ret == CL_SUCCESS || ret == CL_CLEAN) && ctx->scan_incomplete)
        ret = CL_EPARSE;

    return ret;
}
