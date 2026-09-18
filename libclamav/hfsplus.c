/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2013 Sourcefire, Inc.
 *
 *  Authors: David Raynor <draynor@sourcefire.com>
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
/**
 * Documentation:
 * - https://digital-forensics.sans.org/media/FOR518-Reference-Sheet.pdf
 * - https://github.com/sleuthkit/sleuthkit/blob/develop/tsk/fs/tsk_hfs.h
 * - https://github.com/unsound/hfsexplorer/tree/master/src/java/org/catacombae/hfs
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <fcntl.h>

#include "clamav.h"
#include "others.h"
#include "hfsplus.h"
#include "scanners.h"
#include "entconv.h"

#define DECMPFS_HEADER_MAGIC 0x636d7066
#define DECMPFS_HEADER_MAGIC_LE 0x66706d63
#define HFSPLUS_INLINE_OUTPUT_WINDOW (64U * 1024U)

static void headerrecord_to_host(hfsHeaderRecord *);
static void headerrecord_print(const char *, hfsHeaderRecord *);
static void nodedescriptor_to_host(hfsNodeDescriptor *);
static void nodedescriptor_print(const char *, hfsNodeDescriptor *);
static void forkdata_to_host(hfsPlusForkData *);
static void forkdata_print(const char *, hfsPlusForkData *);

static uint16_t hfsplus_read_be16(const uint8_t *data)
{
    uint16_t value;

    memcpy(&value, data, sizeof(value));
    return be16_to_host(value);
}

static uint32_t hfsplus_read_be32(const uint8_t *data)
{
    uint32_t value;

    memcpy(&value, data, sizeof(value));
    return be32_to_host(value);
}

static cl_error_t hfsplus_volumeheader(cli_ctx *, hfsPlusVolumeHeader **);
static cl_error_t hfsplus_readheader(cli_ctx *, hfsPlusVolumeHeader *, hfsNodeDescriptor *,
                                     hfsHeaderRecord *, int, const char *);
static cl_error_t hfsplus_scanfile(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
                                   uint32_t, uint8_t, hfsPlusForkData *, const char *, char **, uint64_t *, char *);
static cl_error_t hfsplus_validate_catalog(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *);
static cl_error_t hfsplus_fetch_node(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
                                     hfsHeaderRecord *, hfsPlusForkData *, uint32_t, uint8_t *,
                                     size_t, uint32_t, uint8_t);
static cl_error_t hfsplus_find_overflow_block(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
                                              uint32_t, uint8_t, uint32_t, uint64_t *);
static cl_error_t hfsplus_resolve_fork_block(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
                                             hfsPlusForkData *, uint32_t, uint8_t, uint64_t, uint64_t *);
static cl_error_t hfsplus_walk_catalog(cli_ctx *, hfsPlusVolumeHeader *, hfsHeaderRecord *,
                                       hfsHeaderRecord *, hfsHeaderRecord *, const char *);

cl_error_t cli_hfsplus_inflate_inline(cli_ctx *ctx, const uint8_t *input,
                                      size_t input_size, uint64_t expected_size,
                                      int output_fd, uint64_t *written)
{
    uint8_t output[HFSPLUS_INLINE_OUTPUT_WINDOW];
    z_stream stream;
    uint64_t total = 0;
    bool initialized = false;
    cl_error_t status = CL_SUCCESS;
    int z_ret;

    if (ctx == NULL || input == NULL || input_size == 0 || input_size > UINT_MAX ||
        output_fd < 0 || written == NULL)
        return CL_EARG;
    *written = 0;

    memset(&stream, 0, sizeof(stream));
    stream.avail_in = (uInt)input_size;
    stream.next_in  = (Bytef *)input;
    z_ret           = inflateInit2(&stream, 15 /* maximum windowBits size */);
    if (z_ret != Z_OK) {
        cli_mark_scan_incomplete(ctx, "HFS+ inline compressed decoder could not be initialized");
        return z_ret == Z_MEM_ERROR ? CL_EMEM : CL_EFORMAT;
    }
    initialized = true;

    for (;;) {
        uInt input_before;
        size_t produced;

        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "HFS+ inline compressed output reached the configured time limit");
            goto done;
        }

        stream.avail_out = sizeof(output);
        stream.next_out  = output;
        input_before     = stream.avail_in;
        z_ret            = inflate(&stream, Z_NO_FLUSH);
        produced         = sizeof(output) - stream.avail_out;

        if (cli_hfsplus_output_size_admission(total, produced, expected_size) != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "HFS+ inline compressed output exceeds its declared size");
            status = CL_EFORMAT;
            goto done;
        }
        if (produced != 0) {
            status = cli_checktimelimit(ctx);
            if (status != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "HFS+ inline compressed output reached the configured time limit");
                goto done;
            }
            if (cli_writen(output_fd, output, produced) != produced) {
                cli_mark_scan_incomplete(ctx, "HFS+ inline compressed output could not be written completely");
                status = CL_EWRITE;
                goto done;
            }
            total += produced;
        }

        if (z_ret == Z_STREAM_END)
            break;
        if (z_ret != Z_OK || (produced == 0 && stream.avail_in == input_before)) {
            cli_mark_scan_incomplete(ctx, "HFS+ inline compressed file ended before its declared size");
            status = CL_EFORMAT;
            goto done;
        }
    }

    if (total != expected_size || stream.avail_in != 0) {
        cli_mark_scan_incomplete(ctx, "HFS+ inline compressed file ended before its declared size");
        status = CL_EFORMAT;
        goto done;
    }
    *written = total;

done:
    if (initialized && inflateEnd(&stream) != Z_OK) {
        cli_mark_scan_incomplete(ctx, "HFS+ inline compressed decoder could not be finalized");
        if (status == CL_SUCCESS)
            status = CL_EFORMAT;
    }
    return status;
}

/* Header Record : fix endianness for useful fields */
static void headerrecord_to_host(hfsHeaderRecord *hdr)
{
    hdr->treeDepth     = be16_to_host(hdr->treeDepth);
    hdr->rootNode      = be32_to_host(hdr->rootNode);
    hdr->leafRecords   = be32_to_host(hdr->leafRecords);
    hdr->firstLeafNode = be32_to_host(hdr->firstLeafNode);
    hdr->lastLeafNode  = be32_to_host(hdr->lastLeafNode);
    hdr->nodeSize      = be16_to_host(hdr->nodeSize);
    hdr->maxKeyLength  = be16_to_host(hdr->maxKeyLength);
    hdr->totalNodes    = be32_to_host(hdr->totalNodes);
    hdr->freeNodes     = be32_to_host(hdr->freeNodes);
    hdr->attributes    = be32_to_host(hdr->attributes); /* not too useful */
}

/* Header Record : print details in debug mode */
static void headerrecord_print(const char *pfx, hfsHeaderRecord *hdr)
{
    cli_dbgmsg("%s Header: depth %hu root %u leafRecords %u firstLeaf %u lastLeaf %u nodeSize %hu\n",
               pfx, hdr->treeDepth, hdr->rootNode, hdr->leafRecords, hdr->firstLeafNode,
               hdr->lastLeafNode, hdr->nodeSize);
    cli_dbgmsg("%s Header: maxKeyLength %hu totalNodes %u freeNodes %u btreeType %hhu attributes %x\n",
               pfx, hdr->maxKeyLength, hdr->totalNodes, hdr->freeNodes,
               hdr->btreeType, hdr->attributes);
}

/* The header record identifies the complete leaf chain. A non-empty tree
 * with no declared last leaf is not an empty tree: accepting it lets a
 * truncated forward-link chain look like a complete scan. */
static cl_error_t hfsplus_validate_leaf_chain_header(cli_ctx *ctx, hfsHeaderRecord *header, const char *name)
{
    if (header->totalNodes == 0) {
        cli_dbgmsg("hfsplus_readheader: %s: tree declares no nodes\n", name);
        cli_mark_scan_incomplete(ctx, "HFS+ file-tree leaf chain header is malformed");
        return CL_EFORMAT;
    }

    if (header->firstLeafNode == 0) {
        if (header->lastLeafNode != 0 || header->leafRecords != 0) {
            cli_dbgmsg("hfsplus_readheader: %s: empty leaf chain has non-empty metadata\n", name);
            cli_mark_scan_incomplete(ctx, "HFS+ file-tree leaf chain header is malformed");
            return CL_EFORMAT;
        }
    } else if (header->firstLeafNode >= header->totalNodes ||
               header->lastLeafNode == 0 ||
               header->lastLeafNode >= header->totalNodes ||
               header->leafRecords == 0) {
        cli_dbgmsg("hfsplus_readheader: %s: leaf chain metadata is inconsistent\n", name);
        cli_mark_scan_incomplete(ctx, "HFS+ file-tree leaf chain header is malformed");
        return CL_EFORMAT;
    }

    return CL_CLEAN;
}

/* Node Descriptor : fix endianness for useful fields */
static void nodedescriptor_to_host(hfsNodeDescriptor *node)
{
    node->fLink      = be32_to_host(node->fLink);
    node->bLink      = be32_to_host(node->bLink);
    node->numRecords = be16_to_host(node->numRecords);
}

/* Node Descriptor : print details in debug mode */
static void nodedescriptor_print(const char *pfx, hfsNodeDescriptor *node)
{
    cli_dbgmsg("%s Desc: fLink %u bLink %u kind %d height %u numRecords %u\n",
               pfx, node->fLink, node->bLink, node->kind, node->height, node->numRecords);
}

/* ForkData : fix endianness */
static void forkdata_to_host(hfsPlusForkData *fork)
{
    int i;

    fork->logicalSize = be64_to_host(fork->logicalSize);
    fork->clumpSize   = be32_to_host(fork->clumpSize); /* does this matter for read-only? */
    fork->totalBlocks = be32_to_host(fork->totalBlocks);
    for (i = 0; i < 8; i++) {
        fork->extents[i].startBlock = be32_to_host(fork->extents[i].startBlock);
        fork->extents[i].blockCount = be32_to_host(fork->extents[i].blockCount);
    }
}

/* ForkData : print details in debug mode */
static void forkdata_print(const char *pfx, hfsPlusForkData *fork)
{
    int i;
    cli_dbgmsg("%s logicalSize " STDu64 " clumpSize " STDu32 " totalBlocks " STDu32 "\n", pfx,
               fork->logicalSize, fork->clumpSize, fork->totalBlocks);
    for (i = 0; i < 8; i++) {
        if (fork->extents[i].startBlock == 0)
            break;
        cli_dbgmsg("%s extent[%d] startBlock " STDu32 " blockCount " STDu32 "\n", pfx, i,
                   fork->extents[i].startBlock, fork->extents[i].blockCount);
    }
}

/* Read and convert the HFS+ volume header */
static cl_error_t hfsplus_volumeheader(cli_ctx *ctx, hfsPlusVolumeHeader **header)
{
    hfsPlusVolumeHeader *volHeader;
    const uint8_t *mPtr;
    uint64_t volumeSize;

    if (!header) {
        return CL_ENULLARG;
    }

    /* Start with volume header, 512 bytes at offset 1024 */
    if (ctx->fmap->len < 1536) {
        cli_dbgmsg("hfsplus_volumeheader: too short for HFS+\n");
        cli_mark_scan_incomplete(ctx, "HFS+ volume header is incomplete");
        return CL_EPARSE;
    }
    mPtr = fmap_need_off_once(ctx->fmap, 1024, 512);
    if (!mPtr) {
        cli_errmsg("hfsplus_volumeheader: cannot read header from map\n");
        cli_mark_scan_incomplete(ctx, "HFS+ volume header could not be read completely");
        return CL_EREAD;
    }

    volHeader = malloc(sizeof(hfsPlusVolumeHeader));
    if (!volHeader) {
        cli_errmsg("hfsplus_volumeheader: header malloc failed\n");
        cli_mark_scan_incomplete(ctx, "HFS+ volume header could not be allocated");
        return CL_EMEM;
    }
    *header = volHeader;
    memcpy(volHeader, mPtr, 512);

    volHeader->signature = be16_to_host(volHeader->signature);
    volHeader->version   = be16_to_host(volHeader->version);
    if ((volHeader->signature == 0x482B) && (volHeader->version == 4)) {
        cli_dbgmsg("hfsplus_volumeheader: HFS+ signature matched\n");
    } else if ((volHeader->signature == 0x4858) && (volHeader->version == 5)) {
        cli_dbgmsg("hfsplus_volumeheader: HFSX v5 signature matched\n");
    } else {
        cli_dbgmsg("hfsplus_volumeheader: no matching signature\n");
        cli_mark_scan_incomplete(ctx, "HFS+ volume header has an invalid signature");
        return CL_EPARSE;
    }
    /* skip fields that will definitely be ignored */
    volHeader->attributes  = be32_to_host(volHeader->attributes);
    volHeader->fileCount   = be32_to_host(volHeader->fileCount);
    volHeader->folderCount = be32_to_host(volHeader->folderCount);
    volHeader->blockSize   = be32_to_host(volHeader->blockSize);
    volHeader->totalBlocks = be32_to_host(volHeader->totalBlocks);

    cli_dbgmsg("HFS+ Header:\n");
    cli_dbgmsg("Signature: %x\n", volHeader->signature);
    cli_dbgmsg("Attributes: %x\n", volHeader->attributes);
    cli_dbgmsg("File Count: " STDu32 "\n", volHeader->fileCount);
    cli_dbgmsg("Folder Count: " STDu32 "\n", volHeader->folderCount);
    cli_dbgmsg("Block Size: " STDu32 "\n", volHeader->blockSize);
    cli_dbgmsg("Total Blocks: " STDu32 "\n", volHeader->totalBlocks);

    /* Block Size must be power of 2 between 512 and 1 MB */
    if ((volHeader->blockSize < 512) || (volHeader->blockSize > (1 << 20))) {
        cli_dbgmsg("hfsplus_volumeheader: Invalid blocksize\n");
        cli_mark_scan_incomplete(ctx, "HFS+ volume header has an invalid block size");
        return CL_EPARSE;
    }
    if (volHeader->blockSize & (volHeader->blockSize - 1)) {
        cli_dbgmsg("hfsplus_volumeheader: Invalid blocksize\n");
        cli_mark_scan_incomplete(ctx, "HFS+ volume header has an invalid block size");
        return CL_EPARSE;
    }

    /* The volume header describes the complete mapped HFS+ partition.  Do
     * this check before admitting any tree or fork extent so a truncated
     * image cannot look clean merely because the metadata it happens to
     * reference is still present before EOF. */
    volumeSize = (uint64_t)volHeader->totalBlocks * volHeader->blockSize;
    if (volHeader->totalBlocks == 0 || volumeSize < 1536 || volumeSize > ctx->fmap->len) {
        cli_dbgmsg("hfsplus_volumeheader: declared volume exceeds the input map\n");
        cli_mark_scan_incomplete(ctx, "HFS+ declared volume exceeds the input map");
        return CL_EFORMAT;
    }

    forkdata_to_host(&(volHeader->allocationFile));
    forkdata_to_host(&(volHeader->extentsFile));
    forkdata_to_host(&(volHeader->catalogFile));
    forkdata_to_host(&(volHeader->attributesFile));
    forkdata_to_host(&(volHeader->startupFile));

    if (cli_debug_flag) {
        forkdata_print("allocationFile", &(volHeader->allocationFile));
        forkdata_print("extentsFile", &(volHeader->extentsFile));
        forkdata_print("catalogFile", &(volHeader->catalogFile));
        forkdata_print("attributesFile", &(volHeader->attributesFile));
        forkdata_print("startupFile", &(volHeader->startupFile));
    }

    return CL_CLEAN;
}

/* Read and convert the header node */
static cl_error_t hfsplus_readheader(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsNodeDescriptor *nodeDesc,
                                     hfsHeaderRecord *headerRec, int headerType, const char *name)
{
    const uint8_t *mPtr = NULL;
    size_t offset;
    uint64_t offset64;
    uint32_t headerStartBlock;
    uint32_t minSize, maxSize;

    /* From TN1150: Node Size must be power of 2 between 512 and 32768 */
    /* Node Size for Catalog or Attributes must be at least 4096 */
    maxSize = 32768; /* Doesn't seem to vary */
    switch (headerType) {
        case HFS_FILETREE_ALLOCATION:
            headerStartBlock = volHeader->allocationFile.extents[0].startBlock;
            minSize  = 512;
            break;
        case HFS_FILETREE_EXTENTS:
            headerStartBlock = volHeader->extentsFile.extents[0].startBlock;
            minSize  = 512;
            break;
        case HFS_FILETREE_CATALOG:
            headerStartBlock = volHeader->catalogFile.extents[0].startBlock;
            minSize  = 4096;
            break;
        case HFS_FILETREE_ATTRIBUTES:
            headerStartBlock = volHeader->attributesFile.extents[0].startBlock;
            minSize  = 4096;
            break;
        case HFS_FILETREE_STARTUP:
            headerStartBlock = volHeader->startupFile.extents[0].startBlock;
            minSize  = 512;
            break;
        default:
            cli_errmsg("hfsplus_readheader: %s: invalid headerType %d\n", name, headerType);
            return CL_EARG;
    }
    /* A tree header occupies one allocation block. Compare block counts here;
     * blockSize is a byte count and cannot be compared to totalBlocks. */
    if (headerStartBlock >= volHeader->totalBlocks ||
        1U > volHeader->totalBlocks - headerStartBlock) {
        cli_dbgmsg("hfsplus_readheader: %s: headerNode is outside the declared volume\n", name);
        cli_mark_scan_incomplete(ctx, "HFS+ file-tree header is outside the declared volume");
        return CL_EFORMAT;
    }
    offset64 = (uint64_t)headerStartBlock * volHeader->blockSize;
    if (offset64 > SIZE_MAX) {
        cli_dbgmsg("hfsplus_readheader: %s: header offset exceeds the native fmap range\n", name);
        cli_mark_scan_incomplete(ctx, "HFS+ file-tree header coordinate is not representable");
        return CL_EFORMAT;
    }
    offset = (size_t)offset64;
    if (offset > ctx->fmap->len || volHeader->blockSize > ctx->fmap->len - offset) {
        cli_dbgmsg("hfsplus_readheader: %s: headerNode is out-of-range\n", name);
        cli_mark_scan_incomplete(ctx, "HFS+ file-tree header is outside the input map");
        return CL_EFORMAT;
    }
    mPtr   = fmap_need_off_once(ctx->fmap, offset, volHeader->blockSize);
    if (!mPtr) {
        cli_dbgmsg("hfsplus_readheader: %s: headerNode is out-of-range\n", name);
        cli_mark_scan_incomplete(ctx, "HFS+ file-tree header could not be read completely");
        return CL_EREAD;
    }

    /* Node descriptor first */
    memcpy(nodeDesc, mPtr, sizeof(hfsNodeDescriptor));
    nodedescriptor_to_host(nodeDesc);
    nodedescriptor_print(name, nodeDesc);
    if (nodeDesc->kind != HFS_NODEKIND_HEADER) {
        cli_dbgmsg("hfsplus_readheader: %s: headerNode not header kind\n", name);
        cli_mark_scan_incomplete(ctx, "HFS+ file-tree header is malformed");
        return CL_EFORMAT;
    }
    if ((nodeDesc->bLink != 0) || (nodeDesc->height != 0) || (nodeDesc->numRecords != 3)) {
        cli_dbgmsg("hfsplus_readheader: %s: Invalid headerNode\n", name);
        cli_mark_scan_incomplete(ctx, "HFS+ file-tree header is malformed");
        return CL_EFORMAT;
    }

    /* Then header record */
    memcpy(headerRec, mPtr + sizeof(hfsNodeDescriptor), sizeof(hfsHeaderRecord));
    headerrecord_to_host(headerRec);
    headerrecord_print(name, headerRec);

    if ((headerRec->nodeSize < minSize) || (headerRec->nodeSize > maxSize)) {
        cli_dbgmsg("hfsplus_readheader: %s: Invalid nodesize\n", name);
        cli_mark_scan_incomplete(ctx, "HFS+ file-tree header is malformed");
        return CL_EFORMAT;
    }
    if (headerRec->nodeSize & (headerRec->nodeSize - 1)) {
        cli_dbgmsg("hfsplus_readheader: %s: Invalid nodesize\n", name);
        cli_mark_scan_incomplete(ctx, "HFS+ file-tree header is malformed");
        return CL_EFORMAT;
    }
    /* KeyLength must be between 6 and 516 for catalog */
    if (headerType == HFS_FILETREE_CATALOG) {
        if ((headerRec->maxKeyLength < 6) || (headerRec->maxKeyLength > 516)) {
            cli_dbgmsg("hfsplus_readheader: %s: Invalid cat maxKeyLength\n", name);
            cli_mark_scan_incomplete(ctx, "HFS+ file-tree header is malformed");
            return CL_EFORMAT;
        }
        if (headerRec->maxKeyLength > (headerRec->nodeSize / 2)) {
            cli_dbgmsg("hfsplus_readheader: %s: Invalid cat maxKeyLength based on nodeSize\n", name);
            cli_mark_scan_incomplete(ctx, "HFS+ file-tree header is malformed");
            return CL_EFORMAT;
        }
    } else if (headerType == HFS_FILETREE_EXTENTS) {
        if (headerRec->maxKeyLength != 10) {
            cli_dbgmsg("hfsplus_readheader: %s: Invalid ext maxKeyLength\n", name);
            cli_mark_scan_incomplete(ctx, "HFS+ file-tree header is malformed");
            return CL_EFORMAT;
        }
    }

    if (hfsplus_validate_leaf_chain_header(ctx, headerRec, name) != CL_SUCCESS)
        return CL_EFORMAT;

    /* hdr->treeDepth = rootnode->height */
    return CL_CLEAN;
}

/**
 * @brief Read and dump a file for scanning.
 *
 * If the filename pointer is provided, the file name will be set and the
 * resulting file will __NOT__ be scanned. The returned pointer must be freed
 * by the caller. If the pointer is NULL, the file will be scanned and,
 * depending on the --leave-temps value, deleted or not.
 *
 * @param ctx           The current scan context
 * @param volHeader     Volume header
 * @param extHeader     Extent overflow file header
 * @param fileID        Catalog file ID owning the fork
 * @param forkType      HFS+ data or resource fork selector
 * @param fork          Fork Data
 * @param dirname       Temp directory name
 * @param[out] filename (optional) temp file name
 * @param orig_filename (optional) Original filename
 * @return cl_error_t
 */
static cl_error_t hfsplus_scanfile(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *extHeader,
                                   uint32_t fileID, uint8_t forkType, hfsPlusForkData *fork,
                                   const char *dirname, char **filename,
                                   uint64_t *temporary_reserved_out, char *orig_filename)
{
    cl_error_t status = CL_SUCCESS;
    const uint8_t *mPtr = NULL;
    char *tmpname       = NULL;
    int ofd             = -1;
    uint64_t targetSize;
    uint64_t temporary_reserved = 0;
    uint64_t logicalBlock = 0;

    if (filename)
        *filename = NULL;
    if (temporary_reserved_out)
        *temporary_reserved_out = 0;

    /* An empty fork has no data to extract. A non-empty fork with no
     * allocation blocks, however, is structurally incomplete and must not be
     * treated as a clean empty child. */
    if (!fork || (fork->logicalSize == 0)) {
        cli_dbgmsg("hfsplus_scanfile: Empty file.\n");
        goto done;
    }
    if (fork->totalBlocks == 0) {
        cli_mark_scan_incomplete(ctx, "HFS+ fork declares data without allocation blocks");
        status = CL_EFORMAT;
        goto done;
    }

    /* check limits */
    targetSize = fork->logicalSize;
#if SIZEOF_LONG < 8
    if (targetSize > ULONG_MAX) {
        cli_dbgmsg("hfsplus_scanfile: File too large for limit check.\n");
        cli_mark_scan_incomplete(ctx, "HFS+ fork size cannot be represented for limit checking");
        status = CL_EFORMAT;
        goto done;
    }
#endif
    status = cli_checklimits("hfsplus_scanfile", ctx, targetSize, 0, 0);
    if (status != CL_SUCCESS) {
        goto done;
    }

    if (targetSize > SIZE_MAX || cli_scan_reserve_temporary(ctx, targetSize) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "HFS+ extracted fork exceeds temporary storage limits");
        status = CL_ERESOURCE;
        goto done;
    }
    temporary_reserved = targetSize;

    status = cli_checktimelimit(ctx);
    if (status != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "HFS+ fork temporary admission reached the configured time limit");
        goto done;
    }

    /* open file */
    status = cli_gentempfd(dirname, &tmpname, &ofd);
    if (status != CL_SUCCESS) {
        cli_dbgmsg("hfsplus_scanfile: Cannot generate temporary file.\n");
        cli_mark_scan_incomplete(ctx, "HFS+ fork temporary output could not be created");
        goto done;
    }
    cli_dbgmsg("hfsplus_scanfile: Extracting to %s\n", tmpname);

    /* Dump file, logical block by logical block. The resolver transparently
     * follows the inline record and any ExtentOverflow records. */
    while (targetSize != 0) {
        uint64_t realFileBlock;
        uint64_t blockOffset64;
        if (logicalBlock >= fork->totalBlocks) {
            cli_dbgmsg("hfsplus_scanfile: output all blocks, remaining size " STDu64 "\n", targetSize);
            break;
        }

        status = hfsplus_resolve_fork_block(ctx, volHeader, extHeader, fork, fileID, forkType,
                                            logicalBlock, &realFileBlock);
        if (status != CL_SUCCESS)
            goto done;

        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "HFS+ fork extraction reached the configured time limit");
            goto done;
        }

        size_t to_write = (targetSize < (uint64_t)volHeader->blockSize) ? (size_t)targetSize : (size_t)volHeader->blockSize;
        size_t written;
        if (realFileBlock > UINT64_MAX / volHeader->blockSize) {
            cli_mark_scan_incomplete(ctx, "HFS+ fork block coordinate overflowed");
            status = CL_EFORMAT;
            goto done;
        }
        blockOffset64 = realFileBlock * volHeader->blockSize;
        if (blockOffset64 > SIZE_MAX || blockOffset64 > ctx->fmap->len ||
            volHeader->blockSize > ctx->fmap->len - (size_t)blockOffset64) {
            cli_dbgmsg("hfsplus_scanfile: block offset exceeds the input map\n");
            cli_mark_scan_incomplete(ctx, "HFS+ fork block is outside the input map");
            status = CL_EFORMAT;
            goto done;
        }

        mPtr = fmap_need_off_once(ctx->fmap, (size_t)blockOffset64, volHeader->blockSize);
        if (!mPtr) {
            cli_errmsg("hfsplus_scanfile: map error\n");
            cli_mark_scan_incomplete(ctx, "HFS+ fork contents could not be read completely");
            status = CL_EREAD;
            goto done;
        }

        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "HFS+ fork output reached the configured time limit");
            goto done;
        }
        written = cli_writen(ofd, mPtr, to_write);
        if (written != to_write) {
            cli_errmsg("hfsplus_scanfile: write error\n");
            cli_mark_scan_incomplete(ctx, "HFS+ fork contents could not be written completely");
            status = CL_EWRITE;
            goto done;
        }

        targetSize -= to_write;
        logicalBlock++;
    }

    if (targetSize != 0) {
        cli_mark_scan_incomplete(ctx, "HFS+ fork ended before its declared size");
        status = CL_EFORMAT;
        goto done;
    }

    /* Now that we're done, ...
     *  A) if filename output param is provided, just pass back the filename.
     *  B) otherwise scan the file.
     */
    if (filename) {
        if (NULL == temporary_reserved_out) {
            cli_mark_scan_incomplete(ctx, "HFS+ temporary reservation ownership was not provided");
            status = CL_EARG;
            goto done;
        }
        *filename = tmpname;
        *temporary_reserved_out = temporary_reserved;
        temporary_reserved = 0;

    } else {
        status = cli_magic_scan_desc_type_reserved(ofd, tmpname, ctx, CL_TYPE_ANY, orig_filename,
                                                   LAYER_ATTRIBUTES_NONE);
        if (status != CL_SUCCESS) {
            goto done;
        }

    }

done:

    if (ofd >= 0) {
        if (close(ofd) != 0) {
            cli_mark_scan_incomplete(ctx, "HFS+ temporary output could not be closed");
            status = cli_merge_cleanup_status(status, CL_EWRITE);
        }
    }
    if ((NULL == filename) ||     // output param not provided, which means we should clean up the temp file,
        (status != CL_SUCCESS)) { // or we failed, so we should clean up the temp file.

        if (tmpname) {
            if (!ctx->engine->keeptmp) {
                if (cli_unlink(tmpname)) {
                    cli_mark_scan_incomplete(ctx, "HFS+ temporary output could not be removed");
                    status = cli_merge_cleanup_status(status, CL_EUNLINK);
                }
            }
            free(tmpname);
        }
    }

    if (temporary_reserved)
        cli_scan_release_temporary(ctx, temporary_reserved);

    return status;
}

/* Calculate true node limit for catalogFile */
static cl_error_t hfsplus_validate_catalog(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *catHeader)
{
    hfsPlusForkData *catFork;
    uint64_t requiredSize;

    catFork = &(volHeader->catalogFile);
    if (catFork->totalBlocks >= volHeader->totalBlocks) {
        cli_dbgmsg("hfsplus_validate_catalog: catFork totalBlocks too large!\n");
        cli_mark_scan_incomplete(ctx, "HFS+ catalog fork is outside the volume");
        return CL_EFORMAT;
    }
    if (catFork->logicalSize > (uint64_t)catFork->totalBlocks * volHeader->blockSize) {
        cli_dbgmsg("hfsplus_validate_catalog: catFork logicalSize too large!\n");
        cli_mark_scan_incomplete(ctx, "HFS+ catalog fork size is inconsistent");
        return CL_EFORMAT;
    }
    requiredSize = (uint64_t)catHeader->totalNodes * catHeader->nodeSize;
    if (catFork->logicalSize < requiredSize) {
        cli_dbgmsg("hfsplus_validate_catalog: too many nodes for catFile\n");
        cli_mark_scan_incomplete(ctx, "HFS+ catalog fork ends before its declared nodes");
        return CL_EFORMAT;
    }

    return CL_CLEAN;
}

/* Check if an attribute is present in the attribute map */
static cl_error_t hfsplus_check_attribute(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *attrHeader,
                                          hfsHeaderRecord *extHeader, uint32_t expectedCnid, const uint8_t name[],
                                          uint32_t nameLen, int *found, uint8_t record[], size_t *recordSize)
{
    cl_error_t status = CL_SUCCESS;
    uint16_t nodeSize, recordNum, topOfOffsets;
    uint16_t recordStart, nextDist, nextStart;
    uint8_t *nodeBuf = NULL;
    uint32_t thisNode, nodeLimit, nodesScanned = 0;
    uint64_t leafRecordsScanned = 0;
    bool foundAttr = false;
    bool reachedLastLeaf;

    if (found) {
        *found = 0;
    }

    if (!attrHeader) {
        return CL_EARG;
    }

    nodeLimit = MIN(attrHeader->totalNodes, HFSPLUS_NODE_LIMIT);
    thisNode  = attrHeader->firstLeafNode;
    nodeSize  = attrHeader->nodeSize;
    reachedLastLeaf = (thisNode == 0);

    /* Need to buffer current node, map will keep moving */
    nodeBuf = cli_max_malloc(nodeSize);
    if (!nodeBuf) {
        cli_dbgmsg("hfsplus_check_attribute: failed to acquire node buffer, "
                   "size " STDu32 "\n",
                   nodeSize);
        cli_mark_scan_incomplete(ctx, "HFS+ attributes tree node buffer could not be allocated");
        status = CL_EMEM;
        goto done;
    }

    /* Walk catalog leaf nodes, and scan contents of each */
    /* Because we want to scan them all, the index nodes add no value */
    while (status == CL_SUCCESS && !foundAttr) {
        hfsNodeDescriptor nodeDesc;

        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "HFS+ attributes traversal reached the configured time limit");
            goto done;
        }

        if (thisNode == 0) {
            cli_dbgmsg("hfsplus_check_attribute: reached end of leaf nodes.\n");
            if (!reachedLastLeaf) {
                cli_mark_scan_incomplete(ctx, "HFS+ attributes leaf chain ended before its declared last leaf");
                status = CL_EFORMAT;
                goto done;
            }
            break;
        }
        if (nodesScanned >= nodeLimit) {
            cli_dbgmsg("hfsplus_check_attribute: node scan limit reached.\n");
            cli_mark_scan_incomplete(ctx, "HFS+ attributes tree node scan limit reached");
            status = CL_EMAXFILES;
            goto done;
        }
        nodesScanned++;

        /* fetch node into buffer */
        status = hfsplus_fetch_node(ctx, volHeader, attrHeader, extHeader, &(volHeader->attributesFile), thisNode,
                                    nodeBuf, nodeSize, hfsAttributesFileID, HFSPLUS_FORKTYPE_DATA);
        if (status != CL_SUCCESS) {
            cli_dbgmsg("hfsplus_check_attribute: node fetch failed.\n");
            goto done;
        }
        memcpy(&nodeDesc, nodeBuf, 14);

        /* convert and validate node */
        nodedescriptor_to_host(&nodeDesc);
        nodedescriptor_print("leaf attribute node", &nodeDesc);
        if ((nodeDesc.kind != HFS_NODEKIND_LEAF) || (nodeDesc.height != 1)) {
            cli_dbgmsg("hfsplus_check_attribute: invalid leaf node!\n");
            cli_mark_scan_incomplete(ctx, "HFS+ attributes tree node is malformed");
            status = CL_EFORMAT;
            goto done;
        }
        if ((nodeSize / 4) < nodeDesc.numRecords) {
            cli_dbgmsg("hfsplus_check_attribute: too many leaf records for one node!\n");
            cli_mark_scan_incomplete(ctx, "HFS+ attributes tree node is malformed");
            status = CL_EFORMAT;
            goto done;
        }
        leafRecordsScanned += (uint64_t)nodeDesc.numRecords;
        if (leafRecordsScanned > attrHeader->leafRecords) {
            cli_mark_scan_incomplete(ctx, "HFS+ attributes leaf record count is inconsistent");
            status = CL_EFORMAT;
            goto done;
        }

        /* Walk this node's records and scan */
        recordStart = 14; /* 1st record can be after end of node descriptor */
        /* offsets take 1 u16 per at the end of the node, along with an empty space offset */
        topOfOffsets = nodeSize - (nodeDesc.numRecords * 2) - 2;
        for (recordNum = 0; recordNum < nodeDesc.numRecords; recordNum++) {
            uint32_t keylen;
            hfsPlusAttributeKey attrKey;
            hfsPlusAttributeRecord attrRec;
            size_t attrRecordOffset;

            /* Locate next record */
            nextDist  = nodeSize - (recordNum * 2) - 2;
            nextStart = nodeBuf[nextDist] * 0x100 + nodeBuf[nextDist + 1];
            /* Check record location */
            if ((nextStart > topOfOffsets - 1) || (nextStart < recordStart)) {
                cli_dbgmsg("hfsplus_check_attribute: bad record location %x for %u!\n", nextStart, recordNum);
                cli_mark_scan_incomplete(ctx, "HFS+ attributes tree record is malformed");
                status = CL_EFORMAT;
                goto done;
            }
            recordStart = nextStart;
            if (recordStart + sizeof(attrKey) >= topOfOffsets) {
                cli_dbgmsg("hfsplus_check_attribute: Not enough data for an attribute key at location %x for %u!\n",
                           nextStart, recordNum);
                cli_mark_scan_incomplete(ctx, "HFS+ attributes tree record is incomplete");
                status = CL_EFORMAT;
                goto done;
            }

            memcpy(&attrKey, &nodeBuf[recordStart], sizeof(attrKey));
            attrKey.keyLength  = be16_to_host(attrKey.keyLength);
            attrKey.cnid       = be32_to_host(attrKey.cnid);
            attrKey.startBlock = be32_to_host(attrKey.startBlock);
            attrKey.nameLength = be16_to_host(attrKey.nameLength);

            /* Get record key length */
            keylen = (uint32_t)nodeBuf[recordStart] * 0x100U + nodeBuf[recordStart + 1];
            if (keylen & 1U)
                keylen++; /* pad 1 byte if required to make 2-byte align */
            /* Validate keylen */
            if (recordStart + attrKey.keyLength + 4 >= topOfOffsets) {
                cli_dbgmsg("hfsplus_check_attribute: key too long for location %x for %u!\n",
                           nextStart, recordNum);
                cli_mark_scan_incomplete(ctx, "HFS+ attributes tree key is malformed");
                status = CL_EFORMAT;
                goto done;
            }

            if ((size_t)recordStart + sizeof(hfsPlusAttributeKey) +
                    (size_t)attrKey.nameLength * 2U >= (size_t)topOfOffsets) {
                cli_dbgmsg("hfsplus_check_attribute: Attribute name is longer than expected: %u\n", attrKey.nameLength);
                cli_mark_scan_incomplete(ctx, "HFS+ attributes tree name is malformed");
                status = CL_EFORMAT;
                goto done;
            }

            if (attrKey.cnid == expectedCnid && attrKey.nameLength * 2 == nameLen && memcmp(&nodeBuf[recordStart + 14], name, nameLen) == 0) {
                attrRecordOffset = (size_t)recordStart + sizeof(hfsPlusAttributeKey) + (size_t)attrKey.nameLength * 2U;
                if (attrRecordOffset > (size_t)topOfOffsets ||
                    sizeof(attrRec) > (size_t)topOfOffsets - attrRecordOffset) {
                    cli_mark_scan_incomplete(ctx, "HFS+ attributes tree record is incomplete");
                    status = CL_EFORMAT;
                    goto done;
                }

                memcpy(&attrRec, &nodeBuf[attrRecordOffset], sizeof(attrRec));
                attrRec.recordType    = be32_to_host(attrRec.recordType);
                attrRec.attributeSize = be32_to_host(attrRec.attributeSize);

                if (attrRec.recordType != HFSPLUS_RECTYPE_INLINE_DATA_ATTRIBUTE) {
                    cli_dbgmsg("hfsplus_check_attribute: Unexpected attribute record type 0x%x\n", attrRec.recordType);
                    continue;
                }

                if (attrRec.attributeSize > *recordSize) {
                    cli_mark_scan_incomplete(ctx, "HFS+ compressed-file attribute is larger than its buffer");
                    status = CL_EFORMAT;
                    goto done;
                }

                if ((size_t)attrRec.attributeSize > (size_t)topOfOffsets - attrRecordOffset - sizeof(attrRec)) {
                    cli_mark_scan_incomplete(ctx, "HFS+ attributes tree record is incomplete");
                    status = CL_EFORMAT;
                    goto done;
                }

                memcpy(record, &nodeBuf[attrRecordOffset + sizeof(attrRec)], attrRec.attributeSize);
                *recordSize = attrRec.attributeSize;

                if (found) {
                    *found = 1;
                }

                foundAttr = true;
                break;
            }
        }

        if (foundAttr)
            break;

        if (thisNode == attrHeader->lastLeafNode) {
            if (nodeDesc.fLink != 0) {
                cli_mark_scan_incomplete(ctx, "HFS+ attributes leaf chain exceeds its declared last leaf");
                status = CL_EFORMAT;
                goto done;
            }
            if (leafRecordsScanned != attrHeader->leafRecords) {
                cli_mark_scan_incomplete(ctx, "HFS+ attributes leaf record count is inconsistent");
                status = CL_EFORMAT;
                goto done;
            }
            reachedLastLeaf = true;
            thisNode = 0;
        } else if (nodeDesc.fLink == 0) {
            cli_mark_scan_incomplete(ctx, "HFS+ attributes leaf chain ended before its declared last leaf");
            status = CL_EFORMAT;
            goto done;
        } else if (thisNode == nodeDesc.fLink) {
            cli_mark_scan_incomplete(ctx, "HFS+ attributes traversal contains a cycle");
            status = CL_EFORMAT;
            goto done;
        } else {
            thisNode = nodeDesc.fLink;
        }
    }

done:

    if (nodeBuf != NULL) {
        free(nodeBuf);
        nodeBuf = NULL;
    }

    return status;
}

/* Fetch a node's contents into the buffer */
static cl_error_t hfsplus_fetch_node(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *catHeader,
                                     hfsHeaderRecord *extHeader, hfsPlusForkData *catFork, uint32_t node, uint8_t *buff,
                                     size_t buffSize, uint32_t fileID, uint8_t forkType)
{
    uint64_t catalogOffset;
    uint64_t startBlock, startOffset;
    uint64_t endBlock, endSize;
    uint64_t curBlock;
    uint64_t realFileBlock;
    uint32_t readSize;
    size_t fileOffset = 0;
    uint32_t buffOffset = 0;

    /* Make sure node is in range */
    if (node >= catHeader->totalNodes) {
        cli_dbgmsg("hfsplus_fetch_node: invalid node number " STDu32 "\n", node);
        cli_mark_scan_incomplete(ctx, "HFS+ file-tree node number is invalid");
        return CL_EFORMAT;
    }

    /* Need one block */
    /* First, calculate the node's offset within the catalog */
    catalogOffset = (uint64_t)node * catHeader->nodeSize;
    /* Determine which block of the catalog we need */
    startBlock  = catalogOffset / volHeader->blockSize;
    startOffset = catalogOffset % volHeader->blockSize;
    endBlock    = (catalogOffset + catHeader->nodeSize - 1) / volHeader->blockSize;
    endSize     = ((catalogOffset + catHeader->nodeSize - 1) % volHeader->blockSize) + 1;
    cli_dbgmsg("hfsplus_fetch_node: need catalog block " STDu64 "\n", startBlock);
    if (startBlock >= catFork->totalBlocks || endBlock >= catFork->totalBlocks) {
        cli_dbgmsg("hfsplus_fetch_node: block number invalid!\n");
        cli_mark_scan_incomplete(ctx, "HFS+ file-tree node block is invalid");
        return CL_EFORMAT;
    }

    for (curBlock = startBlock; curBlock <= endBlock; ++curBlock) {
        cl_error_t resolve_status = hfsplus_resolve_fork_block(ctx, volHeader, extHeader, catFork, fileID,
                                                                forkType, curBlock, &realFileBlock);
        if (resolve_status != CL_SUCCESS)
            return resolve_status;

        /* Block found */
        if (realFileBlock >= volHeader->totalBlocks) {
            cli_dbgmsg("hfsplus_fetch_node: block past end of volume\n");
            cli_mark_scan_incomplete(ctx, "HFS+ file-tree node block is outside the volume");
            return CL_EFORMAT;
        }
        {
            uint64_t fileOffset64 = (uint64_t)realFileBlock * volHeader->blockSize;
            if (fileOffset64 > SIZE_MAX) {
                cli_dbgmsg("hfsplus_fetch_node: file offset exceeds the native fmap range\n");
                cli_mark_scan_incomplete(ctx, "HFS+ file-tree node coordinate is not representable");
                return CL_EFORMAT;
            }
            fileOffset = (size_t)fileOffset64;
        }
        readSize = volHeader->blockSize;

        if (curBlock == startBlock) {
            if (startOffset > SIZE_MAX - fileOffset) {
                cli_dbgmsg("hfsplus_fetch_node: node offset exceeds the native fmap range\n");
                cli_mark_scan_incomplete(ctx, "HFS+ file-tree node coordinate is not representable");
                return CL_EFORMAT;
            }
            fileOffset += (size_t)startOffset;
        } else if (curBlock == endBlock) {
            readSize = (uint32_t)endSize;
        }

        if ((buffOffset + readSize) > buffSize) {
            cli_dbgmsg("hfsplus_fetch_node: Not enough space for read\n");
            cli_mark_scan_incomplete(ctx, "HFS+ file-tree node buffer is too small");
            return CL_EFORMAT;
        }

        if (fileOffset > ctx->fmap->len || readSize > ctx->fmap->len - fileOffset) {
            cli_dbgmsg("hfsplus_fetch_node: node range is outside the input map\n");
            cli_mark_scan_incomplete(ctx, "HFS+ file-tree node is outside the input map");
            return CL_EFORMAT;
        }

        {
            size_t bytesRead = fmap_readn(ctx->fmap, buff + buffOffset, fileOffset, readSize);

            if (bytesRead == (size_t)-1) {
                cli_dbgmsg("hfsplus_fetch_node: node read failed\n");
                cli_mark_scan_incomplete(ctx, "HFS+ file-tree node could not be read completely");
                return CL_EREAD;
            }
            if (bytesRead != readSize) {
                cli_dbgmsg("hfsplus_fetch_node: not all bytes read\n");
                cli_mark_scan_incomplete(ctx, "HFS+ file-tree node is incomplete");
                return CL_EFORMAT;
            }
        }
        buffOffset += readSize;
    }

    return CL_CLEAN;
}

/* Resolve one logical fork block through the inline extent record and, when
 * the eight inline descriptors are exhausted, the ExtentOverflow B-tree. */
static cl_error_t hfsplus_resolve_fork_block(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader,
                                             hfsHeaderRecord *extHeader, hfsPlusForkData *fork,
                                             uint32_t fileID, uint8_t forkType, uint64_t logicalBlock,
                                             uint64_t *realFileBlock)
{
    uint64_t remaining = logicalBlock;
    uint64_t inlineFileBlock = 0;
    bool inlineFound = false;
    uint8_t extentNum;

    if (ctx == NULL || volHeader == NULL || fork == NULL || realFileBlock == NULL ||
        volHeader->blockSize == 0 || logicalBlock >= fork->totalBlocks) {
        cli_mark_scan_incomplete(ctx, "HFS+ fork logical block is invalid");
        return CL_EFORMAT;
    }

    for (extentNum = 0; extentNum < 8; extentNum++) {
        hfsPlusExtentDescriptor *extent = &fork->extents[extentNum];
        uint32_t startBlock            = extent->startBlock;
        uint32_t blockCount            = extent->blockCount;

        if (startBlock == 0 || blockCount == 0) {
            uint8_t trailingExtent;

            /* Zero descriptors terminate the inline list. A fork normally
             * uses far fewer than eight descriptors; only a half-empty
             * descriptor or a non-zero descriptor after the terminator is
             * malformed. */
            if (startBlock != 0 || blockCount != 0) {
                cli_mark_scan_incomplete(ctx, "HFS+ fork extent is incomplete");
                return CL_EFORMAT;
            }
            for (trailingExtent = (uint8_t)(extentNum + 1); trailingExtent < 8; trailingExtent++) {
                if (fork->extents[trailingExtent].startBlock != 0 ||
                    fork->extents[trailingExtent].blockCount != 0) {
                    cli_mark_scan_incomplete(ctx, "HFS+ fork extent follows its terminator");
                    return CL_EFORMAT;
                }
            }
            break;
        }
        if ((startBlock & 0x10000000U) && (blockCount & 0x10000000U)) {
            cli_mark_scan_incomplete(ctx, "HFS+ fork extent is malformed");
            return CL_EFORMAT;
        }
        if (startBlock >= volHeader->totalBlocks ||
            blockCount > volHeader->totalBlocks - startBlock) {
            cli_mark_scan_incomplete(ctx, "HFS+ fork extent is outside the volume");
            return CL_EFORMAT;
        }
        if (remaining < blockCount) {
            inlineFileBlock = (uint64_t)startBlock + remaining;
            inlineFound = true;
            remaining = 0;
        } else {
            remaining -= blockCount;
        }
    }

    if (inlineFound) {
        *realFileBlock = inlineFileBlock;
        return CL_SUCCESS;
    }

    if (fileID == hfsExtentsFileID && forkType == HFSPLUS_FORKTYPE_DATA) {
        cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow file exceeds its inline extents");
        return CL_EFORMAT;
    }
    if (logicalBlock > UINT32_MAX) {
        cli_mark_scan_incomplete(ctx, "HFS+ fork ExtentOverflow coordinate is not representable");
        return CL_EFORMAT;
    }

    return hfsplus_find_overflow_block(ctx, volHeader, extHeader, fileID, forkType,
                                       (uint32_t)logicalBlock, realFileBlock);
}

/* Find the physical block for a logical block in one file/fork's
 * ExtentOverflow records. The extents B-tree is itself read through its
 * inline fork record; recursively overflowing the ExtentOverflow file is an
 * invalid input rather than an unbounded lookup. */
static cl_error_t hfsplus_find_overflow_block(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader,
                                              hfsHeaderRecord *extHeader, uint32_t fileID,
                                              uint8_t forkType, uint32_t logicalBlock,
                                              uint64_t *realFileBlock)
{
    uint8_t *nodeBuf = NULL;
    uint32_t thisNode;
    uint32_t nodeLimit;
    uint32_t nodesScanned = 0;
    uint64_t leafRecordsScanned = 0;
    uint64_t foundFileBlock = 0;
    bool reachedLastLeaf;
    bool found = false;
    cl_error_t status = CL_SUCCESS;

    if (ctx == NULL || volHeader == NULL || extHeader == NULL || realFileBlock == NULL) {
        cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow lookup arguments are invalid");
        return CL_EFORMAT;
    }

    nodeLimit       = MIN(extHeader->totalNodes, HFSPLUS_NODE_LIMIT);
    thisNode        = extHeader->firstLeafNode;
    reachedLastLeaf = (thisNode == 0);
    if (thisNode == 0 || nodeLimit == 0) {
        cli_mark_scan_incomplete(ctx, "HFS+ fork ExtentOverflow record is missing");
        return CL_EFORMAT;
    }

    nodeBuf = cli_max_malloc(extHeader->nodeSize);
    if (nodeBuf == NULL) {
        cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow node buffer could not be allocated");
        return CL_EMEM;
    }

    while (status == CL_SUCCESS && thisNode != 0) {
        hfsNodeDescriptor nodeDesc;
        uint16_t nodeSize = extHeader->nodeSize;
        uint16_t recordNum;
        uint16_t recordStart = sizeof(hfsNodeDescriptor);
        uint16_t topOfOffsets;

        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow traversal reached the configured time limit");
            goto done;
        }
        if (nodesScanned++ >= nodeLimit) {
            cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow node scan limit reached");
            status = CL_EMAXFILES;
            goto done;
        }

        status = hfsplus_fetch_node(ctx, volHeader, extHeader, NULL, &volHeader->extentsFile,
                                    thisNode, nodeBuf, nodeSize, hfsExtentsFileID,
                                    HFSPLUS_FORKTYPE_DATA);
        if (status != CL_SUCCESS)
            goto done;

        memcpy(&nodeDesc, nodeBuf, sizeof(nodeDesc));
        nodedescriptor_to_host(&nodeDesc);
        if (nodeDesc.kind != HFS_NODEKIND_LEAF || nodeDesc.height != 1) {
            cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow leaf node is malformed");
            status = CL_EFORMAT;
            goto done;
        }
        if (nodeDesc.numRecords > nodeSize / 4U) {
            cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow leaf node is malformed");
            status = CL_EFORMAT;
            goto done;
        }
        if ((uint32_t)nodeDesc.numRecords * 2U + 2U > nodeSize) {
            cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow leaf offsets are malformed");
            status = CL_EFORMAT;
            goto done;
        }
        topOfOffsets = (uint16_t)(nodeSize - ((uint32_t)nodeDesc.numRecords * 2U) - 2U);

        for (recordNum = 0; recordNum < nodeDesc.numRecords; recordNum++) {
            uint16_t nextDist = (uint16_t)(nodeSize - ((uint32_t)recordNum * 2U) - 2U);
            uint16_t nextStart;
            uint16_t keyLength;
            size_t extentOffset;
            hfsPlusExtentKey key;
            uint64_t relative;
            uint8_t extentNum;

            nextStart = hfsplus_read_be16(nodeBuf + nextDist);
            if (nextStart < recordStart || nextStart >= topOfOffsets) {
                cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow record offset is malformed");
                status = CL_EFORMAT;
                goto done;
            }
            recordStart = nextStart;
            if (recordStart > topOfOffsets - sizeof(uint16_t)) {
                cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow record is incomplete");
                status = CL_EFORMAT;
                goto done;
            }
            keyLength = hfsplus_read_be16(nodeBuf + recordStart);
            if (keyLength != sizeof(hfsPlusExtentKey) - sizeof(uint16_t)) {
                cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow key is malformed");
                status = CL_EFORMAT;
                goto done;
            }
            if ((size_t)recordStart + sizeof(hfsPlusExtentKey) > topOfOffsets) {
                cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow record is incomplete");
                status = CL_EFORMAT;
                goto done;
            }
            extentOffset = (size_t)recordStart + sizeof(hfsPlusExtentKey);
            if (sizeof(hfsPlusExtentRecord) > (size_t)topOfOffsets - extentOffset) {
                cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow extent record is incomplete");
                status = CL_EFORMAT;
                goto done;
            }
            memcpy(&key, nodeBuf + recordStart, sizeof(key));
            key.keyLength = be16_to_host(key.keyLength);
            key.fileID    = be32_to_host(key.fileID);
            key.startBlock = be32_to_host(key.startBlock);
            leafRecordsScanned++;

            if (key.fileID != fileID || key.forkType != forkType || key.startBlock > logicalBlock)
                continue;

            relative = (uint64_t)logicalBlock - key.startBlock;
            for (extentNum = 0; extentNum < 8; extentNum++) {
                const uint8_t *extentData = nodeBuf + extentOffset + extentNum * sizeof(hfsPlusExtentDescriptor);
                uint32_t startBlock        = hfsplus_read_be32(extentData);
                uint32_t blockCount        = hfsplus_read_be32(extentData + sizeof(uint32_t));

                if (startBlock == 0 || blockCount == 0)
                    break;
                if ((startBlock & 0x10000000U) && (blockCount & 0x10000000U)) {
                    cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow extent is malformed");
                    status = CL_EFORMAT;
                    goto done;
                }
                if (startBlock >= volHeader->totalBlocks ||
                    blockCount > volHeader->totalBlocks - startBlock) {
                    cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow extent is outside the volume");
                    status = CL_EFORMAT;
                    goto done;
                }
                if (!found) {
                    if (relative < blockCount) {
                        foundFileBlock = (uint64_t)startBlock + relative;
                        found          = true;
                    } else {
                        relative -= blockCount;
                    }
                }
            }
        }

        if (thisNode == extHeader->lastLeafNode) {
            if (nodeDesc.fLink != 0) {
                cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow leaf chain exceeds its declared last leaf");
                status = CL_EFORMAT;
                goto done;
            }
            if (leafRecordsScanned != extHeader->leafRecords) {
                cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow leaf record count is inconsistent");
                status = CL_EFORMAT;
                goto done;
            }
            reachedLastLeaf = true;
            thisNode = 0;
        } else if (nodeDesc.fLink == 0) {
            cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow leaf chain ended before its declared last leaf");
            status = CL_EFORMAT;
            goto done;
        } else if (thisNode == nodeDesc.fLink) {
            cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow traversal contains a cycle");
            status = CL_EFORMAT;
            goto done;
        } else {
            thisNode = nodeDesc.fLink;
        }
    }

    if (!reachedLastLeaf) {
        cli_mark_scan_incomplete(ctx, "HFS+ ExtentOverflow leaf chain ended before its declared last leaf");
        status = CL_EFORMAT;
        goto done;
    }
    if (found) {
        *realFileBlock = foundFileBlock;
        status          = CL_SUCCESS;
        goto done;
    }
    cli_mark_scan_incomplete(ctx, "HFS+ fork ExtentOverflow record is missing");
    status = CL_EFORMAT;

done:
    free(nodeBuf);
    return status;
}

static cl_error_t hfsplus_readn_full(cli_ctx *ctx, int fd, void *buffer, size_t length, const char *reason)
{
    size_t read_length = cli_readn(fd, buffer, length);

    if (read_length == length)
        return CL_SUCCESS;

    cli_mark_scan_incomplete(ctx, reason);
    return read_length == (size_t)-1 ? CL_EREAD : CL_EPARSE;
}

cl_error_t cli_hfsplus_seek_to_cmpf_resource(cli_ctx *ctx, int fd, size_t *size)
{
    cl_error_t status = CL_SUCCESS;
    hfsPlusResourceHeader resourceHeader;
    hfsPlusResourceMap resourceMap;
    hfsPlusResourceType resourceType;
    hfsPlusReferenceEntry entry;
    STATBUF resource_stat;
    uint64_t file_size;
    uint64_t type_list_offset;
    uint64_t type_table_size;
    uint64_t cmpf_reference_offset = UINT64_MAX;
    uint16_t type_count_raw;
    uint32_t type_count;
    uint32_t i;
    uint32_t dataLength;

    if (!ctx || !size) {
        status = CL_ENULLARG;
        goto done;
    }

    status = hfsplus_readn_full(ctx, fd, &resourceHeader, sizeof(resourceHeader),
                                "HFS+ resource header could not be read completely");
    if (status != CL_SUCCESS) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read resource header from temporary file\n");
        goto done;
    }

    resourceHeader.dataOffset = be32_to_host(resourceHeader.dataOffset);
    resourceHeader.mapOffset  = be32_to_host(resourceHeader.mapOffset);
    resourceHeader.dataLength = be32_to_host(resourceHeader.dataLength);
    resourceHeader.mapLength  = be32_to_host(resourceHeader.mapLength);

    if (FSTAT(fd, &resource_stat) != 0 || resource_stat.st_size < 0) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to determine resource fork size\n");
        cli_mark_scan_incomplete(ctx, "HFS+ resource fork size could not be determined");
        status = CL_EREAD;
        goto done;
    }
    file_size = (uint64_t)resource_stat.st_size;

    if ((uint64_t)resourceHeader.mapOffset > file_size ||
        (uint64_t)resourceHeader.mapLength > file_size - resourceHeader.mapOffset ||
        resourceHeader.mapLength < sizeof(resourceMap) ||
        (uint64_t)resourceHeader.dataOffset > file_size ||
        (uint64_t)resourceHeader.dataLength > file_size - resourceHeader.dataOffset) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Resource data or map is outside the fork\n");
        cli_mark_scan_incomplete(ctx, "HFS+ resource data or map is outside the fork");
        status = CL_EFORMAT;
        goto done;
    }

    {
        off_t map_offset = (off_t)(uint64_t)resourceHeader.mapOffset;
        if (map_offset < 0 || (uint64_t)map_offset != (uint64_t)resourceHeader.mapOffset) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Resource map offset is not representable\n");
            cli_mark_scan_incomplete(ctx, "HFS+ resource map offset is not representable");
            status = CL_EFORMAT;
            goto done;
        }
        if (lseek(fd, map_offset, SEEK_SET) != map_offset) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to seek to map in temporary file\n");
            cli_mark_scan_incomplete(ctx, "HFS+ resource map could not be located completely");
            status = CL_ESEEK;
            goto done;
        }
    }

    status = hfsplus_readn_full(ctx, fd, &resourceMap, sizeof(resourceMap),
                                "HFS+ resource map could not be read completely");
    if (status != CL_SUCCESS) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read resource map from temporary file\n");
        goto done;
    }

    resourceMap.resourceForkAttributes = be16_to_host(resourceMap.resourceForkAttributes);
    resourceMap.typeListOffset         = be16_to_host(resourceMap.typeListOffset);
    resourceMap.nameListOffset         = be16_to_host(resourceMap.nameListOffset);

    memcpy(&type_count_raw, &resourceMap.typeCount, sizeof(type_count_raw));
    type_count_raw = be16_to_host(type_count_raw);
    if (type_count_raw == UINT16_MAX) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Resource type list is empty\n");
        cli_mark_scan_incomplete(ctx, "HFS+ compressed resource type is missing");
        status = CL_EFORMAT;
        goto done;
    }
    type_count = (uint32_t)type_count_raw + 1U;
    type_list_offset = resourceMap.typeListOffset;
    if (type_list_offset < offsetof(hfsPlusResourceMap, typeCount) ||
        type_list_offset > resourceHeader.mapLength ||
        sizeof(uint16_t) > resourceHeader.mapLength - type_list_offset) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Resource type list is outside the map\n");
        cli_mark_scan_incomplete(ctx, "HFS+ compressed resource type list is outside the map");
        status = CL_EFORMAT;
        goto done;
    }
    type_table_size = sizeof(uint16_t) + (uint64_t)type_count * sizeof(resourceType);
    if (type_table_size > resourceHeader.mapLength - type_list_offset) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Resource type list is truncated\n");
        cli_mark_scan_incomplete(ctx, "HFS+ compressed resource type list is truncated");
        status = CL_EFORMAT;
        goto done;
    }

    {
        uint64_t type_entries_offset = (uint64_t)resourceHeader.mapOffset + type_list_offset + sizeof(uint16_t);
        off_t type_entries_seek = (off_t)type_entries_offset;

        if (type_entries_seek < 0 || (uint64_t)type_entries_seek != type_entries_offset ||
            lseek(fd, type_entries_seek, SEEK_SET) != type_entries_seek) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to seek to type list in temporary file\n");
            cli_mark_scan_incomplete(ctx, "HFS+ compressed resource type list could not be located completely");
            status = CL_ESEEK;
            goto done;
        }
    }

    for (i = 0; i < type_count; ++i) {
        uint64_t reference_list_offset;
        uint64_t reference_count;
        uint64_t reference_bytes;
        uint64_t reference_relative;

        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "HFS+ compressed resource type-table traversal reached the configured time limit");
            goto done;
        }

        status = hfsplus_readn_full(ctx, fd, &resourceType, sizeof(resourceType),
                                    "HFS+ resource type table could not be read completely");
        if (status != CL_SUCCESS) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read resource type from temporary file\n");
            goto done;
        }
        resourceType.instanceCount       = be16_to_host(resourceType.instanceCount);
        resourceType.referenceListOffset = be16_to_host(resourceType.referenceListOffset);

        reference_relative = resourceType.referenceListOffset;
        reference_count    = (uint64_t)resourceType.instanceCount + 1U;
        reference_bytes    = reference_count * sizeof(hfsPlusReferenceEntry);
        if (type_list_offset > resourceHeader.mapLength ||
            reference_relative > resourceHeader.mapLength - type_list_offset ||
            reference_bytes > resourceHeader.mapLength - type_list_offset - reference_relative) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Resource reference list is outside the map\n");
            cli_mark_scan_incomplete(ctx, "HFS+ compressed resource reference list is outside the map");
            status = CL_EFORMAT;
            goto done;
        }

        if (memcmp(resourceType.type, "cmpf", 4) == 0) {
            if (cmpf_reference_offset != UINT64_MAX) {
                cli_dbgmsg("hfsplus_seek_to_cmpf_resource: There are several cmpf resource types in the file\n");
                cli_mark_scan_incomplete(ctx, "HFS+ compressed resource type table is ambiguous");
                status = CL_EFORMAT;
                goto done;
            }

            reference_list_offset = (uint64_t)resourceHeader.mapOffset + type_list_offset + reference_relative;
            cmpf_reference_offset = reference_list_offset;
            cli_dbgmsg("Found compressed resource type!\n");
        }
    }

    if (cmpf_reference_offset == UINT64_MAX) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Didn't find cmpf resource type\n");
        cli_mark_scan_incomplete(ctx, "HFS+ compressed resource type is missing");
        status = CL_EFORMAT;
        goto done;
    }

    {
        off_t reference_offset = (off_t)cmpf_reference_offset;

        if (reference_offset < 0 || (uint64_t)reference_offset != cmpf_reference_offset) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Resource reference index is not representable\n");
            cli_mark_scan_incomplete(ctx, "HFS+ resource reference index is not representable");
            status = CL_EFORMAT;
            goto done;
        }
        if (lseek(fd, reference_offset, SEEK_SET) < 0) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to seek to instance index\n");
            cli_mark_scan_incomplete(ctx, "HFS+ compressed resource index could not be located completely");
            status = CL_ESEEK;
            goto done;
        }
    }

    status = hfsplus_readn_full(ctx, fd, &entry, sizeof(entry),
                                "HFS+ resource entry could not be read completely");
    if (status != CL_SUCCESS) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read resource entry from temporary file\n");
        goto done;
    }

    {
        uint64_t data_offset_in_fork = ((uint64_t)entry.resourceDataOffset[0] << 16) |
                                       ((uint64_t)entry.resourceDataOffset[1] << 8) |
                                       (uint64_t)entry.resourceDataOffset[2];
        uint64_t data_offset64;
        off_t data_offset;

        if (data_offset_in_fork > resourceHeader.dataLength ||
            sizeof(dataLength) > resourceHeader.dataLength - data_offset_in_fork) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Resource data entry is outside the data area\n");
            cli_mark_scan_incomplete(ctx, "HFS+ compressed resource data entry is outside the data area");
            status = CL_EFORMAT;
            goto done;
        }
        data_offset64 = (uint64_t)resourceHeader.dataOffset + data_offset_in_fork;
        if (data_offset64 > file_size || sizeof(dataLength) > file_size - data_offset64) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Resource data entry is outside the fork\n");
            cli_mark_scan_incomplete(ctx, "HFS+ compressed resource data entry is outside the fork");
            status = CL_EFORMAT;
            goto done;
        }
        data_offset = (off_t)data_offset64;
        if (data_offset < 0 || (uint64_t)data_offset != data_offset64) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Resource data offset overflowed\n");
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Resource data offset is not representable\n");
            cli_mark_scan_incomplete(ctx, "HFS+ compressed resource data offset is not representable");
            status = CL_EFORMAT;
            goto done;
        }
        if (lseek(fd, data_offset, SEEK_SET) < 0) {
            cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to seek to data offset\n");
            cli_mark_scan_incomplete(ctx, "HFS+ compressed resource data could not be located completely");
            status = CL_ESEEK;
            goto done;
        }
    }

    status = hfsplus_readn_full(ctx, fd, &dataLength, sizeof(dataLength),
                                "HFS+ compressed resource length could not be read completely");
    if (status != CL_SUCCESS) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Failed to read data length from temporary file\n");
        goto done;
    }

    *size = be32_to_host(dataLength);
    if (*size > resourceHeader.dataLength -
                  (((uint64_t)entry.resourceDataOffset[0] << 16) |
                   ((uint64_t)entry.resourceDataOffset[1] << 8) |
                   (uint64_t)entry.resourceDataOffset[2]) -
                  sizeof(dataLength)) {
        cli_dbgmsg("hfsplus_seek_to_cmpf_resource: Compressed resource exceeds the data area\n");
        cli_mark_scan_incomplete(ctx, "HFS+ compressed resource exceeds the data area");
        status = CL_EFORMAT;
        goto done;
    }

done:
    return status;
}

/**
 * @brief Read the table from the provided file.
 *
 * The caller is responsible for freeing the table.
 *
 * @param fd                File descriptor of the file to read from.
 * @param [out] numBlocks   Number of blocks in the table, as determined from reading the file.
 * @param [out] table       Will be allocated and populated with table data.
 * @return cl_error_t  CL_SUCCESS on success, CL_E* on failure.
 */
static cl_error_t hfsplus_read_block_table(cli_ctx *ctx, int fd, uint32_t *numBlocks, hfsPlusResourceBlockTable **table)
{
    cl_error_t status = CL_SUCCESS;
    uint32_t i;
    size_t table_size;

    if (!table || !numBlocks) {
        status = CL_ENULLARG;
        goto done;
    }

    *table = NULL;

    status = hfsplus_readn_full(ctx, fd, numBlocks, sizeof(*numBlocks),
                                "HFS+ resource block count could not be read completely");
    if (status != CL_SUCCESS) {
        cli_dbgmsg("hfsplus_read_block_table: Failed to read block count\n");
        goto done;
    }

    *numBlocks = le32_to_host(*numBlocks); // Let's do a little little endian just for fun, shall we?
    if (*numBlocks > CLI_MAX_ALLOCATION / sizeof(hfsPlusResourceBlockTable)) {
        cli_mark_scan_incomplete(ctx, "HFS+ resource block table exceeds the allocation ceiling");
        status = CL_ERESOURCE;
        goto done;
    }

    table_size = (size_t)*numBlocks * sizeof(hfsPlusResourceBlockTable);
    *table     = cli_max_malloc(table_size);
    if (!*table) {
        cli_dbgmsg("hfsplus_read_block_table: Failed to allocate memory for block table\n");
        cli_mark_scan_incomplete(ctx, "HFS+ resource block table could not be allocated");
        status = CL_EMEM;
        goto done;
    }

    status = hfsplus_readn_full(ctx, fd, *table, table_size,
                                "HFS+ resource block table could not be read completely");
    if (status != CL_SUCCESS) {
        cli_dbgmsg("hfsplus_read_block_table: Failed to read table\n");
        goto done;
    }

    for (i = 0; i < *numBlocks; ++i) {
        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "HFS+ resource block-table conversion reached the configured time limit");
            goto done;
        }
        (*table)[i].offset = le32_to_host((*table)[i].offset);
        (*table)[i].length = le32_to_host((*table)[i].length);
    }

done:
    if (CL_SUCCESS != status) {
        if (NULL != table) {
            free(*table);
            *table = NULL;
        }
    }
    return status;
}

/* Given the catalog and other details, scan all the volume contents */
static cl_error_t hfsplus_walk_catalog(cli_ctx *ctx, hfsPlusVolumeHeader *volHeader, hfsHeaderRecord *catHeader,
                                       hfsHeaderRecord *extHeader, hfsHeaderRecord *attrHeader, const char *dirname)
{
    cl_error_t status = CL_SUCCESS;
    uint32_t thisNode, nodeLimit, nodesScanned = 0;
    uint64_t leafRecordsScanned = 0;
    uint16_t nodeSize, recordNum, topOfOffsets;
    uint16_t recordStart, nextDist, nextStart;
    uint8_t *nodeBuf                = NULL;
    const uint8_t COMPRESSED_ATTR[] = {0, 'c', 0, 'o', 0, 'm', 0, '.', 0, 'a', 0, 'p', 0, 'p', 0, 'l', 0, 'e', 0, '.', 0, 'd', 0, 'e', 0, 'c', 0, 'm', 0, 'p', 0, 'f', 0, 's'};
    char *tmpname                   = NULL;
    char *resourceFile              = NULL;
    int ifd                         = -1;
    int ofd                         = -1;
    char *name_utf8                 = NULL;
    size_t name_utf8_size           = 0;
    uint64_t resource_reserved      = 0;
    uint64_t output_reserved        = 0;
    bool extracted_file             = false;

    hfsPlusResourceBlockTable *table = NULL;

    nodeLimit = MIN(catHeader->totalNodes, HFSPLUS_NODE_LIMIT);
    thisNode  = catHeader->firstLeafNode;
    nodeSize  = catHeader->nodeSize;

    if (thisNode == 0)
        return CL_SUCCESS;

    /* Need to buffer current node, map will keep moving */
    nodeBuf = cli_max_malloc(nodeSize);
    if (!nodeBuf) {
        cli_dbgmsg("hfsplus_walk_catalog: failed to acquire node buffer, "
                   "size " STDu32 "\n",
                   nodeSize);
        cli_mark_scan_incomplete(ctx, "HFS+ catalog node buffer could not be allocated");
        return CL_EMEM;
    }

    /* Walk catalog leaf nodes, and scan contents of each */
    /* Because we want to scan them all, the index nodes add no value */
    while (status == CL_SUCCESS) {
        hfsNodeDescriptor nodeDesc;

        status = cli_checktimelimit(ctx);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "HFS+ catalog traversal reached the configured time limit");
            goto done;
        }

        if (thisNode == 0) {
            cli_dbgmsg("hfsplus_walk_catalog: reached end of leaf nodes.\n");
            goto done;
        }
        if (nodesScanned >= nodeLimit) {
            cli_dbgmsg("hfsplus_walk_catalog: node scan limit reached.\n");
            cli_mark_scan_incomplete(ctx, "HFS+ catalog node scan limit reached");
            status = CL_EMAXFILES;
            goto done;
        }
        nodesScanned++;

        /* fetch node into buffer */
        status = hfsplus_fetch_node(ctx, volHeader, catHeader, extHeader, &(volHeader->catalogFile), thisNode,
                                    nodeBuf, nodeSize, hfsCatalogFileID, HFSPLUS_FORKTYPE_DATA);
        if (status != CL_SUCCESS) {
            cli_dbgmsg("hfsplus_walk_catalog: node fetch failed.\n");
            goto done;
        }
        memcpy(&nodeDesc, nodeBuf, 14);

        /* convert and validate node */
        nodedescriptor_to_host(&nodeDesc);
        nodedescriptor_print("leaf node", &nodeDesc);
        if ((nodeDesc.kind != HFS_NODEKIND_LEAF) || (nodeDesc.height != 1)) {
            cli_dbgmsg("hfsplus_walk_catalog: invalid leaf node!\n");
            cli_mark_scan_incomplete(ctx, "HFS+ catalog leaf node is malformed");
            status = CL_EFORMAT;
            goto done;
        }
        if ((nodeSize / 4) < nodeDesc.numRecords) {
            cli_dbgmsg("hfsplus_walk_catalog: too many leaf records for one node!\n");
            cli_mark_scan_incomplete(ctx, "HFS+ catalog leaf node is malformed");
            status = CL_EFORMAT;
            goto done;
        }
        leafRecordsScanned += (uint64_t)nodeDesc.numRecords;
        if (leafRecordsScanned > catHeader->leafRecords) {
            cli_mark_scan_incomplete(ctx, "HFS+ catalog leaf record count is inconsistent");
            status = CL_EFORMAT;
            goto done;
        }

        /* Walk this node's records and scan */
        recordStart = 14; /* 1st record can be after end of node descriptor */
        /* offsets take 1 u16 per at the end of the node, along with an empty space offset */
        topOfOffsets = nodeSize - (nodeDesc.numRecords * 2) - 2;
        for (recordNum = 0; recordNum < nodeDesc.numRecords; recordNum++) {
            uint32_t keylen;
            int16_t rectype;
            hfsPlusCatalogFile fileRec;
            name_utf8 = NULL;

            /* Locate next record */
            nextDist  = nodeSize - (recordNum * 2) - 2;
            nextStart = nodeBuf[nextDist] * 0x100 + nodeBuf[nextDist + 1];
            /* Check record location */
            if ((nextStart > topOfOffsets - 1) || (nextStart < recordStart)) {
                cli_dbgmsg("hfsplus_walk_catalog: bad record location %x for %u!\n", nextStart, recordNum);
                cli_mark_scan_incomplete(ctx, "HFS+ catalog record is malformed");
                status = CL_EFORMAT;
                goto done;
            }
            recordStart = nextStart;
            /* Get record key length */
            keylen = (uint32_t)nodeBuf[recordStart] * 0x100U + nodeBuf[recordStart + 1];
            if (keylen & 1U)
                keylen++; /* pad 1 byte if required to make 2-byte align */
            /* Validate keylen */
            if (recordStart + keylen + 4 >= topOfOffsets) {
                cli_dbgmsg("hfsplus_walk_catalog: key too long for location %x for %u!\n",
                           nextStart, recordNum);
                cli_mark_scan_incomplete(ctx, "HFS+ catalog record key is malformed");
                status = CL_EFORMAT;
                goto done;
            }
            /* Collect filename  */
            if (keylen >= 6) {
                uint16_t name_length = (nodeBuf[recordStart + 2 + 4] << 8) | nodeBuf[recordStart + 2 + 4 + 1];
                cl_error_t conversion_status;
                char *index          = (char *)&nodeBuf[recordStart + 2 + 4 + 2];
                if ((name_length > 0) && ((size_t)name_length > (keylen - 6U) / 2U)) {
                    cli_dbgmsg("hfsplus_walk_catalog: catalog name is longer than its key\n");
                    cli_mark_scan_incomplete(ctx, "HFS+ catalog name is malformed");
                    status = CL_EFORMAT;
                    goto done;
                }
                if (name_length > 0) {
                    /*
                     * The name is contained in nodeBuf[recordStart + 2 + 4 + 2 : recordStart + 2 + 4 + 2 + name_length * 2] encoded as UTF-16BE.
                     */
                    conversion_status = cli_codepage_to_utf8((char *)index, name_length * 2, CODEPAGE_UTF16_BE, &name_utf8, &name_utf8_size);
                    if (CL_SUCCESS != conversion_status) {
                        cli_errmsg("hfsplus_walk_catalog: failed to convert UTF-16BE to UTF-8\n");
                        cli_mark_scan_incomplete(ctx, "HFS+ catalog name could not be converted");
                        status = conversion_status == CL_BREAK ? CL_EPARSE : conversion_status;
                        goto done;
                    }
                    cli_dbgmsg("hfsplus_walk_catalog: Extracting file %s\n", name_utf8);
                }
            }
            /* Copy type (after key, which is after keylength field) */
            memcpy(&rectype, &(nodeBuf[recordStart + keylen + 2]), 2);
            rectype = be16_to_host(rectype);
            cli_dbgmsg("hfsplus_walk_catalog: record %u nextStart %x keylen %u type %d\n",
                       recordNum, nextStart, keylen, rectype);
            /* Non-file records are not needed */
            if (rectype != HFSPLUS_RECTYPE_FILE) {
                if (NULL != name_utf8) {
                    free(name_utf8);
                    name_utf8 = NULL;
                }
                continue;
            }
            /* Check file record location */
            if (recordStart + keylen + 2 + sizeof(hfsPlusCatalogFile) >= topOfOffsets) {
                cli_dbgmsg("hfsplus_walk_catalog: not enough bytes for file record!\n");
                cli_mark_scan_incomplete(ctx, "HFS+ catalog file record is incomplete");
                status = CL_EFORMAT;
                goto done;
            }
            memcpy(&fileRec, &(nodeBuf[recordStart + keylen + 2]), sizeof(hfsPlusCatalogFile));

            /* Only scan files */
            fileRec.fileID               = be32_to_host(fileRec.fileID);
            fileRec.permissions.fileMode = be16_to_host(fileRec.permissions.fileMode);
            if ((fileRec.permissions.fileMode & HFS_MODE_TYPEMASK) == HFS_MODE_FILE) {
                int compressed = 0;
                uint8_t attribute[8192];
                size_t attributeSize = sizeof(attribute);

                /* Convert forks and scan */
                forkdata_to_host(&(fileRec.dataFork));
                forkdata_print("data fork:", &(fileRec.dataFork));
                forkdata_to_host(&(fileRec.resourceFork));
                forkdata_print("resource fork:", &(fileRec.resourceFork));

                if (attrHeader != NULL) {
                    cl_error_t attribute_status = hfsplus_check_attribute(ctx, volHeader, attrHeader, extHeader, fileRec.fileID,
                                                                          COMPRESSED_ATTR, sizeof(COMPRESSED_ATTR), &compressed,
                                                                          attribute, &attributeSize);
                    if (attribute_status != CL_SUCCESS) {
                        cli_dbgmsg("hfsplus_walk_catalog: Failed to inspect compressed-file attributes\n");
                        cli_mark_scan_incomplete(ctx, "HFS+ compressed-file attributes could not be inspected");
                        status = attribute_status;
                        goto done;
                    }
                }

                if (compressed) {
                    hfsPlusCompressionHeader header;
                    extracted_file    = false;
                    output_reserved   = 0;
                    resource_reserved = 0;
                    cli_dbgmsg("hfsplus_walk_catalog: File is compressed\n");

                    if (attributeSize < sizeof(header)) {
                        cli_warnmsg("hfsplus_walk_catalog: Error: Compression attribute size is less than the compression header\n");
                        cli_mark_scan_incomplete(ctx, "HFS+ compressed-file header is incomplete");
                        status = CL_EFORMAT;
                        goto done;
                    }

                    memcpy(&header, attribute, sizeof(header));
                    // In the sample I had (12de189078b1e260d669a2b325d688a3a39cb5b9697e00fb1777e1ecc64f4e91), this was stored in little endian.
                    // According to the doc, it should be in big endian.

                    if (header.magic == DECMPFS_HEADER_MAGIC_LE) {
                        header.magic           = cbswap32(header.magic);
                        header.compressionType = cbswap32(header.compressionType);
                        header.fileSize        = cbswap64(header.fileSize);
                    }

                    if (header.magic != DECMPFS_HEADER_MAGIC) {
                        cli_dbgmsg("hfsplus_walk_catalog: Unexpected magic value for compression header: 0x%08x\n", header.magic);
                        cli_mark_scan_incomplete(ctx, "HFS+ compressed-file header has invalid magic");
                        status = CL_EFORMAT;
                        goto done;
                    }

                    if (header.fileSize > SIZE_MAX) {
                        cli_mark_scan_incomplete(ctx, "HFS+ compressed file size cannot be represented");
                        status = CL_ERESOURCE;
                        goto done;
                    }
                    if ((status = cli_checklimits("hfsplus compressed file", ctx, header.fileSize, 0, 0)) != CL_SUCCESS)
                        goto done;
                    if (cli_scan_reserve_temporary(ctx, header.fileSize) != CL_SUCCESS) {
                        cli_mark_scan_incomplete(ctx, "HFS+ compressed output exceeds temporary storage limits");
                        status = CL_ERESOURCE;
                        goto done;
                    }
                    output_reserved = header.fileSize;

                    status = cli_checktimelimit(ctx);
                    if (status != CL_SUCCESS) {
                        cli_mark_scan_incomplete(ctx, "HFS+ compressed output temporary admission reached the configured time limit");
                        goto done;
                    }

                    /* open file */
                    status = cli_gentempfd(dirname, &tmpname, &ofd);
                    if (status != CL_SUCCESS) {
                        cli_dbgmsg("hfsplus_walk_catalog: Cannot generate temporary file.\n");
                        cli_mark_scan_incomplete(ctx, "HFS+ compressed temporary output could not be created");
                        goto done;
                    }

                    cli_dbgmsg("Found compressed file type %u size %" PRIu64 "\n", header.compressionType, header.fileSize);
                    switch (header.compressionType) {
                        case HFSPLUS_COMPRESSION_INLINE: {
                            uint64_t written = 0;
                            if (attributeSize < sizeof(header) + 1) {
                                cli_dbgmsg("hfsplus_walk_catalog: Unexpected end of stream, no compression flag\n");
                                cli_mark_scan_incomplete(ctx, "HFS+ inline compressed file lacks its compression flag");
                                status = CL_EFORMAT;
                                goto done;
                            }

                            if ((attribute[sizeof(header)] & 0x0f) == 0x0f) { // Data is stored uncompressed
                                if (attributeSize - sizeof(header) - 1 != header.fileSize) {
                                    cli_dbgmsg("hfsplus_walk_catalog: Expected file size different from size of data available\n");
                                    cli_mark_scan_incomplete(ctx, "HFS+ inline compressed file size does not match its available data");
                                    status = CL_EFORMAT;
                                    goto done;
                                }

                                status = cli_checktimelimit(ctx);
                                if (status != CL_SUCCESS) {
                                    cli_mark_scan_incomplete(ctx, "HFS+ inline compressed output reached the configured time limit");
                                    goto done;
                                }
                                written = cli_writen(ofd, &attribute[sizeof(header) + 1], (size_t)header.fileSize);
                            } else {
                                status = cli_hfsplus_inflate_inline(ctx, &attribute[sizeof(header)],
                                                                   attributeSize - sizeof(header),
                                                                   header.fileSize, ofd, &written);
                                if (status != CL_SUCCESS)
                                    goto done;
                            }
                            if (written != header.fileSize) {
                                cli_errmsg("hfsplus_walk_catalog: write error\n");
                                cli_mark_scan_incomplete(ctx, "HFS+ inline compressed output could not be written completely");
                                status = CL_EWRITE;
                                goto done;
                            }

                            extracted_file = true;

                            break;
                        }
                        case HFSPLUS_COMPRESSION_RESOURCE: {
                            // FIXME: This is hackish. We're assuming (which is
                            // correct according to the spec) that there's only
                            // one resource, and that it's the compressed data.
                            // Ideally we should check that there is only one
                            // resource, that its type is correct, and that its
                            // name is cmpf.
                            uint64_t written = 0;

                            // 4096 is an approximative value, there should be
                            // at least 16 (resource header) + 30 (map header) +
                            // 4096 bytes (data that doesn't fit in an
                            // attribute)
                            if (fileRec.resourceFork.logicalSize < 4096) {
                                cli_dbgmsg("hfsplus_walk_catalog: Error: Expected more data in the compressed resource fork\n");
                                cli_mark_scan_incomplete(ctx, "HFS+ compressed resource fork is incomplete");
                                status = CL_EFORMAT;
                                goto done;
                            }

                            if ((status = hfsplus_scanfile(ctx, volHeader, extHeader, fileRec.fileID, HFSPLUS_FORKTYPE_RSRC,
                                                           &(fileRec.resourceFork), dirname,
                                                           &resourceFile, &resource_reserved, name_utf8)) != CL_SUCCESS) {
                                cli_dbgmsg("hfsplus_walk_catalog: Error while extracting the resource fork\n");
                                goto done;
                            }

                            if (NULL == resourceFile) {
                                cli_dbgmsg("hfsplus_walk_catalog: Error: hfsplus_scanfile returned no resource file\n");
                                cli_mark_scan_incomplete(ctx, "HFS+ compressed resource fork output is unavailable");
                                status = CL_EFORMAT;
                                goto done;
                            }

                            if (-1 == (ifd = safe_open(resourceFile, O_RDONLY | O_BINARY))) {
                                cli_dbgmsg("hfsplus_walk_catalog: Failed to open temporary file %s\n", resourceFile);
                                cli_mark_scan_incomplete(ctx, "HFS+ compressed resource fork output could not be opened");
                                status = CL_EOPEN;
                                goto done;
                            } else {
                                size_t resourceLen;
                                if (CL_SUCCESS != (status = cli_hfsplus_seek_to_cmpf_resource(ctx, ifd, &resourceLen))) {
                                    cli_dbgmsg("hfsplus_walk_catalog: Failed to find cmpf resource in resource fork\n");
                                } else {
                                    uint32_t numBlocks;
                                    off_t dataOffset = lseek(ifd, 0, SEEK_CUR);

                                    if (dataOffset < 0) {
                                        cli_dbgmsg("hfsplus_walk_catalog: Failed to locate block table data\n");
                                        cli_mark_scan_incomplete(ctx, "HFS+ compressed resource block table could not be located completely");
                                        status = CL_ESEEK;
                                        goto done;
                                    }

                                    if (CL_SUCCESS != (status = hfsplus_read_block_table(ctx, ifd, &numBlocks, &table))) {
                                        cli_dbgmsg("hfsplus_walk_catalog: Failed to read block table\n");
                                    } else {
                                        uint8_t block[4096];
                                        uint8_t uncompressed_block[4096];
                                        unsigned curBlock;

                                        for (curBlock = 0; status == CL_SUCCESS && curBlock < numBlocks; ++curBlock) {
                                            status = cli_checktimelimit(ctx);
                                            if (status != CL_SUCCESS) {
                                                cli_mark_scan_incomplete(ctx, "HFS+ compressed-resource traversal reached the configured time limit");
                                                goto done;
                                            }

                                            int z_ret;
                                            uint64_t blockOffset64;
                                            off_t blockOffset;
                                            size_t curOffset;
                                            size_t readLen;
                                            z_stream stream;
                                            int streamBeginning  = 1;
                                            int streamCompressed = 0;
                                            bool stream_initialized = false;
                                            bool stream_complete    = false;

                                            if (dataOffset < 0 ||
                                                cli_hfsplus_resource_block_offset((uint64_t)dataOffset,
                                                                                  table[curBlock].offset,
                                                                                  &blockOffset64) != CL_SUCCESS) {
                                                cli_dbgmsg("hfsplus_walk_catalog: compressed resource block offset overflowed\n");
                                                cli_mark_scan_incomplete(ctx, "HFS+ compressed resource block offset overflowed");
                                                status = CL_EFORMAT;
                                                goto done;
                                            }
                                            if ((uint64_t)table[curBlock].offset > resourceLen ||
                                                (uint64_t)table[curBlock].length >
                                                    resourceLen - (uint64_t)table[curBlock].offset) {
                                                cli_dbgmsg("hfsplus_walk_catalog: compressed resource block exceeds its declared resource size\n");
                                                cli_mark_scan_incomplete(ctx, "HFS+ compressed resource block exceeds its declared resource size");
                                                status = CL_EFORMAT;
                                                goto done;
                                            }
                                            blockOffset = (off_t)blockOffset64;
                                            if (blockOffset < 0 || (uint64_t)blockOffset != blockOffset64) {
                                                cli_dbgmsg("hfsplus_walk_catalog: compressed resource block offset is not representable\n");
                                                cli_mark_scan_incomplete(ctx, "HFS+ compressed resource block offset is not representable");
                                                status = CL_EFORMAT;
                                                goto done;
                                            }

                                            cli_dbgmsg("Handling block %u of %" PRIu32 " at offset %" PRIi64 " (size %u)\n", curBlock, numBlocks, (int64_t)blockOffset, table[curBlock].length);

                                            if (lseek(ifd, blockOffset, SEEK_SET) != blockOffset) {
                                                cli_dbgmsg("hfsplus_walk_catalog: Failed to seek to beginning of block\n");
                                                cli_mark_scan_incomplete(ctx, "HFS+ compressed resource block could not be located completely");
                                                status = CL_ESEEK;
                                                goto done;
                                            }

                                            for (curOffset = 0; curOffset < table[curBlock].length;) {
                                                readLen = table[curBlock].length - curOffset;
                                                if (readLen > sizeof(block)) {
                                                    readLen = sizeof(block);
                                                }

                                                status = hfsplus_readn_full(
                                                    ctx, ifd, block, readLen,
                                                    "HFS+ compressed resource block could not be read completely");
                                                if (status != CL_SUCCESS) {
                                                    cli_dbgmsg("hfsplus_walk_catalog: Failed to read block from temporary file\n");
                                                    goto resource_block_done;
                                                }

                                                if (streamBeginning) {
                                                    streamCompressed = (block[0] & 0x0f) != 0x0f;

                                                    if (streamCompressed) {
                                                        cli_dbgmsg("Current stream is compressed\n");
                                                        stream.zalloc    = Z_NULL;
                                                        stream.zfree     = Z_NULL;
                                                        stream.opaque    = Z_NULL;
                                                        stream.avail_in  = readLen;
                                                        stream.next_in   = block;
                                                        stream.avail_out = sizeof(uncompressed_block);
                                                        stream.next_out  = uncompressed_block;

                                                        if (Z_OK != (z_ret = inflateInit2(&stream, 15))) {
                                                            cli_dbgmsg("hfsplus_walk_catalog: inflateInit2 failed (%d)\n", z_ret);
                                                            cli_mark_scan_incomplete(ctx, "HFS+ compressed resource decoder could not be initialized");
                                                            status = CL_EFORMAT;
                                                            goto resource_block_done;
                                                        }
                                                        stream_initialized = true;
                                                    }
                                                }

                                                if (streamCompressed) {
                                                    stream.avail_in  = readLen;
                                                    stream.next_in   = block;
                                                    stream.avail_out = sizeof(uncompressed_block);
                                                    stream.next_out  = uncompressed_block;

                                                    while (stream.avail_in > 0) {
                                                        z_ret = inflate(&stream, Z_NO_FLUSH);
                                                        if (z_ret != Z_OK && z_ret != Z_STREAM_END) {
                                                            cli_dbgmsg("hfsplus_walk_catalog: Failed to extract (%d)\n", z_ret);
                                                            cli_mark_scan_incomplete(ctx, "HFS+ compressed resource decoder failed before completion");
                                                            status = CL_EFORMAT;
                                                            goto resource_block_done;
                                                        }
                                                        if (z_ret == Z_STREAM_END)
                                                            stream_complete = true;

                                                        size_t produced = sizeof(uncompressed_block) - stream.avail_out;
                                                        status = cli_checktimelimit(ctx);
                                                        if (status != CL_SUCCESS) {
                                                            cli_mark_scan_incomplete(ctx, "HFS+ compressed-resource output reached the configured time limit");
                                                            goto resource_block_done;
                                                        }
                                                        if (cli_hfsplus_output_size_admission(written, produced, header.fileSize) != CL_SUCCESS) {
                                                            cli_dbgmsg("hfsplus_walk_catalog: Compressed output exceeds its declared size\n");
                                                            cli_mark_scan_incomplete(ctx, "HFS+ compressed output exceeded its declared size");
                                                            status = CL_EFORMAT;
                                                            goto resource_block_done;
                                                        }
                                                        if (cli_writen(ofd, uncompressed_block, produced) != produced) {
                                                            cli_dbgmsg("hfsplus_walk_catalog: Failed to write to temporary file\n");
                                                            cli_mark_scan_incomplete(ctx, "HFS+ compressed output could not be written completely");
                                                            status = CL_EWRITE;
                                                            goto resource_block_done;
                                                        }
                                                        written += produced;
                                                        stream.avail_out = sizeof(uncompressed_block);
                                                        stream.next_out  = uncompressed_block;

                                                        extracted_file = true;

                                                        if (stream.avail_in > 0 && Z_STREAM_END == z_ret) {
                                                            cli_mark_scan_incomplete(ctx, "HFS+ compressed resource contains trailing data");
                                                            status = CL_EFORMAT;
                                                            goto resource_block_done;
                                                        }
                                                    }
                                                } else {
                                                    size_t produced = readLen - (streamBeginning ? 1 : 0);
                                                    status = cli_checktimelimit(ctx);
                                                    if (status != CL_SUCCESS) {
                                                        cli_mark_scan_incomplete(ctx, "HFS+ compressed-resource output reached the configured time limit");
                                                        goto resource_block_done;
                                                    }
                                                    if (cli_hfsplus_output_size_admission(written, produced, header.fileSize) != CL_SUCCESS) {
                                                        cli_dbgmsg("hfsplus_walk_catalog: Compressed output exceeds its declared size\n");
                                                        cli_mark_scan_incomplete(ctx, "HFS+ compressed output exceeded its declared size");
                                                        status = CL_EFORMAT;
                                                        goto resource_block_done;
                                                    }
                                                    if (cli_writen(ofd, &block[streamBeginning ? 1 : 0], produced) != produced) {
                                                        cli_dbgmsg("hfsplus_walk_catalog: Failed to write to temporary file\n");
                                                        cli_mark_scan_incomplete(ctx, "HFS+ compressed output could not be written completely");
                                                        status = CL_EWRITE;
                                                        goto resource_block_done;
                                                    }
                                                    written += produced;

                                                    extracted_file = true;
                                                }

                                                curOffset += readLen;
                                                streamBeginning = 0;
                                            }

                                            if (streamCompressed) {
                                                if (!stream_complete) {
                                                    cli_mark_scan_incomplete(ctx, "HFS+ compressed resource ended before the decoder completed");
                                                    status = CL_EFORMAT;
                                                    goto resource_block_done;
                                                }
                                            }

resource_block_done:
                                            if (stream_initialized) {
                                                if (Z_OK != (z_ret = inflateEnd(&stream))) {
                                                    cli_dbgmsg("hfsplus_walk_catalog: inflateEnd failed (%d)\n", z_ret);
                                                    cli_mark_scan_incomplete(ctx, "HFS+ compressed resource decoder could not be finalized");
                                                    if (status == CL_SUCCESS)
                                                        status = CL_EFORMAT;
                                                }
                                                stream_initialized = false;
                                            }
                                            if (status != CL_SUCCESS)
                                                goto done;
                                        }

                                        if (written != header.fileSize) {
                                            cli_mark_scan_incomplete(ctx, "HFS+ compressed resource ended before its declared size");
                                            status = CL_EFORMAT;
                                            goto done;
                                        }

                                        cli_dbgmsg("hfsplus_walk_catalog: Extracted compressed file from resource fork to %s (size " STDu64 ")\n", tmpname, written);

                                        if (table) {
                                            free(table);
                                            table = NULL;
                                        }
                                    }
                                }
                            }

                            if (ifd >= 0) {
                                if (close(ifd) != 0) {
                                    cli_mark_scan_incomplete(ctx, "HFS+ resource temporary input could not be closed");
                                    status = cli_merge_cleanup_status(status, CL_EWRITE);
                                    goto done;
                                }
                                ifd = -1;
                            }

                            if (!ctx->engine->keeptmp) {
                                if (cli_unlink(resourceFile)) {
                                    cli_mark_scan_incomplete(ctx, "HFS+ resource temporary output could not be removed");
                                    status = cli_merge_cleanup_status(status, CL_EUNLINK);
                                    goto done;
                                }
                            }
                            free(resourceFile);
                            resourceFile = NULL;
                            if (resource_reserved) {
                                cli_scan_release_temporary(ctx, resource_reserved);
                                resource_reserved = 0;
                            }

                            cli_dbgmsg("hfsplus_walk_catalog: Resource compression processing complete\n");
                            break;
                        }
                        default:
                            cli_dbgmsg("hfsplus_walk_catalog: Unknown compression type %u\n", header.compressionType);
                            cli_mark_scan_incomplete(ctx, "HFS+ compressed file uses an unsupported compression type");
                            status = CL_EFORMAT;
                            break;
                    }

                    if (tmpname) {
                        if (extracted_file) {
                            cli_dbgmsg("hfsplus_walk_catalog: Extracted to %s\n", tmpname);

                            /* Scan the extracted file */
                            status = cli_magic_scan_desc_type_reserved(ofd, tmpname, ctx, CL_TYPE_ANY, name_utf8,
                                                                       LAYER_ATTRIBUTES_NONE);
                            if (status != CL_SUCCESS) {
                                goto done;
                            }
                        }

                        if (!ctx->engine->keeptmp) {
                            if (cli_unlink(tmpname)) {
                                cli_mark_scan_incomplete(ctx, "HFS+ compressed temporary output could not be removed");
                                status = cli_merge_cleanup_status(status, CL_EUNLINK);
                                goto done;
                            }
                        }

                        free(tmpname);
                        tmpname = NULL;
                    }

                    if (ofd >= 0) {
                        if (close(ofd) != 0) {
                            cli_mark_scan_incomplete(ctx, "HFS+ compressed temporary output could not be closed");
                            status = cli_merge_cleanup_status(status, CL_EWRITE);
                            goto done;
                        }
                        ofd = -1;
                    }

                    if (status != CL_SUCCESS)
                        goto done;
                    if (output_reserved) {
                        cli_scan_release_temporary(ctx, output_reserved);
                        output_reserved = 0;
                    }
                }

                /* Scan data fork */
                if (fileRec.dataFork.logicalSize) {
                    status = hfsplus_scanfile(ctx, volHeader, extHeader, fileRec.fileID, HFSPLUS_FORKTYPE_DATA,
                                              &(fileRec.dataFork), dirname, NULL, NULL, name_utf8);
                    if (status != CL_SUCCESS) {
                        cli_dbgmsg("hfsplus_walk_catalog: data fork retcode %d\n", status);
                        goto done;
                    }
                }
                /* Scan resource fork */
                if (fileRec.resourceFork.logicalSize) {
                    status = hfsplus_scanfile(ctx, volHeader, extHeader, fileRec.fileID, HFSPLUS_FORKTYPE_RSRC,
                                              &(fileRec.resourceFork), dirname, NULL, NULL, name_utf8);
                    if (status != CL_SUCCESS) {
                        cli_dbgmsg("hfsplus_walk_catalog: resource fork retcode %d", status);
                        goto done;
                    }
                }

                /* A regular catalog file with no data or resource fork is
                 * still a logical child of the HFS+ volume. Admit it through
                 * the shared counter so an empty file cannot bypass
                 * MaxFiles and leave a clean cacheable result. */
                if (!compressed && fileRec.dataFork.logicalSize == 0 &&
                    fileRec.resourceFork.logicalSize == 0) {
                    status = cli_updatelimits(ctx, 0);
                    if (status != CL_SUCCESS) {
                        if (status != CL_ETIMEOUT && status != CL_BREAK)
                            cli_mark_scan_incomplete(ctx, "HFS+ empty file exceeds configured scan limits");
                        goto done;
                    }
                }
            } else {
                cli_dbgmsg("hfsplus_walk_catalog: record mode %o is not File\n", fileRec.permissions.fileMode);
            }

            if (NULL != name_utf8) {
                free(name_utf8);
                name_utf8 = NULL;
            }
        }

        /* After that, proceed to next node */
        if (thisNode == catHeader->lastLeafNode) {
            if (nodeDesc.fLink != 0) {
                cli_mark_scan_incomplete(ctx, "HFS+ catalog leaf chain exceeds its declared last leaf");
                status = CL_EFORMAT;
                goto done;
            }
            if (leafRecordsScanned != catHeader->leafRecords) {
                cli_mark_scan_incomplete(ctx, "HFS+ catalog leaf record count is inconsistent");
                status = CL_EFORMAT;
                goto done;
            }
            thisNode = 0;
        } else if (nodeDesc.fLink == 0) {
            cli_mark_scan_incomplete(ctx, "HFS+ catalog leaf chain ended before its declared last leaf");
            status = CL_EFORMAT;
            goto done;
        } else if (thisNode == nodeDesc.fLink) {
            /* TODO: Add heuristic alert? */
            cli_warnmsg("hfsplus_walk_catalog: simple cycle detected!\n");
            cli_mark_scan_incomplete(ctx, "HFS+ catalog traversal contains a cycle");
            status = CL_EFORMAT;
            goto done;
        } else {
            thisNode = nodeDesc.fLink;
        }
    }

done:
    if (table) {
        free(table);
    }
    if (-1 != ifd) {
        if (close(ifd) != 0) {
            cli_mark_scan_incomplete(ctx, "HFS+ resource temporary input could not be closed");
            status = cli_merge_cleanup_status(status, CL_EWRITE);
        }
    }
    if (-1 != ofd) {
        if (close(ofd) != 0) {
            cli_mark_scan_incomplete(ctx, "HFS+ compressed temporary output could not be closed");
            status = cli_merge_cleanup_status(status, CL_EWRITE);
        }
    }
    if (NULL != resourceFile) {
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(resourceFile)) {
                cli_mark_scan_incomplete(ctx, "HFS+ resource temporary output could not be removed");
                status = cli_merge_cleanup_status(status, CL_EUNLINK);
            }
        }
        free(resourceFile);
        resourceFile = NULL;
    }
    if (resource_reserved) {
        cli_scan_release_temporary(ctx, resource_reserved);
        resource_reserved = 0;
    }
    if (NULL != tmpname) {
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tmpname)) {
                cli_mark_scan_incomplete(ctx, "HFS+ compressed temporary output could not be removed");
                status = cli_merge_cleanup_status(status, CL_EUNLINK);
            }
        }
        free(tmpname);
        tmpname = NULL;
    }
    if (output_reserved) {
        cli_scan_release_temporary(ctx, output_reserved);
        output_reserved = 0;
    }
    if (NULL != nodeBuf) {
        free(nodeBuf);
    }
    if (NULL != name_utf8) {
        free(name_utf8);
    }
    return status;
}

/* Base scan function for scanning HFS+ or HFSX partitions */
cl_error_t cli_scanhfsplus(cli_ctx *ctx)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;
    char *targetdir                = NULL;
    hfsPlusVolumeHeader *volHeader = NULL;
    hfsNodeDescriptor catFileDesc;
    hfsHeaderRecord catFileHeader;
    hfsNodeDescriptor extentFileDesc;
    hfsHeaderRecord extentFileHeader;
    hfsNodeDescriptor attributesFileDesc;
    hfsHeaderRecord attributesFileHeader;
    int hasAttributesFileHeader = 0;

    if (!ctx)
        return CL_ENULLARG;
    if (!ctx->fmap) {
        cli_errmsg("cli_scanhfsplus: Invalid context\n");
        cli_mark_scan_incomplete(ctx, "HFS+ input map is unavailable");
        return CL_EPARSE;
    }
    if (!ctx->engine)
        return CL_ENULLARG;
    if (!ctx->options)
        return CL_ENULLARG;

    status = cli_checktimelimit(ctx);
    if (status != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "HFS+ inspection reached the configured time limit");
        goto done;
    }

    cli_dbgmsg("cli_scanhfsplus: scanning partition content\n");
    /* first, read volume header contents */
    status = hfsplus_volumeheader(ctx, &volHeader);
    if (status != CL_SUCCESS) {
        goto done;
    }

    /*
cli_dbgmsg("sizeof(hfsUniStr255) is %lu\n", sizeof(hfsUniStr255));
cli_dbgmsg("sizeof(hfsPlusBSDInfo) is %lu\n", sizeof(hfsPlusBSDInfo));
cli_dbgmsg("sizeof(hfsPlusExtentDescriptor) is %lu\n", sizeof(hfsPlusExtentDescriptor));
cli_dbgmsg("sizeof(hfsPlusExtentRecord) is %lu\n", sizeof(hfsPlusExtentRecord));
cli_dbgmsg("sizeof(hfsPlusForkData) is %lu\n", sizeof(hfsPlusForkData));
cli_dbgmsg("sizeof(hfsPlusVolumeHeader) is %lu\n", sizeof(hfsPlusVolumeHeader));
cli_dbgmsg("sizeof(hfsNodeDescriptor) is %lu\n", sizeof(hfsNodeDescriptor));
 */

    /* Get root node (header node) of extent overflow file */
    status = hfsplus_readheader(ctx, volHeader, &extentFileDesc, &extentFileHeader, HFS_FILETREE_EXTENTS, "extentFile");
    if (status != CL_SUCCESS) {
        goto done;
    }
    /* Get root node (header node) of catalog file */
    status = hfsplus_readheader(ctx, volHeader, &catFileDesc, &catFileHeader, HFS_FILETREE_CATALOG, "catalogFile");
    if (status != CL_SUCCESS) {
        goto done;
    }

    /* The attributes file is optional only when its fork is empty. A declared
     * but unreadable attributes tree must not be treated as absent: that tree
     * can carry decmpfs metadata required to inspect compressed files. */
    if (volHeader->attributesFile.logicalSize == 0 && volHeader->attributesFile.totalBlocks == 0) {
        hasAttributesFileHeader = 0;
    } else {
        ret = hfsplus_readheader(ctx, volHeader, &attributesFileDesc, &attributesFileHeader, HFS_FILETREE_ATTRIBUTES, "attributesFile");
        if (ret != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "HFS+ declared attributes file could not be inspected");
            status = ret;
            goto done;
        }
        hasAttributesFileHeader = 1;
    }

    /* Create temp folder for contents */
    if (!(targetdir = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "hfsplus-tmp"))) {
        cli_errmsg("cli_scanhfsplus: cli_gentemp failed\n");
        cli_mark_scan_incomplete(ctx, "HFS+ temporary directory could not be allocated");
        status = CL_ETMPDIR;
        goto done;
    }
    if (mkdir(targetdir, 0700)) {
        cli_errmsg("cli_scanhfsplus: Cannot create temporary directory %s\n", targetdir);
        cli_mark_scan_incomplete(ctx, "HFS+ temporary directory could not be created");
        status = CL_ETMPDIR;
        goto done;
    }
    cli_dbgmsg("cli_scanhfsplus: Extracting into %s\n", targetdir);

    /* Can build and scan catalog file if we want ***
    ret = hfsplus_scanfile(ctx, volHeader, &extentFileHeader, hfsCatalogFileID, HFSPLUS_FORKTYPE_DATA,
                           &(volHeader->catalogFile), targetdir, NULL, NULL, NULL);
     */

    status = hfsplus_validate_catalog(ctx, volHeader, &catFileHeader);
    if (status == CL_SUCCESS) {
        cli_dbgmsg("cli_scanhfsplus: validation successful\n");
    } else {
        cli_dbgmsg("cli_scanhfsplus: validation returned %d : %s\n", status, cl_strerror(status));
        goto done;
    }

    /* Walk through catalog to identify files to scan */
    status = hfsplus_walk_catalog(ctx, volHeader, &catFileHeader, &extentFileHeader, hasAttributesFileHeader ? &attributesFileHeader : NULL, targetdir);
    if (status != CL_SUCCESS) {
        goto done;
    }

done:
    if ((status == CL_SUCCESS || status == CL_CLEAN) && ctx->scan_incomplete)
        status = CL_EPARSE;

    if (status != CL_SUCCESS && status != CL_VIRUS && !ctx->scan_incomplete)
        cli_mark_scan_incomplete(ctx, "HFS+ inspection ended before completion");

    if (NULL != targetdir) {
        /* Clean up extracted content, if needed */
        if (!ctx->engine->keeptmp) {
            if (cli_rmdirs(targetdir) != 0) {
                cli_mark_scan_incomplete(ctx, "HFS+ temporary directory could not be removed");
                status = cli_merge_cleanup_status(status, CL_EUNLINK);
            }
        }
        free(targetdir);
    }
    if (NULL != volHeader) {
        free(volHeader);
    }

    return status;
}
