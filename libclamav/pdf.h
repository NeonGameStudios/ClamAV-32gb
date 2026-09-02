/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
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
#ifndef __PDF_H
#define __PDF_H

#include <limits.h>

#include "others.h"
#define PDF_FILTERLIST_MAX 64

/* Non-mmap fallback bound for builds that cannot expose a file-backed virtual
 * mapping to the legacy pointer-based object parser. Certified 64-bit POSIX
 * builds stage large inputs on disk and map them without a heap copy. */
#define PDF_DEEP_PARSE_MAX_SIZE ((size_t)64 * 1024 * 1024)
#define PDF_INPUT_WINDOW_SIZE (64 * 1024)

#if defined(HAVE_MMAP) && defined(HAVE_SYS_MMAN_H)
#define PDF_HAVE_FILE_BACKED_OBJECT_STREAMS 1
#else
#define PDF_HAVE_FILE_BACKED_OBJECT_STREAMS 0
#endif

static inline cl_error_t cli_pdf_legacy_dict_length(size_t length, int *legacy_length)
{
    if (legacy_length == NULL)
        return CL_ENULLARG;
    if (length > (size_t)INT_MAX)
        return CL_ERESOURCE;

    *legacy_length = (int)length;
    return CL_SUCCESS;
}

/* Compute the bounded workspace used by legacy PDF password checks. The
 * file-ID length is derived from PDF input and the callers must not form the
 * native-size additions until both overflow and the shared allocation ceiling
 * have been checked. */
static inline cl_error_t cli_pdf_encryption_buffer_size(size_t file_id_length,
                                                         size_t prefix_length,
                                                         size_t suffix_length,
                                                         size_t *buffer_size)
{
    size_t total;

    if (buffer_size == NULL)
        return CL_ENULLARG;
    if (prefix_length > SIZE_MAX - file_id_length)
        return CL_ERESOURCE;
    total = prefix_length + file_id_length;
    if (suffix_length > SIZE_MAX - total)
        return CL_ERESOURCE;
    total += suffix_length;
    if (total > CLI_MAX_ALLOCATION)
        return CL_ERESOURCE;

    *buffer_size = total;
    return CL_SUCCESS;
}

#define PDF_OBJECT_RECURSION_LIMIT 25
/* Internal object IDs pack the format's object number and generation into
 * one 32-bit lookup key; reject values that cannot be represented losslessly. */
#define PDF_PACKED_OBJECT_NUMBER_MAX 0x00ffffffU
#define PDF_PACKED_GENERATION_NUMBER_MAX 0x000000ffU

struct objstm_struct {
    size_t first;         // offset of first obj
    size_t current;       // offset of current obj
    size_t current_pair;  // offset of current pair describing id, location of object
    size_t length;        // total length of all objects (starting at first)
    size_t n;             // number of objects that should be found in the object stream
    size_t nobjs_found;   // number of objects actually found in the object stream
    char *streambuf;      // address of stream buffer, beginning with first obj pair
    size_t streambuf_len; // length of stream buffer, includes pairs followed by actual objects
    uint64_t temporary_reserved; // retained file-backed bytes charged to the scan
    cl_error_t parse_status;     // retained because parsed objects reference this backing
    bool streambuf_is_mapped;    // streambuf is a read-only file-backed mapping, not heap memory
};

struct pdf_obj {
    /* Object positions are file/map coordinates, not format-defined fields.
     * Keep them native-width so object streams and revisions above 4 GiB do
     * not wrap before bounds checks or extraction. */
    size_t start;
    size_t size;
    uint32_t id;
    uint32_t flags;
    uint32_t statsflags;
    uint32_t numfilters;
    uint32_t filterlist[PDF_FILTERLIST_MAX];
    const char *stream;           // pointer to stream contained in object.
    size_t stream_size;           // size of stream contained in object.
    struct objstm_struct *objstm; // Should be NULL unless the obj exists in an object stream (separate buffer)
    char *path;
    bool extracted; // We've attempted to extract this object. Check to prevent doing it more than once!
};

enum pdf_array_type { PDF_ARR_UNKNOWN = 0,
                      PDF_ARR_STRING,
                      PDF_ARR_ARRAY,
                      PDF_ARR_DICT };
enum pdf_dict_type { PDF_DICT_UNKNOWN = 0,
                     PDF_DICT_STRING,
                     PDF_DICT_ARRAY,
                     PDF_DICT_DICT };

struct pdf_array_node {
    void *data;
    size_t datasz;
    enum pdf_array_type type;

    struct pdf_array_node *prev;
    struct pdf_array_node *next;
};

struct pdf_array {
    struct pdf_array_node *nodes;
    struct pdf_array_node *tail;
};

struct pdf_dict_node {
    char *key;
    void *value;
    size_t valuesz;
    enum pdf_dict_type type;

    struct pdf_dict_node *prev;
    struct pdf_dict_node *next;
};

struct pdf_dict {
    struct pdf_dict_node *nodes;
    struct pdf_dict_node *tail;
};

struct pdf_stats_entry {
    char *data;

    /* populated by pdf_parse_string */
    struct pdf_stats_metadata {
        int length;
        struct pdf_obj *obj;
        int success; /* if finalize succeeds */
    } meta;
};

struct pdf_stats {
    int32_t ninvalidobjs;                     /* Number of invalid objects */
    int32_t njs;                              /* Number of javascript objects */
    int32_t nflate;                           /* Number of flate-encoded objects */
    int32_t nactivex;                         /* Number of ActiveX objects */
    int32_t nflash;                           /* Number of flash objects */
    int32_t ncolors;                          /* Number of colors */
    int32_t nasciihexdecode;                  /* Number of ASCIIHexDecode-filtered objects */
    int32_t nascii85decode;                   /* Number of ASCII85Decode-filtered objects */
    int32_t nembeddedfile;                    /* Number of embedded files */
    int32_t nimage;                           /* Number of image objects */
    int32_t nlzw;                             /* Number of LZW-filtered objects */
    int32_t nrunlengthdecode;                 /* Number of RunLengthDecode-filtered objects */
    int32_t nfaxdecode;                       /* Number of CCITT-filtered objects */
    int32_t njbig2decode;                     /* Number of JBIG2Decode-filtered objects */
    int32_t ndctdecode;                       /* Number of DCTDecode-filtered objects */
    int32_t njpxdecode;                       /* Number of JPXDecode-filtered objects */
    int32_t ncrypt;                           /* Number of Crypt-filtered objects */
    int32_t nstandard;                        /* Number of Standard-filtered objects */
    int32_t nsigned;                          /* Number of Signed objects */
    int32_t nopenaction;                      /* Number of OpenAction objects */
    int32_t nlaunch;                          /* Number of Launch objects */
    int32_t npage;                            /* Number of Page objects */
    int32_t nrichmedia;                       /* Number of RichMedia objects */
    int32_t nacroform;                        /* Number of AcroForm objects */
    int32_t nxfa;                             /* Number of XFA objects */
    struct pdf_stats_entry *author;           /* Author of the PDF */
    struct pdf_stats_entry *creator;          /* Application used to create the PDF */
    struct pdf_stats_entry *producer;         /* Application used to produce the PDF */
    struct pdf_stats_entry *creationdate;     /* Date the PDF was created */
    struct pdf_stats_entry *modificationdate; /* Date the PDF was modified */
    struct pdf_stats_entry *title;            /* Title of the PDF */
    struct pdf_stats_entry *subject;          /* Subject of the PDF */
    struct pdf_stats_entry *keywords;         /* Keywords of the PDF */
};

enum enc_method {
    ENC_UNKNOWN,
    ENC_NONE,
    ENC_IDENTITY,
    ENC_V2,
    ENC_AESV2,
    ENC_AESV3
};

struct pdf_struct {
    struct pdf_obj **objs;
    unsigned nobjs;
    unsigned flags;
    unsigned enc_method_stream;
    unsigned enc_method_string;
    unsigned enc_method_embeddedfile;
    const char *CF;
    long CF_n;
    const char *map;
    size_t size;
    off_t offset;
    off_t startoff;
    cli_ctx *ctx;
    const char *dir;
    /* Set by pdf_extract_obj while its temporary output remains live. */
    uint64_t *temporary_reserved;
    unsigned files;
    uint32_t enc_objid;
    char *fileID;
    unsigned fileIDlen;
    char *key;
    unsigned keylen;
    struct pdf_stats stats;
    cl_error_t metadata_status;
    struct objstm_struct **objstms;
    uint32_t nobjstms;
    uint32_t parse_recursion_depth;
};

#define OBJ_FLAG_PDFNAME_NONE 0x0
#define OBJ_FLAG_PDFNAME_DONE 0x1

#define PDF_EXTRACT_OBJ_NONE 0x0
#define PDF_EXTRACT_OBJ_SCAN 0x1

cl_error_t cli_pdf(const char *dir, cli_ctx *ctx, off_t offset);
cl_error_t cli_pdf_header_check(fmap_t *map, off_t offset);

/**
 * @brief Validate an embedded PDF header against scan context state.
 *
 * This internal admission probe preserves the map-only header semantics while
 * making missing input and pre-existing incomplete state fail-visible.
 */
cl_error_t cli_pdf_embedded_header_check(cli_ctx *ctx, off_t offset);
void pdf_parseobj(struct pdf_struct *pdf, struct pdf_obj *obj);
cl_error_t pdf_extract_obj(struct pdf_struct *pdf, struct pdf_obj *obj, uint32_t flags);
cl_error_t pdf_findobj(struct pdf_struct *pdf);
struct pdf_obj *find_obj(struct pdf_struct *pdf, struct pdf_obj *obj, uint32_t objid);

void pdf_handle_enc(struct pdf_struct *pdf);
cl_error_t pdf_derive_object_key(struct pdf_struct *pdf, uint32_t id,
                                 enum enc_method enc_method,
                                 unsigned char key[16], size_t *key_length);
char *decrypt_any(struct pdf_struct *pdf, uint32_t id, const char *in, size_t *length, enum enc_method enc_method);
enum enc_method get_enc_method(struct pdf_struct *pdf, struct pdf_obj *obj);
enum enc_method parse_enc_method(const char *dict, unsigned len, const char *key, enum enc_method def);
bool pdf_name_equals(const char *left, const char *right);

void pdfobj_flag(struct pdf_struct *pdf, struct pdf_obj *obj, enum pdf_flag flag);
char *pdf_finalize_string(struct pdf_struct *pdf, struct pdf_obj *obj, const char *in, size_t len);
char *pdf_parse_string(struct pdf_struct *pdf, struct pdf_obj *obj, const char *objstart, size_t objsize, const char *str, char **endchar, struct pdf_stats_metadata *meta);
struct pdf_array *pdf_parse_array(struct pdf_struct *pdf, struct pdf_obj *obj, size_t objsize, char *begin, char **endchar);
struct pdf_dict *pdf_parse_dict(struct pdf_struct *pdf, struct pdf_obj *obj, size_t objsize, char *begin, char **endchar);

/* Returns 1 for a valid reference, 0 for a non-reference, -1 when the packed
 * object-number or generation width cannot represent the reference, and -2
 * when the parser deadline expires. */
int is_object_reference(struct pdf_struct *pdf, char *begin, char **endchar, uint32_t *id);
void pdf_free_dict(struct pdf_dict *dict);
void pdf_free_array(struct pdf_array *array);
void pdf_print_dict(struct pdf_dict *dict, unsigned long depth);
void pdf_print_array(struct pdf_array *array, unsigned long depth);

cl_error_t pdf_find_and_parse_objs_in_objstm(struct pdf_struct *pdf, struct objstm_struct *objstm);
cl_error_t pdf_objstm_attach_file(struct pdf_struct *pdf, struct objstm_struct *objstm,
                                  int fd, size_t length);
cl_error_t pdf_objstm_cleanup(struct pdf_struct *pdf, struct objstm_struct *objstm,
                              cl_error_t status);
void pdf_objstm_release_range(struct objstm_struct *objstm, size_t offset,
                              size_t length);

#endif
