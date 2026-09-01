/*
 * Extract component parts of various MS XML files (e.g. MS Office 2003 XML Documents)
 *
 * Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 * Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 * Authors: Kevin Lin
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>

#include "clamav.h"
#include "others.h"
#include "conv.h"
#include "scanners.h"
#include "json_api.h"
#include "msxml.h"
#include "msxml_parser.h"

#include <libxml/parser.h>
#include <libxml/SAX2.h>
#include <libxml/xmlreader.h>

#define MSXML_VERBIOSE 0
#if MSXML_VERBIOSE
#define cli_msxmlmsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define cli_msxmlmsg(...)
#endif

#define check_state(state)                                                   \
    do {                                                                     \
        if (state == -1) {                                                   \
            cli_warnmsg("check_state[msxml]: CL_EPARSE @ ln%d\n", __LINE__); \
            return CL_EPARSE;                                                \
        } else if (state == 0) {                                             \
            cli_dbgmsg("check_state[msxml]: CL_BREAK @ ln%d\n", __LINE__);   \
            return CL_BREAK;                                                 \
        }                                                                    \
    } while (0)

#define track_json(mxctx) (mxctx->ictx->flags & MSXML_FLAG_JSON)

struct msxml_ictx {
    cli_ctx *ctx;
    uint32_t flags;
    const struct key_entry *keys;
    size_t num_keys;
    json_object *root;
    int toval;
};

struct key_entry blank_key = {NULL, NULL, 0};

static int msxml_attribute_limit_exceeded(cli_ctx *ctx, xmlTextReaderPtr reader, int num_attribs);

static int msxml_base64_is_valid(const unsigned char *data, size_t len)
{
    size_t compact_len = 0;
    size_t padding     = 0;
    size_t i;
    int seen_padding = 0;

    for (i = 0; i < len; ++i) {
        unsigned char value = data[i];

        if (isspace(value))
            continue;

        if (value == '=') {
            seen_padding = 1;
            if (++padding > 2)
                return 0;
            continue;
        }

        if (seen_padding || !((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
                              (value >= '0' && value <= '9') || value == '+' || value == '/'))
            return 0;

        compact_len++;
    }

    if (padding) {
        if (((compact_len + padding) & 3U) != 0)
            return 0;
        if ((padding == 1 && (compact_len & 3U) != 3) || (padding == 2 && (compact_len & 3U) != 2))
            return 0;
    } else if ((compact_len & 3U) == 1) {
        return 0;
    }

    return 1;
}

static cl_error_t msxml_reconcile_status(cli_ctx *ctx, cl_error_t status)
{
    if (ctx && (status == CL_SUCCESS || status == CL_CLEAN) && ctx->scan_incomplete)
        return CL_EPARSE;

    return status;
}

static cl_error_t msxml_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t ret;

    if (!ctx)
        return CL_ENULLARG;

    ret = cli_checktimelimit(ctx);
    if (ret != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return ret;
}

static void msxml_note_cleanup_failure(cli_ctx *ctx, cl_error_t *status,
                                       cl_error_t cleanup_status, const char *reason)
{
    if (ctx)
        cli_mark_scan_incomplete(ctx, reason);
    if (status)
        *status = cli_merge_cleanup_status(*status, cleanup_status);
}

static const struct key_entry *msxml_check_key(struct msxml_ictx *ictx, const xmlChar *key, size_t keylen)
{
    unsigned i;

    if (keylen > MSXML_JSON_STRLEN_MAX - 1) {
        cli_dbgmsg("msxml_check_key: key name too long\n");
        return &blank_key;
    }

    for (i = 0; i < ictx->num_keys; ++i) {
        if (keylen == strlen(ictx->keys[i].key) && !strncasecmp((char *)key, ictx->keys[i].key, keylen)) {
            return &ictx->keys[i];
        }
    }

    return &blank_key;
}

static void msxml_error_handler(void *arg, const char *msg, xmlParserSeverities severity, xmlTextReaderLocatorPtr locator)
{
    int line     = xmlTextReaderLocatorLineNumber(locator);
    xmlChar *URI = xmlTextReaderLocatorBaseURI(locator);

    UNUSEDPARAM(arg);

    switch (severity) {
        case XML_PARSER_SEVERITY_WARNING:
        case XML_PARSER_SEVERITY_VALIDITY_WARNING:
            cli_dbgmsg("%s:%d: parser warning : %s", (char *)URI, line, msg);
            break;
        case XML_PARSER_SEVERITY_ERROR:
        case XML_PARSER_SEVERITY_VALIDITY_ERROR:
            cli_dbgmsg("%s:%d: parser error : %s", (char *)URI, line, msg);
            break;
        default:
            cli_dbgmsg("%s:%d: unknown severity : %s", (char *)URI, line, msg);
            break;
    }
    free(URI);
}

static int msxml_is_int(const char *value, size_t len, int32_t *val)
{
    long val2;
    char *endptr = NULL;

    val2 = strtol(value, &endptr, 10);
    if (endptr != value + len) {
        return 0;
    }

    *val = (int32_t)(val2 & 0x0000ffff);

    return 1;
}

static int msxml_parse_value(json_object *wrkptr, const char *arrname, const xmlChar *node_value)
{
    json_object *newobj, *arrobj;
    int val;

    if (!wrkptr)
        return CL_ENULLARG;

    arrobj = cli_jsonarray(wrkptr, arrname);
    if (arrobj == NULL) {
        return CL_EMEM;
    }

    if (msxml_is_int((const char *)node_value, xmlStrlen(node_value), &val)) {
        newobj = json_object_new_int(val);
    } else if (!xmlStrcmp(node_value, (const xmlChar *)"true")) {
        newobj = json_object_new_boolean(1);
    } else if (!xmlStrcmp(node_value, (const xmlChar *)"false")) {
        newobj = json_object_new_boolean(0);
    } else {
        newobj = json_object_new_string((const char *)node_value);
    }

    if (NULL == newobj) {
        cli_errmsg("msxml_parse_value: no memory for json value for [%s]\n", arrname);
        return CL_EMEM;
    }

    json_object_array_add(arrobj, newobj);
    return CL_SUCCESS;
}

#define MAX_ATTRIBS 20
static cl_error_t msxml_parse_element(struct msxml_ctx *mxctx, xmlTextReaderPtr reader, int rlvl, void *jptr)
{
    const xmlChar *element_name = NULL;
    const xmlChar *node_name = NULL, *node_value = NULL;
    const struct key_entry *keyinfo;
    struct attrib_entry attribs[MAX_ATTRIBS];
    cl_error_t ret;
    int state, node_type, endtag = 0, num_attribs = 0;
    cli_ctx *ctx = mxctx->ictx->ctx;

    json_object *root     = mxctx->ictx->root;
    json_object *parent   = (json_object *)jptr;
    json_object *thisjobj = NULL;

    cli_msxmlmsg("in msxml_parse_element @ layer %d\n", rlvl);

    /* check recursion level */
    if (rlvl >= MSXML_RECLEVEL_MAX) {
        cli_dbgmsg("msxml_parse_element: reached msxml json recursion limit\n");

        if (track_json(mxctx)) {
            cl_error_t tmp = cli_json_parse_error(root, "MSXML_RECURSIVE_LIMIT");
            if (tmp != CL_SUCCESS)
                return tmp;
        }

        /* skip it */
        state = xmlTextReaderNext(reader);
        check_state(state);
        return CL_SUCCESS;
    }

    /* acquire element type */
    node_type = xmlTextReaderNodeType(reader);
    if (node_type == -1)
        return CL_EPARSE;

    node_name  = xmlTextReaderConstLocalName(reader);
    node_value = xmlTextReaderConstValue(reader);

    /* branch on node type */
    switch (node_type) {
        case XML_READER_TYPE_ELEMENT:
            cli_msxmlmsg("msxml_parse_element: ELEMENT %s [%d]: %s\n", node_name, node_type, node_value);

            /* storing the element name for verification/collection */
            element_name = node_name;
            if (!element_name) {
                cli_dbgmsg("msxml_parse_element: element tag node nameless\n");

                if (track_json(mxctx)) {
                    cl_error_t tmp = cli_json_parse_error(root, "MSXML_NAMELESS_ELEMENT");
                    if (tmp != CL_SUCCESS)
                        return tmp;
                }

                return CL_EPARSE; /* no name, nameless */
            }

            /* determine if the element is interesting */
            keyinfo = msxml_check_key(mxctx->ictx, element_name, xmlStrlen(element_name));

            cli_msxmlmsg("key:  %s\n", keyinfo->key);
            cli_msxmlmsg("name: %s\n", keyinfo->name);
            cli_msxmlmsg("type: 0x%x\n", keyinfo->type);

            /* element and contents are ignored */
            if (keyinfo->type & MSXML_IGNORE_ELEM) {
                cli_msxmlmsg("msxml_parse_element: IGNORING ELEMENT %s\n", keyinfo->name);

                state = xmlTextReaderNext(reader);
                check_state(state);
                return CL_SUCCESS;
            }

            if (track_json(mxctx) && (keyinfo->type & MSXML_JSON_TRACK)) {
                if (keyinfo->type & MSXML_JSON_ROOT)
                    thisjobj = cli_jsonobj(root, keyinfo->name);
                else if (keyinfo->type & MSXML_JSON_WRKPTR)
                    thisjobj = cli_jsonobj(parent, keyinfo->name);

                if (!thisjobj) {
                    return CL_EMEM;
                }
                cli_msxmlmsg("msxml_parse_element: generated json object [%s]\n", keyinfo->name);

                /* count this element */
                if (thisjobj && (keyinfo->type & MSXML_JSON_COUNT)) {
                    json_object *counter = NULL;

                    if (!json_object_object_get_ex(thisjobj, "Count", &counter)) { /* object not found */
                        cli_jsonint(thisjobj, "Count", 1);
                    } else {
                        int value = json_object_get_int(counter);
                        cli_jsonint(thisjobj, "Count", value + 1);
                    }
                    cli_msxmlmsg("msxml_parse_element: retrieved json object [Count]\n");
                }

                /* check if multiple entries are allowed */
                if (thisjobj && (keyinfo->type & MSXML_JSON_MULTI)) {
                    /* replace this object with an array entry object */
                    json_object *multi = cli_jsonarray(thisjobj, "Multi");
                    if (!multi) {
                        return CL_EMEM;
                    }
                    cli_msxmlmsg("msxml_parse_element: generated or retrieved json multi array\n");

                    thisjobj = cli_jsonobj(multi, NULL);
                    if (!thisjobj)
                        return CL_EMEM;
                    cli_msxmlmsg("msxml_parse_element: generated json multi entry object\n");
                }

                /* handle attributes */
                if (thisjobj && (keyinfo->type & MSXML_JSON_ATTRIB)) {
                    state = xmlTextReaderHasAttributes(reader);
                    if (state == 1) {
                        json_object *attributes;
                        const xmlChar *name, *value;

                        attributes = cli_jsonobj(thisjobj, "Attributes");
                        if (!attributes) {
                            return CL_EPARSE;
                        }
                        cli_msxmlmsg("msxml_parse_element: retrieved json object [Attributes]\n");

                        while (xmlTextReaderMoveToNextAttribute(reader) == 1) {
                            name  = xmlTextReaderConstLocalName(reader);
                            value = xmlTextReaderConstValue(reader);

                            cli_msxmlmsg("\t%s: %s\n", name, value);
                            cli_jsonstr(attributes, (char *)name, (const char *)value);
                        }
                    } else if (state == -1)
                        return CL_EPARSE;
                }
            }

            /* populate attributes for scanning callback - BROKEN, probably from the fact the reader is pointed to the attribute from previously parsing attributes */
            if ((keyinfo->type & MSXML_SCAN_CB) && mxctx->scan_cb) {
                state = xmlTextReaderHasAttributes(reader);
                if (state == 0) {
                    state = xmlTextReaderMoveToFirstAttribute(reader);
                    if (state == 1) {
                        /* read first attribute (current head) */
                        attribs[num_attribs].key   = (const char *)xmlTextReaderConstLocalName(reader);
                        attribs[num_attribs].value = (const char *)xmlTextReaderConstValue(reader);
                        num_attribs++;
                    } else if (state == -1) {
                        return CL_EPARSE;
                    }
                }

                /* start reading attributes or read remainder of attributes */
                if (state == 1) {
                    cli_msxmlmsg("msxml_parse_element: adding attributes to scanning context\n");

                    while ((num_attribs < MAX_ATTRIBS) && (xmlTextReaderMoveToNextAttribute(reader) == 1)) {
                        attribs[num_attribs].key   = (const char *)xmlTextReaderConstLocalName(reader);
                        attribs[num_attribs].value = (const char *)xmlTextReaderConstValue(reader);
                        num_attribs++;
                    }

                    if (msxml_attribute_limit_exceeded(ctx, reader, num_attribs))
                        return CL_EPARSE;
                } else if (state == -1) {
                    return CL_EPARSE;
                }
            }

            /* check self-containment */
            state = xmlTextReaderMoveToElement(reader);
            if (state == -1)
                return CL_EPARSE;

            state = xmlTextReaderIsEmptyElement(reader);
            if (state == 1) {
                cli_msxmlmsg("msxml_parse_element: SELF-CLOSING\n");

                state = xmlTextReaderNext(reader);
                check_state(state);
                return CL_SUCCESS;
            } else if (state == -1)
                return CL_EPARSE;

            /* advance to first content node */
            state = xmlTextReaderRead(reader);
            check_state(state);

            while (!endtag) {
                if (track_json(mxctx) && (cli_json_timeout_cycle_check(ctx, &(mxctx->ictx->toval)) != CL_SUCCESS))
                    return CL_ETIMEOUT;

                node_type = xmlTextReaderNodeType(reader);
                if (node_type == -1)
                    return CL_EPARSE;

                switch (node_type) {
                    case XML_READER_TYPE_ELEMENT:
                        ret = msxml_parse_element(mxctx, reader, rlvl + 1, thisjobj ? thisjobj : parent);
                        if (ret != CL_SUCCESS) {
                            return ret;
                        }
                        break;

                    case XML_READER_TYPE_TEXT:
                        node_value = xmlTextReaderConstValue(reader);

                        cli_msxmlmsg("TEXT: %s\n", node_value);

                        if (thisjobj && (keyinfo->type & MSXML_JSON_VALUE)) {

                            ret = msxml_parse_value(thisjobj, "Value", node_value);
                            if (ret != CL_SUCCESS)
                                return ret;

                            cli_msxmlmsg("msxml_parse_element: added json value [%s: %s]\n", keyinfo->name, (const char *)node_value);
                        }

                        /* callback-based scanning mechanism for embedded objects (used by HWPML) */
                        if ((keyinfo->type & MSXML_SCAN_CB) && mxctx->scan_cb) {
                            char name[1024];
                            char *tempfile = name;
                            int of;
                            size_t vlen = strlen((const char *)node_value);
                            uint64_t temporary_reserved = (uint64_t)vlen;

                            cli_msxmlmsg("BINARY CALLBACK DATA!\n");

                            if (cli_scan_reserve_temporary(ctx, temporary_reserved) != CL_SUCCESS) {
                                cli_mark_scan_incomplete(ctx, "MSXML callback temporary output exceeds temporary storage limits");
                                return CL_ERESOURCE;
                            }

                            if ((ret = msxml_checktimelimit(ctx, "MSXML callback temporary admission reached the configured time limit")) !=
                                CL_SUCCESS) {
                                cli_scan_release_temporary(ctx, temporary_reserved);
                                return ret;
                            }

                            if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tempfile, &of)) != CL_SUCCESS) {
                                cli_warnmsg("msxml_parse_element: failed to create temporary file %s\n", tempfile);
                                cli_mark_scan_incomplete(ctx, "MSXML callback temporary output could not be created");
                                cli_scan_release_temporary(ctx, temporary_reserved);
                                return ret;
                            }

                            if ((ret = msxml_checktimelimit(ctx, "MSXML callback temporary output reached the configured time limit")) !=
                                CL_SUCCESS) {
                                if (close(of) != 0)
                                    msxml_note_cleanup_failure(ctx, &ret, CL_EWRITE,
                                                                "MSXML callback temporary output could not be closed");
                                if (!(ctx->engine->keeptmp) && cli_unlink(tempfile) != 0)
                                    msxml_note_cleanup_failure(ctx, &ret, CL_EUNLINK,
                                                                "MSXML callback temporary output could not be removed");
                                cli_scan_release_temporary(ctx, temporary_reserved);
                                free(tempfile);
                                return ret;
                            }

                            if (cli_writen(of, (char *)node_value, vlen) != vlen) {
                                ret = CL_EWRITE;
                                if (close(of) != 0)
                                    msxml_note_cleanup_failure(ctx, &ret, CL_EWRITE,
                                                                "MSXML callback temporary output could not be closed");
                                if (!(ctx->engine->keeptmp))
                                    if (cli_unlink(tempfile) != 0)
                                        msxml_note_cleanup_failure(ctx, &ret, CL_EUNLINK,
                                                                    "MSXML callback temporary output could not be removed");
                                cli_scan_release_temporary(ctx, temporary_reserved);
                                free(tempfile);
                                cli_mark_scan_incomplete(ctx, "MSXML callback temporary output could not be written completely");
                                return ret;
                            }

                            cli_dbgmsg("msxml_parse_element: extracted binary data to %s\n", tempfile);

                            ret = msxml_checktimelimit(ctx, "MSXML callback nested-scan handoff reached the configured time limit");
                            if (ret == CL_SUCCESS)
                                ret = mxctx->scan_cb(of, tempfile, ctx, num_attribs, attribs, mxctx->scan_data);
                            if (close(of) != 0)
                                msxml_note_cleanup_failure(ctx, &ret, CL_EWRITE,
                                                            "MSXML callback temporary output could not be closed");
                            if (!(ctx->engine->keeptmp) && cli_unlink(tempfile) != 0)
                                msxml_note_cleanup_failure(ctx, &ret, CL_EUNLINK,
                                                            "MSXML callback temporary output could not be removed");
                            cli_scan_release_temporary(ctx, temporary_reserved);
                            free(tempfile);
                            if (ret != CL_SUCCESS) {
                                return ret;
                            }
                        }

                        /* scanning protocol for embedded objects encoded in base64 (used by MSXML) */
                        if (keyinfo->type & MSXML_SCAN_B64) {
                            char name[1024];
                            char *decoded, *tempfile = name;
                            size_t encodedlen;
                            size_t decodedlen;
                            int of;
                            uint64_t temporary_reserved;

                            cli_msxmlmsg("BINARY DATA!\n");

                            encodedlen = strlen((const char *)node_value);
                            if (!msxml_base64_is_valid(node_value, encodedlen)) {
                                cli_warnmsg("msxml_parse_element: malformed base64-encoded binary data\n");
                                cli_mark_scan_incomplete(ctx, "MSXML base64 data was malformed or could not be decoded completely");
                                return CL_EPARSE;
                            }

                            decoded = (char *)cl_base64_decode((char *)node_value, encodedlen, NULL, &decodedlen, 0);
                            if (!decoded) {
                                cli_warnmsg("msxml_parse_element: failed to decode base64-encoded binary data\n");
                                cli_mark_scan_incomplete(ctx, "MSXML base64 data was malformed or could not be decoded completely");
                                return CL_EPARSE;
                            }

                            temporary_reserved = (uint64_t)decodedlen;
                            if (cli_scan_reserve_temporary(ctx, temporary_reserved) != CL_SUCCESS) {
                                cli_mark_scan_incomplete(ctx, "MSXML base64 temporary output exceeds temporary storage limits");
                                free(decoded);
                                return CL_ERESOURCE;
                            }

                            if ((ret = msxml_checktimelimit(ctx, "MSXML base64 temporary admission reached the configured time limit")) !=
                                CL_SUCCESS) {
                                cli_scan_release_temporary(ctx, temporary_reserved);
                                free(decoded);
                                return ret;
                            }

                            if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tempfile, &of)) != CL_SUCCESS) {
                                cli_warnmsg("msxml_parse_element: failed to create temporary file %s\n", tempfile);
                                cli_mark_scan_incomplete(ctx, "MSXML base64 temporary output could not be created");
                                cli_scan_release_temporary(ctx, temporary_reserved);
                                free(decoded);
                                return ret;
                            }

                            if ((ret = msxml_checktimelimit(ctx, "MSXML base64 temporary output reached the configured time limit")) !=
                                CL_SUCCESS) {
                                free(decoded);
                                if (close(of) != 0)
                                    msxml_note_cleanup_failure(ctx, &ret, CL_EWRITE,
                                                                "MSXML base64 temporary output could not be closed");
                                if (!(ctx->engine->keeptmp) && cli_unlink(tempfile) != 0)
                                    msxml_note_cleanup_failure(ctx, &ret, CL_EUNLINK,
                                                                "MSXML base64 temporary output could not be removed");
                                cli_scan_release_temporary(ctx, temporary_reserved);
                                free(tempfile);
                                return ret;
                            }

                            if (cli_writen(of, decoded, decodedlen) != decodedlen) {
                                free(decoded);
                                ret = CL_EWRITE;
                                if (close(of) != 0)
                                    msxml_note_cleanup_failure(ctx, &ret, CL_EWRITE,
                                                                "MSXML base64 temporary output could not be closed");
                                if (!(ctx->engine->keeptmp))
                                    if (cli_unlink(tempfile) != 0)
                                        msxml_note_cleanup_failure(ctx, &ret, CL_EUNLINK,
                                                                    "MSXML base64 temporary output could not be removed");
                                cli_scan_release_temporary(ctx, temporary_reserved);
                                free(tempfile);
                                cli_mark_scan_incomplete(ctx, "MSXML base64 temporary output could not be written completely");
                                return ret;
                            }
                            free(decoded);

                            cli_dbgmsg("msxml_parse_element: extracted binary data to %s\n", tempfile);

                            ret = msxml_checktimelimit(ctx, "MSXML base64 nested-scan handoff reached the configured time limit");
                            if (ret == CL_SUCCESS)
                                ret = cli_magic_scan_desc_type_reserved(of, tempfile, ctx, CL_TYPE_ANY, NULL, LAYER_ATTRIBUTES_NONE);
                            if (close(of) != 0)
                                msxml_note_cleanup_failure(ctx, &ret, CL_EWRITE,
                                                            "MSXML base64 temporary output could not be closed");
                            if (!(ctx->engine->keeptmp) && cli_unlink(tempfile) != 0)
                                msxml_note_cleanup_failure(ctx, &ret, CL_EUNLINK,
                                                            "MSXML base64 temporary output could not be removed");
                            cli_scan_release_temporary(ctx, temporary_reserved);
                            free(tempfile);
                            if (ret != CL_SUCCESS) {
                                return ret;
                            }
                        }

                        /* advance to next node */
                        state = xmlTextReaderRead(reader);
                        check_state(state);
                        break;

                    case XML_READER_TYPE_COMMENT:
                        node_value = xmlTextReaderConstValue(reader);

                        cli_msxmlmsg("COMMENT: %s\n", node_value);

                        /* callback-based scanning mechanism for comments (used by MHTML) */
                        if ((keyinfo->type & MSXML_COMMENT_CB) && mxctx->comment_cb) {
                            ret = mxctx->comment_cb((const char *)node_value, ctx, thisjobj, mxctx->comment_data);
                            if (ret != CL_SUCCESS) {
                                return ret;
                            }
                        }

                        /* advance to next node */
                        state = xmlTextReaderRead(reader);
                        check_state(state);
                        break;

                    case XML_READER_TYPE_SIGNIFICANT_WHITESPACE:
                        /* advance to next node */
                        state = xmlTextReaderRead(reader);
                        check_state(state);
                        break;

                    case XML_READER_TYPE_END_ELEMENT:
                        cli_msxmlmsg("in msxml_parse_element @ layer %d closed\n", rlvl);
                        node_name = xmlTextReaderConstLocalName(reader);
                        if (!node_name) {
                            cli_dbgmsg("msxml_parse_element: element end tag node nameless\n");
                            return CL_EPARSE; /* no name, nameless */
                        }

                        if (xmlStrcmp(element_name, node_name)) {
                            cli_dbgmsg("msxml_parse_element: element tag does not match end tag %s != %s\n", element_name, node_name);
                            return CL_EFORMAT;
                        }

                        /* advance to next element tag */
                        state = xmlTextReaderRead(reader);
                        check_state(state);

                        endtag = 1;
                        break;

                    default:
                        node_name  = xmlTextReaderConstLocalName(reader);
                        node_value = xmlTextReaderConstValue(reader);

                        cli_dbgmsg("msxml_parse_element: unhandled xml secondary node %s [%d]: %s\n", node_name, node_type, node_value);

                        state = xmlTextReaderRead(reader);
                        check_state(state);
                }
            }

            break;
        case XML_READER_TYPE_PROCESSING_INSTRUCTION:
            cli_msxmlmsg("msxml_parse_element: PROCESSING INSTRUCTION %s [%d]: %s\n", node_name, node_type, node_value);
            break;
        case XML_READER_TYPE_SIGNIFICANT_WHITESPACE:
            cli_msxmlmsg("msxml_parse_element: SIGNIFICANT WHITESPACE %s [%d]: %s\n", node_name, node_type, node_value);
            break;
        case XML_READER_TYPE_END_ELEMENT:
            cli_msxmlmsg("msxml_parse_element: END ELEMENT %s [%d]: %s\n", node_name, node_type, node_value);
            return CL_SUCCESS;
        default:
            cli_dbgmsg("msxml_parse_element: unhandled xml primary node %s [%d]: %s\n", node_name, node_type, node_value);
    }

    return CL_SUCCESS;
}

/* reader initialization and closing handled by caller */
cl_error_t cli_msxml_parse_document(cli_ctx *ctx, xmlTextReaderPtr reader, const struct key_entry *keys, const size_t num_keys, uint32_t flags, struct msxml_ctx *mxctx)
{
    struct msxml_ctx reserve;
    struct msxml_ictx ictx;
    int state;
    cl_error_t ret = CL_SUCCESS;

    if (!ctx || !reader || !keys) {
        return CL_ENULLARG;
    }

    if ((flags & MSXML_FLAG_JSON) && !ctx->options)
        return CL_ENULLARG;

    if (!mxctx) {
        memset(&reserve, 0, sizeof(reserve));
        mxctx = &reserve;
    }

    ictx.ctx      = ctx;
    ictx.flags    = flags;
    ictx.keys     = keys;
    ictx.num_keys = num_keys;

    if (flags & MSXML_FLAG_JSON) {
        ictx.root = ctx->this_layer_metadata_json;
        /* JSON Sanity Check */
        if (!ictx.root)
            ictx.flags &= ~MSXML_FLAG_JSON;
        ictx.toval = 0;
    } else {
        ictx.root = NULL;
    }
    mxctx->ictx = &ictx;

    /* Error Handler (setting handler on tree walker causes segfault) */
    if (!(flags & MSXML_FLAG_WALK))
        // xmlTextReaderSetErrorHandler(reader, NULL, NULL); /* xml default handler */
        xmlTextReaderSetErrorHandler(reader, msxml_error_handler, NULL);

    /* Main Processing Loop */
    while ((state = xmlTextReaderRead(reader)) == 1) {
        if ((ictx.flags & MSXML_FLAG_JSON) && (cli_json_timeout_cycle_check(ictx.ctx, &(ictx.toval)) != CL_SUCCESS))
            return CL_ETIMEOUT;

        ret = msxml_parse_element(mxctx, reader, 0, ictx.root);
        if (ret != CL_SUCCESS) {
            if (ret == CL_VIRUS || ret == CL_ETIMEOUT || ret == CL_BREAK) {
                cli_dbgmsg("cli_msxml_parse_document: encountered halt event in parsing xml document\n");
                break;
            } else {
                cli_warnmsg("cli_msxml_parse_document: encountered issue in parsing xml document\n");
                break;
            }
        }
    }

    if (state == -1) {
        ret = CL_EPARSE;
    }

    /* Parse General Error Handler */
    if (ictx.flags & MSXML_FLAG_JSON) {
        cl_error_t tmp = CL_SUCCESS;

        switch (ret) {
            case CL_SUCCESS:
            case CL_BREAK: /* OK */
                break;
            case CL_VIRUS:
                tmp = cli_json_parse_error(ictx.root, "MSXML_INTR_VIRUS");
                break;
            case CL_ETIMEOUT:
                tmp = cli_json_parse_error(ictx.root, "MSXML_INTR_TIMEOUT");
                break;
            case CL_EPARSE:
                tmp = cli_json_parse_error(ictx.root, "MSXML_ERROR_XMLPARSER");
                break;
            case CL_EMEM:
                tmp = cli_json_parse_error(ictx.root, "MSXML_ERROR_OUTOFMEM");
                break;
            case CL_EFORMAT:
                tmp = cli_json_parse_error(ictx.root, "MSXML_ERROR_MALFORMED");
                break;
            default:
                tmp = cli_json_parse_error(ictx.root, "MSXML_ERROR_OTHER");
                break;
        }

        if (tmp) {
            return tmp;
        }
    }

    if ((flags & MSXML_FLAG_FAIL_INCOMPLETE) && ret != CL_SUCCESS && ret != CL_VIRUS && ret != CL_BREAK)
        cli_mark_scan_incomplete(ctx, "MSXML document ended before XML content was fully inspected");

    /* non-critical return suppression */
    if (ret == CL_BREAK)
        ret = CL_SUCCESS;

    /* important but non-critical suppression */
    if (ret == CL_EPARSE && !(flags & MSXML_FLAG_FAIL_INCOMPLETE)) {
        cli_dbgmsg("cli_msxml_parse_document: suppressing parsing error to continue scan\n");
        ret = CL_SUCCESS;
    }

    return msxml_reconcile_status(ctx, ret);
}

/*
 * The xmlTextReader API is a good fit for small metadata documents, but its
 * value accessor exposes one complete text node.  HWPML binary fields are
 * commonly represented by one very large base64 text node, so using that API
 * imposes an accidental allocation proportional to the attachment.  The
 * push-parser path below keeps libxml2's well-formedness checks while feeding
 * it bounded input chunks and handling the relevant text callbacks as a
 * stream.
 */
#define MSXML_STREAM_ATTR_VALUE_MAX 1024U

struct msxml_stream_frame {
    const struct key_entry *keyinfo;
    json_object *json_parent;
    json_object *json_obj;
    int ignored;

    int cb_fd;
    char *cb_name;
    uint64_t cb_reserved;
    uint64_t cb_bytes;
    int cb_saw_data;

    int b64_fd;
    char *b64_name;
    uint64_t b64_reserved;
    uint64_t b64_bytes;
    unsigned char b64_quartet[4];
    size_t b64_used;
    int b64_terminal;
    int b64_saw_data;

    char attr_keys[MAX_ATTRIBS][MSXML_JSON_STRLEN_MAX];
    char attr_values[MAX_ATTRIBS][MSXML_STREAM_ATTR_VALUE_MAX];
    struct attrib_entry attribs[MAX_ATTRIBS];
    int num_attribs;
};

struct msxml_stream_state {
    cli_ctx *ctx;
    struct msxml_ctx *mxctx;
    struct msxml_ictx ictx;
    struct msxml_stream_frame frames[MSXML_RECLEVEL_MAX];
    size_t depth;
    size_t skipped_depth;
    cl_error_t ret;
    int parser_failed;
    xmlParserCtxtPtr parser;
};

static void msxml_stream_fail(struct msxml_stream_state *state, cl_error_t ret, const char *reason)
{
    if (!state)
        return;

    if (reason)
        cli_dbgmsg("MSXML streaming parser: %s\n", reason);

    if (state->ret == CL_SUCCESS || state->ret == CL_BREAK)
        state->ret = ret;

    if (ret != CL_VIRUS && ret != CL_BREAK)
        cli_mark_scan_incomplete(state->ctx, reason ? reason : "MSXML streaming parser stopped before completion");

    if (state->parser)
        xmlStopParser(state->parser);
}

static cl_error_t msxml_stream_checktimelimit(struct msxml_stream_state *state, const char *reason)
{
    cl_error_t ret;

    if (!state)
        return CL_ENULLARG;

    ret = cli_checktimelimit(state->ctx);
    if (ret != CL_SUCCESS)
        msxml_stream_fail(state, ret, reason);

    return ret;
}

static int msxml_stream_copy_xml_string(char *dst, size_t dst_size, const xmlChar *begin, const xmlChar *end)
{
    size_t len;

    if (!dst || dst_size == 0 || !begin)
        return -1;

    if (end && end >= begin)
        len = (size_t)(end - begin);
    else
        len = (size_t)xmlStrlen(begin);

    if (len >= dst_size)
        return -1;

    memcpy(dst, begin, len);
    dst[len] = '\0';
    return 0;
}

static cl_error_t msxml_stream_reserve_write(struct msxml_stream_state *state, int fd, const void *data, size_t len,
                                             uint64_t *reserved, uint64_t *written)
{
    const unsigned char *cursor = (const unsigned char *)data;
    size_t offset               = 0;

    while (offset < len) {
        size_t chunk = MIN((size_t)MSXML_STREAM_IO_SIZE, len - offset);

        if (msxml_stream_checktimelimit(state, "MSXML streaming output reached the configured time limit") != CL_SUCCESS)
            return state->ret;

        if (cli_scan_reserve_temporary(state->ctx, (uint64_t)chunk) != CL_SUCCESS) {
            msxml_stream_fail(state, CL_ERESOURCE, "MSXML streaming spool exceeded the temporary-space limit");
            return CL_ERESOURCE;
        }

        if (msxml_stream_checktimelimit(state, "MSXML streaming output reached the configured time limit") != CL_SUCCESS) {
            cli_scan_release_temporary(state->ctx, (uint64_t)chunk);
            return state->ret;
        }

        if (cli_writen(fd, cursor + offset, chunk) != chunk) {
            cli_scan_release_temporary(state->ctx, (uint64_t)chunk);
            msxml_stream_fail(state, CL_EWRITE, "MSXML streaming spool write failed");
            return CL_EWRITE;
        }

        if (*reserved > UINT64_MAX - chunk || *written > UINT64_MAX - chunk) {
            cli_scan_release_temporary(state->ctx, (uint64_t)chunk);
            msxml_stream_fail(state, CL_EPARSE, "MSXML streaming spool size overflowed");
            return CL_EPARSE;
        }

        *reserved += (uint64_t)chunk;
        *written += (uint64_t)chunk;
        offset += chunk;
    }

    return CL_SUCCESS;
}

static int msxml_stream_base64_value(unsigned char value)
{
    if (value >= 'A' && value <= 'Z')
        return value - 'A';
    if (value >= 'a' && value <= 'z')
        return value - 'a' + 26;
    if (value >= '0' && value <= '9')
        return value - '0' + 52;
    if (value == '+')
        return 62;
    if (value == '/')
        return 63;
    return -1;
}

static cl_error_t msxml_stream_decode_base64(struct msxml_stream_state *state, struct msxml_stream_frame *frame,
                                             const xmlChar *data, int len)
{
    size_t i;

    for (i = 0; i < (size_t)len; i++) {
        if (msxml_stream_checktimelimit(state, "MSXML base64 decoding reached the configured time limit") != CL_SUCCESS)
            return state->ret;

        unsigned char value = data[i];
        unsigned char output[3];
        int a, b, c, d;
        size_t produced;

        if (isspace((int)value))
            continue;

        frame->b64_saw_data = 1;
        if (frame->b64_terminal || (value != '=' && msxml_stream_base64_value(value) < 0)) {
            msxml_stream_fail(state, CL_EPARSE, "MSXML base64 stream contains invalid trailing data");
            return CL_EPARSE;
        }

        frame->b64_quartet[frame->b64_used++] = value;
        if (frame->b64_used != sizeof(frame->b64_quartet))
            continue;

        if (frame->b64_quartet[0] == '=' || frame->b64_quartet[1] == '=' ||
            (frame->b64_quartet[2] == '=' && frame->b64_quartet[3] != '=')) {
            msxml_stream_fail(state, CL_EPARSE, "MSXML base64 stream contains invalid padding");
            return CL_EPARSE;
        }

        a = msxml_stream_base64_value(frame->b64_quartet[0]);
        b = msxml_stream_base64_value(frame->b64_quartet[1]);
        c = frame->b64_quartet[2] == '=' ? 0 : msxml_stream_base64_value(frame->b64_quartet[2]);
        d = frame->b64_quartet[3] == '=' ? 0 : msxml_stream_base64_value(frame->b64_quartet[3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) {
            msxml_stream_fail(state, CL_EPARSE, "MSXML base64 stream contains an invalid alphabet value");
            return CL_EPARSE;
        }

        produced = frame->b64_quartet[2] == '=' ? 1 : (frame->b64_quartet[3] == '=' ? 2 : 3);
        if (state->mxctx->decoded_max_size != 0 &&
            (frame->b64_bytes > state->mxctx->decoded_max_size ||
             (uint64_t)produced > state->mxctx->decoded_max_size - frame->b64_bytes)) {
            msxml_stream_fail(state, CL_EPARSE, "MSXML decoded stream exceeded its parser-family output limit");
            return CL_EPARSE;
        }
        output[0] = (unsigned char)((a << 2) | (b >> 4));
        if (produced > 1)
            output[1] = (unsigned char)((b << 4) | (c >> 2));
        if (produced > 2)
            output[2] = (unsigned char)((c << 6) | d);

        if (msxml_stream_reserve_write(state, frame->b64_fd, output, produced, &frame->b64_reserved, &frame->b64_bytes) != CL_SUCCESS)
            return state->ret;

        if (produced != 3)
            frame->b64_terminal = 1;
        frame->b64_used = 0;
    }

    return CL_SUCCESS;
}

static void msxml_stream_dispose_fd(struct msxml_stream_state *state, int *fd, char **name, uint64_t *reserved)
{
    if (!state || !fd || !name || !reserved)
        return;

    if (*reserved) {
        cli_scan_release_temporary(state->ctx, *reserved);
        *reserved = 0;
    }
    if (*fd >= 0 && close(*fd) != 0)
        msxml_stream_fail(state, CL_EWRITE, "MSXML streaming temporary output could not be closed");
    if (*name) {
        if (!state->ctx->engine->keeptmp && cli_unlink(*name) != 0)
            msxml_stream_fail(state, CL_EUNLINK, "MSXML streaming temporary output could not be removed");
        free(*name);
    }
    *fd   = -1;
    *name = NULL;

}

static void msxml_stream_cleanup_frame(struct msxml_stream_state *state, struct msxml_stream_frame *frame)
{
    if (!state || !frame)
        return;

    msxml_stream_dispose_fd(state, &frame->cb_fd, &frame->cb_name, &frame->cb_reserved);
    msxml_stream_dispose_fd(state, &frame->b64_fd, &frame->b64_name, &frame->b64_reserved);
}

static cl_error_t msxml_stream_finish_frame(struct msxml_stream_state *state, struct msxml_stream_frame *frame)
{
    cl_error_t ret;

    if (!state || !frame || frame->ignored)
        return CL_SUCCESS;

    if (frame->b64_fd >= 0) {
        if (frame->b64_used != 0) {
            msxml_stream_fail(state, CL_EPARSE, "MSXML base64 stream ended with an incomplete quartet");
            return CL_EPARSE;
        }

        if (frame->b64_saw_data) {
            if (msxml_stream_checktimelimit(state, "MSXML streaming base64 nested-scan handoff reached the configured time limit") !=
                CL_SUCCESS)
                return state->ret;
            if (state->mxctx->decoded_cb)
                ret = state->mxctx->decoded_cb(frame->b64_fd, frame->b64_name, state->ctx, state->mxctx->scan_data);
            else
                ret = cli_magic_scan_desc_type_reserved(frame->b64_fd, frame->b64_name, state->ctx, CL_TYPE_ANY, NULL,
                                                        LAYER_ATTRIBUTES_NONE);
            if (ret != CL_SUCCESS)
                return ret;
        }
    }

    if (frame->cb_fd >= 0 && frame->cb_saw_data && state->mxctx->scan_cb) {
        if (msxml_stream_checktimelimit(state, "MSXML streaming callback nested-scan handoff reached the configured time limit") !=
            CL_SUCCESS)
            return state->ret;
        ret                = state->mxctx->scan_cb(frame->cb_fd, frame->cb_name, state->ctx, frame->num_attribs,
                                                   frame->attribs, state->mxctx->scan_data);
        if (ret != CL_SUCCESS)
            return ret;
    }

    return CL_SUCCESS;
}

static void msxml_stream_add_json_value(struct msxml_stream_state *state, struct msxml_stream_frame *frame,
                                        const xmlChar *data, int len)
{
    xmlChar value[4096];
    size_t offset = 0;

    if (!frame->json_obj || !(frame->keyinfo->type & MSXML_JSON_VALUE))
        return;

    while (offset < (size_t)len) {
        size_t chunk = MIN(sizeof(value) - 1, (size_t)len - offset);
        cl_error_t ret;

        if (msxml_stream_checktimelimit(state, "MSXML JSON value processing reached the configured time limit") != CL_SUCCESS)
            return;

        memcpy(value, data + offset, chunk);
        value[chunk] = '\0';
        ret          = msxml_parse_value(frame->json_obj, "Value", value);
        if (ret != CL_SUCCESS) {
            msxml_stream_fail(state, ret, "MSXML JSON value could not be retained");
            return;
        }
        offset += chunk;
    }
}

static void msxml_sax_start_element_ns(void *arg, const xmlChar *localname, const xmlChar *prefix, const xmlChar *URI,
                                       int nb_namespaces, const xmlChar **namespaces, int nb_attributes,
                                       int nb_defaulted, const xmlChar **attributes)
{
    struct msxml_stream_state *state = (struct msxml_stream_state *)arg;
    struct msxml_stream_frame *frame;
    const struct key_entry *keyinfo;
    int i;

    UNUSEDPARAM(prefix);
    UNUSEDPARAM(URI);
    UNUSEDPARAM(nb_namespaces);
    UNUSEDPARAM(namespaces);
    UNUSEDPARAM(nb_defaulted);

    if (!state || state->ret == CL_VIRUS || state->ret == CL_BREAK || state->ret != CL_SUCCESS)
        return;

    if (msxml_stream_checktimelimit(state, "MSXML element processing reached the configured time limit") != CL_SUCCESS)
        return;

    if (state->skipped_depth) {
        state->skipped_depth++;
        return;
    }

    /* Once an element is deliberately ignored, keep libxml2 validating its
     * subtree but do not allocate one callback frame per descendant. This is
     * important for large HWPML document bodies, which may be deeply nested
     * while carrying no required embedded stream. */
    if (state->depth != 0 && state->frames[state->depth - 1].ignored) {
        state->skipped_depth = 1;
        return;
    }

    if (!localname || state->depth >= MSXML_RECLEVEL_MAX) {
        state->skipped_depth = 1;
        msxml_stream_fail(state, CL_EPARSE, "MSXML streaming parser exceeded its recursion limit");
        return;
    }

    frame = &state->frames[state->depth];
    memset(frame, 0, sizeof(*frame));
    frame->cb_fd   = -1;
    frame->b64_fd  = -1;
    keyinfo        = msxml_check_key(&state->ictx, localname, (size_t)xmlStrlen(localname));
    frame->keyinfo = keyinfo;
    frame->ignored = (state->depth != 0 && state->frames[state->depth - 1].ignored) ||
                     ((keyinfo->type & MSXML_IGNORE_ELEM) != 0);

    if (state->depth == 0) {
        frame->json_parent = state->ictx.root;
    } else {
        struct msxml_stream_frame *parent = &state->frames[state->depth - 1];
        frame->json_parent                = parent->json_obj ? parent->json_obj : parent->json_parent;
    }

    state->depth++;

    if (frame->ignored)
        return;

    if ((state->ictx.flags & MSXML_FLAG_JSON) && (keyinfo->type & MSXML_JSON_TRACK)) {
        if (keyinfo->type & MSXML_JSON_ROOT)
            frame->json_obj = cli_jsonobj(state->ictx.root, keyinfo->name);
        else if (keyinfo->type & MSXML_JSON_WRKPTR)
            frame->json_obj = cli_jsonobj(frame->json_parent, keyinfo->name);

        if (!frame->json_obj) {
            msxml_stream_fail(state, CL_EMEM, "MSXML JSON object allocation failed");
            return;
        }

        if (keyinfo->type & MSXML_JSON_COUNT) {
            json_object *counter = NULL;
            if (!json_object_object_get_ex(frame->json_obj, "Count", &counter))
                cli_jsonint(frame->json_obj, "Count", 1);
            else
                cli_jsonint(frame->json_obj, "Count", json_object_get_int(counter) + 1);
        }

        if (keyinfo->type & MSXML_JSON_MULTI) {
            json_object *multi = cli_jsonarray(frame->json_obj, "Multi");
            if (!multi || !(frame->json_obj = cli_jsonobj(multi, NULL))) {
                msxml_stream_fail(state, CL_EMEM, "MSXML JSON multi-value allocation failed");
                return;
            }
        }
    }

    if (nb_attributes < 0 || (nb_attributes > 0 && !attributes)) {
        msxml_stream_fail(state, CL_EPARSE, "MSXML attribute metadata was malformed");
        return;
    }
    if (nb_attributes > MAX_ATTRIBS) {
        msxml_stream_fail(state, CL_EPARSE, "MSXML element exceeded the bounded attribute limit");
        return;
    }

    for (i = 0; i < nb_attributes; i++) {
        const xmlChar *attr_name   = attributes[5 * i];
        const xmlChar *value_begin = attributes[5 * i + 3];
        const xmlChar *value_end   = attributes[5 * i + 4];

        if (msxml_stream_copy_xml_string(frame->attr_keys[i], sizeof(frame->attr_keys[i]), attr_name, NULL) != 0 ||
            msxml_stream_copy_xml_string(frame->attr_values[i], sizeof(frame->attr_values[i]), value_begin, value_end) != 0) {
            msxml_stream_fail(state, CL_EPARSE, "MSXML attribute exceeded the bounded callback representation");
            return;
        }
        frame->attribs[i].key   = frame->attr_keys[i];
        frame->attribs[i].value = frame->attr_values[i];
    }
    frame->num_attribs = nb_attributes;

    if ((state->ictx.flags & MSXML_FLAG_JSON) && frame->json_obj && (keyinfo->type & MSXML_JSON_ATTRIB)) {
        json_object *json_attrs = cli_jsonobj(frame->json_obj, "Attributes");
        if (!json_attrs) {
            msxml_stream_fail(state, CL_EMEM, "MSXML JSON attribute object allocation failed");
            return;
        }
        for (i = 0; i < frame->num_attribs; i++)
            cli_jsonstr(json_attrs, frame->attribs[i].key, frame->attribs[i].value);
    }

    if (keyinfo->type & MSXML_SCAN_CB) {
        if (state->mxctx->scan_cb) {
            if (cli_gentempfd(state->ctx->this_layer_tmpdir, &frame->cb_name, &frame->cb_fd) != CL_SUCCESS) {
                msxml_stream_fail(state, CL_ECREAT, "MSXML callback spool could not be created");
                return;
            }
        }
    }

    if (keyinfo->type & MSXML_SCAN_B64) {
        if (cli_gentempfd(state->ctx->this_layer_tmpdir, &frame->b64_name, &frame->b64_fd) != CL_SUCCESS) {
            msxml_stream_fail(state, CL_ECREAT, "MSXML base64 spool could not be created");
            return;
        }
    }
}

static void msxml_sax_characters(void *arg, const xmlChar *ch, int len)
{
    struct msxml_stream_state *state = (struct msxml_stream_state *)arg;
    struct msxml_stream_frame *frame;
    cl_error_t ret;

    if (!state || !ch || len <= 0 || state->ret != CL_SUCCESS || state->skipped_depth || state->depth == 0)
        return;

    if (msxml_stream_checktimelimit(state, "MSXML character processing reached the configured time limit") != CL_SUCCESS)
        return;

    frame = &state->frames[state->depth - 1];
    if (frame->ignored)
        return;

    if ((state->ictx.flags & MSXML_FLAG_JSON) && (frame->keyinfo->type & MSXML_JSON_VALUE))
        msxml_stream_add_json_value(state, frame, ch, len);
    if (state->ret != CL_SUCCESS)
        return;

    if (frame->cb_fd >= 0) {
        ret = msxml_stream_reserve_write(state, frame->cb_fd, ch, (size_t)len, &frame->cb_reserved, &frame->cb_bytes);
        if (ret != CL_SUCCESS)
            return;
        frame->cb_saw_data = 1;
    }

    if (frame->b64_fd >= 0) {
        ret = msxml_stream_decode_base64(state, frame, ch, len);
        if (ret != CL_SUCCESS)
            return;
    }
}

static void msxml_sax_end_element_ns(void *arg, const xmlChar *localname, const xmlChar *prefix, const xmlChar *URI)
{
    struct msxml_stream_state *state = (struct msxml_stream_state *)arg;
    struct msxml_stream_frame *frame;
    cl_error_t ret;

    UNUSEDPARAM(localname);
    UNUSEDPARAM(prefix);
    UNUSEDPARAM(URI);

    if (!state || state->ret == CL_VIRUS || state->ret == CL_BREAK || state->ret != CL_SUCCESS)
        return;

    if (msxml_stream_checktimelimit(state, "MSXML element processing reached the configured time limit") != CL_SUCCESS)
        return;

    if (state->skipped_depth) {
        state->skipped_depth--;
        return;
    }

    if (state->depth == 0) {
        msxml_stream_fail(state, CL_EPARSE, "MSXML end element had no matching start element");
        return;
    }

    frame = &state->frames[state->depth - 1];
    ret   = msxml_stream_finish_frame(state, frame);
    msxml_stream_cleanup_frame(state, frame);
    state->depth--;

    if (ret != CL_SUCCESS)
        msxml_stream_fail(state, ret, "MSXML embedded stream scan did not complete");
}

static void msxml_sax_comment(void *arg, const xmlChar *value)
{
    struct msxml_stream_state *state = (struct msxml_stream_state *)arg;
    struct msxml_stream_frame *frame;
    cl_error_t ret;

    if (!state || !value || state->ret != CL_SUCCESS || state->skipped_depth || state->depth == 0)
        return;

    if (msxml_stream_checktimelimit(state, "MSXML comment processing reached the configured time limit") != CL_SUCCESS)
        return;

    frame = &state->frames[state->depth - 1];
    if (frame->ignored || !(frame->keyinfo->type & MSXML_COMMENT_CB) || !state->mxctx->comment_cb)
        return;

    ret = state->mxctx->comment_cb((const char *)value, state->ctx, frame->json_obj, state->mxctx->comment_data);
    if (ret != CL_SUCCESS)
        msxml_stream_fail(state, ret, "MSXML comment callback did not complete");
}

static void msxml_sax_error(void *arg, const char *message, ...)
{
    struct msxml_stream_state *state = (struct msxml_stream_state *)arg;

    UNUSEDPARAM(message);
    if (state)
        state->parser_failed = 1;
}

static void msxml_sax_warning(void *arg, const char *message, ...)
{
    UNUSEDPARAM(arg);
    UNUSEDPARAM(message);
}

static void msxml_sax_cdata(void *arg, const xmlChar *value, int len)
{
    msxml_sax_characters(arg, value, len);
}

cl_error_t cli_msxml_parse_document_streaming(cli_ctx *ctx, fmap_t *map, const struct key_entry *keys, size_t num_keys,
                                              uint32_t flags, struct msxml_ctx *mxctx)
{
    struct msxml_ctx reserve;
    struct msxml_stream_state state;
    struct msxml_cbdata input;
    xmlSAXHandler sax;
    unsigned char buffer[MSXML_STREAM_IO_SIZE];
    int nread;
    int parse_ret;

    if (!ctx || !map || !keys)
        return CL_ENULLARG;
    if (!ctx->engine)
        return CL_ENULLARG;
    if ((flags & MSXML_FLAG_JSON) && !ctx->options)
        return CL_ENULLARG;

    if (cli_checktimelimit(ctx) != CL_SUCCESS) {
        cli_mark_scan_incomplete(ctx, "MSXML streaming inspection reached the configured time limit");
        return CL_ETIMEOUT;
    }

    if (!mxctx) {
        memset(&reserve, 0, sizeof(reserve));
        mxctx = &reserve;
    }

    memset(&state, 0, sizeof(state));
    state.ctx           = ctx;
    state.mxctx         = mxctx;
    state.ret           = CL_SUCCESS;
    state.ictx.ctx      = ctx;
    state.ictx.flags    = flags;
    state.ictx.keys     = keys;
    state.ictx.num_keys = num_keys;
    if (flags & MSXML_FLAG_JSON) {
        state.ictx.root = ctx->this_layer_metadata_json;
        if (!state.ictx.root)
            state.ictx.flags &= ~MSXML_FLAG_JSON;
    }
    mxctx->ictx = &state.ictx;

    memset(&sax, 0, sizeof(sax));
    sax.initialized         = XML_SAX2_MAGIC;
    sax.startElementNs      = msxml_sax_start_element_ns;
    sax.endElementNs        = msxml_sax_end_element_ns;
    sax.characters          = msxml_sax_characters;
    sax.ignorableWhitespace = msxml_sax_characters;
    sax.cdataBlock          = msxml_sax_cdata;
    sax.comment             = msxml_sax_comment;
    sax.warning             = msxml_sax_warning;
    sax.error               = msxml_sax_error;
    sax.fatalError          = msxml_sax_error;

    state.parser = xmlCreatePushParserCtxt(&sax, &state, NULL, 0, "msxml-stream.xml");
    if (!state.parser) {
        cli_mark_scan_incomplete(ctx, "MSXML streaming XML parser could not be initialized");
        return CL_EPARSE;
    }
    (void)xmlCtxtUseOptions(state.parser, CLAMAV_MIN_XMLREADER_FLAGS);

    memset(&input, 0, sizeof(input));
    input.map = map;
    for (;;) {
        if (msxml_stream_checktimelimit(&state, "MSXML streaming inspection reached the configured time limit") != CL_SUCCESS)
            break;

        nread = msxml_read_cb(&input, (char *)buffer, sizeof(buffer));
        if (nread < 0) {
            msxml_stream_fail(&state, CL_EREAD, "MSXML fmap input could not be read completely");
            break;
        }
        if (nread == 0)
            break;

        parse_ret = xmlParseChunk(state.parser, (const char *)buffer, nread, 0);
        if (parse_ret != 0) {
            if (state.ret == CL_SUCCESS)
                msxml_stream_fail(&state, CL_EPARSE, "MSXML streaming XML parse failed");
            break;
        }
        if (state.ret != CL_SUCCESS)
            break;
    }

    if (state.ret == CL_SUCCESS) {
        parse_ret = xmlParseChunk(state.parser, NULL, 0, 1);
        if (parse_ret != 0 || state.parser_failed || !state.parser->wellFormed)
            msxml_stream_fail(&state, CL_EPARSE, "MSXML streaming XML document was not complete");
    }

    while (state.depth) {
        state.depth--;
        msxml_stream_cleanup_frame(&state, &state.frames[state.depth]);
    }
    xmlFreeParserCtxt(state.parser);

    if ((flags & MSXML_FLAG_FAIL_INCOMPLETE) && state.ret != CL_SUCCESS && state.ret != CL_VIRUS && state.ret != CL_BREAK)
        cli_mark_scan_incomplete(ctx, "MSXML streaming document ended before XML content was fully inspected");

    if (state.ret == CL_BREAK)
        state.ret = CL_SUCCESS;
    return msxml_reconcile_status(ctx, state.ret);
}

static int msxml_attribute_limit_exceeded(cli_ctx *ctx, xmlTextReaderPtr reader, int num_attribs)
{
    /* A callback receives the complete attribute set as its metadata contract.
     * Do not silently truncate a valid element when the fixed callback
     * representation is full. The reader is still positioned on the last
     * retained attribute, so one additional advance detects an omission. */
    if (num_attribs == MAX_ATTRIBS && xmlTextReaderMoveToNextAttribute(reader) == 1) {
        cli_mark_scan_incomplete(ctx, "MSXML callback element exceeded the bounded attribute limit");
        return 1;
    }
    return 0;
}
