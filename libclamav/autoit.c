/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#if HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "others.h"
#include "scanners.h"
#include "autoit.h"
#include "fmap.h"
#include "fpu.h"

static int fpu_words = FPU_ENDIAN_INITME;

const char *autoit_functions[] = {
    "ABS",
    "ACOS",
    "ADLIBREGISTER",
    "ADLIBUNREGISTER",
    "ASC",
    "ASCW",
    "ASIN",
    "ASSIGN",
    "ATAN",
    "AUTOITSETOPTION",
    "AUTOITWINGETTITLE",
    "AUTOITWINSETTITLE",
    "BEEP",
    "BINARY",
    "BINARYLEN",
    "BINARYMID",
    "BINARYTOSTRING",
    "BITAND",
    "BITNOT",
    "BITOR",
    "BITROTATE",
    "BITSHIFT",
    "BITXOR",
    "BLOCKINPUT",
    "BREAK",
    "CALL",
    "CDTRAY",
    "CEILING",
    "CHR",
    "CHRW",
    "CLIPGET",
    "CLIPPUT",
    "CONSOLEREAD",
    "CONSOLEWRITE",
    "CONSOLEWRITEERROR",
    "CONTROLCLICK",
    "CONTROLCOMMAND",
    "CONTROLDISABLE",
    "CONTROLENABLE",
    "CONTROLFOCUS",
    "CONTROLGETFOCUS",
    "CONTROLGETHANDLE",
    "CONTROLGETPOS",
    "CONTROLGETTEXT",
    "CONTROLHIDE",
    "CONTROLLISTVIEW",
    "CONTROLMOVE",
    "CONTROLSEND",
    "CONTROLSETTEXT",
    "CONTROLSHOW",
    "CONTROLTREEVIEW",
    "COS",
    "DEC",
    "DIRCOPY",
    "DIRCREATE",
    "DIRGETSIZE",
    "DIRMOVE",
    "DIRREMOVE",
    "DLLCALL",
    "DLLCALLADDRESS",
    "DLLCALLBACKFREE",
    "DLLCALLBACKGETPTR",
    "DLLCALLBACKREGISTER",
    "DLLCLOSE",
    "DLLOPEN",
    "DLLSTRUCTCREATE",
    "DLLSTRUCTGETDATA",
    "DLLSTRUCTGETPTR",
    "DLLSTRUCTGETSIZE",
    "DLLSTRUCTSETDATA",
    "DRIVEGETDRIVE",
    "DRIVEGETFILESYSTEM",
    "DRIVEGETLABEL",
    "DRIVEGETSERIAL",
    "DRIVEGETTYPE",
    "DRIVEMAPADD",
    "DRIVEMAPDEL",
    "DRIVEMAPGET",
    "DRIVESETLABEL",
    "DRIVESPACEFREE",
    "DRIVESPACETOTAL",
    "DRIVESTATUS",
    "DUMMYSPEEDTEST",
    "ENVGET",
    "ENVSET",
    "ENVUPDATE",
    "EVAL",
    "EXECUTE",
    "EXP",
    "FILECHANGEDIR",
    "FILECLOSE",
    "FILECOPY",
    "FILECREATENTFSLINK",
    "FILECREATESHORTCUT",
    "FILEDELETE",
    "FILEEXISTS",
    "FILEFINDFIRSTFILE",
    "FILEFINDNEXTFILE",
    "FILEFLUSH",
    "FILEGETATTRIB",
    "FILEGETENCODING",
    "FILEGETLONGNAME",
    "FILEGETPOS",
    "FILEGETSHORTCUT",
    "FILEGETSHORTNAME",
    "FILEGETSIZE",
    "FILEGETTIME",
    "FILEGETVERSION",
    "FILEINSTALL",
    "FILEMOVE",
    "FILEOPEN",
    "FILEOPENDIALOG",
    "FILEREAD",
    "FILEREADLINE",
    "FILEREADTOARRAY",
    "FILERECYCLE",
    "FILERECYCLEEMPTY",
    "FILESAVEDIALOG",
    "FILESELECTFOLDER",
    "FILESETATTRIB",
    "FILESETEND",
    "FILESETPOS",
    "FILESETTIME",
    "FILEWRITE",
    "FILEWRITELINE",
    "FLOOR",
    "FTPSETPROXY",
    "FUNCNAME",
    "GUICREATE",
    "GUICTRLCREATEAVI",
    "GUICTRLCREATEBUTTON",
    "GUICTRLCREATECHECKBOX",
    "GUICTRLCREATECOMBO",
    "GUICTRLCREATECONTEXTMENU",
    "GUICTRLCREATEDATE",
    "GUICTRLCREATEDUMMY",
    "GUICTRLCREATEEDIT",
    "GUICTRLCREATEGRAPHIC",
    "GUICTRLCREATEGROUP",
    "GUICTRLCREATEICON",
    "GUICTRLCREATEINPUT",
    "GUICTRLCREATELABEL",
    "GUICTRLCREATELIST",
    "GUICTRLCREATELISTVIEW",
    "GUICTRLCREATELISTVIEWITEM",
    "GUICTRLCREATEMENU",
    "GUICTRLCREATEMENUITEM",
    "GUICTRLCREATEMONTHCAL",
    "GUICTRLCREATEOBJ",
    "GUICTRLCREATEPIC",
    "GUICTRLCREATEPROGRESS",
    "GUICTRLCREATERADIO",
    "GUICTRLCREATESLIDER",
    "GUICTRLCREATETAB",
    "GUICTRLCREATETABITEM",
    "GUICTRLCREATETREEVIEW",
    "GUICTRLCREATETREEVIEWITEM",
    "GUICTRLCREATEUPDOWN",
    "GUICTRLDELETE",
    "GUICTRLGETHANDLE",
    "GUICTRLGETSTATE",
    "GUICTRLREAD",
    "GUICTRLRECVMSG",
    "GUICTRLREGISTERLISTVIEWSORT",
    "GUICTRLSENDMSG",
    "GUICTRLSENDTODUMMY",
    "GUICTRLSETBKCOLOR",
    "GUICTRLSETCOLOR",
    "GUICTRLSETCURSOR",
    "GUICTRLSETDATA",
    "GUICTRLSETDEFBKCOLOR",
    "GUICTRLSETDEFCOLOR",
    "GUICTRLSETFONT",
    "GUICTRLSETGRAPHIC",
    "GUICTRLSETIMAGE",
    "GUICTRLSETLIMIT",
    "GUICTRLSETONEVENT",
    "GUICTRLSETPOS",
    "GUICTRLSETRESIZING",
    "GUICTRLSETSTATE",
    "GUICTRLSETSTYLE",
    "GUICTRLSETTIP",
    "GUIDELETE",
    "GUIGETCURSORINFO",
    "GUIGETMSG",
    "GUIGETSTYLE",
    "GUIREGISTERMSG",
    "GUISETACCELERATORS",
    "GUISETBKCOLOR",
    "GUISETCOORD",
    "GUISETCURSOR",
    "GUISETFONT",
    "GUISETHELP",
    "GUISETICON",
    "GUISETONEVENT",
    "GUISETSTATE",
    "GUISETSTYLE",
    "GUISTARTGROUP",
    "GUISWITCH",
    "HEX",
    "HOTKEYSET",
    "HTTPSETPROXY",
    "HTTPSETUSERAGENT",
    "HWND",
    "INETCLOSE",
    "INETGET",
    "INETGETINFO",
    "INETGETSIZE",
    "INETREAD",
    "INIDELETE",
    "INIREAD",
    "INIREADSECTION",
    "INIREADSECTIONNAMES",
    "INIRENAMESECTION",
    "INIWRITE",
    "INIWRITESECTION",
    "INPUTBOX",
    "INT",
    "ISADMIN",
    "ISARRAY",
    "ISBINARY",
    "ISBOOL",
    "ISDECLARED",
    "ISDLLSTRUCT",
    "ISFLOAT",
    "ISFUNC",
    "ISHWND",
    "ISINT",
    "ISKEYWORD",
    "ISMAP",
    "ISNUMBER",
    "ISOBJ",
    "ISPTR",
    "ISSTRING",
    "LOG",
    "MAPAPPEND",
    "MAPEXISTS",
    "MAPKEYS",
    "MAPREMOVE",
    "MEMGETSTATS",
    "MOD",
    "MOUSECLICK",
    "MOUSECLICKDRAG",
    "MOUSEDOWN",
    "MOUSEGETCURSOR",
    "MOUSEGETPOS",
    "MOUSEMOVE",
    "MOUSEUP",
    "MOUSEWHEEL",
    "MSGBOX",
    "NUMBER",
    "OBJCREATE",
    "OBJCREATEINTERFACE",
    "OBJEVENT",
    "OBJGET",
    "OBJNAME",
    "ONAUTOITEXITREGISTER",
    "ONAUTOITEXITUNREGISTER",
    "OPT",
    "PING",
    "PIXELCHECKSUM",
    "PIXELGETCOLOR",
    "PIXELSEARCH",
    "PROCESSCLOSE",
    "PROCESSEXISTS",
    "PROCESSGETSTATS",
    "PROCESSLIST",
    "PROCESSSETPRIORITY",
    "PROCESSWAIT",
    "PROCESSWAITCLOSE",
    "PROGRESSOFF",
    "PROGRESSON",
    "PROGRESSSET",
    "PTR",
    "RANDOM",
    "REGDELETE",
    "REGENUMKEY",
    "REGENUMVAL",
    "REGREAD",
    "REGWRITE",
    "ROUND",
    "RUN",
    "RUNAS",
    "RUNASWAIT",
    "RUNWAIT",
    "SEND",
    "SENDKEEPACTIVE",
    "SETERROR",
    "SETEXTENDED",
    "SHELLEXECUTE",
    "SHELLEXECUTEWAIT",
    "SHUTDOWN",
    "SIN",
    "SLEEP",
    "SOUNDPLAY",
    "SOUNDSETWAVEVOLUME",
    "SPLASHIMAGEON",
    "SPLASHOFF",
    "SPLASHTEXTON",
    "SQRT",
    "SRANDOM",
    "STATUSBARGETTEXT",
    "STDERRREAD",
    "STDINWRITE",
    "STDIOCLOSE",
    "STDOUTREAD",
    "STRING",
    "STRINGADDCR",
    "STRINGCOMPARE",
    "STRINGFORMAT",
    "STRINGFROMASCIIARRAY",
    "STRINGINSTR",
    "STRINGISALNUM",
    "STRINGISALPHA",
    "STRINGISASCII",
    "STRINGISDIGIT",
    "STRINGISFLOAT",
    "STRINGISINT",
    "STRINGISLOWER",
    "STRINGISSPACE",
    "STRINGISUPPER",
    "STRINGISXDIGIT",
    "STRINGLEFT",
    "STRINGLEN",
    "STRINGLOWER",
    "STRINGMID",
    "STRINGREGEXP",
    "STRINGREGEXPREPLACE",
    "STRINGREPLACE",
    "STRINGREVERSE",
    "STRINGRIGHT",
    "STRINGSPLIT",
    "STRINGSTRIPCR",
    "STRINGSTRIPWS",
    "STRINGTOASCIIARRAY",
    "STRINGTOBINARY",
    "STRINGTRIMLEFT",
    "STRINGTRIMRIGHT",
    "STRINGUPPER",
    "TAN",
    "TCPACCEPT",
    "TCPCLOSESOCKET",
    "TCPCONNECT",
    "TCPLISTEN",
    "TCPNAMETOIP",
    "TCPRECV",
    "TCPSEND",
    "TCPSHUTDOWN",
    "TCPSTARTUP",
    "TIMERDIFF",
    "TIMERINIT",
    "TOOLTIP",
    "TRAYCREATEITEM",
    "TRAYCREATEMENU",
    "TRAYGETMSG",
    "TRAYITEMDELETE",
    "TRAYITEMGETHANDLE",
    "TRAYITEMGETSTATE",
    "TRAYITEMGETTEXT",
    "TRAYITEMSETONEVENT",
    "TRAYITEMSETSTATE",
    "TRAYITEMSETTEXT",
    "TRAYSETCLICK",
    "TRAYSETICON",
    "TRAYSETONEVENT",
    "TRAYSETPAUSEICON",
    "TRAYSETSTATE",
    "TRAYSETTOOLTIP",
    "TRAYTIP",
    "UBOUND",
    "UDPBIND",
    "UDPCLOSESOCKET",
    "UDPOPEN",
    "UDPRECV",
    "UDPSEND",
    "UDPSHUTDOWN",
    "UDPSTARTUP",
    "VARGETTYPE",
    "WINACTIVATE",
    "WINACTIVE",
    "WINCLOSE",
    "WINEXISTS",
    "WINFLASH",
    "WINGETCARETPOS",
    "WINGETCLASSLIST",
    "WINGETCLIENTSIZE",
    "WINGETHANDLE",
    "WINGETPOS",
    "WINGETPROCESS",
    "WINGETSTATE",
    "WINGETTEXT",
    "WINGETTITLE",
    "WINKILL",
    "WINLIST",
    "WINMENUSELECTITEM",
    "WINMINIMIZEALL",
    "WINMINIMIZEALLUNDO",
    "WINMOVE",
    "WINSETONTOP",
    "WINSETSTATE",
    "WINSETTITLE",
    "WINSETTRANS",
    "WINWAIT",
    "WINWAITACTIVE",
    "WINWAITCLOSE",
    "WINWAITNOTACTIVE"};

const char *autoit_keywords[] = {
    "UNKNOWN_0", // "".
    "AND",
    "OR",
    "NOT",
    "IF",
    "THEN",
    "ELSE",
    "ELSEIF",
    "ENDIF",
    "WHILE",
    "WEND",
    "DO",
    "UNTIL",
    "FOR",
    "NEXT",
    "TO",
    "STEP",
    "IN",
    "EXITLOOP",
    "CONTINUELOOP",
    "SELECT",
    "CASE",
    "ENDSELECT",
    "SWITCH",
    "ENDSWITCH",
    "CONTINUECASE",
    "DIM",
    "REDIM",
    "LOCAL",
    "GLOBAL",
    "CONST",
    "STATIC",
    "FUNC",
    "ENDFUNC",
    "RETURN",
    "EXIT",
    "BYREF",
    "WITH",
    "ENDWITH",
    "TRUE",
    "FALSE",
    "DEFAULT",
    "NULL",
    "VOLATILE",
    "ENUM",
};

/* FIXME: use unicode detection and normalization from edwin */
static unsigned int u2a(uint8_t *dest, unsigned int len)
{
    uint8_t *src = dest;
    unsigned int i, j;

    if (len < 2)
        return len;

    if (len > 4 && src[0] == 0xff && src[1] == 0xfe && src[2]) {
        len -= 2;
        src += 2;
    } else {
        unsigned int cnt = 0;
        j                = (len > 20) ? 20 : (len & ~1);

        for (i = 0; i < j; i += 2)
            cnt += (src[i] != 0 && src[i + 1] == 0);

        if (cnt * 4 < j)
            return len;
    }

    j = len;
    len >>= 1;
    for (i = 0; i < j; i += 2)
        *dest++ = src[i];

    return len;
}

/*********************
   MT related stuff
*********************/

struct MT {
    uint32_t *next;
    uint32_t items;
    uint32_t mt[624];
};

static uint8_t MT_getnext(struct MT *MT)
{
    uint32_t r;

    if (!--MT->items) {
        uint32_t *mt = MT->mt;
        unsigned int i;

        MT->items = 624;
        MT->next  = mt;

        for (i = 0; i < 227; i++)
            mt[i] = ((((mt[i] ^ mt[i + 1]) & 0x7ffffffe) ^ mt[i]) >> 1) ^ ((0 - (mt[i + 1] & 1)) & 0x9908b0df) ^ mt[i + 397];
        for (; i < 623; i++)
            mt[i] = ((((mt[i] ^ mt[i + 1]) & 0x7ffffffe) ^ mt[i]) >> 1) ^ ((0 - (mt[i + 1] & 1)) & 0x9908b0df) ^ mt[i - 227];
        mt[623] = ((((mt[623] ^ mt[0]) & 0x7ffffffe) ^ mt[623]) >> 1) ^ ((0 - (mt[0] & 1)) & 0x9908b0df) ^ mt[i - 227];
    }

    r = *(MT->next++);
    r ^= (r >> 11);
    r ^= ((r & 0xff3a58ad) << 7);
    r ^= ((r & 0xffffdf8c) << 15);
    r ^= (r >> 18);
    return (uint8_t)(r >> 1);
}

static void MT_init(struct MT *MT, uint32_t seed)
{
    unsigned int i;
    uint32_t *mt = MT->mt;

    *mt = seed;
    for (i = 1; i < 624; i++)
        mt[i] = i + 0x6c078965 * ((mt[i - 1] >> 30) ^ mt[i - 1]);
    MT->items = 1;
    MT->next  = MT->mt;
}

static uint8_t MT_getnext_void(void *opaque)
{
    return MT_getnext((struct MT *)opaque);
}

static void MT_decrypt(uint8_t *buf, unsigned int size, uint32_t seed)
{
    struct MT MT;
    MT_init(&MT, seed);

    while (size--)
        *buf++ ^= MT_getnext(&MT);
}

/*********************
     inflate stuff
*********************/

#define AUTOIT_INPUT_CHUNK (64U * 1024U)
#define AUTOIT_OUTPUT_CHUNK (64U * 1024U)
#define AUTOIT_OUTPUT_HISTORY (1U << 15)

typedef uint8_t (*autoit_input_key_next)(void *opaque);

struct UNP {
    uint8_t *outputbuf;
    uint8_t *output_history;
    uint8_t *output_pending;
    size_t output_pending_length;
    int output_fd;
    uint8_t *inputbuf;
    size_t input_capacity;
    size_t input_window_pos;
    size_t input_window_len;
    size_t input_source_offset;
    size_t input_source_remaining;
    fmap_t *input_map;
    void *input_key_ctx;
    autoit_input_key_next input_key_next;
    cli_ctx *ctx;
    uint32_t cur_output;
    uint32_t cur_input;
    uint32_t usize;
    uint32_t csize;
    uint32_t bits_avail;
    union {
        uint32_t full;
        struct {
#if WORDS_BIGENDIAN != 0
            uint16_t h; /* BE */
            uint16_t l;
#else
            uint16_t l; /* LE */
            uint16_t h;
#endif
        } half;
    } bitmap;
    uint32_t error;
};

struct autoit_script_output {
    cli_ctx *ctx;
    uint8_t *pending;
    size_t pending_length;
    int fd;
    uint64_t total;
    uint64_t temporary_reserved;
};

static cl_error_t autoit_checktimelimit(cli_ctx *ctx, const char *reason)
{
    cl_error_t status = cli_checktimelimit(ctx);

    if (status != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, reason);

    return status;
}

static void autoit_output_destroy(struct UNP *UNP)
{
    free(UNP->output_history);
    free(UNP->output_pending);
    UNP->output_history        = NULL;
    UNP->output_pending        = NULL;
    UNP->output_pending_length = 0;
}

static cl_error_t autoit_output_flush(struct UNP *UNP)
{
    cl_error_t status;

    if (UNP->output_pending_length == 0)
        return CL_SUCCESS;

    status = autoit_checktimelimit(UNP->ctx, "AutoIt expanded member output reached the configured time limit");
    if (status != CL_SUCCESS) {
        UNP->error = 1;
        return status;
    }

    if (cli_writen(UNP->output_fd, UNP->output_pending, UNP->output_pending_length) != UNP->output_pending_length) {
        cli_mark_scan_incomplete(UNP->ctx, "AutoIt expanded member temporary output could not be written completely");
        UNP->error = 1;
        return CL_EWRITE;
    }

    UNP->output_pending_length = 0;
    return CL_SUCCESS;
}

static cl_error_t autoit_output_init(struct UNP *UNP, int output_fd)
{
    UNP->output_history = cli_max_malloc(AUTOIT_OUTPUT_HISTORY);
    UNP->output_pending = cli_max_malloc(AUTOIT_OUTPUT_CHUNK);
    if (UNP->output_history == NULL || UNP->output_pending == NULL) {
        cli_mark_scan_incomplete(UNP->ctx, "AutoIt expanded member output window could not be allocated");
        autoit_output_destroy(UNP);
        return CL_EMEM;
    }

    UNP->output_fd             = output_fd;
    UNP->output_pending_length = 0;
    return CL_SUCCESS;
}

static uint8_t autoit_output_history_byte(const struct UNP *UNP, uint32_t distance)
{
    return UNP->output_history[(UNP->cur_output - distance) % AUTOIT_OUTPUT_HISTORY];
}

static cl_error_t autoit_output_byte(struct UNP *UNP, uint8_t value)
{
    if (UNP->cur_output >= UNP->usize) {
        cli_mark_scan_incomplete(UNP->ctx, "AutoIt expanded member exceeded its declared output size");
        UNP->error = 1;
        return CL_EFORMAT;
    }

    UNP->output_history[UNP->cur_output % AUTOIT_OUTPUT_HISTORY] = value;
    UNP->output_pending[UNP->output_pending_length++]            = value;
    UNP->cur_output++;

    if (UNP->output_pending_length == AUTOIT_OUTPUT_CHUNK)
        return autoit_output_flush(UNP);
    return CL_SUCCESS;
}

static void autoit_script_output_destroy(struct autoit_script_output *output)
{
    if (!output)
        return;

    free(output->pending);
    output->pending        = NULL;
    output->pending_length = 0;
}

static cl_error_t autoit_script_output_flush(struct autoit_script_output *output)
{
    cl_error_t status;
    uint64_t admitted;

    if (!output || !output->ctx || output->fd < 0)
        return CL_ENULLARG;
    if (output->pending_length == 0)
        return CL_SUCCESS;

    status = autoit_checktimelimit(output->ctx, "AutoIt EA06 script output temporary admission reached the configured time limit");
    if (status != CL_SUCCESS)
        return status;

    admitted = (uint64_t)output->pending_length;
    status   = cli_scan_reserve_temporary(output->ctx, admitted);
    if (status != CL_SUCCESS) {
        cli_mark_scan_incomplete(output->ctx, "AutoIt EA06 script output exceeds temporary storage limits");
        return status;
    }
    output->temporary_reserved += admitted;

    status = autoit_checktimelimit(output->ctx, "AutoIt EA06 script output reached the configured time limit");
    if (status != CL_SUCCESS) {
        cli_scan_release_temporary(output->ctx, admitted);
        output->temporary_reserved -= admitted;
        return status;
    }

    if (cli_writen(output->fd, output->pending, output->pending_length) != output->pending_length) {
        cli_mark_scan_incomplete(output->ctx, "AutoIt EA06 script output could not be written completely");
        return CL_EWRITE;
    }

    output->pending_length = 0;
    return CL_SUCCESS;
}

static cl_error_t autoit_script_output_init(struct autoit_script_output *output, cli_ctx *ctx, int fd)
{
    if (!output || !ctx || fd < 0)
        return CL_ENULLARG;

    memset(output, 0, sizeof(*output));
    output->ctx     = ctx;
    output->fd      = fd;
    output->pending = cli_max_malloc(AUTOIT_OUTPUT_CHUNK);
    if (!output->pending) {
        cli_mark_scan_incomplete(ctx, "AutoIt EA06 script output window could not be allocated");
        return CL_EMEM;
    }
    return CL_SUCCESS;
}

static cl_error_t autoit_script_output_append(struct autoit_script_output *output,
                                              const void *data, size_t length)
{
    const uint8_t *source = data;
    uint64_t projected;
    cl_error_t status;

    if (!output || !output->ctx || !output->pending || (length != 0 && !data))
        return CL_ENULLARG;
    if (length == 0)
        return CL_SUCCESS;
    if ((uint64_t)length > UINT64_MAX - output->total) {
        cli_mark_scan_incomplete(output->ctx, "AutoIt EA06 script output size overflowed");
        return CL_ERESOURCE;
    }

    projected = output->total + (uint64_t)length;
    status    = cli_checklimits("cli_autoit", output->ctx, projected, 0, 0);
    if (status != CL_SUCCESS)
        return status;

    while (length != 0) {
        size_t available = AUTOIT_OUTPUT_CHUNK - output->pending_length;
        size_t chunk     = MIN(length, available);

        if (available == 0) {
            status = autoit_script_output_flush(output);
            if (status != CL_SUCCESS)
                return status;
            continue;
        }

        memcpy(output->pending + output->pending_length, source, chunk);
        output->pending_length += chunk;
        source += chunk;
        length -= chunk;
    }

    output->total = projected;
    return CL_SUCCESS;
}

static cl_error_t autoit_script_output_byte(struct autoit_script_output *output, uint8_t value)
{
    return autoit_script_output_append(output, &value, 1);
}

static cl_error_t autoit_script_output_token(struct autoit_script_output *output,
                                             const char *token, size_t length)
{
    cl_error_t status = autoit_script_output_append(output, token, length);

    if (status != CL_SUCCESS)
        return status;
    return autoit_script_output_byte(output, ' ');
}

static bool autoit_require_range(cli_ctx *ctx, fmap_t *map, const uint8_t *cursor, size_t length, const char *reason)
{
    if (length == 0)
        return true;
    if (fmap_need_ptr_once(map, cursor, length) != NULL)
        return true;

    cli_mark_scan_incomplete(ctx, reason);
    return false;
}

static void autoit_note_cleanup_failure(cli_ctx *ctx, cl_error_t *status, int failed, const char *reason)
{
    if (!failed)
        return;

    cli_mark_scan_incomplete(ctx, reason);
    if (*status == CL_SUCCESS || *status == CL_CLEAN || *status == CL_BREAK)
        *status = CL_EUNLINK;
}

static cl_error_t autoit_release_temp_member(cli_ctx *ctx, int *tempfd, char **tempfile,
                                             uint64_t *temporary_reserved, cl_error_t status)
{
    if (*tempfd >= 0) {
        autoit_note_cleanup_failure(ctx, &status, close(*tempfd) != 0,
                                    "AutoIt EA06 member temporary output could not be closed");
        *tempfd = -1;
    }
    if (*tempfile != NULL) {
        if (!ctx->engine->keeptmp)
            autoit_note_cleanup_failure(ctx, &status, cli_unlink(*tempfile) != 0,
                                        "AutoIt EA06 member temporary output could not be removed");
        free(*tempfile);
        *tempfile = NULL;
    }
    cli_scan_release_temporary(ctx, *temporary_reserved);
    *temporary_reserved = 0;
    return status;
}

static cl_error_t autoit_scan_temp_member(cli_ctx *ctx, int *tempfd, char **tempfile,
                                          uint64_t *temporary_reserved)
{
    cl_error_t status = CL_SUCCESS;

    if (lseek(*tempfd, 0, SEEK_SET) == -1) {
        cli_mark_scan_incomplete(ctx, "AutoIt EA06 member temporary output could not be rewound");
        status = CL_ESEEK;
    } else {
        status = autoit_checktimelimit(ctx, "AutoIt EA06 member nested-scan handoff reached the configured time limit");
        if (status == CL_SUCCESS)
            status = cli_magic_scan_desc_type_reserved(*tempfd, *tempfile, ctx, CL_TYPE_ANY, NULL,
                                                        LAYER_ATTRIBUTES_NONE);
    }

    return autoit_release_temp_member(ctx, tempfd, tempfile, temporary_reserved, status);
}

static bool autoit_script_read(cli_ctx *ctx, int input_fd, uint32_t offset, void *destination, size_t length,
                               const char *reason)
{
    ssize_t bytes_read;

    if (autoit_checktimelimit(ctx, "AutoIt EA06 script input traversal reached the configured time limit") != CL_SUCCESS)
        return false;

    bytes_read = pread(input_fd, destination, length, (off_t)offset);
    if (bytes_read != (ssize_t)length) {
        cli_mark_scan_incomplete(ctx, reason);
        return false;
    }

    return true;
}

static cl_error_t autoit_script_abort(cli_ctx *ctx, struct autoit_script_output *output,
                                      int *output_fd, char **output_file,
                                      int *input_fd, char **input_file,
                                      uint64_t *input_reserved, cl_error_t status)
{
    autoit_script_output_destroy(output);
    status = autoit_release_temp_member(ctx, output_fd, output_file,
                                        &output->temporary_reserved, status);
    return autoit_release_temp_member(ctx, input_fd, input_file, input_reserved, status);
}

cl_error_t cli_autoit_header_check(cli_ctx *ctx, off_t offset)
{
    static const uint8_t signature_prefix[] = {
        0xa3,
        0x48,
        0x4b,
        0xbe,
        0x98,
        0x6c,
        0x4a,
        0xa9,
        0x99,
        0x4c,
        0x53,
        0x0a,
        0x86,
        0xd6,
        0x48,
        0x7d,
        0x41,
        0x55,
        0x33,
        0x21,
        0x45,
        0x41,
        0x30,
    };
    const uint8_t *buf;
    size_t remaining;

    if (!ctx)
        return CL_ENULLARG;
    if (!ctx->fmap) {
        cli_mark_scan_incomplete(ctx, "AutoIt input map is unavailable");
        return CL_EPARSE;
    }
    if (autoit_checktimelimit(ctx, "AutoIt header inspection reached the configured time limit") != CL_SUCCESS)
        return CL_ETIMEOUT;
    if (offset < 0 || (uint64_t)offset > ctx->fmap->len)
        return CL_EFORMAT;

    remaining = ctx->fmap->len - (size_t)offset;
    if (remaining < 1)
        return CL_EFORMAT;
    if (!(buf = fmap_need_off_once(ctx->fmap, offset, 1)))
        return CL_EREAD;

    /* File-type recognition normally reports the 23-byte signature prefix;
     * accepting the version byte directly also keeps this check usable by
     * callers that already advanced to the parser's entry point. */
    if ((*buf != 0x35) && (*buf != 0x36)) {
        if (remaining < sizeof(signature_prefix) + 1)
            return CL_EFORMAT;
        if (!(buf = fmap_need_off_once(ctx->fmap, offset, sizeof(signature_prefix) + 1))) {
            cli_mark_scan_incomplete(ctx, "AutoIt header signature could not be read completely");
            return CL_EREAD;
        }
        if (memcmp(buf, signature_prefix, sizeof(signature_prefix)) != 0)
            return CL_EFORMAT;
        if ((buf[sizeof(signature_prefix)] != 0x35) && (buf[sizeof(signature_prefix)] != 0x36))
            return CL_EFORMAT;
        if (remaining - (sizeof(signature_prefix) + 1) < 16)
            return CL_EPARSE;
        return CL_SUCCESS;
    }

    if (remaining < 17)
        return CL_EPARSE;
    if (!fmap_need_off_once(ctx->fmap, offset, 17)) {
        cli_mark_scan_incomplete(ctx, "AutoIt header body could not be read completely");
        return CL_EREAD;
    }
    return CL_SUCCESS;
}

static bool autoit_input_refill(struct UNP *UNP, cli_ctx *ctx)
{
    size_t chunk;
    size_t i;

    if (autoit_checktimelimit(ctx, "AutoIt compressed input reached the configured time limit") != CL_SUCCESS) {
        UNP->error = 1;
        return false;
    }

    if (UNP->input_source_remaining == 0 || UNP->input_capacity == 0 ||
        UNP->input_map == NULL || UNP->input_key_next == NULL) {
        cli_mark_scan_incomplete(ctx, "AutoIt compressed input ended before the decoder completed");
        UNP->error = 1;
        return false;
    }

    chunk = MIN(UNP->input_source_remaining, UNP->input_capacity);
    if (fmap_readn(UNP->input_map, UNP->inputbuf, UNP->input_source_offset, chunk) != chunk) {
        cli_mark_scan_incomplete(ctx, "AutoIt compressed input could not be read completely");
        UNP->error = 1;
        return false;
    }

    for (i = 0; i < chunk; i++)
        UNP->inputbuf[i] ^= UNP->input_key_next(UNP->input_key_ctx);

    UNP->input_source_offset += chunk;
    UNP->input_source_remaining -= chunk;
    UNP->input_window_pos = 0;
    UNP->input_window_len = chunk;
    return true;
}

static bool autoit_input_byte(struct UNP *UNP, cli_ctx *ctx, uint8_t *value)
{
    if (UNP->cur_input >= UNP->csize) {
        cli_mark_scan_incomplete(ctx, "AutoIt compressed input ended before the decoder completed");
        UNP->error = 1;
        return false;
    }
    if (UNP->input_window_pos == UNP->input_window_len && !autoit_input_refill(UNP, ctx))
        return false;

    *value = UNP->inputbuf[UNP->input_window_pos++];
    UNP->cur_input++;
    return true;
}

static cl_error_t autoit_init_input_stream(struct UNP *UNP, cli_ctx *ctx, fmap_t *map,
                                           size_t offset, uint32_t size, void *key_ctx,
                                           autoit_input_key_next key_next)
{
    if (offset > map->len || (size_t)size > map->len - offset) {
        cli_mark_scan_incomplete(ctx, "AutoIt compressed stream is outside the input map");
        return CL_EREAD;
    }

    UNP->input_capacity = MIN((size_t)size, (size_t)AUTOIT_INPUT_CHUNK);
    if (UNP->input_capacity == 0)
        return CL_EFORMAT;
    if (!(UNP->inputbuf = cli_max_malloc(UNP->input_capacity))) {
        cli_mark_scan_incomplete(ctx, "AutoIt compressed input window could not be allocated");
        return CL_EMEM;
    }

    UNP->input_window_pos       = 0;
    UNP->input_window_len       = 0;
    UNP->input_source_offset    = offset;
    UNP->input_source_remaining = size;
    UNP->input_map              = map;
    UNP->input_key_ctx          = key_ctx;
    UNP->input_key_next         = key_next;
    UNP->ctx                    = ctx;
    return CL_SUCCESS;
}

static bool autoit_input_read(struct UNP *UNP, cli_ctx *ctx, uint8_t *buffer, size_t length)
{
    size_t i;

    for (i = 0; i < length; i++) {
        if (!autoit_input_byte(UNP, ctx, &buffer[i]))
            return false;
    }
    return true;
}

static uint32_t autoit_read_be32(const uint8_t *value)
{
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) | (uint32_t)value[3];
}

static uint32_t getbits(struct UNP *UNP, uint32_t size)
{
    // cli_dbgmsg("In getbits, (size: %u, bits_avail: %u, UNP->cur_input: %u)\n", size, UNP->bits_avail, UNP->cur_input);
    UNP->bitmap.half.h = 0;
    while (size) {
        if (!UNP->bits_avail) {
            // cli_dbgmsg("cur_input: %u (size: %u)\n", UNP->cur_input, size);
            uint8_t high, low;
            if (UNP->input_key_next == NULL) {
                if (UNP->cur_input > UNP->csize || UNP->csize - UNP->cur_input < 2) {
                    cli_mark_scan_incomplete(UNP->ctx, "AutoIt compressed input ended before the decoder completed");
                    UNP->error = 1;
                    return 0;
                }
                high = UNP->inputbuf[UNP->cur_input++];
                low  = UNP->inputbuf[UNP->cur_input++];
            } else if (!autoit_input_byte(UNP, UNP->ctx, &high) || !autoit_input_byte(UNP, UNP->ctx, &low)) {
                return 0;
            }
            UNP->bitmap.half.l |= high << 8;
            UNP->bitmap.half.l |= low;
            UNP->bits_avail = 16;
        }
        UNP->bitmap.full <<= 1;
        UNP->bits_avail--;
        size--;
    }
    return (uint32_t)UNP->bitmap.half.h;
}

/*********************
 autoit3 EA05 handler
*********************/

static cl_error_t ea05(cli_ctx *ctx, const uint8_t *base)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;
    uint8_t b[300];
    uint8_t comp;
    uint32_t s, m4sum = 0;
    int i;
    unsigned int files          = 0;
    char *tempfile              = NULL;
    int tempfd                  = -1;
    uint64_t temporary_reserved = 0;
    uint8_t stored_buffer[AUTOIT_INPUT_CHUNK];
    struct UNP UNP = {0};
    struct MT input_mt;
    size_t input_offset;
    size_t next_offset;
    uint8_t decoded_header[8];
    fmap_t *map = ctx->fmap;

    UNP.ctx       = ctx;
    UNP.output_fd = -1;

    if (!autoit_require_range(ctx, map, base, 16, "AutoIt EA05 header is truncated")) {
        status = CL_EREAD;
        goto done;
    }

    for (i = 0; i < 16; i++)
        m4sum += *base++;

    // While we have not exceeded the max files limit or the max time limit...
    while (CL_SUCCESS == (status = cli_checklimits("autoit", ctx, 0, 0, 0))) {
        if (base == NULL)
            goto done;
        if (!autoit_require_range(ctx, map, base, 8, "AutoIt EA05 member header is truncated")) {
            status = CL_EREAD;
            goto done;
        }

        /*     MT_decrypt(buf,4,0x16fa);  waste of time */
        if ((uint32_t)cli_readint32(base) != 0xceb06dff) {
            cli_dbgmsg("autoit: no FILE magic found, extraction complete\n");
            goto done;
        }

        s = cli_readint32(base + 4) ^ 0x29bc;
        if ((int32_t)s < 0) {
            cli_mark_scan_incomplete(ctx, "AutoIt EA05 magic string length is invalid");
            status = CL_EFORMAT;
            goto done;
        }
        base += 8;
        if (!autoit_require_range(ctx, map, base, s, "AutoIt EA05 magic string is truncated")) {
            status = CL_EREAD;
            goto done;
        }
        if (cli_debug_flag && s < sizeof(b)) {
            memcpy(b, base, s);
            MT_decrypt(b, s, s + 0xa25e);
            b[s] = '\0';
            cli_dbgmsg("autoit: magic string '%s'\n", b);
        }
        base += s;

        if (!autoit_require_range(ctx, map, base, 4, "AutoIt EA05 filename length is truncated")) {
            status = CL_EREAD;
            goto done;
        }
        s = cli_readint32(base) ^ 0x29ac;
        if ((int32_t)s < 0) {
            cli_mark_scan_incomplete(ctx, "AutoIt EA05 filename length is invalid");
            status = CL_EFORMAT;
            goto done;
        }
        base += 4;
        if (!autoit_require_range(ctx, map, base, s, "AutoIt EA05 filename is truncated")) {
            status = CL_EREAD;
            goto done;
        }
        if (cli_debug_flag && s < sizeof(b)) {
            memcpy(b, base, s);
            MT_decrypt(b, s, s + 0xf25e);
            b[s] = '\0';
            cli_dbgmsg("autoit: original filename '%s'\n", b);
        }
        base += s;

        if (!autoit_require_range(ctx, map, base, 29, "AutoIt EA05 file metadata is truncated")) {
            status = CL_EREAD;
            goto done;
        }

        comp      = *base;
        UNP.csize = cli_readint32(base + 1) ^ 0x45aa;
        if ((int32_t)UNP.csize < 0) {
            cli_dbgmsg("autoit: bad file size - giving up\n");
            cli_mark_scan_incomplete(ctx, "AutoIt EA05 member declares an invalid compressed size");
            status = CL_EFORMAT;
            goto done;
        }

        if (!UNP.csize) {
            cli_dbgmsg("autoit: skipping empty file\n");
            base += 13 + 16;
            continue;
        }
        cli_dbgmsg("autoit: compressed size: %x\n", UNP.csize);
        cli_dbgmsg("autoit: advertised uncompressed size %x\n", cli_readint32(base + 5) ^ 0x45aa);
        cli_dbgmsg("autoit: ref chksum: %x\n", cli_readint32(base + 9) ^ 0xc3d2);

        base += 13 + 16;

        status = cli_checklimits("autoit", ctx, UNP.csize, 0, 0);
        if (status != CL_CLEAN) {
            cli_mark_scan_incomplete(ctx, "AutoIt EA05 member exceeds configured scan limits");
            goto done;
        }

        if (comp == 1 && UNP.csize < 8) {
            cli_dbgmsg("autoit: compressed size too small\n");
            cli_mark_scan_incomplete(ctx, "AutoIt EA05 compressed member is shorter than its header");
            status = CL_EFORMAT;
            goto done;
        }

        files++;
        status = cli_gentempfd_with_prefix(ctx->this_layer_tmpdir, "autoit", &tempfile, &tempfd);
        if (status != CL_SUCCESS) {
            cli_mark_scan_incomplete(ctx, "AutoIt EA05 member temporary output could not be created");
            goto done;
        }

        if (comp == 1) {
            /*
             * File is compressed. Decompress!
             */
            cli_dbgmsg("autoit: file is compressed\n");
            input_offset = fmap_ptr2off(map, base);
            if (input_offset > map->len || (size_t)UNP.csize > map->len - input_offset) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 compressed stream is truncated");
                status = CL_EREAD;
                goto done;
            }
            if (input_offset > SIZE_MAX - (size_t)UNP.csize) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 compressed stream offset overflowed");
                status = CL_EFORMAT;
                goto done;
            }
            next_offset = input_offset + (size_t)UNP.csize;
            if (next_offset == map->len) {
                base = NULL;
            } else if (!(base = fmap_need_off_once(map, next_offset, 1))) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 next member could not be read");
                status = CL_EREAD;
                goto done;
            }

            MT_init(&input_mt, 0x22af + m4sum);
            status = autoit_init_input_stream(&UNP, ctx, map, input_offset, UNP.csize,
                                              &input_mt, MT_getnext_void);
            if (status != CL_SUCCESS)
                goto done;
            if (!autoit_input_read(&UNP, ctx, decoded_header, sizeof(decoded_header))) {
                status = CL_EREAD;
                goto done;
            }

            if (cli_readint32(decoded_header) != 0x35304145) {
                cli_dbgmsg("autoit: bad magic or unsupported version\n");
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 compressed member has invalid decoder magic");
                status = CL_EFORMAT;
                goto done;
            }

            if (!(UNP.usize = autoit_read_be32(decoded_header + 4))) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 compressed member declares a zero output size");
                status = CL_EFORMAT;
                goto done;
            }

            status = cli_checklimits("autoit", ctx, UNP.usize, 0, 0);
            if (status != CL_CLEAN) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 expanded member exceeds configured scan limits");
                goto done;
            }

            status = cli_scan_reserve_temporary(ctx, UNP.usize);
            if (status != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 expanded member exceeds temporary storage limits");
                goto done;
            }
            temporary_reserved = UNP.usize;

            status = autoit_checktimelimit(ctx, "AutoIt EA05 expanded member temporary admission reached the configured time limit");
            if (status != CL_SUCCESS)
                goto done;

            status = autoit_output_init(&UNP, tempfd);
            if (status != CL_SUCCESS)
                goto done;

            cli_dbgmsg("autoit: uncompressed size again: %x\n", UNP.usize);

            UNP.cur_output  = 0;
            UNP.cur_input   = 8;
            UNP.bitmap.full = 0;
            UNP.bits_avail  = 0;
            UNP.error       = 0;

            while (!UNP.error && UNP.cur_output < UNP.usize) {
                if ((UNP.cur_output % AUTOIT_OUTPUT_CHUNK) == 0 &&
                    CL_SUCCESS != (status = cli_checktimelimit(ctx))) {
                    UNP.error = 1;
                    break;
                }
                if (getbits(&UNP, 1)) {
                    uint32_t bb, bs, addme = 0;
                    bb = getbits(&UNP, 15);

                    if ((bs = getbits(&UNP, 2)) == 3) {
                        addme = 3;
                        if ((bs = getbits(&UNP, 3)) == 7) {
                            addme = 10;
                            if ((bs = getbits(&UNP, 5)) == 31) {
                                addme = 41;
                                if ((bs = getbits(&UNP, 8)) == 255) {
                                    addme = 296;
                                    while ((bs = getbits(&UNP, 8)) == 255) {
                                        if (addme > UINT32_MAX - 255) {
                                            UNP.error = 1;
                                            break;
                                        }
                                        addme += 255;
                                    }
                                }
                            }
                        }
                    }
                    if (UNP.error || addme > UINT32_MAX - 3 || bs > UINT32_MAX - 3 - addme) {
                        UNP.error = 1;
                        break;
                    }
                    bs += 3 + addme;

                    /* If getbits set UNP.error, bail out here, since otherwise
                     * the data we'd write out would be garbage */
                    if (UNP.error) {
                        break;
                    }

                    if (bb == 0 || bb > AUTOIT_OUTPUT_HISTORY || bb > UNP.cur_output || bs > UNP.usize - UNP.cur_output) {
                        UNP.error = 1;
                        break;
                    }
                    while (bs--) {
                        status = autoit_output_byte(&UNP, autoit_output_history_byte(&UNP, bb));
                        if (status != CL_SUCCESS)
                            break;
                    }
                } else {
                    uint32_t literal = getbits(&UNP, 8);
                    if (UNP.error)
                        break;
                    status = autoit_output_byte(&UNP, (uint8_t)literal);
                }
            }

            if (!UNP.error && UNP.cur_output != UNP.usize) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 compressed member ended before its declared output size");
                status    = CL_EFORMAT;
                UNP.error = 1;
            }
            if (!UNP.error && status == CL_SUCCESS)
                status = autoit_output_flush(&UNP);

            free(UNP.inputbuf);
            UNP.inputbuf = NULL;
            autoit_output_destroy(&UNP);

            /* Sometimes the autoit exe is in turn packed/lamed with a runtime compressor and similar shit.
             * However, since the autoit script doesn't compress a second time very well, chances are we're
             * still able to match the headers and unpack something (see sample 0811129)
             * I'd rather unpack something (although possibly highly corrupted) than nothing at all
             *
             * - Fortuna audaces iuvat -
             */
            if (UNP.error) {
                cli_dbgmsg("autoit: decompression error after %u bytes  - partial file may exist\n", UNP.cur_output);
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 member decompression was incomplete");
                if (status == CL_SUCCESS)
                    status = CL_EFORMAT;
                goto done;
            }
        } else {
            /*
             * File is NOT compressed.
             */
            cli_dbgmsg("autoit: file is not compressed\n");
            input_offset = fmap_ptr2off(map, base);
            if (input_offset > map->len || (size_t)UNP.csize > map->len - input_offset) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 stored member is truncated");
                status = CL_EREAD;
                goto done;
            }
            if (input_offset > SIZE_MAX - (size_t)UNP.csize) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 stored member offset overflowed");
                status = CL_EFORMAT;
                goto done;
            }
            next_offset = input_offset + (size_t)UNP.csize;
            if (next_offset == map->len) {
                base = NULL;
            } else if (!(base = fmap_need_off_once(map, next_offset, 1))) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 next member could not be read");
                status = CL_EREAD;
                goto done;
            }
            status = cli_scan_reserve_temporary(ctx, UNP.csize);
            if (status != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA05 stored member exceeds temporary storage limits");
                goto done;
            }
            temporary_reserved = UNP.csize;

            status = autoit_checktimelimit(ctx, "AutoIt EA05 stored member temporary admission reached the configured time limit");
            if (status != CL_SUCCESS)
                goto done;

            MT_init(&input_mt, 0x22af + m4sum);
            while (input_offset < next_offset) {
                size_t chunk = MIN(next_offset - input_offset, sizeof(stored_buffer));
                size_t j;

                if (CL_SUCCESS != (status = cli_checktimelimit(ctx)))
                    goto done;
                if (fmap_readn(map, stored_buffer, input_offset, chunk) != chunk) {
                    cli_mark_scan_incomplete(ctx, "AutoIt EA05 stored member could not be read completely");
                    status = CL_EREAD;
                    goto done;
                }
                for (j = 0; j < chunk; j++)
                    stored_buffer[j] ^= MT_getnext(&input_mt);
                if (CL_SUCCESS != (status = autoit_checktimelimit(ctx, "AutoIt EA05 stored member output reached the configured time limit")))
                    goto done;
                if (cli_writen(tempfd, stored_buffer, chunk) != chunk) {
                    cli_mark_scan_incomplete(ctx, "AutoIt EA05 stored member temporary output could not be written completely");
                    status = CL_EWRITE;
                    goto done;
                }
                input_offset += chunk;
            }
            UNP.usize = UNP.csize;
        }

        if (UNP.usize < 4) {
            cli_dbgmsg("autoit: file is too short\n");
            cli_mark_scan_incomplete(ctx, "AutoIt EA05 extracted member is too short to inspect");
            status = CL_EFORMAT;
            goto done;
        }

        if (ctx->engine->keeptmp) {
            cli_dbgmsg("autoit: file extracted to %s\n", tempfile);
        } else {
            cli_dbgmsg("autoit: file successfully extracted\n");
        }

        if (lseek(tempfd, 0, SEEK_SET) == -1) {
            cli_dbgmsg("autoit: call to lseek() has failed\n");
            status = CL_ESEEK;
            goto done;
        }

        ret = cli_magic_scan_desc_type_reserved(tempfd, tempfile, ctx, CL_TYPE_ANY, NULL,
                                                 LAYER_ATTRIBUTES_NONE);
        if (CL_SUCCESS != ret) {
            status = ret;
            goto done;
        }

        if (close(tempfd) == -1) {
            cli_mark_scan_incomplete(ctx, "AutoIt EA05 member temporary output could not be closed");
            status = CL_EWRITE;
        }
        tempfd = -1;
        if (!ctx->engine->keeptmp && cli_unlink(tempfile)) {
            cli_mark_scan_incomplete(ctx, "AutoIt EA05 member temporary output could not be removed");
            if (status == CL_SUCCESS)
                status = CL_EUNLINK;
        }
        free(tempfile);
        tempfile = NULL;
        cli_scan_release_temporary(ctx, temporary_reserved);
        temporary_reserved = 0;
        if (status != CL_SUCCESS)
            goto done;
    }

    if (status != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, "AutoIt EA05 extraction stopped at a configured limit");

done:
    if (NULL != UNP.inputbuf) {
        free(UNP.inputbuf);
    }
    autoit_output_destroy(&UNP);
    if (NULL != UNP.outputbuf) {
        free(UNP.outputbuf);
    }
    if (tempfd >= 0) {
        autoit_note_cleanup_failure(ctx, &status, close(tempfd) != 0,
                                    "AutoIt EA05 member temporary output could not be closed");
        if (!ctx->engine->keeptmp)
            autoit_note_cleanup_failure(ctx, &status, cli_unlink(tempfile) != 0,
                                        "AutoIt EA05 member temporary output could not be removed");
    }
    free(tempfile);
    cli_scan_release_temporary(ctx, temporary_reserved);
    return status;
}

/*********************
  LAME related stuff
*********************/

#define ROFL(a, b) ((a << (b % (sizeof(a) << 3))) | (a >> ((sizeof(a) << 3) - (b % (sizeof(a) << 3)))))

struct LAME {
    uint32_t c0;
    uint32_t c1;
    uint32_t grp1[17];
};

static double LAME_fpusht(struct LAME *l)
{
    union {
        double as_double;
        struct {
            uint32_t lo;
            uint32_t hi;
        } as_uint;
    } ret;

    uint32_t rolled = ROFL(l->grp1[l->c0], 9) + ROFL(l->grp1[l->c1], 13);

    l->grp1[l->c0] = rolled;

    if (!l->c0--) l->c0 = 16;
    if (!l->c1--) l->c1 = 16;

    /*   if (l->grp1[l->c0] == l->grp2[0]) { */
    /*     if (!memcmp(l->grp1, (uint32_t *)l + 0x24 - l->c0, 0x44)) */
    /*       return 0.0; */
    /*   } */

    if (fpu_words == FPU_ENDIAN_LITTLE) {
        ret.as_uint.lo = rolled << 0x14;
        ret.as_uint.hi = 0x3ff00000 | (rolled >> 0xc);
    } else {
        ret.as_uint.hi = rolled << 0x14;
        ret.as_uint.lo = 0x3ff00000 | (rolled >> 0xc);
    }
    return ret.as_double - 1.0;
}

static void LAME_srand(struct LAME *l, uint32_t seed)
{
    unsigned int i;

    for (i = 0; i < 17; i++) {
        seed *= 0x53A9B4FB; /*1403630843*/
        seed       = 1 - seed;
        l->grp1[i] = seed;
    }

    l->c0 = 0;
    l->c1 = 10;

    for (i = 0; i < 9; i++)
        LAME_fpusht(l);
}

static uint8_t LAME_getnext(struct LAME *l)
{
    double x;
    uint8_t ret;

    LAME_fpusht(l);
    x = LAME_fpusht(l) * 256.0;
    if ((int32_t)x < 256)
        ret = (uint8_t)x;
    else
        ret = 0xff;
    return ret;
}

static uint8_t LAME_getnext_void(void *opaque)
{
    return LAME_getnext((struct LAME *)opaque);
}

static void LAME_decrypt(uint8_t *cypher, uint32_t size, uint16_t seed)
{
    struct LAME lame;
    /* mt_srand_timewrap(struct srand_struc bufDC); */

    LAME_srand(&lame, (uint32_t)seed);
    while (size--)
        *cypher++ ^= LAME_getnext(&lame);
}

/*********************
 autoit3 EA06 handler
*********************/

static cl_error_t ea06(cli_ctx *ctx, const uint8_t *base, char *tmpd)
{
    cl_error_t ret = CL_SUCCESS;
    cl_error_t status;
    uint8_t b[600], comp;
    uint32_t s;
    char *stream_tempfile = NULL;
    char *script_tempfile = NULL;
    int stream_tempfd = -1;
    int script_tempfd = -1;
    uint64_t stream_reserved = 0;
    uint8_t stored_buffer[AUTOIT_INPUT_CHUNK];
    bool stream_output = false;
    const char prefixes[] = {'\0', '\0', '@', '$', '\0', '.', '"', '\0'};
    const char *opers[]   = {",", "=", ">", "<", "<>", ">=", "<=", "(", ")", "+", "-", "/", "*", "&", "[", "]", "==", "^", "+=", "-=", "/=", "*=", "&=", "?", ":"};
    struct UNP UNP        = {0};
    struct autoit_script_output script_output = {0};
    struct LAME input_lame;
    size_t input_offset;
    size_t next_offset;
    uint8_t decoded_header[8];
    fmap_t *map = ctx->fmap;

    UNP.ctx = ctx;

    /* Useless due to a bug in CRC calculation - LMAO!!1 */
    /*   if (cli_readn(desc, buf, 24)!=24) */
    /*     return CL_CLEAN; */
    /*   LAME_decrypt(buf, 0x10, 0x99f2); */
    /*   buf+=0x10; */
    if (!autoit_require_range(ctx, map, base, 16, "AutoIt EA06 header is truncated"))
        return CL_EREAD;
    base += 16; /* for now we just skip the garbage */

    while (CL_SUCCESS == (ret = cli_checklimits("cli_autoit", ctx, 0, 0, 0))) {
        bool script = false;

        status = CL_SUCCESS;

        stream_output = false;

        ret = autoit_checktimelimit(ctx, "AutoIt member traversal reached the configured time limit");
        if (ret != CL_SUCCESS)
            break;

        if (base == NULL)
            break;

        if (!autoit_require_range(ctx, map, base, 8, "AutoIt EA06 member header is truncated")) {
            return CL_EREAD;
        }

        /*     LAME_decrypt(buf, 4, 0x18ee); waste of time */
        if (cli_readint32(base) != 0x52ca436b) {
            cli_dbgmsg("autoit: no FILE magic found, giving up (got 0x%08x)\n", cli_readint32(base));
            cli_mark_scan_incomplete(ctx, "AutoIt EA06 member header has invalid magic");
            return CL_EFORMAT;
        }

        s = cli_readint32(base + 4) ^ 0xadbc;
        if (s > UINT32_MAX / 2) {
            cli_mark_scan_incomplete(ctx, "AutoIt EA06 magic string length overflowed");
            return CL_EFORMAT;
        }

        base += 8;

        if (!autoit_require_range(ctx, map, base, (size_t)s * 2, "AutoIt EA06 magic string is truncated"))
            return CL_EREAD;

        if (s < sizeof(b) / 2) {
            memcpy(b, base, (size_t)s * 2);
            LAME_decrypt(b, s * 2, s + 0xb33f);
            u2a(b, s * 2);
            cli_dbgmsg("autoit: magic string '%s'\n", b);

            if (s == 19 && !memcmp(">>>AUTOIT SCRIPT<<<", b, 19)) {
                script = true;
            }
        } else {
            cli_dbgmsg("autoit: magic string too long to print\n");
        }

        base += (size_t)s * 2;

        if (!autoit_require_range(ctx, map, base, 4, "AutoIt EA06 filename length is truncated")) {
            return CL_EREAD;
        }

        s = cli_readint32(base) ^ 0xf820;
        if (s > UINT32_MAX / 2) {
            cli_mark_scan_incomplete(ctx, "AutoIt EA06 filename length overflowed");
            return CL_EFORMAT;
        }

        base += 4;

        if (!autoit_require_range(ctx, map, base, (size_t)s * 2, "AutoIt EA06 filename is truncated"))
            return CL_EREAD;

        if (cli_debug_flag && s < sizeof(b) / 2) {
            memcpy(b, base, (size_t)s * 2);
            LAME_decrypt(b, s * 2, s + 0xf479);
            b[s * 2]     = '\0';
            b[s * 2 + 1] = '\0';
            u2a(b, s * 2);

            cli_dbgmsg("autoit: original filename '%s'\n", b);
        }

        base += (size_t)s * 2;

        if (!autoit_require_range(ctx, map, base, 29, "AutoIt EA06 file metadata is truncated")) {
            return CL_EREAD;
        }

        comp      = *base;
        UNP.csize = cli_readint32(base + 1) ^ 0x87bc;
        if ((int32_t)UNP.csize < 0) {
            cli_dbgmsg("autoit: bad file size - giving up\n");
            cli_mark_scan_incomplete(ctx, "AutoIt EA06 member declares an invalid compressed size");
            return CL_EFORMAT;
        }

        if (!UNP.csize) {
            cli_dbgmsg("autoit: skipping empty file\n");
            base += 13 + 16;
            continue;
        }

        cli_dbgmsg("autoit: compressed size: %x\n", UNP.csize);
        cli_dbgmsg("autoit: advertised uncompressed size %x\n", cli_readint32(base + 5) ^ 0x87bc);
        cli_dbgmsg("autoit: ref chksum: %x\n", cli_readint32(base + 9) ^ 0xa685);

        base += 13 + 16;

        ret = cli_checklimits("autoit", ctx, UNP.csize, 0, 0);
        if (ret != CL_CLEAN) {
            cli_mark_scan_incomplete(ctx, "AutoIt EA06 member exceeds configured scan limits");
            return ret;
        }

        if (comp == 1 && UNP.csize < 8) {
            cli_dbgmsg("autoit: compressed size too small\n");
            cli_mark_scan_incomplete(ctx, "AutoIt EA06 compressed member is shorter than its header");
            return CL_EFORMAT;
        }

        if (comp == 1) {
            cli_dbgmsg("autoit: file is compressed\n");

            input_offset = fmap_ptr2off(map, base);
            if (input_offset > map->len || (size_t)UNP.csize > map->len - input_offset) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 compressed stream is truncated");
                return CL_EREAD;
            }
            if (input_offset > SIZE_MAX - (size_t)UNP.csize) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 compressed stream offset overflowed");
                return CL_EFORMAT;
            }
            next_offset = input_offset + (size_t)UNP.csize;
            if (next_offset == map->len) {
                base = NULL;
            } else if (!(base = fmap_need_off_once(map, next_offset, 1))) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 next member could not be read");
                return CL_EREAD;
            }

            LAME_srand(&input_lame, 0x2477 /* + m4sum (broken by design) */);
            ret = autoit_init_input_stream(&UNP, ctx, map, input_offset, UNP.csize,
                                           &input_lame, LAME_getnext_void);
            if (ret != CL_SUCCESS)
                return ret;
            if (!autoit_input_read(&UNP, ctx, decoded_header, sizeof(decoded_header))) {
                free(UNP.inputbuf);
                UNP.inputbuf = NULL;
                return ctx->scan_timed_out ? CL_ETIMEOUT : CL_EREAD;
            }

            if (cli_readint32(decoded_header) != 0x36304145) {
                cli_dbgmsg("autoit: bad magic or unsupported version\n");
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 compressed member has invalid decoder magic");
                free(UNP.inputbuf);
                UNP.inputbuf = NULL;
                return CL_EFORMAT;
            }

            if (!(UNP.usize = autoit_read_be32(decoded_header + 4))) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 compressed member declares a zero output size");
                free(UNP.inputbuf);
                UNP.inputbuf = NULL;
                return CL_EFORMAT;
            }

            ret = cli_checklimits("autoit", ctx, UNP.usize, 0, 0);
            if (ret != CL_CLEAN) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 expanded member exceeds configured scan limits");
                free(UNP.inputbuf);
                UNP.inputbuf = NULL;
                return ret;
            }

            ret = cli_scan_reserve_temporary(ctx, UNP.usize);
            if (ret != CL_SUCCESS) {
                free(UNP.inputbuf);
                UNP.inputbuf = NULL;
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 expanded member exceeds temporary storage limits");
                return ret;
            }
            stream_reserved = UNP.usize;
            ret = autoit_checktimelimit(ctx, "AutoIt EA06 expanded member temporary admission reached the configured time limit");
            if (ret != CL_SUCCESS) {
                free(UNP.inputbuf);
                UNP.inputbuf = NULL;
                return autoit_release_temp_member(ctx, &stream_tempfd, &stream_tempfile,
                                                  &stream_reserved, ret);
            }
            ret = cli_gentempfd_with_prefix(ctx->this_layer_tmpdir, "autoit", &stream_tempfile, &stream_tempfd);
            if (ret != CL_SUCCESS) {
                free(UNP.inputbuf);
                UNP.inputbuf = NULL;
                cli_scan_release_temporary(ctx, stream_reserved);
                stream_reserved = 0;
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 expanded member temporary output could not be created");
                return ret;
            }
            stream_output = true;
            ret = autoit_output_init(&UNP, stream_tempfd);
            if (ret != CL_SUCCESS) {
                free(UNP.inputbuf);
                UNP.inputbuf = NULL;
                stream_output = false;
                return autoit_release_temp_member(ctx, &stream_tempfd, &stream_tempfile,
                                                  &stream_reserved, ret);
            }

            cli_dbgmsg("autoit: uncompressed size again: %x\n", UNP.usize);

            UNP.cur_output  = 0;
            UNP.cur_input   = 8;
            UNP.bitmap.full = 0;
            UNP.bits_avail  = 0;
            UNP.error       = 0;

            while (!UNP.error && UNP.cur_output < UNP.usize) {
                ret = autoit_checktimelimit(ctx, "AutoIt EA06 decompression reached the configured time limit");
                if (ret != CL_SUCCESS) {
                    UNP.error = 1;
                    break;
                }
                if (!getbits(&UNP, 1)) {
                    uint32_t bb, bs, addme = 0;
                    bb = getbits(&UNP, 15);

                    if ((bs = getbits(&UNP, 2)) == 3) {
                        addme = 3;
                        if ((bs = getbits(&UNP, 3)) == 7) {
                            addme = 10;
                            if ((bs = getbits(&UNP, 5)) == 31) {
                                addme = 41;
                                if ((bs = getbits(&UNP, 8)) == 255) {
                                    addme = 296;
                                    while ((bs = getbits(&UNP, 8)) == 255) {
                                        if (addme > UINT32_MAX - 255) {
                                            UNP.error = 1;
                                            break;
                                        }
                                        addme += 255;
                                    }
                                }
                            }
                        }
                    }
                    if (UNP.error || addme > UINT32_MAX - 3 || bs > UINT32_MAX - 3 - addme) {
                        UNP.error = 1;
                        break;
                    }
                    bs += 3 + addme;

                    /* If getbits set UNP.error, bail out here, since otherwise
                     * the data we'd write out would be garbage */
                    if (UNP.error) {
                        break;
                    }

                    // cli_dbgmsg("cur_output: %u, bs: %u, bb: %u\n", UNP.cur_output, bs, bb);
                    if (bb == 0 || bb > UNP.cur_output || (stream_output && bb > AUTOIT_OUTPUT_HISTORY) ||
                        bs > UNP.usize - UNP.cur_output) {
                        UNP.error = 1;
                        break;
                    }

                    while (bs--) {
                        if (autoit_checktimelimit(ctx, "AutoIt EA06 decompression reached the configured time limit") != CL_SUCCESS) {
                            UNP.error = 1;
                            break;
                        }
                        status = autoit_output_byte(&UNP, autoit_output_history_byte(&UNP, bb));
                        if (status != CL_SUCCESS) {
                            UNP.error = 1;
                            break;
                        }
                    }
                } else {
                    uint32_t literal = getbits(&UNP, 8);
                    if (UNP.error)
                        break;
                    status = autoit_output_byte(&UNP, (uint8_t)literal);
                    if (status != CL_SUCCESS)
                        UNP.error = 1;
                }
            }

            free(UNP.inputbuf);
            UNP.inputbuf = NULL;
            if (!UNP.error && UNP.cur_output != UNP.usize) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 compressed member ended before its declared output size");
                status    = CL_EFORMAT;
                UNP.error = 1;
            }
            if (stream_output && !UNP.error && status == CL_SUCCESS)
                status = autoit_output_flush(&UNP);
            autoit_output_destroy(&UNP);
            if (UNP.error) {
                cli_dbgmsg("autoit: decompression error after %u bytes - partial file may exist\n", UNP.cur_output);
                if (ctx->scan_timed_out) {
                    if (stream_output) {
                        stream_output = false;
                        return autoit_release_temp_member(ctx, &stream_tempfd, &stream_tempfile,
                                                          &stream_reserved, CL_ETIMEOUT);
                    }
                    return CL_ETIMEOUT;
                }
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 member decompression was incomplete");
                if (stream_output) {
                    stream_output = false;
                    return autoit_release_temp_member(ctx, &stream_tempfd, &stream_tempfile,
                                                      &stream_reserved, status == CL_SUCCESS ? CL_EFORMAT : status);
                }
                return CL_EFORMAT;
            }
            if (stream_output && status != CL_SUCCESS) {
                stream_output = false;
                return autoit_release_temp_member(ctx, &stream_tempfd, &stream_tempfile,
                                                  &stream_reserved, status);
            }
        } else {
            cli_dbgmsg("autoit: file is not compressed\n");
            input_offset = fmap_ptr2off(map, base);
            if (input_offset > map->len || (size_t)UNP.csize > map->len - input_offset) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 stored member is truncated");
                return CL_EREAD;
            }
            if (input_offset > SIZE_MAX - (size_t)UNP.csize) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 stored member offset overflowed");
                return CL_EFORMAT;
            }
            next_offset = input_offset + (size_t)UNP.csize;
            if (next_offset == map->len) {
                base = NULL;
            } else if (!(base = fmap_need_off_once(map, next_offset, 1))) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 next member could not be read");
                return CL_EREAD;
            }
            ret = cli_scan_reserve_temporary(ctx, UNP.csize);
            if (ret != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 stored member exceeds temporary storage limits");
                return ret;
            }
            stream_reserved = UNP.csize;
            ret = autoit_checktimelimit(ctx, "AutoIt EA06 stored member temporary admission reached the configured time limit");
            if (ret != CL_SUCCESS)
                return autoit_release_temp_member(ctx, &stream_tempfd, &stream_tempfile,
                                                  &stream_reserved, ret);
            ret = cli_gentempfd_with_prefix(ctx->this_layer_tmpdir, "autoit", &stream_tempfile, &stream_tempfd);
            if (ret != CL_SUCCESS) {
                cli_scan_release_temporary(ctx, stream_reserved);
                stream_reserved = 0;
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 stored member temporary output could not be created");
                return ret;
            }
            stream_output = true;
            LAME_srand(&input_lame, 0x2477 /* + m4sum (broken by design) */);
            while (input_offset < next_offset) {
                size_t chunk = MIN(next_offset - input_offset, sizeof(stored_buffer));
                size_t j;

                if (autoit_checktimelimit(ctx, "AutoIt EA06 stored member traversal reached the configured time limit") != CL_SUCCESS) {
                    stream_output = false;
                    return autoit_release_temp_member(ctx, &stream_tempfd, &stream_tempfile,
                                                      &stream_reserved, CL_ETIMEOUT);
                }
                if (fmap_readn(map, stored_buffer, input_offset, chunk) != chunk) {
                    cli_mark_scan_incomplete(ctx, "AutoIt EA06 stored member could not be read completely");
                    stream_output = false;
                    return autoit_release_temp_member(ctx, &stream_tempfd, &stream_tempfile,
                                                      &stream_reserved, CL_EREAD);
                }
                for (j = 0; j < chunk; j++)
                    stored_buffer[j] ^= LAME_getnext(&input_lame);
                if (autoit_checktimelimit(ctx, "AutoIt EA06 stored member output reached the configured time limit") != CL_SUCCESS) {
                    stream_output = false;
                    return autoit_release_temp_member(ctx, &stream_tempfd, &stream_tempfile,
                                                      &stream_reserved, CL_ETIMEOUT);
                }
                if (cli_writen(stream_tempfd, stored_buffer, chunk) != chunk) {
                    cli_mark_scan_incomplete(ctx, "AutoIt EA06 stored member temporary output could not be written completely");
                    stream_output = false;
                    return autoit_release_temp_member(ctx, &stream_tempfd, &stream_tempfile,
                                                      &stream_reserved, CL_EWRITE);
                }
                input_offset += chunk;
            }
            UNP.usize = UNP.csize;
        }

        if (stream_output && !script) {
            ret = autoit_scan_temp_member(ctx, &stream_tempfd, &stream_tempfile, &stream_reserved);
            stream_output = false;
            if (ret != CL_SUCCESS)
                return ret;
            continue;
        }

        if (script && UNP.usize < 4) {
            cli_dbgmsg("autoit: script is too short\n");
            cli_mark_scan_incomplete(ctx, "AutoIt EA06 script is shorter than its token header");
            stream_output = false;
            return autoit_release_temp_member(ctx, &stream_tempfd, &stream_tempfile,
                                              &stream_reserved, CL_EFORMAT);
        }

        if (script) {
            /* Decode tokens from the file-backed input into a second bounded
             * spool. Only the 64 KiB pending window is resident; every flush
             * is admitted against the shared file, scan, temporary, and time
             * limits before the output is handed to nested scanning. */
            ret = cli_gentempfd_with_prefix(tmpd, "autoit-script", &script_tempfile, &script_tempfd);
            if (ret != CL_SUCCESS) {
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 script output temporary file could not be created");
                stream_output = false;
                return autoit_script_abort(ctx, &script_output,
                                           &script_tempfd, &script_tempfile,
                                           &stream_tempfd, &stream_tempfile,
                                           &stream_reserved, ret);
            }
            ret = autoit_script_output_init(&script_output, ctx, script_tempfd);
            if (ret != CL_SUCCESS)
                return autoit_script_abort(ctx, &script_output,
                                           &script_tempfd, &script_tempfile,
                                           &stream_tempfd, &stream_tempfile,
                                           &stream_reserved, ret);

            UNP.cur_input = 4;
            UNP.error     = 0;

            if (!autoit_script_read(ctx, stream_tempfd, 0, b, sizeof(uint32_t),
                                    "AutoIt EA06 script token header could not be read completely")) {
                return autoit_script_abort(ctx, &script_output,
                                           &script_tempfd, &script_tempfile,
                                           &stream_tempfd, &stream_tempfile,
                                           &stream_reserved,
                                           ctx->scan_timed_out ? CL_ETIMEOUT : CL_EREAD);
            }
            UNP.bits_avail = cli_readint32((char *)b);

            cli_dbgmsg("autoit: script has got %u lines\n", UNP.bits_avail);

#define AUTOIT_SCRIPT_WRITE_OR_ABORT(expression_)                                      \
    do {                                                                                \
        ret = (expression_);                                                            \
        if (ret != CL_SUCCESS)                                                          \
            return autoit_script_abort(ctx, &script_output,                             \
                                       &script_tempfd, &script_tempfile,                 \
                                       &stream_tempfd, &stream_tempfile,                 \
                                       &stream_reserved, ret);                           \
    } while (0)

            while (!UNP.error && UNP.bits_avail && UNP.cur_input < UNP.usize) {
                uint8_t op;

                ret = autoit_checktimelimit(ctx, "AutoIt EA06 script traversal reached the configured time limit");
                if (ret != CL_SUCCESS) {
                    UNP.error = 1;
                    break;
                }

                if (!autoit_script_read(ctx, stream_tempfd, UNP.cur_input, &op, sizeof(op),
                                        "AutoIt EA06 script opcode could not be read completely")) {
                    UNP.error = 1;
                    break;
                }
                UNP.cur_input++;

                switch (op) {
                    case 0: /* keyword ID */ {
                        uint32_t keyword_id;
                        uint32_t keyword_len;
                        uint8_t value[sizeof(uint32_t)];
                        if (UNP.cur_input > UNP.usize || 4 > UNP.usize - UNP.cur_input) {
                            UNP.error = 1;
                            cli_dbgmsg("autoit: too few bytes present - expected enough for a keyword ID\n");
                            break;
                        }

                        if (!autoit_script_read(ctx, stream_tempfd, UNP.cur_input, value, sizeof(value),
                                                "AutoIt EA06 keyword ID could not be read completely")) {
                            UNP.error = 1;
                            break;
                        }
                        keyword_id = cli_readint32((char *)value);
                        if (keyword_id >= (sizeof(autoit_keywords) / sizeof(autoit_keywords[0]))) {
                            UNP.error = 1;
                            cli_dbgmsg("autoit: unknown AutoIT keyword ID: 0x%x\n", keyword_id);
                            break;
                        }

                        UNP.cur_input += 4;

                        keyword_len = strlen(autoit_keywords[keyword_id]);

                        if (cli_debug_flag) {
                            if (0 == memcmp(autoit_keywords[keyword_id], "UNKNOWN", MIN(strlen("UNKNOWN"), keyword_len))) {
                                cli_dbgmsg("autoit: encountered use of unknown keyword ID: %s\n", autoit_keywords[keyword_id]);
                            }
                        }

                        AUTOIT_SCRIPT_WRITE_OR_ABORT(
                            autoit_script_output_token(&script_output, autoit_keywords[keyword_id], keyword_len));
                        break;
                    }
                    case 1: /* function ID */ {
                        uint32_t function_id;
                        uint32_t function_len;
                        uint8_t value[sizeof(uint32_t)];
                        if (UNP.cur_input > UNP.usize || 4 > UNP.usize - UNP.cur_input) {
                            UNP.error = 1;
                            cli_dbgmsg("autoit: too few bytes present - expected enough for a function ID\n");
                            break;
                        }

                        if (!autoit_script_read(ctx, stream_tempfd, UNP.cur_input, value, sizeof(value),
                                                "AutoIt EA06 function ID could not be read completely")) {
                            UNP.error = 1;
                            break;
                        }
                        function_id = cli_readint32((char *)value);
                        if (function_id >= (sizeof(autoit_functions) / sizeof(autoit_functions[0]))) {
                            UNP.error = 1;
                            cli_dbgmsg("autoit: unknown AutoIT function ID: 0x%x\n", function_id);
                            break;
                        }

                        UNP.cur_input += 4;

                        function_len = strlen(autoit_functions[function_id]);

                        if (cli_debug_flag) {
                            if (0 == memcmp(autoit_functions[function_id], "UNKNOWN", MIN(strlen("UNKNOWN"), function_len))) {
                                cli_dbgmsg("autoit: encountered use of unknown function ID: %s\n", autoit_functions[function_id]);
                            }
                        }

                        AUTOIT_SCRIPT_WRITE_OR_ABORT(
                            autoit_script_output_token(&script_output, autoit_functions[function_id], function_len));
                        break;
                    }
                    case 5: /* <INT> */
                        if (UNP.cur_input > UNP.usize || 4 > UNP.usize - UNP.cur_input) {
                            UNP.error = 1;
                            cli_dbgmsg("autoit: not enough space for an int\n");
                            break;
                        }

                        {
                            char formatted[12];
                            int formatted_len;
                            uint8_t value[sizeof(uint32_t)];

                            if (!autoit_script_read(ctx, stream_tempfd, UNP.cur_input, value, sizeof(value),
                                                    "AutoIt EA06 integer token could not be read completely")) {
                                UNP.error = 1;
                                break;
                            }
                            formatted_len = snprintf(formatted, sizeof(formatted), "0x%08x ", cli_readint32((char *)value));
                            if (formatted_len < 0 || (size_t)formatted_len >= sizeof(formatted)) {
                                UNP.error = 1;
                                break;
                            }
                            AUTOIT_SCRIPT_WRITE_OR_ABORT(
                                autoit_script_output_append(&script_output, formatted, (size_t)formatted_len));
                        }
                        UNP.cur_input += 4;
                        break;

                    case 0x10: /* <INT64> */
                    {
                        char formatted[20];
                        int formatted_len;
                        uint64_t val;
                        if (UNP.cur_input > UNP.usize || 8 > UNP.usize - UNP.cur_input) {
                            UNP.error = 1;
                            cli_dbgmsg("autoit: not enough space for an int64\n");
                            break;
                        }

                        {
                            uint8_t value[sizeof(uint64_t)];
                            if (!autoit_script_read(ctx, stream_tempfd, UNP.cur_input, value, sizeof(value),
                                                    "AutoIt EA06 integer64 token could not be read completely")) {
                                UNP.error = 1;
                                break;
                            }
                            val = (uint64_t)cli_readint32((char *)&value[4]);
                            val <<= 32;
                            val += (uint64_t)cli_readint32((char *)value);
                        }
                        formatted_len = snprintf(formatted, sizeof(formatted), "0x%016lx ", (unsigned long int)val);
                        if (formatted_len < 0 || (size_t)formatted_len >= sizeof(formatted)) {
                            UNP.error = 1;
                            break;
                        }
                        AUTOIT_SCRIPT_WRITE_OR_ABORT(
                            autoit_script_output_append(&script_output, formatted, (size_t)formatted_len));
                        UNP.cur_input += 8;
                        break;
                    }

                    case 0x20: /* <DOUBLE> */
                        if (UNP.cur_input > UNP.usize || 8 > UNP.usize - UNP.cur_input) {
                            UNP.error = 1;
                            cli_dbgmsg("autoit: not enough space for a double\n");
                            break;
                        }

                        {
                            char formatted[40];
                            uint8_t value[sizeof(double)];
                            double x;
                            uint8_t *j = (uint8_t *)&x;
                            unsigned int k;
                            int formatted_len;

                            if (!autoit_script_read(ctx, stream_tempfd, UNP.cur_input, value, sizeof(value),
                                                    "AutoIt EA06 double token could not be read completely")) {
                                UNP.error = 1;
                                break;
                            }
                            if (fpu_words == FPU_ENDIAN_LITTLE) {
                                memcpy(&x, value, sizeof(x));
                            } else {
                                for (k = 0; k < sizeof(value); k++)
                                    j[7 - k] = value[k];
                            }

                            formatted_len = snprintf(formatted, sizeof(formatted), "%g ", x);
                            if (formatted_len < 0 || (size_t)formatted_len >= sizeof(formatted)) {
                                UNP.error = 1;
                                break;
                            }
                            AUTOIT_SCRIPT_WRITE_OR_ABORT(
                                autoit_script_output_append(&script_output, formatted, (size_t)formatted_len));
                        }
                        UNP.cur_input += 8;
                        break;

                    case 0x30: /* COSTRUCT */
                    case 0x31: /* COMMAND */
                    case 0x32: /* MACRO */
                    case 0x33: /* VAR */
                    case 0x34: /* FUNC */
                    case 0x35: /* OBJECT */
                    case 0x36: /* STRING */
                    case 0x37: /* DIRECTIVE */
                    {
                        uint32_t chars, dchars, i;
                        uint8_t value[sizeof(uint32_t)];
                        uint8_t probe[20];
                        uint8_t input_chunk[AUTOIT_INPUT_CHUNK];
                        size_t probe_len;
                        size_t sample_len;
                        size_t j;
                        size_t chunk;
                        bool utf16;
                        bool bom;
                        size_t input_at;
                        size_t converted_chars;
                        size_t count;
                        size_t unicode_count;

                        if (UNP.cur_input > UNP.usize || 4 > UNP.usize - UNP.cur_input) {
                            UNP.error = 1;
                            cli_dbgmsg("autoit: not enough space for size\n");
                            break;
                        }

                        if (!autoit_script_read(ctx, stream_tempfd, UNP.cur_input, value, sizeof(value),
                                                "AutoIt EA06 string length could not be read completely")) {
                            UNP.error = 1;
                            break;
                        }
                        chars = cli_readint32((char *)value);
                        if (chars > UINT32_MAX / 2) {
                            UNP.error = 1;
                            cli_dbgmsg("autoit: character count overflow\n");
                            break;
                        }
                        dchars = chars * 2;
                        UNP.cur_input += 4;

                        if (UNP.cur_input > UNP.usize || dchars > UNP.usize - UNP.cur_input) {
                            UNP.error = 1;
                            cli_dbgmsg("autoit: size too big - needed %d, total %d, avail %d\n", dchars, UNP.usize, UNP.usize - UNP.cur_input);
                            break;
                        }

                        if (prefixes[op - 0x30])
                            AUTOIT_SCRIPT_WRITE_OR_ABORT(
                                autoit_script_output_byte(&script_output, prefixes[op - 0x30]));

                        if (chars) {
                            probe_len = MIN((size_t)dchars, sizeof(probe));
                            if (!autoit_script_read(ctx, stream_tempfd, UNP.cur_input, probe, probe_len,
                                                    "AutoIt EA06 string data could not be read completely")) {
                                UNP.error = 1;
                                break;
                            }
                            for (i = 0; i < probe_len; i++)
                                probe[i] ^= (i & 1) ? (uint8_t)(chars >> 8) : (uint8_t)chars;

                            utf16 = false;
                            bom   = false;
                            if (dchars > 4 && probe_len >= 3 && probe[0] == 0xff && probe[1] == 0xfe && probe[2]) {
                                utf16 = true;
                                bom   = true;
                            } else {
                                sample_len = MIN((size_t)20, (size_t)(dchars & ~1U));
                                unicode_count = 0;
                                for (i = 0; i < sample_len; i += 2) {
                                    if (probe[i] != 0 && probe[i + 1] == 0)
                                        unicode_count++;
                                }
                                utf16 = (unicode_count * 4 >= sample_len);
                            }

                            converted_chars = chars - (bom ? 1 : 0);
                            input_at        = UNP.cur_input;
                            if (utf16) {
                                for (i = 0; i < converted_chars;) {
                                    count = MIN((size_t)(converted_chars - i), sizeof(input_chunk) / 2);
                                    if (bom)
                                        input_at = (size_t)UNP.cur_input + 2 + (size_t)i * 2;
                                    else
                                        input_at = (size_t)UNP.cur_input + (size_t)i * 2;
                                    if (!autoit_script_read(ctx, stream_tempfd, (uint32_t)input_at, input_chunk, count * 2,
                                                            "AutoIt EA06 UTF-16 string data could not be read completely")) {
                                        UNP.error = 1;
                                        break;
                                    }
                                    for (j = 0; j < count; j++)
                                        input_chunk[j] = input_chunk[j * 2] ^ (uint8_t)chars;
                                    AUTOIT_SCRIPT_WRITE_OR_ABORT(
                                        autoit_script_output_append(&script_output, input_chunk, count));
                                    i += (uint32_t)count;
                                }
                            } else {
                                for (i = 0; i < chars;) {
                                    chunk = MIN((size_t)(chars - i), sizeof(input_chunk));
                                    if (!autoit_script_read(ctx, stream_tempfd, (uint32_t)(input_at + i), input_chunk, chunk,
                                                            "AutoIt EA06 string data could not be read completely")) {
                                        UNP.error = 1;
                                        break;
                                    }
                                    for (j = 0; j < chunk; j++)
                                        input_chunk[j] ^= ((i + j) & 1) ? (uint8_t)(chars >> 8) : (uint8_t)chars;
                                    AUTOIT_SCRIPT_WRITE_OR_ABORT(
                                        autoit_script_output_append(&script_output, input_chunk, chunk));
                                    i += (uint32_t)chunk;
                                }
                            }
                            UNP.cur_input += dchars;
                        }

                        if (op == 0x36) {
                            // TODO: Mask possible double quotes inside the string: >Say:"Hi "<  ==> >"Say:""Hi"" "<
                            AUTOIT_SCRIPT_WRITE_OR_ABORT(
                                autoit_script_output_byte(&script_output, '"'));
                        }
                        if (op != 0x34)
                            AUTOIT_SCRIPT_WRITE_OR_ABORT(
                                autoit_script_output_byte(&script_output, ' '));
                    } break;

                    case 0x40: /* , */
                    case 0x41: /* = */
                    case 0x42: /* > */
                    case 0x43: /* < */
                    case 0x44: /* <> */
                    case 0x45: /* >= */
                    case 0x46: /* <= */
                    case 0x47: /* ( */
                    case 0x48: /* ) */
                    case 0x49: /* + */
                    case 0x4a: /* - */
                    case 0x4b: /* / */
                    case 0x4c: /* * */
                    case 0x4d: /* & */
                    case 0x4e: /* [ */
                    case 0x4f: /* ] */
                    case 0x50: /* == */
                    case 0x51: /* ^ */
                    case 0x52: /* += */
                    case 0x53: /* -= */
                    case 0x54: /* /= */
                    case 0x55: /* *= */
                    case 0x56: /* &= */
                    case 0x57: /* ? */
                    case 0x58: /* : */
                        // TODO: Fix Autoit plus bug
                        //  if (op == 0x49) /* + */ and next op ==0x05 /*int32*/ and that int32 is negative...
                        //  skip next line (and don't add "+")
                        //  Background: "$a= (-4)" gets incorrect compiled. Decompiled it will be get "$A= (+ -4)"
                        //  That doesn't effects the interpreter however when recompiling decompiled output that will result in a syntax error

                        AUTOIT_SCRIPT_WRITE_OR_ABORT(
                            autoit_script_output_token(&script_output, opers[op - 0x40], strlen(opers[op - 0x40])));
                        break;

                    case 0x7f:
                        UNP.bits_avail--;
                        AUTOIT_SCRIPT_WRITE_OR_ABORT(
                            autoit_script_output_byte(&script_output, '\n'));
                        break;

                    default:
                        cli_dbgmsg("autoit: found unknown op (0x%x)\n", op);
                        UNP.error = 1;
                }
            }

#undef AUTOIT_SCRIPT_WRITE_OR_ABORT

            if (UNP.bits_avail != 0)
                UNP.error = 1;

            if (UNP.error) {
                cli_dbgmsg("autoit: decompilation aborted - partial script may exist\n");
                if (ctx->scan_timed_out)
                    return autoit_script_abort(ctx, &script_output,
                                               &script_tempfd, &script_tempfile,
                                               &stream_tempfd, &stream_tempfile,
                                               &stream_reserved, CL_ETIMEOUT);
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 script decompilation was incomplete");
                return autoit_script_abort(ctx, &script_output,
                                           &script_tempfd, &script_tempfile,
                                           &stream_tempfd, &stream_tempfile,
                                           &stream_reserved, CL_EFORMAT);
            }

            ret = autoit_script_output_flush(&script_output);
            if (ret != CL_SUCCESS)
                return autoit_script_abort(ctx, &script_output,
                                           &script_tempfd, &script_tempfile,
                                           &stream_tempfd, &stream_tempfile,
                                           &stream_reserved, ret);
            autoit_script_output_destroy(&script_output);

            ret = autoit_release_temp_member(ctx, &stream_tempfd, &stream_tempfile,
                                             &stream_reserved, CL_SUCCESS);
            stream_output = false;
            if (ret != CL_SUCCESS)
                return autoit_release_temp_member(ctx, &script_tempfd, &script_tempfile,
                                                  &script_output.temporary_reserved, ret);

            cli_dbgmsg("autoit: decompiled script output is " STDu64 " bytes\n", script_output.total);
            if (ctx->engine->keeptmp)
                cli_dbgmsg("autoit: script extracted to %s\n", script_tempfile);

            ret = autoit_scan_temp_member(ctx, &script_tempfd, &script_tempfile,
                                          &script_output.temporary_reserved);
            if (ret != CL_SUCCESS)
                return ret;
            continue;
        } else {
            cli_mark_scan_incomplete(ctx, "AutoIt EA06 non-script member was not written to a temporary spool");
            return CL_EFORMAT;
        }
    }
    if (ret != CL_SUCCESS)
        cli_mark_scan_incomplete(ctx, "AutoIt EA06 extraction stopped at a configured limit");
    return ret;
}

/*********************
   autoit3 wrapper
*********************/

cl_error_t cli_scanautoit(cli_ctx *ctx, off_t offset)
{
    cl_error_t status = CL_SUCCESS;
    const uint8_t *version;
    char *tmpd;
    fmap_t *map;

    cli_dbgmsg("in scanautoit()\n");

    if (!ctx)
        return CL_ENULLARG;
    if (!ctx->fmap) {
        cli_mark_scan_incomplete(ctx, "AutoIt input map is unavailable");
        return CL_EPARSE;
    }
    if (autoit_checktimelimit(ctx, "AutoIt inspection reached the configured time limit") != CL_SUCCESS)
        return CL_ETIMEOUT;

    map = ctx->fmap;

    if (offset < 0 || (uint64_t)offset > SIZE_MAX || (size_t)offset >= map->len) {
        cli_mark_scan_incomplete(ctx, "AutoIt layer offset is outside the input map");
        return CL_EREAD;
    }
    if (!(version = fmap_need_off_once(map, offset, sizeof(*version)))) {
        cli_mark_scan_incomplete(ctx, "AutoIt version byte could not be read completely");
        return CL_EREAD;
    }

    if (!(tmpd = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "autoit-tmp"))) {
        cli_mark_scan_incomplete(ctx, "AutoIt temporary directory could not be created");
        return CL_ETMPDIR;
    }
    if (mkdir(tmpd, 0700)) {
        cli_dbgmsg("autoit: Can't create temporary directory %s\n", tmpd);
        cli_mark_scan_incomplete(ctx, "AutoIt temporary directory could not be created");
        free(tmpd);
        return CL_ETMPDIR;
    }
    if (ctx->engine->keeptmp)
        cli_dbgmsg("autoit: Extracting files to %s\n", tmpd);

    switch (*version) {
        case 0x35:
            status = ea05(ctx, version + 1);
            break;
        case 0x36:
            if (fpu_words == FPU_ENDIAN_INITME)
                fpu_words = get_fpu_endian();
            if (fpu_words == FPU_ENDIAN_UNKNOWN) {
                cli_dbgmsg("autoit: EA06 support not available"
                           "(cannot extract ea06 doubles, unknown floating double representation).\n");
                cli_mark_scan_incomplete(ctx, "AutoIt EA06 parser is unavailable for this floating-point representation");
                status = CL_EFORMAT;
            } else
                status = ea06(ctx, version + 1, tmpd);
            break;
        default:
            /* NOT REACHED */
            cli_dbgmsg("autoit: unknown method\n");
            cli_mark_scan_incomplete(ctx, "AutoIt compression method is unsupported");
            status = CL_EFORMAT;
    }

    if (!ctx->engine->keeptmp && cli_rmdirs(tmpd) != 0) {
        cli_mark_scan_incomplete(ctx, "AutoIt temporary directory could not be removed");
        if (status == CL_SUCCESS || status == CL_CLEAN || status == CL_BREAK)
            status = CL_EUNLINK;
    }

    free(tmpd);
    return status;
}
