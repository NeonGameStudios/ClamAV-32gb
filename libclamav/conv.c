/*
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
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

#if defined(HAVE_CONF_H) && HAVE_CONF_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <math.h>

#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

// libclamav
#include "clamav.h"
#include "conv.h"
#include "others.h"

/** Get the expected decoded length of a base64-encoded string.
 *
 * The OpenSSL memory BIO used by cl_base64_decode() accepts an int length,
 * and the decoded buffer is subject to the individual allocation ceiling.
 * Reject oversized inputs before inspecting data or forming 3 * len.
 */
static int base64_len(const char *data, size_t len, size_t *decoded_len)
{
    size_t padding = 0;
    size_t i;

    if (!decoded_len || (len != 0 && data == NULL) || len > (size_t)INT_MAX ||
        len > (size_t)CLI_MAX_ALLOCATION || len > (size_t)-1 / 3)
        return 0;

    if (!len) {
        *decoded_len = 0;
        return 1;
    }

    for (i = len - 1; i > 0 && data[i] == '='; i--)
        padding++;

    *decoded_len = (3 * len) / 4;
    if (padding > *decoded_len)
        return 0;
    *decoded_len -= padding;
    return 1;
}

/** Get a conservative encoded length for the OpenSSL Base64 BIO. */
static int base64_encoded_len(size_t len, size_t *encoded_len)
{
    size_t groups;
    size_t encoded_chars;
    size_t line_breaks;

    if (encoded_len == NULL || len > (size_t)INT_MAX)
        return 0;
    if (len == 0) {
        *encoded_len = 0;
        return 1;
    }
    if (len > SIZE_MAX - 2)
        return 0;
    groups = (len + 2) / 3;
    if (groups > SIZE_MAX / 4)
        return 0;
    encoded_chars = groups * 4;
    if (encoded_chars > SIZE_MAX - 2)
        return 0;
    /* The default BIO emits line breaks and a final newline. Keep two extra
     * bytes of slack beyond the complete 64-character line count. */
    line_breaks = encoded_chars / 64 + 2;
    if (encoded_chars > SIZE_MAX - line_breaks)
        return 0;
    *encoded_len = encoded_chars + line_breaks;
    return *encoded_len < (size_t)CLI_MAX_ALLOCATION;
}

/** Decode a base64-encoded string
 * @param[in] data The base64-encoded string
 * @param[in] len Length of the base64-encoded string
 * @param[out] obuf If obuf is not set to NULL, store the decoded data in obuf. Otherwise, the decoded data is stored in a dynamically-allocated buffer.
 * @param[out] olen The length of the decoded data
 * @return The base64-decoded data
 */
void *cl_base64_decode(char *data, size_t len, void *obuf, size_t *olen, int oneline)
{
    BIO *bio, *b64;
    void *buf;
    size_t decoded_len;
    int read_len;

    if (!olen || !base64_len(data, len, &decoded_len))
        return NULL;
    if (len > (size_t)INT_MAX)
        return NULL;

    buf = (obuf) ? obuf : cli_max_malloc(decoded_len + 1);
    if (!(buf))
        return NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!(b64)) {
        if (!(obuf))
            free(buf);

        return NULL;
    }

    bio = BIO_new_mem_buf(data, (int)len);
    if (!(bio)) {
        BIO_free(b64);
        if (!(obuf))
            free(buf);

        return NULL;
    }

    bio = BIO_push(b64, bio);
    if (oneline)
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    read_len = BIO_read(bio, buf, (int)decoded_len);
    if (read_len < 0) {
        if (!obuf)
            free(buf);
        BIO_free_all(bio);
        return NULL;
    }
    *olen = (size_t)read_len;

    BIO_free_all(bio);

    return buf;
}

/** Base64-encode data
 * @param[in] data The data to be encoded
 * @param[in] len The length of the data
 * @return A pointer to the base64-encoded data. The data is stored in a dynamically-allocated buffer.
 */
char *cl_base64_encode(void *data, size_t len)
{
    BIO *bio, *b64;
    char *buf, *p;
    long bio_len;
    int written;
    size_t elen;

    if (len != 0 && data == NULL)
        return NULL;
    if (!base64_encoded_len(len, &elen))
        return NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!(b64))
        return NULL;
    bio = BIO_new(BIO_s_mem());
    if (!(bio)) {
        BIO_free(b64);
        return NULL;
    }

    bio = BIO_push(b64, bio);
    written = BIO_write(bio, data, (int)len);
    if (written != (int)len) {
        BIO_free_all(bio);
        return NULL;
    }

    if (BIO_flush(bio) != 1) {
        BIO_free_all(bio);
        return NULL;
    }
    bio_len = BIO_get_mem_data(bio, &buf);
    if (bio_len < 0 || (uint64_t)bio_len > SIZE_MAX) {
        BIO_free_all(bio);
        return NULL;
    }
    elen = (size_t)bio_len;
    if (elen >= (size_t)CLI_MAX_ALLOCATION) {
        BIO_free_all(bio);
        return NULL;
    }

    /* Ensure we're dealing with a NULL-terminated string */
    p = (char *)cli_max_malloc(elen + 1);
    if (NULL == p) {
        BIO_free_all(bio);
        return NULL;
    }
    if (elen != 0)
        memcpy((void *)p, (void *)buf, elen);
    p[elen] = 0x00;
    buf     = p;

    BIO_free_all(bio);

    return buf;
}

#if defined(CONV_SELF_TEST)

int main(int argc, char *argv[])
{
    char *plaintext, *encoded, *decoded;
    unsigned char *sha_plaintext, *sha_decoded;
    size_t len;
    int ret = 0;
    unsigned int shalen;

    initialize_crypto();

    plaintext     = (argv[1]) ? argv[1] : "Hello. This is dog";
    sha_plaintext = sha256(plaintext, strlen(plaintext), NULL, NULL);
    if (!(sha_plaintext)) {
        fprintf(stderr, "Could not generate sha256 of plaintext\n");
        return 1;
    }

    encoded = base64_encode(plaintext, strlen(plaintext));
    if (!(encoded)) {
        fprintf(stderr, "Could not base64 encode plaintest\n");
        return 1;
    }
    fprintf(stderr, "Base64 encoded: %s\n", encoded);

    decoded = base64_decode(encoded, strlen(encoded), NULL, &len);
    if (!(decoded)) {
        fprintf(stderr, "Could not base64 decoded string\n");
        return 1;
    }

    sha_decoded = sha256(decoded, len, NULL, &shalen);
    if (!(sha_decoded)) {
        fprintf(stderr, "Could not generate sha256 of decoded data\n");
        return 1;
    }

    if (memcmp(sha_plaintext, sha_decoded, shalen)) {
        fprintf(stderr, "Decoded does not match plaintext: %s\n", decoded);
        ret = 1;
    }

    free(sha_decoded);
    free(sha_plaintext);
    free(encoded);
    free(decoded);

    cleanup_crypto();

    return ret;
}

#endif
