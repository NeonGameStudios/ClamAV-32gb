/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
 *
 *  Summary: Hash-table and -set data structures.
 *
 *  Acknowledgements: hash32shift() is an implementation of Thomas Wang's
 * 	                  32-bit integer hash function:
 * 	                  http://www.cris.com/~Ttwang/tech/inthash.htm
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "clamav.h"
#include "clamav-config.h"
#include "others.h"
#include "hashtab.h"

#define MODULE_NAME "hashtab: "

static const char DELETED_KEY[] = "";
#define DELETED_HTU32_KEY ((uint32_t)(-1))

static cl_error_t nearest_power(size_t num, size_t *power)
{
    size_t n = 64;

    if (!power)
        return CL_ENULLARG;

    while (n < num) {
        if (n > SIZE_MAX / 2)
            return CL_ERESOURCE;
        n *= 2;
    }

    *power = n;
    return CL_SUCCESS;
}

cl_error_t cli_hashtab_table_size(size_t count, size_t element_size, size_t *bytes)
{
    if (!bytes || !element_size)
        return CL_EARG;

    if (count > SIZE_MAX / element_size || count > CLI_MAX_ALLOCATION / element_size)
        return CL_ERESOURCE;

    *bytes = count * element_size;
    return CL_SUCCESS;
}

static cl_error_t cli_hashtab_capacity(size_t requested, size_t element_size, size_t *capacity)
{
    cl_error_t ret;
    size_t rounded;
    size_t table_size;

    if (!capacity || !element_size)
        return CL_EARG;

    ret = nearest_power(requested, &rounded);
    if (ret != CL_SUCCESS)
        return ret;

    ret = cli_hashtab_table_size(rounded, element_size, &table_size);
    if (ret != CL_SUCCESS)
        return ret;

    *capacity = rounded;
    return CL_SUCCESS;
}

#ifdef PROFILE_HASHTABLE
/* I know, this is ugly, most of these functions get a const s, that gets its const-ness discarded,
 * and then these functions modify something the compiler assumes is readonly.
 * Please, never use PROFILE_HASHTABLE in production code, and in releases. Use it for development only!*/

static inline void PROFILE_INIT(struct cli_hashtable *s)
{
    memset(&s->PROFILE_STRUCT, 0, sizeof(s->PROFILE_STRUCT));
}

static inline void PROFILE_CALC_HASH(struct cli_hashtable *s)
{
    s->PROFILE_STRUCT.calc_hash++;
}

static inline void PROFILE_FIND_ELEMENT(struct cli_hashtable *s)
{
    s->PROFILE_STRUCT.find_req++;
}

static inline void PROFILE_FIND_NOTFOUND(struct cli_hashtable *s, size_t tries)
{
    s->PROFILE_STRUCT.not_found++;
    s->PROFILE_STRUCT.not_found_tries += tries;
}

static inline void PROFILE_FIND_FOUND(struct cli_hashtable *s, size_t tries)
{
    s->PROFILE_STRUCT.found++;
    s->PROFILE_STRUCT.found_tries += tries;
}

static inline void PROFILE_HASH_EXHAUSTED(struct cli_hashtable *s)
{
    s->PROFILE_STRUCT.hash_exhausted++;
}

static inline void PROFILE_GROW_START(struct cli_hashtable *s)
{
    s->PROFILE_STRUCT.grow++;
}

static inline void PROFILE_GROW_FOUND(struct cli_hashtable *s, size_t tries)
{
    s->PROFILE_STRUCT.grow_found++;
    s->PROFILE_STRUCT.grow_found_tries += tries;
}

static inline void PROFILE_GROW_DONE(struct cli_hashtable *s)
{
}

static inline void PROFILE_DELETED_REUSE(struct cli_hashtable *s, size_t tries)
{
    s->PROFILE_STRUCT.deleted_reuse++;
    s->PROFILE_STRUCT.deleted_tries += tries;
}

static inline void PROFILE_INSERT(struct cli_hashtable *s, size_t tries)
{
    s->PROFILE_STRUCT.inserts++;
    s->PROFILE_STRUCT.insert_tries += tries;
}

static inline void PROFILE_DATA_UPDATE(struct cli_hashtable *s, size_t tries)
{
    s->PROFILE_STRUCT.update++;
    s->PROFILE_STRUCT.update_tries += tries;
}

static inline void PROFILE_HASH_DELETE(struct cli_hashtable *s)
{
    s->PROFILE_STRUCT.deletes++;
}

static inline void PROFILE_HASH_CLEAR(struct cli_hashtable *s)
{
    s->PROFILE_STRUCT.clear++;
}

static inline void PROFILE_REPORT(const struct cli_hashtable *s)
{
    size_t lookups, queries, insert_tries, inserts;
    cli_dbgmsg("--------Hashtable usage report for %p--------------\n", (const void *)s);
    cli_dbgmsg("hash function calculations:%ld\n", s->PROFILE_STRUCT.calc_hash);
    cli_dbgmsg("successful finds/total searches: %ld/%ld; lookups: %ld\n", s->PROFILE_STRUCT.found, s->PROFILE_STRUCT.find_req, s->PROFILE_STRUCT.found_tries);
    cli_dbgmsg("unsuccessful finds/total searches: %ld/%ld; lookups: %ld\n", s->PROFILE_STRUCT.not_found, s->PROFILE_STRUCT.find_req, s->PROFILE_STRUCT.not_found_tries);
    cli_dbgmsg("successful finds during grow:%ld; lookups: %ld\n", s->PROFILE_STRUCT.grow_found, s->PROFILE_STRUCT.grow_found_tries);
    lookups = s->PROFILE_STRUCT.found_tries + s->PROFILE_STRUCT.not_found_tries + s->PROFILE_STRUCT.grow_found_tries;
    queries = s->PROFILE_STRUCT.find_req + s->PROFILE_STRUCT.grow_found;
    cli_dbgmsg("Find Lookups/total queries: %ld/%ld = %3f\n", lookups, queries, lookups * 1.0 / queries);
    insert_tries = s->PROFILE_STRUCT.insert_tries + s->PROFILE_STRUCT.update_tries + s->PROFILE_STRUCT.deleted_tries;

    cli_dbgmsg("new item insert tries/new items: %ld/%ld\n", s->PROFILE_STRUCT.insert_tries, s->PROFILE_STRUCT.inserts);
    cli_dbgmsg("update tries/updates: %ld/%ld\n", s->PROFILE_STRUCT.update_tries, s->PROFILE_STRUCT.update);
    cli_dbgmsg("deleted item reuse tries/deleted&reused items: %ld/%ld\n", s->PROFILE_STRUCT.deleted_tries, s->PROFILE_STRUCT.deleted_reuse);
    inserts = s->PROFILE_STRUCT.inserts + s->PROFILE_STRUCT.update + s->PROFILE_STRUCT.deleted_reuse;
    cli_dbgmsg("Insert tries/total inserts: %ld/%ld = %3f\n", insert_tries, inserts, insert_tries * 1.0 / inserts);

    cli_dbgmsg("Grows: %ld, Deletes : %ld, hashtable clears: %ld\n", s->PROFILE_STRUCT.grow, s->PROFILE_STRUCT.deletes, s->PROFILE_STRUCT.clear);
    cli_dbgmsg("--------Report end-------------\n");
}

#else
#define PROFILE_INIT(s)
#define PROFILE_CALC_HASH(s)
#define PROFILE_FIND_ELEMENT(s)
#define PROFILE_FIND_NOTFOUND(s, tries)
#define PROFILE_FIND_FOUND(s, tries)
#define PROFILE_HASH_EXHAUSTED(s)
#define PROFILE_GROW_START(s)
#define PROFILE_GROW_FOUND(s, tries)
#define PROFILE_GROW_DONE(s)
#define PROFILE_DELETED_REUSE(s, tries)
#define PROFILE_INSERT(s, tries)
#define PROFILE_DATA_UPDATE(s, tries)
#define PROFILE_HASH_CLEAR(s)
#define PROFILE_REPORT(s)
#endif

cl_error_t cli_hashtab_init(struct cli_hashtable *s, size_t capacity)
{
    cl_error_t ret;

    if (!s)
        return CL_ENULLARG;

    PROFILE_INIT(s);

    ret = cli_hashtab_capacity(capacity, sizeof(*s->htable), &capacity);
    if (ret != CL_SUCCESS)
        return ret;

    s->htable = cli_max_calloc(capacity, sizeof(*s->htable));
    if (!s->htable) {
        return CL_EMEM;
    }
    s->capacity = capacity;
    s->used     = 0;
    s->maxfill  = 8 * capacity / 10;
    return CL_SUCCESS;
}

cl_error_t cli_htu32_init(struct cli_htu32 *s, size_t capacity, mpool_t *mempool)
{
    cl_error_t ret;

#ifndef USE_MPOOL
    UNUSEDPARAM(mempool);
#endif

    if (!s)
        return CL_ENULLARG;

    PROFILE_INIT(s);

    ret = cli_hashtab_capacity(capacity, sizeof(*s->htable), &capacity);
    if (ret != CL_SUCCESS)
        return ret;

    s->htable = MPOOL_CALLOC(mempool, capacity, sizeof(*s->htable));
    if (!s->htable) {
        return CL_EMEM;
    }
    s->capacity = capacity;
    s->used     = 0;
    s->maxfill  = 8 * capacity / 10;
    return CL_SUCCESS;
}

static inline uint32_t hash32shift(uint32_t key)
{
    key = ~key + (key << 15);
    key = key ^ (key >> 12);
    key = key + (key << 2);
    key = key ^ (key >> 4);
    key = (key + (key << 3)) + (key << 11);
    key = key ^ (key >> 16);
    return key;
}

static inline size_t hash(const unsigned char *k, const size_t len, const size_t SIZE)
{
    uint32_t Hash = 1;
    size_t i;
    for (i = 0; i < len; i++) {
        /* a simple add is good, because we use the mixing function below */
        Hash += k[i];
        /* mixing function */
        Hash = hash32shift(Hash);
    }
    /* SIZE is power of 2 */
    return Hash & (SIZE - 1);
}

static inline size_t hash_htu32(uint32_t k, const size_t SIZE)
{
    /* mixing function */
    size_t Hash = hash32shift(k);
    /* SIZE is power of 2 */
    return Hash & (SIZE - 1);
}

/* if returned element has key==NULL, then key was not found in table */
struct cli_element *cli_hashtab_find(const struct cli_hashtable *s, const char *key, const size_t len)
{
    struct cli_element *element;
    size_t tries = 1;
    size_t idx;

    if (!s)
        return NULL;
    PROFILE_CALC_HASH(s);
    PROFILE_FIND_ELEMENT(s);
    idx     = hash((const unsigned char *)key, len, s->capacity);
    element = &s->htable[idx];
    do {
        if (!element->key) {
            PROFILE_FIND_NOTFOUND(s, tries);
            return NULL; /* element not found, place is empty*/
        } else if (element->key != DELETED_KEY && len == element->len && (key == element->key || strncmp(key, element->key, len) == 0)) {
            PROFILE_FIND_FOUND(s, tries);
            return element; /* found */
        } else {
            idx     = (idx + tries++) & (s->capacity - 1);
            element = &s->htable[idx];
        }
    } while (tries <= s->capacity);
    PROFILE_HASH_EXHAUSTED(s);
    return NULL; /* not found */
}

const struct cli_htu32_element *cli_htu32_find(const struct cli_htu32 *s, uint32_t key)
{
    struct cli_htu32_element *element;
    size_t tries = 1;
    size_t idx;

    if (!s)
        return NULL;
    PROFILE_CALC_HASH(s);
    PROFILE_FIND_ELEMENT(s);
    idx     = hash_htu32(key, s->capacity);
    element = &s->htable[idx];
    do {
        if (!element->key) {
            PROFILE_FIND_NOTFOUND(s, tries);
            return NULL; /* element not found, place is empty */
        } else if (key == element->key) {
            PROFILE_FIND_FOUND(s, tries);
            return element; /* found */
        } else {
            idx     = (idx + tries++) & (s->capacity - 1);
            element = &s->htable[idx];
        }
    } while (tries <= s->capacity);
    PROFILE_HASH_EXHAUSTED(s);
    return NULL; /* not found */
}

const struct cli_htu32_element *cli_htu32_next(const struct cli_htu32 *s, const struct cli_htu32_element *current)
{
    size_t ncur;
    if (!s || !s->capacity)
        return NULL;

    if (!current)
        ncur = 0;
    else {
        ncur = (size_t)(current - s->htable);
        if (ncur >= s->capacity)
            return NULL;

        ncur++;
    }
    for (; ncur < s->capacity; ncur++) {
        const struct cli_htu32_element *item = &s->htable[ncur & (s->capacity - 1)];
        if (item->key && item->key != DELETED_HTU32_KEY)
            return item;
    }
    return NULL;
}

static cl_error_t cli_hashtab_grow(struct cli_hashtable *s)
{
    cl_error_t ret;
    size_t new_capacity;
    struct cli_element *htable;
    size_t i, idx, used = 0;

    if (s->capacity == SIZE_MAX)
        return CL_ERESOURCE;

    ret = cli_hashtab_capacity(s->capacity + 1, sizeof(*s->htable), &new_capacity);
    if (ret != CL_SUCCESS)
        return ret;

    cli_dbgmsg("hashtab.c: new capacity: %zu\n", new_capacity);
    if (new_capacity == s->capacity) {
        cli_errmsg("hashtab.c: capacity problem growing from: %zu\n", s->capacity);
        return CL_ERESOURCE;
    }
    htable = cli_max_calloc(new_capacity, sizeof(*s->htable));
    if (!htable) {
        return CL_EMEM;
    }

    PROFILE_GROW_START(s);
    cli_dbgmsg("hashtab.c: Warning: growing open-addressing hashtables is slow. Either allocate more storage when initializing, or use other hashtable types!\n");
    for (i = 0; i < s->capacity; i++) {
        if (s->htable[i].key && s->htable[i].key != DELETED_KEY) {
            struct cli_element *element;
            size_t tries = 1;

            PROFILE_CALC_HASH(s);
            idx     = hash((const unsigned char *)s->htable[i].key, s->htable[i].len, new_capacity);
            element = &htable[idx];

            while (element->key && tries <= new_capacity) {
                idx     = (idx + tries++) & (new_capacity - 1);
                element = &htable[idx];
            }
            if (!element->key) {
                /* copy element from old hashtable to new */
                PROFILE_GROW_FOUND(s, tries);
                *element = s->htable[i];
                used++;
            } else {
                cli_errmsg("hashtab.c: Impossible - unable to rehash table");
                free(htable);
                return CL_EMEM; /* this means we didn't find enough room for all elements in the new table, should never happen */
            }
        }
    }
    free(s->htable);
    s->htable   = htable;
    s->used     = used;
    s->capacity = new_capacity;
    s->maxfill  = new_capacity * 8 / 10;
    cli_dbgmsg("Table %p size after grow: %zu\n", (void *)s, s->capacity);
    PROFILE_GROW_DONE(s);
    return CL_SUCCESS;
}

#ifndef USE_MPOOL
#define cli_htu32_grow(A, B) cli_htu32_grow(A)
#endif

static cl_error_t cli_htu32_grow(struct cli_htu32 *s, mpool_t *mempool)
{
    cl_error_t ret;
    size_t new_capacity;
    struct cli_htu32_element *htable;
    size_t i, idx, used = 0;

    if (s->capacity == SIZE_MAX)
        return CL_ERESOURCE;

    ret = cli_hashtab_capacity(s->capacity + 1, sizeof(*s->htable), &new_capacity);
    if (ret != CL_SUCCESS)
        return ret;

    htable = MPOOL_CALLOC(mempool, new_capacity, sizeof(*s->htable));
    cli_dbgmsg("hashtab.c: new capacity: %zu\n", new_capacity);
    if (new_capacity == s->capacity)
        return CL_ERESOURCE;
    if (!htable)
        return CL_EMEM;

    PROFILE_GROW_START(s);

    for (i = 0; i < s->capacity; i++) {
        if (s->htable[i].key && s->htable[i].key != DELETED_HTU32_KEY) {
            struct cli_htu32_element *element;
            size_t tries = 1;

            PROFILE_CALC_HASH(s);
            idx     = hash_htu32(s->htable[i].key, new_capacity);
            element = &htable[idx];

            while (element->key && tries <= new_capacity) {
                idx     = (idx + tries++) & (new_capacity - 1);
                element = &htable[idx];
            }
            if (!element->key) {
                /* copy element from old hashtable to new */
                PROFILE_GROW_FOUND(s, tries);
                *element = s->htable[i];
                used++;
            } else {
                cli_errmsg("hashtab.c: Impossible - unable to rehash table");
                MPOOL_FREE(mempool, htable);
                return CL_EMEM; /* this means we didn't find enough room for all elements in the new table, should never happen */
            }
        }
    }
    MPOOL_FREE(mempool, s->htable);
    s->htable   = htable;
    s->used     = used;
    s->capacity = new_capacity;
    s->maxfill  = new_capacity * 8 / 10;
    cli_dbgmsg("Table %p size after grow: %zu\n", (void *)s, s->capacity);
    PROFILE_GROW_DONE(s);
    return CL_SUCCESS;
}

const struct cli_element *cli_hashtab_insert(struct cli_hashtable *s, const char *key, const size_t len, const cli_element_data data)
{
    cl_error_t ret;
    struct cli_element *element;
    struct cli_element *deleted_element;
    size_t tries;
    size_t idx;

    if (!s || !key)
        return NULL;
    if (!s->htable || !s->capacity || len == SIZE_MAX || len >= CLI_MAX_ALLOCATION)
        return NULL;

    for (;;) {
        tries          = 1;
        deleted_element = NULL;

        if (s->used > s->maxfill) {
            cli_dbgmsg("hashtab.c:Growing hashtable %p, because it has exceeded maxfill, old size: %zu\n", (void *)s, s->capacity);
            ret = cli_hashtab_grow(s);
            if (ret != CL_SUCCESS)
                return NULL;
        }

        PROFILE_CALC_HASH(s);
        idx     = hash((const unsigned char *)key, len, s->capacity);
        element = &s->htable[idx];

        do {
            if (!element->key) {
                char *thekey;
                /* element not found, place is empty, insert*/
                if (deleted_element) {
                    /* reuse deleted elements*/
                    element = deleted_element;
                    PROFILE_DELETED_REUSE(s, tries);
                } else {
                    PROFILE_INSERT(s, tries);
                }
                thekey = cli_max_malloc(len + 1);
                if (!thekey) {
                    cli_errmsg("hashtab.c: Unable to allocate memory for thekey\n");
                    return NULL;
                }
                strncpy(thekey, key, len + 1);
                thekey[len]   = '\0';
                element->key  = thekey;
                element->data = data;
                element->len  = len;
                s->used++;
                return element;
            } else if (element->key == DELETED_KEY) {
                deleted_element = element;
                element->key    = NULL;
            } else if (len == element->len && strncmp(key, element->key, len) == 0) {
                PROFILE_DATA_UPDATE(s, tries);
                element->data = data; /* key found, update */
                return element;
            } else {
                idx     = (idx + tries++) % s->capacity;
                element = &s->htable[idx];
            }
        } while (tries <= s->capacity);
        /* no free place found*/
        PROFILE_HASH_EXHAUSTED(s);
        cli_dbgmsg("hashtab.c: Growing hashtable %p, because it's full, old size: %zu.\n", (void *)s, s->capacity);
        ret = cli_hashtab_grow(s);
        if (ret != CL_SUCCESS) {
            cli_warnmsg("hashtab.c: Unable to grow hashtable\n");
            return NULL;
        }
    }
}

cl_error_t cli_htu32_insert(struct cli_htu32 *s, const struct cli_htu32_element *item, mpool_t *mempool)
{
    cl_error_t ret;
    struct cli_htu32_element *element;
    struct cli_htu32_element *deleted_element;
    size_t tries;
    size_t idx;

#ifndef USE_MPOOL
    UNUSEDPARAM(mempool);
#endif

    if (!s)
        return CL_ENULLARG;
    if (!item)
        return CL_ENULLARG;
    if (!s->htable || !s->capacity)
        return CL_ESTATE;

    for (;;) {
        tries          = 1;
        deleted_element = NULL;

        if (s->used > s->maxfill) {
            cli_dbgmsg("hashtab.c:Growing hashtable %p, because it has exceeded maxfill, old size: %zu\n", (void *)s, s->capacity);
            ret = cli_htu32_grow(s, mempool);
            if (ret != CL_SUCCESS)
                return ret;
        }

        PROFILE_CALC_HASH(s);
        idx     = hash_htu32(item->key, s->capacity);
        element = &s->htable[idx];

        do {
            if (!element->key) {
                /* element not found, place is empty, insert*/
                if (deleted_element) {
                    /* reuse deleted elements*/
                    element = deleted_element;
                    PROFILE_DELETED_REUSE(s, tries);
                } else {
                    PROFILE_INSERT(s, tries);
                }
                *element = *item;
                s->used++;
                return CL_SUCCESS;
            } else if (element->key == DELETED_HTU32_KEY) {
                deleted_element = element;
                element->key    = 0;
            } else if (item->key == element->key) {
                PROFILE_DATA_UPDATE(s, tries);
                element->data = item->data; /* key found, update */
                return CL_SUCCESS;
            } else {
                idx     = (idx + tries++) % s->capacity;
                element = &s->htable[idx];
            }
        } while (tries <= s->capacity);
        /* no free place found*/
        PROFILE_HASH_EXHAUSTED(s);
        cli_dbgmsg("hashtab.c: Growing hashtable %p, because it's full, old size: %zu.\n", (void *)s, s->capacity);
        ret = cli_htu32_grow(s, mempool);
        if (ret != CL_SUCCESS) {
            cli_warnmsg("hashtab.c: Unable to grow hashtable\n");
            return ret;
        }
    }
}

void cli_hashtab_delete(struct cli_hashtable *s, const char *key, const size_t len)
{
    struct cli_element *el = cli_hashtab_find(s, key, len);
    if (!el || el->key == DELETED_KEY)
        return;
    free((void *)el->key);
    el->key = DELETED_KEY;
}

void cli_htu32_delete(struct cli_htu32 *s, uint32_t key)
{
    struct cli_htu32_element *el = (struct cli_htu32_element *)cli_htu32_find(s, key);
    if (el)
        el->key = DELETED_HTU32_KEY;
}

void cli_hashtab_clear(struct cli_hashtable *s)
{
    size_t i;
    PROFILE_HASH_CLEAR(s);
    for (i = 0; i < s->capacity; i++) {
        if (s->htable[i].key && s->htable[i].key != DELETED_KEY)
            free((void *)s->htable[i].key);
    }
    if (s->htable)
        memset(s->htable, 0, s->capacity * sizeof(*s->htable));
    s->used = 0;
}

void cli_htu32_clear(struct cli_htu32 *s)
{
    PROFILE_HASH_CLEAR(s);
    if (s->htable)
        memset(s->htable, 0, s->capacity * sizeof(struct cli_htu32_element));
    s->used = 0;
}

void cli_hashtab_free(struct cli_hashtable *s)
{
    cli_hashtab_clear(s);
    free(s->htable);
    s->htable   = NULL;
    s->capacity = 0;
}

void cli_htu32_free(struct cli_htu32 *s, mpool_t *mempool)
{
#ifndef USE_MPOOL
    UNUSEDPARAM(mempool);
#endif

    MPOOL_FREE(mempool, s->htable);
    s->htable   = NULL;
    s->capacity = 0;
}

size_t cli_htu32_numitems(struct cli_htu32 *s)
{
    if (!s) return 0;
    return s->capacity;
}

cl_error_t cli_hashtab_store(const struct cli_hashtable *s, FILE *out)
{
    size_t i;
    for (i = 0; i < s->capacity; i++) {
        const struct cli_element *e = &s->htable[i];
        if (e->key && e->key != DELETED_KEY) {
            fprintf(out, "%zu %s\n", (size_t)e->data, e->key);
        }
    }
    return CL_SUCCESS;
}

cl_error_t cli_hashtab_generate_c(const struct cli_hashtable *s, const char *name)
{
    size_t i;
    printf("/* TODO: include GPL headers */\n");
    printf("#include <hashtab.h>\n");
    printf("static struct cli_element %s_elements[] = {\n", name);
    for (i = 0; i < s->capacity; i++) {
        const struct cli_element *e = &s->htable[i];
        if (!e->key)
            printf("\t{NULL,0,0},\n");
        else if (e->key == DELETED_KEY)
            printf("\t{DELETED_KEY,0,0},\n");
        else
            printf("\t{\"%s\", %zu, %zu},\n", e->key, (size_t)e->data, e->len);
    }
    printf("};\n");
    printf("const struct cli_hashtable %s = {\n", name);
    printf("\t%s_elements, %zu, %zu, %zu", name, s->capacity, s->used, s->maxfill);
    printf("\n};\n");

    PROFILE_REPORT(s);
    return CL_SUCCESS;
}

cl_error_t cli_hashtab_load(FILE *in, struct cli_hashtable *s)
{
    char line[1024];

    if (!in || !s)
        return CL_ENULLARG;

    while (fgets(line, sizeof(line), in)) {
        char l[1024];
        size_t val;
        if (sscanf(line, "%zu %1023s", &val, l) != 2)
            return CL_EFORMAT;
        if (!cli_hashtab_insert(s, l, strlen(l), (const cli_element_data)val))
            return CL_EMEM;
    }
    return CL_SUCCESS;
}

cl_error_t cli_hashset_init(struct cli_hashset *hs, size_t initial_capacity, uint8_t load_factor)
{
    cl_error_t ret;
    size_t capacity;
    size_t keys_size;
    size_t bitmap_size;
    uint32_t *keys;
    uint32_t *bitmap;

    if (!hs)
        return CL_ENULLARG;

    if (load_factor < 50 || load_factor > 99) {
        cli_dbgmsg(MODULE_NAME "Invalid load factor: %u, using default of 80%%\n", load_factor);
        load_factor = 80;
    }

    ret = cli_hashtab_capacity(initial_capacity, sizeof(*hs->keys), &capacity);
    if (ret != CL_SUCCESS || capacity > UINT32_MAX)
        return (ret == CL_SUCCESS) ? CL_ERESOURCE : ret;
    ret = cli_hashtab_table_size(capacity >> 5, sizeof(*hs->bitmap), &bitmap_size);
    if (ret != CL_SUCCESS)
        return ret;

    ret = cli_hashtab_table_size(capacity, sizeof(*hs->keys), &keys_size);
    if (ret != CL_SUCCESS)
        return ret;

    keys = cli_max_malloc(keys_size);
    if (!keys) {
        cli_errmsg("hashtab.c: Unable to allocate memory for hs->keys\n");
        return CL_EMEM;
    }

    bitmap = cli_max_calloc(1, bitmap_size);
    if (!bitmap) {
        free(keys);
        cli_errmsg("hashtab.c: Unable to allocate memory for hs->bitmap\n");
        return CL_EMEM;
    }

    hs->limit    = (uint32_t)(capacity * load_factor / 100);
    hs->capacity = (uint32_t)capacity;
    hs->mask     = (uint32_t)capacity - 1;
    hs->count    = 0;
    hs->keys     = keys;
    hs->bitmap   = bitmap;
    hs->mempool  = NULL;
    return CL_SUCCESS;
}

cl_error_t cli_hashset_init_pool(struct cli_hashset *hs, size_t initial_capacity, uint8_t load_factor, mpool_t *mempool)
{
    cl_error_t ret;
    size_t capacity;
    size_t keys_size;
    size_t bitmap_size;
    uint32_t *keys;
    uint32_t *bitmap;

    if (!hs)
        return CL_ENULLARG;

    if (load_factor < 50 || load_factor > 99) {
        cli_dbgmsg(MODULE_NAME "Invalid load factor: %u, using default of 80%%\n", load_factor);
        load_factor = 80;
    }

    ret = cli_hashtab_capacity(initial_capacity, sizeof(*hs->keys), &capacity);
    if (ret != CL_SUCCESS || capacity > UINT32_MAX)
        return (ret == CL_SUCCESS) ? CL_ERESOURCE : ret;
    ret = cli_hashtab_table_size(capacity >> 5, sizeof(*hs->bitmap), &bitmap_size);
    if (ret != CL_SUCCESS)
        return ret;

    ret = cli_hashtab_table_size(capacity, sizeof(*hs->keys), &keys_size);
    if (ret != CL_SUCCESS)
        return ret;

    keys = MPOOL_MALLOC(mempool, keys_size);
    if (!keys) {
        cli_errmsg("hashtab.c: Unable to allocate memory pool for hs->keys\n");
        return CL_EMEM;
    }

    bitmap = MPOOL_CALLOC(mempool, 1, bitmap_size);
    if (!bitmap) {
        MPOOL_FREE(mempool, keys);
        cli_errmsg("hashtab.c: Unable to allocate/initialize memory for hs->keys\n");
        return CL_EMEM;
    }

    hs->limit    = (uint32_t)(capacity * load_factor / 100);
    hs->capacity = (uint32_t)capacity;
    hs->mask     = (uint32_t)capacity - 1;
    hs->count    = 0;
    hs->mempool  = mempool;
    hs->keys     = keys;
    hs->bitmap   = bitmap;
    return CL_SUCCESS;
}

void cli_hashset_destroy(struct cli_hashset *hs)
{
    cli_dbgmsg(MODULE_NAME "Freeing hashset, elements: %u, capacity: %u\n", hs->count, hs->capacity);
    if (hs->mempool) {
        MPOOL_FREE(hs->mempool, hs->keys);
        MPOOL_FREE(hs->mempool, hs->bitmap);
    } else {
        free(hs->keys);
        free(hs->bitmap);
    }
    hs->keys = hs->bitmap = NULL;
    hs->capacity          = 0;
}

#define BITMAP_CONTAINS(bmap, val) ((bmap)[(val) >> 5] & ((uint32_t)1U << ((val)&0x1f)))
#define BITMAP_INSERT(bmap, val) ((bmap)[(val) >> 5] |= ((uint32_t)1U << ((val)&0x1f)))
#define BITMAP_REMOVE(bmap, val) ((bmap)[(val) >> 5] &= ~((uint32_t)1U << ((val)&0x1f)))

/*
 * searches the hashset for the @key.
 * Returns the position the key is at, or a candidate position where it could be inserted.
 */
static inline size_t cli_hashset_search(const struct cli_hashset *hs, const uint32_t key)
{
    /* calculate hash value for this key, and map it to our table */
    size_t idx   = hash32shift(key) & (hs->mask);
    size_t tries = 1;

    /* check whether the entry is used, and if the key matches */
    while (BITMAP_CONTAINS(hs->bitmap, idx) && (hs->keys[idx] != key)) {
        /* entry used, key different -> collision */
        idx = (idx + tries++) & (hs->mask);
        /* quadratic probing, with c1 = c2 = 1/2, guaranteed to walk the entire table
         * for table sizes power of 2.*/
    }
    /* we have either found the key, or a candidate insertion position */
    return idx;
}

static void cli_hashset_addkey_internal(struct cli_hashset *hs, const uint32_t key)
{
    const size_t idx = cli_hashset_search(hs, key);
    /* we know hashtable is not full, when this method is called */

    if (!BITMAP_CONTAINS(hs->bitmap, idx)) {
        /* add new key */
        BITMAP_INSERT(hs->bitmap, idx);
        hs->keys[idx] = key;
        hs->count++;
    }
}

static cl_error_t cli_hashset_grow(struct cli_hashset *hs)
{
    struct cli_hashset new_hs;
    size_t i;
    cl_error_t rc;

    /* in-place growing is not possible, since the new keys
     * will hash to different locations. */
    cli_dbgmsg(MODULE_NAME "Growing hashset, used: %u, capacity: %u\n", hs->count, hs->capacity);
    /* create a bigger hashset */

    if (hs->capacity > UINT32_MAX / 2)
        return CL_ERESOURCE;

    if (hs->mempool) {
        rc = cli_hashset_init_pool(&new_hs, (size_t)hs->capacity * 2,
                                   (uint8_t)(hs->limit * 100 / hs->capacity),
                                   hs->mempool);
    } else {
        rc = cli_hashset_init(&new_hs, (size_t)hs->capacity * 2,
                              (uint8_t)(hs->limit * 100 / hs->capacity));
    }
    if (rc != CL_SUCCESS) {
        return rc;
    }
    /* and copy keys */
    for (i = 0; i < hs->capacity; i++) {
        if (BITMAP_CONTAINS(hs->bitmap, i)) {
            const uint32_t key = hs->keys[i];
            cli_hashset_addkey_internal(&new_hs, key);
        }
    }
    cli_hashset_destroy(hs);
    /* replace old hashset with new one */
    *hs = new_hs;
    return CL_SUCCESS;
}

cl_error_t cli_hashset_addkey(struct cli_hashset *hs, const uint32_t key)
{
    if (!hs)
        return CL_ENULLARG;
    if (hs->count == UINT32_MAX)
        return CL_ERESOURCE;

    /* check that we didn't reach the load factor.
     * Even if we don't know yet whether we'd add this key */
    if (hs->count + 1 > hs->limit) {
        cl_error_t rc = cli_hashset_grow(hs);
        if (rc != CL_SUCCESS) {
            return rc;
        }
    }
    cli_hashset_addkey_internal(hs, key);
    return CL_SUCCESS;
}

cl_error_t cli_hashset_removekey(struct cli_hashset *hs, const uint32_t key)
{
    const size_t idx = cli_hashset_search(hs, key);
    if (BITMAP_CONTAINS(hs->bitmap, idx)) {
        BITMAP_REMOVE(hs->bitmap, idx);
        hs->keys[idx] = 0;
        hs->count--;
        return CL_SUCCESS;
    }
    return CL_ERROR;
}

bool cli_hashset_contains(const struct cli_hashset *hs, const uint32_t key)
{
    const size_t idx = cli_hashset_search(hs, key);
    return BITMAP_CONTAINS(hs->bitmap, idx) != 0;
}

ssize_t cli_hashset_toarray(const struct cli_hashset *hs, uint32_t **array)
{
    size_t i, j;
    size_t array_size;
    uint32_t *arr;

    if (!hs || !array) {
        return -1;
    }

    if (cli_hashtab_table_size(hs->count, sizeof(*arr), &array_size) != CL_SUCCESS)
        return -1;

    *array = arr = cli_max_malloc(array_size);
    if (!arr) {
        cli_errmsg("hashtab.c: Unable to allocate memory for array\n");
        return -1;
    }

    for (i = 0, j = 0; i < hs->capacity && j < hs->count; i++) {
        if (BITMAP_CONTAINS(hs->bitmap, i)) {
            arr[j++] = hs->keys[i];
        }
    }
    return (ssize_t)j;
}

void cli_hashset_init_noalloc(struct cli_hashset *hs)
{
    memset(hs, 0, sizeof(*hs));
}

bool cli_hashset_contains_maybe_noalloc(const struct cli_hashset *hs, const uint32_t key)
{
    if (!hs->keys) {
        return false;
    }

    return cli_hashset_contains(hs, key);
}

cl_error_t cli_map_init(struct cli_map *m, int32_t keysize, int32_t valuesize,
                        int32_t capacity)
{
    cl_error_t ret;

    if (!m || keysize <= 0 || valuesize < 0 || capacity <= 0) {
        return CL_EARG;
    }

    memset(m, 0, sizeof(*m));

    ret = cli_hashtab_init(&m->htab, 16);
    if (CL_SUCCESS != ret) {
        return ret;
    }

    m->keysize     = keysize;
    m->valuesize   = valuesize;
    m->last_insert = -1;
    m->last_find   = -1;

    return CL_SUCCESS;
}

static int cli_map_allocation_size_valid(size_t count, size_t element_size)
{
    return element_size != 0 && count <= SIZE_MAX / element_size &&
           count <= CLI_MAX_ALLOCATION / element_size;
}

cl_error_t cli_map_addkey(struct cli_map *m, const void *key, int32_t keysize)
{
    uint32_t n;
    struct cli_element *el;

    if (!m || !key || m->keysize != keysize) {
        return CL_EARG;
    }

    el = cli_hashtab_find(&m->htab, key, (size_t)keysize);
    if (el) {
        // already exists
        m->last_insert = (int32_t)el->data;
        return CL_ECREAT;
    }

    if (m->nvalues == UINT32_MAX || m->nvalues > (uint32_t)INT32_MAX) {
        return CL_EMEM;
    }
    n = m->nvalues + 1;
    if (m->valuesize) {
        void *v;
        const size_t value_count = (size_t)n;
        const size_t value_size  = (size_t)m->valuesize;

        if (!cli_map_allocation_size_valid(value_count, value_size)) {
            return CL_EMEM;
        }

        v = cli_max_realloc(m->u.sized_values, value_count * value_size);
        if (!v) {
            return CL_EMEM;
        }

        m->u.sized_values = v;
        memset((char *)m->u.sized_values + (value_count - 1) * value_size, 0, value_size);
    } else {
        struct cli_map_value *v;

        if (!cli_map_allocation_size_valid((size_t)n, sizeof(*v))) {
            return CL_EMEM;
        }

        v = cli_max_realloc(m->u.unsized_values, (size_t)n * sizeof(*v));
        if (!v) {
            return CL_EMEM;
        }

        m->u.unsized_values = v;
        memset(&m->u.unsized_values[n - 1], 0, sizeof(*m->u.unsized_values));
    }
    m->nvalues = n;
    if (!cli_hashtab_insert(&m->htab, key, (size_t)keysize,
                            (const cli_element_data)(n - 1))) {
        return CL_EMEM;
    }

    m->last_insert = (int32_t)(n - 1);
    return CL_SUCCESS;
}

cl_error_t cli_map_removekey(struct cli_map *m, const void *key, int32_t keysize)
{
    struct cli_element *el;

    if (!m || !key || m->keysize != keysize) {
        return CL_EARG;
    }

    el = cli_hashtab_find(&m->htab, key, (size_t)keysize);
    if (!el) {
        // not found, can't remove
        return CL_EUNLINK;
    }

    if ((int32_t)el->data >= (int32_t)m->nvalues || (int32_t)el->data < 0) {
        return CL_EARG;
    }

    if (!m->valuesize) {
        struct cli_map_value *v = &m->u.unsized_values[(int32_t)el->data];
        free(v->value);
        v->value     = NULL;
        v->valuesize = 0;
    } else {
        char *v = (char *)m->u.sized_values + (int32_t)el->data * m->valuesize;
        memset(v, 0, (size_t)m->valuesize);
    }

    cli_hashtab_delete(&m->htab, key, (size_t)keysize);

    return CL_SUCCESS;
}

cl_error_t cli_map_setvalue(struct cli_map *m, const void *value, int32_t valuesize)
{
    if (!m || valuesize < 0 || (valuesize != 0 && !value) ||
        (m->valuesize && m->valuesize != valuesize) ||
        (uint32_t)(m->last_insert) >= m->nvalues || m->last_insert < 0) {
        return CL_EARG;
    }

    if (m->valuesize) {
        memcpy((char *)m->u.sized_values +
                   (size_t)m->last_insert * (size_t)m->valuesize,
               value, (size_t)valuesize);
    } else {
        struct cli_map_value *v = &m->u.unsized_values[m->last_insert];

        if (v->value) {
            free(v->value);
        }

        v->value = cli_max_malloc((size_t)valuesize);
        if (!v->value) {
            cli_errmsg("hashtab.c: Unable to allocate  memory for v->value\n");
            return CL_EMEM;
        }

        memcpy(v->value, value, (size_t)valuesize);
        v->valuesize = valuesize;
    }
    return CL_SUCCESS;
}

cl_error_t cli_map_find(struct cli_map *m, const void *key, int32_t keysize)
{
    struct cli_element *el;
    if (!m || !key || m->keysize != keysize) {
        return CL_EARG;
    }

    el = cli_hashtab_find(&m->htab, key, (size_t)keysize);
    if (!el) {
        // not found
        return CL_EACCES;
    }

    m->last_find = (int32_t)el->data;

    return CL_SUCCESS;
}

int cli_map_getvalue_size(struct cli_map *m)
{
    if (!m)
        return -1;

    if (m->valuesize) {
        return m->valuesize;
    }

    if (m->last_find < 0 || (uint32_t)(m->last_find) >= m->nvalues) {
        return -1;
    }

    return m->u.unsized_values[m->last_find].valuesize;
}

void *cli_map_getvalue(struct cli_map *m)
{
    if (!m)
        return NULL;

    if (m->last_find < 0 || (uint32_t)(m->last_find) >= m->nvalues) {
        return NULL;
    }

    if (m->valuesize) {
        return (char *)m->u.sized_values + m->last_find * m->valuesize;
    }

    return m->u.unsized_values[m->last_find].value;
}

void cli_map_delete(struct cli_map *m)
{
    if (!m)
        return;

    cli_hashtab_free(&m->htab);

    if (!m->valuesize) {
        unsigned i;

        for (i = 0; i < m->nvalues; i++) {
            free(m->u.unsized_values[i].value);
        }

        free(m->u.unsized_values);
    } else {
        free(m->u.sized_values);
    }

    memset(m, 0, sizeof(*m));
}
