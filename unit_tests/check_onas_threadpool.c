/*
 * Regression coverage for the on-access worker pool's minimum-size contract.
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <pthread.h>

#include "thpool.h"

#ifdef CLAMAV_TEST_PTHREAD_CREATE_WRAP
static int fail_next_pthread_create = 1;

extern int __real_pthread_create(pthread_t *, const pthread_attr_t *,
                                 void *(*)(void *), void *);

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine)(void *), void *arg)
{
    if (fail_next_pthread_create) {
        fail_next_pthread_create = 0;
        return EAGAIN;
    }

    return __real_pthread_create(thread, attr, start_routine, arg);
}
#endif

static void increment(void *arg)
{
    int *value = (int *)arg;

    (*value)++;
}

int main(void)
{
    threadpool pool;
    int value = 0;

    assert(thpool_init(0) == NULL);
    assert(thpool_init(-1) == NULL);

#ifdef CLAMAV_TEST_PTHREAD_CREATE_WRAP
    /* pthread_create() failure must return promptly and leave no worker
     * using the partially initialized pool. */
    assert(thpool_init(1) == NULL);
#endif

    pool = thpool_init(1);
    assert(pool != NULL);
    assert(thpool_add_work(pool, increment, &value) == 0);
    thpool_wait(pool);
    assert(value == 1);
    thpool_destroy(pool);

    return 0;
}
