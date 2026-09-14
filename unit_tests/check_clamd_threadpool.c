/*
 * Regression coverage for clamd threadpool admission when a worker cannot be
 * created. A dispatch must fail before publishing a job that no worker can
 * consume, and a later dispatch must still be able to run normally.
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>

#include "thrmgr.h"

pthread_mutex_t exit_mutex   = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t reload_mutex = PTHREAD_MUTEX_INITIALIZER;
int progexit                 = 0;
int reload                   = 0;

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

static pthread_mutex_t callback_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t callback_cond    = PTHREAD_COND_INITIALIZER;
static int callback_count              = 0;

static void record_callback(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&callback_mutex);
    callback_count++;
    pthread_cond_signal(&callback_cond);
    pthread_mutex_unlock(&callback_mutex);
}

static void wait_for_callbacks(int expected)
{
    pthread_mutex_lock(&callback_mutex);
    while (callback_count < expected)
        pthread_cond_wait(&callback_cond, &callback_mutex);
    pthread_mutex_unlock(&callback_mutex);
}

static void reset_callbacks(void)
{
    pthread_mutex_lock(&callback_mutex);
    callback_count = 0;
    pthread_mutex_unlock(&callback_mutex);
}

int main(void)
{
    threadpool_t *pool;
    int marker = 1;

    assert(thrmgr_new(1, 1, 0, record_callback) == NULL);
    pool = thrmgr_new(1, 1, 1, record_callback);
    assert(pool != NULL);

#ifdef CLAMAV_TEST_PTHREAD_CREATE_WRAP
    /* The failed create must not leave a permanently queued request. */
    assert(thrmgr_dispatch(pool, &marker) == 0);
#endif

    assert(thrmgr_dispatch(pool, &marker) == 1);
    wait_for_callbacks(1);

    thrmgr_destroy(pool);

#ifdef CLAMAV_TEST_PTHREAD_CREATE_WRAP
    reset_callbacks();
    pool = thrmgr_new(1, 1, 1, record_callback);
    assert(pool != NULL);
    assert(thrmgr_try_reserve(pool) == 1);
    fail_next_pthread_create = 1;
    /* A reserved dispatch that fails to create a worker must restore the
     * reservation so the same request can be admitted on retry. */
    assert(thrmgr_group_dispatch_reserved(pool, NULL, &marker, 0) == 0);
    assert(thrmgr_group_dispatch_reserved(pool, NULL, &marker, 0) == 1);
    wait_for_callbacks(1);
    thrmgr_destroy(pool);
#endif

    pthread_cond_destroy(&callback_cond);
    pthread_mutex_destroy(&callback_mutex);
    return 0;
}
