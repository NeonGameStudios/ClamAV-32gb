/*
 * Regression coverage for milter connection-pool monitor startup. A milter
 * with configured clamd sockets must fail initialization if its monitor
 * thread cannot be created; a successful monitor must also be reclaimable.
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>

#include "connpool.h"

void nc_ping_entry(struct CP_ENTRY *entry)
{
    entry->dead = 0;
}

int nc_connect_entry(struct CP_ENTRY *entry)
{
    (void)entry;
    return -1;
}

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

static struct optstruct *make_options(void)
{
    return optadditem("ClamdSocket", "unix:/tmp/clamd-milter-test.sock", 1,
                      OPT_MILTER, 0, NULL);
}

int main(void)
{
    struct optstruct *opts;

    opts = make_options();
    assert(opts != NULL);
#ifdef CLAMAV_TEST_PTHREAD_CREATE_WRAP
    assert(cpool_init(opts) != 0);
    assert(cp == NULL);
#else
    assert(cpool_init(opts) == 0);
    assert(cp != NULL);
    cpool_free();
#endif
    optfree(opts);

#ifdef CLAMAV_TEST_PTHREAD_CREATE_WRAP
    opts = make_options();
    assert(opts != NULL);
    assert(cpool_init(opts) == 0);
    assert(cp != NULL);
    cpool_free();
    optfree(opts);
#endif

    return 0;
}
