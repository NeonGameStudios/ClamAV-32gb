/* Regression coverage for clamd's legacy write-all helper. */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "clamd_others.h"

#ifdef CLAMAV_TEST_WRITE_WRAP
static int fail_next_write;
static int fail_next_malloc;

extern ssize_t __real_write(int fd, const void *buffer, size_t count);
extern void *__real_malloc(size_t size);

ssize_t __wrap_write(int fd, const void *buffer, size_t count)
{
    if (fail_next_write) {
        fail_next_write = 0;
        return 0;
    }

    return __real_write(fd, buffer, count);
}

void *__wrap_malloc(size_t size)
{
    if (fail_next_malloc) {
        fail_next_malloc = 0;
        return NULL;
    }

    return __real_malloc(size);
}
#endif

int main(void)
{
    int pipe_fds[2];
    char received[sizeof("clamd-write")];
    const char payload[] = "clamd-write";

    assert(pipe(pipe_fds) == 0);
    assert(writen(pipe_fds[1], (void *)payload, sizeof(payload) - 1) == (int)(sizeof(payload) - 1));
    assert(read(pipe_fds[0], received, sizeof(payload) - 1) == (ssize_t)(sizeof(payload) - 1));
    assert(memcmp(received, payload, sizeof(payload) - 1) == 0);

#ifdef CLAMAV_TEST_WRITE_WRAP
    fail_next_write = 1;
    errno            = 0;
    assert(writen(pipe_fds[1], (void *)payload, sizeof(payload) - 1) == -1);
    assert(errno == EIO);

    {
        struct fd_data fds = FDS_INIT(NULL);

        /* The command-buffer allocation failure must roll back the newly
         * counted descriptor instead of leaving an uninitialized slot live. */
        fail_next_malloc = 1;
        assert(fds_add(&fds, pipe_fds[0], 0, 0) == -1);
        assert(fds.nfds == 0);
        fds_free(&fds);
    }

#ifdef HAVE_POLL
    {
        int poll_fds[2];
        int added_fds[2];
        struct fd_data fds = FDS_INIT(NULL);

        /* A failed resize must preserve the old poll array so cleanup can
         * still safely release it. */
        assert(pipe(poll_fds) == 0);
        assert(pipe(added_fds) == 0);
        assert(fds_add(&fds, poll_fds[0], 1, 0) == 0);
        assert(write(poll_fds[1], "x", 1) == 1);
        assert(fds_poll_recv(&fds, 1, 0, NULL) > 0);
        assert(fds.poll_data != NULL);
        assert(fds.poll_data_nfds == 1);
        assert(fds_add(&fds, added_fds[0], 1, 0) == 0);
        fail_next_malloc = 1;
        assert(fds_poll_recv(&fds, 1, 0, NULL) == -1);
        assert(fds.poll_data != NULL);
        assert(fds.poll_data_nfds == 1);
        fds_free(&fds);
        assert(close(poll_fds[0]) == 0);
        assert(close(poll_fds[1]) == 0);
        assert(close(added_fds[0]) == 0);
        assert(close(added_fds[1]) == 0);
    }
#endif

#ifdef HAVE_FD_PASSING
    {
        int passed_fds[2];
        int shutdown_fds[2];
        struct fd_data fds = FDS_INIT(NULL);

        /* Removal cleanup must close an ancillary descriptor that was
         * received but never claimed by the scan connection. */
        assert(pipe(passed_fds) == 0);
        assert(fds_add(&fds, pipe_fds[0], 1, 0) == 0);
        fds.buf[0].recvfd = passed_fds[0];
        fds_remove(&fds, pipe_fds[0]);
        fds_cleanup(&fds);
        errno = 0;
        assert(fcntl(passed_fds[0], F_GETFD) == -1);
        assert(errno == EBADF);
        fds_free(&fds);
        assert(close(passed_fds[1]) == 0);

        /* Daemon-wide teardown must close the same kind of unclaimed
         * descriptor when the owning slot is still active. */
        assert(pipe(shutdown_fds) == 0);
        assert(fds_add(&fds, pipe_fds[0], 1, 0) == 0);
        fds.buf[0].recvfd = shutdown_fds[0];
        fds_free(&fds);
        errno = 0;
        assert(fcntl(shutdown_fds[0], F_GETFD) == -1);
        assert(errno == EBADF);
        assert(close(shutdown_fds[1]) == 0);
    }
#endif
#endif

    assert(close(pipe_fds[0]) == 0);
    assert(close(pipe_fds[1]) == 0);
    return 0;
}
