/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Linked only into test-faults. No fault controls are installed in production. */
#include "cm.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int __real_cm_write_json(const char *, const char *, struct json_object *, struct cm_error *);
int __wrap_cm_write_json(const char *, const char *, struct json_object *, struct cm_error *);
int __real_renameat(int, const char *, int, const char *);
int __wrap_renameat(int, const char *, int, const char *);
int __real_fsync(int);
int __wrap_fsync(int);
FILE *__real_fopen(const char *, const char *);
FILE *__wrap_fopen(const char *, const char *);
int __real_cm_exec(const char *, char *const[], struct cm_error *);
int __wrap_cm_exec(const char *, char *const[], struct cm_error *);
int __real_cm_updates(const struct cm_paths *, int, char **, bool, struct cm_error *);
int __wrap_cm_updates(const struct cm_paths *, int, char **, bool, struct cm_error *);
int __real_cm_reconcile_guard(const struct cm_paths *, struct cm_error *);
int __wrap_cm_reconcile_guard(const struct cm_paths *, struct cm_error *);

static bool matches(const char *variable, const char *value)
{
    const char *wanted = getenv(variable);
    return wanted && !strcmp(wanted, value);
}
static int barrier(struct cm_error *e)
{
    const char *ready = getenv("CM_TEST_READY"), *release = getenv("CM_TEST_RELEASE");
    if (!ready || !release)
        return cm_fail(e, "test barrier paths are missing");
    int fd = open(ready, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return cm_fail(e, "test barrier: %s", strerror(errno));
    close(fd);
    struct timespec pause = {.tv_nsec = 10000000};
    for (unsigned i = 0; i < 1500; i++) {
        if (!access(release, F_OK))
            return 0;
        nanosleep(&pause, NULL);
    }
    return cm_fail(e, "test barrier deadline expired");
}
int __wrap_cm_write_json(const char *dir, const char *name, struct json_object *o,
                         struct cm_error *e)
{
    static bool failed, held;
    if (!held && matches("CM_TEST_HOLD_WRITE", name)) {
        held = true;
        if (barrier(e))
            return -1;
    }
    if (!failed && matches("CM_TEST_FAIL_WRITE", name)) {
        failed = true;
        return cm_fail(e, "injected write failure for %s", name);
    }
    return __real_cm_write_json(dir, name, o, e);
}
int __wrap_renameat(int olddir, const char *oldname, int newdir, const char *newname)
{
    static bool failed;
    if (!failed && matches("CM_TEST_FAIL_RENAME", newname)) {
        failed = true;
        errno = EIO;
        return -1;
    }
    return __real_renameat(olddir, oldname, newdir, newname);
}
int __wrap_fsync(int fd)
{
    static bool failed;
    const char *needle = getenv("CM_TEST_FAIL_FSYNC");
    if (!failed && needle) {
        char path[CM_PATH_MAX], link[80];
        snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
        ssize_t length = readlink(link, path, sizeof path - 1);
        if (length >= 0) {
            path[length] = 0;
            if (strstr(path, needle)) {
                failed = true;
                errno = getenv("CM_TEST_DISK_FULL") ? ENOSPC : EIO;
                return -1;
            }
        }
    }
    return __real_fsync(fd);
}
FILE *__wrap_fopen(const char *path, const char *mode)
{
    if (matches("CM_TEST_FAIL_FOPEN", path)) {
        errno = EACCES;
        return NULL;
    }
    return __real_fopen(path, mode);
}
int __wrap_cm_exec(const char *program, char *const argv[], struct cm_error *e)
{
    if (getenv("CM_TEST_PACKAGE_BARRIER") &&
        (!strcmp(program, "/usr/bin/apt-get") || !strcmp(program, "/usr/bin/unattended-upgrade")))
        return barrier(e);
    return __real_cm_exec(program, argv, e);
}
int __wrap_cm_updates(const struct cm_paths *p, int argc, char **argv, bool dry,
                      struct cm_error *e)
{
    struct cm_paths selected = *p;
    if (getenv("CM_TEST_PACKAGE_BARRIER"))
        selected.offline = false;
    return __real_cm_updates(&selected, argc, argv, dry, e);
}
int __wrap_cm_reconcile_guard(const struct cm_paths *p, struct cm_error *e)
{
    if (getenv("CM_TEST_HOLD_RECONCILE") && barrier(e))
        return -1;
    return __real_cm_reconcile_guard(p, e);
}
