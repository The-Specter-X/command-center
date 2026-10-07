/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syslog.h>
#include <systemd/sd-journal.h>
#include <time.h>
#include <unistd.h>

int cm_fail(struct cm_error *e, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->text, sizeof e->text, fmt, ap);
    va_end(ap);
    return -1;
}
void *cm_alloc(size_t n)
{
    void *p = calloc(1, n);
    if (!p) {
        fputs("command-center: out of memory\n", stderr);
        exit(1);
    }
    return p;
}
char *cm_strdup(const char *s)
{
    char *p = strdup(s);
    if (!p) {
        fputs("command-center: out of memory\n", stderr);
        exit(1);
    }
    return p;
}
static void journal_event(int priority, const char *component, const char *action, uint32_t rule,
                          const char *address, const char *fmt, va_list ap)
{
    char message[2048];
    vsnprintf(message, sizeof message, fmt, ap);
    sd_journal_send("MESSAGE=%s", message, "PRIORITY=%d", priority,
                    "SYSLOG_IDENTIFIER=command-center", "CM_COMPONENT=%s", component,
                    "CM_ACTION=%s", action, "CM_RULE_ID=%u", rule,
                    "CM_ADDRESS=%s", address ? address : "", NULL);
}
void cm_event(int priority, const char *component, const char *action, uint32_t rule,
              const char *address, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    journal_event(priority, component, action, rule, address, fmt, ap);
    va_end(ap);
}
void cm_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    journal_event(5, "administration", "event", 0, NULL, fmt, ap);
    va_end(ap);
}
bool cm_plain(const char *s, bool identifier)
{
    if (identifier && !*s)
        return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (identifier) {
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.' || *p == ':'))
                return false;
        } else if (*p < 32 || *p > 126)
            return false;
    }
    return true;
}
int cm_uint(const char *s, uint64_t lo, uint64_t hi, uint64_t *out, struct cm_error *e)
{
    if (!s || !*s)
        return cm_fail(e, "expected an unsigned integer");
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9')
            return cm_fail(e, "invalid integer: %s", s);
    errno = 0;
    char *end;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || *end || v < lo || v > hi)
        return cm_fail(e, "integer outside allowed range: %s", s);
    *out = v;
    return 0;
}
uint64_t cm_now(void)
{
    time_t t = time(NULL);
    return t < 0 ? 0 : (uint64_t)t;
}
int cm_address(const char *input, bool cidr, char *out, size_t cap, struct cm_error *e)
{
    if (!input || strlen(input) >= CM_ADDRESS_MAX)
        return cm_fail(e, "invalid address length");
    char s[CM_ADDRESS_MAX];
    strcpy(s, input);
    char *slash = strchr(s, '/');
    uint64_t prefix = 0;
    if (slash) {
        if (!cidr)
            return cm_fail(e, "a single IP address is required");
        *slash++ = 0;
    }
    unsigned char bytes[16];
    int family = strchr(s, ':') ? AF_INET6 : AF_INET;
    unsigned bits = family == AF_INET ? 32U : 128U;
    if (inet_pton(family, s, bytes) != 1)
        return cm_fail(e, "invalid numeric IP address: %s", input);
    if (slash && cm_uint(slash, 0, bits, &prefix, e))
        return -1;
    if (slash)
        for (unsigned i = 0; i < bits / 8; i++) {
            unsigned remain = prefix > i * 8 ? (unsigned)prefix - i * 8 : 0;
            if (remain < 8)
                bytes[i] &= remain ? (unsigned char)(0xffU << (8 - remain)) : 0;
        }
    static const unsigned char mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
    if (family == AF_INET6 && (!slash || prefix >= 96) && !memcmp(bytes, mapped, sizeof mapped)) {
        memmove(bytes, bytes + 12, 4);
        family = AF_INET;
        if (slash)
            prefix -= 96;
    }
    char text[INET6_ADDRSTRLEN];
    if (!inet_ntop(family, bytes, text, sizeof text))
        return cm_fail(e, "cannot format IP address");
    int n = slash ? snprintf(out, cap, "%s/%llu", text, (unsigned long long)prefix)
                  : snprintf(out, cap, "%s", text);
    if (n < 0 || (size_t)n >= cap)
        return cm_fail(e, "address buffer too small");
    return 0;
}
bool cm_contains(const char *network, const char *address)
{
    char s[CM_ADDRESS_MAX];
    if (strlen(network) >= sizeof s)
        return false;
    strcpy(s, network);
    char *slash = strchr(s, '/');
    if (slash)
        *slash++ = 0;
    int af = strchr(s, ':') ? AF_INET6 : AF_INET;
    if ((strchr(address, ':') != NULL) != (af == AF_INET6))
        return false;
    unsigned char a[16], b[16];
    if (inet_pton(af, s, a) != 1 || inet_pton(af, address, b) != 1)
        return false;
    unsigned bits = af == AF_INET ? 32U : 128U;
    uint64_t prefix = bits;
    struct cm_error e;
    if (slash && cm_uint(slash, 0, bits, &prefix, &e))
        return false;
    for (unsigned i = 0; i < (unsigned)prefix / 8; i++)
        if (a[i] != b[i])
            return false;
    unsigned rem = (unsigned)prefix % 8;
    return !rem || ((a[prefix / 8] ^ b[prefix / 8]) & (0xffU << (8 - rem))) == 0;
}
int cm_service(const char *s, uint16_t *port, char *proto, struct cm_error *e)
{
    struct {
        const char *name;
        unsigned port;
    } aliases[] = {{"ssh", 22},    {"http", 80},        {"https", 443},       {"dns", 53},
                   {"smtp", 25},   {"submission", 587}, {"imap", 143},        {"imaps", 993},
                   {"quic", 443},  {"ntp", 123},        {"wireguard", 51820}, {"postgresql", 5432},
                   {"mysql", 3306}};
    for (size_t i = 0; i < sizeof aliases / sizeof *aliases; i++)
        if (!strcmp(s, aliases[i].name)) {
            *port = (uint16_t)aliases[i].port;
            strcpy(proto, !strcmp(s, "dns") ? "both"
                          : (!strcmp(s, "quic") || !strcmp(s, "ntp") || !strcmp(s, "wireguard"))
                              ? "udp"
                              : "tcp");
            return 0;
        }
    if (strlen(s) > 16)
        return cm_fail(e, "expected PORT/tcp, PORT/udp, or a documented service alias");
    char buf[17];
    strcpy(buf, s);
    char *p = strchr(buf, '/');
    if (!p)
        return cm_fail(e, "a protocol is required, for example 22/tcp");
    *p++ = 0;
    if (strcmp(p, "tcp") && strcmp(p, "udp") && strcmp(p, "both"))
        return cm_fail(e, "protocol must be tcp, udp or both");
    uint64_t v;
    if (cm_uint(buf, 1, 65535, &v, e))
        return -1;
    *port = (uint16_t)v;
    strcpy(proto, p);
    return 0;
}
int cm_duration(const char *s, unsigned *seconds, struct cm_error *e)
{
    size_t len = strlen(s);
    if (!len || len > 12)
        return cm_fail(e, "invalid duration");
    char buf[13];
    strcpy(buf, s);
    unsigned mult = 1;
    char c = buf[len - 1];
    if (c < '0' || c > '9') {
        buf[len - 1] = 0;
        switch (c) {
        case 's':
            break;
        case 'm':
            mult = 60;
            break;
        case 'h':
            mult = 3600;
            break;
        case 'd':
            mult = 86400;
            break;
        default:
            return cm_fail(e, "duration suffix must be s, m, h, or d");
        }
    }
    uint64_t v;
    if (cm_uint(buf, 1, 2592000U / mult, &v, e))
        return -1;
    *seconds = (unsigned)v * mult;
    return 0;
}
static int path(char *dst, const char *root, const char *suffix, struct cm_error *e)
{
    int n = snprintf(dst, CM_PATH_MAX, "%s%s", root, suffix);
    return n < 0 || n >= CM_PATH_MAX ? cm_fail(e, "path is too long") : 0;
}
int cm_paths_init(struct cm_paths *p, const char *root, struct cm_error *e)
{
    memset(p, 0, sizeof *p);
    const char *r = root ? root : "";
    if (root &&
        (root[0] != '/' || strstr(root, "/../") || strstr(root, "/./") || strlen(root) > 3000 ||
         !strcmp(root, "/") || !strcmp(root + strlen(root) - 1, "/")))
        return cm_fail(
            e, "--root requires an absolute directory without a trailing slash or dot components");
    if (root) {
        const char *q = strrchr(root, '/');
        if (!strcmp(q, "/..") || !strcmp(q, "/."))
            return cm_fail(e, "invalid root path");
    }
    p->offline = root != NULL;
    return path(p->config, r, "/etc/command-center", e) ||
                   path(p->state, r, "/var/lib/command-center", e) ||
                   path(p->run, r, "/run/command-center", e)
               ? -1
               : 0;
}
static int directory(const char *s, bool create, struct cm_error *e)
{
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return cm_fail(e, "open root: %s", strerror(errno));
    char *copy = cm_strdup(s), *save = NULL;
    char *part = strtok_r(copy, "/", &save);
    while (part) {
        if (!strcmp(part, ".") || !strcmp(part, "..")) {
            close(fd);
            free(copy);
            return cm_fail(e, "unsafe directory component");
        }
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0 && errno == ENOENT && create) {
            if (mkdirat(fd, part, 0700) < 0 && errno != EEXIST) {
                close(fd);
                free(copy);
                return cm_fail(e, "create %s: %s", s, strerror(errno));
            }
            next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        }
        if (next < 0) {
            int x = errno;
            close(fd);
            free(copy);
            cm_fail(e, "open %s: %s", s, strerror(x));
            return !create && x == ENOENT ? -2 : -1;
        }
        struct stat st;
        if (fstat(next, &st) < 0 || (st.st_uid != 0 && st.st_uid != geteuid()) ||
            ((st.st_mode & 0022) && !(st.st_mode & S_ISVTX))) {
            close(next);
            close(fd);
            free(copy);
            return cm_fail(e, "unsafe ownership or permissions on %s", s);
        }
        close(fd);
        fd = next;
        part = strtok_r(NULL, "/", &save);
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || (st.st_mode & 0022)) {
        close(fd);
        free(copy);
        return cm_fail(e, "application directory must not be writable by other users: %s", s);
    }
    free(copy);
    return fd;
}
int cm_prepare(const struct cm_paths *p, struct cm_error *e)
{
    const char *dirs[] = {p->config, p->state, p->run};
    for (size_t i = 0; i < 3; i++) {
        int fd = directory(dirs[i], true, e);
        if (fd < 0)
            return -1;
        close(fd);
    }
    return 0;
}
static int named_lock(const struct cm_paths *p, const char *name, struct cm_error *e)
{
    int dir = directory(p->run, true, e);
    if (dir < 0)
        return -1;
    int fd = openat(dir, name, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    close(dir);
    struct stat st;
    if (fd < 0)
        return cm_fail(e, "open lock: %s", strerror(errno));
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 ||
        (st.st_mode & 0022)) {
        close(fd);
        return cm_fail(e, "unsafe lock file");
    }
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        int saved = errno;
        close(fd);
        cm_fail(e, "another Command Center operation is in progress; retry later");
        return saved == EWOULDBLOCK || saved == EAGAIN ? -2 : -1;
    }
    return fd;
}
int cm_lock(const struct cm_paths *p, struct cm_error *e)
{
    return named_lock(p, "lock", e);
}
int cm_guard_lock(const struct cm_paths *p, struct cm_error *e)
{
    return named_lock(p, "guard.lock", e);
}
int cm_read_text(const char *dir, const char *name, char **out, struct cm_error *e)
{
    *out = NULL;
    int d = directory(dir, false, e);
    if (d < 0) {
        if (d == -2)
            e->text[0] = 0;
        return d == -2 ? 1 : -1;
    }
    int fd = openat(d, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int x = errno;
    close(d);
    if (fd < 0) {
        if (x == ENOENT)
            return 1;
        return cm_fail(e, "open %s/%s: %s", dir, name, strerror(x));
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_uid != geteuid() ||
        (st.st_mode & 0022) || st.st_size < 0 || (uint64_t)st.st_size > CM_MAX_FILE) {
        close(fd);
        return cm_fail(e, "unsafe or oversized file: %s/%s", dir, name);
    }
    size_t cap = (size_t)st.st_size;
    char *data = cm_alloc(cap + 1);
    size_t used = 0;
    while (used < cap) {
        ssize_t n = read(fd, data + used, cap - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            close(fd);
            free(data);
            return cm_fail(e, "short or failed read: %s/%s", dir, name);
        }
        used += (size_t)n;
    }
    char extra;
    ssize_t n;
    do {
        n = read(fd, &extra, 1);
    } while (n < 0 && errno == EINTR);
    close(fd);
    if (n != 0 || memchr(data, 0, used)) {
        free(data);
        return cm_fail(e, "file changed or contains NUL bytes: %s/%s", dir, name);
    }
    *out = data;
    return 0;
}
int cm_read_lock(const struct cm_paths *p, struct cm_error *e)
{
    int dir = directory(p->run, false, e);
    if (dir < 0)
        return dir;
    int fd = openat(dir, "lock", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int saved = errno;
    close(dir);
    if (fd < 0) {
        if (saved == ENOENT)
            return -2;
        return cm_fail(e, "open read lock: %s", strerror(saved));
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 ||
        (st.st_mode & 0022)) {
        close(fd);
        return cm_fail(e, "unsafe read lock file");
    }
    if (flock(fd, LOCK_SH | LOCK_NB) < 0) {
        int lock_errno = errno;
        close(fd);
        cm_fail(e, "another operation is in progress; retry for a consistent read");
        return lock_errno == EWOULDBLOCK || lock_errno == EAGAIN ? -3 : -1;
    }
    return fd;
}
/* json-c deliberately accepts duplicate keys. Reject them, including escaped
 * spellings, after syntax validation so configuration has one interpretation. */
static int unique_keys(const char *text, size_t length, struct cm_error *e)
{
    struct json_object *keys[32] = {0};
    bool expecting_key[32] = {0};
    unsigned depth = 0;
    int result = 0;
    for (size_t i = 0; i < length && !result; i++) {
        char c = text[i];
        if (c == '{' || c == '[') {
            if (depth == 32) {
                result = cm_fail(e, "JSON nesting limit exceeded");
                break;
            }
            keys[depth] = c == '{' ? json_object_new_object() : NULL;
            expecting_key[depth++] = c == '{';
        } else if (c == '}' || c == ']') {
            if (depth) {
                depth--;
                if (keys[depth])
                    json_object_put(keys[depth]);
                keys[depth] = NULL;
            }
        } else if (c == ',' && depth) {
            expecting_key[depth - 1] = keys[depth - 1] != NULL;
        } else if (c == '"') {
            size_t start = i++;
            while (i < length && text[i] != '"') {
                if (text[i] == '\\')
                    i++;
                i++;
            }
            if (depth && expecting_key[depth - 1]) {
                size_t n = i - start + 1;
                if (n > 1024) {
                    result = cm_fail(e, "JSON key exceeds size limit");
                    break;
                }
                char key_text[1025];
                memcpy(key_text, text + start, n);
                key_text[n] = 0;
                struct json_object *decoded = json_tokener_parse(key_text), *previous;
                const char *key = decoded ? json_object_get_string(decoded) : NULL;
                if (!key || json_object_get_string_len(decoded) != (int)strlen(key) ||
                    json_object_object_get_ex(keys[depth - 1], key, &previous))
                    result = cm_fail(e, "duplicate or invalid JSON object key");
                else
                    json_object_object_add(keys[depth - 1], key, json_object_new_boolean(true));
                if (decoded)
                    json_object_put(decoded);
                expecting_key[depth - 1] = false;
            }
        }
    }
    while (depth) {
        depth--;
        if (keys[depth])
            json_object_put(keys[depth]);
    }
    return result;
}
int cm_read_json(const char *dir, const char *name, struct json_object **out, struct cm_error *e)
{
    *out = NULL;
    char *data;
    int r = cm_read_text(dir, name, &data, e);
    if (r)
        return r;
    struct json_tokener *tok = json_tokener_new_ex(32);
    if (!tok) {
        free(data);
        return cm_fail(e, "cannot allocate JSON parser");
    }
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    size_t len = strlen(data);
    struct json_object *o = json_tokener_parse_ex(tok, data, (int)len);
    enum json_tokener_error err = json_tokener_get_error(tok);
    size_t end = json_tokener_get_parse_end(tok);
    while (end < len &&
           (data[end] == ' ' || data[end] == '\n' || data[end] == '\t' || data[end] == '\r'))
        end++;
    if (err != json_tokener_success || end != len || !o) {
        if (o)
            json_object_put(o);
        json_tokener_free(tok);
        free(data);
        return cm_fail(e, "invalid JSON in %s/%s", dir, name);
    }
    json_tokener_free(tok);
    if (unique_keys(data, len, e)) {
        json_object_put(o);
        free(data);
        return -1;
    }
    free(data);
    *out = o;
    return 0;
}
static int write_text(const char *dir, const char *name, const char *text, mode_t mode,
                      struct cm_error *e)
{
    if (strlen(text) > CM_MAX_FILE)
        return cm_fail(e, "generated file exceeds the size limit: %s", name);
    int d = directory(dir, true, e);
    if (d < 0)
        return -1;
    char temp[128];
    int fd = -1;
    for (unsigned i = 0; i < 100; i++) {
        snprintf(temp, sizeof temp, ".%s.%ld.%u.tmp", name, (long)getpid(), i);
        fd = openat(d, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0)
            break;
        if (errno != EEXIST)
            break;
    }
    if (fd < 0) {
        close(d);
        return cm_fail(e, "create temporary %s: %s", name, strerror(errno));
    }
    size_t len = strlen(text), done = 0;
    int r = 0;
    while (done < len) {
        ssize_t n = write(fd, text + done, len - done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            r = cm_fail(e, "write %s: %s", name, strerror(errno));
            break;
        }
        done += (size_t)n;
    }
    if (!r && fchmod(fd, mode) < 0)
        r = cm_fail(e, "set permissions for %s: %s", name, strerror(errno));
    if (!r && fsync(fd) < 0)
        r = cm_fail(e, "sync %s: %s", name, strerror(errno));
    if (close(fd) < 0 && !r)
        r = cm_fail(e, "close %s: %s", name, strerror(errno));
    if (!r && renameat(d, temp, d, name) < 0)
        r = cm_fail(e, "replace %s: %s", name, strerror(errno));
    if (!r && fsync(d) < 0)
        r = cm_fail(e, "sync directory %s: %s", dir, strerror(errno));
    if (r)
        unlinkat(d, temp, 0);
    close(d);
    return r;
}
int cm_write_text(const char *dir, const char *name, const char *text, struct cm_error *e)
{
    return write_text(dir, name, text, 0600, e);
}
int cm_write_public_text(const char *dir, const char *name, const char *text, struct cm_error *e)
{
    return write_text(dir, name, text, 0644, e);
}
int cm_write_json(const char *dir, const char *name, struct json_object *o, struct cm_error *e)
{
    return cm_write_text(
        dir, name,
        json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE),
        e);
}
int cm_remove(const char *dir, const char *name, struct cm_error *e)
{
    int d = directory(dir, false, e);
    if (d < 0)
        return -1;
    int r = unlinkat(d, name, 0);
    if (r < 0 && errno != ENOENT) {
        close(d);
        return cm_fail(e, "remove %s: %s", name, strerror(errno));
    }
    r = fsync(d);
    close(d);
    return r < 0 ? cm_fail(e, "sync directory: %s", strerror(errno)) : 0;
}
int cm_exists(const char *dir, const char *name)
{
    char p[CM_PATH_MAX];
    int n = snprintf(p, sizeof p, "%s/%s", dir, name);
    struct stat st;
    return n > 0 && (size_t)n < sizeof p && lstat(p, &st) == 0;
}
int cm_exec(const char *program, char *const argv[], struct cm_error *e)
{
    pid_t pid;
    char *env[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", NULL};
    int spawned = posix_spawn(&pid, program, NULL, NULL, argv, env);
    if (spawned)
        return cm_fail(e, "execute %s: %s", program, strerror(spawned));
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        return cm_fail(e, "wait: %s", strerror(errno));
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status))
        return cm_fail(e, "%s failed (status %d)", program,
                       WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));
    return 0;
}
int cm_capture(const char *program, char *const argv[], char **output, struct cm_error *e)
{
    *output = NULL;
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC) < 0)
        return cm_fail(e, "pipe: %s", strerror(errno));
    /* Keep pipe descriptors distinct from stdio even when the caller closed it. */
    for (size_t i = 0; i < 2; i++)
        if (pipes[i] <= STDERR_FILENO) {
            int moved = fcntl(pipes[i], F_DUPFD_CLOEXEC, 3);
            if (moved < 0) {
                close(pipes[0]);
                close(pipes[1]);
                return cm_fail(e, "relocate pipe: %s", strerror(errno));
            }
            close(pipes[i]);
            pipes[i] = moved;
        }
    posix_spawn_file_actions_t actions;
    int setup = posix_spawn_file_actions_init(&actions);
    if (setup) {
        close(pipes[0]);
        close(pipes[1]);
        return cm_fail(e, "spawn actions: %s", strerror(setup));
    }
    setup = posix_spawn_file_actions_addclose(&actions, pipes[0]);
    if (!setup)
        setup = posix_spawn_file_actions_adddup2(&actions, pipes[1], STDOUT_FILENO);
    if (!setup)
        setup = posix_spawn_file_actions_addclose(&actions, pipes[1]);
    pid_t pid;
    char *env[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", NULL};
    if (!setup)
        setup = posix_spawn(&pid, program, &actions, NULL, argv, env);
    posix_spawn_file_actions_destroy(&actions);
    if (setup) {
        close(pipes[0]);
        close(pipes[1]);
        return cm_fail(e, "execute %s: %s", program, strerror(setup));
    }
    close(pipes[1]);
    size_t size = 0, cap = 65536;
    char *text = cm_alloc(cap + 1);
    bool too_big = false;
    int read_error = 0;
    for (;;) {
        char chunk[4096];
        ssize_t n = read(pipes[0], chunk, sizeof chunk);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            read_error = errno;
            break;
        }
        if (!n)
            break;
        if (size + (size_t)n > cap) {
            too_big = true;
            continue;
        }
        memcpy(text + size, chunk, (size_t)n);
        size += (size_t)n;
    }
    close(pipes[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        free(text);
        return cm_fail(e, "wait: %s", strerror(errno));
    }
    if (read_error || too_big || !WIFEXITED(status) || WEXITSTATUS(status)) {
        free(text);
        return cm_fail(e, "%s failed or produced excessive output", program);
    }
    *output = text;
    return 0;
}
bool cm_keys(struct json_object *o, const char *const *keys, struct cm_error *e)
{
    if (!json_object_is_type(o, json_type_object)) {
        cm_fail(e, "expected a JSON object");
        return false;
    }
    json_object_object_foreach(o, key, val)
    {
        (void)val;
        bool found = false;
        for (size_t i = 0; keys[i]; i++)
            if (!strcmp(key, keys[i]))
                found = true;
        if (!found) {
            cm_fail(e, "unknown configuration key: %s", key);
            return false;
        }
    }
    return true;
}
int cm_get_int(struct json_object *o, const char *key, uint64_t lo, uint64_t hi, uint64_t *out,
               struct cm_error *e)
{
    struct json_object *v;
    if (!json_object_object_get_ex(o, key, &v) || !json_object_is_type(v, json_type_int) ||
        json_object_get_int64(v) < 0)
        return cm_fail(e, "%s must be an integer", key);
    uint64_t n = json_object_get_uint64(v);
    if (n < lo || n > hi)
        return cm_fail(e, "%s is outside its allowed range", key);
    *out = n;
    return 0;
}
int cm_get_bool(struct json_object *o, const char *key, bool *out, struct cm_error *e)
{
    struct json_object *v;
    if (!json_object_object_get_ex(o, key, &v) || !json_object_is_type(v, json_type_boolean))
        return cm_fail(e, "%s must be a boolean", key);
    *out = json_object_get_boolean(v);
    return 0;
}
int cm_get_string(struct json_object *o, const char *key, char *out, size_t cap, struct cm_error *e)
{
    struct json_object *v;
    if (!json_object_object_get_ex(o, key, &v) || !json_object_is_type(v, json_type_string))
        return cm_fail(e, "%s must be a string", key);
    int len = json_object_get_string_len(v);
    const char *s = json_object_get_string(v);
    if (len < 0 || (size_t)len >= cap || strlen(s) != (size_t)len)
        return cm_fail(e, "invalid or oversized %s", key);
    memcpy(out, s, (size_t)len + 1);
    return 0;
}

int cm_service_config(const struct cm_config *c, const char *name, uint16_t *port, char *proto,
                      struct cm_error *e)
{
    for (size_t i = 0; i < c->alias_count; i++)
        if (!strcmp(name, c->aliases[i].name)) {
            *port = c->aliases[i].port;
            strcpy(proto, c->aliases[i].protocol);
            return 0;
        }
    return cm_service(name, port, proto, e);
}
