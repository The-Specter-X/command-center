/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int sig)
{
    (void)sig;
    stopping = 1;
}
int cm_guard_parse(const char *message, char *ip, size_t cap)
{
    const char *prefixes[] = {"Failed password for ", "Failed publickey for ",
                              "Failed keyboard-interactive/pam for "};
    bool matched = false;
    for (size_t i = 0; i < 3; i++)
        if (!strncmp(message, prefixes[i], strlen(prefixes[i])))
            matched = true;
    if (!matched || strlen(message) > 4096)
        return 0;
    /* Use the final delimiter: an attacker-controlled username can contain 'from'. */
    const char *from = NULL, *p = message;
    while ((p = strstr(p, " from "))) {
        from = p + 6;
        p += 6;
    }
    if (!from)
        return 0;
    const char *port = strstr(from, " port ");
    if (!port || port == from || (size_t)(port - from) >= CM_ADDRESS_MAX)
        return 0;
    char raw[CM_ADDRESS_MAX];
    memcpy(raw, from, (size_t)(port - from));
    raw[port - from] = 0;
    p = port + 6;
    const char *end = p;
    while (*end >= '0' && *end <= '9')
        end++;
    if (end == p || strncmp(end, " ssh2", 5))
        return 0;
    if (end[5] && end[5] != ' ' && end[5] != ':')
        return 0;
    if ((size_t)(end - p) > 5)
        return 0;
    char number[6];
    memcpy(number, p, (size_t)(end - p));
    number[end - p] = 0;
    struct cm_error error;
    uint64_t n;
    if (cm_uint(number, 1, 65535, &n, &error) || cm_address(raw, false, ip, cap, &error))
        return 0;
    return 1;
}
int cm_guard_event(const struct cm_config *c, struct cm_state *s, const char *ip, uint64_t now,
                   bool *banned, struct cm_error *e)
{
    *banned = false;
    if (!c->guard_enabled || cm_ignored(c, ip))
        return 0;
    cm_state_expire(s, now);
    size_t active = 0;
    for (size_t i = 0; i < s->attempt_count; i++) {
        struct cm_attempt *a = &s->attempts[i];
        size_t count = 0;
        for (size_t j = 0; j < a->count; j++)
            if (a->times[j] <= now && now - a->times[j] < c->window)
                a->times[count++] = a->times[j];
        a->count = count;
        if (count)
            s->attempts[active++] = *a;
    }
    s->attempt_count = active;
    for (size_t i = 0; i < s->ban_count; i++)
        if (s->bans[i].automatic && !strcmp(s->bans[i].address, ip))
            return 0;
    size_t index = s->attempt_count;
    for (size_t i = 0; i < s->attempt_count; i++)
        if (!strcmp(s->attempts[i].address, ip)) {
            index = i;
            break;
        }
    if (index == s->attempt_count) {
        if (index == CM_MAX_ATTEMPTS)
            return cm_fail(e, "SSH failure tracking capacity reached");
        memset(&s->attempts[index], 0, sizeof s->attempts[index]);
        strcpy(s->attempts[index].address, ip);
        s->attempt_count++;
    }
    struct cm_attempt *a = &s->attempts[index];
    if (a->count && now < a->times[a->count - 1])
        return 0;
    if (a->count == 100)
        return cm_fail(e, "SSH failure count capacity reached");
    a->times[a->count++] = now;
    if (a->count >= c->threshold) {
        if (cm_state_ban_scoped(s, ip, c->duration ? now + c->duration : INT64_MAX, true,
                                c->guard_all, e))
            return -1;
        memmove(a, a + 1, (s->attempt_count - index - 1) * sizeof *a);
        s->attempt_count--;
        *banned = true;
    }
    return 0;
}
static int cursor(sd_journal *journal, char *dst, size_t cap, struct cm_error *e)
{
    char *value = NULL;
    int r = sd_journal_get_cursor(journal, &value);
    if (r < 0)
        return cm_fail(e, "journal cursor: %s", strerror(-r));
    if (strlen(value) >= cap) {
        free(value);
        return cm_fail(e, "journal cursor is too long");
    }
    strcpy(dst, value);
    free(value);
    return 0;
}
static int seek(sd_journal *j, struct cm_state *s, struct cm_error *e)
{
    if (*s->cursor) {
        int r = sd_journal_seek_cursor(j, s->cursor);
        if (r < 0)
            return cm_fail(e, "journal seek: %s", strerror(-r));
        r = sd_journal_next(j);
        if (r < 0)
            return cm_fail(e, "journal next: %s", strerror(-r));
        if (r > 0 && sd_journal_test_cursor(j, s->cursor) > 0)
            return 0;
        cm_log("saved SSH journal cursor unavailable; starting at current journal tail");
    }
    int r = sd_journal_seek_tail(j);
    if (r < 0)
        return cm_fail(e, "journal tail: %s", strerror(-r));
    r = sd_journal_previous(j);
    if (r < 0)
        return cm_fail(e, "journal previous: %s", strerror(-r));
    if (r > 0)
        return cursor(j, s->cursor, sizeof s->cursor, e);
    *s->cursor = 0;
    return 0;
}
int cm_guard_run(const struct cm_paths *p, struct cm_error *e)
{
    if (p->offline)
        return cm_fail(e, "the SSH monitor is unavailable in offline mode");
    int reader_lock = cm_guard_lock(p, e);
    if (reader_lock < 0) {
        char why[sizeof e->text];
        strcpy(why, e->text);
        return cm_fail(e, "SSH reader guard.lock: %s", why);
    }
    struct sigaction action = {0};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) < 0 || sigaction(SIGINT, &action, NULL) < 0) {
        close(reader_lock);
        return cm_fail(e, "signal setup: %s", strerror(errno));
    }
    sd_journal *journal = NULL;
    int r = sd_journal_open(&journal, SD_JOURNAL_LOCAL_ONLY);
    if (r < 0) {
        close(reader_lock);
        return cm_fail(e, "open system journal: %s", strerror(-r));
    }
    const char *matches[] = {"_UID=0", "_SYSTEMD_UNIT=ssh.service", "_SYSTEMD_UNIT=sshd.service",
                             "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session"};
    for (size_t i = 0; i < sizeof matches / sizeof *matches; i++)
        if ((r = sd_journal_add_match(journal, matches[i], 0)) < 0) {
            sd_journal_close(journal);
            close(reader_lock);
            return cm_fail(e, "journal match: %s", strerror(-r));
        }
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    bool positioned = false, ready = false;
    r = 0;
    while (!stopping) {
        struct cm_error busy;
        int lock = cm_lock(p, &busy);
        if (lock < 0) {
            if (lock != -2) {
                r = cm_fail(e, "SSH guard lock failed: %s", busy.text);
                break;
            }
            usleep(200000);
            continue;
        }
        if (cm_committed_policy(p, c, e) || cm_state_load(p, s, e)) {
            close(lock);
            r = -1;
            break;
        }
        if (!c->guard_enabled || !c->enabled) {
            close(lock);
            break;
        }
        if (cm_exists(p->state, "transaction.json")) {
            close(lock);
            r = cm_fail(e, "recover the interrupted transaction before running the SSH monitor");
            break;
        }
        if (!positioned) {
            if (seek(journal, s, e)) {
                close(lock);
                r = -1;
                break;
            }
            positioned = true;
        }
        if (!ready) {
            sd_notify(0, "READY=1");
            ready = true;
        }
        if (cm_exists(p->state, "pending.json")) {
            close(lock);
            usleep(200000);
            continue;
        }
        bool changed = false, new_ban = false;
        unsigned entries = 0;
        uint64_t now = cm_now();
        while (entries++ < 128 && (r = sd_journal_next(journal)) > 0) {
            uint64_t realtime;
            const void *data;
            size_t length;
            if (sd_journal_get_realtime_usec(journal, &realtime) >= 0 &&
                realtime / 1000000 <= now && now - realtime / 1000000 < c->window &&
                sd_journal_get_data(journal, "MESSAGE", &data, &length) >= 0 && length > 8 &&
                length <= 4104) {
                const char *bytes = data;
                char message[4097], ip[CM_ADDRESS_MAX];
                size_t n = length - 8;
                if (!memchr(bytes + 8, 0, n)) {
                    memcpy(message, bytes + 8, n);
                    message[n] = 0;
                    if (cm_guard_parse(message, ip, sizeof ip)) {
                        bool banned = false;
                        if (cm_guard_event(c, s, ip, realtime / 1000000, &banned, e)) {
                            r = -1;
                            break;
                        }
                        if (banned) {
                            new_ban = true;
                            cm_log("SSH authentication threshold reached for %s", ip);
                        }
                    }
                }
            }
            if (cursor(journal, s->cursor, sizeof s->cursor, e)) {
                r = -1;
                break;
            }
            changed = true;
        }
        if (r < 0) {
            if (!*e->text)
                cm_fail(e, "journal read failed: %s", strerror(-r));
            close(lock);
            r = -1;
            break;
        }
        if (changed || !positioned) {
            if (new_ban) {
                struct cm_options opt = {.no_rollback = true, .state_only = true};
                r = cm_transaction(p, c, s, &opt, false, e);
            } else {
                struct json_object *state = cm_state_json(s);
                r = cm_write_json(p->state, "state.json", state, e);
                json_object_put(state);
            }
        }
        close(lock);
        if (r < 0)
            break;
        if (!ready) {
            sd_notify(0, "READY=1");
            ready = true;
        }
        if (entries <= 128) {
            r = sd_journal_wait(journal, 1000000);
            if (r < 0 && r != -EINTR) {
                cm_fail(e, "journal wait: %s", strerror(-r));
                r = -1;
                break;
            }
        }
        r = 0;
    }
    free(c);
    free(s);
    sd_journal_close(journal);
    close(reader_lock);
    return r < 0 ? -1 : 0;
}
