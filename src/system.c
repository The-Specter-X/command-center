/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-journal.h>
#include <time.h>
#include <unistd.h>

static int open_bus(sd_bus **bus, struct cm_error *e)
{
    int r = sd_bus_open_system(bus);
    return r < 0 ? cm_fail(e, "system bus: %s", strerror(-r)) : 0;
}
int cm_systemd_state(const char *unit, const char *property, char *out, size_t cap,
                     struct cm_error *e)
{
    sd_bus *bus = NULL;
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    if (open_bus(&bus, e))
        return -1;
    int r = sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager", "LoadUnit", &error, &reply, "s",
                               unit);
    const char *path = NULL;
    if (r >= 0)
        r = sd_bus_message_read(reply, "o", &path);
    char *value = NULL;
    if (r >= 0)
        r = sd_bus_get_property_string(bus, "org.freedesktop.systemd1", path,
                                       "org.freedesktop.systemd1.Unit", property, &error, &value);
    if (r >= 0) {
        if (strlen(value) >= cap)
            r = -EOVERFLOW;
        else
            strcpy(out, value);
    }
    if (r < 0)
        cm_fail(e, "systemd %s/%s: %s", unit, property,
                error.message ? error.message : strerror(-r));
    free(value);
    sd_bus_message_unref(reply);
    sd_bus_error_free(&error);
    sd_bus_unref(bus);
    return r < 0 ? -1 : 0;
}
static int unit_busy(const char *unit, bool *busy, struct cm_error *e)
{
    sd_bus *bus = NULL;
    sd_bus_message *reply = NULL, *property = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    if (open_bus(&bus, e))
        return -1;
    int r = sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager", "LoadUnit", &error, &reply, "s",
                               unit);
    const char *path = NULL, *job_path = NULL;
    uint32_t id = 0;
    if (r >= 0)
        r = sd_bus_message_read(reply, "o", &path);
    if (r >= 0)
        r = sd_bus_get_property(bus, "org.freedesktop.systemd1", path,
                                "org.freedesktop.systemd1.Unit", "Job", &error, &property, "(uo)");
    if (r >= 0)
        r = sd_bus_message_read(property, "(uo)", &id, &job_path);
    if (r < 0)
        cm_fail(e, "systemd job: %s", error.message ? error.message : strerror(-r));
    *busy = id != 0;
    sd_bus_message_unref(property);
    sd_bus_message_unref(reply);
    sd_bus_error_free(&error);
    sd_bus_unref(bus);
    return r < 0 ? -1 : 0;
}
int cm_systemd(const char *action, bool guard, struct cm_error *e)
{
    sd_bus *bus = NULL;
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    if (open_bus(&bus, e))
        return -1;
    const char *unit = guard ? "command-center-guard.service" : "command-center.service";
    int r;
    if (!strcmp(action, "enable"))
        r = sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager", "EnableUnitFiles", &error,
                               &reply, "asbb", 1, unit, 0, 0);
    else if (!strcmp(action, "disable"))
        r = sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager", "DisableUnitFiles", &error,
                               &reply, "asb", 1, unit, 0);
    else
        r = sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               !strcmp(action, "stop") ? "StopUnit" : "StartUnit", &error, &reply,
                               "ss", unit, "replace");
    if (r < 0)
        cm_fail(e, "systemd %s %s: %s", action, unit, error.message ? error.message : strerror(-r));
    sd_bus_message_unref(reply);
    reply = NULL;
    if (r >= 0 && (!strcmp(action, "enable") || !strcmp(action, "disable")))
        r = sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager", "Reload", &error, &reply, "");
    if (r < 0 && !*e->text)
        cm_fail(e, "systemd reload: %s", error.message ? error.message : strerror(-r));
    sd_bus_message_unref(reply);
    sd_bus_error_free(&error);
    sd_bus_unref(bus);
    if (r < 0)
        return -1;
    if (!strcmp(action, "start") || !strcmp(action, "stop")) {
        for (unsigned i = 0; i < 150; i++) {
            char state[64];
            bool busy = false;
            if (cm_systemd_state(unit, "ActiveState", state, sizeof state, e))
                return -1;
            if (unit_busy(unit, &busy, e))
                return -1;
            if (!strcmp(state, "failed"))
                return cm_fail(e, "%s failed; inspect cm logs", unit);
            if (!busy && !strcmp(action, "stop") && !strcmp(state, "inactive"))
                return 0;
            if (!busy && !strcmp(action, "start") && !strcmp(state, "active"))
                return 0;
            if (!busy && guard && !strcmp(state, "inactive"))
                return 0; /* disabled ExecCondition */
            struct timespec t = {.tv_nsec = 200000000};
            nanosleep(&t, NULL);
        }
        return cm_fail(e, "systemd operation did not finish within 30 seconds");
    }
    return 0;
}
static volatile sig_atomic_t log_stop;
int cm_reconcile_guard(const struct cm_paths *p, struct cm_error *e)
{
    int lock = cm_read_lock(p, e);
    for (unsigned i = 0; lock == -3 && i < 100; i++) {
        usleep(50000);
        lock = cm_read_lock(p, e);
    }
    if (lock < 0)
        return -1;
    struct cm_config *c = cm_alloc(sizeof *c);
    int r = cm_committed_policy(p, c, e);
    bool active = c->enabled && c->guard_enabled;
    if (!r && !c->activation_known)
        r = cm_fail(e, "activation unknown; reconcile with start or stop");
    free(c);
    close(lock);
    if (r)
        return -1;
    if (!active) {
        char service[64];
        struct cm_error ignored = {0};
        if (cm_systemd_state("command-center-guard.service", "ActiveState", service,
                            sizeof service, &ignored) || !strcmp(service, "inactive") ||
            !strcmp(service, "failed"))
            return 0;
    }
    return cm_systemd(active ? "start" : "stop", true, e);
}
int cm_stop(const struct cm_paths *p, struct cm_error *e)
{
    struct cm_error service_error = {0};
    int stopped = cm_systemd("stop", false, &service_error);
    /* A failed loader never ran ExecStop. Explicit cleanup must run regardless. */
    int lock = cm_lock(p, e);
    for (unsigned i = 0; lock < 0 && i < 100; i++) {
        usleep(50000);
        lock = cm_lock(p, e);
    }
    if (lock < 0)
        return -1;
    int r = cm_suspend(p, e);
    close(lock);
    if (r)
        return -1;
    char guard[64];
    if (cm_systemd_state("command-center-guard.service", "ActiveState", guard, sizeof guard, e))
        return -1;
    if (strcmp(guard, "inactive") && strcmp(guard, "failed"))
        return cm_systemd("stop", true, e);
    if (stopped)
        cm_log("loader stop reported %s; explicit CM cleanup verified", service_error.text);
    return 0;
}
static void log_signal(int signal_number)
{
    (void)signal_number;
    log_stop = 1;
}
static int severity(const char *s)
{
    if (!strcmp(s, "debug"))
        return 7;
    if (!strcmp(s, "info"))
        return 6;
    if (!strcmp(s, "notice"))
        return 5;
    if (!strcmp(s, "warning"))
        return 4;
    if (!strcmp(s, "error"))
        return 3;
    if (!strcmp(s, "critical"))
        return 2;
    return -1;
}
int cm_logs(const struct cm_paths *p, int argc, char **argv, bool json, struct cm_error *e)
{
    if (p->offline)
        return cm_fail(e, "offline mode cannot read the system journal");
    bool follow = false;
    unsigned since = 3600, lines = 200;
    int level = 6;
    if (geteuid() == 0) {
        struct cm_config *c = cm_alloc(sizeof *c);
        int cr = cm_committed_policy(p, c, e);
        if (!cr)
            level = (int)c->log_level;
        free(c);
        if (cr)
            return -1;
    }
    log_stop = 0;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--follow")) {
            follow = true;
            continue;
        }
        if (i + 1 >= argc)
            return cm_fail(e, "log option needs a value");
        const char *key = argv[i++];
        if (!strcmp(key, "--since")) {
            if (cm_duration(argv[i], &since, e))
                return -1;
        } else if (!strcmp(key, "--level")) {
            level = severity(argv[i]);
            if (level < 0)
                return cm_fail(e, "invalid severity");
        } else if (!strcmp(key, "--lines")) {
            uint64_t n;
            if (cm_uint(argv[i], 1, 10000, &n, e))
                return -1;
            lines = (unsigned)n;
        } else
            return cm_fail(e, "unknown log option");
    }
    sd_journal *j = NULL;
    int r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
    if (r < 0)
        return cm_fail(e, "journal open: %s", strerror(-r));
    r = sd_journal_add_match(j, "SYSLOG_IDENTIFIER=command-center", 0);
    if (r >= 0)
        r = sd_journal_add_match(j, "_UID=0", 0);
    if (r >= 0)
        r = sd_journal_add_disjunction(j);
    if (r >= 0)
        r = sd_journal_add_match(j, "_TRANSPORT=kernel", 0);
    if (r >= 0)
        r = sd_journal_seek_realtime_usec(j, (cm_now() > since ? cm_now() - since : 0) * 1000000);
    struct json_object *records = json_object_new_array();
    struct sigaction oldint = {0}, oldterm = {0}, sa = {0};
    sa.sa_handler = log_signal;
    sigemptyset(&sa.sa_mask);
    if (follow) {
        log_stop = 0;
        if (sigaction(SIGINT, &sa, &oldint) || sigaction(SIGTERM, &sa, &oldterm)) {
            sd_journal_close(j);
            json_object_put(records);
            return cm_fail(e, "log signal setup failed");
        }
    }
    while (r >= 0 && !log_stop) {
        r = sd_journal_next(j);
        if (r == 0) {
            if (!follow)
                break;
            r = sd_journal_wait(j, 1000000);
            if (r == -EINTR)
                r = 0;
            continue;
        }
        if (r < 0)
            break;
        const void *raw = NULL;
        size_t length = 0;
        uint64_t timestamp = 0;
        if (sd_journal_get_data(j, "MESSAGE", &raw, &length) < 0 || length <= 8 || length > 65544)
            continue;
        char *message = cm_alloc(length - 7);
        memcpy(message, (const char *)raw + 8, length - 8);
        bool kernel = sd_journal_get_data(j, "_TRANSPORT", &raw, &length) >= 0 && length == 17 &&
                      !memcmp(raw, "_TRANSPORT=kernel", 17);
        if (kernel && strncmp(message, "CM-", 3)) {
            free(message);
            continue;
        }
        int priority = 6;
        if (sd_journal_get_data(j, "PRIORITY", &raw, &length) >= 0 && length == 10 &&
            ((const char *)raw)[9] >= '0' && ((const char *)raw)[9] <= '7')
            priority = ((const char *)raw)[9] - '0';
        if (priority > level) {
            free(message);
            continue;
        }
        sd_journal_get_realtime_usec(j, &timestamp);
        struct json_object *v = json_object_new_object();
        json_object_object_add(v, "time_usec", json_object_new_uint64(timestamp));
        json_object_object_add(v, "priority", json_object_new_int(priority));
        json_object_object_add(v, "message", json_object_new_string(message));
        const char *fields[] = {"CM_COMPONENT", "CM_ACTION", "CM_RULE_ID", "CM_ADDRESS"};
        const char *keys[] = {"component", "action", "rule_id", "address"};
        for (size_t i = 0; i < 4; i++) {
            size_t prefix = strlen(fields[i]) + 1;
            if (sd_journal_get_data(j, fields[i], &raw, &length) >= 0 &&
                length > prefix && length - prefix <= 4096 &&
                !memchr((const char *)raw + prefix, 0, length - prefix))
                json_object_object_add(v, keys[i],
                    json_object_new_string_len((const char *)raw + prefix, (int)(length - prefix)));
        }
        free(message);
        if (follow) {
            if (json)
                puts(json_object_to_json_string_ext(v, JSON_C_TO_STRING_PLAIN));
            else
                printf("%llu priority=%d %s\n", (unsigned long long)timestamp, priority,
                       json_object_to_json_string_ext(v, JSON_C_TO_STRING_PLAIN));
            fflush(stdout);
            json_object_put(v);
        } else {
            json_object_array_add(records, v);
            if (json_object_array_length(records) > lines)
                json_object_array_del_idx(records, 0, 1);
        }
    }
    if (follow) {
        sigaction(SIGINT, &oldint, NULL);
        sigaction(SIGTERM, &oldterm, NULL);
    } else if (json)
        puts(json_object_to_json_string_ext(records, JSON_C_TO_STRING_PRETTY));
    else
        for (size_t i = 0; i < json_object_array_length(records); i++)
            puts(json_object_to_json_string_ext(json_object_array_get_idx(records, i),
                                                JSON_C_TO_STRING_PLAIN));
    json_object_put(records);
    sd_journal_close(j);
    return r < 0 ? cm_fail(e, "journal read: %s", strerror(-r)) : 0;
}
