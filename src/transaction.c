/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <stdlib.h>
#include <string.h>

static struct json_object *bundle(const struct cm_config *c, const struct cm_state *s)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "schema", json_object_new_int(1));
    json_object_object_add(o, "config", cm_config_json(c));
    json_object_object_add(o, "state", cm_state_json(s));
    json_object_object_add(o, "active", json_object_new_boolean(c->enabled));
    return o;
}
int cm_bundle_parse(struct json_object *o, struct cm_config *c, struct cm_state *s,
                    struct cm_error *e)
{
    static const char *const keys[] = {"schema", "config",           "state", "deadline",
                                       "active", "preserve_desired", NULL};
    uint64_t n;
    struct json_object *cfg, *state;
    if (!cm_keys(o, keys, e) || cm_get_int(o, "schema", 1, 1, &n, e) ||
        !json_object_object_get_ex(o, "config", &cfg) ||
        !json_object_object_get_ex(o, "state", &state))
        return cm_fail(e, "invalid recovery record");
    struct json_object *deadline;
    if (json_object_object_get_ex(o, "deadline", &deadline) &&
        cm_get_int(o, "deadline", 1, INT64_MAX, &n, e))
        return -1;
    bool preserve = false;
    if (json_object_object_get_ex(o, "preserve_desired", &deadline) &&
        cm_get_bool(o, "preserve_desired", &preserve, e))
        return -1;
    if (cm_config_parse(cfg, c, e) || cm_state_parse(state, s, e))
        return -1;
    return cm_get_bool(o, "active", &c->enabled, e);
}
int cm_committed_policy(const struct cm_paths *p, struct cm_config *c, struct cm_error *e)
{
    struct json_object *record = NULL;
    int r = cm_read_json(p->state, "committed.json", &record, e);
    if (r == 1) {
        cm_config_default(c);
        return 0;
    }
    if (r)
        return -1;
    struct cm_state *unused = cm_alloc(sizeof *unused);
    r = cm_bundle_parse(record, c, unused, e);
    free(unused);
    json_object_put(record);
    if (r)
        return -1;
    record = NULL;
    r = cm_read_json(p->run, "active.json", &record, e);
    if (r == 1) {
        c->enabled = false;
        return 0;
    }
    if (!r) {
        static const char *const keys[] = {"active", NULL};
        r = !cm_keys(record, keys, e) || cm_get_bool(record, "active", &c->enabled, e) ? -1 : 0;
        json_object_put(record);
    }
    return r;
}
static int save(const struct cm_paths *p, const struct cm_config *c, const struct cm_state *s,
                bool write_config, struct cm_error *e)
{
    struct json_object *cfg = cm_config_json(c), *state = cm_state_json(s);
    int r = write_config ? cm_write_json(p->config, "config.json", cfg, e) : 0;
    if (!r)
        r = cm_write_json(p->state, "state.json", state, e);
    json_object_put(cfg);
    json_object_put(state);
    if (r)
        return -1;
    struct json_object *active = json_object_new_object();
    json_object_object_add(active, "active", json_object_new_boolean(c->enabled));
    r = cm_write_json(p->run, "active.json", active, e);
    json_object_put(active);
    if (r)
        return -1;
    if (!p->offline) {
        struct json_object *snapshot = NULL;
        bool a, b;
        size_t foreign;
        if (cm_kernel_snapshot(&snapshot, &a, &b, &foreign, e))
            return -1;
        r = cm_write_json(p->state, "applied.json", snapshot, e);
        json_object_put(snapshot);
    }
    if (!r) {
        struct json_object *committed = bundle(c, s);
        r = cm_write_json(p->state, "committed.json", committed, e);
        json_object_put(committed);
    }
    return r;
}
static int restore(const struct cm_paths *p, struct json_object *record, struct cm_error *e)
{
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    int r = cm_bundle_parse(record, c, s, e);
    if (!r && !p->offline) {
        struct json_object *snapshot;
        bool a, b;
        size_t foreign;
        r = cm_kernel_snapshot(&snapshot, &a, &b, &foreign, e);
        if (!r) {
            json_object_put(snapshot);
            char *script = cm_firewall_script(c, s, a, b, true);
            r = cm_nft(script, false, NULL, e);
            free(script);
        }
    }
    bool preserve = false;
    struct json_object *flag = NULL;
    if (!r && json_object_object_get_ex(record, "preserve_desired", &flag))
        r = cm_get_bool(record, "preserve_desired", &preserve, e);
    if (!r)
        r = save(p, c, s, !preserve, e);
    free(c);
    free(s);
    return r;
}
static int stop_timer(const struct cm_paths *p, struct cm_error *e)
{
    if (p->offline)
        return 0;
    char *argv[] = {"systemctl", "stop", "command-center-rollback.timer", NULL};
    return cm_exec("/usr/bin/systemctl", argv, e);
}
static int start_timer(unsigned seconds, struct cm_error *e)
{
    char on[64];
    snprintf(on, sizeof on, "--on-active=%us", seconds);
    char *argv[] = {"systemd-run",
                    "--quiet",
                    "--unit=command-center-rollback",
                    "--collect",
                    on,
                    "--timer-property=AccuracySec=1s",
                    "--property=Restart=on-failure",
                    "--property=RestartSec=2s",
                    "--property=StartLimitIntervalSec=0",
                    "/usr/bin/command-center",
                    "rollback",
                    NULL};
    return cm_exec("/usr/bin/systemd-run", argv, e);
}
int cm_recover(const struct cm_paths *p, struct cm_error *e)
{
    struct json_object *o;
    int r = cm_read_json(p->state, "transaction.json", &o, e);
    if (r == 1)
        return 0;
    if (r)
        return -1;
    r = restore(p, o, e);
    json_object_put(o);
    if (!r)
        r = cm_remove(p->state, "transaction.json", e);
    if (!r) {
        cm_log("recovered interrupted transaction to previous configuration");
        fputs("Recovered the previous configuration.\n", stdout);
    }
    return r;
}
int cm_transaction(const struct cm_paths *p, const struct cm_config *c, const struct cm_state *s,
                   const struct cm_options *opt, bool replace, struct cm_error *e)
{
    if (opt->stage) {
        if (cm_exists(p->state, "pending.json") || cm_exists(p->state, "transaction.json"))
            return cm_fail(e, "resolve pending recovery before staging");
        if (opt->dry_run) {
            struct json_object *cfg = cm_config_json(c);
            puts(json_object_to_json_string_ext(cfg, JSON_C_TO_STRING_PRETTY));
            json_object_put(cfg);
            return 0;
        }
        struct json_object *cfg = cm_config_json(c);
        int staged = cm_write_json(p->config, "config.json", cfg, e);
        json_object_put(cfg);
        return staged;
    }
    if (cm_exists(p->state, "transaction.json"))
        return cm_fail(e, "an interrupted transaction needs recovery; run command-center recover");
    if (cm_exists(p->state, "pending.json"))
        return cm_fail(e, "a change awaits confirmation; run command-center confirm or rollback");
    struct cm_config *old = cm_alloc(sizeof *old);
    struct cm_state *previous = cm_alloc(sizeof *previous);
    int r = 0;
    struct json_object *committed = NULL;
    int checkpoint = cm_read_json(p->state, "committed.json", &committed, e);
    if (checkpoint < 0)
        r = -1;
    else if (checkpoint == 1)
        cm_config_default(old);
    else {
        r = cm_bundle_parse(committed, old, previous, e);
        json_object_put(committed);
    }
    if (!r)
        r = cm_state_load(p, previous, e);
    if (!r && !replace && !opt->state_only) {
        struct cm_config *file_config = cm_alloc(sizeof *file_config);
        r = cm_config_load(p, file_config, e);
        if (!r) {
            struct json_object *file = cm_config_json(file_config), *last = cm_config_json(old);
            if (!json_object_equal(file, last))
                r = cm_fail(e, "configuration was edited outside CM; validate it and explicitly "
                               "reload before using other mutation commands");
            json_object_put(file);
            json_object_put(last);
        }
        free(file_config);
    }
    bool a = false, b = false;
    size_t foreign = 0;
    if (!r && !p->offline) {
        int drift = cm_drift(p, &a, &b, &foreign, e);
        if (drift < 0)
            r = -1;
        else if (drift && !replace)
            r = cm_fail(e, "managed nftables rules changed outside Command Center; inspect status, "
                           "then explicitly reload to restore saved policy");
    }
    if (r) {
        free(old);
        free(previous);
        return -1;
    }
    struct json_object *next_config = cm_config_json(c), *old_config = cm_config_json(old);
    bool config_changed = !json_object_equal(next_config, old_config);
    json_object_put(next_config);
    json_object_put(old_config);
    bool activation = c->enabled != old->enabled;
    if (opt->state_only && (config_changed || activation)) {
        free(old);
        free(previous);
        return cm_fail(e, "state-only transactions cannot change policy or activation");
    }
    char *script = cm_firewall_script(c, s, a, b, config_changed || replace || activation);
    if (opt->dry_run) {
        struct json_object *candidate = cm_config_json(c);
        printf("# Proposed configuration: %s\n",
               json_object_to_json_string_ext(candidate, JSON_C_TO_STRING_PLAIN));
        json_object_put(candidate);
        fputs(script, stdout);
        if (!p->offline)
            r = cm_nft(script, true, NULL, e);
        free(script);
        free(old);
        free(previous);
        return r;
    }
    if (!p->offline && cm_nft(script, true, NULL, e)) {
        free(script);
        free(old);
        free(previous);
        return -1;
    }
    struct json_object *prior = bundle(old, previous);
    if (opt->state_only)
        json_object_object_add(prior, "preserve_desired", json_object_new_boolean(true));
    bool guarded = !opt->no_rollback && opt->rollback &&
                   (config_changed || activation || replace) && (c->enabled || old->enabled);
    if (activation && !config_changed && !replace && !c->rule_count && !c->guard_enabled &&
        !c->input_drop && !c->output_drop && !s->ban_count)
        guarded = false; /* A fresh passive start changes no filtering behavior. */
    if (guarded) {
        json_object_object_add(prior, "deadline", json_object_new_uint64(cm_now() + opt->rollback));
        r = cm_write_json(p->state, "pending.json", prior, e);
        if (!r && !p->offline)
            r = start_timer(opt->rollback, e);
        if (r) {
            struct cm_error ignored;
            cm_remove(p->state, "pending.json", &ignored);
        }
    }
    if (!r)
        r = cm_write_json(p->state, "transaction.json", prior, e);
    if (!r && !p->offline)
        r = cm_nft(script, false, NULL, e);
    if (!r)
        r = save(p, c, s, !opt->state_only, e);
    if (!r)
        r = cm_remove(p->state, "transaction.json", e);
    if (r) {
        char original[sizeof e->text];
        strcpy(original, e->text);
        struct cm_error recovery;
        if (cm_exists(p->state, "transaction.json") && restore(p, prior, &recovery) == 0) {
            cm_remove(p->state, "transaction.json", &recovery);
            if (guarded) {
                stop_timer(p, &recovery);
                cm_remove(p->state, "pending.json", &recovery);
            }
            cm_fail(e, "%s; previous configuration restored", original);
        } else if (cm_exists(p->state, "transaction.json"))
            cm_fail(e, "%s; recovery record retained: %s", original, recovery.text);
        else if (guarded) {
            stop_timer(p, &recovery);
            cm_remove(p->state, "pending.json", &recovery);
        }
    } else {
        if (foreign)
            fprintf(
                stderr,
                "Notice: %zu other nftables base chain(s) can affect traffic outside CM's scope.\n",
                foreign);
        if (guarded)
            printf("Change pending: confirm from a new connection within %u seconds using "
                   "'command-center confirm'.\n",
                   opt->rollback);
        cm_log("configuration/state transaction committed%s",
               guarded ? "; confirmation pending" : "");
    }
    json_object_put(prior);
    free(script);
    free(old);
    free(previous);
    return r;
}
int cm_confirm(const struct cm_paths *p, struct cm_error *e)
{
    if (cm_exists(p->state, "transaction.json"))
        return cm_fail(e, "recover the interrupted transaction before confirming");
    struct json_object *o;
    int r = cm_read_json(p->state, "pending.json", &o, e);
    if (r == 1)
        return cm_fail(e, "no change is awaiting confirmation");
    if (r)
        return -1;
    uint64_t deadline;
    r = cm_get_int(o, "deadline", 1, INT64_MAX, &deadline, e);
    json_object_put(o);
    if (r)
        return -1;
    if (cm_now() >= deadline)
        return cm_fail(e, "confirmation deadline expired; run command-center rollback");
    int configuration_drift = cm_config_drift(p, e);
    if (configuration_drift)
        return configuration_drift < 0
                   ? -1
                   : cm_fail(e, "saved configuration changed; refusing to confirm");
    bool a, b;
    size_t foreign;
    if (!p->offline) {
        r = cm_drift(p, &a, &b, &foreign, e);
        if (r)
            return r < 0 ? -1 : cm_fail(e, "live policy changed; refusing to confirm");
    }
    if (cm_remove(p->state, "pending.json", e))
        return -1;
    struct cm_error cleanup;
    if (stop_timer(p, &cleanup))
        cm_log("change confirmed; transient timer cleanup failed: %s", cleanup.text);
    cm_log("firewall change confirmed");
    puts("Change confirmed.");
    return 0;
}
int cm_rollback(const struct cm_paths *p, struct cm_error *e)
{
    struct json_object *o;
    int r = cm_read_json(p->state, "pending.json", &o, e);
    if (r == 1) {
        puts("No pending change.");
        return 0;
    }
    if (r)
        return -1;
    /* The durable transaction record also protects a crash during rollback. */
    r = cm_write_json(p->state, "transaction.json", o, e);
    if (!r)
        r = restore(p, o, e);
    json_object_put(o);
    if (!r)
        r = cm_remove(p->state, "transaction.json", e);
    if (!r)
        r = cm_remove(p->state, "pending.json", e);
    if (!r) {
        struct cm_error ignored;
        stop_timer(p, &ignored);
        cm_log("pending firewall change rolled back");
        puts("Previous configuration restored.");
    }
    return r;
}
int cm_restore_config(const struct cm_paths *p, struct cm_error *e)
{
    if (cm_exists(p->state, "transaction.json") || cm_exists(p->state, "pending.json"))
        return cm_fail(e,
                       "recover or roll back the pending operation before restoring configuration");
    struct json_object *record = NULL;
    int r = cm_read_json(p->state, "committed.json", &record, e);
    if (r == 1)
        return cm_fail(e, "no committed configuration is available");
    if (r)
        return -1;
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    r = cm_bundle_parse(record, c, s, e);
    json_object_put(record);
    if (!r) {
        struct json_object *cfg = cm_config_json(c);
        r = cm_write_json(p->config, "config.json", cfg, e);
        json_object_put(cfg);
    }
    free(c);
    free(s);
    if (!r)
        puts("Last committed configuration restored; use reload to restore live rule drift.");
    return r;
}
int cm_apply(const struct cm_paths *p, struct cm_error *e)
{
    bool boot = !cm_exists(p->run, "active.json");
    int r = cm_recover(p, e);
    if (!r && cm_exists(p->state, "pending.json") && boot)
        r = cm_rollback(p, e);
    if (r)
        return -1;
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    struct json_object *record = NULL;
    r = cm_read_json(p->state, "committed.json", &record, e);
    bool fresh = r == 1;
    if (r == 1) {
        cm_config_default(c);
        memset(s, 0, sizeof *s);
        r = 0;
    } else if (!r) {
        r = cm_bundle_parse(record, c, s, e);
        json_object_put(record);
    }
    c->enabled = true;
    bool state_failed = false;
    char state_error[1024] = {0};
    if (!r) {
        struct cm_state *current = cm_alloc(sizeof *current);
        if (cm_state_load(p, current, e)) {
            state_failed = true;
            strcpy(state_error, e->text);
            cm_log("boot uses checkpoint bans because current state is invalid: %s", state_error);
        } else
            *s = *current;
        free(current);
    }
    if (!r && !p->offline) {
        bool a, b;
        size_t foreign;
        struct json_object *snapshot = NULL;
        r = cm_kernel_snapshot(&snapshot, &a, &b, &foreign, e);
        if (!r) {
            json_object_put(snapshot);
            char *script = cm_firewall_script(c, s, a, b, true);
            r = cm_nft(script, false, NULL, e);
            free(script);
        }
        if (!r) {
            r = cm_kernel_snapshot(&snapshot, &a, &b, &foreign, e);
            if (!r) {
                r = cm_write_json(p->state, "applied.json", snapshot, e);
                json_object_put(snapshot);
            }
        }
    }
    if (!r) {
        if (fresh && !cm_exists(p->config, "config.json")) {
            struct json_object *cfg = cm_config_json(c);
            r = cm_write_json(p->config, "config.json", cfg, e);
            json_object_put(cfg);
        }
        if (!r && fresh && !cm_exists(p->state, "state.json")) {
            struct json_object *state = cm_state_json(s);
            r = cm_write_json(p->state, "state.json", state, e);
            json_object_put(state);
        }
        struct json_object *active = json_object_new_object();
        json_object_object_add(active, "active", json_object_new_boolean(true));
        if (!r)
            r = cm_write_json(p->run, "active.json", active, e);
        json_object_put(active);
        if (!r && !state_failed) {
            struct json_object *committed = bundle(c, s);
            r = cm_write_json(p->state, "committed.json", committed, e);
            json_object_put(committed);
        }
    }
    free(c);
    free(s);
    if (!r)
        cm_log("last committed firewall policy loaded");
    if (!r && state_failed)
        return cm_fail(
            e, "committed policy/checkpoint bans loaded, but current state needs recovery: %s",
            state_error);
    return r;
}
int cm_restore_checkpoint(const struct cm_paths *p, struct cm_error *e)
{
    if (cm_exists(p->state, "transaction.json") || cm_exists(p->state, "pending.json"))
        return cm_fail(
            e,
            "ordinary recovery/rollback must resolve existing intent before checkpoint recovery");
    struct json_object *record = NULL;
    int r = cm_read_json(p->state, "committed.json", &record, e);
    if (r == 1)
        return cm_fail(e, "no committed checkpoint is available");
    if (r)
        return -1;
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    r = cm_bundle_parse(record, c, s, e);
    free(c);
    free(s);
    if (!r)
        r = cm_write_json(p->state, "transaction.json", record, e);
    if (!r)
        r = restore(p, record, e);
    json_object_put(record);
    if (!r)
        r = cm_remove(p->state, "transaction.json", e);
    if (!r) {
        puts("Committed configuration and state checkpoint restored.");
        cm_log("explicit committed checkpoint recovery completed");
    }
    return r;
}

int cm_suspend(const struct cm_paths *p, struct cm_error *e)
{
    if (cm_exists(p->state, "pending.json") && cm_rollback(p, e))
        return -1;
    if (cm_recover(p, e))
        return -1;
    struct json_object *record = NULL;
    int r = cm_read_json(p->state, "committed.json", &record, e);
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    if (r == 1) {
        cm_config_default(c);
        r = 0;
        record = bundle(c, s);
    } else if (!r)
        r = cm_bundle_parse(record, c, s, e);
    if (!r)
        json_object_object_add(record, "preserve_desired", json_object_new_boolean(true));
    if (!r)
        r = cm_write_json(p->state, "transaction.json", record, e);
    if (!r && !p->offline) {
        struct json_object *snapshot = NULL;
        bool a, b;
        size_t foreign;
        r = cm_kernel_snapshot(&snapshot, &a, &b, &foreign, e);
        if (!r) {
            json_object_put(snapshot);
            struct cm_config stopped = {0};
            char *script = cm_firewall_script(&stopped, s, a, b, true);
            r = cm_nft(script, false, NULL, e);
            free(script);
        }
        if (!r) {
            r = cm_kernel_snapshot(&snapshot, &a, &b, &foreign, e);
            if (!r) {
                r = cm_write_json(p->state, "applied.json", snapshot, e);
                json_object_put(snapshot);
            }
        }
    }
    if (!r) {
        struct json_object *active = json_object_new_object();
        json_object_object_add(active, "active", json_object_new_boolean(false));
        r = cm_write_json(p->run, "active.json", active, e);
        json_object_put(active);
    }
    if (!r) {
        json_object_object_add(record, "active", json_object_new_boolean(false));
        json_object_object_del(record, "preserve_desired");
        r = cm_write_json(p->state, "committed.json", record, e);
    }
    if (!r)
        r = cm_remove(p->state, "transaction.json", e);
    if (record)
        json_object_put(record);
    free(c);
    free(s);
    return r;
}
