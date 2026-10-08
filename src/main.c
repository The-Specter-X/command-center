/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void cm_help(FILE *f)
{
    fputs(
        "Command Center " CM_VERSION "\nUsage: cm [OPTIONS] COMMAND [ARGUMENTS]\n\n"
        "Firewall: allow|deny|reject|limit [in|out] SERVICE [--from CIDR] [--to CIDR]\n"
        "          [--interface NAME] [--family 4|6|any] [--comment TEXT]\n"
        "          limit also accepts --rate N/second|minute|hour --burst N\n"
        "  rules | delete NUMBER | move NUMBER before NUMBER\n"
        "  default in|out allow|deny | status | reload | plan | export | check | doctor\n"
        "  start | stop | enable [--now] | disable [--now]\n"
        "  confirm | rollback | recover [checkpoint] | init\n"
        "  profiles | profile show NAME | use NAME [--ssh-port PORT/tcp] [--keep-rules]\n"
        "  services | service show NAME | service set NAME PORT/tcp|udp | service delete NAME\n"
        "  protect ssh [--failures N] [--window DURATION] [--ban DURATION|permanent]\n"
        "              [--scope ssh|all] [--port PORT/tcp]\n"
        "  protect ssh status|disable | protect ssh ignore add|delete CIDR\n"
        "  ban IP [--for DURATION|permanent] [--scope all|ssh] | unban IP | bans\n"
        "  logging level debug|info|notice|warning|error|critical | logging packets off|low|medium|high\n"
        "  logs [--since DURATION] [--level SEVERITY] [--lines N] [--follow]\n"
        "  net [addresses|interfaces|routes|dns|listeners]\n"
        "  net route get ADDRESS | net public-ip [--family 4|6] [--url HTTPS_URL]\n"
        "  info | cpu | memory | disk | inode | os | hardware | time | timezone\n"
        "  updates status|enable|disable|check|run|logs\n"
        "  updates reboot on|off | updates schedule HH:MM|default\n"
        "  config show|validate|restore | help | version\n\n"
        "Options: --json --dry-run --stage --root DIRECTORY (offline)\n"
        "         --timeout SECONDS (confirmation; default 120) --no-rollback\n"
        "         --interval MS (CPU sample; default 1000; 250..10000)\n"
        "Profiles: passive, guard-only, web-server, ssh-only, isolation.\n"
        "Durations: integer with optional s/m/h/d; permanent only for bans.\n"
        "Start preserves other tables and initially adds no restrictions.\n"
        "CM does not manage forwarding/NAT or claim to protect Docker-published ports.\n"
        "See docs/COMMANDS.md for exact semantics and recovery.\n",
        f);
}
static bool report(const char *s)
{
    return !strcmp(s, "cpu") || !strcmp(s, "memory") || !strcmp(s, "disk") || !strcmp(s, "inode") ||
           !strcmp(s, "os") || !strcmp(s, "hardware") || !strcmp(s, "time") ||
           !strcmp(s, "timezone");
}
static bool local_option(const char *s)
{
    const char *names[] = {"--from",  "--to",    "--interface", "--family", "--comment",
                           "--rate",  "--burst", "--failures",  "--window", "--ban",
                           "--scope", "--port",  "--ssh-port",  "--for",    "--since",
                           "--level", "--lines", "--url",       "-a",       "-d"};
    for (size_t i = 0; i < sizeof names / sizeof *names; i++)
        if (!strcmp(s, names[i]))
            return true;
    return false;
}
static void show_bans(const struct cm_state *s, bool json)
{
    if (json) {
        struct json_object *o = cm_state_json(s), *a;
        json_object_object_get_ex(o, "bans", &a);
        puts(json_object_to_json_string_ext(a, JSON_C_TO_STRING_PRETTY));
        json_object_put(o);
        return;
    }
    puts("ADDRESS ORIGIN SCOPE REMAINING");
    for (size_t i = 0; i < s->ban_count; i++) {
        const struct cm_ban *b = &s->bans[i];
        printf("%s %s %s ", b->address, b->automatic ? "automatic" : "manual",
               b->all_ports ? "all" : "ssh");
        if (b->expires == INT64_MAX)
            puts("permanent");
        else
            printf("%llu seconds\n",
                   (unsigned long long)(b->expires > cm_now() ? b->expires - cm_now() : 0));
    }
    if (!s->ban_count)
        puts("No unexpired bans.");
}
static int start(const struct cm_paths *p, const struct cm_options *opt, struct cm_error *e)
{
    if (!opt->dry_run && cm_prepare(p, e))
        return -1;
    int lock = opt->dry_run ? cm_read_lock(p, e) : cm_lock(p, e);
    if (lock == -1 || lock < -2 || (!opt->dry_run && lock < 0))
        return -1;
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    int r = cm_config_load(p, c, e) || cm_state_load(p, s, e) ? -1 : 0;
    if (!r) {
        c->enabled = true;
        c->activation_known = true;
        r = cm_transaction(p, c, s, opt, false, e);
    }
    free(c);
    free(s);
    if (lock >= 0)
        close(lock);
    if (!r && !p->offline && !opt->dry_run)
        r = cm_systemd("start", false, e);
    if (!r && !p->offline && !opt->dry_run)
        r = cm_reconcile_guard(p, e);
    return r;
}
static int dispatch(const struct cm_paths *p, struct cm_config *c, struct cm_state *s,
                    const char *cmd, int n, char **v, bool json, const struct cm_options *opt,
                    struct cm_error *e)
{
    bool mutate = false;
    int r = 0;
    uint32_t audit_rule = 0;
    char audit_address[CM_ADDRESS_MAX] = {0};
    if (!strcmp(cmd, "rules") && !n)
        cm_rules(c, json);
    else if (!strcmp(cmd, "bans") && !n)
        show_bans(s, json);
    else if (!strcmp(cmd, "plan") && !n)
        return cm_plan(p, c, opt, true, json, e);
    else if ((!strcmp(cmd, "export") || !strcmp(cmd, "check")) && !n) {
        struct cm_config candidate = *c;
        candidate.enabled = true;
        bool a = false, b = false;
        size_t foreign;
        struct json_object *snapshot = NULL;
        if (!p->offline && !strcmp(cmd, "check")) {
            r = cm_kernel_snapshot(&snapshot, &a, &b, &foreign, e);
            if (!r)
                json_object_put(snapshot);
        }
        if (r)
            return r;
        char *script = cm_firewall_script(&candidate, s, a, b, true);
        if (!strcmp(cmd, "export"))
            fputs(script, stdout);
        else if (p->offline)
            puts("Configuration validated; native validation requires live mode.");
        else {
            r = cm_nft(script, true, NULL, e);
            if (!r)
                puts("Configuration and native batch validated.");
        }
        free(script);
        return r;
    } else if (!strcmp(cmd, "config") && n == 1 &&
               (!strcmp(v[0], "show") || !strcmp(v[0], "validate"))) {
        if (!strcmp(v[0], "show")) {
            struct json_object *o = cm_config_json(c);
            puts(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY));
            json_object_put(o);
        } else
            puts("Configuration is valid.");
    } else if (!strcmp(cmd, "init") && !n) {
        if (cm_exists(p->config, "config.json"))
            return 0;
        mutate = true;
    } else if ((!strcmp(cmd, "allow") || !strcmp(cmd, "deny") || !strcmp(cmd, "reject") ||
                !strcmp(cmd, "limit")) &&
               n) {
        r = cm_rule_add(c, n, v,
                        !strcmp(cmd, "allow")    ? CM_ALLOW
                        : !strcmp(cmd, "deny")   ? CM_DENY
                        : !strcmp(cmd, "reject") ? CM_REJECT
                                                 : CM_LIMIT,
                        e);
        mutate = true;
    } else if (!strcmp(cmd, "delete") && n == 1) {
        uint64_t id;
        r = cm_uint(v[0], 1, UINT32_MAX - 1, &id, e);
        if (!r)
            r = cm_rule_delete(c, (uint32_t)id, e);
        if (!r)
            audit_rule = (uint32_t)id;
        mutate = true;
    } else if (!strcmp(cmd, "move") && n == 3 && !strcmp(v[1], "before")) {
        uint64_t id, before;
        r = cm_uint(v[0], 1, UINT32_MAX - 1, &id, e) || cm_uint(v[2], 1, UINT32_MAX - 1, &before, e)
                ? -1
                : 0;
        if (!r)
            r = cm_rule_move(c, (uint32_t)id, (uint32_t)before, e);
        if (!r)
            audit_rule = (uint32_t)id;
        mutate = true;
    } else if (!strcmp(cmd, "default") && n == 2) {
        if (strcmp(v[0], "in") && strcmp(v[0], "out"))
            return cm_fail(e, "direction must be in or out");
        if (strcmp(v[1], "allow") && strcmp(v[1], "deny"))
            return cm_fail(e, "policy must be allow or deny");
        if (!strcmp(v[0], "in"))
            c->input_drop = !strcmp(v[1], "deny");
        else {
            c->output_drop = !strcmp(v[1], "deny");
            c->isolation = false;
        }
        strcpy(c->profile, "custom");
        mutate = true;
    } else if (!strcmp(cmd, "reload") && !n)
        return cm_transaction(p, c, s, opt, true, e);
    else if (!strcmp(cmd, "services") && !n)
        return cm_aliases(c, 0, v, json, e);
    else if (!strcmp(cmd, "service")) {
        r = cm_aliases(c, n, v, json, e);
        mutate = n && !(n == 2 && !strcmp(v[0], "show"));
    } else if (!strcmp(cmd, "profiles") && !n)
        puts(json ? "[\"passive\",\"guard-only\",\"web-server\",\"ssh-only\",\"isolation\"]"
                  : "passive\nguard-only\nweb-server\nssh-only\nisolation");
    else if (!strcmp(cmd, "use") || (!strcmp(cmd, "profile") && n >= 2 && !strcmp(v[0], "show"))) {
        int offset = !strcmp(cmd, "profile") ? 1 : 0;
        bool keep = false;
        uint16_t port = 22;
        const char *override = NULL;
        for (int i = offset + 1; i < n && !r; i++) {
            if (!strcmp(v[i], "--keep-rules"))
                keep = true;
            else if (!strcmp(v[i], "--ssh-port") && i + 1 < n) {
                if (override)
                    r = cm_fail(e, "duplicate SSH port option");
                override = v[++i];
            } else
                r = cm_fail(e, "unknown profile option");
        }
        if (n <= offset)
            r = cm_fail(e, "profile name required");
        if (!r && (override || strcmp(v[offset], "passive")))
            r = cm_ssh_port(c, override, &port, e);
        if (!r)
            r = cm_profile(c, v[offset], port, keep, e);
        if (!r && offset) {
            struct json_object *o = cm_config_json(c);
            puts(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY));
            json_object_put(o);
        } else if (!offset)
            mutate = true;
    } else if (!strcmp(cmd, "protect")) {
        if (n == 2 && !strcmp(v[0], "ssh") && !strcmp(v[1], "status")) {
            struct json_object *o = cm_config_json(c), *g;
            json_object_object_get_ex(o, "guard", &g);
            puts(json_object_to_json_string_ext(g, JSON_C_TO_STRING_PRETTY));
            json_object_put(o);
        } else {
            r = cm_protect(c, s, n, v, e);
            mutate = true;
        }
    } else if (!strcmp(cmd, "ban") && n) {
        char ip[CM_ADDRESS_MAX];
        unsigned duration = 3600;
        bool all = true;
        r = cm_address(v[0], false, ip, sizeof ip, e);
        unsigned seen = 0;
        for (int i = 1; i < n && !r; i += 2) {
            if (i + 1 >= n) {
                r = cm_fail(e, "ban option needs a value");
                break;
            }
            unsigned flag = 0;
            if (!strcmp(v[i], "--for") || !strcmp(v[i], "for")) {
                flag = 1;
                if (!strcmp(v[i + 1], "permanent"))
                    duration = 0;
                else
                    r = cm_duration(v[i + 1], &duration, e);
            } else if (!strcmp(v[i], "--scope")) {
                flag = 2;
                if (strcmp(v[i + 1], "all") && strcmp(v[i + 1], "ssh"))
                    r = cm_fail(e, "scope must be all or ssh");
                else
                    all = !strcmp(v[i + 1], "all");
            } else
                r = cm_fail(e, "unknown ban option");
            if (seen & flag)
                r = cm_fail(e, "duplicate ban option");
            seen |= flag;
        }
        if (!r)
            r = cm_state_ban_scoped(s, ip, duration ? cm_now() + duration : INT64_MAX, false, all,
                                    e);
        if (!r)
            strcpy(audit_address, ip);
        mutate = true;
    } else if (!strcmp(cmd, "unban") && n == 1) {
        char ip[CM_ADDRESS_MAX];
        r = cm_address(v[0], false, ip, sizeof ip, e);
        if (!r) {
            strcpy(audit_address, ip);
            size_t at = 0;
            for (size_t i = 0; i < s->ban_count; i++)
                if (strcmp(s->bans[i].address, ip))
                    s->bans[at++] = s->bans[i];
            s->ban_count = at;
            at = 0;
            for (size_t i = 0; i < s->attempt_count; i++)
                if (strcmp(s->attempts[i].address, ip))
                    s->attempts[at++] = s->attempts[i];
            s->attempt_count = at;
        }
        mutate = true;
    } else if (!strcmp(cmd, "logging") && n == 2) {
        r = -1;
        if (!strcmp(v[0], "packets")) {
            const char *levels[] = {"off", "low", "medium", "high"};
            for (unsigned i = 0; i < 4; i++)
                if (!strcmp(v[1], levels[i])) {
                    c->packet_log = i;
                    r = 0;
                }
        } else if (!strcmp(v[0], "level")) {
            const char *levels[] = {"critical", "error", "warning", "notice", "info", "debug"};
            for (unsigned i = 0; i < 6; i++)
                if (!strcmp(v[1], levels[i])) {
                    c->log_level = i + 2;
                    r = 0;
                }
        }
        if (r)
            cm_fail(e, "invalid logging setting");
        mutate = true;
    } else
        return cm_fail(e, "unknown command or invalid arguments; use cm help");
    if (!r && mutate) {
        struct cm_options transaction = *opt;
        transaction.state_only = !strcmp(cmd, "ban") || !strcmp(cmd, "unban");
        r = cm_transaction(p, c, s, &transaction, false, e);
    }
    if (!r && mutate && !p->offline && !opt->dry_run)
        cm_event(5, opt->stage ? "configuration" : "firewall", cmd, audit_rule, audit_address,
                  "%s %s", cmd, opt->stage ? "staged" : "committed");
    return r;
}
static bool command_readonly(const char *cmd, int n, char **v)
{
    const char *names[] = {"rules", "bans", "export", "status", "doctor", "check",
                          "profiles", "profile", "services", "guard-check", "plan"};
    for (size_t i = 0; i < sizeof names / sizeof *names; i++)
        if (!strcmp(cmd, names[i]))
            return true;
    return (!strcmp(cmd, "service") && (!n || (n == 2 && !strcmp(v[0], "show")))) ||
        (!strcmp(cmd, "config") && (n != 1 || strcmp(v[0], "restore"))) ||
        (!strcmp(cmd, "protect") && n == 2 && !strcmp(v[1], "status"));
}
int main(int argc, char **argv)
{
    if (getuid() != geteuid()) {
        fputs("command-center must not be setuid\n", stderr);
        return 1;
    }
    struct cm_error e = {0};
    struct cm_options opt = {.rollback = 120};
    bool json = false, now = false;
    unsigned interval = 1000;
    const char *root = NULL;
    const char *command_name = NULL;
    char **args = cm_alloc((size_t)(argc + 1) * sizeof *args);
    int count = 0, result = 0, lock = -1, lifecycle = -1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--root")) {
            if (root || i + 1 >= argc)
                goto usage;
            root = argv[++i];
        } else if (!strcmp(argv[i], "--json"))
            json = true;
        else if (!strcmp(argv[i], "--dry-run"))
            opt.dry_run = true;
        else if (!strcmp(argv[i], "--stage"))
            opt.stage = true;
        else if (!strcmp(argv[i], "--no-rollback"))
            opt.no_rollback = true;
        else if (!strcmp(argv[i], "--now"))
            now = true;
        else if (!strcmp(argv[i], "--timeout") || !strcmp(argv[i], "--rollback") ||
                 !strcmp(argv[i], "--interval")) {
            bool sample = !strcmp(argv[i], "--interval");
            uint64_t value;
            if (++i >= argc ||
                cm_uint(argv[i], sample ? 250 : 1, sample ? 10000 : 3600, &value, &e))
                goto usage;
            if (sample)
                interval = (unsigned)value;
            else
                opt.rollback = (unsigned)value;
        } else {
            args[count++] = argv[i];
            if (local_option(argv[i])) {
                if (i + 1 >= argc)
                    goto usage;
                args[count++] = argv[++i];
            }
        }
    }
    if (!count) {
        cm_help(stdout);
        goto done;
    }
    const char *cmd = args[0];
    command_name = cmd;
    int n = count - 1;
    char **v = args + 1;
    if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        if (n)
            goto usage;
        cm_help(stdout);
        goto done;
    }
    if (!strcmp(cmd, "version") || !strcmp(cmd, "--version")) {
        if (n)
            goto usage;
        puts(CM_VERSION);
        goto done;
    }
    struct cm_paths p;
    if (cm_paths_init(&p, root, &e))
        goto failed;
    if (!strcmp(cmd, "info") || report(cmd)) {
        if (n || opt.dry_run || opt.stage || now)
            goto usage;
        if (p.offline && (!strcmp(cmd, "time") || !strcmp(cmd, "timezone"))) {
            cm_fail(&e, "offline time cannot query the system bus");
            goto failed;
        }
        result =
            !strcmp(cmd, "info") ? cm_info(interval, json, &e) : cm_report(cmd, interval, json, &e);
        goto finished;
    }
    if (!strcmp(cmd, "net")) {
        if (p.offline || opt.dry_run || opt.stage || now) {
            cm_fail(&e, "network reporting requires live mode");
            goto failed;
        }
        result = cm_network(n, v, json, &e);
        goto finished;
    }
    if (!strcmp(cmd, "logs")) {
        if (opt.dry_run || opt.stage || now)
            goto usage;
        result = cm_logs(&p, n, v, json, &e);
        goto finished;
    }
    if (!p.offline && geteuid() != 0 &&
        !(!strcmp(cmd, "updates") && n == 1 && !strcmp(v[0], "status"))) {
        cm_fail(&e, "this operation requires root");
        goto failed;
    }
    if (now && strcmp(cmd, "enable") && strcmp(cmd, "disable"))
        goto usage;
    bool readonly = command_readonly(cmd, n, v);
    /* Never hold this lock in unit helpers: their caller waits for them while
     * holding it. CLI lifecycle intent remains serialized across systemd jobs. */
    if (!readonly && !opt.dry_run && strcmp(cmd, "updates") && strcmp(cmd, "guard") &&
        strcmp(cmd, "apply") && strcmp(cmd, "suspend")) {
        if (cm_prepare(&p, &e))
            goto failed;
        lifecycle = cm_named_lock(&p, "lifecycle.lock", &e);
        if (lifecycle < 0)
            goto failed;
    }
    if (!strcmp(cmd, "start") || !strcmp(cmd, "stop") || !strcmp(cmd, "enable") ||
        !strcmp(cmd, "disable")) {
        if (n || opt.stage || json)
            goto usage;
        bool boot = !strcmp(cmd, "enable") || !strcmp(cmd, "disable");
        if (opt.dry_run && boot) {
            printf("Would %s boot startup%s.\n", cmd, now ? " and change current activation" : "");
            goto done;
        }
        if (boot) {
            if (p.offline) {
                if (cm_prepare(&p, &e))
                    goto failed;
                lock = cm_lock(&p, &e);
                if (lock < 0)
                    goto failed;
                struct json_object *o = json_object_new_object();
                json_object_object_add(o, "enabled",
                                       json_object_new_boolean(!strcmp(cmd, "enable")));
                result = cm_write_json(p.config, "boot.json", o, &e);
                json_object_put(o);
                close(lock);
                lock = -1;
            } else
                result = cm_systemd(cmd, false, &e);
            if (result || !now)
                goto finished;
            cmd = !strcmp(cmd, "enable") ? "start" : "stop";
        }
        if (!strcmp(cmd, "start"))
            result = start(&p, &opt, &e);
        else if (opt.dry_run)
            puts("Would stop CM filtering and protection; other tables remain untouched.");
        else if (p.offline) {
            if (cm_prepare(&p, &e))
                goto failed;
            lock = cm_lock(&p, &e);
            if (lock < 0)
                goto failed;
            result = cm_suspend(&p, &e);
        } else
            result = cm_stop(&p, &e);
        goto finished;
    }
    if (!strcmp(cmd, "updates")) {
        if (opt.stage || now || json)
            goto usage;
        if (n && (!strcmp(v[0], "enable") || !strcmp(v[0], "disable") ||
                  !strcmp(v[0], "reboot") || !strcmp(v[0], "schedule"))) {
            if (!opt.dry_run) {
                if (cm_prepare(&p, &e))
                    goto failed;
                lock = cm_named_lock(&p, "updates.lock", &e);
                if (lock < 0)
                    goto failed;
            }
        }
        result = cm_updates(&p, n, v, opt.dry_run, &e);
        goto finished;
    }
    if (!strcmp(cmd, "guard") && n == 1 && !strcmp(v[0], "run")) {
        if (p.offline || opt.dry_run || opt.stage)
            goto usage;
        if (cm_prepare(&p, &e))
            goto failed;
        result = cm_guard_run(&p, &e);
        goto finished;
    }
    if (opt.stage &&
        (readonly || !strcmp(cmd, "ban") || !strcmp(cmd, "unban") || !strcmp(cmd, "protect")))
        goto usage;
    if (!readonly && !opt.dry_run) {
        if (cm_prepare(&p, &e))
            goto failed;
        lock = cm_lock(&p, &e);
    } else
        lock = cm_read_lock(&p, &e);
    /* A busy ExecCondition must not silently skip an enabled protector. */
    if (!strcmp(cmd, "guard-check"))
        for (unsigned i = 0; lock == -3 && i < 100; i++) {
            usleep(50000);
            lock = cm_read_lock(&p, &e);
        }
    if (lock == -1 || lock < -2 || (!readonly && !opt.dry_run && lock < 0))
        goto failed;
    e.text[0] = 0;
    if (!strcmp(cmd, "apply") || !strcmp(cmd, "suspend")) {
        if (n || opt.dry_run)
            goto usage;
        result = !strcmp(cmd, "apply") ? cm_apply(&p, &e) : cm_suspend(&p, &e);
        goto finished;
    }
    if (!strcmp(cmd, "confirm") || !strcmp(cmd, "rollback") || !strcmp(cmd, "recover")) {
        if (opt.dry_run || opt.stage)
            goto usage;
        if (!strcmp(cmd, "recover") && n == 1 && !strcmp(v[0], "checkpoint"))
            result = cm_restore_checkpoint(&p, &e);
        else if (n)
            goto usage;
        else
            result = !strcmp(cmd, "confirm")    ? cm_confirm(&p, &e)
                     : !strcmp(cmd, "rollback") ? cm_rollback(&p, &e)
                                                : cm_recover(&p, &e);
        if (!result && !p.offline) {
            if (lock >= 0) {
                close(lock);
                lock = -1;
            }
            result = cm_reconcile_guard(&p, &e);
        }
        goto finished;
    }
    if (!strcmp(cmd, "config") && n == 1 && !strcmp(v[0], "restore")) {
        if (opt.dry_run)
            goto usage;
        result = cm_restore_config(&p, &e);
        goto finished;
    }
    if (!strcmp(cmd, "status") || !strcmp(cmd, "doctor")) {
        if (n || opt.dry_run)
            goto usage;
        result = cm_status(&p, json, &e);
        goto finished;
    }
    if (!strcmp(cmd, "guard-check")) {
        if (n || opt.dry_run || opt.stage || json)
            goto usage;
        struct cm_config *committed = cm_alloc(sizeof *committed);
        result = cm_committed_policy(&p, committed, &e);
        if (!result && !committed->activation_known)
            result = cm_fail(&e, "activation unknown; reconcile with start or stop");
        if (!result)
            result = committed->enabled && committed->guard_enabled ? 0 : 1;
        free(committed);
        goto finished;
    }
    if (json && (!readonly || !strcmp(cmd, "export") || !strcmp(cmd, "check") ||
                 (!strcmp(cmd, "config") && n == 1 && !strcmp(v[0], "validate"))))
        goto usage;
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    bool ban_command = !strcmp(cmd, "ban") || !strcmp(cmd, "unban");
    result = (ban_command ? cm_committed_policy(&p, c, &e) : cm_config_load(&p, c, &e)) ||
        cm_state_load(&p, s, &e) ? -1 : 0;
    if (!result) {
        cm_state_expire(s, cm_now());
        result = dispatch(&p, c, s, cmd, n, v, json, &opt, &e);
    }
    if (!result && !readonly && !p.offline && !opt.dry_run && !opt.stage &&
        (!strcmp(cmd, "protect") || !strcmp(cmd, "use") || !strcmp(cmd, "reload"))) {
        if (lock >= 0) {
            close(lock);
            lock = -1;
        }
        result = cm_reconcile_guard(&p, &e);
    }
    free(c);
    free(s);
finished:
    if (result < 0)
        goto failed;
done:
    if (lock >= 0)
        close(lock);
    if (lifecycle >= 0)
        close(lifecycle);
    free(args);
    return result;
failed:
    fprintf(stderr, "command-center: %s\n", *e.text ? e.text : "operation failed");
    if (!root && geteuid() == 0)
        cm_event(3, "cli", command_name ? command_name : "parse", 0, NULL,
                  "%s failed: %s", command_name ? command_name : "parse",
                  *e.text ? e.text : "operation failed");
    /* ExecCondition 1 means disabled; an operational error must fail/retry the unit. */
    result = command_name && !strcmp(command_name, "guard-check") ? 255 : 1;
    goto done;
usage:
    fprintf(stderr, "command-center: %s\n", *e.text ? e.text : "invalid arguments; use cm help");
    result = 2;
    goto done;
}
