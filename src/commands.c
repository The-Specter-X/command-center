/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static bool same(const struct cm_rule *a, const struct cm_rule *b)
{
    return a->kind == b->kind && a->port == b->port && a->port_end == b->port_end &&
           a->outgoing == b->outgoing && a->family == b->family &&
           !strcmp(a->protocol, b->protocol) && !strcmp(a->source, b->source) &&
           !strcmp(a->destination, b->destination) && !strcmp(a->interface, b->interface);
}
static int rate(const char *arg, unsigned *n, unsigned *period, struct cm_error *e)
{
    char text[64];
    if (strlen(arg) >= sizeof text)
        return cm_fail(e, "invalid rate");
    strcpy(text, arg);
    char *slash = strchr(text, '/');
    *period = 60;
    if (slash) {
        *slash++ = 0;
        if (!strcmp(slash, "s") || !strcmp(slash, "second"))
            *period = 1;
        else if (!strcmp(slash, "m") || !strcmp(slash, "minute"))
            *period = 60;
        else if (!strcmp(slash, "h") || !strcmp(slash, "hour"))
            *period = 3600;
        else
            return cm_fail(e, "rate unit must be second, minute or hour");
    }
    uint64_t v;
    if (cm_uint(text, 1, 100000, &v, e))
        return -1;
    *n = (unsigned)v;
    return 0;
}
int cm_rule_add(struct cm_config *c, int argc, char **argv, enum cm_kind kind, struct cm_error *e)
{
    struct cm_rule r = {.kind = kind, .period = 60};
    int i = 0;
    if (argc && (!strcmp(argv[0], "out") || !strcmp(argv[0], "in")))
        r.outgoing = !strcmp(argv[i++], "out");
    if (i >= argc)
        return cm_fail(e, "a service or PORT[-END]/tcp|udp is required");
    const char *service = argv[i++];
    if (!strcmp(service, "all"))
        strcpy(r.protocol, kind == CM_LIMIT ? "tcp" : "any");
    else {
        char spec[64];
        if (strlen(service) >= sizeof spec)
            return cm_fail(e, "invalid service");
        strcpy(spec, service);
        char *dash = strchr(spec, '-'), *slash = strchr(spec, '/');
        if (dash && slash && dash < slash) {
            *dash++ = 0;
            *slash++ = 0;
            uint64_t lo, hi;
            if (cm_uint(spec, 1, 65535, &lo, e) || cm_uint(dash, lo, 65535, &hi, e) ||
                (strcmp(slash, "tcp") && strcmp(slash, "udp") && strcmp(slash, "both")))
                return cm_fail(e, "invalid port range");
            r.port = (uint16_t)lo;
            r.port_end = (uint16_t)hi;
            strcpy(r.protocol, slash);
        } else if (cm_service_config(c, service, &r.port, r.protocol, e))
            return -1;
        if (!r.port_end)
            r.port_end = r.port;
    }
    if (kind == CM_LIMIT) {
        if (strcmp(r.protocol, "tcp"))
            return cm_fail(e, "connection limiting supports TCP only");
        r.rate = 6;
        r.burst = 5;
    }
    unsigned seen = 0;
    while (i < argc) {
        const char *key = argv[i++];
        if (i >= argc)
            return cm_fail(e, "option %s requires a value", key);
        const char *value = argv[i++];
        unsigned flag = 0;
        if (!strcmp(key, "--from") || !strcmp(key, "from")) {
            flag = 1;
            if (cm_address(value, true, r.source, sizeof r.source, e))
                return -1;
        } else if (!strcmp(key, "--to")) {
            flag = 2;
            if (cm_address(value, true, r.destination, sizeof r.destination, e))
                return -1;
        } else if (!strcmp(key, "--interface")) {
            flag = 4;
            if (strlen(value) >= sizeof r.interface || !cm_plain(value, true))
                return cm_fail(e, "invalid interface name");
            strcpy(r.interface, value);
        } else if (!strcmp(key, "--comment")) {
            flag = 8;
            if (strlen(value) >= sizeof r.comment || !cm_plain(value, false))
                return cm_fail(e, "comment must be printable ASCII, at most 159 bytes");
            strcpy(r.comment, value);
        } else if (!strcmp(key, "--family")) {
            flag = 16;
            if (!strcmp(value, "4"))
                r.family = 4;
            else if (!strcmp(value, "6"))
                r.family = 6;
            else if (strcmp(value, "any"))
                return cm_fail(e, "family must be 4, 6 or any");
        } else if (kind == CM_LIMIT && (!strcmp(key, "--rate") || !strcmp(key, "rate"))) {
            flag = 32;
            if (rate(value, &r.rate, &r.period, e))
                return -1;
        } else if (kind == CM_LIMIT && (!strcmp(key, "--burst") || !strcmp(key, "burst"))) {
            uint64_t n;
            flag = 64;
            if (cm_uint(value, 1, 100000, &n, e))
                return -1;
            r.burst = (unsigned)n;
        } else
            return cm_fail(e, "unknown rule option: %s", key);
        if (seen & flag)
            return cm_fail(e, "duplicate rule option: %s", key);
        seen |= flag;
    }
    unsigned af = *r.source ? (strchr(r.source, ':') ? 6U : 4U) : 0;
    unsigned df = *r.destination ? (strchr(r.destination, ':') ? 6U : 4U) : 0;
    if ((af && df && af != df) || (r.family && ((af && af != r.family) || (df && df != r.family))))
        return cm_fail(e, "incompatible address families");
    for (size_t j = 0; j < c->rule_count; j++)
        if (same(&r, &c->rules[j])) {
            c->rules[j].rate = r.rate;
            c->rules[j].burst = r.burst;
            c->rules[j].period = r.period;
            if (*r.comment)
                strcpy(c->rules[j].comment, r.comment);
            return 0;
        }
    if (c->rule_count == CM_MAX_RULES || c->next_id == UINT32_MAX)
        return cm_fail(e, "rule capacity or number space exhausted");
    r.id = c->next_id++;
    c->rules[c->rule_count++] = r;
    return 0;
}
int cm_rule_delete(struct cm_config *c, uint32_t id, struct cm_error *e)
{
    for (size_t i = 0; i < c->rule_count; i++)
        if (c->rules[i].id == id) {
            memmove(c->rules + i, c->rules + i + 1, (c->rule_count - i - 1) * sizeof c->rules[0]);
            c->rule_count--;
            return 0;
        }
    return cm_fail(e, "rule number %u does not exist", id);
}
int cm_rule_move(struct cm_config *c, uint32_t id, uint32_t before, struct cm_error *e)
{
    size_t a = SIZE_MAX, b = SIZE_MAX;
    for (size_t i = 0; i < c->rule_count; i++) {
        if (c->rules[i].id == id)
            a = i;
        if (c->rules[i].id == before)
            b = i;
    }
    if (a == SIZE_MAX || b == SIZE_MAX)
        return cm_fail(e, "both rule numbers must exist");
    if (a == b)
        return 0;
    struct cm_rule r = c->rules[a];
    if (a < b) {
        memmove(c->rules + a, c->rules + a + 1, (b - a - 1) * sizeof r);
        c->rules[b - 1] = r;
    } else {
        memmove(c->rules + b + 1, c->rules + b, (a - b) * sizeof r);
        c->rules[b] = r;
    }
    return 0;
}
void cm_rules(const struct cm_config *c, bool json)
{
    if (json) {
        struct json_object *o = cm_config_json(c), *a;
        json_object_object_get_ex(o, "rules", &a);
        puts(json_object_to_json_string_ext(a, JSON_C_TO_STRING_PRETTY));
        json_object_put(o);
        return;
    }
    puts("NUMBER ORDER ACTION DIR SERVICE FROM TO INTERFACE FAMILY COMMENT");
    for (size_t i = 0; i < c->rule_count; i++) {
        const struct cm_rule *r = &c->rules[i];
        printf("[%u] %zu %s %s ", r->id, i + 1,
               r->kind == CM_ALLOW    ? "allow"
               : r->kind == CM_DENY   ? "deny"
               : r->kind == CM_REJECT ? "reject"
                                      : "limit",
               r->outgoing ? "out" : "in");
        if (!r->port)
            printf("all/%s", r->protocol);
        else if (r->port_end != r->port)
            printf("%u-%u/%s", r->port, r->port_end, r->protocol);
        else
            printf("%u/%s", r->port, r->protocol);
        printf(" %s %s %s %u %s", *r->source ? r->source : "any",
               *r->destination ? r->destination : "any", *r->interface ? r->interface : "any",
               r->family, r->comment);
        if (r->kind == CM_LIMIT)
            printf(" rate=%u/%s burst=%u", r->rate,
                   r->period == 1      ? "second"
                   : r->period == 3600 ? "hour"
                                       : "minute",
                   r->burst);
        putchar('\n');
    }
    if (!c->rule_count)
        puts("No rules. Existing non-CM firewall restrictions remain in effect.");
}
int cm_profile(struct cm_config *c, const char *name, uint16_t ssh, bool keep, struct cm_error *e)
{
    if (strcmp(name, "passive") && strcmp(name, "guard-only") && strcmp(name, "web-server") &&
        strcmp(name, "ssh-only") && strcmp(name, "isolation"))
        return cm_fail(e, "unknown profile");
    if (!strcmp(name, "guard-only")) {
        c->guard_enabled = true;
        c->guard_ports[0] = ssh;
        c->guard_port_count = 1;
        strcpy(c->profile, name);
        return 0;
    }
    if (!keep)
        c->rule_count = 0;
    c->input_drop = strcmp(name, "passive") != 0;
    c->output_drop = !strcmp(name, "isolation");
    c->isolation = c->output_drop;
    c->guard_enabled = c->input_drop;
    c->guard_ports[0] = ssh;
    c->guard_port_count = 1;
    strcpy(c->profile, name);
    if (c->input_drop) {
        char port[24];
        snprintf(port, sizeof port, "%u/tcp", ssh);
        char *args[] = {port};
        if (cm_rule_add(c, 1, args, CM_ALLOW, e))
            return -1;
    }
    if (!strcmp(name, "web-server")) {
        char *http[] = {"http"}, *https[] = {"https"};
        if (cm_rule_add(c, 1, http, CM_ALLOW, e) || cm_rule_add(c, 1, https, CM_ALLOW, e))
            return -1;
    }
    return 0;
}
int cm_protect(struct cm_config *c, struct cm_state *s, int argc, char **argv, struct cm_error *e)
{
    if (argc < 1 || strcmp(argv[0], "ssh"))
        return cm_fail(e, "only the tested SSH protector is supported");
    if (argc == 2 && !strcmp(argv[1], "disable")) {
        c->guard_enabled = false;
        s->attempt_count = 0;
        *s->cursor = 0;
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "ignore")) {
        char address[CM_ADDRESS_MAX];
        if (cm_address(argv[3], true, address, sizeof address, e))
            return -1;
        size_t at = c->ignore_count;
        for (size_t i = 0; i < c->ignore_count; i++)
            if (!strcmp(c->ignore[i], address))
                at = i;
        if (!strcmp(argv[2], "add")) {
            if (at == c->ignore_count) {
                if (at == CM_MAX_IGNORE)
                    return cm_fail(e, "ignore capacity reached");
                strcpy(c->ignore[c->ignore_count++], address);
            }
        } else if (!strcmp(argv[2], "delete")) {
            if (at == c->ignore_count)
                return cm_fail(e, "ignore address not found");
            memmove(c->ignore + at, c->ignore + at + 1,
                    (c->ignore_count - at - 1) * sizeof c->ignore[0]);
            c->ignore_count--;
        } else
            return cm_fail(e, "ignore requires add or delete");
        s->attempt_count = 0;
        return 0;
    }
    unsigned seen = 0;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc)
            return cm_fail(e, "protection option needs a value");
        unsigned flag = 0;
        uint64_t n;
        const char *k = argv[i], *v = argv[i + 1];
        if (!strcmp(k, "--failures") || !strcmp(k, "-a")) {
            flag = 1;
            if (cm_uint(v, 1, 100, &n, e))
                return -1;
            c->threshold = (unsigned)n;
        } else if (!strcmp(k, "--window")) {
            flag = 2;
            if (cm_duration(v, &c->window, e) || c->window > 86400)
                return cm_fail(e, "counting window must be between 1s and 1d");
        } else if (!strcmp(k, "--ban") || !strcmp(k, "-d")) {
            flag = 4;
            if (!strcmp(v, "permanent"))
                c->duration = 0;
            else if (cm_duration(v, &c->duration, e))
                return -1;
        } else if (!strcmp(k, "--scope")) {
            flag = 8;
            if (strcmp(v, "ssh") && strcmp(v, "all"))
                return cm_fail(e, "scope must be ssh or all");
            c->guard_all = !strcmp(v, "all");
        } else if (!strcmp(k, "--port")) {
            flag = 16;
            char proto[5];
            if (cm_service_config(c, v, &c->guard_ports[0], proto, e) || strcmp(proto, "tcp"))
                return cm_fail(e, "SSH requires a TCP port");
            c->guard_port_count = 1;
        } else
            return cm_fail(e, "unknown protection option: %s", k);
        if (seen & flag)
            return cm_fail(e, "duplicate protection option");
        seen |= flag;
    }
    if (!c->guard_enabled) {
        uint16_t port;
        char proto[5];
        if (!(seen & 16) && !cm_service_config(c, "ssh", &port, proto, e)) {
            c->guard_ports[0] = port;
            c->guard_port_count = 1;
        }
    }
    c->guard_enabled = true;
    s->attempt_count = 0;
    *s->cursor = 0;
    return 0;
}
int cm_aliases(struct cm_config *c, int argc, char **argv, bool json, struct cm_error *e)
{
    if (!argc || (argc == 2 && !strcmp(argv[0], "show"))) {
        const char *names[] = {"ssh",       "http",       "https",      "quic", "dns",
                               "ntp",       "smtp",       "submission", "imap", "imaps",
                               "wireguard", "postgresql", "mysql"};
        struct json_object *o = json_object_new_object();
        for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
            uint16_t p;
            char proto[5], v[32];
            if (cm_service_config(c, names[i], &p, proto, e)) {
                json_object_put(o);
                return -1;
            }
            snprintf(v, sizeof v, "%u/%s", p, proto);
            json_object_object_add(o, names[i], json_object_new_string(v));
        }
        for (size_t i = 0; i < c->alias_count; i++) {
            char v[32];
            snprintf(v, sizeof v, "%u/%s", c->aliases[i].port, c->aliases[i].protocol);
            json_object_object_add(o, c->aliases[i].name, json_object_new_string(v));
        }
        if (argc) {
            struct json_object *v;
            if (!json_object_object_get_ex(o, argv[1], &v)) {
                json_object_put(o);
                return cm_fail(e, "unknown service alias");
            }
            puts(json ? json_object_to_json_string_ext(v, JSON_C_TO_STRING_PLAIN)
                      : json_object_get_string(v));
        } else if (json)
            puts(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY));
        else {
            json_object_object_foreach(o, k, v)
            {
                printf("%-16s %s\n", k, json_object_get_string(v));
            }
        }
        json_object_put(o);
        return 0;
    }
    if (argc < 2 || strlen(argv[1]) >= 32 || !cm_plain(argv[1], true))
        return cm_fail(e, "service set NAME PORT/tcp|udp|both or service delete NAME");
    if (!strcmp(argv[1], "all") || !strcmp(argv[1], "in") || !strcmp(argv[1], "out"))
        return cm_fail(e, "alias name is reserved");
    size_t at = c->alias_count;
    for (size_t i = 0; i < c->alias_count; i++)
        if (!strcmp(c->aliases[i].name, argv[1]))
            at = i;
    if (argc == 2 && !strcmp(argv[0], "delete")) {
        if (at == c->alias_count)
            return cm_fail(e, "no custom alias with that name");
        memmove(c->aliases + at, c->aliases + at + 1,
                (c->alias_count - at - 1) * sizeof c->aliases[0]);
        c->alias_count--;
        return 0;
    }
    if (argc != 3 || strcmp(argv[0], "set"))
        return cm_fail(e, "invalid service command");
    uint16_t port;
    char proto[5];
    if (cm_service(argv[2], &port, proto, e))
        return -1;
    if (at == c->alias_count) {
        if (at == 64)
            return cm_fail(e, "alias capacity reached");
        c->alias_count++;
    }
    strcpy(c->aliases[at].name, argv[1]);
    strcpy(c->aliases[at].protocol, proto);
    c->aliases[at].port = port;
    return 0;
}
