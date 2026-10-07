/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <limits.h>
#include <string.h>

static void integer(struct json_object *o, const char *k, uint64_t n)
{
    json_object_object_add(o, k, json_object_new_uint64(n));
}
static void boolean(struct json_object *o, const char *k, bool b)
{
    json_object_object_add(o, k, json_object_new_boolean(b));
}
static void string(struct json_object *o, const char *k, const char *s)
{
    json_object_object_add(o, k, json_object_new_string(s));
}
void cm_config_default(struct cm_config *c)
{
    memset(c, 0, sizeof *c);
    c->next_id = 1;
    c->log_level = 6;
    strcpy(c->profile, "passive");
    c->threshold = 6;
    c->window = 600;
    c->duration = 3600;
    c->guard_ports[0] = 22;
    c->guard_port_count = 1;
    strcpy(c->ignore[0], "127.0.0.0/8");
    strcpy(c->ignore[1], "::1/128");
    c->ignore_count = 2;
}
struct json_object *cm_config_json(const struct cm_config *c)
{
    struct json_object *o = json_object_new_object(), *rules = json_object_new_array(),
                       *guard = json_object_new_object(), *ignore = json_object_new_array(),
                       *ports = json_object_new_array();
    integer(o, "schema", 2);
    integer(o, "next_id", c->next_id);
    boolean(o, "input_drop", c->input_drop);
    boolean(o, "output_drop", c->output_drop);
    boolean(o, "isolation", c->isolation);
    integer(o, "packet_log", c->packet_log);
    integer(o, "log_level", c->log_level);
    string(o, "profile", c->profile);
    struct json_object *aliases = json_object_new_array();
    for (size_t i = 0; i < c->alias_count; i++) {
        struct json_object *v = json_object_new_object();
        string(v, "name", c->aliases[i].name);
        integer(v, "port", c->aliases[i].port);
        string(v, "protocol", c->aliases[i].protocol);
        json_object_array_add(aliases, v);
    }
    json_object_object_add(o, "aliases", aliases);
    for (size_t i = 0; i < c->rule_count; i++) {
        const struct cm_rule *r = &c->rules[i];
        struct json_object *v = json_object_new_object();
        integer(v, "id", r->id);
        string(v, "action",
               r->kind == CM_ALLOW    ? "allow"
               : r->kind == CM_DENY   ? "deny"
               : r->kind == CM_REJECT ? "reject"
                                      : "limit");
        integer(v, "port", r->port);
        integer(v, "port_end", r->port_end ? r->port_end : r->port);
        boolean(v, "outgoing", r->outgoing);
        integer(v, "family", r->family);
        string(v, "destination", r->destination);
        string(v, "interface", r->interface);
        string(v, "comment", r->comment);
        integer(v, "period", r->period ? r->period : 60);
        string(v, "protocol", r->protocol);
        string(v, "source", r->source);
        integer(v, "rate", r->rate);
        integer(v, "burst", r->burst);
        json_object_array_add(rules, v);
    }
    json_object_object_add(o, "rules", rules);
    boolean(guard, "enabled", c->guard_enabled);
    boolean(guard, "all_ports", c->guard_all);
    integer(guard, "threshold", c->threshold);
    integer(guard, "window", c->window);
    integer(guard, "duration", c->duration);
    for (size_t i = 0; i < c->ignore_count; i++)
        json_object_array_add(ignore, json_object_new_string(c->ignore[i]));
    for (size_t i = 0; i < c->guard_port_count; i++)
        json_object_array_add(ports, json_object_new_int(c->guard_ports[i]));
    json_object_object_add(guard, "ignore", ignore);
    json_object_object_add(guard, "ports", ports);
    json_object_object_add(o, "guard", guard);
    return o;
}
static int array(struct json_object *o, const char *key, size_t max, struct json_object **a,
                 struct cm_error *e)
{
    if (!json_object_object_get_ex(o, key, a) || !json_object_is_type(*a, json_type_array) ||
        json_object_array_length(*a) > max)
        return cm_fail(e, "%s must be an array with at most %zu entries", key, max);
    return 0;
}
int cm_config_parse(struct json_object *o, struct cm_config *c, struct cm_error *e)
{
    static const char *const keys[] = {"schema",     "next_id",     "rules",     "guard",
                                       "input_drop", "output_drop", "isolation", "packet_log",
                                       "log_level",  "profile",     "aliases",   NULL};
    uint64_t n;
    memset(c, 0, sizeof *c);
    if (!cm_keys(o, keys, e) || cm_get_int(o, "schema", 2, 2, &n, e) ||
        cm_get_int(o, "next_id", 1, UINT32_MAX, &n, e))
        return -1;
    c->next_id = (uint32_t)n;
    if (cm_get_bool(o, "input_drop", &c->input_drop, e) ||
        cm_get_bool(o, "output_drop", &c->output_drop, e) ||
        cm_get_bool(o, "isolation", &c->isolation, e) ||
        cm_get_string(o, "profile", c->profile, sizeof c->profile, e) ||
        cm_get_int(o, "packet_log", 0, 3, &n, e))
        return -1;
    c->packet_log = (unsigned)n;
    if (cm_get_int(o, "log_level", 2, 7, &n, e))
        return -1;
    c->log_level = (unsigned)n;
    if (!cm_plain(c->profile, true))
        return cm_fail(e, "invalid profile label");
    struct json_object *aliases;
    if (array(o, "aliases", 64, &aliases, e))
        return -1;
    c->alias_count = json_object_array_length(aliases);
    for (size_t i = 0; i < c->alias_count; i++) {
        struct json_object *v = json_object_array_get_idx(aliases, i);
        static const char *const ak[] = {"name", "port", "protocol", NULL};
        struct cm_alias *a = &c->aliases[i];
        if (!cm_keys(v, ak, e) || cm_get_string(v, "name", a->name, sizeof a->name, e) ||
            cm_get_string(v, "protocol", a->protocol, sizeof a->protocol, e) ||
            cm_get_int(v, "port", 1, 65535, &n, e) || !cm_plain(a->name, true))
            return cm_fail(e, "invalid service alias");
        a->port = (uint16_t)n;
        if (!strcmp(a->name, "all") || !strcmp(a->name, "in") || !strcmp(a->name, "out"))
            return cm_fail(e, "alias name is reserved");
        if (strcmp(a->protocol, "tcp") && strcmp(a->protocol, "udp") && strcmp(a->protocol, "both"))
            return cm_fail(e, "invalid alias protocol");
        for (size_t j = 0; j < i; j++)
            if (!strcmp(a->name, c->aliases[j].name))
                return cm_fail(e, "duplicate alias");
    }
    struct json_object *rules;
    if (array(o, "rules", CM_MAX_RULES, &rules, e))
        return -1;
    c->rule_count = json_object_array_length(rules);
    for (size_t i = 0; i < c->rule_count; i++) {
        struct json_object *v = json_object_array_get_idx(rules, i);
        struct cm_rule *r = &c->rules[i];
        char action[8], source[CM_ADDRESS_MAX];
        static const char *const rkeys[] = {"id",       "action", "port",        "protocol",
                                            "source",   "rate",   "burst",       "port_end",
                                            "outgoing", "family", "destination", "interface",
                                            "comment",  "period", NULL};
        if (!cm_keys(v, rkeys, e) || cm_get_int(v, "id", 1, UINT32_MAX - 1, &n, e))
            return -1;
        r->id = (uint32_t)n;
        if (r->id >= c->next_id)
            return cm_fail(e, "rule IDs must be below next_id");
        for (size_t j = 0; j < i; j++)
            if (c->rules[j].id == r->id)
                return cm_fail(e, "duplicate rule ID");
        if (cm_get_string(v, "action", action, sizeof action, e))
            return -1;
        if (!strcmp(action, "allow"))
            r->kind = CM_ALLOW;
        else if (!strcmp(action, "deny"))
            r->kind = CM_DENY;
        else if (!strcmp(action, "reject"))
            r->kind = CM_REJECT;
        else if (!strcmp(action, "limit"))
            r->kind = CM_LIMIT;
        else
            return cm_fail(e, "invalid rule action");
        if (cm_get_int(v, "port", 0, 65535, &n, e))
            return -1;
        r->port = (uint16_t)n;
        if (cm_get_int(v, "port_end", r->port, 65535, &n, e))
            return -1;
        r->port_end = (uint16_t)n;
        if (!r->port && r->port_end)
            return cm_fail(e, "all-port rules must have port and port_end equal to zero");
        if (cm_get_bool(v, "outgoing", &r->outgoing, e) || cm_get_int(v, "family", 0, 6, &n, e))
            return -1;
        r->family = (unsigned)n;
        if (r->family && r->family != 4 && r->family != 6)
            return cm_fail(e, "family must be 0, 4 or 6");
        char dest[CM_ADDRESS_MAX];
        if (cm_get_string(v, "destination", dest, sizeof dest, e) ||
            cm_get_string(v, "interface", r->interface, sizeof r->interface, e) ||
            cm_get_string(v, "comment", r->comment, sizeof r->comment, e))
            return -1;
        if (*dest && cm_address(dest, true, r->destination, sizeof r->destination, e))
            return -1;
        if ((*r->interface && !cm_plain(r->interface, true)) || !cm_plain(r->comment, false))
            return cm_fail(e, "invalid interface/comment");
        if (cm_get_int(v, "period", 1, 3600, &n, e))
            return -1;
        r->period = (unsigned)n;
        if (r->period != 1 && r->period != 60 && r->period != 3600)
            return cm_fail(e, "rate period must be second, minute or hour");
        if (cm_get_string(v, "protocol", r->protocol, sizeof r->protocol, e) ||
            cm_get_string(v, "source", source, sizeof source, e))
            return -1;
        if (strcmp(r->protocol, "tcp") && strcmp(r->protocol, "udp") &&
            strcmp(r->protocol, "both") && strcmp(r->protocol, "any"))
            return cm_fail(e, "invalid rule protocol");
        if (!strcmp(r->protocol, "any") && r->port)
            return cm_fail(e, "a port requires TCP or UDP");
        if (*source && cm_address(source, true, r->source, sizeof r->source, e))
            return -1;
        unsigned af = *r->source ? (strchr(r->source, ':') ? 6U : 4U) : 0;
        unsigned df = *r->destination ? (strchr(r->destination, ':') ? 6U : 4U) : 0;
        if ((af && df && af != df) ||
            (r->family && ((af && af != r->family) || (df && df != r->family))))
            return cm_fail(e, "incompatible rule address families");
        if (cm_get_int(v, "rate", 0, 100000, &n, e))
            return -1;
        r->rate = (unsigned)n;
        if (cm_get_int(v, "burst", 0, 100000, &n, e))
            return -1;
        r->burst = (unsigned)n;
        if (r->kind == CM_LIMIT && (strcmp(r->protocol, "tcp") || !r->rate || !r->burst))
            return cm_fail(e, "limit rules require TCP and positive rate/burst values");
        if (r->kind != CM_LIMIT && (r->rate || r->burst))
            return cm_fail(e, "rate and burst are only valid for limit rules");
        for (size_t j = 0; j < i; j++)
            if (c->rules[j].kind == r->kind && c->rules[j].port == r->port &&
                !strcmp(c->rules[j].protocol, r->protocol) &&
                !strcmp(c->rules[j].source, r->source) && c->rules[j].port_end == r->port_end &&
                c->rules[j].outgoing == r->outgoing && c->rules[j].family == r->family &&
                !strcmp(c->rules[j].destination, r->destination) &&
                !strcmp(c->rules[j].interface, r->interface))
                return cm_fail(e, "duplicate rule definition");
    }
    struct json_object *g;
    if (!json_object_object_get_ex(o, "guard", &g))
        return cm_fail(e, "guard configuration is required");
    static const char *const gkeys[] = {"enabled", "threshold", "window",    "duration",
                                        "ports",   "ignore",    "all_ports", NULL};
    if (!cm_keys(g, gkeys, e) || cm_get_bool(g, "enabled", &c->guard_enabled, e) ||
        cm_get_bool(g, "all_ports", &c->guard_all, e) || cm_get_int(g, "threshold", 1, 100, &n, e))
        return -1;
    c->threshold = (unsigned)n;
    if (cm_get_int(g, "window", 1, 86400, &n, e))
        return -1;
    c->window = (unsigned)n;
    if (cm_get_int(g, "duration", 0, 2592000, &n, e))
        return -1;
    c->duration = (unsigned)n;
    struct json_object *a;
    if (array(g, "ports", 32, &a, e))
        return -1;
    c->guard_port_count = json_object_array_length(a);
    if (!c->guard_port_count)
        return cm_fail(e, "guard must have at least one port");
    for (size_t i = 0; i < c->guard_port_count; i++) {
        struct json_object *v = json_object_array_get_idx(a, i);
        int64_t port = json_object_get_int64(v);
        if (!json_object_is_type(v, json_type_int) || port < 1 || port > 65535)
            return cm_fail(e, "invalid guard port");
        c->guard_ports[i] = (uint16_t)port;
        for (size_t j = 0; j < i; j++)
            if (c->guard_ports[j] == port)
                return cm_fail(e, "duplicate guard port");
    }
    if (array(g, "ignore", CM_MAX_IGNORE, &a, e))
        return -1;
    c->ignore_count = json_object_array_length(a);
    for (size_t i = 0; i < c->ignore_count; i++) {
        struct json_object *v = json_object_array_get_idx(a, i);
        if (!json_object_is_type(v, json_type_string) ||
            json_object_get_string_len(v) != (int)strlen(json_object_get_string(v)) ||
            cm_address(json_object_get_string(v), true, c->ignore[i], sizeof c->ignore[i], e))
            return cm_fail(e, "invalid guard ignore address");
        for (size_t j = 0; j < i; j++)
            if (!strcmp(c->ignore[j], c->ignore[i]))
                return cm_fail(e, "duplicate guard ignore address");
    }
    return 0;
}
int cm_config_load(const struct cm_paths *p, struct cm_config *c, struct cm_error *e)
{
    struct json_object *o;
    int r = cm_read_json(p->config, "config.json", &o, e);
    if (r == 1) {
        if (cm_exists(p->state, "committed.json"))
            return cm_fail(
                e, "config.json is missing from an established installation; use config restore");
        cm_config_default(c);
        return 0;
    }
    if (r)
        return -1;
    r = cm_config_parse(o, c, e);
    json_object_put(o);
    if (!r) {
        struct json_object *active = NULL;
        int found = cm_read_json(p->run, "active.json", &active, e);
        if (found < 0)
            return -1;
        if (!found) {
            r = cm_get_bool(active, "active", &c->enabled, e);
            json_object_put(active);
        }
    }
    return r;
}
struct json_object *cm_state_json(const struct cm_state *s)
{
    struct json_object *o = json_object_new_object(), *bans = json_object_new_array(),
                       *attempts = json_object_new_array();
    integer(o, "schema", 1);
    string(o, "cursor", s->cursor);
    for (size_t i = 0; i < s->ban_count; i++) {
        struct json_object *v = json_object_new_object();
        string(v, "address", s->bans[i].address);
        integer(v, "expires", s->bans[i].expires);
        boolean(v, "automatic", s->bans[i].automatic);
        boolean(v, "all_ports", s->bans[i].all_ports);
        json_object_array_add(bans, v);
    }
    for (size_t i = 0; i < s->attempt_count; i++) {
        struct json_object *v = json_object_new_object(), *times = json_object_new_array();
        string(v, "address", s->attempts[i].address);
        for (size_t j = 0; j < s->attempts[i].count; j++)
            json_object_array_add(times, json_object_new_uint64(s->attempts[i].times[j]));
        json_object_object_add(v, "times", times);
        json_object_array_add(attempts, v);
    }
    json_object_object_add(o, "bans", bans);
    json_object_object_add(o, "attempts", attempts);
    return o;
}
int cm_state_parse(struct json_object *o, struct cm_state *s, struct cm_error *e)
{
    static const char *const keys[] = {"schema", "cursor", "bans", "attempts", NULL};
    uint64_t n;
    memset(s, 0, sizeof *s);
    if (!cm_keys(o, keys, e) || cm_get_int(o, "schema", 1, 1, &n, e) ||
        cm_get_string(o, "cursor", s->cursor, sizeof s->cursor, e))
        return -1;
    struct json_object *a;
    if (array(o, "bans", CM_MAX_BANS, &a, e))
        return -1;
    s->ban_count = json_object_array_length(a);
    for (size_t i = 0; i < s->ban_count; i++) {
        struct json_object *v = json_object_array_get_idx(a, i);
        char ip[CM_ADDRESS_MAX];
        static const char *const bkeys[] = {"address", "expires", "automatic", "all_ports", NULL};
        if (!cm_keys(v, bkeys, e) || cm_get_string(v, "address", ip, sizeof ip, e) ||
            cm_address(ip, false, s->bans[i].address, sizeof s->bans[i].address, e) ||
            cm_get_int(v, "expires", 1, INT64_MAX, &s->bans[i].expires, e) ||
            cm_get_bool(v, "automatic", &s->bans[i].automatic, e) ||
            cm_get_bool(v, "all_ports", &s->bans[i].all_ports, e))
            return -1;
        for (size_t j = 0; j < i; j++)
            if (s->bans[j].automatic == s->bans[i].automatic &&
                !strcmp(s->bans[j].address, s->bans[i].address))
                return cm_fail(e, "duplicate ban");
    }
    if (array(o, "attempts", CM_MAX_ATTEMPTS, &a, e))
        return -1;
    s->attempt_count = json_object_array_length(a);
    for (size_t i = 0; i < s->attempt_count; i++) {
        struct json_object *v = json_object_array_get_idx(a, i), *times;
        char ip[CM_ADDRESS_MAX];
        static const char *const akeys[] = {"address", "times", NULL};
        if (!cm_keys(v, akeys, e) || cm_get_string(v, "address", ip, sizeof ip, e) ||
            cm_address(ip, false, s->attempts[i].address, sizeof s->attempts[i].address, e) ||
            array(v, "times", 100, &times, e))
            return -1;
        s->attempts[i].count = json_object_array_length(times);
        for (size_t j = 0; j < s->attempts[i].count; j++) {
            struct json_object *t = json_object_array_get_idx(times, j);
            if (!json_object_is_type(t, json_type_int) || json_object_get_int64(t) <= 0)
                return cm_fail(e, "invalid attempt timestamp");
            s->attempts[i].times[j] = json_object_get_uint64(t);
            if (j && s->attempts[i].times[j] < s->attempts[i].times[j - 1])
                return cm_fail(e, "attempt timestamps must be ordered");
        }
        for (size_t j = 0; j < i; j++)
            if (!strcmp(s->attempts[j].address, s->attempts[i].address))
                return cm_fail(e, "duplicate attempt address");
    }
    return 0;
}
int cm_config_drift(const struct cm_paths *p, struct cm_error *e)
{
    struct cm_config *current = cm_alloc(sizeof *current), *last = cm_alloc(sizeof *last);
    int r = cm_config_load(p, current, e);
    struct json_object *record = NULL;
    if (!r) {
        int found = cm_read_json(p->state, "committed.json", &record, e);
        if (found < 0)
            r = -1;
        else if (found == 1)
            cm_config_default(last);
        else {
            struct cm_state *checkpoint = cm_alloc(sizeof *checkpoint);
            r = cm_bundle_parse(record, last, checkpoint, e);
            free(checkpoint);
            json_object_put(record);
        }
    }
    if (!r) {
        struct json_object *a = cm_config_json(current), *b = cm_config_json(last);
        r = json_object_equal(a, b) ? 0 : 1;
        json_object_put(a);
        json_object_put(b);
    }
    free(current);
    free(last);
    return r;
}
int cm_state_load(const struct cm_paths *p, struct cm_state *s, struct cm_error *e)
{
    struct json_object *o;
    int r = cm_read_json(p->state, "state.json", &o, e);
    if (r == 1) {
        if (cm_exists(p->state, "committed.json"))
            return cm_fail(
                e, "state.json is missing; restore a backup or explicitly recover checkpoint");
        memset(s, 0, sizeof *s);
        return 0;
    }
    if (r)
        return -1;
    r = cm_state_parse(o, s, e);
    json_object_put(o);
    return r;
}
void cm_state_expire(struct cm_state *s, uint64_t now)
{
    size_t j = 0;
    for (size_t i = 0; i < s->ban_count; i++)
        if (s->bans[i].expires == INT64_MAX || s->bans[i].expires > now)
            s->bans[j++] = s->bans[i];
    s->ban_count = j;
}
bool cm_ignored(const struct cm_config *c, const char *ip)
{
    for (size_t i = 0; i < c->ignore_count; i++)
        if (cm_contains(c->ignore[i], ip))
            return true;
    return false;
}
int cm_state_ban_scoped(struct cm_state *s, const char *ip, uint64_t expiry, bool automatic,
                        bool all, struct cm_error *e)
{
    for (size_t i = 0; i < s->ban_count; i++)
        if (s->bans[i].automatic == automatic && !strcmp(s->bans[i].address, ip)) {
            s->bans[i].all_ports = all;
            if (expiry > s->bans[i].expires)
                s->bans[i].expires = expiry;
            return 0;
        }
    if (s->ban_count == CM_MAX_BANS)
        return cm_fail(e, "ban capacity reached (%u); no existing bans were evicted", CM_MAX_BANS);
    struct cm_ban *b = &s->bans[s->ban_count++];
    strcpy(b->address, ip);
    b->expires = expiry;
    b->automatic = automatic;
    b->all_ports = all;
    return 0;
}

int cm_state_ban(struct cm_state *s, const char *ip, uint64_t expiry, bool automatic,
                 struct cm_error *e)
{
    return cm_state_ban_scoped(s, ip, expiry, automatic, !automatic, e);
}
