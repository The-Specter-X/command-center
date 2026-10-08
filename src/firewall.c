/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <nftables/libnftables.h>
#include <stdlib.h>
#include <string.h>

static void quote(FILE *f, const char *text)
{
    fputc('"', f);
    for (const char *p = text; *p; p++) {
        if (*p == '"' || *p == '\\')
            fputc('\\', f);
        fputc(*p, f);
    }
    fputc('"', f);
}
static void match(FILE *f, const struct cm_rule *r)
{
    if (r->family)
        fprintf(f, "meta nfproto ipv%u ", r->family);
    if (*r->interface) {
        fputs(r->outgoing ? "oifname " : "iifname ", f);
        quote(f, r->interface);
        fputc(' ', f);
    }
    if (*r->source)
        fprintf(f, "%s saddr %s ", strchr(r->source, ':') ? "ip6" : "ip", r->source);
    if (*r->destination)
        fprintf(f, "%s daddr %s ", strchr(r->destination, ':') ? "ip6" : "ip", r->destination);
    if (!strcmp(r->protocol, "both"))
        fputs("meta l4proto { tcp, udp } ", f);
    else if (strcmp(r->protocol, "any"))
        fprintf(f, "meta l4proto %s ", r->protocol);
    if (r->port) {
        fprintf(f, "th dport %u", r->port);
        if (r->port_end > r->port)
            fprintf(f, "-%u", r->port_end);
        fputc(' ', f);
    }
}
static void verdict(FILE *f, enum cm_kind kind, unsigned logging)
{
    if (kind == CM_DENY)
        fputs(logging ? "counter jump log_drop" : "counter drop", f);
    else if (kind == CM_REJECT)
        fputs("counter jump reject_traffic", f);
    else
        fputs(logging >= 2 ? "counter jump log_accept" : "counter accept", f);
}
static void plumbing(FILE *f, bool out)
{
    fprintf(f, "  %s \"lo\" accept comment \"cm:loopback\"\n", out ? "oifname" : "iifname");
    /* Numeric ICMP protocol IDs do not depend on /etc/protocols or NSS. */
    fputs("  meta l4proto 1 icmp type { destination-unreachable, time-exceeded, "
          "parameter-problem } accept\n",
          f);
    fputs("  meta l4proto 58 icmpv6 type { destination-unreachable, packet-too-big, "
          "time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, "
          "nd-neighbor-solicit, nd-neighbor-advert } accept\n",
          f);
    if (out)
        fputs("  udp sport 68 udp dport 67 accept\n  udp sport 546 udp dport 547 accept\n", f);
    else
        fputs("  udp sport 67 udp dport 68 accept\n  ip6 saddr fe80::/10 udp sport 547 udp dport "
              "546 accept\n",
              f);
}
unsigned cm_meter_timeout(const struct cm_rule *r)
{
    uint64_t period = r->period ? r->period : 60;
    uint64_t rate = r->rate ? r->rate : 1;
    uint64_t refill = ((uint64_t)r->burst * period + rate - 1) / rate;
    uint64_t timeout = refill > period * 2 ? refill : period * 2;
    return (unsigned)(timeout + 1); /* Inputs bound this to 360000001 seconds. */
}
unsigned cm_meter_size(const struct cm_config *c)
{
    unsigned sets = 0;
    for (size_t i = 0; i < c->rule_count; i++)
        if (c->rules[i].kind == CM_LIMIT)
            sets += 2;
    unsigned size = sets ? CM_METER_BUDGET / sets : 65536U;
    return size < 65536U ? size : 65536U;
}
char *cm_firewall_script(const struct cm_config *c, const struct cm_state *s, bool policy_exists,
                         bool bans_exist, bool rebuild)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    if (!f) {
        fputs("cannot allocate ruleset buffer\n", stderr);
        exit(1);
    }
    if (rebuild && policy_exists)
        fprintf(f, "delete table inet %s\n", CM_TABLE);
    if (bans_exist)
        fprintf(f, "delete table inet %s\n", CM_BAN_TABLE);
    if (rebuild && c->enabled) {
        fprintf(f, "table inet %s {\n", CM_TABLE);
        bool rejecting = c->packet_log != 0;
        for (size_t i = 0; i < c->rule_count; i++)
            rejecting = rejecting || c->rules[i].kind == CM_REJECT;
        if (rejecting) {
            fputs(" chain reject_traffic {\n", f);
            if (c->packet_log)
                fprintf(f,
                        " limit rate 5/second burst 10 packets log prefix \"CM-REJECT \" "
                        "level warn%s\n",
                        c->packet_log == 3 ? " flags all" : "");
            fputs(" meta l4proto tcp counter reject with tcp reset\n"
                  " counter reject with icmpx type port-unreachable\n }\n",
                  f);
        }
        if (c->packet_log) {
            const char *flags = c->packet_log == 3 ? " flags all" : "";
            fprintf(
                f,
                " chain log_drop { limit rate 5/second burst 10 packets log prefix \"CM-DROP \" "
                "level warn%s\n counter drop\n }\n",
                flags);
            if (c->packet_log >= 2)
                fprintf(f,
                        " chain log_accept { ct state new limit rate 5/second burst 10 packets log "
                        "prefix \"CM-ALLOW \" level info%s\n accept\n }\n",
                        flags);
        }
        for (size_t i = 0; i < c->rule_count; i++)
            if (c->rules[i].kind == CM_LIMIT) {
                const struct cm_rule *r = &c->rules[i];
                for (unsigned family = 4; family <= 6; family += 2) {
                    fprintf(f,
                            " set rate%u_%u { type ipv%u_addr; flags dynamic,timeout; timeout %us; "
                            "size %u; }\n",
                            family, r->id, family, cm_meter_timeout(r), cm_meter_size(c));
                    fprintf(f,
                            " chain gate%u_%u { update @rate%u_%u { %s %s "
                            "limit rate %u/%s burst %u packets } return\n ",
                            family, r->id, family, r->id, family == 4 ? "ip" : "ip6",
                            r->outgoing ? "daddr" : "saddr", r->rate,
                            r->period == 1      ? "second"
                            : r->period == 3600 ? "hour"
                                                : "minute",
                            r->burst);
                    /* Exhausted buckets and a full dynamic set both reach this drop. */
                    verdict(f, CM_DENY, c->packet_log);
                    fputs("\n }\n", f);
                }
            }
        for (unsigned direction = 0; direction < 2; direction++) {
            bool out = direction != 0;
            bool restrictive = out ? c->output_drop : c->input_drop;
            fprintf(f, " chain %s { type filter hook %s priority 0; policy %s;\n",
                    out ? "output" : "input", out ? "output" : "input",
                    restrictive ? "drop" : "accept");
            if (restrictive) {
                plumbing(f, out);
                fputs("  ct state invalid ", f);
                verdict(f, CM_DENY, c->packet_log);
                fputc('\n', f);
            }
            /* All limit gates precede every ordinary allow, including overlapping rules. */
            for (size_t i = 0; i < c->rule_count; i++) {
                const struct cm_rule *r = &c->rules[i];
                if (r->kind != CM_LIMIT || r->outgoing != out)
                    continue;
                for (unsigned family = 4; family <= 6; family += 2) {
                    if ((r->family && r->family != family) ||
                        (*r->source && ((strchr(r->source, ':') != NULL) != (family == 6))) ||
                        (*r->destination &&
                         ((strchr(r->destination, ':') != NULL) != (family == 6))))
                        continue;
                    fprintf(f, "  meta nfproto ipv%u ", family);
                    match(f, r);
                    fprintf(f, "ct state new tcp flags & (syn | ack) == syn jump gate%u_%u", family,
                            r->id);
                    fprintf(f, " comment \"cm:rate:%u:%u\"\n", r->id, family);
                }
            }
            /* User rule order is visible and first-match; IDs are stable. */
            for (size_t i = 0; i < c->rule_count; i++) {
                const struct cm_rule *r = &c->rules[i];
                if (r->outgoing != out)
                    continue;
                fputs("  ", f);
                match(f, r);
                verdict(f, r->kind, c->packet_log);
                char comment[224];
                snprintf(comment, sizeof comment, "cm:rule:%u %s", r->id, r->comment);
                fputs(" comment ", f);
                quote(f, comment);
                fputc('\n', f);
            }
            if (!c->isolation)
                fputs("  ct state established,related accept comment \"cm:established\"\n", f);
            else if (out) {
                fputs("  ct state established ct direction reply meta l4proto tcp tcp sport { ", f);
                for (size_t i = 0; i < c->guard_port_count; i++)
                    fprintf(f, "%s%u", i ? "," : "", c->guard_ports[i]);
                fputs(" } accept comment \"cm:ssh-replies\"\n", f);
            }
            if (c->packet_log && restrictive)
                fputs("  counter jump log_drop\n", f);
            else if (c->packet_log >= 2)
                fputs("  counter jump log_accept\n", f);
            fputs(" }\n", f);
        }
        fputs("}\n", f);
    }
    bool need_bans = c->enabled && c->guard_enabled;
    for (size_t i = 0; i < s->ban_count; i++)
        if (c->enabled && !s->bans[i].automatic && s->bans[i].expires > cm_now())
            need_bans = true;
    if (need_bans) {
        fprintf(f, "table inet %s {\n", CM_BAN_TABLE);
        if (c->packet_log)
            fprintf(f,
                    " chain log_ban { limit rate 5/second burst 10 packets log prefix \"CM-BAN \" "
                    "level warn%s\n counter drop\n }\n",
                    c->packet_log == 3 ? " flags all" : "");
        const char *names[] = {"manual_all4", "manual_all6", "manual_ssh4", "manual_ssh6",
                               "auto_all4",   "auto_all6",   "auto_ssh4",   "auto_ssh6"};
        uint64_t now = cm_now();
        for (unsigned k = 0; k < 8; k++) {
            fprintf(f, " set %s { type %s; flags timeout; size %u;", names[k],
                    k % 2 ? "ipv6_addr" : "ipv4_addr", CM_MAX_BANS);
            bool first = true;
            for (size_t i = 0; i < s->ban_count; i++) {
                const struct cm_ban *b = &s->bans[i];
                if (b->expires <= now || b->automatic != (k >= 4) ||
                    b->all_ports != ((k % 4) < 2) ||
                    ((strchr(b->address, ':') != NULL) != (k % 2 != 0)) ||
                    (b->automatic && (!c->guard_enabled || cm_ignored(c, b->address))))
                    continue;
                fputs(first ? " elements = { " : ", ", f);
                first = false;
                fputs(b->address, f);
                if (b->expires != INT64_MAX)
                    fprintf(f, " timeout %llus", (unsigned long long)(b->expires - now));
            }
            if (!first)
                fputs(" };", f);
            fputs(" }\n", f);
        }
        fputs(" chain input { type filter hook input priority -20; policy accept;\n", f);
        for (unsigned k = 0; k < 8; k++) {
            fprintf(f, "  %s saddr @%s ", k % 2 ? "ip6" : "ip", names[k]);
            if ((k % 4) >= 2) {
                fputs("meta l4proto tcp tcp dport { ", f);
                for (size_t i = 0; i < c->guard_port_count; i++)
                    fprintf(f, "%s%u", i ? "," : "", c->guard_ports[i]);
                fputs(" } ", f);
            }
            fprintf(f, "counter %s comment \"cm:ban:%s\"\n",
                    c->packet_log ? "jump log_ban" : "drop", names[k]);
        }
        fputs(" }\n}\n", f);
    }
    if (fclose(f)) {
        free(buf);
        fputs("cannot finish ruleset buffer\n", stderr);
        exit(1);
    }
    return buf;
}
int cm_nft(const char *commands, bool check, char **output, struct cm_error *e)
{
    if (output)
        *output = NULL;
    struct nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx)
        return cm_fail(e, "cannot allocate libnftables context");
    nft_ctx_output_set_flags(ctx, NFT_CTX_OUTPUT_JSON | NFT_CTX_OUTPUT_NUMERIC_ALL);
    nft_ctx_set_dry_run(ctx, check);
    nft_ctx_clear_include_paths(ctx);
    if (nft_ctx_buffer_output(ctx) || nft_ctx_buffer_error(ctx)) {
        nft_ctx_free(ctx);
        return cm_fail(e, "cannot capture libnftables diagnostics");
    }
    int r = nft_run_cmd_from_buffer(ctx, commands);
    if (r) {
        const char *message = nft_ctx_get_error_buffer(ctx);
        cm_fail(e, "nftables: %s", message && *message ? message : "operation failed");
    } else if (output)
        *output = cm_strdup(nft_ctx_get_output_buffer(ctx));
    nft_ctx_free(ctx);
    return r ? -1 : 0;
}
void cm_normalize(struct json_object *o)
{
    if (json_object_is_type(o, json_type_array)) {
        for (size_t i = 0; i < json_object_array_length(o); i++)
            cm_normalize(json_object_array_get_idx(o, i));
        return;
    }
    if (!json_object_is_type(o, json_type_object))
        return;
    json_object_object_del(o, "handle");
    json_object_object_del(o, "packets");
    json_object_object_del(o, "bytes");
    /* Runtime set entries and their expiry are not policy structure. */
    struct json_object *set;
    struct json_object *family, *table, *name;
    if (json_object_object_get_ex(o, "set", &set) && json_object_is_type(set, json_type_object) &&
        json_object_object_get_ex(set, "family", &family) &&
        json_object_object_get_ex(set, "table", &table) &&
        json_object_object_get_ex(set, "name", &name))
        json_object_object_del(set, "elem");
    if (json_object_object_get_ex(o, "set", &set) && json_object_is_type(set, json_type_object))
        json_object_object_del(set, "count");
    json_object_object_foreach(o, key, val)
    {
        (void)key;
        cm_normalize(val);
    }
}
static int objects(const char *command, struct json_object **out, struct cm_error *e)
{
    char *text = NULL;
    if (cm_nft(command, false, &text, e))
        return -1;
    struct json_object *root = json_tokener_parse(text);
    free(text);
    struct json_object *objects;
    if (!root || !json_object_object_get_ex(root, "nftables", &objects) ||
        !json_object_is_type(objects, json_type_array)) {
        if (root)
            json_object_put(root);
        return cm_fail(e, "invalid libnftables ruleset output");
    }
    *out = json_object_get(objects);
    json_object_put(root);
    return 0;
}
static bool named(struct json_object *v, const char *field, const char *value)
{
    struct json_object *x = NULL;
    return json_object_object_get_ex(v, field, &x) &&
        json_object_is_type(x, json_type_string) && !strcmp(json_object_get_string(x), value);
}
static int tables(bool *policy, bool *bans, struct cm_error *e)
{
    struct json_object *list = NULL;
    if (objects("list tables\n", &list, e))
        return -1;
    *policy = false;
    *bans = false;
    for (size_t i = 0; i < json_object_array_length(list); i++) {
        struct json_object *v = NULL;
        if (json_object_object_get_ex(json_object_array_get_idx(list, i), "table", &v) &&
            named(v, "family", "inet")) {
            *policy |= named(v, "name", CM_TABLE);
            *bans |= named(v, "name", CM_BAN_TABLE);
        }
    }
    json_object_put(list);
    return 0;
}
int cm_kernel_snapshot(struct json_object **out, bool *policy, bool *bans, size_t *foreign,
                       struct cm_error *e)
{
    *foreign = 0; /* Foreign-owner inventory belongs to status, not the mutation hot path. */
    if (tables(policy, bans, e))
        return -1;
    struct json_object *selected = json_object_new_array();
    const char *commands[] = {"list table inet " CM_TABLE "\n", "list table inet " CM_BAN_TABLE "\n"};
    for (unsigned k = 0; k < 2; k++) {
        if (!(k ? *bans : *policy))
            continue;
        struct json_object *list = NULL;
        if (objects(commands[k], &list, e)) {
            json_object_put(selected);
            return -1;
        }
        for (size_t i = 0; i < json_object_array_length(list); i++) {
            struct json_object *v = json_object_array_get_idx(list, i), *ignore;
            if (!json_object_object_get_ex(v, "metainfo", &ignore) &&
                !json_object_object_get_ex(v, "element", &ignore))
                json_object_array_add(selected, json_object_get(v));
        }
        json_object_put(list);
    }
    cm_normalize(selected);
    *out = selected;
    return 0;
}
int cm_foreign_chains(size_t *count, struct cm_error *e)
{
    struct json_object *list = NULL;
    if (objects("list ruleset\n", &list, e))
        return -1;
    *count = 0;
    for (size_t i = 0; i < json_object_array_length(list); i++) {
        struct json_object *v = NULL, *hook = NULL;
        if (json_object_object_get_ex(json_object_array_get_idx(list, i), "chain", &v) &&
            json_object_object_get_ex(v, "hook", &hook) &&
            !(named(v, "family", "inet") &&
              (named(v, "table", CM_TABLE) || named(v, "table", CM_BAN_TABLE))))
            (*count)++;
    }
    json_object_put(list);
    return 0;
}
static unsigned ban_set(const struct cm_ban *b)
{
    return (b->automatic ? 4U : 0U) + (b->all_ports ? 0U : 2U) +
        (strchr(b->address, ':') ? 1U : 0U);
}
static bool enforced(const struct cm_config *c, const struct cm_ban *b, uint64_t now)
{
    return c->enabled && b->expires > now &&
        (!b->automatic || (c->guard_enabled && !cm_ignored(c, b->address)));
}
static bool unchanged_ban(const struct cm_config *c, const struct cm_ban *b,
                          const struct cm_state *s, uint64_t now)
{
    for (size_t i = 0; i < s->ban_count; i++)
        if (enforced(c, &s->bans[i], now) && !strcmp(b->address, s->bans[i].address) &&
            b->automatic == s->bans[i].automatic && b->all_ports == s->bans[i].all_ports &&
            b->expires == s->bans[i].expires)
            return true;
    return false;
}
char *cm_ban_delta(const struct cm_config *c, const struct cm_state *old, const struct cm_state *next)
{
    const char *names[] = {"manual_all4", "manual_all6", "manual_ssh4", "manual_ssh6",
                          "auto_all4", "auto_all6", "auto_ssh4", "auto_ssh6"};
    char *buf = NULL;
    size_t length = 0;
    FILE *f = open_memstream(&buf, &length);
    if (!f)
        return NULL;
    uint64_t now = cm_now();
    for (size_t i = 0; i < old->ban_count; i++)
        if (!unchanged_ban(c, &old->bans[i], next, now))
            fprintf(f, "destroy element inet %s %s { %s }\n", CM_BAN_TABLE,
                    names[ban_set(&old->bans[i])], old->bans[i].address);
    for (size_t i = 0; i < next->ban_count; i++) {
        const struct cm_ban *b = &next->bans[i];
        if (!enforced(c, b, now) || unchanged_ban(c, b, old, now))
            continue;
        fprintf(f, "destroy element inet %s %s { %s }\nadd element inet %s %s { %s",
                CM_BAN_TABLE, names[ban_set(b)], b->address, CM_BAN_TABLE, names[ban_set(b)], b->address);
        if (b->expires != INT64_MAX)
            fprintf(f, " timeout %llus", (unsigned long long)(b->expires - now));
        fputs(" }\n", f);
    }
    if (fclose(f)) {
        free(buf);
        return NULL;
    }
    return buf;
}
int cm_ban_drift(const struct cm_config *c, const struct cm_state *s, struct cm_error *e)
{
    bool policy, bans;
    if (tables(&policy, &bans, e))
        return -1;
    uint64_t now = cm_now();
    if (!bans) {
        for (size_t i = 0; i < s->ban_count; i++)
            if (enforced(c, &s->bans[i], now) && s->bans[i].expires > now + 2)
                return 1;
        return 0;
    }
    struct json_object *list = NULL;
    if (objects("list table inet " CM_BAN_TABLE "\n", &list, e))
        return -1;
    const char *names[] = {"manual_all4", "manual_all6", "manual_ssh4", "manual_ssh6",
                          "auto_all4", "auto_all6", "auto_ssh4", "auto_ssh6"};
    bool seen[CM_MAX_BANS] = {0};
    int drift = 0;
    for (size_t i = 0; i < json_object_array_length(list) && !drift; i++) {
        struct json_object *set = NULL, *elements = NULL;
        struct json_object *v = json_object_array_get_idx(list, i);
        if (!json_object_object_get_ex(v, "set", &set) &&
            !json_object_object_get_ex(v, "element", &set))
            continue;
        if (!json_object_object_get_ex(set, "elem", &elements))
            continue;
        if (!json_object_is_type(elements, json_type_array) ||
            json_object_array_length(elements) > CM_MAX_BANS) {
            drift = 1;
            break;
        }
        unsigned k = 0;
        while (k < 8 && !named(set, "name", names[k]))
            k++;
        if (k == 8)
            continue;
        for (size_t j = 0; j < json_object_array_length(elements); j++) {
            struct json_object *element = json_object_array_get_idx(elements, j), *value = element,
                               *attr = NULL, *expires = NULL, *timeout = NULL;
            if (json_object_is_type(element, json_type_object)) {
                if (!json_object_object_get_ex(element, "elem", &attr))
                    attr = element;
                if (!json_object_object_get_ex(attr, "val", &value)) {
                    drift = 1;
                    break;
                }
                json_object_object_get_ex(attr, "expires", &expires);
                json_object_object_get_ex(attr, "timeout", &timeout);
            }
            if (expires && json_object_get_uint64(expires) <= 2)
                continue; /* Natural expiry can race state collection by two seconds. */
            size_t at = 0;
            while (at < s->ban_count && !(enforced(c, &s->bans[at], now) &&
                ban_set(&s->bans[at]) == k && named(set, "name", names[k]) &&
                json_object_is_type(value, json_type_string) &&
                !strcmp(s->bans[at].address, json_object_get_string(value))))
                at++;
            if (at == s->ban_count) {
                drift = 1;
                break;
            }
            seen[at] = true;
            bool timed = timeout && json_object_get_uint64(timeout) != 0;
            if (timed == (s->bans[at].expires == INT64_MAX)) {
                drift = 1;
                break;
            }
            if (expires && s->bans[at].expires != INT64_MAX) {
                uint64_t remaining = json_object_get_uint64(expires),
                         expected = s->bans[at].expires - now;
                if ((remaining > expected && remaining - expected > 2) ||
                    (expected > remaining && expected - remaining > 2)) {
                    drift = 1;
                    break;
                }
            }
        }
    }
    for (size_t i = 0; i < s->ban_count; i++)
        if (enforced(c, &s->bans[i], now) && s->bans[i].expires > now + 2 && !seen[i])
            drift = 1;
    json_object_put(list);
    return drift;
}
static struct json_object *table_objects(struct json_object *list, const char *table)
{
    struct json_object *selected = json_object_new_array();
    if (!json_object_is_type(list, json_type_array)) {
        json_object_put(selected);
        return NULL;
    }
    for (size_t i = 0; i < json_object_array_length(list); i++) {
        struct json_object *object = json_object_array_get_idx(list, i);
        bool valid = false, included = false;
        if (json_object_is_type(object, json_type_object)) {
            json_object_object_foreach(object, kind, value) {
                const char *field = !strcmp(kind, "table") ? "name" : "table";
                if (named(value, "family", "inet") &&
                    (named(value, field, CM_TABLE) || named(value, field, CM_BAN_TABLE))) {
                    valid = true;
                    included |= named(value, field, table);
                }
            }
        }
        if (!valid) {
            json_object_put(selected);
            return NULL;
        }
        if (included)
            json_object_array_add(selected, json_object_get(object));
    }
    return selected;
}
int cm_drift(const struct cm_paths *p, bool *policy, bool *bans, size_t *foreign,
             struct cm_error *e)
{
    struct json_object *live = NULL, *saved = NULL;
    if (cm_kernel_snapshot(&live, policy, bans, foreign, e))
        return -1;
    int r = cm_read_json(p->state, "applied.json", &saved, e);
    if (r < 0) {
        json_object_put(live);
        return -1;
    }
    bool active = false, known = false;
    if (cm_activation(p, &active, &known, e)) {
        json_object_put(live);
        if (saved)
            json_object_put(saved);
        return -1;
    }
    int drift = 0;
    if (known && !active && !*policy && !*bans)
        drift = 0; /* Disabled startup legitimately leaves last boot's snapshot unapplied. */
    else if (r == 1)
        drift = (*policy ? CM_DRIFT_POLICY : 0) | (*bans ? CM_DRIFT_BANS : 0);
    else {
        cm_normalize(saved);
        const char *names[] = {CM_TABLE, CM_BAN_TABLE};
        for (unsigned k = 0; k < 2; k++) {
            struct json_object *a = table_objects(live, names[k]), *b = table_objects(saved, names[k]);
            if (!a || !b)
                drift |= CM_DRIFT_POLICY | CM_DRIFT_BANS;
            else if (!json_object_equal(a, b))
                drift |= k ? CM_DRIFT_BANS : CM_DRIFT_POLICY;
            if (a)
                json_object_put(a);
            if (b)
                json_object_put(b);
        }
    }
    json_object_put(live);
    if (saved)
        json_object_put(saved);
    return drift;
}
