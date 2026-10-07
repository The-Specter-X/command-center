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
    fputs("  meta l4proto icmp icmp type { destination-unreachable, time-exceeded, "
          "parameter-problem } accept\n",
          f);
    fputs("  meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, "
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
                        "level warning%s\n",
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
                "level warning%s\n counter drop\n }\n",
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
                            "size 65536; }\n",
                            family, r->id, family, (r->period ? r->period : 60) * 2);
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
                    "level warning%s\n counter drop\n }\n",
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
    json_object_object_foreach(o, key, val)
    {
        (void)key;
        cm_normalize(val);
    }
}
int cm_kernel_snapshot(struct json_object **out, bool *policy, bool *bans, size_t *foreign,
                       struct cm_error *e)
{
    char *text = NULL;
    if (cm_nft("list ruleset\n", false, &text, e))
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
    *policy = false;
    *bans = false;
    *foreign = 0;
    struct json_object *selected = json_object_new_array();
    for (size_t i = 0; i < json_object_array_length(objects); i++) {
        struct json_object *item = json_object_array_get_idx(objects, i), *v = NULL;
        if (!json_object_is_type(item, json_type_object)) {
            json_object_put(root);
            json_object_put(selected);
            return cm_fail(e, "unexpected libnftables object");
        }
        const char *type = NULL;
        json_object_object_foreach(item, k, value)
        {
            type = k;
            v = value;
            break;
        }
        if (!v || !type || !strcmp(type, "metainfo"))
            continue;
        struct json_object *family, *name, *table, *hook;
        const char *tbl = NULL;
        if (!json_object_object_get_ex(v, "family", &family))
            continue;
        if (!strcmp(type, "table") && json_object_object_get_ex(v, "name", &name))
            tbl = json_object_get_string(name);
        else if (json_object_object_get_ex(v, "table", &table))
            tbl = json_object_get_string(table);
        bool ours = tbl && !strcmp(json_object_get_string(family), "inet") &&
                    (!strcmp(tbl, CM_TABLE) || !strcmp(tbl, CM_BAN_TABLE));
        if (ours) {
            if (!strcmp(type, "table")) {
                if (!strcmp(tbl, CM_TABLE))
                    *policy = true;
                else
                    *bans = true;
            }
            /* Element listings can be separate objects for dynamic sets. */
            if (strcmp(type, "element"))
                json_object_array_add(selected, json_object_get(item));
        } else if (!strcmp(type, "chain") && json_object_object_get_ex(v, "hook", &hook))
            (*foreign)++;
    }
    cm_normalize(selected);
    json_object_put(root);
    *out = selected;
    return 0;
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
    bool equal = r == 1 ? !*policy && !*bans : json_object_equal(live, saved);
    json_object_put(live);
    if (saved)
        json_object_put(saved);
    return equal ? 0 : 1;
}
