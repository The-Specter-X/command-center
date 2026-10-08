/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void subprocesses(void)
{
    /* Captured output must survive callers with any combination of closed stdio. */
    for (unsigned mask = 0; mask < 8; mask++) {
        pid_t pid = fork();
        assert(pid >= 0);
        if (!pid) {
            for (unsigned fd = 0; fd < 3; fd++)
                if (mask & (1U << fd))
                    close((int)fd);
            struct cm_error e;
            char *output = NULL;
            char *argv[] = {"printf", "captured text", NULL};
            int result = cm_capture("/usr/bin/printf", argv, &output, &e);
            bool good = !result && output && !strcmp(output, "captured text");
            free(output);
            _exit(good ? 0 : 1);
        }
        int status;
        assert(waitpid(pid, &status, 0) == pid);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    struct cm_error e;
    char *output = NULL;
    char *argv[] = {"missing", NULL};
    assert(cm_capture("/no/such/command-center-program", argv, &output, &e));
    assert(!output);
    char *slow[] = {"sleep", "3", NULL};
    assert(cm_exec_timeout("/usr/bin/sleep", slow, 1, &e));
    assert(strstr(e.text, "deadline"));
}

static void strict_json(void)
{
    struct cm_error e;
    struct json_object *o = NULL;
    const char *bad[] = {"{\"x\":1,\"x\":2}", "{\"x\":1,\"\\u0078\":2}",
                         "{}{}", "{\"x\":NaN}", "{\"x\":1,}", "{\"x\":\"\xff\"}"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        assert(cm_parse_json(bad[i], strlen(bad[i]), &o, &e));
        assert(!o);
    }
    assert(cm_parse_json("{}\0{}", 5, &o, &e));
    assert(!cm_parse_json("{\"x\":[1,2]}\n", 12, &o, &e));
    json_object_put(o);
}

static void saturation(void)
{
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    struct cm_error e = {0};
    cm_config_default(c);
    c->guard_enabled = true;
    c->threshold = 3;
    s->attempt_count = CM_MAX_ATTEMPTS;
    for (size_t i = 0; i < s->attempt_count; i++) {
        snprintf(s->attempts[i].address, CM_ADDRESS_MAX, "2001:db8::%zx", i + 1);
        s->attempts[i].times[0] = 1000;
        s->attempts[i].count = 1;
    }
    bool banned = true;
    assert(cm_guard_event(c, s, "192.0.2.1", 1001, &banned, &e) == 1);
    assert(!banned && s->attempt_count == CM_MAX_ATTEMPTS);
    assert(!cm_guard_event(c, s, "2001:db8::1", 1001, &banned, &e) && !banned);
    assert(!cm_guard_event(c, s, "2001:db8::1", 1002, &banned, &e) && banned);
    assert(s->ban_count == 1 && s->attempt_count == CM_MAX_ATTEMPTS - 1);
    assert(!cm_guard_event(c, s, "192.0.2.1", 1003, &banned, &e));
    memset(s, 0, sizeof *s);
    s->ban_count = CM_MAX_BANS;
    for (size_t i = 0; i < s->ban_count; i++) {
        snprintf(s->bans[i].address, CM_ADDRESS_MAX, "2001:db8::%zx", i + 1);
        s->bans[i].expires = INT64_MAX;
        s->bans[i].all_ports = true;
    }
    c->threshold = 100;
    for (unsigned i = 0; i < 110; i++) {
        int result = cm_guard_event(c, s, "192.0.2.2", 1000, &banned, &e);
        assert(result == (i >= 99 ? 1 : 0));
        assert(!banned);
    }
    assert(s->attempt_count == 1 && s->attempts[0].count == 100);
    assert(s->ban_count == CM_MAX_BANS && s->bans[0].expires == INT64_MAX);
    s->ban_count--; /* Once capacity is available, the retained source can progress. */
    assert(!cm_guard_event(c, s, "192.0.2.2", 1001, &banned, &e) && banned);
    assert(s->ban_count == CM_MAX_BANS && !s->attempt_count);
    free(c);
    free(s);
}

static void semantic_changes(void)
{
    struct cm_config *a = cm_alloc(sizeof *a), *b = cm_alloc(sizeof *b);
    cm_config_default(a);
    *b = *a;
    assert(!cm_changes(a, b));
    b->log_level = 4;
    assert(cm_changes(a, b) == CM_CHANGE_METADATA);
    *b = *a;
    b->threshold++;
    assert(cm_changes(a, b) == CM_CHANGE_GUARD);
    *b = *a;
    b->guard_ports[0] = 2222;
    assert(cm_changes(a, b) == (CM_CHANGE_GUARD | CM_CHANGE_BANS));
    a->isolation = b->isolation = true;
    assert(cm_changes(a, b) == CM_CHANGE_ENFORCEMENT);
    *b = *a;
    b->input_drop = true;
    assert(cm_changes(a, b) == CM_CHANGE_POLICY);
    struct cm_rule meter = {.rate = 1, .period = 1, .burst = 10};
    assert(cm_meter_timeout(&meter) == 11);
    meter = (struct cm_rule){.rate = 3, .period = 3600, .burst = 7};
    assert(cm_meter_timeout(&meter) == 8401);
    meter = (struct cm_rule){.rate = 1, .period = 3600, .burst = 100000};
    assert(cm_meter_timeout(&meter) == 360000001);
    a->rule_count = CM_MAX_RULES;
    for (size_t i = 0; i < a->rule_count; i++)
        a->rules[i].kind = CM_LIMIT;
    assert(cm_meter_size(a) == 512);
    assert(cm_meter_size(a) * 2 * CM_MAX_RULES <= CM_METER_BUDGET);
    free(a);
    free(b);
}

static void addresses(void)
{
    struct cm_error e;
    char out[CM_ADDRESS_MAX];
    uint64_t n;
    unsigned duration;
    uint16_t port;
    char protocol[5];
    assert(!cm_uint("65535", 1, 65535, &n, &e) && n == 65535);
    assert(cm_uint("-1", 0, 65535, &n, &e));
    assert(cm_uint("+1", 0, 65535, &n, &e));
    assert(cm_uint("18446744073709551616", 0, UINT64_MAX, &n, &e));
    assert(!cm_address("192.0.2.99/24", true, out, sizeof out, &e) && !strcmp(out, "192.0.2.0/24"));
    assert(!cm_address("2001:0DB8::a/64", true, out, sizeof out, &e) &&
           !strcmp(out, "2001:db8::/64"));
    assert(cm_contains("192.0.2.0/24", "192.0.2.250"));
    assert(!cm_contains("192.0.2.0/24", "192.0.3.1"));
    assert(cm_contains("2001:db8::/33", "2001:db8:4000::1"));
    assert(!cm_contains("2001:db8::/33", "2001:db8:8000::1"));
    assert(!cm_contains("0.0.0.0/0", "::1"));
    assert(cm_contains("::/0", "2001:db8::1"));
    const char *bad[] = {"hostname",    "1.2.3.999", "192.0.2.1; flush ruleset",
                         "::1%lo",      "::1/129",   "192.0.2.1/-1",
                         "192.0.2.1/33"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
        assert(cm_address(bad[i], true, out, sizeof out, &e));
    assert(cm_address("192.0.2.1/24", false, out, sizeof out, &e));
    assert(!cm_address("::ffff:192.0.2.1", false, out, sizeof out, &e) &&
           !strcmp(out, "192.0.2.1"));
    assert(!cm_duration("30d", &duration, &e) && duration == 2592000);
    assert(!cm_duration("10m", &duration, &e) && duration == 600);
    assert(cm_duration("31d", &duration, &e));
    assert(cm_duration("0", &duration, &e));
    assert(cm_duration("1hour", &duration, &e));
    assert(!cm_service("ssh", &port, protocol, &e) && port == 22 && !strcmp(protocol, "tcp"));
    assert(!cm_service("53/udp", &port, protocol, &e) && port == 53 && !strcmp(protocol, "udp"));
    assert(cm_service("22", &port, protocol, &e));
    assert(cm_service("0/tcp", &port, protocol, &e));
}
static void configuration(void)
{
    struct cm_error e;
    struct cm_config *c = cm_alloc(sizeof *c), *copy = cm_alloc(sizeof *copy);
    cm_config_default(c);
    struct json_object *o = cm_config_json(c);
    assert(!cm_config_parse(o, copy, &e));
    assert(copy->threshold == 6 && !copy->enabled && !copy->guard_enabled);
    json_object_object_add(o, "unexpected", json_object_new_int(1));
    assert(cm_config_parse(o, copy, &e));
    json_object_object_del(o, "unexpected");
    json_object_object_add(o, "enabled", json_object_new_string("false"));
    assert(cm_config_parse(o, copy, &e));
    json_object_put(o);
    c->rule_count = 1;
    c->next_id = 2;
    c->rules[0] = (struct cm_rule){.id = 1, .kind = CM_LIMIT, .port = 22, .rate = 6, .burst = 5};
    strcpy(c->rules[0].protocol, "tcp");
    o = cm_config_json(c);
    assert(!cm_config_parse(o, copy, &e));
    json_object_put(o);
    c->rules[0].rate = 0;
    o = cm_config_json(c);
    assert(cm_config_parse(o, copy, &e));
    json_object_put(o);
    free(c);
    free(copy);
}
static void guard(void)
{
    struct cm_error e;
    char ip[CM_ADDRESS_MAX];
    assert(cm_guard_parse("Failed password for invalid user admin from 192.0.2.1 port 40000 ssh2",
                          ip, sizeof ip) &&
           !strcmp(ip, "192.0.2.1"));
    assert(
        cm_guard_parse(
            "Failed password for user from 203.0.113.1 port 1 ssh2 from 2001:db8::2 port 2222 ssh2",
            ip, sizeof ip) &&
        !strcmp(ip, "2001:db8::2"));
    assert(cm_guard_parse(
        "Failed publickey for user from 192.0.2.2 port 40000 ssh2: ED25519 SHA256:example", ip,
        sizeof ip));
    assert(!cm_guard_parse("Accepted password for user from 192.0.2.1 port 40000 ssh2", ip,
                           sizeof ip));
    assert(
        !cm_guard_parse("Failed password for x from 192.0.2.1;flush port 1 ssh2", ip, sizeof ip));
    assert(!cm_guard_parse("Failed password for x from 192.0.2.1 port -1 ssh2", ip, sizeof ip));
    assert(!cm_guard_parse("Failed password for x from 192.0.2.1 port 1 ssh200", ip, sizeof ip));
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    cm_config_default(c);
    c->guard_enabled = true;
    c->threshold = 3;
    c->window = 60;
    c->duration = 120;
    bool banned;
    assert(!cm_guard_event(c, s, "127.0.0.1", 1000, &banned, &e) && !s->attempt_count);
    assert(!cm_guard_event(c, s, "192.0.2.1", 1000, &banned, &e) && !banned);
    assert(!cm_guard_event(c, s, "192.0.2.1", 1001, &banned, &e) && !banned);
    assert(!cm_guard_event(c, s, "192.0.2.1", 1002, &banned, &e) && banned && s->ban_count == 1 &&
           s->bans[0].expires == 1122);
    assert(!cm_guard_event(c, s, "192.0.2.1", 1003, &banned, &e) && !banned && s->ban_count == 1);
    assert(!cm_guard_event(c, s, "192.0.2.2", 1000, &banned, &e));
    assert(!cm_guard_event(c, s, "192.0.2.2", 1060, &banned, &e) && !banned);
    assert(s->attempts[0].count == 1);
    cm_state_expire(s, 1122);
    assert(!s->ban_count);
    struct json_object *o = cm_state_json(s);
    struct cm_state *copy = cm_alloc(sizeof *copy);
    assert(!cm_state_parse(o, copy, &e));
    assert(copy->attempt_count == s->attempt_count);
    json_object_put(o);
    s->ban_count = CM_MAX_BANS;
    for (size_t i = 0; i < CM_MAX_BANS; i++) {
        snprintf(s->bans[i].address, sizeof s->bans[i].address, "10.%zu.%zu.%zu", i / 65536,
                 (i / 256) % 256, i % 256);
        s->bans[i].expires = 2000;
    }
    assert(cm_state_ban(s, "203.0.113.20", 2000, false, &e));
    assert(!cm_state_ban(s, "10.0.0.1", 3000, false, &e));
    assert(s->bans[1].expires == 3000);
    free(c);
    free(s);
    free(copy);
}
static void policy(void)
{
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    cm_config_default(c);
    c->enabled = true;
    c->guard_enabled = true;
    c->next_id = 3;
    c->rule_count = 2;
    c->rules[0] = (struct cm_rule){.id = 1, .kind = CM_ALLOW, .port = 22};
    strcpy(c->rules[0].protocol, "tcp");
    c->rules[1] = (struct cm_rule){.id = 2, .kind = CM_DENY, .port = 22};
    strcpy(c->rules[1].protocol, "tcp");
    strcpy(c->rules[1].source, "192.0.2.0/24");
    char *text = cm_firewall_script(c, s, true, true, true);
    assert(!strstr(text, "flush ruleset"));
    assert(strstr(text, "cm:rule:1") < strstr(text, "cm:rule:2"));
    assert(strstr(text, "cm:rule:2") < strstr(text, "cm:established"));
    assert(!strstr(text, "cm:loopback")); /* Passive start introduces no exceptions. */
    c->input_drop = true;
    free(text);
    text = cm_firewall_script(c, s, true, true, true);
    assert(strstr(text, "nd-neighbor-advert"));
    assert(strstr(text, "cm:loopback"));
    free(text);
    text = cm_firewall_script(c, s, true, true, false);
    assert(!strstr(text, "delete table inet command_center\n"));
    assert(!strstr(text, "table inet command_center {"));
    free(text);
    struct json_object *a =
        json_tokener_parse("[{\"set\":{\"family\":\"inet\",\"table\":\"x\",\"handle\":1,\"elem\":["
                           "\"192.0.2.1\"],\"name\":\"a\"}},{\"rule\":{\"handle\":2,"
                           "\"expr\":[{\"counter\":{\"packets\":5,\"bytes\":20}}]}}]");
    struct json_object *b =
        json_tokener_parse("[{\"set\":{\"family\":\"inet\",\"table\":\"x\",\"handle\":3,\"elem\":[]"
                           ",\"name\":\"a\"}},{\"rule\":{"
                           "\"handle\":9,\"expr\":[{\"counter\":{\"packets\":0,\"bytes\":0}}]}}]");
    cm_normalize(a);
    cm_normalize(b);
    assert(json_object_equal(a, b));
    json_object_put(a);
    json_object_put(b);
    struct json_object *dynamic =
        json_tokener_parse("{\"set\":{\"op\":\"update\",\"elem\":{\"payload\":{\"protocol\":\"ip\","
                           "\"field\":\"saddr\"}},\"set\":\"@rate4_1\"}}");
    char *original = cm_strdup(json_object_to_json_string(dynamic));
    cm_normalize(dynamic);
    assert(!strcmp(original, json_object_to_json_string(dynamic)));
    free(original);
    json_object_put(dynamic);
    free(c);
    free(s);
}
static void commands(void)
{
    struct cm_config *c = cm_alloc(sizeof *c), *copy = cm_alloc(sizeof *copy);
    struct cm_state *s = cm_alloc(sizeof *s);
    struct cm_error e = {0};
    cm_config_default(c);
    char *out[] = {"out",         "443/tcp", "--to",      "203.0.113.10",
                   "--interface", "eth0",    "--comment", "quote \" and slash \\"};
    assert(!cm_rule_add(c, 8, out, CM_ALLOW, &e));
    assert(c->rules[0].outgoing && c->rules[0].id == 1);
    char *range[] = {"8000-8010/udp", "--family", "6"};
    assert(!cm_rule_add(c, 3, range, CM_REJECT, &e));
    char *limit[] = {"all", "--rate", "4/hour", "--burst", "2"};
    assert(!cm_rule_add(c, 5, limit, CM_LIMIT, &e));
    assert(c->rules[2].period == 3600 && c->rules[2].port == 0);
    assert(!cm_rule_move(c, 3, 1, &e));
    assert(c->rules[0].id == 3 && c->rules[1].id == 1);
    assert(!cm_rule_delete(c, 2, &e));
    assert(cm_rule_delete(c, 2, &e));
    struct json_object *o = cm_config_json(c);
    assert(!cm_config_parse(o, copy, &e));
    assert(copy->rules[0].id == 3 && copy->rules[1].outgoing);
    json_object_put(o);
    c->enabled = true;
    c->packet_log = 3;
    char *script = cm_firewall_script(c, s, false, false, true);
    assert(strstr(script, "flags all") && strstr(script, "203.0.113.10"));
    assert(strstr(script, "cm:rate:3:4") < strstr(script, "cm:rule:1"));
    assert(strstr(script, "quote \\\" and slash \\\\"));
    assert(!strstr(script, "flush ruleset"));
    free(script);
    assert(!cm_profile(c, "isolation", 2222, false, &e));
    assert(c->input_drop && c->output_drop && c->isolation && c->rules[0].port == 2222);
    script = cm_firewall_script(c, s, false, false, true);
    assert(strstr(script, "cm:ssh-replies") && !strstr(script, "cm:established"));
    free(script);
    c->duration = 0;
    c->threshold = 1;
    c->guard_all = true;
    bool banned;
    assert(!cm_guard_event(c, s, "192.0.2.9", 100, &banned, &e));
    assert(banned && s->bans[0].expires == INT64_MAX && s->bans[0].all_ports);
    cm_state_expire(s, UINT64_C(4000000000));
    assert(s->ban_count == 1);
    free(c);
    free(copy);
    free(s);
}
int main(void)
{
    addresses();
    configuration();
    guard();
    policy();
    commands();
    subprocesses();
    strict_json();
    saturation();
    semantic_changes();
    puts("Core boundary, guard, and policy tests passed.");
    return 0;
}
