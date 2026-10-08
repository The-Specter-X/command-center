/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

static double milliseconds(void)
{
    struct timespec t;
    assert(!clock_gettime(CLOCK_MONOTONIC, &t));
    return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1000000.0;
}
int main(void)
{
    struct cm_state *s = cm_alloc(sizeof *s), *copy = cm_alloc(sizeof *copy);
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_error e = {0};
    cm_config_default(c);
    c->enabled = c->guard_enabled = true;
    c->threshold = 100;
    uint64_t now = cm_now();
    s->ban_count = CM_MAX_BANS;
    s->attempt_count = CM_MAX_ATTEMPTS;
    for (size_t i = 0; i < CM_MAX_BANS; i++) {
        snprintf(s->bans[i].address, CM_ADDRESS_MAX, "2001:db8:1::%zx", i + 1);
        s->bans[i].expires = INT64_MAX;
        s->bans[i].all_ports = true;
        snprintf(s->attempts[i].address, CM_ADDRESS_MAX, "2001:db8:2::%zx", i + 1);
        s->attempts[i].count = 100;
        for (size_t j = 0; j < 100; j++)
            s->attempts[i].times[j] = now;
    }
    double start = milliseconds();
    struct json_object *record = cm_state_json(s), *parsed = NULL;
    const char *encoded = json_object_to_json_string_ext(record, JSON_C_TO_STRING_PLAIN);
    size_t bytes = strlen(encoded);
    assert(bytes < CM_MAX_FILE);
    assert(!cm_parse_json(encoded, bytes, &parsed, &e));
    assert(!cm_state_parse(parsed, copy, &e));
    assert(copy->ban_count == CM_MAX_BANS && copy->attempt_count == CM_MAX_ATTEMPTS);
    double state_ms = milliseconds() - start;
    size_t pretty_bytes = strlen(json_object_to_json_string_ext(record, JSON_C_TO_STRING_PRETTY));
    assert(pretty_bytes < CM_MAX_FILE);
    json_object_put(parsed);
    json_object_put(record);
    /* Exercise the persisted-file bound with the longest accepted timestamp values. */
    for (size_t i = 0; i < s->attempt_count; i++)
        for (size_t j = 0; j < 100; j++)
            s->attempts[i].times[j] = INT64_MAX;
    record = cm_state_json(s);
    size_t worst_bytes = strlen(json_object_to_json_string_ext(record, JSON_C_TO_STRING_PRETTY));
    assert(worst_bytes < CM_MAX_FILE);
    json_object_put(record);
    start = milliseconds();
    bool banned;
    for (unsigned i = 0; i < 128; i++)
        assert(cm_guard_event(c, copy, "192.0.2.1", now, &banned, &e) == 1 && !banned);
    double batch_ms = milliseconds() - start;
    c->rule_count = CM_MAX_RULES;
    c->next_id = CM_MAX_RULES + 1;
    for (size_t i = 0; i < c->rule_count; i++) {
        c->rules[i] = (struct cm_rule){.id = (uint32_t)i + 1, .kind = CM_LIMIT,
            .port = (uint16_t)(1000 + i), .rate = 1, .burst = 100000, .period = 3600};
        strcpy(c->rules[i].protocol, "tcp");
    }
    start = milliseconds();
    char *script = cm_firewall_script(c, s, true, true, true);
    size_t script_bytes = strlen(script);
    assert(script_bytes < CM_MAX_FILE && !strstr(script, "flush ruleset"));
    assert(strstr(script, "timeout 360000001s; size 512"));
    double compile_ms = milliseconds() - start;
    struct rusage usage;
    assert(!getrusage(RUSAGE_SELF, &usage));
    printf("{\"schema\":1,\"bans\":%u,\"tracked_sources\":%u,\"timestamps_per_source\":100,"
           "\"state_bytes\":%zu,\"state_pretty_bytes\":%zu,\"worst_timestamp_pretty_bytes\":%zu,"
           "\"state_roundtrip_ms\":%.3f,\"saturated_batch_events\":128,"
           "\"saturated_batch_ms\":%.3f,\"limit_rules\":%u,\"declared_meter_entries\":%u,"
           "\"compiled_bytes\":%zu,\"compile_ms\":%.3f,\"peak_rss_kib\":%ld}\n",
           CM_MAX_BANS, CM_MAX_ATTEMPTS, bytes, pretty_bytes, worst_bytes, state_ms, batch_ms, CM_MAX_RULES,
           cm_meter_size(c) * 2 * CM_MAX_RULES, script_bytes, compile_ms, usage.ru_maxrss);
    free(script);
    free(c);
    free(s);
    free(copy);
    return 0;
}
