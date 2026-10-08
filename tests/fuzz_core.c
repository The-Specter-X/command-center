/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *, size_t);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 65536)
        return 0;
    char *text = cm_alloc(size + 1);
    memcpy(text, data, size);
    struct cm_error e = {0};
    char address[CM_ADDRESS_MAX], protocol[5];
    uint16_t port;
    unsigned duration;
    uint64_t number;
    if (!cm_address(text, true, address, sizeof address, &e)) {
        char again[CM_ADDRESS_MAX];
        assert(!cm_address(address, true, again, sizeof again, &e));
        assert(!strcmp(address, again));
    }
    cm_service(text, &port, protocol, &e);
    cm_uint(text, 0, UINT64_MAX, &number, &e);
    cm_duration(text, &duration, &e);
    if (cm_guard_parse(text, address, sizeof address))
        assert(!cm_address(address, false, address, sizeof address, &e));
    struct json_object *o = NULL;
    if (!cm_parse_json(text, size, &o, &e)) {
        struct cm_config *c = cm_alloc(sizeof *c), *copy = cm_alloc(sizeof *copy);
        struct cm_state *s = cm_alloc(sizeof *s), *state_copy = cm_alloc(sizeof *state_copy);
        bool config = !cm_config_parse(o, c, &e);
        bool state = !cm_state_parse(o, s, &e);
        if (!config && !state && !cm_bundle_parse(o, c, s, &e))
            config = state = true;
        if (config) {
            struct json_object *round = cm_config_json(c);
            assert(!cm_config_parse(round, copy, &e));
            assert(!cm_changes(c, copy));
            json_object_put(round);
            c->enabled = true;
            if (!state)
                memset(s, 0, sizeof *s);
            char *script = cm_firewall_script(c, s, true, true, true);
            assert(strlen(script) < CM_MAX_FILE && !strstr(script, "flush ruleset"));
            free(script);
        }
        if (state) {
            struct json_object *round = cm_state_json(s);
            assert(!cm_state_parse(round, state_copy, &e));
            assert(state_copy->ban_count == s->ban_count);
            json_object_put(round);
            cm_state_expire(s, cm_now());
        }
        free(c);
        free(copy);
        free(s);
        free(state_copy);
        json_object_put(o);
    }
    free(text);
    return 0;
}

#ifdef CM_FUZZ_STANDALONE
static uint32_t random_state = 1;
static uint32_t next_random(void)
{
    random_state = random_state * 1664525U + 1013904223U;
    return random_state;
}
int main(void)
{
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    cm_config_default(c);
    struct json_object *config = cm_config_json(c), *state = cm_state_json(s),
                       *bundle = json_object_new_object();
    json_object_object_add(bundle, "schema", json_object_new_int(1));
    json_object_object_add(bundle, "config", json_object_get(config));
    json_object_object_add(bundle, "state", json_object_get(state));
    json_object_object_add(bundle, "active", json_object_new_boolean(true));
    const char *seeds[] = {json_object_to_json_string(config), json_object_to_json_string(state),
        json_object_to_json_string(bundle), "192.0.2.1/24", "2001:db8::1", "2222/tcp", "30d",
        "Failed password for invalid user from 192.0.2.1 port 12345 ssh2",
        "{\"a\":1,\"\\u0061\":2}"};
    for (size_t i = 0; i < sizeof seeds / sizeof *seeds; i++) {
        size_t len = strlen(seeds[i]);
        LLVMFuzzerTestOneInput((const uint8_t *)seeds[i], len);
        for (unsigned j = 0; j < 256; j++) {
            uint8_t *mutated = cm_alloc(len + 1);
            memcpy(mutated, seeds[i], len);
            size_t n = (size_t)next_random() % (len + 1);
            if (n < len)
                mutated[n] = (uint8_t)next_random();
            LLVMFuzzerTestOneInput(mutated, j % 2 ? len : n);
            free(mutated);
        }
    }
    json_object_put(config);
    json_object_put(state);
    json_object_put(bundle);
    free(c);
    free(s);
    puts("Deterministic parser fuzz smoke passed (9 seeds, 2304 mutations).");
    return 0;
}
#endif
