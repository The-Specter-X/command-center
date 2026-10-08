/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Native transport is replaced at the library boundary: no kernel commands run. */
#include "cm.h"
#include <assert.h>
#include <nftables/libnftables.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int __wrap_nft_run_cmd_from_buffer(struct nft_ctx *, const char *);
const char *__wrap_nft_ctx_get_output_buffer(struct nft_ctx *);
struct nft_ctx *__wrap_nft_ctx_new(uint32_t);
void __wrap_nft_ctx_free(struct nft_ctx *);
void __wrap_nft_ctx_output_set_flags(struct nft_ctx *, unsigned);
void __wrap_nft_ctx_set_dry_run(struct nft_ctx *, bool);
void __wrap_nft_ctx_clear_include_paths(struct nft_ctx *);
int __wrap_nft_ctx_buffer_output(struct nft_ctx *);
int __wrap_nft_ctx_buffer_error(struct nft_ctx *);
static char context_token;
struct nft_ctx *__wrap_nft_ctx_new(uint32_t flags)
{
    assert(flags == NFT_CTX_DEFAULT);
    return (struct nft_ctx *)&context_token;
}
void __wrap_nft_ctx_free(struct nft_ctx *ctx) { (void)ctx; }
void __wrap_nft_ctx_output_set_flags(struct nft_ctx *ctx, unsigned flags)
{
    (void)ctx;
    assert(flags & NFT_CTX_OUTPUT_JSON);
}
void __wrap_nft_ctx_set_dry_run(struct nft_ctx *ctx, bool dry) { (void)ctx; assert(!dry); }
void __wrap_nft_ctx_clear_include_paths(struct nft_ctx *ctx) { (void)ctx; }
int __wrap_nft_ctx_buffer_output(struct nft_ctx *ctx) { (void)ctx; return 0; }
int __wrap_nft_ctx_buffer_error(struct nft_ctx *ctx) { (void)ctx; return 0; }
static char *inventory;
static const char *ban_table;
static const char *output;
static unsigned queries;
int __wrap_nft_run_cmd_from_buffer(struct nft_ctx *ctx, const char *command)
{
    (void)ctx;
    queries++;
    if (!strcmp(command, "list tables\n"))
        output = inventory;
    else if (!strcmp(command, "list table inet " CM_TABLE "\n"))
        output = "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\"command_center\",\"handle\":8}}]}";
    else if (!strcmp(command, "list table inet " CM_BAN_TABLE "\n"))
        output = ban_table;
    else {
        fputs("Hot path attempted an unexpected or whole-ruleset query\n", stderr);
        abort();
    }
    return 0;
}
const char *__wrap_nft_ctx_get_output_buffer(struct nft_ctx *ctx)
{
    (void)ctx;
    return output;
}
static void make_inventory(void)
{
    size_t size;
    FILE *stream = open_memstream(&inventory, &size);
    assert(stream);
    fputs("{\"nftables\":[", stream);
    for (unsigned i = 0; i < 10000; i++)
        fprintf(stream, "{\"table\":{\"family\":\"inet\",\"name\":\"foreign_%u\"}},", i);
    fputs("{\"table\":{\"family\":\"inet\",\"name\":\"command_center\"}},"
          "{\"table\":{\"family\":\"inet\",\"name\":\"command_center_bans\"}}]}", stream);
    assert(!fclose(stream));
}
static void membership(void)
{
    struct cm_error e = {0};
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s), *next = cm_alloc(sizeof *next);
    cm_config_default(c);
    c->enabled = c->guard_enabled = true;
    assert(!cm_state_ban(s, "192.0.2.1", cm_now() + 60, false, &e));
    ban_table = "{\"nftables\":[{\"set\":{\"family\":\"inet\",\"table\":\"command_center_bans\","
        "\"name\":\"manual_all4\",\"elem\":[{\"elem\":{\"val\":\"192.0.2.1\",\"timeout\":60,\"expires\":60}}]}}]}";
    assert(!cm_ban_drift(c, s, &e)); /* nft JSON timeout/expiry units are seconds. */
    s->bans[0].expires += 60;
    assert(cm_ban_drift(c, s, &e) == 1);
    s->bans[0].expires = INT64_MAX;
    assert(cm_ban_drift(c, s, &e) == 1);
    ban_table = "{\"nftables\":[{\"set\":{\"name\":\"manual_all4\",\"elem\":[\"192.0.2.1\"]}}]}";
    assert(!cm_ban_drift(c, s, &e));
    *next = *s;
    next->bans[0].all_ports = false;
    char *delta = cm_ban_delta(c, s, next);
    assert(delta && strstr(delta, "destroy element inet command_center_bans manual_all4"));
    assert(strstr(delta, "add element inet command_center_bans manual_ssh4"));
    assert(!strstr(delta, "delete table"));
    free(delta);
    delta = cm_ban_delta(c, s, s);
    assert(delta && !*delta);
    free(delta);
    ban_table = "{\"nftables\":[{\"set\":{\"name\":\"manual_all4\",\"elem\":[]}}]}";
    assert(cm_ban_drift(c, s, &e) == 1);
    s->bans[0].expires = cm_now() + 1;
    assert(!cm_ban_drift(c, s, &e)); /* Missing nearly-expired entries are tolerated. */
    s->ban_count = 0;
    ban_table = "{\"nftables\":[{\"set\":{\"name\":\"manual_all4\",\"elem\":[\"192.0.2.9\"]}}]}";
    assert(cm_ban_drift(c, s, &e) == 1);
    free(c);
    free(s);
    free(next);
}
static double full_membership(void)
{
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    struct cm_error e = {0};
    cm_config_default(c);
    c->enabled = true;
    s->ban_count = CM_MAX_BANS;
    char *table = NULL;
    size_t length;
    FILE *stream = open_memstream(&table, &length);
    assert(stream);
    fputs("{\"nftables\":[{\"set\":{\"name\":\"manual_all4\",\"elem\":[", stream);
    for (size_t i = 0; i < s->ban_count; i++) {
        struct cm_ban *b = &s->bans[i];
        snprintf(b->address, sizeof b->address, "10.64.%zu.%zu", i / 256, i % 256);
        b->expires = INT64_MAX;
        b->all_ports = true;
        fprintf(stream, "%s\"%s\"", i ? "," : "", b->address);
    }
    fputs("]}}]}", stream);
    assert(!fclose(stream));
    ban_table = table;
    struct timespec start, end;
    assert(!clock_gettime(CLOCK_MONOTONIC, &start));
    assert(!cm_ban_drift(c, s, &e));
    assert(!clock_gettime(CLOCK_MONOTONIC, &end));
    s->bans[CM_MAX_BANS / 2].all_ports = false;
    assert(cm_ban_drift(c, s, &e) == 1);
    double ms = (double)(end.tv_sec - start.tv_sec) * 1000.0 +
        (double)(end.tv_nsec - start.tv_nsec) / 1000000.0;
    free(table);
    free(c);
    free(s);
    return ms;
}
int main(void)
{
    make_inventory();
    ban_table = "{\"nftables\":[{\"set\":{\"family\":\"inet\",\"table\":\"command_center_bans\","
        "\"name\":\"manual_all4\",\"handle\":7,\"count\":1,\"elem\":[\"192.0.2.1\"]}}]}";
    struct json_object *snapshot = NULL;
    struct cm_error e;
    bool policy, bans;
    size_t foreign;
    struct timespec start, end;
    assert(!clock_gettime(CLOCK_MONOTONIC, &start));
    assert(!cm_kernel_snapshot(&snapshot, &policy, &bans, &foreign, &e));
    assert(!clock_gettime(CLOCK_MONOTONIC, &end));
    assert(policy && bans && queries == 3 && foreign == 0);
    assert(json_object_array_length(snapshot) == 2);
    const char *text = json_object_to_json_string(snapshot);
    assert(!strstr(text, "elem") && !strstr(text, "handle") && !strstr(text, "count"));
    json_object_put(snapshot);
    membership();
    double full_ms = full_membership();
    double ms = (double)(end.tv_sec - start.tv_sec) * 1000.0 +
        (double)(end.tv_nsec - start.tv_nsec) / 1000000.0;
    printf("{\"schema\":1,\"simulated_foreign_tables\":10000,\"snapshot_queries\":3,"
           "\"snapshot_objects\":2,\"snapshot_ms\":%.3f,\"full_ban_membership_ms\":%.3f,"
           "\"membership_and_delta_tests\":\"passed\"}\n", ms, full_ms);
    free(inventory);
    return 0;
}
