/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CM_H
#define CM_H
#define _GNU_SOURCE
#include <json-c/json.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define CM_VERSION "2.1.0"
#define CM_TABLE "command_center"
#define CM_BAN_TABLE "command_center_bans"
#define CM_MAX_RULES 256
#define CM_MAX_IGNORE 64
#define CM_MAX_BANS 4096
#define CM_MAX_ATTEMPTS 4096
#define CM_METER_BUDGET 262144U
#define CM_MAX_FILE (16U * 1024U * 1024U)
#define CM_PATH_MAX 4096
#define CM_ADDRESS_MAX 80

struct cm_error {
    char text[1024];
};
struct cm_paths {
    char config[CM_PATH_MAX], state[CM_PATH_MAX], run[CM_PATH_MAX];
    bool offline;
};
enum cm_kind { CM_ALLOW, CM_DENY, CM_LIMIT, CM_REJECT };
struct cm_rule {
    uint32_t id;
    enum cm_kind kind;
    uint16_t port, port_end;
    char protocol[5];
    char source[CM_ADDRESS_MAX];
    char destination[CM_ADDRESS_MAX], interface[16], comment[160];
    bool outgoing;
    unsigned family, rate, burst, period;
};
struct cm_alias {
    char name[32], protocol[5];
    uint16_t port;
};
struct cm_config {
    bool enabled, guard_enabled, activation_known;
    uint32_t next_id;
    size_t rule_count, ignore_count, guard_port_count;
    struct cm_rule rules[CM_MAX_RULES];
    char ignore[CM_MAX_IGNORE][CM_ADDRESS_MAX];
    uint16_t guard_ports[32];
    unsigned threshold, window, duration;
    bool input_drop, output_drop, isolation, guard_all;
    unsigned packet_log, log_level;
    char profile[32];
    size_t alias_count;
    struct cm_alias aliases[64];
};
struct cm_ban {
    char address[CM_ADDRESS_MAX];
    uint64_t expires;
    bool automatic;
    bool all_ports;
};
struct cm_attempt {
    char address[CM_ADDRESS_MAX];
    uint64_t times[100];
    size_t count;
};
struct cm_state {
    size_t ban_count, attempt_count;
    struct cm_ban bans[CM_MAX_BANS];
    struct cm_attempt attempts[CM_MAX_ATTEMPTS];
    char cursor[2048];
};
struct cm_options {
    bool dry_run, no_rollback, stage, state_only;
    unsigned rollback;
};

int cm_fail(struct cm_error *, const char *, ...) __attribute__((format(printf, 2, 3)));
void *cm_alloc(size_t);
char *cm_strdup(const char *);
void cm_log(const char *, ...) __attribute__((format(printf, 1, 2)));
void cm_event(int, const char *, const char *, uint32_t, const char *, const char *, ...)
    __attribute__((format(printf, 6, 7)));
int cm_uint(const char *, uint64_t, uint64_t, uint64_t *, struct cm_error *);
uint64_t cm_now(void);
int cm_address(const char *, bool, char *, size_t, struct cm_error *);
bool cm_contains(const char *, const char *);
int cm_service(const char *, uint16_t *, char *, struct cm_error *);
int cm_duration(const char *, unsigned *, struct cm_error *);
int cm_paths_init(struct cm_paths *, const char *, struct cm_error *);
int cm_prepare(const struct cm_paths *, struct cm_error *);
int cm_lock(const struct cm_paths *, struct cm_error *);
int cm_guard_lock(const struct cm_paths *, struct cm_error *);
int cm_named_lock(const struct cm_paths *, const char *, struct cm_error *);
int cm_read_lock(const struct cm_paths *, struct cm_error *);
int cm_read_json(const char *, const char *, struct json_object **, struct cm_error *);
int cm_parse_json(const char *, size_t, struct json_object **, struct cm_error *);
int cm_read_text(const char *, const char *, char **, struct cm_error *);
int cm_write_json(const char *, const char *, struct json_object *, struct cm_error *);
int cm_write_text(const char *, const char *, const char *, struct cm_error *);
int cm_write_public_text(const char *, const char *, const char *, struct cm_error *);
int cm_remove(const char *, const char *, struct cm_error *);
int cm_exists(const char *, const char *);
int cm_exec(const char *, char *const[], struct cm_error *);
int cm_exec_timeout(const char *, char *const[], unsigned, struct cm_error *);
int cm_capture(const char *, char *const[], char **, struct cm_error *);
bool cm_keys(struct json_object *, const char *const *, struct cm_error *);
int cm_get_int(struct json_object *, const char *, uint64_t, uint64_t, uint64_t *,
               struct cm_error *);
int cm_get_bool(struct json_object *, const char *, bool *, struct cm_error *);
int cm_get_string(struct json_object *, const char *, char *, size_t, struct cm_error *);

void cm_config_default(struct cm_config *);
struct json_object *cm_config_json(const struct cm_config *);
int cm_config_parse(struct json_object *, struct cm_config *, struct cm_error *);
int cm_config_load(const struct cm_paths *, struct cm_config *, struct cm_error *);
int cm_boot_id(const struct cm_paths *, char *, size_t, struct cm_error *);
int cm_activation(const struct cm_paths *, bool *, bool *, struct cm_error *);
int cm_activation_save(const struct cm_paths *, bool, struct cm_error *);
int cm_config_drift(const struct cm_paths *, struct cm_error *);
struct json_object *cm_state_json(const struct cm_state *);
int cm_state_parse(struct json_object *, struct cm_state *, struct cm_error *);
int cm_state_load(const struct cm_paths *, struct cm_state *, struct cm_error *);
void cm_state_expire(struct cm_state *, uint64_t);
bool cm_ignored(const struct cm_config *, const char *);
int cm_state_ban(struct cm_state *, const char *, uint64_t, bool, struct cm_error *);
int cm_state_ban_scoped(struct cm_state *, const char *, uint64_t, bool, bool, struct cm_error *);
int cm_service_config(const struct cm_config *, const char *, uint16_t *, char *,
                      struct cm_error *);
bool cm_plain(const char *, bool);

char *cm_firewall_script(const struct cm_config *, const struct cm_state *, bool, bool, bool);
unsigned cm_meter_timeout(const struct cm_rule *);
unsigned cm_meter_size(const struct cm_config *);
char *cm_ban_delta(const struct cm_config *, const struct cm_state *, const struct cm_state *);
int cm_ban_drift(const struct cm_config *, const struct cm_state *, struct cm_error *);
int cm_foreign_chains(size_t *, struct cm_error *);
int cm_nft(const char *, bool, char **, struct cm_error *);
int cm_kernel_snapshot(struct json_object **, bool *, bool *, size_t *, struct cm_error *);
void cm_normalize(struct json_object *);
enum cm_drift_kind { CM_DRIFT_POLICY = 1, CM_DRIFT_BANS = 2 };
/* Nonnegative results are a bitmask of CM_DRIFT_*; negative means inspection failed. */
int cm_drift(const struct cm_paths *, bool *, bool *, size_t *, struct cm_error *);
int cm_recover(const struct cm_paths *, struct cm_error *);
int cm_transaction(const struct cm_paths *, const struct cm_config *, const struct cm_state *,
                   const struct cm_options *, bool, struct cm_error *);
int cm_confirm(const struct cm_paths *, struct cm_error *);
int cm_rollback(const struct cm_paths *, struct cm_error *);
int cm_apply(const struct cm_paths *, struct cm_error *);
int cm_suspend(const struct cm_paths *, struct cm_error *);
int cm_restore_config(const struct cm_paths *, struct cm_error *);
int cm_restore_checkpoint(const struct cm_paths *, struct cm_error *);
int cm_bundle_parse(struct json_object *, struct cm_config *, struct cm_state *, struct cm_error *);
int cm_committed_policy(const struct cm_paths *, struct cm_config *, struct cm_error *);
enum cm_change { CM_CHANGE_POLICY = 1, CM_CHANGE_GUARD = 2, CM_CHANGE_BANS = 4,
                 CM_CHANGE_METADATA = 8,
                 CM_CHANGE_ENFORCEMENT = CM_CHANGE_POLICY | CM_CHANGE_GUARD | CM_CHANGE_BANS };
unsigned cm_changes(const struct cm_config *, const struct cm_config *);
int cm_plan(const struct cm_paths *, const struct cm_config *, const struct cm_options *,
            bool, bool, struct cm_error *);

int cm_guard_parse(const char *, char *, size_t);
int cm_guard_event(const struct cm_config *, struct cm_state *, const char *, uint64_t, bool *,
                   struct cm_error *);
int cm_guard_run(const struct cm_paths *, struct cm_error *);
int cm_updates(const struct cm_paths *, int, char **, bool, struct cm_error *);
int cm_info(unsigned, bool, struct cm_error *);
int cm_report(const char *, unsigned, bool, struct cm_error *);
int cm_network(int, char **, bool, struct cm_error *);
int cm_logs(const struct cm_paths *, int, char **, bool, struct cm_error *);
int cm_systemd(const char *, bool, struct cm_error *);
int cm_systemd_state(const char *, const char *, char *, size_t, struct cm_error *);
int cm_reconcile_guard(const struct cm_paths *, struct cm_error *);
int cm_stop(const struct cm_paths *, struct cm_error *);
int cm_rule_add(struct cm_config *, int, char **, enum cm_kind, struct cm_error *);
int cm_rule_delete(struct cm_config *, uint32_t, struct cm_error *);
int cm_rule_move(struct cm_config *, uint32_t, uint32_t, struct cm_error *);
void cm_rules(const struct cm_config *, bool);
int cm_profile(struct cm_config *, const char *, uint16_t, bool, struct cm_error *);
int cm_ssh_port(const struct cm_config *, const char *, uint16_t *, struct cm_error *);
int cm_protect(struct cm_config *, struct cm_state *, int, char **, struct cm_error *);
int cm_aliases(struct cm_config *, int, char **, bool, struct cm_error *);
int cm_status(const struct cm_paths *, bool, struct cm_error *);
void cm_help(FILE *);
void cm_print_report(struct json_object *);
#endif
