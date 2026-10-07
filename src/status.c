/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <stdlib.h>
#include <string.h>

int cm_status(const struct cm_paths *p, bool json, struct cm_error *e)
{
    struct cm_config *c = cm_alloc(sizeof *c);
    struct cm_state *s = cm_alloc(sizeof *s);
    int r = cm_config_load(p, c, e) || cm_state_load(p, s, e) ? -1 : 0;
    if (r) {
        free(c);
        free(s);
        return -1;
    }
    cm_state_expire(s, cm_now());
    struct cm_config *live = cm_alloc(sizeof *live);
    if (cm_committed_policy(p, live, e)) {
        free(c);
        free(s);
        free(live);
        return -1;
    }
    bool policy = false, bans = false;
    size_t foreign = 0;
    int drift = 0;
    int configuration_drift = cm_config_drift(p, e);
    if (configuration_drift < 0) {
        free(c);
        free(s);
        free(live);
        return -1;
    }
    if (!p->offline) {
        drift = cm_drift(p, &policy, &bans, &foreign, e);
        if (drift < 0) {
            free(c);
            free(s);
            free(live);
            return -1;
        }
    }
    bool pending = cm_exists(p->state, "pending.json"),
         recovery = cm_exists(p->state, "transaction.json");
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "schema", json_object_new_int(1));
    json_object_object_add(o, "offline", json_object_new_boolean(p->offline));
    json_object_object_add(o, "configured_enabled", json_object_new_boolean(c->enabled));
    json_object_object_add(o, "policy_table_present", json_object_new_boolean(policy));
    json_object_object_add(o, "ban_table_present", json_object_new_boolean(bans));
    json_object_object_add(o, "drift",
                           json_object_new_boolean(drift != 0 || configuration_drift != 0));
    json_object_object_add(o, "kernel_drift", json_object_new_boolean(drift != 0));
    json_object_object_add(o, "configuration_drift",
                           json_object_new_boolean(configuration_drift != 0));
    json_object_object_add(o, "pending_confirmation", json_object_new_boolean(pending));
    json_object_object_add(o, "recovery_required", json_object_new_boolean(recovery));
    json_object_object_add(o, "foreign_base_chains", json_object_new_uint64(foreign));
    json_object_object_add(o, "rule_count", json_object_new_uint64(c->rule_count));
    json_object_object_add(o, "guard_configured_enabled",
                           json_object_new_boolean(c->guard_enabled));
    json_object_object_add(o, "guard_applied_enabled",
                           json_object_new_boolean(live->enabled && live->guard_enabled));
    json_object_object_add(o, "unexpired_bans", json_object_new_uint64(s->ban_count));
    char service[64] = "unavailable", loader[64] = "unavailable", boot[64] = "unavailable";
    struct cm_error ignored = {0};
    if (!p->offline) {
        cm_systemd_state("command-center-guard.service", "ActiveState", service, sizeof service,
                         &ignored);
        cm_systemd_state("command-center.service", "ActiveState", loader, sizeof loader, &ignored);
        cm_systemd_state("command-center.service", "UnitFileState", boot, sizeof boot, &ignored);
    } else {
        struct json_object *b = NULL;
        int found = cm_read_json(p->config, "boot.json", &b, &ignored);
        if (!found) {
            bool enabled = false;
            if (!cm_get_bool(b, "enabled", &enabled, &ignored))
                strcpy(boot, enabled ? "enabled" : "disabled");
            json_object_put(b);
        } else
            strcpy(boot, "disabled");
    }
    json_object_object_add(o, "active", json_object_new_boolean(c->enabled));
    json_object_object_add(o, "boot_startup", json_object_new_string(boot));
    json_object_object_add(o, "loader_service", json_object_new_string(loader));
    json_object_object_add(o, "guard_service_state", json_object_new_string(service));
    json_object_object_add(o, "profile", json_object_new_string(c->profile));
    json_object_object_add(o, "incoming_default",
                           json_object_new_string(c->input_drop ? "deny" : "unchanged/allow"));
    json_object_object_add(o, "outgoing_default",
                           json_object_new_string(c->output_drop ? "deny" : "unchanged/allow"));
    json_object_object_add(o, "forwarding",
                           json_object_new_string("unmanaged; includes forwarded container ports"));
    json_object_object_add(o, "rules", NULL);
    struct json_object *cfg = cm_config_json(c), *rules = NULL;
    json_object_object_get_ex(cfg, "rules", &rules);
    json_object_object_add(o, "rules", json_object_get(rules));
    json_object_put(cfg);
    if (json)
        puts(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY));
    else {
        printf("Mode: %s\nCM active this boot: %s\nRules: %zu\n",
               p->offline ? "offline (kernel not inspected)" : "live",
               c->enabled ? "enabled" : "disabled", c->rule_count);
        printf("Saved configuration drift: %s\n", configuration_drift ? "DETECTED" : "none");
        if (!p->offline)
            printf("Host policy table: %s\nBan table: %s\nManaged rule drift: %s\nOther base "
                   "chains: %zu\n",
                   policy ? "present" : "absent", bans ? "present" : "absent",
                   drift ? "DETECTED" : "none", foreign);
        printf("SSH guard configured: %s; service: %s\nUnexpired bans: %zu\nPending confirmation: "
               "%s\nRecovery required: %s\n",
               c->guard_enabled ? "enabled" : "disabled", service, s->ban_count,
               pending ? "yes" : "no", recovery ? "YES" : "no");
    }
    if (!json)
        printf("Boot startup: %s; loader: %s; profile: %s\nIncoming default: %s; outgoing default: "
               "%s\nForwarding/NAT: unmanaged; other tables remain effective.\n",
               boot, loader, c->profile, c->input_drop ? "deny" : "unchanged/allow",
               c->output_drop ? "deny" : "unchanged/allow");
    if (!json)
        cm_rules(c, false);
    bool guard_failed =
        !p->offline && live->enabled && live->guard_enabled && strcmp(service, "active");
    json_object_put(o);
    free(c);
    free(s);
    free(live);
    return drift || configuration_drift || recovery || guard_failed ? 3 : 0;
}
