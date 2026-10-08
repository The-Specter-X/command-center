/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <stdlib.h>
#include <string.h>

static bool equal_field(struct json_object *a, struct json_object *b, const char *key)
{
    struct json_object *x = NULL, *y = NULL;
    json_object_object_get_ex(a, key, &x);
    json_object_object_get_ex(b, key, &y);
    return json_object_equal(x, y);
}
unsigned cm_changes(const struct cm_config *a, const struct cm_config *b)
{
    struct json_object *x = cm_config_json(a), *y = cm_config_json(b), *gx, *gy;
    json_object_object_get_ex(x, "guard", &gx);
    json_object_object_get_ex(y, "guard", &gy);
    unsigned changes = 0;
    if (a->input_drop != b->input_drop || a->output_drop != b->output_drop ||
        a->isolation != b->isolation || a->packet_log != b->packet_log ||
        !equal_field(x, y, "rules") ||
        ((a->isolation || b->isolation) && !equal_field(gx, gy, "ports")))
        changes |= CM_CHANGE_POLICY;
    if (!json_object_equal(gx, gy))
        changes |= CM_CHANGE_GUARD;
    if (a->guard_enabled != b->guard_enabled || a->packet_log != b->packet_log ||
        !equal_field(gx, gy, "ignore") || !equal_field(gx, gy, "ports"))
        changes |= CM_CHANGE_BANS;
    if (a->log_level != b->log_level || a->next_id != b->next_id ||
        strcmp(a->profile, b->profile) || !equal_field(x, y, "aliases"))
        changes |= CM_CHANGE_METADATA;
    json_object_put(x);
    json_object_put(y);
    return changes;
}
int cm_plan(const struct cm_paths *p, const struct cm_config *candidate,
            const struct cm_options *opt, bool replace, bool json, struct cm_error *e)
{
    struct cm_config *old = cm_alloc(sizeof *old);
    struct cm_state *state = cm_alloc(sizeof *state);
    struct json_object *record = NULL;
    int r = cm_read_json(p->state, "committed.json", &record, e);
    if (r == 1) {
        cm_config_default(old);
        r = 0;
    } else if (!r) {
        r = cm_bundle_parse(record, old, state, e);
        json_object_put(record);
    }
    if (!r) {
        bool active, known;
        r = cm_activation(p, &active, &known, e);
        if (!r && known)
            old->enabled = active;
    }
    if (r) {
        free(old);
        free(state);
        return -1;
    }
    bool kernel_drift = false, policy_drift = false, ban_drift = false;
    if (!p->offline) {
        bool policy, bans;
        size_t foreign;
        int native = cm_drift(p, &policy, &bans, &foreign, e);
        int membership = native < 0 ? -1 : cm_ban_drift(old, state, e);
        if (native < 0 || membership < 0) {
            free(old);
            free(state);
            return -1;
        }
        kernel_drift = native != 0;
        policy_drift = (native & CM_DRIFT_POLICY) != 0;
        ban_drift = membership != 0;
    }
    unsigned changes = cm_changes(old, candidate);
    bool activation = old->enabled != candidate->enabled;
    bool rebuild = policy_drift || activation || (changes & CM_CHANGE_POLICY);
    bool protected = !opt->no_rollback && opt->rollback &&
        (old->enabled || candidate->enabled) && (kernel_drift || ban_drift || activation ||
                                                (changes & CM_CHANGE_ENFORCEMENT));
    if (activation && !changes && !candidate->rule_count && !candidate->guard_enabled &&
        !candidate->input_drop && !candidate->output_drop && !state->ban_count)
        protected = false;
    struct json_object *o = json_object_new_object(), *a = cm_config_json(old),
                       *b = cm_config_json(candidate), *added = json_object_new_array(),
                       *removed = json_object_new_array(), *modified = json_object_new_array();
    struct json_object *ar, *br;
    json_object_object_get_ex(a, "rules", &ar);
    json_object_object_get_ex(b, "rules", &br);
    for (size_t i = 0; i < candidate->rule_count; i++) {
        size_t j = 0;
        while (j < old->rule_count && old->rules[j].id != candidate->rules[i].id)
            j++;
        if (j == old->rule_count)
            json_object_array_add(added, json_object_new_int64(candidate->rules[i].id));
        else if (!json_object_equal(json_object_array_get_idx(ar, j),
                                    json_object_array_get_idx(br, i)))
            json_object_array_add(modified, json_object_new_int64(candidate->rules[i].id));
    }
    for (size_t i = 0; i < old->rule_count; i++) {
        size_t j = 0;
        while (j < candidate->rule_count && candidate->rules[j].id != old->rules[i].id)
            j++;
        if (j == candidate->rule_count)
            json_object_array_add(removed, json_object_new_int64(old->rules[i].id));
    }
    bool order = old->rule_count != candidate->rule_count;
    for (size_t i = 0; !order && i < old->rule_count; i++)
        order = old->rules[i].id != candidate->rules[i].id;
    json_object_object_add(o, "schema", json_object_new_int(1));
    json_object_object_add(o, "applied", a);
    json_object_object_add(o, "desired", b);
    json_object_object_add(o, "added_rules", added);
    json_object_object_add(o, "removed_rules", removed);
    json_object_object_add(o, "modified_rules", modified);
    json_object_object_add(o, "rule_order_changed", json_object_new_boolean(order));
    json_object_object_add(o, "activation_known", json_object_new_boolean(candidate->activation_known));
    json_object_object_add(o, "policy_rebuild", json_object_new_boolean(rebuild));
    json_object_object_add(o, "repair_drift", json_object_new_boolean(replace && (kernel_drift || ban_drift)));
    json_object_object_add(o, "guard_changed", json_object_new_boolean(changes & CM_CHANGE_GUARD));
    json_object_object_add(o, "ban_scope_changed", json_object_new_boolean(changes & CM_CHANGE_BANS));
    json_object_object_add(o, "metadata_changed", json_object_new_boolean(changes & CM_CHANGE_METADATA));
    json_object_object_add(o, "confirmation_seconds", json_object_new_int(protected ? (int)opt->rollback : 0));
    json_object_object_add(o, "meter_entries_per_set", json_object_new_int((int)cm_meter_size(candidate)));
    if (json)
        puts(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY));
    else {
        printf("# Policy plan: incoming %s -> %s; outgoing %s -> %s\n",
               old->input_drop ? "deny" : "allow", candidate->input_drop ? "deny" : "allow",
               old->output_drop ? "deny" : "allow", candidate->output_drop ? "deny" : "allow");
        printf("# Rules: added %s; removed %s; modified %s; order %s\n",
               json_object_to_json_string(added), json_object_to_json_string(removed),
               json_object_to_json_string(modified), order ? "changed" : "unchanged");
        printf("# Objects: policy %s; guard %s; ban scope %s; metadata %s\n",
               rebuild ? "rebuild (meters reset)" : "preserved",
               changes & CM_CHANGE_GUARD ? "changed" : "unchanged",
               changes & CM_CHANGE_BANS ? "changed" : "unchanged",
               changes & CM_CHANGE_METADATA ? "changed" : "unchanged");
        printf("# Confirmation: %u seconds; activation %s\n", protected ? opt->rollback : 0,
               candidate->activation_known ? "known" : "UNKNOWN; reconcile with start/stop");
    }
    json_object_put(o);
    free(old);
    free(state);
    return 0;
}
