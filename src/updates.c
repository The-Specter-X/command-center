/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <stdlib.h>
#include <string.h>

#define UPDATE_FILE "90command-center"
#define UPDATE_HEADER                                                                              \
    "// Managed by Command Center. Edit other APT fragments for additional policy.\n"
static void fragment(char *buf, size_t cap, bool enabled, bool reboot)
{
    snprintf(buf, cap,
             UPDATE_HEADER
             "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade "
             "\"%u\";\nUnattended-Upgrade::Automatic-Reboot \"%s\";\n",
             enabled ? 1U : 0U, reboot ? "true" : "false");
}
static int apt_path(const struct cm_paths *p, char *dst, size_t cap, struct cm_error *e)
{
    const char *suffix = "/etc/command-center";
    size_t root = strlen(p->config) - strlen(suffix);
    int n = snprintf(dst, cap, "%.*s/etc/apt/apt.conf.d", (int)root, p->config);
    return n < 0 || (size_t)n >= cap ? cm_fail(e, "APT path too long") : 0;
}
static int load_policy(const char *dir, bool *enabled, bool *reboot, char **prior,
                       struct cm_error *e)
{
    *enabled = false;
    *reboot = false;
    int r = cm_read_text(dir, UPDATE_FILE, prior, e);
    if (r == 1)
        return 0;
    if (r)
        return -1;
    char candidate[512];
    for (unsigned a = 0; a < 2; a++)
        for (unsigned b = 0; b < 2; b++) {
            fragment(candidate, sizeof candidate, a, b);
            if (!strcmp(*prior, candidate)) {
                *enabled = a;
                *reboot = b;
                return 0;
            }
        }
    free(*prior);
    *prior = NULL;
    return cm_fail(e,
                   "%s was modified outside CM; move that policy into a separate APT fragment "
                   "before using update controls",
                   UPDATE_FILE);
}
static int status(struct cm_error *e)
{
    char *argv[] = {"apt-config", "shell",
                    "CM_ENABLED", "APT::Periodic::Unattended-Upgrade",
                    "CM_REBOOT",  "Unattended-Upgrade::Automatic-Reboot",
                    NULL};
    char *text;
    if (cm_capture("/usr/bin/apt-config", argv, &text, e))
        return -1;
    puts("Effective APT settings (absent values use the distribution defaults):");
    fputs(text, stdout);
    free(text);
    puts("Schedule and execution: systemctl status apt-daily.timer apt-daily-upgrade.timer");
    puts("Origins, exclusions, and package policy: /etc/apt/apt.conf.d/50unattended-upgrades and "
         "other APT fragments");
    return 0;
}
static void timer_fragment(char *text, size_t cap, unsigned hour, unsigned minute)
{
    snprintf(text, cap,
             "# Managed by Command Center.\n[Timer]\nOnCalendar=\nOnCalendar=*-*-* "
             "%02u:%02u:00\nRandomizedDelaySec=0\nAccuracySec=1min\nPersistent=true\n",
             hour, minute);
}
static int schedule(const struct cm_paths *p, const char *value, bool dry, struct cm_error *e)
{
    unsigned hour = 0, minute = 0;
    bool remove = !strcmp(value, "default");
    if (!remove) {
        uint64_t h, m;
        if (strlen(value) != 5 || value[2] != ':')
            return cm_fail(e, "schedule requires HH:MM or default");
        char a[3] = {value[0], value[1], 0}, b[3] = {value[3], value[4], 0};
        if (cm_uint(a, 0, 23, &h, e) || cm_uint(b, 0, 59, &m, e))
            return -1;
        hour = (unsigned)h;
        minute = (unsigned)m;
    }
    size_t root = strlen(p->config) - strlen("/etc/command-center");
    char dir[CM_PATH_MAX], text[512];
    int n = snprintf(dir, sizeof dir, "%.*s/etc/systemd/system/apt-daily-upgrade.timer.d",
                     (int)root, p->config);
    if (n < 0 || (size_t)n >= sizeof dir)
        return cm_fail(e, "schedule path too long");
    const char *file = "90-command-center.conf";
    char *prior = NULL;
    int r = cm_read_text(dir, file, &prior, e);
    if (r < 0)
        return -1;
    if (prior) {
        unsigned h = 24, m = 60;
        const char *clock = strstr(prior, "OnCalendar=*-*-* ");
        char expected[512];
        bool valid = clock && sscanf(clock, "OnCalendar=*-*-* %2u:%2u:00", &h, &m) == 2 &&
                     h < 24 && m < 60;
        if (valid)
            timer_fragment(expected, sizeof expected, h, m);
        if (!valid || strcmp(prior, expected)) {
            free(prior);
            return cm_fail(e, "timer drop-in was modified outside CM; refusing replacement/removal");
        }
    }
    /* One empty OnCalendar resets all calendar AND monotonic triggers. Adding
     * empty On*Sec directives afterward would erase the new calendar as well. */
    timer_fragment(text, sizeof text, hour, minute);
    if (dry) {
        if (remove)
            printf("# Remove only %s/%s\n", dir, file);
        else
            fputs(text, stdout);
        free(prior);
        return 0;
    }
    if (remove) {
        if (prior)
            r = cm_remove(dir, file, e);
        else
            r = 0;
    } else
        r = cm_write_public_text(dir, file, text, e);
    if (!r && !p->offline) {
        char *reload[] = {"systemctl", "daemon-reload", NULL},
             *restart[] = {"systemctl", "try-restart", "apt-daily-upgrade.timer", NULL};
        r = cm_exec("/usr/bin/systemctl", reload, e);
        if (!r)
            r = cm_exec("/usr/bin/systemctl", restart, e);
        if (r) {
            char original[sizeof e->text];
            strcpy(original, e->text);
            struct cm_error undo;
            int restored =
                prior ? cm_write_public_text(dir, file, prior, &undo) : cm_remove(dir, file, &undo);
            cm_exec("/usr/bin/systemctl", reload, &undo);
            cm_exec("/usr/bin/systemctl", restart, &undo);
            cm_fail(e, "%s; timer drop-in %s", original,
                    restored ? "restoration failed" : "restored");
        }
    }
    free(prior);
    if (!r) {
        printf("Upgrade schedule: %s (system local time).\n",
               remove ? "distribution default" : value);
        if (!p->offline)
            cm_log("upgrade schedule set to %s", value);
    }
    return r;
}
int cm_updates(const struct cm_paths *p, int argc, char **argv, bool dry, struct cm_error *e)
{
    if (argc < 1)
        return cm_fail(
            e, "usage: command-center updates status|enable|disable|reboot on|off|check|run|logs");
    const char *cmd = argv[0];
    if (!strcmp(cmd, "schedule") && argc == 2)
        return schedule(p, argv[1], dry, e);
    if (!strcmp(cmd, "status") && argc == 1) {
        if (p->offline) {
            char dir[CM_PATH_MAX];
            bool enabled, reboot;
            char *prior = NULL;
            if (apt_path(p, dir, sizeof dir, e) || load_policy(dir, &enabled, &reboot, &prior, e))
                return -1;
            free(prior);
            printf("Offline update policy: %s; automatic reboot: %s\n",
                   enabled ? "enabled" : "disabled", reboot ? "on" : "off");
            return 0;
        }
        return status(e);
    }
    if (!strcmp(cmd, "logs") && argc == 1) {
        if (p->offline || dry)
            return cm_fail(e, "logs requires live mode");
        char *args[] = {"journalctl", "--no-pager", "-u", "apt-daily-upgrade.service",
                        "-n",         "100",        NULL};
        return cm_exec("/usr/bin/journalctl", args, e);
    }
    if ((!strcmp(cmd, "check") || !strcmp(cmd, "run")) && argc == 1) {
        if (p->offline)
            return cm_fail(e, "package execution is unavailable in offline mode");
        if (!strcmp(cmd, "check") || dry) {
            char *args[] = {"unattended-upgrade", "--dry-run", "--debug", NULL};
            return cm_exec("/usr/bin/unattended-upgrade", args, e);
        }
        char *refresh[] = {"apt-get", "update", NULL};
        if (cm_exec("/usr/bin/apt-get", refresh, e))
            return -1;
        char *upgrade[] = {"unattended-upgrade", "--verbose", NULL};
        return cm_exec("/usr/bin/unattended-upgrade", upgrade, e);
    }
    bool toggle = (!strcmp(cmd, "enable") || !strcmp(cmd, "disable")) && argc == 1;
    bool set_reboot =
        !strcmp(cmd, "reboot") && argc == 2 && (!strcmp(argv[1], "on") || !strcmp(argv[1], "off"));
    if (!toggle && !set_reboot)
        return cm_fail(e, "invalid updates command; see command-center help");
    char dir[CM_PATH_MAX], text[512];
    bool enabled, reboot;
    char *prior = NULL;
    if (apt_path(p, dir, sizeof dir, e) || load_policy(dir, &enabled, &reboot, &prior, e))
        return -1;
    if (toggle)
        enabled = !strcmp(cmd, "enable");
    else
        reboot = !strcmp(argv[1], "on");
    fragment(text, sizeof text, enabled, reboot);
    if (dry) {
        fputs(text, stdout);
        free(prior);
        return 0;
    }
    int r = cm_write_public_text(dir, UPDATE_FILE, text, e);
    if (!r && enabled && !p->offline) {
        char *args[] = {
            "systemctl", "enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer", NULL};
        r = cm_exec("/usr/bin/systemctl", args, e);
        if (r) {
            char original[sizeof e->text];
            strcpy(original, e->text);
            struct cm_error undo;
            int restored = prior ? cm_write_public_text(dir, UPDATE_FILE, prior, &undo)
                                 : cm_remove(dir, UPDATE_FILE, &undo);
            cm_fail(e, "%s; %s", original,
                    restored ? "could not restore the previous APT fragment"
                             : "previous APT fragment restored");
        }
    }
    free(prior);
    if (!r) {
        printf("Automatic upgrades: %s; automatic reboot: %s.\n", enabled ? "enabled" : "disabled",
               reboot ? "on" : "off");
        if (!p->offline)
            cm_log("automatic update policy %s; automatic reboot %s", enabled ? "enabled" : "disabled",
                   reboot ? "on" : "off");
    }
    return r;
}
