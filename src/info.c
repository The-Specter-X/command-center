/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <systemd/sd-bus.h>
#include <time.h>
#include <unistd.h>

struct cpu_sample {
    char name[32];
    uint64_t ticks[8];
};
struct cpus {
    size_t count;
    struct cpu_sample items[4097];
};
static int cpus_read(struct cpus *s, struct cm_error *e)
{
    memset(s, 0, sizeof *s);
    FILE *f = fopen("/proc/stat", "re");
    if (!f)
        return cm_fail(e, "read /proc/stat: %s", strerror(errno));
    char line[2048];
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "cpu", 3))
            continue;
        if (s->count == 4097) {
            fclose(f);
            return cm_fail(e, "CPU count exceeds supported reporting limit");
        }
        struct cpu_sample *v = &s->items[s->count];
        unsigned long long n[8] = {0};
        int fields = sscanf(line, "%31s %llu %llu %llu %llu %llu %llu %llu %llu", v->name, &n[0],
                            &n[1], &n[2], &n[3], &n[4], &n[5], &n[6], &n[7]);
        if (fields < 5) {
            fclose(f);
            return cm_fail(e, "malformed CPU counters");
        }
        for (size_t i = 0; i < 8; i++)
            v->ticks[i] = n[i];
        s->count++;
    }
    int bad = ferror(f);
    fclose(f);
    if (bad || !s->count)
        return cm_fail(e, "CPU counters unavailable");
    return 0;
}
static struct json_object *cpu_json(const struct cpus *before, const struct cpus *after)
{
    struct json_object *array = json_object_new_array();
    for (size_t i = 0; i < after->count; i++) {
        const struct cpu_sample *b = &after->items[i], *a = NULL;
        for (size_t j = 0; j < before->count; j++)
            if (!strcmp(b->name, before->items[j].name)) {
                a = &before->items[j];
                break;
            }
        struct json_object *v = json_object_new_object();
        json_object_object_add(v, "cpu", json_object_new_string(b->name));
        bool valid = a != NULL;
        uint64_t delta[8] = {0}, total = 0;
        if (a)
            for (size_t j = 0; j < 8; j++) {
                if (b->ticks[j] < a->ticks[j])
                    valid = false;
                else
                    delta[j] = b->ticks[j] - a->ticks[j];
                if (UINT64_MAX - total < delta[j])
                    valid = false;
                else
                    total += delta[j];
            }
        valid = valid && total > 0;
        json_object_object_add(v, "available", json_object_new_boolean(valid));
        if (valid) {
            uint64_t busy = total - delta[3] - delta[4] - delta[7];
            json_object_object_add(v, "busy_percent",
                                   json_object_new_double((double)busy * 100 / (double)total));
            json_object_object_add(v, "idle_percent",
                                   json_object_new_double((double)delta[3] * 100 / (double)total));
            json_object_object_add(v, "iowait_percent",
                                   json_object_new_double((double)delta[4] * 100 / (double)total));
            json_object_object_add(v, "steal_percent",
                                   json_object_new_double((double)delta[7] * 100 / (double)total));
        }
        json_object_array_add(array, v);
    }
    return array;
}
static int memory(struct json_object **out, struct cm_error *e)
{
    FILE *f = fopen("/proc/meminfo", "re");
    if (!f)
        return cm_fail(e, "read /proc/meminfo: %s", strerror(errno));
    uint64_t total = 0, free_mem = 0, available = 0, swap_total = 0, swap_free = 0;
    bool have_total = false, have_available = false;
    char line[256];
    while (fgets(line, sizeof line, f)) {
        char key[64], unit[8];
        unsigned long long n;
        if (sscanf(line, "%63s %llu %7s", key, &n, unit) != 3 || strcmp(unit, "kB") ||
            n > UINT64_MAX / 1024)
            continue;
        uint64_t bytes = (uint64_t)n * 1024;
        if (!strcmp(key, "MemTotal:")) {
            total = bytes;
            have_total = true;
        } else if (!strcmp(key, "MemFree:"))
            free_mem = bytes;
        else if (!strcmp(key, "MemAvailable:")) {
            available = bytes;
            have_available = true;
        } else if (!strcmp(key, "SwapTotal:"))
            swap_total = bytes;
        else if (!strcmp(key, "SwapFree:"))
            swap_free = bytes;
    }
    int bad = ferror(f);
    fclose(f);
    if (bad || !have_total || !have_available || available > total)
        return cm_fail(e, "required memory counters unavailable");
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "total_bytes", json_object_new_uint64(total));
    json_object_object_add(o, "free_bytes", json_object_new_uint64(free_mem));
    json_object_object_add(o, "available_bytes", json_object_new_uint64(available));
    json_object_object_add(o, "used_estimate_bytes", json_object_new_uint64(total - available));
    json_object_object_add(o, "swap_total_bytes", json_object_new_uint64(swap_total));
    json_object_object_add(o, "swap_free_bytes", json_object_new_uint64(swap_free));
    *out = o;
    return 0;
}
static bool local_fs(const char *type)
{
    const char *types[] = {"ext2",    "ext3",     "ext4",    "btrfs", "xfs",  "zfs",
                           "f2fs",    "bcachefs", "vfat",    "exfat", "ntfs", "ntfs3",
                           "fuseblk", "overlay",  "iso9660", "udf"};
    for (size_t i = 0; i < sizeof types / sizeof *types; i++)
        if (!strcmp(type, types[i]))
            return true;
    return false;
}
static void unescape(char *s)
{
    char *out = s;
    while (*s) {
        if (s[0] == '\\' && s[1] && s[2] && s[3] && s[1] >= '0' && s[1] <= '7' && s[2] >= '0' &&
            s[2] <= '7' && s[3] >= '0' && s[3] <= '7') {
            *out++ = (char)((s[1] - '0') * 64 + (s[2] - '0') * 8 + s[3] - '0');
            s += 4;
        } else
            *out++ = *s++;
    }
    *out = 0;
}
static uint64_t bytes(fsblkcnt_t blocks, unsigned long size)
{
    if (size && blocks > UINT64_MAX / size)
        return UINT64_MAX;
    return (uint64_t)blocks * size;
}
static int filesystems(struct json_object **out, struct cm_error *e)
{
    FILE *f = fopen("/proc/self/mountinfo", "re");
    if (!f)
        return cm_fail(e, "read mountinfo: %s", strerror(errno));
    struct json_object *array = json_object_new_array();
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 65536) {
            free(line);
            fclose(f);
            json_object_put(array);
            return cm_fail(e, "mountinfo entry exceeds reporting limit");
        }
        char *dash = strstr(line, " - ");
        if (!dash)
            continue;
        *dash = 0;
        char *save = NULL, *part = strtok_r(line, " ", &save), *mount = NULL, *device = NULL;
        unsigned field = 1;
        while (part) {
            if (field == 3)
                device = part;
            if (field == 5)
                mount = part;
            field++;
            part = strtok_r(NULL, " ", &save);
        }
        char *save2 = NULL, *type = strtok_r(dash + 3, " ", &save2);
        if (!mount || !device || !type || !local_fs(type))
            continue;
        unescape(mount);
        bool duplicate = false;
        for (size_t i = 0; i < json_object_array_length(array); i++) {
            struct json_object *previous = json_object_array_get_idx(array, i), *id;
            if (json_object_object_get_ex(previous, "device", &id) &&
                !strcmp(json_object_get_string(id), device)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate)
            continue;
        struct json_object *v = json_object_new_object();
        json_object_object_add(v, "mount", json_object_new_string(mount));
        json_object_object_add(v, "device", json_object_new_string(device));
        json_object_object_add(v, "type", json_object_new_string(type));
        struct statvfs st;
        if (statvfs(mount, &st) < 0) {
            json_object_object_add(v, "error", json_object_new_string(strerror(errno)));
            json_object_array_add(array, v);
            continue;
        }
        unsigned long size = st.f_frsize ? st.f_frsize : st.f_bsize;
        uint64_t used = st.f_blocks >= st.f_bfree ? st.f_blocks - st.f_bfree : 0;
        json_object_object_add(v, "total_bytes", json_object_new_uint64(bytes(st.f_blocks, size)));
        json_object_object_add(v, "used_bytes", json_object_new_uint64(bytes(used, size)));
        json_object_object_add(v, "free_bytes", json_object_new_uint64(bytes(st.f_bfree, size)));
        json_object_object_add(v, "available_bytes",
                               json_object_new_uint64(bytes(st.f_bavail, size)));
        if (st.f_blocks)
            json_object_object_add(
                v, "used_percent",
                json_object_new_double((double)used * 100 / (double)st.f_blocks));
        if (st.f_files) {
            json_object_object_add(v, "inodes_total", json_object_new_uint64(st.f_files));
            json_object_object_add(v, "inodes_free", json_object_new_uint64(st.f_ffree));
            json_object_object_add(v, "inodes_available", json_object_new_uint64(st.f_favail));
            uint64_t used_inodes = st.f_files >= st.f_ffree ? st.f_files - st.f_ffree : 0;
            json_object_object_add(
                v, "inodes_used_percent",
                json_object_new_double((double)used_inodes * 100 / (double)st.f_files));
        }
        json_object_array_add(array, v);
    }
    free(line);
    int bad = ferror(f);
    fclose(f);
    if (bad) {
        json_object_put(array);
        return cm_fail(e, "mountinfo read failed");
    }
    *out = array;
    return 0;
}
static const char *str(struct json_object *o, const char *key)
{
    struct json_object *v;
    return json_object_object_get_ex(o, key, &v) ? json_object_get_string(v) : "unavailable";
}
static double number(struct json_object *o, const char *key)
{
    struct json_object *v;
    return json_object_object_get_ex(o, key, &v) ? json_object_get_double(v) : 0;
}
static void safe_print(const char *s)
{
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (*p < 32 || *p == 127)
            printf("\\x%02x", *p);
        else
            putchar(*p);
}
static int info_all(unsigned interval, bool json, const char *selected, struct cm_error *e)
{
    struct cpus *before = cm_alloc(sizeof *before), *after = cm_alloc(sizeof *after);
    int r = cpus_read(before, e);
    if (r) {
        free(before);
        free(after);
        return -1;
    }
    struct timespec wait = {.tv_sec = interval / 1000,
                            .tv_nsec = (long)(interval % 1000) * 1000000L};
    while (nanosleep(&wait, &wait) < 0)
        if (errno != EINTR) {
            free(before);
            free(after);
            return cm_fail(e, "CPU sampling wait failed");
        }
    if (cpus_read(after, e)) {
        free(before);
        free(after);
        return -1;
    }
    struct json_object *o = json_object_new_object(), *ram = NULL, *disk = NULL;
    struct utsname u;
    json_object_object_add(o, "schema", json_object_new_int(1));
    json_object_object_add(o, "interval_ms", json_object_new_int((int)interval));
    if (uname(&u) == 0) {
        json_object_object_add(o, "kernel", json_object_new_string(u.release));
        json_object_object_add(o, "architecture", json_object_new_string(u.machine));
    }
    FILE *cpu = fopen("/proc/cpuinfo", "re");
    if (cpu) {
        char line[1024];
        while (fgets(line, sizeof line, cpu)) {
            if (!strncmp(line, "model name", 10) || !strncmp(line, "Hardware", 8)) {
                char *value = strchr(line, ':');
                if (value) {
                    value++;
                    while (*value == ' ' || *value == '\t')
                        value++;
                    value[strcspn(value, "\r\n")] = 0;
                    json_object_object_add(o, "cpu_model", json_object_new_string(value));
                    break;
                }
            }
        }
        fclose(cpu);
    }
    json_object_object_add(o, "cpus", cpu_json(before, after));
    free(before);
    free(after);
    if (memory(&ram, e) || filesystems(&disk, e)) {
        if (ram)
            json_object_put(ram);
        json_object_put(o);
        return -1;
    }
    json_object_object_add(o, "memory", ram);
    json_object_object_add(o, "filesystems", disk);
    if (selected) {
        struct json_object *v = NULL;
        if (!json_object_object_get_ex(o, selected, &v)) {
            json_object_put(o);
            return cm_fail(e, "report section unavailable");
        }
        if (!json)
            printf("%s:\n", selected);
        puts(json_object_to_json_string_ext(v, JSON_C_TO_STRING_PRETTY));
        json_object_put(o);
        return 0;
    }
    if (json)
        puts(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY |
                                                   JSON_C_TO_STRING_NOSLASHESCAPE));
    else {
        printf("Kernel: %s (%s)\nCPU: %s\n", str(o, "kernel"), str(o, "architecture"),
               str(o, "cpu_model"));
        struct json_object *cpus;
        json_object_object_get_ex(o, "cpus", &cpus);
        for (size_t i = 0; i < json_object_array_length(cpus); i++) {
            struct json_object *v = json_object_array_get_idx(cpus, i), *valid;
            json_object_object_get_ex(v, "available", &valid);
            if (json_object_get_boolean(valid))
                printf("%-8s busy %6.1f%%  idle %6.1f%%  I/O wait %6.1f%%  steal %6.1f%%\n",
                       str(v, "cpu"), number(v, "busy_percent"), number(v, "idle_percent"),
                       number(v, "iowait_percent"), number(v, "steal_percent"));
            else
                printf("%-8s sample unavailable (counter change or CPU hotplug)\n", str(v, "cpu"));
        }
        printf("RAM: %.2f GiB total; %.2f GiB available; %.2f GiB completely free\n",
               number(ram, "total_bytes") / 1073741824.0,
               number(ram, "available_bytes") / 1073741824.0,
               number(ram, "free_bytes") / 1073741824.0);
        printf("Swap: %.2f GiB total; %.2f GiB free\n",
               number(ram, "swap_total_bytes") / 1073741824.0,
               number(ram, "swap_free_bytes") / 1073741824.0);
        for (size_t i = 0; i < json_object_array_length(disk); i++) {
            struct json_object *v = json_object_array_get_idx(disk, i), *err, *inodes;
            safe_print(str(v, "mount"));
            printf(" (%s): ", str(v, "type"));
            if (json_object_object_get_ex(v, "error", &err)) {
                printf("%s\n", json_object_get_string(err));
                continue;
            }
            printf("%.2f GiB total; %.2f GiB available; %.1f%% used; ",
                   number(v, "total_bytes") / 1073741824.0,
                   number(v, "available_bytes") / 1073741824.0, number(v, "used_percent"));
            if (json_object_object_get_ex(v, "inodes_total", &inodes))
                printf("inodes %.1f%% used (%s free)\n", number(v, "inodes_used_percent"),
                       str(v, "inodes_free"));
            else
                puts("inodes unavailable");
        }
    }
    json_object_put(o);
    return 0;
}

int cm_info(unsigned interval, bool json, struct cm_error *e)
{
    return info_all(interval, json, NULL, e);
}
static void read_field(struct json_object *o, const char *key, const char *path)
{
    FILE *f = fopen(path, "re");
    char line[1024];
    if (f && fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        json_object_object_add(o, key, json_object_new_string(line));
    } else
        json_object_object_add(o, key, NULL);
    if (f)
        fclose(f);
}
static struct json_object *os(void)
{
    struct json_object *o = json_object_new_object();
    struct utsname u;
    if (!uname(&u)) {
        json_object_object_add(o, "kernel", json_object_new_string(u.release));
        json_object_object_add(o, "architecture", json_object_new_string(u.machine));
        json_object_object_add(o, "hostname", json_object_new_string(u.nodename));
    }
    FILE *f = fopen("/etc/os-release", "re");
    char line[2048];
    if (f) {
        while (fgets(line, sizeof line, f)) {
            char *equal = strchr(line, '=');
            if (!equal)
                continue;
            *equal++ = 0;
            equal[strcspn(equal, "\r\n")] = 0;
            size_t n = strlen(equal);
            if (n >= 2 && ((*equal == '"' && equal[n - 1] == '"') ||
                           (*equal == '\'' && equal[n - 1] == '\''))) {
                equal[n - 1] = 0;
                equal++;
            }
            if (!strcmp(line, "ID") || !strcmp(line, "VERSION_ID") || !strcmp(line, "PRETTY_NAME"))
                json_object_object_add(o, line, json_object_new_string(equal));
        }
        fclose(f);
    }
    read_field(o, "uptime_seconds_and_idle", "/proc/uptime");
    return o;
}
static struct json_object *hardware(void)
{
    struct json_object *o = json_object_new_object(), *devices = json_object_new_array();
    read_field(o, "vendor", "/sys/class/dmi/id/sys_vendor");
    read_field(o, "product", "/sys/class/dmi/id/product_name");
    read_field(o, "online_cpus", "/sys/devices/system/cpu/online");
    read_field(o, "possible_cpus", "/sys/devices/system/cpu/possible");
    FILE *f = fopen("/proc/cpuinfo", "re");
    char line[2048];
    if (f) {
        while (fgets(line, sizeof line, f))
            if (!strncmp(line, "model name", 10) || !strncmp(line, "Hardware", 8)) {
                char *v = strchr(line, ':');
                if (v) {
                    v++;
                    while (*v == ' ' || *v == '\t')
                        v++;
                    v[strcspn(v, "\r\n")] = 0;
                    json_object_object_add(o, "cpu_model", json_object_new_string(v));
                    break;
                }
            }
        fclose(f);
    }
    DIR *d = opendir("/sys/block");
    struct dirent *entry;
    size_t count = 0;
    if (d) {
        while ((entry = readdir(d)) && count < 4096) {
            if (entry->d_name[0] == '.')
                continue;
            count++;
            struct json_object *v = json_object_new_object();
            char path[CM_PATH_MAX];
            json_object_object_add(v, "name", json_object_new_string(entry->d_name));
            snprintf(path, sizeof path, "/sys/block/%s/size", entry->d_name);
            read_field(v, "sectors_512_bytes", path);
            snprintf(path, sizeof path, "/sys/block/%s/device/model", entry->d_name);
            read_field(v, "model", path);
            snprintf(path, sizeof path, "/sys/block/%s/queue/rotational", entry->d_name);
            read_field(v, "rotational", path);
            json_object_array_add(devices, v);
        }
        closedir(d);
    }
    json_object_object_add(o, "block_devices", devices);
    return o;
}
static struct json_object *clock_info(void)
{
    struct json_object *o = json_object_new_object();
    time_t now = time(NULL);
    struct tm local, utc;
    char a[80], b[80];
    if (localtime_r(&now, &local) && gmtime_r(&now, &utc)) {
        strftime(a, sizeof a, "%Y-%m-%dT%H:%M:%S%z", &local);
        strftime(b, sizeof b, "%Y-%m-%dT%H:%M:%SZ", &utc);
        json_object_object_add(o, "local", json_object_new_string(a));
        json_object_object_add(o, "utc", json_object_new_string(b));
    }
    read_field(o, "timezone", "/etc/timezone");
    sd_bus *bus = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    char *zone = NULL;
    int synced = 0;
    if (sd_bus_open_system(&bus) >= 0) {
        if (sd_bus_get_property_string(bus, "org.freedesktop.timedate1",
                                       "/org/freedesktop/timedate1", "org.freedesktop.timedate1",
                                       "Timezone", &error, &zone) >= 0)
            json_object_object_add(o, "timezone", json_object_new_string(zone));
        sd_bus_error_free(&error);
        if (sd_bus_get_property_trivial(bus, "org.freedesktop.timedate1",
                                        "/org/freedesktop/timedate1", "org.freedesktop.timedate1",
                                        "NTPSynchronized", &error, 'b', &synced) >= 0)
            json_object_object_add(o, "synchronized", json_object_new_boolean(synced));
        else
            json_object_object_add(o, "synchronized", NULL);
    } else
        json_object_object_add(o, "synchronized", NULL);
    free(zone);
    sd_bus_error_free(&error);
    sd_bus_unref(bus);
    return o;
}
int cm_report(const char *name, unsigned interval, bool json, struct cm_error *e)
{
    if (!strcmp(name, "cpu"))
        return info_all(interval, json, "cpus", e);
    struct json_object *o = NULL;
    int r = 0;
    if (!strcmp(name, "memory"))
        r = memory(&o, e);
    else if (!strcmp(name, "disk") || !strcmp(name, "inode"))
        r = filesystems(&o, e);
    else if (!strcmp(name, "os"))
        o = os();
    else if (!strcmp(name, "hardware"))
        o = hardware();
    else if (!strcmp(name, "time") || !strcmp(name, "timezone"))
        o = clock_info();
    else
        return cm_fail(e, "unknown report");
    if (!r) {
        if (!json)
            printf("%s:\n", name);
        puts(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY |
                                                   JSON_C_TO_STRING_NOSLASHESCAPE));
    }
    if (o)
        json_object_put(o);
    return r;
}
