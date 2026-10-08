/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cm.h"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <net/if.h>
#include <netlink/addr.h>
#include <netlink/cache.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/nexthop.h>
#include <netlink/route/route.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-bus.h>

static void text(struct json_object *o, const char *key, const char *s)
{
    json_object_object_add(o, key, s ? json_object_new_string(s) : NULL);
}
static void number(struct json_object *o, const char *key, uint64_t n)
{
    json_object_object_add(o, key, json_object_new_uint64(n));
}
static const char *address(struct nl_addr *a, char *buf, size_t size)
{
    return a ? nl_addr2str(a, buf, size) : NULL;
}
static void interface(struct json_object *o, int index)
{
    char name[IF_NAMESIZE];
    number(o, "interface_index", (uint64_t)(unsigned)index);
    text(o, "interface", if_indextoname((unsigned)index, name));
}
static struct json_object *route(struct rtnl_route *r)
{
    struct json_object *o = json_object_new_object(), *hops = json_object_new_array();
    char buf[128];
    number(o, "family", (uint64_t)(unsigned)rtnl_route_get_family(r));
    text(o, "destination", address(rtnl_route_get_dst(r), buf, sizeof buf));
    text(o, "preferred_source", address(rtnl_route_get_pref_src(r), buf, sizeof buf));
    number(o, "table", rtnl_route_get_table(r));
    number(o, "metric", rtnl_route_get_priority(r));
    number(o, "type", rtnl_route_get_type(r));
    for (int i = 0; i < rtnl_route_get_nnexthops(r); i++) {
        struct rtnl_nexthop *nh = rtnl_route_nexthop_n(r, i);
        struct json_object *v = json_object_new_object();
        interface(v, rtnl_route_nh_get_ifindex(nh));
        text(v, "gateway", address(rtnl_route_nh_get_gateway(nh), buf, sizeof buf));
        number(v, "weight", rtnl_route_nh_get_weight(nh));
        json_object_array_add(hops, v);
    }
    json_object_object_add(o, "nexthops", hops);
    return o;
}
static int netlink(const char *kind, const char *destination, struct json_object **out,
                   struct cm_error *e)
{
    struct nl_sock *socket = nl_socket_alloc();
    struct nl_cache *cache = NULL;
    if (!socket)
        return cm_fail(e, "cannot allocate Netlink socket");
    int r = nl_connect(socket, NETLINK_ROUTE);
    struct json_object *list = json_object_new_array();
    if (r < 0)
        goto done;
    if (destination) {
        char normalized[CM_ADDRESS_MAX];
        struct nl_addr *a = NULL;
        struct rtnl_route *rt = NULL;
        if (cm_address(destination, false, normalized, sizeof normalized, e)) {
            r = -NLE_INVAL;
            goto done;
        }
        r = nl_addr_parse(normalized, AF_UNSPEC, &a);
        if (r >= 0)
            r = rtnl_route_lookup(socket, a, &rt);
        if (r >= 0)
            json_object_array_add(list, route(rt));
        if (rt)
            rtnl_route_put(rt);
        if (a)
            nl_addr_put(a);
    } else {
        if (!strcmp(kind, "interfaces"))
            r = rtnl_link_alloc_cache(socket, AF_UNSPEC, &cache);
        else if (!strcmp(kind, "addresses"))
            r = rtnl_addr_alloc_cache(socket, &cache);
        else
            r = rtnl_route_alloc_cache(socket, AF_UNSPEC, 0, &cache);
        if (r < 0)
            goto done;
        size_t count = 0;
        for (struct nl_object *object = nl_cache_get_first(cache); object;
             object = nl_cache_get_next(object)) {
            if (++count > 65536) {
                r = -NLE_MSGSIZE;
                break;
            }
            struct json_object *v = NULL;
            char buf[128];
            if (!strcmp(kind, "interfaces")) {
                struct rtnl_link *l = (struct rtnl_link *)object;
                v = json_object_new_object();
                text(v, "name", rtnl_link_get_name(l));
                number(v, "index", (uint64_t)(unsigned)rtnl_link_get_ifindex(l));
                number(v, "mtu", rtnl_link_get_mtu(l));
                number(v, "flags", rtnl_link_get_flags(l));
                number(v, "operstate", rtnl_link_get_operstate(l));
                text(v, "mac", address(rtnl_link_get_addr(l), buf, sizeof buf));
                number(v, "rx_bytes", rtnl_link_get_stat(l, RTNL_LINK_RX_BYTES));
                number(v, "tx_bytes", rtnl_link_get_stat(l, RTNL_LINK_TX_BYTES));
                number(v, "rx_errors", rtnl_link_get_stat(l, RTNL_LINK_RX_ERRORS));
                number(v, "tx_errors", rtnl_link_get_stat(l, RTNL_LINK_TX_ERRORS));
            } else if (!strcmp(kind, "addresses")) {
                struct rtnl_addr *a = (struct rtnl_addr *)object;
                v = json_object_new_object();
                interface(v, rtnl_addr_get_ifindex(a));
                number(v, "family", (uint64_t)(unsigned)rtnl_addr_get_family(a));
                number(v, "prefix", (uint64_t)(unsigned)rtnl_addr_get_prefixlen(a));
                text(v, "local", address(rtnl_addr_get_local(a), buf, sizeof buf));
                number(v, "scope", (uint64_t)(unsigned)rtnl_addr_get_scope(a));
            } else
                v = route((struct rtnl_route *)object);
            json_object_array_add(list, v);
        }
    }
done:
    if (cache)
        nl_cache_free(cache);
    nl_socket_free(socket);
    if (r < 0) {
        json_object_put(list);
        return cm_fail(e, "Netlink %s: %s", kind, nl_geterror(r));
    }
    *out = list;
    return 0;
}
static int dns(struct json_object **out, struct cm_error *e)
{
    struct json_object *o = json_object_new_object(), *list = json_object_new_array();
    sd_bus *bus = NULL;
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = sd_bus_open_system(&bus);
    if (r >= 0)
        r = sd_bus_get_property(bus, "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
                                "org.freedesktop.resolve1.Manager", "DNS", &error, &reply,
                                "a(iiay)");
    if (r >= 0)
        r = sd_bus_message_enter_container(reply, 'a', "(iiay)");
    bool provider = r >= 0;
    while (r >= 0 && provider) {
        r = sd_bus_message_enter_container(reply, 'r', "iiay");
        if (r <= 0)
            break;
        int index = 0, af = 0;
        const void *bytes = NULL;
        size_t size = 0;
        r = sd_bus_message_read(reply, "ii", &index, &af);
        if (r >= 0)
            r = sd_bus_message_read_array(reply, 'y', &bytes, &size);
        if (r >= 0 && ((af == AF_INET && size == 4) || (af == AF_INET6 && size == 16))) {
            char ip[INET6_ADDRSTRLEN];
            if (inet_ntop(af, bytes, ip, sizeof ip)) {
                struct json_object *v = json_object_new_object();
                interface(v, index);
                text(v, "address", ip);
                json_object_array_add(list, v);
            }
        }
        if (r >= 0)
            r = sd_bus_message_exit_container(reply);
    }
    sd_bus_message_unref(reply);
    sd_bus_error_free(&error);
    sd_bus_unref(bus);
    if (provider && r < 0) {
        json_object_put(list);
        json_object_put(o);
        return cm_fail(e, "cannot decode resolver DNS data");
    }
    text(o, "source", provider ? "systemd-resolved" : "/etc/resolv.conf");
    text(o, "interpretation",
         provider ? "known upstream servers; selection may depend on interface/domain"
                  : "configured resolver endpoints; local stub upstreams may be unknown");
    if (!provider) {
        FILE *f = fopen("/etc/resolv.conf", "re");
        if (!f) {
            json_object_put(list);
            json_object_put(o);
            return cm_fail(e, "read resolver configuration: %s", strerror(errno));
        }
        char line[1024], ip[80], key[64];
        size_t count = 0;
        while (fgets(line, sizeof line, f) && count++ < 4096)
            if (sscanf(line, "%63s %79s", key, ip) == 2 && !strcmp(key, "nameserver")) {
                char normalized[CM_ADDRESS_MAX];
                struct cm_error ignored;
                if (!cm_address(ip, false, normalized, sizeof normalized, &ignored)) {
                    struct json_object *v = json_object_new_object();
                    text(v, "address", normalized);
                    json_object_array_add(list, v);
                }
            }
        fclose(f);
    }
    json_object_object_add(o, "servers", list);
    *out = o;
    return 0;
}
struct response {
    char text[128];
    size_t used;
};
static size_t receive(void *data, size_t size, size_t count, void *context)
{
    struct response *r = context;
    if (size && count > SIZE_MAX / size)
        return 0;
    size_t n = size * count;
    if (n >= sizeof r->text - r->used)
        return 0;
    memcpy(r->text + r->used, data, n);
    r->used += n;
    return n;
}
static int public_ip(int argc, char **argv, struct json_object **out, struct cm_error *e)
{
    int family = 4;
    const char *url = NULL;
    for (int i = 0; i < argc; i += 2) {
        if (i + 1 >= argc)
            return cm_fail(e, "public-ip option needs a value");
        if (!strcmp(argv[i], "--family")) {
            if (!strcmp(argv[i + 1], "6"))
                family = 6;
            else if (!strcmp(argv[i + 1], "4"))
                family = 4;
            else
                return cm_fail(e, "family must be 4 or 6");
        } else if (!strcmp(argv[i], "--url"))
            url = argv[i + 1];
        else
            return cm_fail(e, "unknown public-ip option");
    }
    if (!url)
        url = family == 4 ? "https://api.ipify.org" : "https://api6.ipify.org";
    if (strncmp(url, "https://", 8) || strlen(url) > 2048 || !cm_plain(url, false))
        return cm_fail(e, "public IP endpoint must be a bounded HTTPS URL");
    CURL *curl = curl_easy_init();
    if (!curl)
        return cm_fail(e, "cannot initialize HTTPS client");
    struct response data = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE,
                     (long)(family == 4 ? CURL_IPRESOLVE_V4 : CURL_IPRESOLVE_V6));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "command-center/" CM_VERSION);
    CURLcode r = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    if (r != CURLE_OK || status != 200)
        return cm_fail(e, "public-IP request failed: %s (HTTP %ld)", curl_easy_strerror(r), status);
    while (data.used && (data.text[data.used - 1] == '\n' || data.text[data.used - 1] == '\r' ||
                         data.text[data.used - 1] == ' '))
        data.text[--data.used] = 0;
    char ip[CM_ADDRESS_MAX];
    if (cm_address(data.text, false, ip, sizeof ip, e) ||
        (strchr(ip, ':') != NULL) != (family == 6))
        return cm_fail(e, "endpoint returned an invalid address/family");
    struct json_object *o = json_object_new_object();
    text(o, "observed_address", ip);
    text(o, "endpoint", url);
    number(o, "family", (uint64_t)(unsigned)family);
    *out = o;
    return 0;
}
static int listeners(struct json_object **out, struct cm_error *e)
{
    const char *paths[] = {"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"};
    struct json_object *list = json_object_new_array();
    for (unsigned k = 0; k < 4; k++) {
        FILE *f = fopen(paths[k], "re");
        if (!f) {
            if (errno == ENOENT && k % 2)
                continue;
            json_object_put(list);
            return cm_fail(e, "read sockets: %s", strerror(errno));
        }
        char line[1024];
        size_t count = 0;
        while (fgets(line, sizeof line, f)) {
            unsigned slot, port, state;
            char hex[33];
            if (sscanf(line, "%u: %32[0-9A-Fa-f]:%x %*s %x", &slot, hex, &port, &state) != 4)
                continue;
            if (k < 2 && state != 10)
                continue;
            size_t length = strlen(hex);
            if (length != (k % 2 ? 32U : 8U) || port > 65535)
                continue;
            unsigned char bytes[16] = {0};
            bool valid = true;
            for (size_t i = 0; i < length / 8; i++) {
                char word[9];
                memcpy(word, hex + i * 8, 8);
                word[8] = 0;
                char *end = NULL;
                unsigned long value = strtoul(word, &end, 16);
                if (!end || *end || value > UINT32_MAX) {
                    valid = false;
                    break;
                }
                uint32_t v = (uint32_t)value;
                memcpy(bytes + i * 4, &v, 4);
            }
            char ip[INET6_ADDRSTRLEN];
            if (!valid || !inet_ntop(k % 2 ? AF_INET6 : AF_INET, bytes, ip, sizeof ip))
                continue;
            if (++count > 65536) {
                fclose(f);
                json_object_put(list);
                return cm_fail(e, "socket reporting capacity reached");
            }
            struct json_object *o = json_object_new_object();
            text(o, "protocol", k < 2 ? "tcp" : "udp");
            text(o, "address", ip);
            number(o, "port", port);
            text(o, "state", k < 2 ? "listening" : "bound");
            json_object_array_add(list, o);
        }
        fclose(f);
    }
    *out = list;
    return 0;
}
int cm_network(int argc, char **argv, bool json, struct cm_error *e)
{
    const char *cmd = argc ? argv[0] : "summary";
    struct json_object *o = NULL;
    int r = 0;
    if (!strcmp(cmd, "summary") && argc <= 1) {
        o = json_object_new_object();
        const char *sections[] = {"interfaces", "addresses", "routes"};
        for (unsigned i = 0; i < 3 && !r; i++) {
            struct json_object *a = NULL;
            r = netlink(sections[i], NULL, &a, e);
            if (!r)
                json_object_object_add(o, sections[i], a);
        }
        if (!r) {
            struct json_object *a = NULL;
            r = dns(&a, e);
            if (!r)
                json_object_object_add(o, "dns", a);
        }
    } else if ((!strcmp(cmd, "interfaces") || !strcmp(cmd, "addresses") ||
                !strcmp(cmd, "routes")) &&
               argc == 1)
        r = netlink(cmd, NULL, &o, e);
    else if (!strcmp(cmd, "route") && argc == 3 && !strcmp(argv[1], "get"))
        r = netlink("route", argv[2], &o, e);
    else if (!strcmp(cmd, "dns") && argc == 1)
        r = dns(&o, e);
    else if (!strcmp(cmd, "listeners") && argc == 1)
        r = listeners(&o, e);
    else if (!strcmp(cmd, "public-ip"))
        r = public_ip(argc - 1, argv + 1, &o, e);
    else
        return cm_fail(e, "unknown network command or arguments");
    if (!r) {
        if (json)
            puts(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY |
                                               JSON_C_TO_STRING_NOSLASHESCAPE));
        else {
            printf("Network %s (current network namespace):\n", cmd);
            cm_print_report(o);
        }
    }
    if (o)
        json_object_put(o);
    return r;
}
