#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>

#include "netacct.h"

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) *e-- = '\0';
    return s;
}

void cfg_set_defaults(struct cfg *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->iface, sizeof(cfg->iface), "%s", NETACCT_DEFAULT_IFACE);
    cfg->poll_interval = NETACCT_DEFAULT_POLL_INTERVAL;
    cfg->flush_interval = NETACCT_DEFAULT_FLUSH_INTERVAL;
    snprintf(cfg->root_dir, sizeof(cfg->root_dir), "%s", NETACCT_DEFAULT_ROOT);
    cfg->pcap_buffer_mb = NETACCT_DEFAULT_PCAP_BUFFER_MB;
    cfg->top_n = NETACCT_DEFAULT_TOP_N;
    snprintf(cfg->subnet_text, sizeof(cfg->subnet_text), "auto");
    snprintf(cfg->subnet6_text, sizeof(cfg->subnet6_text), "auto");
    cfg->local6_prefix = -1;
}

static void mask_ipv6_prefix(uint8_t addr[NETACCT_ADDR_BYTES], int prefix) {
    if (prefix < 0) prefix = 0;
    if (prefix > 128) prefix = 128;
    int full = prefix / 8;
    int rem = prefix % 8;
    if (full < NETACCT_ADDR_BYTES) {
        if (rem) {
            uint8_t mask = (uint8_t)(0xffu << (8 - rem));
            addr[full] &= mask;
            full++;
        }
        for (int i = full; i < NETACCT_ADDR_BYTES; i++) addr[i] = 0;
    }
}

int parse_ipv4_cidr(const char *cidr, uint32_t *out_net, uint32_t *out_mask) {
    if (!cidr || !out_net || !out_mask) return -1;
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%s", cidr);
    char *slash = strchr(tmp, '/');
    if (!slash) return -1;
    *slash++ = '\0';
    char *end = NULL;
    long prefix = strtol(slash, &end, 10);
    if (!end || *end != '\0' || prefix < 0 || prefix > 32) return -1;
    struct in_addr a;
    if (inet_pton(AF_INET, tmp, &a) != 1) return -1;
    uint32_t mask = (prefix == 0) ? 0 : (0xffffffffu << (32 - prefix));
    uint32_t ip = ntohl(a.s_addr);
    *out_mask = mask;
    *out_net = ip & mask;
    return 0;
}

int parse_ipv6_cidr(const char *cidr, uint8_t out_net[NETACCT_ADDR_BYTES], int *out_prefix) {
    if (!cidr || !out_net || !out_prefix) return -1;
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s", cidr);
    char *slash = strchr(tmp, '/');
    if (!slash) return -1;
    *slash++ = '\0';
    char *end = NULL;
    long prefix = strtol(slash, &end, 10);
    if (!end || *end != '\0' || prefix < 0 || prefix > 128) return -1;
    struct in6_addr a;
    if (inet_pton(AF_INET6, tmp, &a) != 1) return -1;
    memcpy(out_net, a.s6_addr, NETACCT_ADDR_BYTES);
    mask_ipv6_prefix(out_net, (int)prefix);
    *out_prefix = (int)prefix;
    return 0;
}

const char *format_ipv4_host(uint32_t ip_host, char *buf, size_t len) {
    struct in_addr a;
    a.s_addr = htonl(ip_host);
    if (!inet_ntop(AF_INET, &a, buf, len)) snprintf(buf, len, "0.0.0.0");
    return buf;
}

const char *format_netacct_addr(const struct netacct_addr *addr, char *buf, size_t len) {
    if (!addr || !buf || len == 0) return "";
    if (addr->ipv == NETACCT_IPV4) {
        struct in_addr a;
        memcpy(&a.s_addr, addr->bytes, sizeof(a.s_addr));
        if (!inet_ntop(AF_INET, &a, buf, len)) snprintf(buf, len, "0.0.0.0");
        return buf;
    }
    if (addr->ipv == NETACCT_IPV6) {
        struct in6_addr a6;
        memcpy(a6.s6_addr, addr->bytes, NETACCT_ADDR_BYTES);
        if (!inet_ntop(AF_INET6, &a6, buf, len)) snprintf(buf, len, "::");
        return buf;
    }
    snprintf(buf, len, "unknown");
    return buf;
}

static int ipv6_prefix_from_netmask(const uint8_t mask[NETACCT_ADDR_BYTES]) {
    int prefix = 0;
    int saw_zero = 0;
    for (int i = 0; i < NETACCT_ADDR_BYTES; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            int one = (mask[i] >> bit) & 1;
            if (one) {
                if (saw_zero) return -1;
                prefix++;
            } else {
                saw_zero = 1;
            }
        }
    }
    return prefix;
}

static int is_ipv6_linklocal(const uint8_t addr[NETACCT_ADDR_BYTES]) {
    return addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80;
}

int detect_iface_ipv4_network(const char *iface, uint32_t *out_net, uint32_t *out_mask,
                              char *out_text, size_t out_text_len) {
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) return -1;
    int rc = -1;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_netmask) continue;
        if (strcmp(ifa->ifa_name, iface) != 0) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        struct sockaddr_in *nm = (struct sockaddr_in *)ifa->ifa_netmask;
        uint32_t ip = ntohl(sa->sin_addr.s_addr);
        uint32_t mask = ntohl(nm->sin_addr.s_addr);
        uint32_t net = ip & mask;
        if (out_net) *out_net = net;
        if (out_mask) *out_mask = mask;
        if (out_text && out_text_len > 0) {
            int prefix = 0;
            uint32_t m = mask;
            while (m & 0x80000000u) { prefix++; m <<= 1; }
            char nbuf[INET_ADDRSTRLEN];
            format_ipv4_host(net, nbuf, sizeof(nbuf));
            snprintf(out_text, out_text_len, "%s/%d", nbuf, prefix);
        }
        rc = 0;
        break;
    }
    freeifaddrs(ifaddr);
    return rc;
}

int detect_iface_ipv6_network(const char *iface, uint8_t out_net[NETACCT_ADDR_BYTES],
                              int *out_prefix, char *out_text, size_t out_text_len) {
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) return -1;
    int rc = -1;
    uint8_t fallback_net[NETACCT_ADDR_BYTES] = {0};
    int fallback_prefix = -1;

    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_netmask) continue;
        if (strcmp(ifa->ifa_name, iface) != 0) continue;
        if (ifa->ifa_addr->sa_family != AF_INET6) continue;

        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ifa->ifa_addr;
        struct sockaddr_in6 *nm = (struct sockaddr_in6 *)ifa->ifa_netmask;
        int prefix = ipv6_prefix_from_netmask(nm->sin6_addr.s6_addr);
        if (prefix < 0) continue;

        uint8_t net[NETACCT_ADDR_BYTES];
        memcpy(net, sa->sin6_addr.s6_addr, NETACCT_ADDR_BYTES);
        mask_ipv6_prefix(net, prefix);

        if (is_ipv6_linklocal(sa->sin6_addr.s6_addr)) {
            if (fallback_prefix < 0) {
                memcpy(fallback_net, net, NETACCT_ADDR_BYTES);
                fallback_prefix = prefix;
            }
            continue;
        }

        memcpy(out_net, net, NETACCT_ADDR_BYTES);
        *out_prefix = prefix;
        rc = 0;
        break;
    }

    if (rc != 0 && fallback_prefix >= 0) {
        memcpy(out_net, fallback_net, NETACCT_ADDR_BYTES);
        *out_prefix = fallback_prefix;
        rc = 0;
    }

    if (rc == 0 && out_text && out_text_len > 0) {
        struct netacct_addr a;
        memset(&a, 0, sizeof(a));
        a.ipv = NETACCT_IPV6;
        memcpy(a.bytes, out_net, NETACCT_ADDR_BYTES);
        char abuf[INET6_ADDRSTRLEN];
        format_netacct_addr(&a, abuf, sizeof(abuf));
        snprintf(out_text, out_text_len, "%s/%d", abuf, *out_prefix);
    }

    freeifaddrs(ifaddr);
    return rc;
}

int cfg_ip_is_local(const struct cfg *cfg, uint32_t ip_be) {
    if (!cfg || !cfg->has_local_net) return 0;
    uint32_t ip = ntohl(ip_be);
    return (ip & cfg->local_mask) == cfg->local_net;
}

int cfg_ip6_is_local(const struct cfg *cfg, const uint8_t ip6[NETACCT_ADDR_BYTES]) {
    if (!cfg || !cfg->has_local6_net || !ip6) return 0;
    int full = cfg->local6_prefix / 8;
    int rem = cfg->local6_prefix % 8;
    if (full > 0 && memcmp(ip6, cfg->local6_net, (size_t)full) != 0) return 0;
    if (rem) {
        uint8_t mask = (uint8_t)(0xffu << (8 - rem));
        if ((ip6[full] & mask) != (cfg->local6_net[full] & mask)) return 0;
    }
    return 1;
}

static int parse_int_range(const char *value, int minv, int maxv, int *out) {
    char *end = NULL;
    long v = strtol(value, &end, 10);
    if (!end || *end != '\0' || v < minv || v > maxv) return -1;
    *out = (int)v;
    return 0;
}

int cfg_apply_option(struct cfg *cfg, const char *key, const char *value) {
    if (!cfg || !key || !value) return -1;
    if (strcmp(key, "iface") == 0 || strcmp(key, "interface") == 0) {
        snprintf(cfg->iface, sizeof(cfg->iface), "%s", value);
        return 0;
    }
    if (strcmp(key, "root") == 0 || strcmp(key, "root_dir") == 0 || strcmp(key, "root-dir") == 0) {
        snprintf(cfg->root_dir, sizeof(cfg->root_dir), "%s", value);
        return 0;
    }
    if (strcmp(key, "poll_interval") == 0 || strcmp(key, "poll-interval") == 0) return parse_int_range(value, 1, 3600, &cfg->poll_interval);
    if (strcmp(key, "flush_interval") == 0 || strcmp(key, "flush-interval") == 0) return parse_int_range(value, 1, 3600, &cfg->flush_interval);
    if (strcmp(key, "pcap_buffer_mb") == 0 || strcmp(key, "pcap-buffer-mb") == 0) return parse_int_range(value, 1, 256, &cfg->pcap_buffer_mb);
    if (strcmp(key, "top") == 0 || strcmp(key, "top_n") == 0 || strcmp(key, "top-n") == 0) return parse_int_range(value, 1, MAX_IP_ENTRIES, &cfg->top_n);
    if (strcmp(key, "subnet") == 0 || strcmp(key, "local_subnet") == 0 || strcmp(key, "local-subnet") == 0) {
        if (strcmp(value, "auto") == 0) {
            cfg->has_local_net = 0;
            cfg->local_net = 0;
            cfg->local_mask = 0;
            snprintf(cfg->subnet_text, sizeof(cfg->subnet_text), "auto");
            return 0;
        }
        uint32_t net, mask;
        if (parse_ipv4_cidr(value, &net, &mask) != 0) return -1;
        cfg->local_net = net;
        cfg->local_mask = mask;
        cfg->has_local_net = 1;
        snprintf(cfg->subnet_text, sizeof(cfg->subnet_text), "%s", value);
        return 0;
    }
    if (strcmp(key, "subnet6") == 0 || strcmp(key, "local_subnet6") == 0 || strcmp(key, "local-subnet6") == 0) {
        if (strcmp(value, "auto") == 0) {
            memset(cfg->local6_net, 0, sizeof(cfg->local6_net));
            cfg->local6_prefix = -1;
            cfg->has_local6_net = 0;
            snprintf(cfg->subnet6_text, sizeof(cfg->subnet6_text), "auto");
            return 0;
        }
        uint8_t net6[NETACCT_ADDR_BYTES];
        int prefix6;
        if (parse_ipv6_cidr(value, net6, &prefix6) != 0) return -1;
        memcpy(cfg->local6_net, net6, NETACCT_ADDR_BYTES);
        cfg->local6_prefix = prefix6;
        cfg->has_local6_net = 1;
        snprintf(cfg->subnet6_text, sizeof(cfg->subnet6_text), "%s", value);
        return 0;
    }
    return -1;
}

int cfg_load_file(struct cfg *cfg, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    int lineno = 0;
    int rc = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *p = trim(line);
        if (*p == '\0' || *p == '#') continue;
        char *eq = strchr(p, '=');
        if (!eq) {
            fprintf(stderr, "[config] %s:%d: expected key=value\n", path, lineno);
            rc = -1;
            continue;
        }
        *eq++ = '\0';
        char *key = trim(p);
        char *value = trim(eq);
        char *comment = strchr(value, '#');
        if (comment) { *comment = '\0'; value = trim(value); }
        if (cfg_apply_option(cfg, key, value) != 0) {
            fprintf(stderr, "[config] %s:%d: invalid option %s=%s\n", path, lineno, key, value);
            rc = -1;
        }
    }
    fclose(f);
    return rc;
}
