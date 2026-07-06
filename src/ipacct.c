#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "netacct.h"

struct iface_counters g_iface;

static int addr_set(struct netacct_addr *out, uint8_t ipv, const void *addr) {
    if (!out || !addr) return -1;
    memset(out, 0, sizeof(*out));
    out->ipv = ipv;
    if (ipv == NETACCT_IPV4) {
        memcpy(out->bytes, addr, 4);
        return 0;
    }
    if (ipv == NETACCT_IPV6) {
        memcpy(out->bytes, addr, NETACCT_ADDR_BYTES);
        return 0;
    }
    return -1;
}

static size_t addr_hash(const struct netacct_addr *addr) {
    uint32_t h = 2166136261u;
    h ^= addr->ipv;
    h *= 16777619u;
    size_t len = (addr->ipv == NETACCT_IPV4) ? 4 : NETACCT_ADDR_BYTES;
    for (size_t i = 0; i < len; i++) {
        h ^= addr->bytes[i];
        h *= 16777619u;
    }
    return h % IP_HASH_BUCKETS;
}

static int addr_equal(const struct netacct_addr *a, const struct netacct_addr *b) {
    if (a->ipv != b->ipv) return 0;
    size_t len = (a->ipv == NETACCT_IPV4) ? 4 : NETACCT_ADDR_BYTES;
    return memcmp(a->bytes, b->bytes, len) == 0;
}

static void list_add(struct ip_counter *e) {
    e->lprev = g_iface.active_tail;
    e->lnext = NULL;
    if (g_iface.active_tail) g_iface.active_tail->lnext = e;
    else g_iface.active_head = e;
    g_iface.active_tail = e;
}

static void list_remove(struct ip_counter *e) {
    if (e->lprev) e->lprev->lnext = e->lnext;
    else g_iface.active_head = e->lnext;
    if (e->lnext) e->lnext->lprev = e->lprev;
    else g_iface.active_tail = e->lprev;
}

static struct ip_counter *lookup_locked(const struct netacct_addr *addr) {
    size_t h = addr_hash(addr);
    for (struct ip_counter *e = g_iface.entries[h]; e; e = e->next) {
        if (addr_equal(&e->addr, addr)) return e;
    }
    return NULL;
}

static struct ip_counter *get_or_create_locked(const struct netacct_addr *addr) {
    struct ip_counter *e = lookup_locked(addr);
    if (e) return e;
    e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->addr = *addr;
    size_t h = addr_hash(addr);
    e->next = g_iface.entries[h];
    g_iface.entries[h] = e;
    list_add(e);
    return e;
}

int ipacct_add_client(uint8_t ipv, const void *addr) {
    struct netacct_addr key;
    if (addr_set(&key, ipv, addr) != 0) return -1;
    pthread_mutex_lock(&g_iface.lock);
    struct ip_counter *e = get_or_create_locked(&key);
    pthread_mutex_unlock(&g_iface.lock);
    if (!e) return -1;
    char ipbuf[INET6_ADDRSTRLEN];
    format_netacct_addr(&key, ipbuf, sizeof(ipbuf));
    fprintf(stderr, "[ipacct] tracking %s\n", ipbuf);
    return 0;
}

int ipacct_del_client(uint8_t ipv, const void *addr) {
    struct netacct_addr key;
    if (addr_set(&key, ipv, addr) != 0) return -1;
    pthread_mutex_lock(&g_iface.lock);
    size_t h = addr_hash(&key);
    struct ip_counter **pp = &g_iface.entries[h];
    while (*pp) {
        if (addr_equal(&(*pp)->addr, &key)) {
            struct ip_counter *victim = *pp;
            *pp = victim->next;
            list_remove(victim);
            free(victim);
            pthread_mutex_unlock(&g_iface.lock);
            return 0;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&g_iface.lock);
    return -1;
}

int ipacct_accumulate_kernel_delta(uint64_t rx_delta, uint64_t tx_delta,
                                   uint64_t latest_rx, uint64_t latest_tx) {
    pthread_mutex_lock(&g_iface.lock);
    g_iface.kernel_rx_delta += rx_delta;
    g_iface.kernel_tx_delta += tx_delta;
    g_iface.last_kernel_rx = latest_rx;
    g_iface.last_kernel_tx = latest_tx;
    pthread_mutex_unlock(&g_iface.lock);
    return 0;
}

void ipacct_get_latest_kernel_counts(uint64_t *out_rx, uint64_t *out_tx) {
    pthread_mutex_lock(&g_iface.lock);
    if (out_rx) *out_rx = g_iface.last_kernel_rx;
    if (out_tx) *out_tx = g_iface.last_kernel_tx;
    pthread_mutex_unlock(&g_iface.lock);
}

int ipacct_update_rx(const char *iface, uint8_t ipv, const void *addr, uint32_t bytes) {
    (void)iface;
    struct netacct_addr key;
    if (addr_set(&key, ipv, addr) != 0) return -1;
    pthread_mutex_lock(&g_iface.lock);
    struct ip_counter *e = get_or_create_locked(&key);
    if (e) e->rx_bytes += bytes;
    pthread_mutex_unlock(&g_iface.lock);
    return e ? 0 : -1;
}

int ipacct_update_tx(const char *iface, uint8_t ipv, const void *addr, uint32_t bytes) {
    (void)iface;
    struct netacct_addr key;
    if (addr_set(&key, ipv, addr) != 0) return -1;
    pthread_mutex_lock(&g_iface.lock);
    struct ip_counter *e = get_or_create_locked(&key);
    if (e) e->tx_bytes += bytes;
    pthread_mutex_unlock(&g_iface.lock);
    return e ? 0 : -1;
}

void ipacct_snapshot_and_clear(uint64_t *out_kernel_rx, uint64_t *out_kernel_tx,
                               struct ip_record *out_ips, int *out_ip_count) {
    pthread_mutex_lock(&g_iface.lock);
    if (out_kernel_rx) *out_kernel_rx = g_iface.kernel_rx_delta;
    if (out_kernel_tx) *out_kernel_tx = g_iface.kernel_tx_delta;
    int n = 0;
    for (struct ip_counter *e = g_iface.active_head; e; e = e->lnext) {
        if (e->rx_bytes == 0 && e->tx_bytes == 0) continue;
        if (n < MAX_IP_ENTRIES) {
            out_ips[n].addr = e->addr;
            out_ips[n].rx = e->rx_bytes;
            out_ips[n].tx = e->tx_bytes;
            n++;
        } else {
            fprintf(stderr, "[ipacct] snapshot full; dropping extra active IPs in this flush\n");
        }
        e->rx_bytes = 0;
        e->tx_bytes = 0;
    }
    if (out_ip_count) *out_ip_count = n;
    g_iface.kernel_rx_delta = 0;
    g_iface.kernel_tx_delta = 0;
    pthread_mutex_unlock(&g_iface.lock);
}
