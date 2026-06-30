#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "netacct.h"

struct iface_counters g_iface;

static size_t ip_hash(uint32_t ip) {
    return (ip ^ (ip >> 16)) % IP_HASH_BUCKETS;
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

static struct ip_counter *lookup_locked(uint32_t ip) {
    size_t h = ip_hash(ip);
    for (struct ip_counter *e = g_iface.entries[h]; e; e = e->next) {
        if (e->ip == ip) return e;
    }
    return NULL;
}

static struct ip_counter *get_or_create_locked(uint32_t ip) {
    struct ip_counter *e = lookup_locked(ip);
    if (e) return e;
    e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->ip = ip;
    size_t h = ip_hash(ip);
    e->next = g_iface.entries[h];
    g_iface.entries[h] = e;
    list_add(e);
    return e;
}

int ipacct_add_client(uint32_t ip) {
    pthread_mutex_lock(&g_iface.lock);
    struct ip_counter *e = get_or_create_locked(ip);
    pthread_mutex_unlock(&g_iface.lock);
    if (!e) return -1;
    char ipbuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ipbuf, sizeof(ipbuf));
    fprintf(stderr, "[ipacct] tracking %s\n", ipbuf);
    return 0;
}

int ipacct_del_client(uint32_t ip) {
    pthread_mutex_lock(&g_iface.lock);
    size_t h = ip_hash(ip);
    struct ip_counter **pp = &g_iface.entries[h];
    while (*pp) {
        if ((*pp)->ip == ip) {
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

int ipacct_update_rx(const char *iface, uint32_t ip, uint32_t bytes) {
    (void)iface;
    pthread_mutex_lock(&g_iface.lock);
    struct ip_counter *e = get_or_create_locked(ip);
    if (e) e->rx_bytes += bytes;
    pthread_mutex_unlock(&g_iface.lock);
    return e ? 0 : -1;
}

int ipacct_update_tx(const char *iface, uint32_t ip, uint32_t bytes) {
    (void)iface;
    pthread_mutex_lock(&g_iface.lock);
    struct ip_counter *e = get_or_create_locked(ip);
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
            out_ips[n].ip = e->ip;
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
