// simple per-iface single global implementation
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "netacct.h"


struct iface_counters g_iface;
//static struct iface_counters g_iface;

// Expose the snapshot function symbol for storage/flush
//int __attribute__((weak)) ipacct_snapshot_and_clear(uint64_t*,uint64_t*,struct ip_counter*,int*);

//extern struct ip_counter *g_iface.entries[];

/* Simple hash */
static size_t ip_hash(uint32_t ip) {
    return (ip ^ (ip >> 16)) % MAX_IP_ENTRIES;
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

/* Lookup entry by IP */
static struct ip_counter *lookup(uint32_t ip) {
    size_t h = ip_hash(ip);
    struct ip_counter *e = g_iface.entries[h];
    while (e) {
        if (e->ip == ip) return e;
        e = e->next;
    }
    return NULL;
}

void ipacct_add_client(uint32_t ip) {
    pthread_mutex_lock(&g_iface.lock);
    if (lookup(ip)) {
        pthread_mutex_unlock(&g_iface.lock);
        return; // already present
    }
    size_t h = ip_hash(ip);
    struct ip_counter *e = calloc(1, sizeof(*e));
    if (!e) {
        pthread_mutex_unlock(&g_iface.lock);
        return;
    }
    e->ip = ip;
    e->rx_bytes = 0;
    e->tx_bytes = 0;
    e->next = g_iface.entries[h];
    g_iface.entries[h] = e;
    list_add(e);

    char ipbuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ipbuf, sizeof(ipbuf));
    fprintf(stderr, "[ipacct] Registered client %s\n", ipbuf);

    pthread_mutex_unlock(&g_iface.lock);
}

void ipacct_del_client(uint32_t ip) {
    pthread_mutex_lock(&g_iface.lock);
    size_t h = ip_hash(ip);
    struct ip_counter **pp = &g_iface.entries[h];
    while (*pp) {
        if ((*pp)->ip == ip) {
            struct ip_counter *victim = *pp;
            *pp = victim->next;
            list_remove(victim);

            // flush stats before free (TODO: call into flush logic if needed)
            char ipbuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip, ipbuf, sizeof(ipbuf));
            fprintf(stderr, "[ipacct] Removed client %s (rx=%lu, tx=%lu)\n",
                    ipbuf, victim->rx_bytes, victim->tx_bytes);

            free(victim);
            pthread_mutex_unlock(&g_iface.lock);
            return;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&g_iface.lock);
}

int ipacct_accumulate_kernel_delta(uint64_t rx_delta, uint64_t tx_delta) {
    pthread_mutex_lock(&g_iface.lock);
    g_iface.kernel_rx_delta += rx_delta;
    g_iface.kernel_tx_delta += tx_delta;
    pthread_mutex_unlock(&g_iface.lock);
    return 0;
}

int ipacct_update_rx(const char *iface, uint32_t ip, uint32_t bytes) {
    (void)iface;
    pthread_mutex_lock(&g_iface.lock);
    //struct ip_counter *e = find_entry(ip);
    struct ip_counter *e = lookup(ip);
    if (e) e->rx_bytes += bytes;
    pthread_mutex_unlock(&g_iface.lock);
    return 0;
}

int ipacct_update_tx(const char *iface, uint32_t ip, uint32_t bytes) {
    (void)iface;
    pthread_mutex_lock(&g_iface.lock);
    //struct ip_counter *e = find_entry(ip);
    struct ip_counter *e = lookup(ip);
    if (e) e->tx_bytes += bytes;
    pthread_mutex_unlock(&g_iface.lock);
    return 0;
}

// helpers for poller/flush to access snapshot
void ipacct_snapshot_and_clear(uint64_t *out_kernel_rx, uint64_t *out_kernel_tx,
                               struct ip_record *out_ips, int *out_ip_count) {
    pthread_mutex_lock(&g_iface.lock);
    if (out_kernel_rx) *out_kernel_rx = g_iface.kernel_rx_delta;
    if (out_kernel_tx) *out_kernel_tx = g_iface.kernel_tx_delta;
    // copy ip counters
    size_t n = 0;
    for (struct ip_counter *e = g_iface.active_head; e && n < MAX_IP_ENTRIES; e = e->lnext) {
        out_ips[n].ip = e->ip;
        out_ips[n].rx = e->rx_bytes;
        out_ips[n].tx = e->tx_bytes;
        // zero per-flush deltas after snapshot
        e->rx_bytes = 0;
        e->tx_bytes = 0;
        n++;
    }

    if (out_ip_count) *out_ip_count = n;
    // zero kernel deltas
    g_iface.kernel_rx_delta = 0;
    g_iface.kernel_tx_delta = 0;
    pthread_mutex_unlock(&g_iface.lock);
}
