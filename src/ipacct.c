// simple per-iface single global implementation

#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>

#include "netacct.h"

struct iface_counters g_iface;
//static struct iface_counters g_iface;

// Expose the snapshot function symbol for storage/flush
//int __attribute__((weak)) ipacct_snapshot_and_clear(uint64_t*,uint64_t*,struct ip_counter*,int*);

int ipacct_accumulate_kernel_delta(uint64_t rx_delta, uint64_t tx_delta) {
    pthread_mutex_lock(&g_iface.lock);
    g_iface.kernel_rx_delta += rx_delta;
    g_iface.kernel_tx_delta += tx_delta;
    pthread_mutex_unlock(&g_iface.lock);
    return 0;
}

int ipacct_add_local(const char *iface, uint32_t ip) {
    pthread_mutex_lock(&g_iface.lock);
    if (g_iface.entry_count == 0) {
        strncpy(g_iface.name, iface, MAX_IFACE_NAME-1);
        g_iface.name[MAX_IFACE_NAME-1] = '\0';
    } else {
        if (strncmp(g_iface.name, iface, MAX_IFACE_NAME) != 0) {
            pthread_mutex_unlock(&g_iface.lock);
            return -1;
        }
    }
    if (g_iface.entry_count >= MAX_IP_ENTRIES) {
        pthread_mutex_unlock(&g_iface.lock);
        return -1;
    }
    g_iface.entries[g_iface.entry_count].ip = ip;
    g_iface.entries[g_iface.entry_count].rx_bytes = 0;
    g_iface.entries[g_iface.entry_count].tx_bytes = 0;
    g_iface.entry_count++;
    pthread_mutex_unlock(&g_iface.lock);
    return 0;
}

static struct ip_counter* find_entry(uint32_t ip) {
    for (int i = 0; i < g_iface.entry_count; ++i) {
        if (g_iface.entries[i].ip == ip) return &g_iface.entries[i];
    }
    return NULL;
}

int ipacct_update_rx(const char *iface, uint32_t ip, uint32_t bytes) {
    (void)iface;
    pthread_mutex_lock(&g_iface.lock);
    struct ip_counter *e = find_entry(ip);
    if (e) e->rx_bytes += bytes;
    pthread_mutex_unlock(&g_iface.lock);
    return 0;
}

int ipacct_update_tx(const char *iface, uint32_t ip, uint32_t bytes) {
    (void)iface;
    pthread_mutex_lock(&g_iface.lock);
    struct ip_counter *e = find_entry(ip);
    if (e) e->tx_bytes += bytes;
    pthread_mutex_unlock(&g_iface.lock);
    return 0;
}

// helpers for poller/flush to access snapshot
void ipacct_snapshot_and_clear(uint64_t *out_kernel_rx, uint64_t *out_kernel_tx,
                               struct ip_counter *out_ips, int *out_ip_count) {
    pthread_mutex_lock(&g_iface.lock);
    if (out_kernel_rx) *out_kernel_rx = g_iface.kernel_rx_delta;
    if (out_kernel_tx) *out_kernel_tx = g_iface.kernel_tx_delta;
    // copy ip counters
    int n = g_iface.entry_count;
    for (int i = 0; i < n; ++i) {
        out_ips[i] = g_iface.entries[i];
        // zero per-flush deltas after snapshot
        g_iface.entries[i].rx_bytes = 0;
        g_iface.entries[i].tx_bytes = 0;
    }
    if (out_ip_count) *out_ip_count = n;
    // zero kernel deltas
    g_iface.kernel_rx_delta = 0;
    g_iface.kernel_tx_delta = 0;
    pthread_mutex_unlock(&g_iface.lock);
}
