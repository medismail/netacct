#ifndef NETACCT_H
#define NETACCT_H

#include <stdint.h>
#include <pthread.h>

#define MAX_IFACE_NAME 32
#define MAX_IP_ENTRIES 64  // safe bound for <=30 IPs

struct ip_record {
    uint32_t ip;      // IPv4 addr (network byte order)
    uint64_t rx;
    uint64_t tx;
};

struct ip_counter {
    uint32_t ip;      // IPv4 addr (network byte order)
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    struct ip_counter *next;
    struct ip_counter *lprev;  // for active list
    struct ip_counter *lnext;  // for active list
};

struct iface_counters {
    char name[MAX_IFACE_NAME];
    struct ip_counter *entries[MAX_IP_ENTRIES];
    struct ip_counter *active_head;
    struct ip_counter *active_tail;
    // kernel totals delta since last flush
    uint64_t kernel_rx_delta;
    uint64_t kernel_tx_delta;
    // last read kernel counters
    uint64_t last_kernel_rx;
    uint64_t last_kernel_tx;
    pthread_mutex_t lock;
};

struct cfg {
    char *iface;
    int poll_interval;   // seconds
    int flush_interval;  // seconds
    char *root_dir;
};

struct __attribute__((packed)) ip_entry_on_disk {
    uint8_t ipv;
    uint8_t pad;
    uint32_t addr;
    uint64_t rx_delta;
    uint64_t tx_delta;
};

// API
int collector_init(struct cfg *cfg);
int collector_run(struct cfg *cfg);
int reporter_run(int argc, char **argv);
void *control_thread_fn(void *arg);

// per-IP API
int ipacct_add_local(const char *iface, uint32_t ip);
int ipacct_update_rx(const char *iface, uint32_t ip, uint32_t bytes);
int ipacct_update_tx(const char *iface, uint32_t ip, uint32_t bytes);
void ipacct_add_client(uint32_t ip);
void ipacct_del_client(uint32_t ip);

// storage
int storage_append_daily(const char *root_dir, const char *iface,
                         uint32_t ts, uint64_t rx_delta, uint64_t tx_delta,
                         uint16_t ip_count, const void *ip_entries, size_t ip_entries_len);

#endif // NETACCT_H

