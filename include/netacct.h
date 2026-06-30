#ifndef NETACCT_H
#define NETACCT_H

#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <pthread.h>

#define MAX_IFACE_NAME 32
#define MAX_ROOT_DIR 256
#define MAX_SUBNET_TEXT 64
#define MAX_IP_ENTRIES 4096
#define IP_HASH_BUCKETS 1024

#define NETACCT_DEFAULT_IFACE "eth0"
#define NETACCT_DEFAULT_ROOT "/var/lib/netacct"
#define NETACCT_DEFAULT_POLL_INTERVAL 1
#define NETACCT_DEFAULT_FLUSH_INTERVAL 5
#define NETACCT_DEFAULT_PCAP_BUFFER_MB 4
#define NETACCT_DEFAULT_TOP_N 50

extern volatile sig_atomic_t netacct_running;

struct ip_record {
    uint32_t ip;
    uint64_t rx;
    uint64_t tx;
};

struct ip_counter {
    uint32_t ip;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    struct ip_counter *next;
    struct ip_counter *lprev;
    struct ip_counter *lnext;
};

struct iface_counters {
    char name[MAX_IFACE_NAME];
    struct ip_counter *entries[IP_HASH_BUCKETS];
    struct ip_counter *active_head;
    struct ip_counter *active_tail;

    uint64_t kernel_rx_delta;
    uint64_t kernel_tx_delta;
    uint64_t last_kernel_rx;
    uint64_t last_kernel_tx;

    pthread_mutex_t lock;
};

struct cfg {
    char iface[MAX_IFACE_NAME];
    int poll_interval;
    int flush_interval;
    char root_dir[MAX_ROOT_DIR];

    uint32_t local_net;
    uint32_t local_mask;
    int has_local_net;
    char subnet_text[MAX_SUBNET_TEXT];

    int pcap_buffer_mb;
    int top_n;
};

struct __attribute__((packed)) ip_entry_on_disk {
    uint8_t ipv;
    uint8_t pad;
    uint32_t addr;
    uint64_t rx_delta;
    uint64_t tx_delta;
};

struct pcap_runtime_stats {
    uint64_t packets_seen;
    uint64_t ipv4_packets;
    uint64_t local_packets;
    uint64_t accounted_bytes;
    unsigned int pcap_recv;
    unsigned int pcap_drop;
    unsigned int pcap_ifdrop;
};

void cfg_set_defaults(struct cfg *cfg);
int cfg_load_file(struct cfg *cfg, const char *path);
int cfg_apply_option(struct cfg *cfg, const char *key, const char *value);
int parse_ipv4_cidr(const char *cidr, uint32_t *out_net, uint32_t *out_mask);
int detect_iface_ipv4_network(const char *iface, uint32_t *out_net, uint32_t *out_mask,
                              char *out_text, size_t out_text_len);
int cfg_ip_is_local(const struct cfg *cfg, uint32_t ip_be);
const char *format_ipv4_host(uint32_t ip_host, char *buf, size_t len);

int collector_init(struct cfg *cfg);
int collector_run(struct cfg *cfg);
int reporter_run(int argc, char **argv);
void *control_thread_fn(void *arg);

int pcap_start_for_iface_threaded(struct cfg *cfg);
void pcap_request_stop(void);
void pcap_get_runtime_stats(struct pcap_runtime_stats *out);

void *poller_thread_fn(void *arg);
int poller_persist_last_counts(const struct cfg *cfg);

int ipacct_add_client(uint32_t ip);
int ipacct_del_client(uint32_t ip);
int ipacct_update_rx(const char *iface, uint32_t ip, uint32_t bytes);
int ipacct_update_tx(const char *iface, uint32_t ip, uint32_t bytes);
int ipacct_accumulate_kernel_delta(uint64_t rx_delta, uint64_t tx_delta,
                                   uint64_t latest_rx, uint64_t latest_tx);
void ipacct_snapshot_and_clear(uint64_t *out_kernel_rx, uint64_t *out_kernel_tx,
                               struct ip_record *out_ips, int *out_ip_count);
void ipacct_get_latest_kernel_counts(uint64_t *out_rx, uint64_t *out_tx);

int storage_append_daily(const char *root_dir, const char *iface,
                         uint32_t ts, uint64_t rx_delta, uint64_t tx_delta,
                         uint16_t ip_count, const void *ip_entries, size_t ip_entries_len);

#endif /* NETACCT_H */
