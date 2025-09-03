#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#include "netacct.h"

// Forwarded functions
int pcap_start_for_iface_threaded(const char *iface);
void *poller_thread_fn(void *arg);
extern void ipacct_snapshot_and_clear(uint64_t*,uint64_t*,struct ip_counter*,int*);
extern int ipacct_accumulate_kernel_delta(uint64_t rx_delta, uint64_t tx_delta);

static volatile int running = 1;

void sigint_handler(int sig) { (void)sig; running = 0; }

int collector_init(const struct cfg *cfg) {
    // init global structures: set mutex
    extern struct iface_counters g_iface;
    memset(&g_iface, 0, sizeof(g_iface));
    pthread_mutex_init(&g_iface.lock, NULL);
    g_iface.kernel_rx_delta = 0;
    g_iface.kernel_tx_delta = 0;
    g_iface.last_kernel_rx = 0;
    g_iface.last_kernel_tx = 0;
    return 0;
}

void *pcap_thread_fn(void *arg) {
    struct cfg *cfg = arg;
    pcap_start_for_iface_threaded(cfg->iface);
    return NULL;
}

void *flush_thread_fn(void *arg) {
    struct cfg *cfg = arg;
    int interval = cfg->flush_interval;
    while (running) {
        sleep(interval);

        time_t now = time(NULL);
        uint64_t kernel_rx = 0, kernel_tx = 0;
        struct ip_counter ips[MAX_IP_ENTRIES];
        int ipn = 0;
        // snapshot and clear
        ipacct_snapshot_and_clear(&kernel_rx, &kernel_tx, ips, &ipn);

        // append to storage
        if (kernel_rx == 0 && kernel_tx == 0 && ipn == 0) continue; // nothing to write
        if (storage_append_daily(cfg->root_dir, cfg->iface, (uint32_t)now,
                                 kernel_rx, kernel_tx, (uint16_t)ipn,
                                 ips, sizeof(struct ip_counter)*ipn) != 0) {
            fprintf(stderr, "storage append failed\n");
        } else {
            printf("flushed %u: kernel_rx=%lu kernel_tx=%lu ipn=%d\n",
                   (unsigned)now, kernel_rx, kernel_tx, ipn);
        }
    }
    // final flush before exit
    time_t now = time(NULL);
    uint64_t kernel_rx = 0, kernel_tx = 0;
    struct ip_counter ips[MAX_IP_ENTRIES];
    int ipn = 0;
    ipacct_snapshot_and_clear(&kernel_rx, &kernel_tx, ips, &ipn);
    if (kernel_rx || kernel_tx || ipn) {
        storage_append_daily(cfg->root_dir, cfg->iface, (uint32_t)now,
                             kernel_rx, kernel_tx, (uint16_t)ipn,
                             ips, sizeof(struct ip_counter)*ipn);
    }
    return NULL;
}

int collector_run(struct cfg cfg) {

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    // for testing add a local IP (replace with your local IP)
    uint32_t myip;
    inet_pton(AF_INET, "172.16.3.66", &myip);
    ipacct_add_local(cfg.iface, myip);

    pthread_t pcap_thread, poll_thread, flush_thread;
    pthread_create(&pcap_thread, NULL, pcap_thread_fn, &cfg);
    pthread_create(&poll_thread, NULL, poller_thread_fn, &cfg);
    pthread_create(&flush_thread, NULL, flush_thread_fn, &cfg);

    while (running) sleep(1);

    // attempt graceful shutdown: stop pcap loop by breaking pcap_loop isn't trivial here,
    // but program exiting will close handle; join threads
    pthread_cancel(pcap_thread); // best-effort
    pthread_join(pcap_thread, NULL);
    pthread_cancel(poll_thread);
    pthread_join(poll_thread, NULL);
    pthread_join(flush_thread, NULL);

    return 0;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    struct cfg cfg;
    cfg.iface = "enp0s3";
    cfg.poll_interval = 1;
    cfg.flush_interval = 5;
    cfg.root_dir = "./data";

    collector_init(&cfg);
    printf("netacct starting for iface=%s\n", cfg.iface);
    collector_run(cfg);
    printf("netacct stopped\n");
    return 0;
}
