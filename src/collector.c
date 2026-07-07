#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#include "netacct.h"

extern struct iface_counters g_iface;
volatile sig_atomic_t netacct_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    netacct_running = 0;
    pcap_request_stop();
}

int collector_init(struct cfg *cfg) {
    if (!cfg) return -1;

    if (!cfg->has_local_net) {
        if (detect_iface_ipv4_network(cfg->iface, &cfg->local_net, &cfg->local_mask,
                                      cfg->subnet_text, sizeof(cfg->subnet_text)) != 0) {
            fprintf(stderr,
                    "[collector] cannot auto-detect IPv4 subnet for %s. Use --subnet A.B.C.D/MASK\n",
                    cfg->iface);
            return -1;
        }
        cfg->has_local_net = 1;
    }

    if (!cfg->has_local6_net) {
        if (detect_iface_ipv6_network(cfg->iface, cfg->local6_net, &cfg->local6_prefix,
                                      cfg->subnet6_text, sizeof(cfg->subnet6_text)) == 0) {
            cfg->has_local6_net = 1;
        } else {
            snprintf(cfg->subnet6_text, sizeof(cfg->subnet6_text), "disabled");
            fprintf(stderr,
                    "[collector] IPv6 accounting disabled: cannot auto-detect IPv6 subnet for %s. Use --subnet6 PREFIX/LEN to force it.\n",
                    cfg->iface);
        }
    }

    memset(&g_iface, 0, sizeof(g_iface));
    snprintf(g_iface.name, sizeof(g_iface.name), "%s", cfg->iface);
    if (pthread_mutex_init(&g_iface.lock, NULL) != 0) {
        perror("pthread_mutex_init");
        return -1;
    }
    return 0;
}

static void *pcap_thread_fn(void *arg) {
    return (void *)(intptr_t)pcap_start_for_iface_threaded((struct cfg *)arg);
}

static void log_flush_stats(uint32_t ts, uint64_t kernel_rx, uint64_t kernel_tx, int ipn) {
    struct pcap_runtime_stats ps;
    pcap_get_runtime_stats(&ps);
    fprintf(stderr,
            "[flush] ts=%u kernel_rx=%llu kernel_tx=%llu ip_records=%d ipv4_packets=%llu ipv6_packets=%llu pcap_recv=%u pcap_drop=%u pcap_ifdrop=%u accounted_l2=%llu\n",
            ts,
            (unsigned long long)kernel_rx,
            (unsigned long long)kernel_tx,
            ipn,
            (unsigned long long)ps.ipv4_packets,
            (unsigned long long)ps.ipv6_packets,
            ps.pcap_recv,
            ps.pcap_drop,
            ps.pcap_ifdrop,
            (unsigned long long)ps.accounted_bytes);
}

static int flush_once(struct cfg *cfg, int final) {
    time_t now = time(NULL);
    uint64_t kernel_rx = 0, kernel_tx = 0;
    struct ip_record ips[MAX_IP_ENTRIES];
    int ipn = 0;

    ipacct_snapshot_and_clear(&kernel_rx, &kernel_tx, ips, &ipn);
    if (kernel_rx == 0 && kernel_tx == 0 && ipn == 0) {
        if (final) poller_persist_last_counts(cfg);
        return 0;
    }

    if (storage_append_daily(cfg->root_dir, cfg->iface, (uint32_t)now,
                             kernel_rx, kernel_tx, (uint16_t)ipn,
                             ips, sizeof(struct ip_record) * (size_t)ipn) != 0) {
        fprintf(stderr, "[flush] storage append failed; keeping last persisted counters unchanged\n");
        return -1;
    }

    if (poller_persist_last_counts(cfg) != 0) {
        fprintf(stderr, "[flush] warning: failed to persist last kernel counters\n");
    }

    log_flush_stats((uint32_t)now, kernel_rx, kernel_tx, ipn);
    return 0;
}

static void *flush_thread_fn(void *arg) {
    struct cfg *cfg = (struct cfg *)arg;
    while (netacct_running) {
        for (int i = 0; i < cfg->flush_interval && netacct_running; i++) sleep(1);
        if (!netacct_running) break;
        flush_once(cfg, 0);
    }
    flush_once(cfg, 1);
    return NULL;
}

int collector_run(struct cfg *cfg) {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    pthread_t pcap_thread, poll_thread, flush_thread, control_thread;
    int control_started = 0;

    if (pthread_create(&pcap_thread, NULL, pcap_thread_fn, cfg) != 0) {
        perror("pthread_create pcap");
        return 1;
    }
    if (pthread_create(&poll_thread, NULL, poller_thread_fn, cfg) != 0) {
        perror("pthread_create poller");
        netacct_running = 0;
        pcap_request_stop();
        pthread_join(pcap_thread, NULL);
        return 1;
    }
    if (pthread_create(&flush_thread, NULL, flush_thread_fn, cfg) != 0) {
        perror("pthread_create flush");
        netacct_running = 0;
        pcap_request_stop();
        pthread_join(pcap_thread, NULL);
        pthread_join(poll_thread, NULL);
        return 1;
    }

    if (pthread_create(&control_thread, NULL, control_thread_fn, cfg) != 0) {
        fprintf(stderr, "[control] disabled: cannot start control thread\n");
        control_started = 0;
    } else {
        control_started = 1;
    }

    while (netacct_running) sleep(1);

    pcap_request_stop();
    pthread_join(pcap_thread, NULL);
    pthread_join(poll_thread, NULL);
    pthread_join(flush_thread, NULL);

    if (control_started) {
        pthread_cancel(control_thread);
        pthread_join(control_thread, NULL);
    }

    fprintf(stderr, "[netacct] stopped\n");
    return 0;
}
