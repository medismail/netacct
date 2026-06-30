#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "netacct.h"

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

static const struct cfg *g_cfg = NULL;
static pcap_t *g_handle = NULL;
static struct pcap_runtime_stats g_stats;

void pcap_request_stop(void) {
    if (g_handle) pcap_breakloop(g_handle);
}

void pcap_get_runtime_stats(struct pcap_runtime_stats *out) {
    if (!out) return;
    *out = g_stats;
    if (g_handle) {
        struct pcap_stat ps;
        if (pcap_stats(g_handle, &ps) == 0) {
            out->pcap_recv = ps.ps_recv;
            out->pcap_drop = ps.ps_drop;
            out->pcap_ifdrop = ps.ps_ifdrop;
        }
    }
}

static uint16_t read_be16(const u_char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    const struct cfg *cfg = (const struct cfg *)user;
    g_stats.packets_seen++;

    if (h->caplen < 34) return;
    uint16_t ethertype = read_be16(bytes + 12);
    if (ethertype != ETHERTYPE_IP) return;

    const u_char *ip = bytes + 14;
    size_t ip_avail = h->caplen - 14;
    uint8_t version = ip[0] >> 4;
    size_t ihl = (size_t)(ip[0] & 0x0fu) * 4u;
    if (version != 4 || ihl < 20 || ihl > ip_avail) return;

    g_stats.ipv4_packets++;

    uint32_t src, dst;
    memcpy(&src, ip + 12, sizeof(src));
    memcpy(&dst, ip + 16, sizeof(dst));

    uint32_t bytes_on_iface = h->len;
    int accounted = 0;

    if (cfg_ip_is_local(cfg, src)) {
        ipacct_update_tx(cfg->iface, src, bytes_on_iface);
        accounted = 1;
    }
    if (cfg_ip_is_local(cfg, dst)) {
        ipacct_update_rx(cfg->iface, dst, bytes_on_iface);
        accounted = 1;
    }

    if (accounted) {
        g_stats.local_packets++;
        g_stats.accounted_bytes += bytes_on_iface;
    }
}

int pcap_start_for_iface_threaded(struct cfg *cfg) {
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));
    memset(&g_stats, 0, sizeof(g_stats));
    g_cfg = cfg;

    g_handle = pcap_create(cfg->iface, errbuf);
    if (!g_handle) {
        fprintf(stderr, "[pcap] pcap_create(%s) failed: %s\n", cfg->iface, errbuf);
        return -1;
    }

    int buffer_bytes = cfg->pcap_buffer_mb * 1024 * 1024;
    pcap_set_snaplen(g_handle, 65535);
    pcap_set_promisc(g_handle, 0);
    pcap_set_timeout(g_handle, 1000);
    pcap_set_buffer_size(g_handle, buffer_bytes);
#ifdef PCAP_ERROR_ACTIVATED
    pcap_set_immediate_mode(g_handle, 0);
#endif

    int rc = pcap_activate(g_handle);
    if (rc < 0) {
        fprintf(stderr, "[pcap] activate failed on %s: %s\n", cfg->iface, pcap_geterr(g_handle));
        pcap_close(g_handle);
        g_handle = NULL;
        return -1;
    }
    if (rc > 0) fprintf(stderr, "[pcap] activate warning on %s: %s\n", cfg->iface, pcap_statustostr(rc));

    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, "ip", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "[pcap] compile failed: %s\n", pcap_geterr(g_handle));
        pcap_close(g_handle);
        g_handle = NULL;
        return -1;
    }
    if (pcap_setfilter(g_handle, &fp) == -1) {
        fprintf(stderr, "[pcap] setfilter failed: %s\n", pcap_geterr(g_handle));
        pcap_freecode(&fp);
        pcap_close(g_handle);
        g_handle = NULL;
        return -1;
    }
    pcap_freecode(&fp);

    fprintf(stderr, "[pcap] capturing IPv4 on %s with %d MB buffer\n", cfg->iface, cfg->pcap_buffer_mb);

    while (netacct_running) {
        rc = pcap_dispatch(g_handle, 128, packet_handler, (u_char *)g_cfg);
        if (rc == PCAP_ERROR_BREAK) break;
        if (rc == PCAP_ERROR) {
            fprintf(stderr, "[pcap] dispatch error: %s\n", pcap_geterr(g_handle));
            break;
        }
    }

    struct pcap_stat ps;
    if (pcap_stats(g_handle, &ps) == 0) {
        g_stats.pcap_recv = ps.ps_recv;
        g_stats.pcap_drop = ps.ps_drop;
        g_stats.pcap_ifdrop = ps.ps_ifdrop;
    }

    pcap_close(g_handle);
    g_handle = NULL;
    return 0;
}
