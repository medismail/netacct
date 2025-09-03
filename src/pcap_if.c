#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include "netacct.h"

extern int ipacct_update_rx(const char *iface, uint32_t ip, uint32_t bytes);
extern int ipacct_update_tx(const char *iface, uint32_t ip, uint32_t bytes);

static const char *g_iface = NULL;
static pcap_t *pcap_handle = NULL;

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    if (h->caplen < sizeof(struct ether_header)) return;

    const struct ether_header *eth = (const struct ether_header*)bytes;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return; // IPv4 only for MVP

    const struct ip *iph = (const struct ip*)(bytes + sizeof(struct ether_header));
    // ensure ip header length fits
    if ((const u_char*)iph + sizeof(struct ip) > bytes + h->caplen) return;

    uint32_t src = iph->ip_src.s_addr;
    uint32_t dst = iph->ip_dst.s_addr;
    uint32_t len = ntohs(iph->ip_len);

    // Update tx/rx for local IPs if present
    ipacct_update_tx(g_iface, src, len);
    ipacct_update_rx(g_iface, dst, len);
}

int pcap_start_for_iface_threaded(const char *iface) {
    g_iface = iface;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(iface, 65536, 0, 1000, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", iface, errbuf);
        return -1;
    }
    struct bpf_program fp;
    if (pcap_compile(pcap_handle, &fp, "ip", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile failed\n");
        pcap_close(pcap_handle);
        return -1;
    }
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed\n");
        pcap_freecode(&fp);
        pcap_close(pcap_handle);
        return -1;
    }
    pcap_freecode(&fp);

    // blocking loop; should run in its own thread
    pcap_loop(pcap_handle, 0, packet_handler, NULL);
    return 0;
}

