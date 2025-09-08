// reader.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <inttypes.h>
#include <netinet/in.h>

#include "netacct.h"

/*struct ip_entry_on_disk {
    uint8_t  ipv;
    uint8_t  pad;
    uint32_t addr;      // network byte order
    uint64_t rx_delta;
    uint64_t tx_delta;
} __attribute__((packed));*/

#define MAX_IPS 512

int reporter_run(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <dailyfile.bin>\n", argv[0]);
        return 2;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    struct ip_record totals[MAX_IPS];
    int n_totals = 0;

    uint64_t kernel_total_rx = 0;
    uint64_t kernel_total_tx = 0;

    while (1) {
        uint32_t ts;
        uint64_t total_rx_delta;
        uint64_t total_tx_delta;
        uint16_t ip_count;

        /* Read header fields individually to avoid struct padding issues */
        if (fread(&ts, sizeof(ts), 1, f) != 1) break;
        if (fread(&total_rx_delta, sizeof(total_rx_delta), 1, f) != 1) {
            fprintf(stderr, "Unexpected EOF reading total_rx\n"); fclose(f); return 1;
        }
        if (fread(&total_tx_delta, sizeof(total_tx_delta), 1, f) != 1) {
            fprintf(stderr, "Unexpected EOF reading total_tx\n"); fclose(f); return 1;
        }
        if (fread(&ip_count, sizeof(ip_count), 1, f) != 1) {
            fprintf(stderr, "Unexpected EOF reading ip_count\n"); fclose(f); return 1;
        }

        kernel_total_rx += total_rx_delta;
        kernel_total_tx += total_tx_delta;

        for (uint16_t i = 0; i < ip_count; ++i) {
            struct ip_entry_on_disk e;
            if (fread(&e, sizeof(e), 1, f) != 1) {
                fprintf(stderr, "Unexpected EOF reading ip_entry\n");
                fclose(f);
                return 1;
            }
            if (e.ipv != 4) continue; // skip non-IPv4 entries (future-proof)

            /* Try to find existing entry */
            int found = -1;
            for (int j = 0; j < n_totals; ++j) {
                if (totals[j].ip == e.addr) { found = j; break; }
            }
            if (found == -1) {
                if (n_totals >= MAX_IPS) {
                    fprintf(stderr, "Too many unique IPs (> %d)\n", MAX_IPS);
                    fclose(f);
                    return 1;
                }
                totals[n_totals].ip = e.addr;
                totals[n_totals].rx = e.rx_delta;
                totals[n_totals].tx = e.tx_delta;
                n_totals++;
            } else {
                totals[found].rx += e.rx_delta;
                totals[found].tx += e.tx_delta;
            }
        }
    }

    fclose(f);

    /* Print results */
    printf("%-15s %-15s %-15s %-15s\n",
           "IP Address", "RX Bytes", "TX Bytes", "Total");
    uint64_t sum_ips_rx = 0, sum_ips_tx = 0;
    for (int i = 0; i < n_totals; ++i) {
        struct in_addr a; a.s_addr = totals[i].ip;
        char ipbuf[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf))) strncpy(ipbuf, "???", sizeof(ipbuf));
        uint64_t total = totals[i].rx + totals[i].tx;
        printf("%-15s %-15" PRIu64 " %-15" PRIu64 " %-15" PRIu64 "\n",
               ipbuf, totals[i].rx, totals[i].tx, total);
        sum_ips_rx += totals[i].rx;
        sum_ips_tx += totals[i].tx;
    }

    printf("\nKernel totals (accumulated from header fields):\n");
    printf("  RX: %" PRIu64 "  TX: %" PRIu64 "\n", kernel_total_rx, kernel_total_tx);
    printf("Sum of per-IP deltas: RX: %" PRIu64 "  TX: %" PRIu64 "\n", sum_ips_rx, sum_ips_tx);

    if (kernel_total_rx > 0) {
        double pct_rx = 100.0 * (double)(kernel_total_rx - sum_ips_rx) / (double)kernel_total_rx;
        printf("Unattributed RX = %" PRIu64 " (%.4f%% of kernel RX)\n",
               (kernel_total_rx > sum_ips_rx) ? (kernel_total_rx - sum_ips_rx) : 0UL, pct_rx);
    }
    if (kernel_total_tx > 0) {
        double pct_tx = 100.0 * (double)(kernel_total_tx - sum_ips_tx) / (double)kernel_total_tx;
        printf("Unattributed TX = %" PRIu64 " (%.4f%% of kernel TX)\n",
               (kernel_total_tx > sum_ips_tx) ? (kernel_total_tx - sum_ips_tx) : 0UL, pct_tx);
    }

    return 0;
}

