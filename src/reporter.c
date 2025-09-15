// reader.c - daily / monthly network usage report

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "netacct.h"

#define HASH_SIZE 256

struct record_header {
    uint32_t ts;          // epoch seconds
    uint64_t total_rx;
    uint64_t total_tx;
    uint16_t ip_count;
} __attribute__((packed));

struct ip_total {
    uint32_t ip;
    uint64_t rx;
    uint64_t tx;
    struct ip_total *next;
};

static struct ip_total *totals[HASH_SIZE];
static uint64_t kernel_rx_total = 0;
static uint64_t kernel_tx_total = 0;

static struct ip_total *get_total(uint32_t ip) {
    unsigned h = ip % HASH_SIZE;
    for (struct ip_total *e = totals[h]; e; e = e->next) {
        if (e->ip == ip) return e;
    }
    struct ip_total *e = calloc(1, sizeof(*e));
    e->ip = ip;
    e->next = totals[h];
    totals[h] = e;
    return e;
}

static void clear_totals() {
    for (int i = 0; i < HASH_SIZE; i++) {
        struct ip_total *e = totals[i];
        while (e) {
            struct ip_total *n = e->next;
            free(e);
            e = n;
        }
        totals[i] = NULL;
    }
}

static void *open_daily_file(const char *path, int *is_gzip) {
    FILE *f = fopen(path, "rb");
    if (f) {
        *is_gzip = 0;
        return f;
    }
    char gzpath[1024];
    snprintf(gzpath, sizeof(gzpath), "%s.gz", path);
    gzFile gzf = gzopen(gzpath, "rb");
    if (gzf) {
        *is_gzip = 1;
        return gzf;
    }
    return NULL;
}

static size_t daily_read(void *fh, int is_gzip, void *buf, size_t len) {
    if (is_gzip) {
        int n = gzread((gzFile)fh, buf, (unsigned)len);
        return (n < 0) ? 0 : (size_t)n;
    } else {
        return fread(buf, 1, len, (FILE*)fh);
    }
}

static void daily_close(void *fh, int is_gzip) {
    if (is_gzip) gzclose((gzFile)fh);
    else fclose((FILE*)fh);
}

static void process_file(const char *path) {
    int is_gzip = 0;
    void *fh = open_daily_file(path, &is_gzip);
    if (!fh) return;

    struct record_header h;
    while (daily_read(fh, is_gzip, &h, sizeof(h)) == sizeof(h)) {
        kernel_rx_total += h.total_rx;
        kernel_tx_total += h.total_tx;

        for (int i = 0; i < h.ip_count; i++) {
            struct ip_entry_on_disk rec;
            if (daily_read(fh, is_gzip, &rec, sizeof(rec)) != sizeof(rec)) break;
            if (rec.ipv == 4) {
                struct ip_total *t = get_total(rec.addr);
                t->rx += rec.rx_delta;
                t->tx += rec.tx_delta;
            }
        }
    }

    daily_close(fh, is_gzip);
}

static void print_totals(const char *label) {
    uint64_t grand_rx = 0, grand_tx = 0;

    for (int i = 0; i < HASH_SIZE; i++) {
        for (struct ip_total *e = totals[i]; e; e = e->next) {
            grand_rx += e->rx;
            grand_tx += e->tx;
        }
    }

    double kernel_mb = (double)(kernel_rx_total + kernel_tx_total) / (1024.0*1024.0);

    printf("=== %s ===\n", label);
    for (int i = 0; i < HASH_SIZE; i++) {
        for (struct ip_total *e = totals[i]; e; e = e->next) {
            struct in_addr a = { .s_addr = e->ip };
            double mb = (double)(e->rx + e->tx) / (1024.0*1024.0);
            double pct = kernel_mb > 0 ? (mb / kernel_mb) * 100.0 : 0.0;

            printf("  %-15s  RX: %.2f MB  TX: %.2f MB  Total: %.2f MB (%.1f%%)\n",
                   inet_ntoa(a),
                   (double)e->rx / (1024.0*1024.0),
                   (double)e->tx / (1024.0*1024.0),
                   mb, pct);
        }
    }
    double grand_mb = (double)(grand_rx+grand_tx) / (1024.0*1024.0);
    double pct = kernel_mb > 0 ? ( grand_mb/ kernel_mb) * 100.0 : 0.0;
    printf("  %-15s  RX: %.2f MB  TX: %.2f MB  Total: %.2f MB (%.1f%%)\n",
           "ALL (per-IP)",
           (double)grand_rx / (1024.0*1024.0),
           (double)grand_tx / (1024.0*1024.0),
           (double)(grand_rx+grand_tx)/(1024.0*1024.0), pct);
    printf("  %-15s  RX: %.2f MB  TX: %.2f MB  Total: %.2f MB (100%% kernel)\n",
           "KERNEL",
           (double)kernel_rx_total / (1024.0*1024.0),
           (double)kernel_tx_total / (1024.0*1024.0),
           kernel_mb);
}

static int is_datafile(const char *name) {
    return (strstr(name, ".bin") || strstr(name, ".bin.gz"));
}

static void daily_report(const char *dirpath) {
    DIR *d = opendir(dirpath);
    if (!d) {
        perror("opendir");
        return;
    }

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!is_datafile(de->d_name)) continue;

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dirpath, de->d_name);

        // reset totals for each file/day
        clear_totals();
        process_file(path);

        // label by filename prefix (YYYYMMDD)
        char day[257] = {0};
        strncpy(day, de->d_name, 256);
        print_totals(day);
    }
    closedir(d);
}

static void monthly_report(const char *dirpath) {
    DIR *d = opendir(dirpath);
    if (!d) {
        perror("opendir");
        return;
    }

    clear_totals();

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!is_datafile(de->d_name)) continue;

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dirpath, de->d_name);
        process_file(path);
    }
    closedir(d);

    print_totals("Monthly");
}

int reporter_run(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <directory> <daily|monthly>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[2], "daily") == 0) {
        daily_report(argv[1]);
    } else if (strcmp(argv[2], "monthly") == 0) {
        monthly_report(argv[1]);
    } else {
        fprintf(stderr, "Unknown report type: %s\n", argv[2]);
        return 1;
    }

    return 0;
}

