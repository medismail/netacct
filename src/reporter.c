#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <sys/stat.h>

#include "netacct.h"

#define HASH_SIZE 1024
#define IP_COL_WIDTH 45

struct record_header {
    uint32_t ts;
    uint64_t total_rx;
    uint64_t total_tx;
    uint16_t ip_count;
} __attribute__((packed));

struct ip_total {
    struct netacct_addr addr;
    uint64_t rx;
    uint64_t tx;
    struct ip_total *next;
};

struct report_ctx {
    struct ip_total *totals[HASH_SIZE];
    uint64_t kernel_rx_total;
    uint64_t kernel_tx_total;
};

struct report_opts {
    char root_dir[MAX_ROOT_DIR];
    char iface[MAX_IFACE_NAME];
    char day[16];
    char month[16];
    char format[16];
    int top_n;
    int human;
};

struct row {
    struct netacct_addr addr;
    uint64_t rx;
    uint64_t tx;
};

static void report_opts_defaults(struct report_opts *o) {
    memset(o, 0, sizeof(*o));
    snprintf(o->root_dir, sizeof(o->root_dir), "%s", NETACCT_DEFAULT_ROOT);
    snprintf(o->iface, sizeof(o->iface), "%s", NETACCT_DEFAULT_IFACE);
    snprintf(o->format, sizeof(o->format), "text");
    o->top_n = NETACCT_DEFAULT_TOP_N;
}

static unsigned addr_hash(const struct netacct_addr *addr) {
    uint32_t h = 2166136261u;
    h ^= addr->ipv;
    h *= 16777619u;
    size_t len = (addr->ipv == NETACCT_IPV4) ? 4 : NETACCT_ADDR_BYTES;
    for (size_t i = 0; i < len; i++) {
        h ^= addr->bytes[i];
        h *= 16777619u;
    }
    return h % HASH_SIZE;
}

static int addr_equal(const struct netacct_addr *a, const struct netacct_addr *b) {
    if (a->ipv != b->ipv) return 0;
    size_t len = (a->ipv == NETACCT_IPV4) ? 4 : NETACCT_ADDR_BYTES;
    return memcmp(a->bytes, b->bytes, len) == 0;
}

static struct ip_total *get_total(struct report_ctx *ctx, const struct netacct_addr *addr) {
    unsigned h = addr_hash(addr);
    for (struct ip_total *e = ctx->totals[h]; e; e = e->next) {
        if (addr_equal(&e->addr, addr)) return e;
    }
    struct ip_total *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->addr = *addr;
    e->next = ctx->totals[h];
    ctx->totals[h] = e;
    return e;
}

static void clear_ctx(struct report_ctx *ctx) {
    for (int i = 0; i < HASH_SIZE; i++) {
        struct ip_total *e = ctx->totals[i];
        while (e) {
            struct ip_total *n = e->next;
            free(e);
            e = n;
        }
        ctx->totals[i] = NULL;
    }
    ctx->kernel_rx_total = 0;
    ctx->kernel_tx_total = 0;
}

static int has_suffix(const char *s, const char *suffix) {
    size_t sl = strlen(s), sul = strlen(suffix);
    return sl >= sul && strcmp(s + sl - sul, suffix) == 0;
}

static int is_datafile(const char *name) {
    return has_suffix(name, ".bin") || has_suffix(name, ".bin.gz");
}

static void *open_data_file(const char *path, int *is_gzip) {
    if (has_suffix(path, ".gz")) {
        gzFile gzf = gzopen(path, "rb");
        if (gzf) { *is_gzip = 1; return gzf; }
        return NULL;
    }
    FILE *f = fopen(path, "rb");
    if (f) { *is_gzip = 0; return f; }
    char gzpath[1024];
    snprintf(gzpath, sizeof(gzpath), "%s.gz", path);
    gzFile gzf = gzopen(gzpath, "rb");
    if (gzf) { *is_gzip = 1; return gzf; }
    return NULL;
}

static size_t data_read(void *fh, int is_gzip, void *buf, size_t len) {
    if (is_gzip) {
        int n = gzread((gzFile)fh, buf, (unsigned)len);
        return n < 0 ? 0 : (size_t)n;
    }
    return fread(buf, 1, len, (FILE *)fh);
}

static void data_close(void *fh, int is_gzip) {
    if (is_gzip) gzclose((gzFile)fh);
    else fclose((FILE *)fh);
}

static int read_entry(void *fh, int is_gzip, struct netacct_addr *addr, uint64_t *rx, uint64_t *tx) {
    uint8_t prefix[2];
    if (data_read(fh, is_gzip, prefix, sizeof(prefix)) != sizeof(prefix)) return -1;
    memset(addr, 0, sizeof(*addr));
    addr->ipv = prefix[0];

    if (addr->ipv == NETACCT_IPV4) {
        uint32_t ipv4;
        if (data_read(fh, is_gzip, &ipv4, sizeof(ipv4)) != sizeof(ipv4)) return -1;
        memcpy(addr->bytes, &ipv4, sizeof(ipv4));
    } else if (addr->ipv == NETACCT_IPV6) {
        if (data_read(fh, is_gzip, addr->bytes, NETACCT_ADDR_BYTES) != NETACCT_ADDR_BYTES) return -1;
    } else {
        return -1;
    }

    if (data_read(fh, is_gzip, rx, sizeof(*rx)) != sizeof(*rx)) return -1;
    if (data_read(fh, is_gzip, tx, sizeof(*tx)) != sizeof(*tx)) return -1;
    return 0;
}

static int process_file(struct report_ctx *ctx, const char *path) {
    int is_gzip = 0;
    void *fh = open_data_file(path, &is_gzip);
    if (!fh) return -1;
    struct record_header h;
    while (data_read(fh, is_gzip, &h, sizeof(h)) == sizeof(h)) {
        ctx->kernel_rx_total += h.total_rx;
        ctx->kernel_tx_total += h.total_tx;
        if (h.ip_count > MAX_IP_ENTRIES) {
            fprintf(stderr, "[report] invalid ip_count=%u in %s\n", h.ip_count, path);
            data_close(fh, is_gzip);
            return -1;
        }
        for (uint16_t i = 0; i < h.ip_count; i++) {
            struct netacct_addr addr;
            uint64_t rx = 0, tx = 0;
            if (read_entry(fh, is_gzip, &addr, &rx, &tx) != 0) {
                data_close(fh, is_gzip);
                return -1;
            }
            struct ip_total *t = get_total(ctx, &addr);
            if (!t) { data_close(fh, is_gzip); return -1; }
            t->rx += rx;
            t->tx += tx;
        }
    }
    data_close(fh, is_gzip);
    return 0;
}

static int cmp_row_total_desc(const void *a, const void *b) {
    const struct row *ra = (const struct row *)a;
    const struct row *rb = (const struct row *)b;
    uint64_t ta = ra->rx + ra->tx;
    uint64_t tb = rb->rx + rb->tx;
    if (ta < tb) return 1;
    if (ta > tb) return -1;
    return 0;
}

static struct row *collect_rows(struct report_ctx *ctx, size_t *out_count,
                                uint64_t *out_ip_rx, uint64_t *out_ip_tx) {
    size_t cap = 64, n = 0;
    struct row *rows = calloc(cap, sizeof(*rows));
    if (!rows) return NULL;
    uint64_t ip_rx = 0, ip_tx = 0;
    for (int i = 0; i < HASH_SIZE; i++) {
        for (struct ip_total *e = ctx->totals[i]; e; e = e->next) {
            if (n == cap) {
                cap *= 2;
                struct row *nr = realloc(rows, cap * sizeof(*rows));
                if (!nr) { free(rows); return NULL; }
                rows = nr;
            }
            rows[n].addr = e->addr;
            rows[n].rx = e->rx;
            rows[n].tx = e->tx;
            ip_rx += e->rx;
            ip_tx += e->tx;
            n++;
        }
    }
    qsort(rows, n, sizeof(*rows), cmp_row_total_desc);
    *out_count = n;
    *out_ip_rx = ip_rx;
    *out_ip_tx = ip_tx;
    return rows;
}

static double pct(uint64_t part, uint64_t total) {
    return total ? ((double)part * 100.0 / (double)total) : 0.0;
}

static const char *format_bytes(uint64_t bytes, int human, char *buf, size_t len) {
    if (!human) {
        snprintf(buf, len, "%llu", (unsigned long long)bytes);
        return buf;
    }

    static const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB" };
    double value = (double)bytes;
    size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < sizeof(units) / sizeof(units[0])) {
        value /= 1024.0;
        unit++;
    }

    if (unit == 0) snprintf(buf, len, "%llu B", (unsigned long long)bytes);
    else if (value >= 100.0) snprintf(buf, len, "%.0f %s", value, units[unit]);
    else if (value >= 10.0) snprintf(buf, len, "%.1f %s", value, units[unit]);
    else snprintf(buf, len, "%.2f %s", value, units[unit]);
    return buf;
}

static void print_text(struct report_ctx *ctx, const struct report_opts *o, const char *label) {
    size_t n = 0;
    uint64_t ip_rx = 0, ip_tx = 0;
    struct row *rows = collect_rows(ctx, &n, &ip_rx, &ip_tx);
    if (!rows) return;
    uint64_t kernel_total = ctx->kernel_rx_total + ctx->kernel_tx_total;
    uint64_t ip_total = ip_rx + ip_tx;
    size_t limit = (o->top_n > 0 && (size_t)o->top_n < n) ? (size_t)o->top_n : n;
    const char *rx_label = o->human ? "RX" : "RX bytes";
    const char *tx_label = o->human ? "TX" : "TX bytes";
    const char *total_label = o->human ? "Total" : "Total bytes";
    printf("=== netacct %s iface=%s ===\n", label, o->iface);
    printf("%-*s %3s %14s %14s %14s %9s\n", IP_COL_WIDTH, "IP", "ver", rx_label, tx_label, total_label, "%kernel");
    for (size_t i = 0; i < limit; i++) {
        char ipbuf[INET6_ADDRSTRLEN];
        char rxbuf[32], txbuf[32], totalbuf[32];
        format_netacct_addr(&rows[i].addr, ipbuf, sizeof(ipbuf));
        uint64_t total = rows[i].rx + rows[i].tx;
        printf("%-*s %3u %14s %14s %14s %8.2f%%\n", IP_COL_WIDTH, ipbuf, rows[i].addr.ipv,
               format_bytes(rows[i].rx, o->human, rxbuf, sizeof(rxbuf)),
               format_bytes(rows[i].tx, o->human, txbuf, sizeof(txbuf)),
               format_bytes(total, o->human, totalbuf, sizeof(totalbuf)),
               pct(total, kernel_total));
    }
    if (limit < n) printf("... %zu more IPs hidden by --top %d\n", n - limit, o->top_n);
    char rxbuf[32], txbuf[32], totalbuf[32], gapbuf[32];
    printf("%-*s %3s %14s %14s %14s %8.2f%%\n", IP_COL_WIDTH, "ALL(per-IP)", "",
           format_bytes(ip_rx, o->human, rxbuf, sizeof(rxbuf)),
           format_bytes(ip_tx, o->human, txbuf, sizeof(txbuf)),
           format_bytes(ip_total, o->human, totalbuf, sizeof(totalbuf)),
           pct(ip_total, kernel_total));
    printf("%-*s %3s %14s %14s %14s %8.2f%%\n", IP_COL_WIDTH, "KERNEL", "",
           format_bytes(ctx->kernel_rx_total, o->human, rxbuf, sizeof(rxbuf)),
           format_bytes(ctx->kernel_tx_total, o->human, txbuf, sizeof(txbuf)),
           format_bytes(kernel_total, o->human, totalbuf, sizeof(totalbuf)),
           100.0);
    if (kernel_total >= ip_total) {
        uint64_t gap = kernel_total - ip_total;
        printf("coverage_gap=%s coverage_gap_bytes=%llu coverage_gap_percent=%.4f%%\n",
               format_bytes(gap, o->human, gapbuf, sizeof(gapbuf)),
               (unsigned long long)gap, pct(gap, kernel_total));
    } else {
        uint64_t over = ip_total - kernel_total;
        printf("over_account=%s over_account_bytes=%llu over_account_percent=%.4f%%\n",
               format_bytes(over, o->human, gapbuf, sizeof(gapbuf)),
               (unsigned long long)over, pct(over, kernel_total));
    }
    free(rows);
}

static void print_csv(struct report_ctx *ctx, const struct report_opts *o, const char *label) {
    size_t n = 0;
    uint64_t ip_rx = 0, ip_tx = 0;
    struct row *rows = collect_rows(ctx, &n, &ip_rx, &ip_tx);
    if (!rows) return;
    uint64_t kernel_total = ctx->kernel_rx_total + ctx->kernel_tx_total;
    size_t limit = (o->top_n > 0 && (size_t)o->top_n < n) ? (size_t)o->top_n : n;
    printf("label,type,ip_version,ip,rx_bytes,tx_bytes,total_bytes,pct_kernel\n");
    for (size_t i = 0; i < limit; i++) {
        char ipbuf[INET6_ADDRSTRLEN];
        format_netacct_addr(&rows[i].addr, ipbuf, sizeof(ipbuf));
        uint64_t total = rows[i].rx + rows[i].tx;
        printf("%s,ip,%u,%s,%llu,%llu,%llu,%.4f\n", label, rows[i].addr.ipv, ipbuf,
               (unsigned long long)rows[i].rx, (unsigned long long)rows[i].tx,
               (unsigned long long)total, pct(total, kernel_total));
    }
    printf("%s,all_per_ip,,,%llu,%llu,%llu,%.4f\n", label,
           (unsigned long long)ip_rx, (unsigned long long)ip_tx,
           (unsigned long long)(ip_rx + ip_tx), pct(ip_rx + ip_tx, kernel_total));
    printf("%s,kernel,,,%llu,%llu,%llu,100.0000\n", label,
           (unsigned long long)ctx->kernel_rx_total, (unsigned long long)ctx->kernel_tx_total,
           (unsigned long long)kernel_total);
    free(rows);
}

static void print_json(struct report_ctx *ctx, const struct report_opts *o, const char *label) {
    size_t n = 0;
    uint64_t ip_rx = 0, ip_tx = 0;
    struct row *rows = collect_rows(ctx, &n, &ip_rx, &ip_tx);
    if (!rows) return;
    uint64_t kernel_total = ctx->kernel_rx_total + ctx->kernel_tx_total;
    size_t limit = (o->top_n > 0 && (size_t)o->top_n < n) ? (size_t)o->top_n : n;
    printf("{\n");
    printf("  \"label\": \"%s\",\n", label);
    printf("  \"iface\": \"%s\",\n", o->iface);
    printf("  \"kernel\": {\"rx_bytes\": %llu, \"tx_bytes\": %llu, \"total_bytes\": %llu},\n",
           (unsigned long long)ctx->kernel_rx_total, (unsigned long long)ctx->kernel_tx_total,
           (unsigned long long)kernel_total);
    printf("  \"per_ip_total\": {\"rx_bytes\": %llu, \"tx_bytes\": %llu, \"total_bytes\": %llu, \"pct_kernel\": %.6f},\n",
           (unsigned long long)ip_rx, (unsigned long long)ip_tx,
           (unsigned long long)(ip_rx + ip_tx), pct(ip_rx + ip_tx, kernel_total));
    printf("  \"ips\": [\n");
    for (size_t i = 0; i < limit; i++) {
        char ipbuf[INET6_ADDRSTRLEN];
        format_netacct_addr(&rows[i].addr, ipbuf, sizeof(ipbuf));
        uint64_t total = rows[i].rx + rows[i].tx;
        printf("    {\"ip_version\": %u, \"ip\": \"%s\", \"rx_bytes\": %llu, \"tx_bytes\": %llu, \"total_bytes\": %llu, \"pct_kernel\": %.6f}%s\n",
               rows[i].addr.ipv, ipbuf, (unsigned long long)rows[i].rx, (unsigned long long)rows[i].tx,
               (unsigned long long)total, pct(total, kernel_total), (i + 1 < limit) ? "," : "");
    }
    printf("  ]\n}\n");
    free(rows);
}

static void print_report(struct report_ctx *ctx, const struct report_opts *o, const char *label) {
    if (strcmp(o->format, "csv") == 0) print_csv(ctx, o, label);
    else if (strcmp(o->format, "json") == 0) print_json(ctx, o, label);
    else print_text(ctx, o, label);
}

static int report_day(const struct report_opts *o) {
    struct report_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s/daily/%s.bin", o->root_dir, o->iface, o->day);
    if (process_file(&ctx, path) != 0) {
        fprintf(stderr, "[report] no readable data for %s\n", path);
        clear_ctx(&ctx);
        return 1;
    }
    print_report(&ctx, o, o->day);
    clear_ctx(&ctx);
    return 0;
}

static int report_month(const struct report_opts *o) {
    struct report_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    char dirpath[1024];
    snprintf(dirpath, sizeof(dirpath), "%s/%s/daily", o->root_dir, o->iface);
    DIR *d = opendir(dirpath);
    if (!d) { perror("opendir"); return 1; }
    int files = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!is_datafile(de->d_name)) continue;
        if (strncmp(de->d_name, o->month, 7) != 0) continue;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dirpath, de->d_name);
        if (process_file(&ctx, path) == 0) files++;
    }
    closedir(d);
    if (files == 0) {
        fprintf(stderr, "[report] no data files for month %s in %s\n", o->month, dirpath);
        clear_ctx(&ctx);
        return 1;
    }
    print_report(&ctx, o, o->month);
    clear_ctx(&ctx);
    return 0;
}

static int list_ifaces(const char *root) {
    DIR *d = opendir(root);
    if (!d) { perror("opendir"); return 1; }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s/daily", root, de->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) printf("%s\n", de->d_name);
    }
    closedir(d);
    return 0;
}

static void usage_report(void) {
    fprintf(stderr,
            "Usage:\n"
            "  netacct report --iface IFACE [--root DIR] (--day YYYY-MM-DD | --month YYYY-MM) [--format text|csv|json] [--top N] [--human]\n"
            "  netacct list-ifaces [--root DIR]\n");
}

int reporter_run(int argc, char **argv) {
    if (argc < 1) { usage_report(); return 1; }
    if (strcmp(argv[0], "list-ifaces") == 0) {
        const char *root = NETACCT_DEFAULT_ROOT;
        for (int i = 1; i < argc; i++) {
            if ((strcmp(argv[i], "--root") == 0 || strcmp(argv[i], "--root-dir") == 0) && i + 1 < argc) root = argv[++i];
        }
        return list_ifaces(root);
    }
    if (strcmp(argv[0], "report") != 0) { usage_report(); return 1; }

    struct report_opts o;
    report_opts_defaults(&o);
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--root") == 0 || strcmp(argv[i], "--root-dir") == 0) && i + 1 < argc) snprintf(o.root_dir, sizeof(o.root_dir), "%s", argv[++i]);
        else if ((strcmp(argv[i], "--iface") == 0 || strcmp(argv[i], "--interface") == 0) && i + 1 < argc) snprintf(o.iface, sizeof(o.iface), "%s", argv[++i]);
        else if (strcmp(argv[i], "--day") == 0 && i + 1 < argc) snprintf(o.day, sizeof(o.day), "%s", argv[++i]);
        else if (strcmp(argv[i], "--month") == 0 && i + 1 < argc) snprintf(o.month, sizeof(o.month), "%s", argv[++i]);
        else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) snprintf(o.format, sizeof(o.format), "%s", argv[++i]);
        else if (strcmp(argv[i], "--human") == 0) o.human = 1;
        else if (strcmp(argv[i], "--bytes") == 0) o.human = 0;
        else if (strcmp(argv[i], "--top") == 0 && i + 1 < argc) { o.top_n = atoi(argv[++i]); if (o.top_n <= 0) o.top_n = NETACCT_DEFAULT_TOP_N; }
        else { fprintf(stderr, "unknown or incomplete report option: %s\n", argv[i]); usage_report(); return 1; }
    }
    if ((o.day[0] == '\0') == (o.month[0] == '\0')) {
        fprintf(stderr, "choose exactly one of --day or --month\n");
        usage_report();
        return 1;
    }
    if (strcmp(o.format, "text") != 0 && strcmp(o.format, "csv") != 0 && strcmp(o.format, "json") != 0) {
        fprintf(stderr, "invalid format: %s\n", o.format);
        return 1;
    }
    if (o.human && strcmp(o.format, "text") != 0) {
        fprintf(stderr, "--human is only supported with --format text\n");
        return 1;
    }
    return o.day[0] ? report_day(&o) : report_month(&o);
}
