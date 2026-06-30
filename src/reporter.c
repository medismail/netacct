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

struct record_header {
    uint32_t ts;
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
};

struct row {
    uint32_t ip;
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

static unsigned ip_hash(uint32_t ip) {
    return (ip ^ (ip >> 16)) % HASH_SIZE;
}

static struct ip_total *get_total(struct report_ctx *ctx, uint32_t ip) {
    unsigned h = ip_hash(ip);
    for (struct ip_total *e = ctx->totals[h]; e; e = e->next) {
        if (e->ip == ip) return e;
    }
    struct ip_total *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->ip = ip;
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
            struct ip_entry_on_disk rec;
            if (data_read(fh, is_gzip, &rec, sizeof(rec)) != sizeof(rec)) {
                data_close(fh, is_gzip);
                return -1;
            }
            if (rec.ipv != 4) continue;
            struct ip_total *t = get_total(ctx, rec.addr);
            if (!t) { data_close(fh, is_gzip); return -1; }
            t->rx += rec.rx_delta;
            t->tx += rec.tx_delta;
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
            rows[n].ip = e->ip;
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

static void print_text(struct report_ctx *ctx, const struct report_opts *o, const char *label) {
    size_t n = 0;
    uint64_t ip_rx = 0, ip_tx = 0;
    struct row *rows = collect_rows(ctx, &n, &ip_rx, &ip_tx);
    if (!rows) return;
    uint64_t kernel_total = ctx->kernel_rx_total + ctx->kernel_tx_total;
    uint64_t ip_total = ip_rx + ip_tx;
    size_t limit = (o->top_n > 0 && (size_t)o->top_n < n) ? (size_t)o->top_n : n;
    printf("=== netacct %s iface=%s ===\n", label, o->iface);
    printf("%-15s %14s %14s %14s %9s\n", "IP", "RX bytes", "TX bytes", "Total bytes", "%kernel");
    for (size_t i = 0; i < limit; i++) {
        struct in_addr a = { .s_addr = rows[i].ip };
        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
        uint64_t total = rows[i].rx + rows[i].tx;
        printf("%-15s %14llu %14llu %14llu %8.2f%%\n", ipbuf,
               (unsigned long long)rows[i].rx,
               (unsigned long long)rows[i].tx,
               (unsigned long long)total,
               pct(total, kernel_total));
    }
    if (limit < n) printf("... %zu more IPs hidden by --top %d\n", n - limit, o->top_n);
    printf("%-15s %14llu %14llu %14llu %8.2f%%\n", "ALL(per-IP)",
           (unsigned long long)ip_rx, (unsigned long long)ip_tx,
           (unsigned long long)ip_total, pct(ip_total, kernel_total));
    printf("%-15s %14llu %14llu %14llu %8.2f%%\n", "KERNEL",
           (unsigned long long)ctx->kernel_rx_total,
           (unsigned long long)ctx->kernel_tx_total,
           (unsigned long long)kernel_total, 100.0);
    if (kernel_total >= ip_total) {
        printf("coverage_gap_bytes=%llu coverage_gap_percent=%.4f%%\n",
               (unsigned long long)(kernel_total - ip_total), pct(kernel_total - ip_total, kernel_total));
    } else {
        printf("over_account_bytes=%llu over_account_percent=%.4f%%\n",
               (unsigned long long)(ip_total - kernel_total), pct(ip_total - kernel_total, kernel_total));
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
    printf("label,type,ip,rx_bytes,tx_bytes,total_bytes,pct_kernel\n");
    for (size_t i = 0; i < limit; i++) {
        struct in_addr a = { .s_addr = rows[i].ip };
        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
        uint64_t total = rows[i].rx + rows[i].tx;
        printf("%s,ip,%s,%llu,%llu,%llu,%.4f\n", label, ipbuf,
               (unsigned long long)rows[i].rx, (unsigned long long)rows[i].tx,
               (unsigned long long)total, pct(total, kernel_total));
    }
    printf("%s,all_per_ip,,%llu,%llu,%llu,%.4f\n", label,
           (unsigned long long)ip_rx, (unsigned long long)ip_tx,
           (unsigned long long)(ip_rx + ip_tx), pct(ip_rx + ip_tx, kernel_total));
    printf("%s,kernel,,%llu,%llu,%llu,100.0000\n", label,
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
        struct in_addr a = { .s_addr = rows[i].ip };
        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
        uint64_t total = rows[i].rx + rows[i].tx;
        printf("    {\"ip\": \"%s\", \"rx_bytes\": %llu, \"tx_bytes\": %llu, \"total_bytes\": %llu, \"pct_kernel\": %.6f}%s\n",
               ipbuf, (unsigned long long)rows[i].rx, (unsigned long long)rows[i].tx,
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
            "  netacct report --iface IFACE [--root DIR] (--day YYYY-MM-DD | --month YYYY-MM) [--format text|csv|json] [--top N]\n"
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
    return o.day[0] ? report_day(&o) : report_month(&o);
}
