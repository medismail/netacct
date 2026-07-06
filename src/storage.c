#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <zlib.h>

#include "netacct.h"

static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    return mkdir(path, 0755);
}

static void make_date(char *out, size_t n, time_t ts) {
    struct tm gm;
    gmtime_r(&ts, &gm);
    strftime(out, n, "%Y-%m-%d", &gm);
}

static int compress_old_file(const char *daily_dir, uint32_t ts) {
    char yesterday[32];
    time_t yts = (time_t)ts - 86400;
    make_date(yesterday, sizeof(yesterday), yts);
    char src[1024], dst[1024];
    snprintf(src, sizeof(src), "%s/%s.bin", daily_dir, yesterday);
    snprintf(dst, sizeof(dst), "%s/%s.bin.gz", daily_dir, yesterday);
    if (access(src, F_OK) != 0 || access(dst, F_OK) == 0) return 0;

    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    gzFile out = gzopen(dst, "wb6");
    if (!out) { fclose(in); return -1; }
    char buf[8192];
    size_t n;
    int rc = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (gzwrite(out, buf, (unsigned)n) != (int)n) { rc = -1; break; }
    }
    fclose(in);
    if (gzclose(out) != Z_OK) rc = -1;
    if (rc == 0) {
        unlink(src);
        fprintf(stderr, "[storage] compressed %s -> %s\n", src, dst);
    } else {
        unlink(dst);
    }
    return rc;
}

static int copy_fd(int from, int to) {
    char buf[8192];
    for (;;) {
        ssize_t r = read(from, buf, sizeof(buf));
        if (r == 0) return 0;
        if (r < 0) return -1;
        char *p = buf;
        ssize_t left = r;
        while (left > 0) {
            ssize_t w = write(to, p, (size_t)left);
            if (w <= 0) return -1;
            p += w;
            left -= w;
        }
    }
}

static int write_record_entry(int fd, const struct ip_record *rec) {
    if (rec->addr.ipv == NETACCT_IPV4) {
        struct ip_entry_v4_on_disk e;
        memset(&e, 0, sizeof(e));
        e.ipv = NETACCT_IPV4;
        memcpy(&e.addr, rec->addr.bytes, sizeof(e.addr));
        e.rx_delta = rec->rx;
        e.tx_delta = rec->tx;
        return write(fd, &e, sizeof(e)) == (ssize_t)sizeof(e) ? 0 : -1;
    }
    if (rec->addr.ipv == NETACCT_IPV6) {
        struct ip_entry_v6_on_disk e;
        memset(&e, 0, sizeof(e));
        e.ipv = NETACCT_IPV6;
        memcpy(e.addr, rec->addr.bytes, NETACCT_ADDR_BYTES);
        e.rx_delta = rec->rx;
        e.tx_delta = rec->tx;
        return write(fd, &e, sizeof(e)) == (ssize_t)sizeof(e) ? 0 : -1;
    }
    return -1;
}

int storage_append_daily(const char *root_dir, const char *iface,
                         uint32_t ts, uint64_t rx_delta, uint64_t tx_delta,
                         uint16_t ip_count, const void *ip_entries_void, size_t ip_entries_len) {
    (void)ip_entries_len;
    char daily_dir[512];
    char date[32];
    make_date(date, sizeof(date), (time_t)ts);
    snprintf(daily_dir, sizeof(daily_dir), "%s/%s/daily", root_dir, iface);
    if (ensure_dir(daily_dir) != 0) { perror("ensure_dir"); return -1; }
    compress_old_file(daily_dir, ts);

    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/%s.bin", daily_dir, date);
    char tmpfile[1024];
    snprintf(tmpfile, sizeof(tmpfile), "%s/.journal.%s.%u.tmp", daily_dir, iface, ts);

    int tfd = open(tmpfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (tfd < 0) return -1;
    if (write(tfd, &ts, sizeof(ts)) != (ssize_t)sizeof(ts)) { close(tfd); unlink(tmpfile); return -1; }
    if (write(tfd, &rx_delta, sizeof(rx_delta)) != (ssize_t)sizeof(rx_delta)) { close(tfd); unlink(tmpfile); return -1; }
    if (write(tfd, &tx_delta, sizeof(tx_delta)) != (ssize_t)sizeof(tx_delta)) { close(tfd); unlink(tmpfile); return -1; }
    if (write(tfd, &ip_count, sizeof(ip_count)) != (ssize_t)sizeof(ip_count)) { close(tfd); unlink(tmpfile); return -1; }

    const struct ip_record *ip_entries = (const struct ip_record *)ip_entries_void;
    for (uint16_t i = 0; i < ip_count; ++i) {
        if (write_record_entry(tfd, &ip_entries[i]) != 0) { close(tfd); unlink(tmpfile); return -1; }
    }

    if (fsync(tfd) != 0) { close(tfd); unlink(tmpfile); return -1; }
    close(tfd);

    int fd = open(filepath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) { unlink(tmpfile); return -1; }
    int tf = open(tmpfile, O_RDONLY);
    if (tf < 0) { close(fd); unlink(tmpfile); return -1; }
    int rc = copy_fd(tf, fd);
    if (rc == 0 && fsync(fd) != 0) rc = -1;
    close(tf);
    close(fd);
    unlink(tmpfile);
    return rc;
}
