#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

#include "netacct.h"

// binary record layout (little-endian assumed):
// header:
//   uint32_t ts; // epoch seconds
//   uint64_t total_rx_delta;
//   uint64_t total_tx_delta;
//   uint16_t ip_count;
// followed by ip entries (repeated ip_count times):
//   uint8_t ipv; (value 4)
//   uint8_t pad;
//   uint32_t addr; // network order
//   uint64_t rx_delta;
//   uint64_t tx_delta;

int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return 0;
    if (mkdir(path, 0755) == 0) return 0;
    // try recursive
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp+1; *p; ++p) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    return mkdir(path, 0755);
}

static void make_date(char *out, size_t n, time_t ts) {
    struct tm gm;
    gmtime_r(&ts, &gm); // use UTC for file partitioning
    strftime(out, n, "%Y-%m-%d", &gm);
}

int storage_append_daily(const char *root_dir, const char *iface,
                         uint32_t ts, uint64_t rx_delta, uint64_t tx_delta,
                         uint16_t ip_count, const void *ip_entries_void, size_t ip_entries_len)
{
    char daily_dir[512];
    char date[32];
    make_date(date, sizeof(date), ts);
    snprintf(daily_dir, sizeof(daily_dir), "%s/%s/daily", root_dir, iface);
    ensure_dir(daily_dir);

    // target file path
    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/%s.bin", daily_dir, date);

    // write record to a temporary journal file
    char tmpfile[1024];
    snprintf(tmpfile, sizeof(tmpfile), "%s/.journal.%s.%u.tmp", daily_dir, iface, ts);

    int tfd = open(tmpfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (tfd < 0) return -1;

    // prepare header
    if (write(tfd, &ts, sizeof(ts)) != sizeof(ts)) { close(tfd); unlink(tmpfile); return -1; }
    if (write(tfd, &rx_delta, sizeof(rx_delta)) != sizeof(rx_delta)) { close(tfd); unlink(tmpfile); return -1; }
    if (write(tfd, &tx_delta, sizeof(tx_delta)) != sizeof(tx_delta)) { close(tfd); unlink(tmpfile); return -1; }
    if (write(tfd, &ip_count, sizeof(ip_count)) != sizeof(ip_count)) { close(tfd); unlink(tmpfile); return -1; }

    // write ip entries (we transform to on-disk structure)
    const struct ip_record *ip_entries = (const struct ip_record*)ip_entries_void;
    for (int i = 0; i < ip_count; ++i) {
        struct ip_entry_on_disk e;
        e.ipv = 4;
        e.pad = 0;
        e.addr = ip_entries[i].ip; // network order already
        e.rx_delta = ip_entries[i].rx;
        e.tx_delta = ip_entries[i].tx;
        if (write(tfd, &e, sizeof(e)) != sizeof(e)) { close(tfd); unlink(tmpfile); return -1; }
    }

    fsync(tfd); close(tfd);

    // now append tmpfile to final daily file atomically
    int fd = open(filepath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) { unlink(tmpfile); return -1; }

    int tf = open(tmpfile, O_RDONLY);
    if (tf < 0) { close(fd); unlink(tmpfile); return -1; }

    char buf[8192];
    ssize_t r;
    while ((r = read(tf, buf, sizeof(buf))) > 0) {
        ssize_t w = write(fd, buf, r);
        if (w != r) { close(tf); close(fd); unlink(tmpfile); return -1; }
    }
    fsync(fd);
    close(tf);
    close(fd);
    unlink(tmpfile);
    return 0;
}
