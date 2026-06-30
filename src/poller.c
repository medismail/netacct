#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/if.h>
#include <errno.h>

#include "netacct.h"

struct meta_persist {
    char boot_id[37];
    uint32_t ifindex;
    uint32_t reserved;
};

static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    return mkdir(path, 0755);
}

static int read_boot_id(char out[37]) {
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (!f) return -1;
    if (!fgets(out, 37, f)) { fclose(f); return -1; }
    fclose(f);
    out[36] = '\0';
    return 0;
}

static int read_u64_file(const char *path, uint64_t *out) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    unsigned long long v = 0;
    if (fscanf(f, "%llu", &v) != 1) { fclose(f); return -1; }
    fclose(f);
    *out = (uint64_t)v;
    return 0;
}

static int load_last_counts(const char *root_dir, const char *iface,
                            uint64_t *out_last_rx, uint64_t *out_last_tx) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s/.last_counts", root_dir, iface);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    int ok = fread(out_last_rx, sizeof(uint64_t), 1, f) == 1 && fread(out_last_tx, sizeof(uint64_t), 1, f) == 1;
    fclose(f);
    return ok ? 0 : -1;
}

static int save_last_counts_values(const char *root_dir, const char *iface,
                                   uint64_t last_rx, uint64_t last_tx) {
    char dir[512], tmp[768], path[768];
    snprintf(dir, sizeof(dir), "%s/%s", root_dir, iface);
    if (ensure_dir(dir) != 0) return -1;
    snprintf(tmp, sizeof(tmp), "%s/.last_counts.tmp.%d", dir, getpid());
    snprintf(path, sizeof(path), "%s/.last_counts", dir);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    if (write(fd, &last_rx, sizeof(last_rx)) != (ssize_t)sizeof(last_rx)) { close(fd); unlink(tmp); return -1; }
    if (write(fd, &last_tx, sizeof(last_tx)) != (ssize_t)sizeof(last_tx)) { close(fd); unlink(tmp); return -1; }
    if (fsync(fd) != 0) { close(fd); unlink(tmp); return -1; }
    close(fd);
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

int poller_persist_last_counts(const struct cfg *cfg) {
    uint64_t rx = 0, tx = 0;
    ipacct_get_latest_kernel_counts(&rx, &tx);
    return save_last_counts_values(cfg->root_dir, cfg->iface, rx, tx);
}

static int load_meta(const char *root_dir, const char *iface, struct meta_persist *m) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s/.meta", root_dir, iface);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    int ok = fread(m, sizeof(*m), 1, f) == 1;
    fclose(f);
    return ok ? 0 : -1;
}

static int save_meta(const char *root_dir, const char *iface) {
    char dir[512], tmp[768], path[768];
    snprintf(dir, sizeof(dir), "%s/%s", root_dir, iface);
    if (ensure_dir(dir) != 0) return -1;
    struct meta_persist m;
    memset(&m, 0, sizeof(m));
    read_boot_id(m.boot_id);
    m.ifindex = if_nametoindex(iface);
    snprintf(tmp, sizeof(tmp), "%s/.meta.tmp.%d", dir, getpid());
    snprintf(path, sizeof(path), "%s/.meta", dir);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    if (write(fd, &m, sizeof(m)) != (ssize_t)sizeof(m)) { close(fd); unlink(tmp); return -1; }
    if (fsync(fd) != 0) { close(fd); unlink(tmp); return -1; }
    close(fd);
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static int metadata_matches(const struct cfg *cfg) {
    struct meta_persist oldm;
    if (load_meta(cfg->root_dir, cfg->iface, &oldm) != 0) return 0;
    char cur_boot[37] = {0};
    read_boot_id(cur_boot);
    uint32_t cur_ifindex = if_nametoindex(cfg->iface);
    return oldm.ifindex == cur_ifindex && strncmp(oldm.boot_id, cur_boot, sizeof(oldm.boot_id)) == 0;
}

static uint64_t compute_delta(uint64_t cur, uint64_t last) {
    if (cur >= last) return cur - last;
    return cur;
}

void *poller_thread_fn(void *arg) {
    struct cfg *cfg = (struct cfg *)arg;
    char rxpath[256], txpath[256];
    snprintf(rxpath, sizeof(rxpath), "/sys/class/net/%s/statistics/rx_bytes", cfg->iface);
    snprintf(txpath, sizeof(txpath), "/sys/class/net/%s/statistics/tx_bytes", cfg->iface);

    uint64_t last_rx = 0, last_tx = 0;
    int have_last = 0;

    if (metadata_matches(cfg) && load_last_counts(cfg->root_dir, cfg->iface, &last_rx, &last_tx) == 0) {
        have_last = 1;
        fprintf(stderr, "[poller] restored last counters rx=%llu tx=%llu\n",
                (unsigned long long)last_rx, (unsigned long long)last_tx);
    } else {
        fprintf(stderr, "[poller] fresh baseline: no valid previous counters for this boot/ifindex\n");
    }
    save_meta(cfg->root_dir, cfg->iface);

    while (netacct_running) {
        uint64_t cur_rx = 0, cur_tx = 0;
        if (read_u64_file(rxpath, &cur_rx) != 0 || read_u64_file(txpath, &cur_tx) != 0) {
            fprintf(stderr, "[poller] cannot read sysfs counters for %s: %s\n", cfg->iface, strerror(errno));
            for (int i = 0; i < cfg->poll_interval && netacct_running; i++) sleep(1);
            continue;
        }

        if (!have_last) {
            last_rx = cur_rx;
            last_tx = cur_tx;
            have_last = 1;
            ipacct_accumulate_kernel_delta(0, 0, cur_rx, cur_tx);
        } else {
            uint64_t d_rx = compute_delta(cur_rx, last_rx);
            uint64_t d_tx = compute_delta(cur_tx, last_tx);
            ipacct_accumulate_kernel_delta(d_rx, d_tx, cur_rx, cur_tx);
            last_rx = cur_rx;
            last_tx = cur_tx;
        }

        for (int i = 0; i < cfg->poll_interval && netacct_running; i++) sleep(1);
    }
    return NULL;
}
