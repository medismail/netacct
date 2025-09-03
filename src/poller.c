// src/poller.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <net/if.h>
#include <sys/sysinfo.h>

#include "netacct.h"

/* ---------- Helpers ---------- */

static int ensure_dir_recursive(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return 0;
    char tmp[1024];
    strncpy(tmp, path, sizeof(tmp)-1);
    tmp[sizeof(tmp)-1] = '\0';
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {}
    return 0;
}

/* .last_counts file: updated every poll */
static int load_last_counts(const char *root_dir, const char *iface,
                             uint64_t *out_last_rx, uint64_t *out_last_tx)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s/.last_counts", root_dir, iface);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint64_t rx=0, tx=0;
    if (fread(&rx, sizeof(rx), 1, f) != 1) { fclose(f); return -1; }
    if (fread(&tx, sizeof(tx), 1, f) != 1) { fclose(f); return -1; }
    fclose(f);
    *out_last_rx = rx; *out_last_tx = tx;
    return 0;
}

static int save_last_counts(const char *root_dir, const char *iface,
                            uint64_t last_rx, uint64_t last_tx)
{
    char dirpath[1024], tmpfile[1024], path[1024];
    snprintf(dirpath, sizeof(dirpath), "%s/%s", root_dir, iface);
    ensure_dir_recursive(dirpath);
    snprintf(tmpfile, sizeof(tmpfile), "%s/.last_counts.tmp.%d", dirpath, getpid());
    snprintf(path, sizeof(path), "%s/.last_counts", dirpath);

    int fd = open(tmpfile, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) return -1;
    if (write(fd,&last_rx,sizeof(last_rx))!=sizeof(last_rx)) { close(fd); unlink(tmpfile); return -1; }
    if (write(fd,&last_tx,sizeof(last_tx))!=sizeof(last_tx)) { close(fd); unlink(tmpfile); return -1; }
    fsync(fd); close(fd);
    if (rename(tmpfile, path)!=0) { unlink(tmpfile); return -1; }
    return 0;
}

/* .meta file: updated on flush */
struct meta_persist {
    uint64_t boot_time_sec;
    uint32_t ifindex;
    uint32_t reserved;
};

static int save_meta(const char *root_dir, const char *iface) {
    char dirpath[1024], tmpfile[1024], path[1024];
    snprintf(dirpath, sizeof(dirpath), "%s/%s", root_dir, iface);
    ensure_dir_recursive(dirpath);
    snprintf(tmpfile, sizeof(tmpfile), "%s/.meta.tmp.%d", dirpath, getpid());
    snprintf(path, sizeof(path), "%s/.meta", dirpath);

    struct meta_persist m = {0};
    struct sysinfo si;
    sysinfo(&si);
    time_t now = time(NULL);
    m.boot_time_sec = (uint64_t)(now - si.uptime);
    m.ifindex = if_nametoindex(iface);

    int fd = open(tmpfile,O_WRONLY|O_CREAT|O_TRUNC,0644);
    if (fd<0) return -1;
    if (write(fd,&m,sizeof(m))!=sizeof(m)) { close(fd); unlink(tmpfile); return -1; }
    fsync(fd); close(fd);
    if (rename(tmpfile,path)!=0) { unlink(tmpfile); return -1; }
    return 0;
}

static int load_meta(const char *root_dir, const char *iface,
                     uint64_t *boot_time_sec, uint32_t *ifindex) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s/.meta", root_dir, iface);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    struct meta_persist m;
    if (fread(&m, sizeof(m),1,f)!=1) { fclose(f); return -1; }
    fclose(f);
    *boot_time_sec = m.boot_time_sec;
    *ifindex = m.ifindex;
    return 0;
}

/* Compute delta with wrap/reset detection */
static uint64_t compute_delta(uint64_t cur, uint64_t last) {
    if (cur >= last) return cur - last;
    const uint64_t SMALL_RESET_THRESHOLD = 1024ULL*1024ULL;
    if (cur <= SMALL_RESET_THRESHOLD) return cur; // reset
    return cur + (UINT64_MAX - last) + 1ULL; // wrap
}

/* sysfs read */
static int read_u64_file(const char *path, uint64_t *out) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    unsigned long long v=0;
    if (fscanf(f,"%llu",&v)!=1) { fclose(f); return -1; }
    fclose(f); *out=(uint64_t)v; return 0;
}

/* API to storage */
extern int ipacct_accumulate_kernel_delta(uint64_t rx_delta, uint64_t tx_delta);

/* ---------- Poller thread ---------- */

void *poller_thread_fn(void *arg) {
    struct cfg *cfg = (struct cfg*)arg;
    char rxpath[256], txpath[256];
    snprintf(rxpath,sizeof(rxpath),"/sys/class/net/%s/statistics/rx_bytes",cfg->iface);
    snprintf(txpath,sizeof(txpath),"/sys/class/net/%s/statistics/tx_bytes",cfg->iface);

    uint64_t last_rx_seen=0, last_tx_seen=0;
    int have_last=0;

    // validate meta at startup
    uint64_t meta_boot=0; uint32_t meta_ifidx=0;
    if (load_meta(cfg->root_dir,cfg->iface,&meta_boot,&meta_ifidx)==0) {
        struct sysinfo si; sysinfo(&si);
        time_t now=time(NULL);
        uint64_t cur_boot=(uint64_t)(now - si.uptime);
        uint32_t cur_ifidx=if_nametoindex(cfg->iface);
        if (meta_boot!=cur_boot || meta_ifidx!=cur_ifidx) {
            fprintf(stderr,"[poller] Meta mismatch (boot/ifindex), treating as reset\\n");
            have_last=0;
        }
    }

    if (load_last_counts(cfg->root_dir,cfg->iface,&last_rx_seen,&last_tx_seen)==0) {
        have_last=1;
    }

    while (1) {
        uint64_t cur_rx=0, cur_tx=0;
        if (read_u64_file(rxpath,&cur_rx)!=0 || read_u64_file(txpath,&cur_tx)!=0) {
            sleep(cfg->poll_interval);
            continue;
        }
        if (!have_last) {
            last_rx_seen=cur_rx; last_tx_seen=cur_tx; have_last=1;
            save_last_counts(cfg->root_dir,cfg->iface,last_rx_seen,last_tx_seen);
        } else {
            uint64_t rx_delta=compute_delta(cur_rx,last_rx_seen);
            uint64_t tx_delta=compute_delta(cur_tx,last_tx_seen);
            if (rx_delta||tx_delta) {
                ipacct_accumulate_kernel_delta(rx_delta,tx_delta);
            }
            last_rx_seen=cur_rx; last_tx_seen=cur_tx;
            save_last_counts(cfg->root_dir,cfg->iface,last_rx_seen,last_tx_seen);
        }
        sleep(cfg->poll_interval);
    }
    return NULL;
}

/* ---------- Flush hook ---------- */

void poller_on_flush(const struct cfg *cfg) {
    if (save_meta(cfg->root_dir, cfg->iface)!=0) {
        perror("save_meta");
    }
}

