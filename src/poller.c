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
#include <sys/sysinfo.h>
#include <net/if.h>

#include "netacct.h"

/* ---------- Persistence ---------- */

/* .last_counts file: updated every poll */
static int load_last_counts(const char *root_dir, const char *iface,
                             uint64_t *out_last_rx, uint64_t *out_last_tx)
{
    char path[1024];
    snprintf(path,sizeof(path),"%s/%s/.last_counts",root_dir,iface);
    FILE *f=fopen(path,"rb");
    if(!f) return -1;
    if(fread(out_last_rx,sizeof(uint64_t),1,f)!=1){fclose(f);return -1;}
    if(fread(out_last_tx,sizeof(uint64_t),1,f)!=1){fclose(f);return -1;}
    fclose(f); return 0;
}

static int save_last_counts(const char *root_dir,const char *iface,
                            uint64_t last_rx,uint64_t last_tx)
{
    char dir[1024],tmp[1536],path[1536];
    snprintf(dir,sizeof(dir),"%s/%s",root_dir,iface);
    mkdir(dir,0755);
    snprintf(tmp,sizeof(tmp),"%s/.last_counts.tmp.%d",dir,getpid());
    snprintf(path,sizeof(path),"%s/.last_counts",dir);

    int fd=open(tmp,O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(fd<0) return -1;
    if(write(fd,&last_rx,sizeof(last_rx))!=sizeof(last_rx)) {close(fd);unlink(tmp);return -1;}
    if(write(fd,&last_tx,sizeof(last_tx))!=sizeof(last_tx)) {close(fd);unlink(tmp);return -1;}
    fsync(fd); close(fd);
    if(rename(tmp,path)!=0){unlink(tmp);return -1;}
    return 0;
}

/* .meta file: compared + refreshed at startup */
struct meta_persist {
    uint64_t boot_uptime; // seconds since boot when program started
    uint32_t ifindex;
    uint32_t reserved;
};

static int load_meta(const char *root_dir,const char *iface,struct meta_persist *m) {
    char path[1024];
    snprintf(path,sizeof(path),"%s/%s/.meta",root_dir,iface);
    FILE *f=fopen(path,"rb"); if(!f) return -1;
    if(fread(m,sizeof(*m),1,f)!=1){fclose(f);return -1;}
    fclose(f); return 0;
}

static int save_meta(const char *root_dir,const char *iface) {
    char dir[1024],tmp[1536],path[1536];
    snprintf(dir,sizeof(dir),"%s/%s",root_dir,iface);
    mkdir(dir,0755);
    snprintf(tmp,sizeof(tmp),"%s/.meta.tmp.%d",dir,getpid());
    snprintf(path,sizeof(path),"%s/.meta",dir);

    struct sysinfo si; sysinfo(&si);
    struct meta_persist m={0};
    m.boot_uptime=(uint64_t)si.uptime;
    m.ifindex=if_nametoindex(iface);

    int fd=open(tmp,O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(fd<0) return -1;
    if(write(fd,&m,sizeof(m))!=sizeof(m)) {close(fd);unlink(tmp);return -1;}
    fsync(fd); close(fd);
    if(rename(tmp,path)!=0){unlink(tmp);return -1;}
    return 0;
}

/* ---------- Helpers ---------- */

static uint64_t compute_delta(uint64_t cur,uint64_t last) {
    if(cur>=last) return cur-last;
    const uint64_t SMALL_RESET=1024ULL*1024ULL;
    if(cur<=SMALL_RESET) return cur; // reset
    return cur+(UINT64_MAX-last)+1ULL; // wrap
}

static int read_u64_file(const char *path,uint64_t *out) {
    FILE *f=fopen(path,"r"); if(!f) return -1;
    unsigned long long v=0;
    if(fscanf(f,"%llu",&v)!=1){fclose(f);return -1;}
    fclose(f); *out=(uint64_t)v; return 0;
}

extern int ipacct_accumulate_kernel_delta(uint64_t rx,uint64_t tx);

/* ---------- Poller thread ---------- */

void *poller_thread_fn(void *arg) {
    struct cfg *cfg=(struct cfg*)arg;
    char rxpath[256],txpath[256];
    snprintf(rxpath,sizeof(rxpath),"/sys/class/net/%s/statistics/rx_bytes",cfg->iface);
    snprintf(txpath,sizeof(txpath),"/sys/class/net/%s/statistics/tx_bytes",cfg->iface);

    uint64_t last_rx=0,last_tx=0; int have_last=0;

    // --- Startup checks ---
    struct sysinfo si; sysinfo(&si);
    uint64_t cur_boot=(uint64_t)si.uptime;
    uint32_t cur_ifidx=if_nametoindex(cfg->iface);

    struct meta_persist m;
    if (load_meta(cfg->root_dir,cfg->iface,&m)==0) {
        if (m.boot_uptime > cur_boot || m.ifindex!=cur_ifidx) {
            fprintf(stderr,"[poller] Meta mismatch (boot/ifindex), reset state\n");
        } else if (load_last_counts(cfg->root_dir,cfg->iface,&last_rx,&last_tx)==0) {
            have_last=1;
        }
    }
    // always refresh meta to current values
    save_meta(cfg->root_dir,cfg->iface);

    // --- Main loop ---
    while(1) {
        uint64_t cur_rx=0,cur_tx=0;
        if(read_u64_file(rxpath,&cur_rx)!=0 || read_u64_file(txpath,&cur_tx)!=0) {
            sleep(cfg->poll_interval); continue;
        }
        if(!have_last) {
            last_rx=cur_rx; last_tx=cur_tx; have_last=1;
            save_last_counts(cfg->root_dir,cfg->iface,last_rx,last_tx);
        } else {
            uint64_t d_rx=compute_delta(cur_rx,last_rx);
            uint64_t d_tx=compute_delta(cur_tx,last_tx);
            if(d_rx||d_tx) ipacct_accumulate_kernel_delta(d_rx,d_tx);
            last_rx=cur_rx; last_tx=cur_tx;
            save_last_counts(cfg->root_dir,cfg->iface,last_rx,last_tx);
        }
        sleep(cfg->poll_interval);
    }
    return NULL;
}
