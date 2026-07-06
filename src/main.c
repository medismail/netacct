#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netacct.h"

static void print_usage(FILE *out) {
    fprintf(out,
        "netacct - lightweight IPv4/IPv6 accounting for one LAN interface\n\n"
        "Usage:\n"
        "  netacct daemon [options]\n"
        "  netacct report --iface IFACE [--root DIR] (--day YYYY-MM-DD | --month YYYY-MM) [--format text|csv|json] [--top N] [--human]\n"
        "  netacct list-ifaces [--root DIR]\n\n"
        "Daemon options:\n"
        "  --config FILE           Load key=value config file\n"
        "  --iface IFACE           Interface to monitor, default eth0\n"
        "  --root DIR              Storage root, default /var/lib/netacct\n"
        "  --subnet CIDR|auto      Local IPv4 subnet to account, default auto from IFACE\n"
        "  --subnet6 CIDR|auto     Local IPv6 subnet to account, default auto from IFACE\n"
        "  --poll-interval SEC     Kernel counter poll interval, default 1\n"
        "  --flush-interval SEC    Storage flush interval, default 5\n"
        "  --pcap-buffer-mb MB     libpcap kernel buffer, default 4\n\n"
        "Example:\n"
        "  sudo ./bin/netacct daemon --iface eth0 --subnet auto --subnet6 auto --root /var/lib/netacct\n"
        "  ./bin/netacct report --iface eth0 --day 2026-06-30 --root /var/lib/netacct --human\n");
}

static int is_option_with_value(const char *arg) {
    return strcmp(arg, "--config") == 0 || strcmp(arg, "--iface") == 0 ||
           strcmp(arg, "--interface") == 0 || strcmp(arg, "--root") == 0 ||
           strcmp(arg, "--root-dir") == 0 || strcmp(arg, "--subnet") == 0 ||
           strcmp(arg, "--local-subnet") == 0 || strcmp(arg, "--subnet6") == 0 ||
           strcmp(arg, "--local-subnet6") == 0 || strcmp(arg, "--poll-interval") == 0 ||
           strcmp(arg, "--flush-interval") == 0 || strcmp(arg, "--pcap-buffer-mb") == 0 ||
           strcmp(arg, "--top") == 0;
}

static int apply_cli_options(struct cfg *cfg, int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            i++;
            continue;
        }
        if (!is_option_with_value(argv[i])) continue;
        if (i + 1 >= argc) {
            fprintf(stderr, "missing value for %s\n", argv[i]);
            return -1;
        }
        const char *key = argv[i] + 2;
        const char *value = argv[++i];
        if (cfg_apply_option(cfg, key, value) != 0) {
            fprintf(stderr, "invalid option: %s %s\n", argv[i - 1], value);
            return -1;
        }
    }
    return 0;
}

static int pre_load_config(struct cfg *cfg, int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --config\n");
                return -1;
            }
            if (cfg_load_file(cfg, argv[i + 1]) != 0) {
                fprintf(stderr, "failed to load config: %s\n", argv[i + 1]);
                return -1;
            }
            i++;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    struct cfg cfg;
    cfg_set_defaults(&cfg);

    if (argc < 2) {
        print_usage(stderr);
        return 1;
    }

    const char *cmd = argv[1];
    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "help") == 0) {
        print_usage(stdout);
        return 0;
    }

    if (strcmp(cmd, "report") == 0 || strcmp(cmd, "list-ifaces") == 0) {
        return reporter_run(argc - 1, argv + 1);
    }

    int opt_start = 1;
    if (strcmp(cmd, "daemon") == 0 || strcmp(cmd, "run") == 0 || strcmp(cmd, "collect") == 0) {
        opt_start = 2;
    } else if (cmd[0] == '-') {
        opt_start = 1;
    } else {
        fprintf(stderr, "unknown command: %s\n\n", cmd);
        print_usage(stderr);
        return 1;
    }

    if (pre_load_config(&cfg, argc - opt_start, argv + opt_start) != 0) return 1;
    if (apply_cli_options(&cfg, argc - opt_start, argv + opt_start) != 0) return 1;

    if (collector_init(&cfg) != 0) return 1;

    fprintf(stderr,
            "[netacct] iface=%s root=%s subnet=%s subnet6=%s poll=%ds flush=%ds pcap_buffer=%dMB\n",
            cfg.iface, cfg.root_dir, cfg.subnet_text, cfg.subnet6_text,
            cfg.poll_interval, cfg.flush_interval, cfg.pcap_buffer_mb);

    return collector_run(&cfg);
}
