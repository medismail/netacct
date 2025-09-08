#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netacct.h"

int main(int argc, char **argv) {
    struct cfg cfg;
    cfg.iface = "enp0s3";
    cfg.poll_interval = 2;
    cfg.flush_interval = 10;
    cfg.root_dir = "./data";

    if (argc > 1 && strcmp(argv[1], "report") == 0) {
        return reporter_run(argc-1, argv+1);
    } else {
        collector_init(&cfg);
        printf("netacct starting for iface=%s\n", cfg.iface);
        collector_run(&cfg);
        printf("netacct stopped\n");
    }
    return 0;
}
