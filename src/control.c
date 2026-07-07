#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cjson/cJSON.h>

#include "netacct.h"

#define CONTROL_SOCK_PATH "/run/netacct.sock"

static int parse_ip_any(const char *ipstr, uint8_t *ipv, uint8_t addr[NETACCT_ADDR_BYTES]) {
    struct in_addr a4;
    struct in6_addr a6;
    memset(addr, 0, NETACCT_ADDR_BYTES);
    if (inet_pton(AF_INET, ipstr, &a4) == 1) {
        *ipv = NETACCT_IPV4;
        memcpy(addr, &a4.s_addr, sizeof(a4.s_addr));
        return 0;
    }
    if (inet_pton(AF_INET6, ipstr, &a6) == 1) {
        *ipv = NETACCT_IPV6;
        memcpy(addr, a6.s6_addr, NETACCT_ADDR_BYTES);
        return 0;
    }
    return -1;
}

static void handle_command(const char *line) {
    cJSON *root = cJSON_Parse(line);
    if (!root) {
        fprintf(stderr, "[control] JSON parse error\n");
        return;
    }

    cJSON *action_item = cJSON_GetObjectItemCaseSensitive(root, "action");
    cJSON *ip_item = cJSON_GetObjectItemCaseSensitive(root, "ip");

    if (!cJSON_IsString(action_item) || !cJSON_IsString(ip_item)) {
        fprintf(stderr, "[control] invalid JSON; expected {\"action\":\"add|del\",\"ip\":\"address\"}\n");
        cJSON_Delete(root);
        return;
    }

    const char *action = action_item->valuestring;
    const char *ipstr = ip_item->valuestring;
    uint8_t ipv = 0;
    uint8_t addr[NETACCT_ADDR_BYTES];
    if (parse_ip_any(ipstr, &ipv, addr) != 0) {
        fprintf(stderr, "[control] invalid IP address: %s\n", ipstr);
        cJSON_Delete(root);
        return;
    }

    if (strcmp(action, "add") == 0) {
        ipacct_add_client(ipv, addr);
        fprintf(stderr, "[control] added %s\n", ipstr);
    } else if (strcmp(action, "del") == 0) {
        ipacct_del_client(ipv, addr);
        fprintf(stderr, "[control] removed %s\n", ipstr);
    } else {
        fprintf(stderr, "[control] unknown action: %s\n", action);
    }

    cJSON_Delete(root);
}

void *control_thread_fn(void *arg) {
    (void)arg;
    int fd = -1;
    struct sockaddr_un addr;

    unlink(CONTROL_SOCK_PATH);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("[control] socket");
        return NULL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[control] bind");
        close(fd);
        return NULL;
    }
    chmod(CONTROL_SOCK_PATH, 0660);

    if (listen(fd, 5) < 0) {
        perror("[control] listen");
        close(fd);
        unlink(CONTROL_SOCK_PATH);
        return NULL;
    }

    fprintf(stderr, "[control] listening on %s\n", CONTROL_SOCK_PATH);

    while (netacct_running) {
        int cfd = accept(fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("[control] accept");
            break;
        }
        char buf[512];
        ssize_t n = read(cfd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            handle_command(buf);
        }
        close(cfd);
    }

    close(fd);
    unlink(CONTROL_SOCK_PATH);
    return NULL;
}
