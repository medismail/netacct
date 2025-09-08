// src/control.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#include "netacct.h"

#define CONTROL_SOCK_PATH "/var/run/netacct.sock"


static void handle_command(const char *line) {
    cJSON *root = cJSON_Parse(line);
    if (!root) {
        fprintf(stderr, "[control] JSON parse error\n");
        return;
    }

    cJSON *action_item = cJSON_GetObjectItemCaseSensitive(root, "action");
    cJSON *ip_item     = cJSON_GetObjectItemCaseSensitive(root, "ip");

    if (!cJSON_IsString(action_item) || !cJSON_IsString(ip_item)) {
        fprintf(stderr, "[control] Invalid JSON (missing fields)\n");
        cJSON_Delete(root);
        return;
    }

    const char *action = action_item->valuestring;
    const char *ipstr  = ip_item->valuestring;

    struct in_addr addr;
    if (inet_aton(ipstr, &addr) == 0) {
        fprintf(stderr, "[control] Invalid IP: %s\n", ipstr);
        cJSON_Delete(root);
        return;
    }

    if (strcmp(action, "add") == 0) {
        ipacct_add_client(addr.s_addr);
        fprintf(stderr, "[control] Added client %s\n", ipstr);
    } else if (strcmp(action, "del") == 0) {
        ipacct_del_client(addr.s_addr);
        fprintf(stderr, "[control] Removed client %s\n", ipstr);
    } else {
        fprintf(stderr, "[control] Unknown action: %s\n", action);
    }

    cJSON_Delete(root);
}

/*static void handle_command(const char *line) {
    json_error_t err;
    json_t *root = json_loads(line, 0, &err);
    if (!root) {
        fprintf(stderr, "[control] JSON parse error: %s\n", err.text);
        return;
    }

    const char *action = json_string_value(json_object_get(root, "action"));
    const char *ipstr  = json_string_value(json_object_get(root, "ip"));

    if (!action || !ipstr) {
        fprintf(stderr, "[control] Invalid JSON (missing fields)\n");
        json_decref(root);
        return;
    }

    struct in_addr addr;
    if (inet_aton(ipstr, &addr) == 0) {
        fprintf(stderr, "[control] Invalid IP: %s\n", ipstr);
        json_decref(root);
        return;
    }

    if (strcmp(action, "add") == 0) {
        ipacct_add_client(addr.s_addr);
        fprintf(stderr, "[control] Added client %s\n", ipstr);
    } else if (strcmp(action, "del") == 0) {
        ipacct_del_client(addr.s_addr);
        fprintf(stderr, "[control] Removed client %s\n", ipstr);
    } else {
        fprintf(stderr, "[control] Unknown action: %s\n", action);
    }

    json_decref(root);
}*/

void *control_thread_fn(void *arg) {
    //struct cfg *cfg = arg;
    (void)arg;
    int fd, cfd;
    struct sockaddr_un addr;

    unlink(CONTROL_SOCK_PATH);

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return NULL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_SOCK_PATH, sizeof(addr.sun_path)-1);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return NULL;
    }

    if (listen(fd, 5) < 0) {
        perror("listen");
        close(fd);
        return NULL;
    }

    fprintf(stderr, "[control] Listening on %s\n", CONTROL_SOCK_PATH);

    char buf[512];
    while (1) {
        cfd = accept(fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        ssize_t n = read(cfd, buf, sizeof(buf)-1);
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
