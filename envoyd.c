/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Simon Gomizelj, 2012
 */

#include "envoyd.h"
#include "monitor.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <pwd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <systemd/sd-daemon.h>

struct sock_info_t {
    char *ssh_auth_sock, *gpg_agent_info;
    int server_sock, ssh_auth_fd, gpg_agent_fd;
};

static enum agent default_type = AGENT_SSH_AGENT;
static struct agent_info_t *agents = NULL;
static bool sd_activated = false;
static int epoll_fd;

static struct sock_info_t s;

static void sighandler(int signum)
{
    switch (signum) {
    case SIGINT:
    case SIGTERM:
        close(epoll_fd);

        if (!sd_activated) {
            /* shutdown_socket(s.server_sock, NULL); */
        }

        kill_monitor(agents);
        exit(EXIT_SUCCESS);
    }
}

static inline void epoll_register(int epoll_fd, int fd)
{
    struct epoll_event event = {
        .data.fd = fd,
        .events  = EPOLLIN | EPOLLET
    };

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0)
        err(EXIT_FAILURE, "failed to add socket to epoll");
}

static int create_socket(const char *path, mode_t mode)
{
    int fd;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    socklen_t sa_len;

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        err(EXIT_FAILURE, "couldn't create socket");

    sa_len = init_socket(&sa.un, path);
    if (bind(fd, &sa.sa, sa_len) < 0)
        err(EXIT_FAILURE, "failed to bind");

    if (sa.un.sun_path[0] != '@')
        chmod(sa.un.sun_path, mode);

    if (listen(fd, SOMAXCONN) < 0)
        err(EXIT_FAILURE, "failed to listen");

    return fd;
}

static void get_sockets(struct sock_info_t *s)
{
    int fd, n;
    const char *path;

    /* FIXME: obviously shouldn't hardcoded */
    mkdir("/run/user/1000/envoy", 0700);

    n = sd_listen_fds(0);
    switch (n) {
    case 0:
        path = env_envoy_socket();
        s->server_sock = create_socket(path, 0777);
        /* fallthrough */
    case 1:
        s->ssh_auth_sock = "/run/user/1000/envoy/ssh";
        s->ssh_auth_fd = create_socket(s->ssh_auth_sock, 0777);
        /* fallthrough */
    case 2:
        s->gpg_agent_info = "/run/user/1000/envoy/gpg";
        s->gpg_agent_fd = create_socket(s->gpg_agent_info, 0777);
        /* fallthrough */
    case 3:
        sd_activated = true;
        fd = SD_LISTEN_FDS_START;
        break;
    default:
        err(EXIT_FAILURE, "too many file descriptors recieved");
    }
}

static struct agent_info_t *find_agent_info(struct agent_info_t *agents, uid_t uid)
{
    struct agent_info_t *node;
    for (node = agents; node; node = node->next) {
        if (node->uid == uid)
            return node;
    }

    return NULL;
}

static void send_agent(int fd, struct agent_data_t *agent, bool close_sock)
{
    if (write(fd, agent, sizeof(struct agent_data_t)) < 0)
        err(EXIT_FAILURE, "failed to write agent data");
    if (close_sock)
        close(fd);
}

static void send_message(int fd, enum status status, bool close_sock)
{
    struct agent_data_t d = { .status = status };
    send_agent(fd, &d, close_sock);
}

static void accept_ctrl_conn(void)
{
    struct ucred cred;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    static socklen_t sa_len = sizeof(struct sockaddr_un);
    static socklen_t cred_len = sizeof(struct ucred);
    uid_t server_uid = geteuid();

    int cfd = accept4(s.server_sock, &sa.sa, &sa_len, SOCK_CLOEXEC);
    if (cfd < 0)
        err(EXIT_FAILURE, "failed to accept connection");

    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0)
        err(EXIT_FAILURE, "couldn't obtain credentials from unix domain socket");

    if (server_uid != 0 && server_uid != cred.uid) {
        fprintf(stderr, "Connection from uid=%u rejected.\n", cred.uid);
        send_message(cfd, ENVOY_BADUSER, true);
        return;
    }

    struct agent_info_t *node = find_agent_info(agents, cred.uid);

    if (!node || node->d.pid == 0 || !monitor_pid_alive(node->d.pid, cred.uid)) {
        if (node)
            node->d.pid = 0;

        epoll_register(epoll_fd, cfd);
        send_message(cfd, ENVOY_STOPPED, false);
    } else {
        send_agent(cfd, &node->d, true);
    }
}

static void handle_ctrl_conn(int cfd)
{
    struct ucred cred;
    static socklen_t cred_len = sizeof(struct ucred);
    enum agent type;

    int nbytes_r = read(cfd, &type, sizeof(enum agent));
    if (nbytes_r < 0)
        err(EXIT_FAILURE, "couldn't read agent type to start");

    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0)
        err(EXIT_FAILURE, "couldn't obtain credentials from unix domain socket");

    struct agent_info_t *node = find_agent_info(agents, cred.uid);

    if (!node) {
        node = calloc(1, sizeof(struct agent_info_t));
        node->uid = cred.uid;
        node->next = agents;
        agents = node;
    } else {
        printf("Agent for uid=%u is has terminated. Restarting...\n", cred.uid);
    }

    node->d.type = type != AGENT_DEFAULT ? type : default_type;

    run_agent(&node->d, cred.uid, cred.gid);
    send_agent(cfd, &node->d, true);

    if (node->d.pid)
        node->d.status = ENVOY_RUNNING;
}

static void handle_ssh_conn(int fd)
{
    struct ucred cred;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    static socklen_t sa_len = sizeof(struct sockaddr_un);
    static socklen_t cred_len = sizeof(struct ucred);

    int cfd = accept4(fd, &sa.sa, &sa_len, SOCK_CLOEXEC);
    if (cfd < 0)
        err(EXIT_FAILURE, "failed to accept connection");

    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0)
        err(EXIT_FAILURE, "couldn't obtain credentials from unix domain socket");

    struct agent_info_t *node = find_agent_info(agents, cred.uid);
    if (!node) {
        close(cfd);
        return;
    }

    int sshfd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sshfd < 0)
        err(EXIT_FAILURE, "couldn't create socket");

    sa_len = init_socket(&sa.un, node->d.sock);
    if (connect(sshfd, &sa.sa, sa_len) < 0)
        err(EXIT_FAILURE, "failed to connect to agent");

    /* FIXME: this is too one way atm */

    char buf[BUFSIZ];
    ssize_t bytes_r;
    while ((bytes_r = read(cfd, buf, BUFSIZ)) < 0) {
        write(sshfd, buf, bytes_r);
    }

    if (bytes_r < 0 && errno != EAGAIN)
        err(EXIT_FAILURE, "failed to read from ssh child");

    close(sshfd);
    close(cfd);
}

static int loop(void)
{
    struct epoll_event events[4];

    epoll_register(epoll_fd, s.server_sock);
    epoll_register(epoll_fd, s.ssh_auth_fd);
    epoll_register(epoll_fd, s.gpg_agent_fd);

    while (true) {
        int i, n = epoll_wait(epoll_fd, events, 4, -1);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            err(EXIT_FAILURE, "epoll_wait failed");
        }

        for (i = 0; i < n; ++i) {
            struct epoll_event *evt = &events[i];
            int fd = evt->data.fd;

            if (evt->events & EPOLLERR || evt->events & EPOLLHUP) {
                close(fd);
            } else if (fd == s.ssh_auth_fd) {
                handle_ssh_conn(fd);
            } else if (fd == s.server_sock) {
                accept_ctrl_conn();
            } else {
                handle_ctrl_conn(fd);
            }

            fflush(stdout);
        }
    }

    return 0;
}

static void __attribute__((__noreturn__)) usage(FILE *out)
{
    fprintf(out, "usage: %s [options]\n", program_invocation_short_name);
    fputs("Options:\n"
        " -h, --help            display this help and exit\n"
        " -v, --version         display version\n"
        " -a, --agent=AGENT     set the agent to start\n", out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    static const struct option opts[] = {
        { "help",    no_argument,       0, 'h' },
        { "version", no_argument,       0, 'v' },
        { "agent",   required_argument, 0, 't' },
        { 0, 0, 0, 0 }
    };

    while (true) {
        int opt = getopt_long(argc, argv, "hvt:", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':
            usage(stdout);
            break;
        case 'v':
            printf("%s %s\n", program_invocation_short_name, ENVOY_VERSION);
            return 0;
        case 't':
            default_type = find_agent(optarg);
            if (default_type == LAST_AGENT)
                errx(EXIT_FAILURE, "unknown agent: %s", optarg);
            break;
        default:
            usage(stderr);
        }
    }

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0)
        err(EXIT_FAILURE, "failed to start epoll");

    get_sockets(&s);
    init_monitor();

    signal(SIGTERM, sighandler);
    signal(SIGINT,  sighandler);

    return loop();
}

// vim: et:sts=4:sw=4:cino=(0
