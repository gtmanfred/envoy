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

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <sys/stat.h>
#include <err.h>

const struct agent_t Agent[LAST_AGENT] = {
    [AGENT_SSH_AGENT] = {
        .name = "ssh-agent",
        .argv = (char *const []){ "/usr/bin/ssh-agent", NULL }
    },
    [AGENT_GPG_AGENT] = {
        .name = "gpg-agent",
        .argv = (char *const []){ "/usr/bin/gpg-agent", "--daemon", "--enable-ssh-support", NULL }
    }
};

const char *env_lookup(const char *env, const char *def)
{
    const char *value = getenv(env);
    return value ? value : def;
}

const char *env_envoy_socket(void)
{
    return env_lookup("ENVOY_SOCKET", "@/vodik/envoy");
}

size_t init_socket(struct sockaddr_un *un, const char *socket)
{
    off_t off = 0;
    size_t len;

    *un = (struct sockaddr_un){ .sun_family = AF_UNIX };

    if (socket[0] == '@')
        off = 1;

    len = strlen(socket);
    memcpy(&un->sun_path[off], &socket[off], len - off);

    return len + sizeof(un->sun_family);
}

int create_socket(const char *path, mode_t mode)
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

int connect_gpg_socket(const char *path, int mode)
{
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    char *split;
    size_t len;
    socklen_t sa_len;

    int fd = socket(AF_UNIX, SOCK_STREAM | mode, 0);
    if (fd < 0) {
        warn("couldn't create socket");
        return -1;
    }

    split = strchr(path, ':');
    len = split - path;

    sa.un = (struct sockaddr_un){ .sun_family = AF_UNIX };
    memcpy(&sa.un.sun_path, path, len);

    sa_len = len + sizeof(sa.un.sun_family);
    if (connect(fd, &sa.sa, sa_len) < 0) {
        warn("failed to connect to gpg-agent");
        return -1;
    }

    return fd;
}


/* void shutdown_socket(int socket, const char *socket) */
/* { */
/*     close(socket); */
/*     if (path[0] != '@') */
/*         unlink(path); */
/* } */

enum agent find_agent(const char *string)
{
    size_t i;

    for (i = 0; i < LAST_AGENT; i++)
        if (strcmp(Agent[i].name, string) == 0)
            break;

    return i;
}

// vim: et:sts=4:sw=4:cino=(0
