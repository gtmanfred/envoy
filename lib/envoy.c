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

#include "envoy.h"

#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

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

static const char *get_socket_path(void)
{
    const char *socket = getenv("ENVOY_SOCKET");
    return socket ? socket : "@/vodik/envoy";
}

size_t init_envoy_socket(struct sockaddr_un *un)
{
    const char *socket = get_socket_path();
    off_t off = 0;
    size_t len;

    *un = (struct sockaddr_un){ .sun_family = AF_UNIX };

    if (socket[0] == '@')
        off = 1;

    len = strlen(socket);
    memcpy(&un->sun_path[off], &socket[off], len - off);

    return len + sizeof(un->sun_family);
}

void unlink_envoy_socket(void)
{
    const char *socket = get_socket_path();
    if (socket[0] != '@')
        unlink(socket);
}

static int read_agent(int fd, struct agent_data_t *data)
{
    int nbytes_r;

    while (true) {
        nbytes_r = read(fd, data, sizeof(*data));
        if (nbytes_r < 0) {
            if (errno != EAGAIN)
                return -errno;
        } else {
            return nbytes_r;
        }
    }
}

static int start_agent(int fd, struct agent_data_t *data, enum agent type)
{
    if (write(fd, &type, sizeof(enum agent)) < 0)
        return -errno;
    return read_agent(fd, data);
}

int envoy_agent(struct agent_data_t *data, enum agent id, bool start)
{
    socklen_t sa_len;
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -errno;

    sa_len = init_envoy_socket(&sa.un);
    if (connect(fd, &sa.sa, sa_len) < 0)
        return -errno;

    int ret = read_agent(fd, data);

    if (ret && start && data->status == ENVOY_STOPPED)
        ret = start_agent(fd, data, id);

    close(fd);
    return ret;
}

enum agent lookup_agent(const char *string)
{
    size_t i;

    for (i = 0; i < LAST_AGENT; i++)
        if (strcmp(Agent[i].name, string) == 0)
            break;

    return i;
}

int get_agent(struct agent_data_t *data, enum agent id, bool start)
{
    int ret = envoy_agent(data, id, start);
    if (ret < 0)
        err(EXIT_FAILURE, "failed to fetch agent");

    switch (data->status) {
    case ENVOY_STOPPED:
    case ENVOY_STARTED:
    case ENVOY_RUNNING:
        break;
    case ENVOY_FAILED:
        errx(EXIT_FAILURE, "agent failed to start, check envoyd's log");
    case ENVOY_BADUSER:
        errx(EXIT_FAILURE, "connection rejected, user is unauthorized to use this agent");
    }

    return ret;
}
