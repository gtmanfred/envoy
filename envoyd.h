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

#ifndef ENVOYD_H
#define ENVOYD_H

#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

enum agent {
    AGENT_DEFAULT = -1,
    AGENT_SSH_AGENT = 0,
    AGENT_GPG_AGENT,
    LAST_AGENT
};

enum status {
    ENVOY_STOPPED = 0,
    ENVOY_STARTED,
    ENVOY_RUNNING,
    ENVOY_FAILED,
    ENVOY_BADUSER,
};

struct agent_t {
    const char *name;
    char *const *argv;
};

struct agent_data_t {
    enum agent type;
    enum status status;
    pid_t pid;
    char sock[PATH_MAX];
    char gpg[PATH_MAX];
};

struct agent_info_t {
    uid_t uid;
    struct agent_data_t d;
    struct agent_info_t *next;
};

extern const struct agent_t Agent[LAST_AGENT];
extern const char *envoy_sock;

const char *env_lookup(const char *env, const char *def);
const char *env_envoy_socket(void);

size_t init_socket(struct sockaddr_un *un, const char *socket);
void shutdown_socket(int socket, const char *path);
enum agent find_agent(const char *string);

#endif

// vim: et:sts=4:sw=4:cino=(0
