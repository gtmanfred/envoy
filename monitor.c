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
 * Copyright (C) Simon Gomizelj, 2013
 */

#include "envoyd.h"
#include "cgroups.h"

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

/* cgroup support */
static bool (*pid_alive)(pid_t pid, uid_t uid);
static void (*kill_agent)(uid_t uid) = NULL;
static char *cgroup_name = NULL;

static void cgroup_cleanup(uid_t uid)
{
    bool done = false;
    char *namespace;

    if (asprintf(&namespace, "%d.agent", uid) < 0)
        err(EXIT_FAILURE, "failed to allocate memory");

    int cgroup_fd = cg_open_controller("cpu", "envoy", cgroup_name, namespace, NULL);
    do {
        FILE *fp = subsystem_open(cgroup_fd, "cgroup.procs", "r");
        pid_t cgroup_pid;
        done = true;
        while (fscanf(fp, "%d", &cgroup_pid) != EOF) {
            kill(cgroup_pid, SIGKILL);
            done = false;
        }
        fclose(fp);
    } while (!done);
    close(cgroup_fd);

    if (cg_destroy_controller("cpu", "envoy", cgroup_name, namespace, NULL) < 0)
        warn("failed to close envoy's namespace cgroup");

    free(namespace);
}

static bool fallback_alive(pid_t pid, uid_t __attribute__((unused)) uid)
{
    if (kill(pid, 0) < 0) {
        if (errno != ESRCH)
            err(EXIT_FAILURE, "something strange happened with kill");
        return false;
    }
    return true;
}

static bool pid_in_cgroup(pid_t pid, uid_t uid)
{
    char *namespace;
    bool found = false;
    pid_t cgroup_pid;

    /* each user's agents are namespaces by uid */
    if (asprintf(&namespace, "%d.agent", uid) < 0)
        err(EXIT_FAILURE, "failed to allocate memory");

    int cgroup_fd = cg_open_controller("cpu", "envoy", cgroup_name, namespace, NULL);
    FILE *fp = subsystem_open(cgroup_fd, "cgroup.procs", "r");
    if (!fp)
        err(EXIT_FAILURE, "failed to open cgroup info");

    while (fscanf(fp, "%d", &cgroup_pid) != EOF) {
        if (cgroup_pid == pid) {
            found = true;
            break;
        }
    }

    fclose(fp);
    close(cgroup_fd);
    free(namespace);
    return found;
}

static void parse_agentdata_line(char *val, struct agent_data_t *info)
{
    char *eol, *var;

    eol = strchr(val, ';');
    if (eol)
        *eol = '\0';

    if (strchr(val, '=') == NULL)
        return;

    var = strsep(&val, "=");

    if (strcmp(var, "SSH_AUTH_SOCK") == 0)
        strcpy(info->sock, val);
    else if (strcmp(var, "SSH_AGENT_PID") == 0)
        info->pid = atoi(val);
    else if (strcmp(var, "GPG_AGENT_INFO") == 0)
        strcpy(info->gpg, val);
}

static int parse_agentdata(int fd, struct agent_data_t *data)
{
    char b[BUFSIZ];
    char *l, *nl;
    ssize_t bytes_r;

    bytes_r = read(fd, b, sizeof(b));
    if (bytes_r <= 0)
        return bytes_r;

    b[bytes_r] = '\0';
    l = &b[0];

    while (l < &b[bytes_r]) {
        nl = strchr(l, '\n');
        if (!nl)
            break;

        *nl = '\0';
        parse_agentdata_line(l, data);

        l = nl + 1;
    }

    return 0;
}

static void __attribute__((__noreturn__)) exec_agent(const struct agent_t *agent, uid_t uid, gid_t gid)
{
    char *namespace, *home;
    int cgroup_fd;
    struct passwd *pwd;

    /* each user's agents are namespaces by uid */
    if (asprintf(&namespace, "%d.agent", uid) < 0)
        err(EXIT_FAILURE, "failed to allocate memory");

    cgroup_fd = cg_open_controller("cpu", "envoy", cgroup_name, namespace, NULL);
    subsystem_set(cgroup_fd, "tasks", "0");
    free(namespace);
    close(cgroup_fd);

    if (setregid(gid, gid) < 0 || setreuid(uid, uid) < 0)
        err(EXIT_FAILURE, "unable to drop to uid=%u gid=%u\n", uid, gid);

    pwd = getpwuid(uid);
    if (pwd == NULL || pwd->pw_dir == NULL)
        err(EXIT_FAILURE, "failed to lookup passwd entry");

    /* setup the most minimal environment */
    if (asprintf(&home, "HOME=%s", pwd->pw_dir) < 0)
        err(EXIT_FAILURE, "failed to allocate memory");

    char *env[] = {
        "PATH=/usr/local/bin:/usr/bin:/bin",
        home, NULL
    };

    execve(agent->argv[0], agent->argv, env);
    err(EXIT_FAILURE, "failed to start %s", agent->name);
}

int run_agent(struct agent_data_t *data, uid_t uid, gid_t gid)
{
    const struct agent_t *agent = &Agent[data->type];
    int fd[2], stat = 0, rc = 0;

    data->status = ENVOY_STARTED;
    data->sock[0] = '\0';
    data->gpg[0] = '\0';

    printf("Starting %s for uid=%u gid=%u.\n", agent->name, uid, gid);

    if (pipe(fd) < 0)
        err(EXIT_FAILURE, "failed to create pipe");

    switch (fork()) {
    case -1:
        err(EXIT_FAILURE, "failed to fork");
        break;
    case 0:
        dup2(fd[1], STDOUT_FILENO);
        close(fd[0]);
        close(fd[1]);

        exec_agent(agent, uid, gid);
        break;
    default:
        break;
    }

    if (wait(&stat) < 1)
        err(EXIT_FAILURE, "failed to get process status");

    if (stat) {
        rc = -1;
        data->pid = 0;
        data->status = ENVOY_FAILED;

        if (WIFEXITED(stat))
            fprintf(stderr, "%s exited with status %d.\n",
                    agent->name, WEXITSTATUS(stat));
        if (WIFSIGNALED(stat))
            fprintf(stderr, "%s terminated with signal %d.\n",
                    agent->name, WTERMSIG(stat));
    } else if (parse_agentdata(fd[0], data) < 0) {
        err(EXIT_FAILURE, "failed to parse %s output", agent->name);
    }

    close(fd[0]);
    close(fd[1]);
    return rc;
}

bool monitor_pid_alive(pid_t pid, uid_t uid)
{
    return pid_alive(pid, uid);
}

void init_monitor(void)
{
    int cgroup_fd = cg_open_subsystem("cpu");
    if (cgroup_fd < 0) {
        fprintf(stderr, "Failed to initialize cgroup subsystem! It's likely there's no kernel support.\n"
                "Falling back to a naive (and less than reliable) method of process management...\n");
        pid_alive = fallback_alive;
        return;
    }

    if (asprintf(&cgroup_name, "%d.monitor", getpid()) < 0)
        err(EXIT_FAILURE, "failed to allocate memory");

    kill_agent = cgroup_cleanup;
    pid_alive = pid_in_cgroup;
    close(cgroup_fd);
}

void kill_monitor(struct agent_info_t *agents)
{
    if (kill_agent) {
        while (agents) {
            if (agents->d.pid <= 0)
                continue;
            kill_agent(agents->uid);
            agents = agents->next;
        }

        if (cg_destroy_controller("cpu", "envoy", cgroup_name, NULL) < 0)
            warn("failed to close envoy's process cgroup");

        if (cg_destroy_controller("cpu", "envoy", NULL) < 0 && errno != EBUSY)
            warn("failed to close envoy's cgroup");
    }
}
