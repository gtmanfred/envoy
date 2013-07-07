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

#define PAM_SM_SESSION

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gpgme.h>
#include <locale.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/_pam_macros.h>

#include "lib/envoy.h"

#define UNUSED           __attribute__((unused))
#define PAM_LOG_ERR      LOG_AUTHPRIV | LOG_ERR
#define PAM_LOG_WARNING  LOG_AUTHPRIV | LOG_WARNING

#define ENV_ITEM(n) { (n), #n }
static struct {
    int item;
    const char *name;
} env_items[] = {
    ENV_ITEM(PAM_SERVICE),
    ENV_ITEM(PAM_USER),
    ENV_ITEM(PAM_TTY),
    ENV_ITEM(PAM_RHOST),
    ENV_ITEM(PAM_RUSER),
};

struct fingers {
	char *fingerprint;
	struct fingers *next;
};

static int __attribute__((format (printf, 2, 3))) pam_setenv(pam_handle_t *ph, const char *fmt, ...)
{
    va_list ap;
    int nbytes;
    char *line = NULL;

    va_start(ap, fmt);
    nbytes = vasprintf(&line, fmt, ap);
    va_end(ap);

    if (nbytes < 0)
        return -1;

    pam_putenv(ph, line);
    free(line);
    return 0;
}

static int set_privileges(bool drop, uid_t *uid, gid_t *gid)
{
    uid_t tmp_uid = geteuid();
    gid_t tmp_gid = getegid();

    if (drop && tmp_uid == *uid)
        return false;

    if (setegid(*gid) < 0 || seteuid(*uid) < 0) {
        if (drop) {
            syslog(PAM_LOG_ERR, "pam-envoy: failed to set privileges to uid=%d gid=%d: %s",
                   *uid, *gid, strerror(errno));
        }
        return false;
    }

    *uid = tmp_uid;
    *gid = tmp_gid;
    return true;
}

static int pam_get_agent(struct agent_data_t *data, enum agent id, uid_t uid, gid_t gid)
{
    int ret;
    bool dropped = set_privileges(true, &uid, &gid);

    ret = envoy_agent(data, id, true);
    if (ret < 0)
        syslog(PAM_LOG_ERR, "failed to fetch agent: %s", strerror(errno));

    switch (data->status) {
        case ENVOY_STOPPED:
        case ENVOY_STARTED:
        case ENVOY_RUNNING:
            break;
        case ENVOY_FAILED:
            syslog(PAM_LOG_ERR, "agent failed to start, check envoyd's log");
        case ENVOY_BADUSER:
            syslog(PAM_LOG_ERR, "connection rejected, user is unauthorized to use this agent");
    }

    if (dropped) {
        set_privileges(false, &uid, &gid);
    }

    return ret;
}

static int unlock_keys( char *preset[], char **envlist, char *fpr) {
	preset[6] = fpr;
	execve(preset[0], preset, envlist);
	return 0;
}

int do_free(struct fingers *fpr){
	if (fpr->fingerprint == NULL){
		free(fpr);
		return 0;
	}
	do_free(fpr->next);
	free(fpr);
	return 0;
}
static int __attribute__((format (printf, 3, 4))) gpg_send_message(struct fingers *fpr, int fd, const char *fmt, ...)
{ 
	va_list ap;
    int nbytes;
    char buf[BUFSIZ];
	char *lines = NULL;
	char *fingerprint = NULL;
	struct fingers *tmp = fpr;

    va_start(ap, fmt);
    nbytes = vdprintf(fd, fmt, ap);
    va_end(ap);

    if (nbytes < 0)
        return -1;

    if (read(fd, buf, BUFSIZ) < 0)
        return -1;

	lines = buf;

	while(1){
		char buffer[100];
		int n;
		sscanf(lines, " %99[^\n]%n", buffer, &n);
		if (strlen(buffer) <= 3)
			break;
		fingerprint = strtok(lines, " ");
		fingerprint = strtok(NULL, " ");
		fingerprint = strtok(NULL, " ");
		fpr->fingerprint = fingerprint;
		fpr->next = malloc( sizeof(struct fingers));
		fpr = fpr->next;
		lines += n;
	}
	fpr->fingerprint = NULL;
	fpr = tmp;

    return !strncmp(buf, "OK\n", 3);
}

static int unlock_sshkey_fingerprints( char *preset[], char **envlist) {
    char buf[BUFSIZ], *split;
	struct agent_data_t data;
	const char *sock;
	struct fingers *fpr;
	fpr = malloc( sizeof(struct fingers));
	pid_t pid;

	get_agent(&data, AGENT_DEFAULT, true);
	sock = data.gpg;

    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    size_t len;
    socklen_t sa_len;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0), nbytes;
    if (fd < 0) {
        warn("couldn't create socket");
        return -1;
    }

    split = strchr(sock, ':');
    len = split - sock;

    sa.un = (struct sockaddr_un){ .sun_family = AF_UNIX };
    memcpy(&sa.un.sun_path, sock, len);

    sa_len = len + sizeof(sa.un.sun_family);
    if (connect(fd, &sa.sa, sa_len) < 0) {
        warn("failed to connect to gpg-agent");
        return -1;
    }

    nbytes = read(fd, buf, BUFSIZ);
    if (nbytes < 0)
        err(EXIT_FAILURE, "failed to read from gpg-agent socket");

    if (strncmp(buf, "OK", 2) != 0) {
        warnx("incorrect response from gpg-agent");
        return -1;
    }

	gpg_send_message(fpr, fd, "KEYINFO --list\n");
	while(fpr->fingerprint != NULL) {
		pid = fork();
		if (pid == 0)
			unlock_keys(preset, envlist, fpr->fingerprint);
	}
	
	do_free(fpr);
	return  0;
}


static gpgme_key_t get_fingerprints(){
	gpgme_error_t err;
	gpgme_ctx_t ctx;
	gpgme_key_t key;

	gpgme_check_version (NULL);
	setlocale (LC_ALL, "");
	gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));

	err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
	if (err) {
		fprintf (stderr, "%s: %s", gpgme_strsource(err), gpgme_strerror(err));
		exit(1);
	}

	err = gpgme_new (&ctx);
	if (err) {
		fprintf (stderr, "%s: %s", gpgme_strsource(err), gpgme_strerror(err));
		exit(1);
	}

	err = gpgme_op_keylist_start (ctx, NULL, 0);
	if (err) {
		fprintf (stderr, "%s: %s", gpgme_strsource(err), gpgme_strerror(err));
		exit(1);
	}

	err = gpgme_op_keylist_next(ctx, &key);
	if (err) {
		fprintf (stderr, "%s: %s", gpgme_strsource(err), gpgme_strerror(err));
		exit(1);
	}

	return key;
}




PAM_EXTERN int pam_sm_authenticate (pam_handle_t *pamh, int flags UNUSED,
                     int argc UNUSED, const char **argv UNUSED)
{

    const void *void_pass;
    int retval;
    int call_setuid = 0;
	char * preset[] = {"/usr/lib/gnupg/gpg-preset-passphrase", "-v", "-c", "-p",  NULL, NULL, NULL};
    int fds[2];
    pid_t pid;
	gpgme_subkey_t key;

    retval = pam_get_item (pamh, PAM_AUTHTOK, &void_pass);
    if (retval != PAM_SUCCESS) {
        return retval;
    } else if (void_pass == NULL) {
        char *resp = NULL;

        retval = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF,
                             &resp, "Password: ");

        if (retval != PAM_SUCCESS) {
            _pam_drop (resp);
            if (retval == PAM_CONV_AGAIN)
                retval = PAM_INCOMPLETE;
            return retval;
        }

        pam_set_item (pamh, PAM_AUTHTOK, resp);
        preset[4] = strdupa (resp);
        _pam_drop (resp);
    } else {
        preset[4] = strdup(void_pass);
    }

    if (pipe(fds) != 0) {
        pam_syslog (pamh, LOG_ERR, "Could not create pipe: %m");
        return PAM_SYSTEM_ERR;
    }

    pid = fork();
    if (pid == -1)
        return PAM_SYSTEM_ERR;

    if (pid > 0) { /* parent */
        int status = 0;
        if (preset[4] != NULL) { /* send password to the child */
            if (write(fds[1], preset[4], strlen(preset[4])+1) == -1)
                pam_syslog(pamh, LOG_ERR, "sending password to child failed: %m");
            preset[4] = NULL;
        } else {
            if (write(fds[1], "", 1) == -1) /* blank password */
                pam_syslog(pamh, LOG_ERR, "sending password to child failed: %m");
        }
        close(fds[0]);
        close(fds[1]);
        while ((retval = waitpid (pid, &status, 0)) == -1 && errno == EINTR);
        if (retval == (pid_t)-1) {
            pam_syslog (pamh, LOG_ERR, "waitpid returns with -1: %m");
            return PAM_SYSTEM_ERR;
        } else if (status != 0) {
            if (WIFEXITED(status)) {
                pam_syslog (pamh, LOG_ERR, "%s failed: exit code %d",
                            preset, WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                pam_syslog (pamh, LOG_ERR, "%s failed: caught signal %d%s",
                            preset, WTERMSIG(status),
                            WCOREDUMP(status) ? " (core dumped)" : "");
            } else {
                pam_syslog (pamh, LOG_ERR, "%s failed: unknown status 0x%x",
                            preset, status);
            }
            return PAM_SYSTEM_ERR;
        }
        return PAM_SUCCESS;
    } else /* child */ {
        int i;
        char **envlist, **tmp;
        int envlen, nitems;
        char *envstr;

        /* reopen stdin as pipe */
        if (dup2(fds[0], STDIN_FILENO) == -1) {
            int err = errno;
            pam_syslog (pamh, LOG_ERR, "dup2 of STDIN failed: %m");
            _exit (err);
        }

        for (i = 0; i < sysconf (_SC_OPEN_MAX); i++) {
            if (i != STDIN_FILENO)
                close (i);
        }

        /* New stdout and stderr.  */
        if ((i = open ("/dev/null", O_RDWR)) < 0) {
            int err = errno;
            pam_syslog (pamh, LOG_ERR, "open of /dev/null failed: %m");
            _exit (err);
        }

        if (dup (i) == -1) {
            int err = errno;
            pam_syslog (pamh, LOG_ERR, "dup failed: %m");
            _exit (err);
        }

        if (call_setuid)
            if (setuid (geteuid ()) == -1) {
                int err = errno;
                pam_syslog (pamh, LOG_ERR, "setuid(%lu) failed: %m",
                            (unsigned long) geteuid ());
                _exit (err);
            }

        if (setsid () == -1) {
            int err = errno;
            pam_syslog (pamh, LOG_ERR, "setsid failed: %m");
            _exit (err);
        }

        /*
         * Set up the child's environment list.  It consists of the PAM
         * environment, plus a few hand-picked PAM items.
         */
        envlist = pam_getenvlist(pamh);
        for (envlen = 0; envlist[envlen] != NULL; ++envlen)
            /* nothing */ ;
        nitems = sizeof(env_items) / sizeof(*env_items);
        /* + 2 because of PAM_TYPE and NULL entry */
        tmp = realloc(envlist, (envlen + nitems + 2) * sizeof(*envlist));
        if (tmp == NULL) {
            free(envlist);
            pam_syslog (pamh, LOG_ERR, "realloc environment failed: %m");
            _exit (ENOMEM);
        }
        envlist = tmp;
        for (i = 0; i < nitems; ++i) {
            const void *item;

            if (pam_get_item(pamh, env_items[i].item, &item) != PAM_SUCCESS || item == NULL)
                continue;
            if (asprintf(&envstr, "%s=%s", env_items[i].name, (const char *)item) < 0) {
                free(envlist);
                pam_syslog (pamh, LOG_ERR, "prepare environment failed: %m");
                _exit (ENOMEM);
            }
            envlist[envlen++] = envstr;
            envlist[envlen] = NULL;
        }

        if (asprintf(&envstr, "PAM_TYPE=%s", "auth") < 0) {
            free(envlist);
            pam_syslog (pamh, LOG_ERR, "prepare environment failed: %m");
            _exit (ENOMEM);
        }
        envlist[envlen++] = envstr;
        envlist[envlen] = NULL;

		key = get_fingerprints()->subkeys;
		do {
			pid = fork();
			if (pid == 0)
				unlock_keys(preset, envlist, key->fpr);
		} while((key = key->next) != NULL);

		//unlock_sshkey_fingerprints(preset, envlist);
        i = errno;
        pam_syslog (pamh, LOG_ERR, "execve(%s,...) failed: %m", preset);
        free(envlist);
        _exit (i);
    }

    return PAM_SYSTEM_ERR;

}

/* PAM entry point for session creation */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *ph, int UNUSED flags,
                                   int argc, const char **argv)
{
    struct agent_data_t data;
    const struct passwd *pwd;
    const char *user;
    enum agent id = AGENT_DEFAULT;
    int ret;

    ret = pam_get_user(ph, &user, NULL);
    if (ret != PAM_SUCCESS) {
        syslog(PAM_LOG_ERR, "pam-envoy: couldn't get the user name: %s",
               pam_strerror(ph, ret));
        return PAM_SERVICE_ERR;
    }

    pwd = getpwnam(user);
    if (!pwd) {
        syslog(PAM_LOG_ERR, "pam-envoy: error looking up user information: %s",
               strerror(errno));
        return PAM_SERVICE_ERR;
    }

    if (argc > 1) {
        syslog(PAM_LOG_WARNING, "pam-envoy: too many arguments");
        return PAM_SUCCESS;
    } else if (argc == 1) {
        id = lookup_agent(argv[0]);
    }

    if (pam_get_agent(&data, id, pwd->pw_uid, pwd->pw_gid) < 0) {
        syslog(PAM_LOG_WARNING, "pam-envoy: failed to get agent for user");
        return PAM_SUCCESS;
    }

    if (data.type == AGENT_GPG_AGENT) {
        pam_setenv(ph, "GPG_AGENT_INFO=%s", data.gpg);
    }

    pam_setenv(ph, "SSH_AUTH_SOCK=%s", data.sock);
    pam_setenv(ph, "SSH_AGENT_PID=%d", data.pid);

    return PAM_SUCCESS;
}

/* PAM entry point for session cleanup */
PAM_EXTERN int pam_sm_close_session(pam_handle_t UNUSED *ph, int UNUSED flags,
                                    int UNUSED argc, const char UNUSED **argv)
{
    return PAM_IGNORE;
}

/* PAM entry point for setting user credentials (that is, to actually
 * establish the authenticated user's credentials to the service
 * provider) */
PAM_EXTERN int pam_sm_setcred(pam_handle_t UNUSED *ph, int UNUSED flags,
                              int UNUSED argc, const char UNUSED **argv)
{
    return PAM_IGNORE;
}

/* PAM entry point for authentication token (password) changes */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t UNUSED *ph, int UNUSED flags,
                                int UNUSED argc, const char UNUSED **argv)
{
    return PAM_IGNORE;
}

// vim: et:sts=4:sw=4:cino=(0
