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

#ifndef MONITOR_H
#define MONITOR_H

#include "envoyd.h"
#include <stdbool.h>

void init_monitor(void);
int run_agent(struct agent_data_t *data, uid_t uid, gid_t gid);
bool monitor_pid_alive(pid_t pid, uid_t uid);
void kill_monitor(struct agent_info_t *agents);

#endif
