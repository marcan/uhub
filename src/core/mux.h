/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2015-2013, Hector Martin
 *
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "uhub.h"

struct hub_mux
{
	struct linked_list*    users;
	struct hub_info*        hub;                /** The hub instance this user belong to */
	void* ptr;
	struct ioq_recv*        recv_queue;
	struct ioq_send*        send_queue;
	struct net_connection*  connection;         /** Connection data */
	int is_disconnecting;
};

extern void mux_net_io_want_write(struct hub_mux* mux);
extern void mux_net_io_want_read(struct hub_mux* mux);

extern struct hub_mux* mux_create(struct hub_info* hub, struct net_connection* con, struct ip_addr_encap* addr);

extern int mux_handle_message(struct hub_mux* mux, const char* line, size_t length);

extern void mux_disconnect_user(struct hub_mux* mux, struct hub_user* user);
extern int mux_send_to_user(struct hub_mux *mux, struct hub_user *user, struct adc_message *msg);
extern int mux_broadcast(struct hub_mux *mux, struct adc_message *msg);

extern void mux_destroy(struct hub_mux* mux);
extern void mux_disconnect(struct hub_mux* mux);
