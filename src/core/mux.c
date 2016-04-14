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

struct hub_mux* mux_create(struct hub_info* hub, struct net_connection* con, struct ip_addr_encap* addr)
{
	struct hub_mux* mux = NULL;

	LOG_TRACE("mux_create(), hub=%p, con[sd=%d]", hub, net_con_get_sd(con));

	mux = (struct hub_mux*) hub_malloc_zero(sizeof(struct hub_mux));
	if (mux == NULL)
		return NULL; /* OOM */

	mux->send_queue = ioq_send_create();
	mux->recv_queue = ioq_recv_create();

	mux->connection = con;
	mux->users = list_create();
	net_con_reinitialize(mux->connection, net_event_mux, mux, NET_EVENT_READ);

	mux->hub = hub;
	return mux;
}

void mux_net_io_want_write(struct hub_mux* mux)
{
	if (mux->is_disconnecting)
		return;
	net_con_update(mux->connection, NET_EVENT_READ | NET_EVENT_WRITE);
}

void mux_net_io_want_read(struct hub_mux* mux)
{
	if (mux->is_disconnecting)
		return;
	net_con_update(mux->connection, NET_EVENT_READ);
}

static int mux_user_disconnected(struct hub_mux *mux, const char* line, size_t length)
{
	if (mux->is_disconnecting)
		return;

	sid_t sid = string_to_sid(line);
	struct hub_user* user = uman_get_user_by_sid(mux->hub->users, sid);

	if (!user)
	{
		LOG_WARN("received message from unknown user: %s", line);
		return 0;
	}

	hub_disconnect_user(user->hub, user, quit_disconnected);
}

static int mux_send(struct hub_mux *mux, struct adc_message *msg)
{
	if (mux->is_disconnecting)
		return 0;

	uhub_assert(msg->cache && *msg->cache);
	
	//LOG_WARN("%s", msg->cache);

	if (ioq_send_is_empty(mux->send_queue))
	{
		/* Perform oportunistic write */
		ioq_send_add(mux->send_queue, msg);
		handle_net_write_mux(mux);
	}
	else
	{
		ioq_send_add(mux->send_queue, msg);
		mux_net_io_want_write(mux);
	}
	return 1;
	
}

int mux_send_to_user(struct hub_mux *mux, struct hub_user *user, struct adc_message *msg)
{
	int ret;
	if (mux->is_disconnecting)
		return 0;

	uhub_assert(msg->cache && *msg->cache);

	msg = adc_msg_copy(msg);

	if(!adc_msg_grow(msg, msg->length + 7))
		return 0;
	
	memmove(&msg->cache[7], msg->cache, msg->length);
	msg->cache[0] = 'M';
	msg->cache[1] = ' ';
	memcpy(&msg->cache[2], sid_to_string(user->id.sid), 4);
	msg->cache[6] = ' ';
	msg->length += 7;

	ret = mux_send(mux, msg);
	adc_msg_free(msg);
	return ret;
}

int mux_broadcast(struct hub_mux *mux, struct adc_message *msg)
{
	int ret;
	if (mux->is_disconnecting)
		return 0;

	uhub_assert(msg->cache && *msg->cache);

	msg = adc_msg_copy(msg);

	if(!adc_msg_grow(msg, msg->length + 2))
		return 0;
	
	memmove(&msg->cache[2], msg->cache, msg->length);
	msg->cache[0] = 'B';
	msg->cache[1] = ' ';
	msg->length += 2;

	ret = mux_send(mux, msg);
	adc_msg_free(msg);
	return ret;
}

static void mux_notify_user(struct hub_mux *mux, struct hub_user* user, char type)
{
	if (mux->is_disconnecting)
		return;

	/* FIXME: evil, but this way we can reuse the ioqueue stuff unchanged */
	struct adc_message* msg = adc_msg_construct(0, 2);
	
	msg->cache[0] = type;
	msg->cache[1] = ' ';
	memcpy(&msg->cache[2], sid_to_string(user->id.sid), 4);
	msg->cache[6] = '\n';
	msg->length = 7;
	msg->cache[msg->length] = 0;

	mux_send(mux, msg);
	adc_msg_free(msg);
}

static int mux_new_user(struct hub_mux *mux, const char* line, size_t length)
{
	struct ip_addr_encap raw_addr;
	if (ip_convert_to_binary(line, &raw_addr) < 0)
	{
		LOG_WARN("invalid IP address: %s", line);
		/* This will cause a state lockup, so kill the connection */
		return quit_protocol_error;
	}

	struct hub_user* user = user_create(mux->hub, NULL, &raw_addr);
	if (!user) /* OOM */
		return quit_protocol_error;

	user->mux = mux;
	/* We need a SID early */
	uman_get_free_sid(mux->hub->users, user);
	list_append(mux->users, user);
	mux_notify_user(mux, user, '+');
	return 0;
}

void mux_disconnect_user(struct hub_mux *mux, struct hub_user* user)
{
	if (mux->is_disconnecting)
		return;

	mux_notify_user(mux, user, '-');
	list_remove(mux->users, user);
}

static int mux_message_from_user(struct hub_mux *mux, const char* line, size_t length)
{
	char* p = memchr(line, ' ', length);
	if (!p)
	{
		LOG_WARN("invalid mux message: %s", line);
		return 0;
	}

	p[0] = '\0';

	sid_t sid = string_to_sid(line);
	struct hub_user* user = uman_get_user_by_sid(mux->hub->users, sid);

	if (!user)
	{
		LOG_WARN("received message from unknown user: %s", line);
		return 0;
	}

	if (hub_handle_message(user->hub, user, p + 1, length - (p - line + 1)))
		hub_disconnect_user(user->hub, user, quit_protocol_error);

	return 0;
}

int mux_handle_message(struct hub_mux* mux, const char* line, size_t length)
{

	//LOG_TRACE("mux_handle_message(%s)", line);

	if (mux->is_disconnecting)
		return 0;

	if (length == 4 && memcmp(line, "MUX0", 4) == 0)
	{
		/* Hello */
		return 0;
	}

	if (length < 2 || line[1] != ' ')
	{
		LOG_WARN("invalid mux message: %s", line);
		return 0;
	}

	switch (line[0]) {
		case '+':
			/* New user (connect) */
			return mux_new_user(mux, &line[2], length - 2);
		case '-':
			/* Disconnect user */
			return mux_user_disconnected(mux, &line[2], length - 2);
		case 'M':
			/* Message from user */
			return mux_message_from_user(mux, &line[2], length - 2);
		default:
			LOG_WARN("invalid mux message: %s", line);
			return 0;
	}
}

static void disconnect_user(void* ptr)
{
	if (ptr)
	{
		struct hub_user* user = (struct hub_user*) ptr;
		hub_disconnect_user(user->hub, user, quit_disconnected);
	}
}

static void clear_user(void* ptr)
{
	if (ptr)
	{
		struct hub_user* u = (struct hub_user*) ptr;

		/* Mark the user as already being disconnected.
		 * This prevents the hub from trying to send
		 * quit messages to other users.
		 */
		u->credentials = auth_cred_none;
		user_destroy(u);
	}
}

void mux_disconnect(struct hub_mux *mux)
{
	mux->is_disconnecting = 1;

	list_clear(mux->users, &disconnect_user);

	mux_destroy(mux);
}

void mux_destroy(struct hub_mux *mux)
{
	mux->is_disconnecting = 1;

	ioq_recv_destroy(mux->recv_queue);
	ioq_send_destroy(mux->send_queue);

	net_shutdown_r(net_con_get_sd(mux->connection));
	net_con_close(mux->connection);
	mux->connection = 0;
	
	list_clear(mux->users, &clear_user);
	list_destroy(mux->users);
	hub_free(mux);
}
