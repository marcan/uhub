/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2013, Jan Vidar Krey
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

#define CBUF_FLAG_CONST_BUFFER 0x01

struct cbuffer
{
	size_t capacity;
	size_t size;
	size_t flags;
	char* buf;
};

extern struct cbuffer* cbuf_create(size_t capacity)
{
	struct cbuffer* buf = hub_malloc(sizeof(struct cbuffer));
	buf->capacity = capacity;
	buf->size = 0;
	buf->flags = 0;
	buf->buf = hub_malloc(capacity + 1);
	buf->buf[0] = '\0';
	return buf;
}

struct cbuffer* cbuf_create_const(const char* buffer)
{
	struct cbuffer* buf = hub_malloc(sizeof(struct cbuffer));
	buf->capacity = 0;
	buf->size = strlen(buffer);
	buf->flags = CBUF_FLAG_CONST_BUFFER;
	buf->buf = (char*) buffer;
	return buf;
}

void cbuf_destroy(struct cbuffer* buf)
{
	if (!(buf->flags & CBUF_FLAG_CONST_BUFFER))
	{
		hub_free(buf->buf);
	}
	hub_free(buf);
}

void cbuf_resize(struct cbuffer* buf, size_t capacity)
{
	cbuf_try_deconst(buf);
	uhub_assert(buf->flags == 0);
	buf->capacity = capacity;
	buf->buf = hub_realloc(buf->buf, capacity + 1);
}

void cbuf_deconst(struct cbuffer* buf)
{
	char *buffer;
	if (!(buf->flags & CBUF_FLAG_CONST_BUFFER))
	{
		return;
	}
	buf->capacity = buf->size;
	buf->flags = buf->flags & (~CBUF_FLAG_CONST_BUFFER);
	buffer = hub_malloc(buf->capacity + 1);
	memcpy(buffer, buf->buf, buf->size+1);
	buf->buf=buffer;
}

void cbuf_append_bytes(struct cbuffer* buf, const char* msg, size_t len)
{
	cbuf_try_deconst(buf);
	uhub_assert(buf->flags == 0);
	if (buf->size + len >= buf->capacity)
		cbuf_resize(buf, buf->size + len);

	memcpy(buf->buf + buf->size, msg, len);
	buf->size += len;
	buf->buf[buf->size] = '\0';
}

void cbuf_append(struct cbuffer* buf, const char* msg)
{
	size_t len = strlen(msg);
	cbuf_try_deconst(buf);
	uhub_assert(buf->flags == 0);
	cbuf_append_bytes(buf, msg, len);
}

void cbuf_append_format(struct cbuffer* buf, const char* format, ...)
{
#if defined(HAVE_VSCPRINTF)
	va_list args;
	int bytes;
	cbuf_try_deconst(buf);
	uhub_assert(buf->flags == 0);
	va_start(args, format);
	/*Get the needed size*/
	bytes = vscprintf(format, args);
	if (buf->size + bytes < buf->capacity)
		cbuf_resize(buf, buf->size + bytes);
	/*Do the call over the buffer ifself avoiding a memory copy*/
	snprintf(buf->buf + buf->size, bytes+1, format, args);
	buf->size += bytes;
	va_end(args);
#else
#if defined(HAVE_VASPRINTF)
	char *tmp;
#else
	static char tmp[1024];
#endif
	va_list args;
	int bytes;
	cbuf_try_deconst(buf);
	uhub_assert(buf->flags == 0);
	va_start(args, format);
#if defined(HAVE_VASPRINTF)
	bytes = vasprintf(&tmp, format, args);
#else
	bytes = vsnprintf(tmp, 1024, format, args);
#endif
	va_end(args);
	cbuf_append_bytes(buf, tmp, bytes);
#if defined(HAVE_VASPRINTF)
	free(tmp);
#endif
#endif
}

void cbuf_append_strftime(struct cbuffer* buf, const char* format, const struct tm* tm)
{
	static char tmp[1024];
	int bytes;
	cbuf_try_deconst(buf);
	uhub_assert(buf->flags == 0);
	bytes = strftime(tmp, sizeof(tmp), format, tm);
	cbuf_append_bytes(buf, tmp, bytes);
}

const char* cbuf_get(struct cbuffer* buf)
{
	return buf->buf;
}

size_t cbuf_size(struct cbuffer* buf)
{
	return buf->size;
}
