/*
 * Originally from: https://github.com/romanbsd/statsd-c-client
 *
 * Copyright (c) 2012 Roman Shterenzon
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define _H_STATSD_CLIENT
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

struct _statsd_link {
	struct sockaddr_in server;
	int sock;
	char *ns;
};

typedef struct _statsd_link statsd_link;

statsd_link *statsd_init(const char *host, int port);
statsd_link *statsd_init_with_namespace(const char *host, int port,
					const char *ns);
void statsd_finalize(statsd_link *link);

/*
  write the stat line to the provided buffer,
  type can be "c", "g" or "ms"
  lf - whether line feed needs to be added
 */
void statsd_prepare(statsd_link *link, const char *stat, size_t value,
		    const char *type, float sample_rate, char *buf,
		    size_t buflen, int lf, char *tag);

/* manually send a message, which might be composed of several lines. Must be
 * null-terminated */
int statsd_send(statsd_link *link, const char *message);

int statsd_inc(statsd_link *link, const char *stat, float sample_rate, char *tag);
int statsd_dec(statsd_link *link, const char *stat, float sample_rate, char *tag);
int statsd_count(statsd_link *link, const char *stat, size_t count, float sample_rate,
		 char *tag);
int statsd_gauge(statsd_link *link, const char *stat, size_t value, char *tag);
int statsd_timing(statsd_link *link, const char *stat, size_t ms, char *tag);
