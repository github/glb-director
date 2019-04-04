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

#include "statsd-client.h"
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_MSG_LEN 100

statsd_link *statsd_init_with_namespace(const char *host, int port,
					const char *ns_)
{
	if (!host || !port || !ns_)
		return NULL;

	size_t len = strlen(ns_);

	statsd_link *temp = statsd_init(host, port);
	if (!temp)
		return NULL;

	if ((temp->ns = malloc(len + 2)) == NULL) {
		perror("malloc");
		return NULL;
	}
	strcpy(temp->ns, ns_);
	temp->ns[len++] = '.';
	temp->ns[len] = 0;

	return temp;
}

statsd_link *statsd_init(const char *host, int port)
{
	if (!host || !port)
		return NULL;

	statsd_link *temp = calloc(1, sizeof(statsd_link));
	if (!temp) {
		fprintf(stderr, "calloc() failed");
		goto err;
	}

	if ((temp->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		perror("socket");
		goto err;
	}

	memset(&temp->server, 0, sizeof(temp->server));
	temp->server.sin_family = AF_INET;
	temp->server.sin_port = htons(port);

	struct addrinfo *result = NULL, hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	int error;
	if ((error = getaddrinfo(host, NULL, &hints, &result))) {
		fprintf(stderr, "%s\n", gai_strerror(error));
		goto err;
	}
	memcpy(&(temp->server.sin_addr),
	       &((struct sockaddr_in *)result->ai_addr)->sin_addr,
	       sizeof(struct in_addr));
	freeaddrinfo(result);

	srandom(time(NULL));

	return temp;

err:
	if (temp) {
		free(temp);
	}

	return NULL;
}

void statsd_finalize(statsd_link *link)
{
	if (!link)
		return;

	// close socket
	if (link->sock != -1) {
		close(link->sock);
		link->sock = -1;
	}

	// freeing ns
	if (link->ns) {
		free(link->ns);
		link->ns = NULL;
	}

	// free whole link
	free(link);
}

/* will change the original string */
static void cleanup(char *dst_stat, const char *stat, int dst_size)
{
	int i;
	for (i = 0; i < dst_size - 1; i++) {
		char c = stat[i];

		if (c == ':' || c == '|' || c == '@') {
			c = '_';
		}

		dst_stat[i] = c;

		if (c == 0) {
			return; // we're done and terminated
		}
	}
	dst_stat[i] = 0;
}

static int should_send(float sample_rate)
{
	if (sample_rate < 1.0) {
		float p = ((float)random() / RAND_MAX);
		return sample_rate > p;
	} else {
		return 1;
	}
}

int statsd_send(statsd_link *link, const char *message)
{
	if (!link)
		return -2;
	int slen = sizeof(link->server);

	if (sendto(link->sock, message, strlen(message), 0,
		   (struct sockaddr *)&link->server, slen) == -1) {
		perror("sendto");
		return -1;
	}
	return 0;
}

static int send_stat(statsd_link *link, const char *stat, size_t value,
		     const char *type, float sample_rate, char *tag)
{
	char message[MAX_MSG_LEN];
	if (!should_send(sample_rate)) {
		return 0;
	}

	statsd_prepare(link, stat, value, type, sample_rate, message,
		       MAX_MSG_LEN, 0, tag);

	return statsd_send(link, message);
}

void statsd_prepare(statsd_link *link, const char *stat, size_t value,
		    const char *type, float sample_rate, char *message,
		    size_t buflen, int lf, char *tag)
{
	if (!link)
		return;

	char stat_cleaned[64];
	cleanup(stat_cleaned, stat, sizeof(stat_cleaned));
	if (sample_rate == 1.0) {
		snprintf(message, buflen, "%s%s:%zd|%s|#%s%s",
			 link->ns ? link->ns : "", stat_cleaned, value, type, tag,
			 lf ? "\n" : "");
	} else {
		snprintf(message, buflen, "%s%s:%zd|%s|@%.2f|#%s%s",
			 link->ns ? link->ns : "", stat_cleaned, value, type,
			 sample_rate, tag, lf ? "\n" : "");
	}
}

/* public interface */
int statsd_count(statsd_link *link, const char *stat, size_t value, float sample_rate,
		 char *tag)
{
	return send_stat(link, stat, value, "c", sample_rate, tag);
}

int statsd_dec(statsd_link *link, const char *stat, float sample_rate, char *tag)
{
	return statsd_count(link, stat, -1, sample_rate, tag);
}

int statsd_inc(statsd_link *link, const char *stat, float sample_rate, char *tag)
{
	return statsd_count(link, stat, 1, sample_rate, tag);
}

int statsd_gauge(statsd_link *link, const char *stat, size_t value, char *tag)
{
	return send_stat(link, stat, value, "g", 1.0, tag);
}

int statsd_timing(statsd_link *link, const char *stat, size_t ms, char *tag)
{
	return send_stat(link, stat, ms, "ms", 1.0, tag);
}
