/*
 * BSD 3-Clause License
 * 
 * Copyright (c) 2018 GitHub.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <jansson.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#define MAX_MESSAGE_SZ 1024
bool debug;

// outputs formatted logs to stdout or stderr

inline static int glb_log_out(FILE *f, const char *format, va_list log_data)
{
	int ret;

	ret = vfprintf(f, format, log_data);
	fflush(f);
	return ret;
}

// creates variable array of log message input and feeds to glb_log_out

inline static int glb_log(FILE *f, const char *format, ...)
{
	va_list log_data;
	int ret;

	va_start(log_data, format);
	ret = glb_log_out(f, format, log_data);
	va_end(log_data);
	return ret;
}

inline static void glb_log_level(const char *level, char *message)
{
	char *log_string;
	json_t *object;
	struct timespec ts;
	char timestamp[64];
	double f_ts;
	json_t *json_timestamp;
	json_t *json_level;
	json_t *json_message;

	object = json_object();
	clock_gettime(CLOCK_REALTIME, &ts);

	snprintf(timestamp, 64, "%ld.%ld", ts.tv_sec, ts.tv_nsec);

	f_ts = atof(timestamp);
	json_timestamp = json_real(f_ts);
	json_level = json_string(level);
	json_message = json_string(message);

	json_object_set(object, "timestamp", json_timestamp);
	json_object_set(object, "level", json_level);
	json_object_set(object, "message", json_message);

	log_string = json_dumps(object, 0);

	FILE *log_file = NULL;

	// log to stdout or stderr depending on log level
	// check if debug flag is set for additional logging

	if (strcmp(level, "error") == 0) {
		log_file = stderr;
		glb_log(log_file, "%s\n", log_string);
	} else if (strcmp(level, "debug") == 0) {
		if (debug) {
			log_file = stdout;
			glb_log(log_file, "%s\n", log_string);
		}
	} else {
		log_file = stdout;
		glb_log(log_file, "%s\n", log_string);
	}

	json_decref(json_timestamp);
	json_decref(json_level);
	json_decref(json_message);
	json_decref(object);
	free(log_string);
}

inline static void glb_log_info(const char *format, ...)
{
	va_list args;
	char message[MAX_MESSAGE_SZ];

	va_start(args, format);
	vsnprintf(message, MAX_MESSAGE_SZ, format, args);
	va_end(args);

	glb_log_level("info", message);
}

inline static void glb_log_debug(const char *format, ...)
{
	if (!debug) return;
	
	va_list args;
	char message[MAX_MESSAGE_SZ];

	va_start(args, format);
	vsnprintf(message, MAX_MESSAGE_SZ, format, args);
	va_end(args);

	glb_log_level("debug", message);
}

inline static void glb_log_error(const char *format, ...)
{
	va_list args;
	char message[MAX_MESSAGE_SZ];

	va_start(args, format);
	vsnprintf(message, MAX_MESSAGE_SZ, format, args);
	va_end(args);

	glb_log_level("error", message);
}

inline static void glb_log_error_and_exit(const char *format, ...)
{
	va_list args;
	char message[MAX_MESSAGE_SZ];

	va_start(args, format);
	vsnprintf(message, MAX_MESSAGE_SZ, format, args);
	va_end(args);

	glb_log_level("error", message);

	exit(1);
}
