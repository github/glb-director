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
