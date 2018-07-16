#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <arpa/inet.h>

#include "debug.h"

typedef unsigned char uint8_t;

extern int default_level;
/** @internal
  Do not use directly, use the debug macro */
	void
_debug(const char *filename, int line, int level, const char *format, ...)
{
	char buf[28];
	va_list vlist;
	time_t ts;

	time(&ts);

	if (default_level >= level) {
		if (level <= LOG_WARNING) {
			fprintf(stderr, "[%d][%.24s][%u](%s:%d) ", level, ctime_r(&ts, buf), getpid(),
					filename, line);
			va_start(vlist, format);
			vfprintf(stderr, format, vlist);
			va_end(vlist);
			fputc('\n', stderr);
		} else if (DAEMON) {
			fprintf(stdout, "[%d][%.24s][%u](%s:%d) ", level, ctime_r(&ts, buf), getpid(),
					filename, line);
			va_start(vlist, format);
			vfprintf(stdout, format, vlist);
			va_end(vlist);
			fputc('\n', stdout);
			fflush(stdout);
		}

		if (LOG_TO_SYSLOG) {
			openlog("WDS-SON", LOG_PID, LOG_DAEMON);
			va_start(vlist, format);
			vsyslog(level, format, vlist);
			va_end(vlist);
			closelog();
		}
	}
}

void hexdump(const uint8_t *data, int32_t len)
{
	int32_t i;
	uint8_t *temp = (uint8_t *)malloc(len * 6);
		
	if(LOG_TO_SYSLOG){
		for(i = 0; i < len; i++){
			snprintf(temp + i * 3,  len * 6 - i * 3, "%02x ", data[i]);
		}
		openlog("WDS-SON", LOG_PID, LOG_DAEMON);
		syslog(LOG_INFO, "hexdump length: %d", len);
		syslog(LOG_INFO, "%s", temp);
		closelog();
		free(temp);
	}
}

