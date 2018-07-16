#ifndef __DEBUG_H_
#define __DEBUG_H_

/** @brief Used to output messages.
   *The messages will include the finlname and line number, and will be sent to syslog if so configured in the config file 
    */
#define debug(level, format...) _debug(__FILE__, __LINE__, level, format)
#define DAEMON 1
#define LOG_TO_SYSLOG 0

/** @internal */
void _debug(const char *filename, int line, int level, const char *format, ...);

void hexdump(const uint8_t *data, int32_t len);
#endif /* _DEBUG_H_ */

