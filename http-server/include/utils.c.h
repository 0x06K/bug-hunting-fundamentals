#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdio.h>

// Logging levels
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} log_level_t;

// String utilities
char* str_trim(char *str);
char* str_trim_left(char *str);
char* str_trim_right(char *str);
int str_starts_with(const char *str, const char *prefix);
int str_ends_with(const char *str, const char *suffix);
char* str_to_lower(char *str);
char* str_to_upper(char *str);
char* str_duplicate(const char *str);

// URL utilities
char* url_decode(const char *encoded);
char* url_encode(const char *str);
void parse_query_string(const char *query, char params[][2][256], int *param_count, int max_params);

// File utilities
int file_exists(const char *filepath);
long file_size(const char *filepath);
char* file_read_all(const char *filepath, size_t *size);
const char* get_mime_type(const char *filepath);

// Network utilities
int socket_set_nonblocking(int fd);
int socket_set_reuseaddr(int fd);
ssize_t socket_recv_all(int fd, char *buffer, size_t size, int timeout_ms);
ssize_t socket_send_all(int fd, const char *buffer, size_t size);

// Time utilities
void get_timestamp_string(char *buffer, size_t buffer_size);
void get_http_date_string(char *buffer, size_t buffer_size);

// Logging functions
void log_init(const char *log_file, log_level_t level);
void log_message(log_level_t level, const char *format, ...);
void log_debug(const char *format, ...);
void log_info(const char *format, ...);
void log_warn(const char *format, ...);
void log_error(const char *format, ...);
void log_cleanup(void);

// Memory utilities
void* safe_malloc(size_t size);
void* safe_calloc(size_t count, size_t size);
void* safe_realloc(void *ptr, size_t size);

// Error handling
void print_error(const char *message);
void print_errno(const char *message);

#endif // UTILS_H
