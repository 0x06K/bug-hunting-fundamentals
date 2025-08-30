#ifndef REQUEST_H
#define REQUEST_H

#include <stddef.h>

#define MAX_REQUEST_SIZE 8192
#define MAX_HEADER_COUNT 50
#define MAX_HEADER_SIZE 1024
#define MAX_METHOD_SIZE 16
#define MAX_PATH_SIZE 2048
#define MAX_VERSION_SIZE 16

typedef enum {
    METHOD_GET,
    METHOD_POST,
    METHOD_PUT,
    METHOD_DELETE,
    METHOD_HEAD,
    METHOD_OPTIONS,
    METHOD_UNKNOWN
} http_method_t;

typedef struct {
    char name[MAX_HEADER_SIZE];
    char value[MAX_HEADER_SIZE];
} http_header_t;

typedef struct {
    http_method_t method;
    char path[MAX_PATH_SIZE];
    char version[MAX_VERSION_SIZE];
    http_header_t headers[MAX_HEADER_COUNT];
    int header_count;
    char *body;
    size_t body_length;
    int valid;
} http_request_t;

// Request parsing functions
int request_parse(const char *raw_request, http_request_t *request);
http_method_t request_parse_method(const char *method_str);
int request_parse_headers(const char *header_section, http_request_t *request);
const char* request_get_header(const http_request_t *request, const char *name);
void request_free(http_request_t *request);
void request_init(http_request_t *request);

// Utility functions for request handling
const char* method_to_string(http_method_t method);

#endif // REQUEST_H
