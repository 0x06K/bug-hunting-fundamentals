#ifndef RESPONSE_H
#define RESPONSE_H

#include <stddef.h>

#define MAX_RESPONSE_SIZE 65536
#define MAX_HEADERS 20
#define MAX_HEADER_LINE 256

typedef enum {
    STATUS_OK = 200,
    STATUS_CREATED = 201,
    STATUS_NO_CONTENT = 204,
    STATUS_MOVED_PERMANENTLY = 301,
    STATUS_FOUND = 302,
    STATUS_NOT_MODIFIED = 304,
    STATUS_BAD_REQUEST = 400,
    STATUS_UNAUTHORIZED = 401,
    STATUS_FORBIDDEN = 403,
    STATUS_NOT_FOUND = 404,
    STATUS_METHOD_NOT_ALLOWED = 405,
    STATUS_INTERNAL_SERVER_ERROR = 500,
    STATUS_NOT_IMPLEMENTED = 501,
    STATUS_SERVICE_UNAVAILABLE = 503
} http_status_t;

typedef struct {
    char name[MAX_HEADER_LINE];
    char value[MAX_HEADER_LINE];
} response_header_t;

typedef struct {
    http_status_t status_code;
    response_header_t headers[MAX_HEADERS];
    int header_count;
    char *body;
    size_t body_length;
    char *content_type;
} http_response_t;

// Response building functions
void response_init(http_response_t *response);
void response_set_status(http_response_t *response, http_status_t status);
void response_add_header(http_response_t *response, const char *name, const char *value);
void response_set_body(http_response_t *response, const char *body, size_t length);
void response_set_content_type(http_response_t *response, const char *content_type);
int response_build(const http_response_t *response, char *buffer, size_t buffer_size);
void response_free(http_response_t *response);

// Convenience functions for common responses
void response_set_text(http_response_t *response, const char *text);
void response_set_html(http_response_t *response, const char *html);
void response_set_json(http_response_t *response, const char *json);
void response_set_file(http_response_t *response, const char *filepath);

// Status code utilities
const char* status_code_to_string(http_status_t status);

#endif // RESPONSE_H
