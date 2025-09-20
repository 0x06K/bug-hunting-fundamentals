#define _POSIX_C_SOURCE 200809L
#include "response.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <strings.h>  // For strncmp on POSIX systems


void response_init(http_response_t *response) {
    if (!response) return;
    
    response->status_code = STATUS_OK;
    memset(response->headers, 0, sizeof(response->headers));
    response->header_count = 0;
    response->body = NULL;
    response->body_length = 0;
    response->content_type = NULL;
}

void response_free(http_response_t *response) {
    if (!response) return;
    
    if (response->body) {
        free(response->body);
        response->body = NULL;
    }
    
    if (response->content_type) {
        free(response->content_type);
        response->content_type = NULL;
    }
    
    response->body_length = 0;
}

void response_set_status(http_response_t *response, http_status_t status) {
    if (response) {
        response->status_code = status;
    }
}

void response_add_header(http_response_t *response, const char *name, const char *value) {
    if (!response || !name || !value || response->header_count >= MAX_HEADERS) {
        return;
    }
    
    // Check if header already exists, update if so
    for (int i = 0; i < response->header_count; i++) {
        const char* tmp = name;
        size_t length = 0;
        while(*tmp != '\0'){ length++; tmp++; } 
        if (strncmp(response->headers[i].name, name, length) == 0) {
            strncpy(response->headers[i].value, value, MAX_HEADER_LINE - 1);
            response->headers[i].value[MAX_HEADER_LINE - 1] = '\0';
            return;
        }
    }
    
    // Add new header
    strncpy(response->headers[response->header_count].name, name, MAX_HEADER_LINE - 1);
    strncpy(response->headers[response->header_count].value, value, MAX_HEADER_LINE - 1);
    response->headers[response->header_count].name[MAX_HEADER_LINE - 1] = '\0';
    response->headers[response->header_count].value[MAX_HEADER_LINE - 1] = '\0';
    response->header_count++;
}

void response_set_body(http_response_t *response, const char *body, size_t length) {
    if (!response) return;
    
    if (response->body) {
        free(response->body);
        response->body = NULL;
    }
    
    if (body && length > 0) {
        response->body = malloc(length + 1);
        if (response->body) {
            memcpy(response->body, body, length);
            response->body[length] = '\0';
            response->body_length = length;
            
            // Set Content-Length header
            char length_str[32];
            snprintf(length_str, sizeof(length_str), "%zu", length);
            response_add_header(response, "Content-Length", length_str);
        }
    } else {
        response->body_length = 0;
        response_add_header(response, "Content-Length", "0");
    }
}

void response_set_content_type(http_response_t *response, const char *content_type) {
    if (!response || !content_type) return;
    
    if (response->content_type) {
        free(response->content_type);
    }
    
    response->content_type = str_duplicate(content_type);
    response_add_header(response, "Content-Type", content_type);
}

void response_set_text(http_response_t *response, const char *text) {
    if (!response || !text) return;
    
    response_set_content_type(response, "text/plain; charset=utf-8");
    response_set_body(response, text, strlen(text));
}

void response_set_html(http_response_t *response, const char *html) {
    if (!response || !html) return;
    
    response_set_content_type(response, "text/html; charset=utf-8");
    response_set_body(response, html, strlen(html));
}

void response_set_json(http_response_t *response, const char *json) {
    if (!response || !json) return;
    
    response_set_content_type(response, "application/json; charset=utf-8");
    response_set_body(response, json, strlen(json));
}

void response_set_file(http_response_t *response, const char *filepath) {
    if (!response || !filepath) return;
    
    if (!file_exists(filepath)) {
        response_set_status(response, STATUS_NOT_FOUND);
        response_set_text(response, "File not found");
        return;
    }
    
    size_t file_size_val;
    char *file_content = file_read_all(filepath, &file_size_val);
    
    if (!file_content) {
        response_set_status(response, STATUS_INTERNAL_SERVER_ERROR);
        response_set_text(response, "Error reading file");
        return;
    }
    
    const char *mime_type = get_mime_type(filepath);
    response_set_content_type(response, mime_type);
    response_set_body(response, file_content, file_size_val);
    
    free(file_content);
}

const char* status_code_to_string(http_status_t status) {
    switch (status) {
        case STATUS_OK: return "200 OK";
        case STATUS_CREATED: return "201 Created";
        case STATUS_NO_CONTENT: return "204 No Content";
        case STATUS_MOVED_PERMANENTLY: return "301 Moved Permanently";
        case STATUS_FOUND: return "302 Found";
        case STATUS_NOT_MODIFIED: return "304 Not Modified";
        case STATUS_BAD_REQUEST: return "400 Bad Request";
        case STATUS_UNAUTHORIZED: return "401 Unauthorized";
        case STATUS_FORBIDDEN: return "403 Forbidden";
        case STATUS_NOT_FOUND: return "404 Not Found";
        case STATUS_METHOD_NOT_ALLOWED: return "405 Method Not Allowed";
        case STATUS_INTERNAL_SERVER_ERROR: return "500 Internal Server Error";
        case STATUS_NOT_IMPLEMENTED: return "501 Not Implemented";
        case STATUS_SERVICE_UNAVAILABLE: return "503 Service Unavailable";
        default: return "500 Internal Server Error";
    }
}

int response_build(const http_response_t *response, char *buffer, size_t buffer_size) {
    if (!response || !buffer || buffer_size == 0) return -1;
    
    size_t offset = 0;
    
    // Status line
    int written = snprintf(buffer + offset, buffer_size - offset, 
                          "HTTP/1.1 %s\r\n", status_code_to_string(response->status_code));
    
    if (written < 0 || (size_t)written >= buffer_size - offset) return -1;
    offset += written;
    
    // Add server header if not present
    int has_server = 0;
    for (int i = 0; i < response->header_count; i++) {
        if (strncmp(response->headers[i].name, "Server", 6) == 0) {
            has_server = 1;
            break;
        }
    }
    
    if (!has_server) {
        written = snprintf(buffer + offset, buffer_size - offset, "Server: SimpleHTTP/1.0\r\n");
        if (written < 0 || (size_t)written >= buffer_size - offset) return -1;
        offset += written;
    }
    
    // Add date header if not present
    int has_date = 0;
    for (int i = 0; i < response->header_count; i++) {
        if (strncmp(response->headers[i].name, "Date", 4) == 0) {
            has_date = 1;
            break;
        }
    }
    
    if (!has_date) {
        char date_str[128];
        get_http_date_string(date_str, sizeof(date_str));
        written = snprintf(buffer + offset, buffer_size - offset, "Date: %s\r\n", date_str);
        if (written < 0 || (size_t)written >= buffer_size - offset) return -1;
        offset += written;
    }
    
    // Headers
    for (int i = 0; i < response->header_count; i++) {
        written = snprintf(buffer + offset, buffer_size - offset, 
                          "%s: %s\r\n", response->headers[i].name, response->headers[i].value);
        
        if (written < 0 || (size_t)written >= buffer_size - offset) return -1;
        offset += written;
    }
    
    // Connection header (keep it simple)
    written = snprintf(buffer + offset, buffer_size - offset, "Connection: close\r\n");
    if (written < 0 || (size_t)written >= buffer_size - offset) return -1;
    offset += written;
    
    // Empty line before body
    written = snprintf(buffer + offset, buffer_size - offset, "\r\n");
    if (written < 0 || (size_t)written >= buffer_size - offset) return -1;
    offset += written;
    
    // Body
    if (response->body && response->body_length > 0) {
        if (offset + response->body_length >= buffer_size) return -1;
        memcpy(buffer + offset, response->body, response->body_length);
        offset += response->body_length;
    }
    
    return (int)offset;
}