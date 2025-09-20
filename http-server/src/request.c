#include "request.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void request_init(http_request_t *request) {
    if (!request) return;
    
    request->method = METHOD_UNKNOWN;
    memset(request->path, 0, MAX_PATH_SIZE);
    memset(request->version, 0, MAX_VERSION_SIZE);
    memset(request->headers, 0, sizeof(request->headers));
    request->header_count = 0;
    request->body = NULL;
    request->body_length = 0;
    request->valid = 0;
}

void request_free(http_request_t *request) {
    if (!request) return;
    
    if (request->body) {
        free(request->body);
        request->body = NULL;
    }
    request->body_length = 0;
}

http_method_t request_parse_method(const char *method_str) {
    if (!method_str) return METHOD_UNKNOWN;
    
    if (strncmp(method_str, "GET", 3) == 0) return METHOD_GET;
    if (strncmp(method_str, "POST", 4) == 0) return METHOD_POST;
    if (strncmp(method_str, "PUT", 3) == 0) return METHOD_PUT;
    if (strncmp(method_str, "DELETE", 6) == 0) return METHOD_DELETE;
    if (strncmp(method_str, "HEAD", 4) == 0) return METHOD_HEAD;
    if (strncmp(method_str, "OPTIONS", 7) == 0) return METHOD_OPTIONS;
    
    return METHOD_UNKNOWN;
}

const char* method_to_string(http_method_t method) {
    switch (method) {
        case METHOD_GET: return "GET";
        case METHOD_POST: return "POST";
        case METHOD_PUT: return "PUT";
        case METHOD_DELETE: return "DELETE";
        case METHOD_HEAD: return "HEAD";
        case METHOD_OPTIONS: return "OPTIONS";
        default: return "UNKNOWN";
    }
}

int request_parse_headers(const char *header_section, http_request_t *request) {
    if (!header_section || !request) return -1;
    
    char *headers_copy = str_duplicate(header_section);
    if (!headers_copy) return -1;
    
    char *line = strtok(headers_copy, "\r\n");
    request->header_count = 0;
    
    while (line && request->header_count < MAX_HEADER_COUNT) {
        char *colon = strchr(line, ':');
        if (!colon) {
            line = strtok(NULL, "\r\n");
            continue;
        }
        
        *colon = '\0';
        char *name = str_trim(line);
        char *value = str_trim(colon + 1);
        
        if (strlen(name) < MAX_HEADER_SIZE && strlen(value) < MAX_HEADER_SIZE) {
            strncpy(request->headers[request->header_count].name, name, MAX_HEADER_SIZE - 1);
            strncpy(request->headers[request->header_count].value, value, MAX_HEADER_SIZE - 1);
            request->headers[request->header_count].name[MAX_HEADER_SIZE - 1] = '\0';
            request->headers[request->header_count].value[MAX_HEADER_SIZE - 1] = '\0';
            request->header_count++;
        }
        
        line = strtok(NULL, "\r\n");
    }
    
    free(headers_copy);
    return 0;
}

const char* request_get_header(const http_request_t *request, const char *name) {
    if (!request || !name) return NULL;
    const char* tmp = name;
    size_t length = 0;
    while(*tmp != '\0'){ length++; tmp++; } 
    for (int i = 0; i < request->header_count; i++) {
        if (strncmp(request->headers[i].name, name, length) == 0) {
            return request->headers[i].value;
        }
    }
    return NULL;
}

int request_parse(const char *raw_request, http_request_t *request) {
    if (!raw_request || !request) return -1;
    
    request_init(request);
    
    // Find the end of headers (double CRLF)
    const char *body_start = strstr(raw_request, "\r\n\r\n");
    if (!body_start) {
        // Try single LF for malformed requests
        body_start = strstr(raw_request, "\n\n");
        if (!body_start) return -1;
        body_start += 2;
    } else {
        body_start += 4;
    }
    
    // Calculate header length
    size_t header_length = body_start - raw_request;
    
    // Copy headers section
    char *headers_copy = malloc(header_length + 1);
    if (!headers_copy) return -1;
    
    strncpy(headers_copy, raw_request, header_length);
    headers_copy[header_length] = '\0';
    
    // Parse request line (first line)
    char *first_line_end = strstr(headers_copy, "\r\n");
    if (!first_line_end) {
        first_line_end = strchr(headers_copy, '\n');
    }
    
    if (!first_line_end) {
        free(headers_copy);
        return -1;
    }
    
    *first_line_end = '\0';
    
    // Parse method, path, and version
    char method_str[MAX_METHOD_SIZE];
    char path_str[MAX_PATH_SIZE];
    char version_str[MAX_VERSION_SIZE];
    
    int parsed = sscanf(headers_copy, "%15s %2047s %15s", 
                       method_str, path_str, version_str);
    
    if (parsed != 3) {
        free(headers_copy);
        return -1;
    }
    
    request->method = request_parse_method(method_str);
    strncpy(request->path, path_str, MAX_PATH_SIZE - 1);
    strncpy(request->version, version_str, MAX_VERSION_SIZE - 1);
    request->path[MAX_PATH_SIZE - 1] = '\0';
    request->version[MAX_VERSION_SIZE - 1] = '\0';
    
    // Parse headers
    char *header_start = first_line_end + 1;
    if (*header_start == '\n') header_start++; // Skip LF after CR
    
    if (request_parse_headers(header_start, request) != 0) {
        free(headers_copy);
        return -1;
    }
    
    // Handle body if present
    size_t body_length = strlen(body_start);
    const char *content_length_str = request_get_header(request, "Content-Length");
    
    if (content_length_str) {
        size_t expected_length = (size_t)atol(content_length_str);
        if (expected_length > 0) {
            request->body = malloc(expected_length + 1);
            if (request->body) {
                size_t copy_length = (body_length < expected_length) ? body_length : expected_length;
                memcpy(request->body, body_start, copy_length);
                request->body[copy_length] = '\0';
                request->body_length = copy_length;
            }
        }
    } else if (body_length > 0) {
        // No Content-Length header, use available body data
        request->body = malloc(body_length + 1);
        if (request->body) {
            memcpy(request->body, body_start, body_length);
            request->body[body_length] = '\0';
            request->body_length = body_length;
        }
    }
    
    free(headers_copy);
    request->valid = 1;
    return 0;
}