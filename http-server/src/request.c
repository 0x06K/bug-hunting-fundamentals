int request_parse(const char *raw_request, http_request_t *request) {
    request_init(request);

    // parse request line (method, path, version, etc.)
    // assuming first line is something like: "GET /index.html HTTP/1.1"
    const char *line_end = strstr(raw_request, "\r\n");
    if (!line_end) {
        return 0; // invalid request
    }

    char request_line[1024];
    size_t len = line_end - raw_request;
    if (len >= sizeof(request_line)) {
        return 0; // line too long
    }
    memcpy(request_line, raw_request, len);
    request_line[len] = '\0';

    // tokenize method, path, version
    char method_str[16], path[512], version[16];
    if (sscanf(request_line, "%15s %511s %15s", method_str, path, version) != 3) {
        return 0; // malformed request line
    }

    request->method = request_parse_method(method_str);
    request->path   = strdup(path);    // you’ll need to free later
    request->version = strdup(version);

    // find start of headers
    const char *header_section = line_end + 2; // skip "\r\n"
    request_parse_headers(header_section, request);

    return 1;
}

// Convert method string to enum
http_method_t request_parse_method(const char *method_str) {
    if (strcasecmp(method_str, "GET") == 0)    return HTTP_GET;
    if (strcasecmp(method_str, "POST") == 0)   return HTTP_POST;
    if (strcasecmp(method_str, "PUT") == 0)    return HTTP_PUT;
    if (strcasecmp(method_str, "DELETE") == 0) return HTTP_DELETE;
    return HTTP_UNKNOWN;
}

// Parse headers section into request->headers
int request_parse_headers(const char *header_section, http_request_t *request) {
    const char *line_start = header_section;
    request->header_count = 0;

    while (*line_start && !(line_start[0] == '\r' && line_start[1] == '\n')) {
        const char *line_end = strstr(line_start, "\r\n");
        if (!line_end) break;

        char line[1024];
        size_t len = line_end - line_start;
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, line_start, len);
        line[len] = '\0';

        // split "Name: Value"
        char *colon = strchr(line, ':');
        if (colon && request->header_count < 64) {
            *colon = '\0';
            char *name  = line;
            char *value = colon + 1;

            // trim whitespace
            while (isspace((unsigned char)*value)) value++;

            request->headers[request->header_count].name  = strdup(name);
            request->headers[request->header_count].value = strdup(value);
            request->header_count++;
        }

        line_start = line_end + 2; // move to next line
    }

    return request->header_count;
}

// Lookup header by name
const char* request_get_header(const http_request_t *request, const char *name) {
    for (int i = 0; i < request->header_count; i++) {
        if (strcasecmp(request->headers[i].name, name) == 0) {
            return request->headers[i].value;
        }
    }
    return NULL;
}

// Initialize empty request
void request_init(http_request_t *request) {
    request->method = HTTP_UNKNOWN;
    request->path = NULL;
    request->version = NULL;
    request->header_count = 0;
}

// Free allocated memory
void request_free(http_request_t *request) {
    free(request->path);
    free(request->version);

    for (int i = 0; i < request->header_count; i++) {
        free(request->headers[i].name);
        free(request->headers[i].value);
    }
    request->header_count = 0;
}
