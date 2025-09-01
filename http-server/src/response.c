void response_init(http_response_t *response) {
    response->status = 200;  // default OK
    response->header_count = 0;
    response->body = NULL;
    response->body_length = 0;
    response->content_type = NULL;
}

void response_set_status(http_response_t *response, http_status_t status) {
    response->status = status;
}

void response_add_header(http_response_t *response, const char *name, const char *value) {
    if (response->header_count >= 64) {
        return; // too many headers
    }

    int i = response->header_count;
    response->headers[i].name  = strdup(name);
    response->headers[i].value = strdup(value);
    response->header_count++;
}
<