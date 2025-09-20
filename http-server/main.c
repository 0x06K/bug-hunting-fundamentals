#include "server.h"
#include "request.h"
#include "response.h"
#include "router.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function declarations for route handlers
void handle_home(const http_request_t *request, http_response_t *response);
void handle_api_hello(const http_request_t *request, http_response_t *response);
void handle_api_users(const http_request_t *request, http_response_t *response);
void handle_api_echo(const http_request_t *request, http_response_t *response);

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    
    // Parse command line arguments
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number: %s\n", argv[1]);
            return 1;
        }
    }
    
    // Initialize logging
    log_init(NULL, LOG_INFO); // Log to stderr
    
    log_info("Starting HTTP server on port %d", port);
    
    // Initialize server
    server_t server;
    if (server_init(&server, port) != 0) {
        log_error("Failed to initialize server");
        return 1;
    }
    
    // Add routes
    server_get("/", handle_home);
    server_get("/api/hello", handle_api_hello);
    server_get("/api/users", handle_api_users);
    server_post("/api/echo", handle_api_echo);
    
    // Start server
    if (server_start(&server) != 0) {
        log_error("Failed to start server");
        server_cleanup(&server);
        return 1;
    }
    
    // Run server (blocks until stopped)
    server_run(&server);
    
    // Cleanup
    server_cleanup(&server);
    log_cleanup();
    
    return 0;
}

// Route handler implementations
void handle_home(const http_request_t *request, http_response_t *response) {
    (void)request; // Suppress unused parameter warning
    
    const char *html = 
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "    <title>Simple HTTP Server</title>\n"
        "    <style>\n"
        "        body { font-family: Arial, sans-serif; margin: 40px; }\n"
        "        h1 { color: #333; }\n"
        "        .api-link { display: block; margin: 10px 0; color: #0066cc; }\n"
        "        .method { font-weight: bold; color: #008000; }\n"
        "    </style>\n"
        "</head>\n"
        "<body>\n"
        "    <h1>Welcome to Simple HTTP Server</h1>\n"
        "    <p>This is a lightweight HTTP server built in C.</p>\n"
        "    \n"
        "    <h2>Available API Endpoints:</h2>\n"
        "    <a href=\"/api/hello\" class=\"api-link\">\n"
        "        <span class=\"method\">GET</span> /api/hello - Simple greeting\n"
        "    </a>\n"
        "    <a href=\"/api/users\" class=\"api-link\">\n"
        "        <span class=\"method\">GET</span> /api/users - List of users (JSON)\n"
        "    </a>\n"
        "    <div class=\"api-link\">\n"
        "        <span class=\"method\">POST</span> /api/echo - Echo request body\n"
        "    </div>\n"
        "    \n"
        "    <h2>Static Files:</h2>\n"
        "    <p>Static files can be served from the <code>/static/</code> path.</p>\n"
        "</body>\n"
        "</html>";
    
    response_set_html(response, html);
}

void handle_api_hello(const http_request_t *request, http_response_t *response) {
    (void)request; // Suppress unused parameter warning
    
    const char *json = 
        "{\n"
        "    \"message\": \"Hello, World!\",\n"
        "    \"timestamp\": \"2024-01-01T12:00:00Z\",\n"
        "    \"server\": \"SimpleHTTP/1.0\"\n"
        "}";
    
    response_set_json(response, json);
}

void handle_api_users(const http_request_t *request, http_response_t *response) {
    (void)request; // Suppress unused parameter warning
    
    const char *json = 
        "{\n"
        "    \"users\": [\n"
        "        {\n"
        "            \"id\": 1,\n"
        "            \"name\": \"John Doe\",\n"
        "            \"email\": \"john@example.com\"\n"
        "        },\n"
        "        {\n"
        "            \"id\": 2,\n"
        "            \"name\": \"Jane Smith\",\n"
        "            \"email\": \"jane@example.com\"\n"
        "        },\n"
        "        {\n"
        "            \"id\": 3,\n"
        "            \"name\": \"Bob Johnson\",\n"
        "            \"email\": \"bob@example.com\"\n"
        "        }\n"
        "    ],\n"
        "    \"total\": 3\n"
        "}";
    
    response_set_json(response, json);
}

void handle_api_echo(const http_request_t *request, http_response_t *response) {
    if (!request->body || request->body_length == 0) {
        response_set_status(response, STATUS_BAD_REQUEST);
        response_set_json(response, 
            "{\n"
            "    \"error\": \"No request body provided\",\n"
            "    \"message\": \"POST request must include a body to echo\"\n"
            "}"
        );
        return;
    }
    
    // Create response JSON with echoed content
    char response_json[4096];
    snprintf(response_json, sizeof(response_json),
        "{\n"
        "    \"method\": \"%s\",\n"
        "    \"path\": \"%s\",\n"
        "    \"body_length\": %zu,\n"
        "    \"echoed_content\": \"%s\"\n"
        "}",
        method_to_string(request->method),
        request->path,
        request->body_length,
        request->body
    );
    
    response_set_json(response, response_json);
}