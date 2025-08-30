#ifndef ROUTER_H
#define ROUTER_H

#include "request.h"
#include "response.h"

#define MAX_ROUTES 100
#define MAX_ROUTE_PATH 256

// Route handler function pointer type
typedef void (*route_handler_t)(const http_request_t *request, http_response_t *response);

typedef struct {
    http_method_t method;
    char path[MAX_ROUTE_PATH];
    route_handler_t handler;
    int is_wildcard; // For paths like /api/*
} route_t;

typedef struct {
    route_t routes[MAX_ROUTES];
    int route_count;
} router_t;

// Router management
void router_init(router_t *router);
int router_add_route(router_t *router, http_method_t method, const char *path, route_handler_t handler);
route_handler_t router_find_handler(const router_t *router, http_method_t method, const char *path);
void router_handle_request(const router_t *router, const http_request_t *request, http_response_t *response);

// Convenience functions for adding routes
int router_get(router_t *router, const char *path, route_handler_t handler);
int router_post(router_t *router, const char *path, route_handler_t handler);
int router_put(router_t *router, const char *path, route_handler_t handler);
int router_delete(router_t *router, const char *path, route_handler_t handler);

// Path matching utilities
int path_matches(const char *route_path, const char *request_path);
int is_wildcard_match(const char *pattern, const char *path);

// Default handlers
void handle_404(const http_request_t *request, http_response_t *response);
void handle_500(const http_request_t *request, http_response_t *response);
void handle_static_file(const http_request_t *request, http_response_t *response);

#endif // ROUTER_H
