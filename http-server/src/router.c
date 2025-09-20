#include "router.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void router_init(router_t *router) {
    if (!router) return;
    
    memset(router->routes, 0, sizeof(router->routes));
    router->route_count = 0;
}

int router_add_route(router_t *router, http_method_t method, const char *path, route_handler_t handler) {
    if (!router || !path || !handler || router->route_count >= MAX_ROUTES) {
        return -1;
    }
    
    route_t *route = &router->routes[router->route_count];
    route->method = method;
    strncpy(route->path, path, MAX_ROUTE_PATH - 1);
    route->path[MAX_ROUTE_PATH - 1] = '\0';
    route->handler = handler;
    route->is_wildcard = (strstr(path, "*") != NULL);
    
    router->route_count++;
    return 0;
}

int router_get(router_t *router, const char *path, route_handler_t handler) {
    return router_add_route(router, METHOD_GET, path, handler);
}

int router_post(router_t *router, const char *path, route_handler_t handler) {
    return router_add_route(router, METHOD_POST, path, handler);
}

int router_put(router_t *router, const char *path, route_handler_t handler) {
    return router_add_route(router, METHOD_PUT, path, handler);
}

int router_delete(router_t *router, const char *path, route_handler_t handler) {
    return router_add_route(router, METHOD_DELETE, path, handler);
}

int path_matches(const char *route_path, const char *request_path) {
    if (!route_path || !request_path) return 0;
    
    // Exact match
    if (strcmp(route_path, request_path) == 0) {
        return 1;
    }
    
    // Wildcard match
    if (strstr(route_path, "*")) {
        return is_wildcard_match(route_path, request_path);
    }
    
    return 0;
}

int is_wildcard_match(const char *pattern, const char *path) {
    if (!pattern || !path) return 0;
    
    const char *star = strchr(pattern, '*');
    if (!star) {
        return strcmp(pattern, path) == 0;
    }
    
    // Check prefix before *
    size_t prefix_len = star - pattern;
    if (strncmp(pattern, path, prefix_len) != 0) {
        return 0;
    }
    
    // If * is at the end, match anything after prefix
    if (*(star + 1) == '\0') {
        return 1;
    }
    
    // More complex wildcard matching (simplified)
    const char *suffix = star + 1;
    size_t suffix_len = strlen(suffix);
    size_t path_len = strlen(path);
    
    if (path_len < prefix_len + suffix_len) {
        return 0;
    }
    
    return strcmp(path + path_len - suffix_len, suffix) == 0;
}

route_handler_t router_find_handler(const router_t *router, http_method_t method, const char *path) {
    if (!router || !path) return NULL;
    
    for (int i = 0; i < router->route_count; i++) {
        const route_t *route = &router->routes[i];
        
        if (route->method == method && path_matches(route->path, path)) {
            return route->handler;
        }
    }
    
    return NULL;
}

void router_handle_request(const router_t *router, const http_request_t *request, http_response_t *response) {
    if (!router || !request || !response) return;
    
    // Handle static files first (if path starts with /static/)
    if (str_starts_with(request->path, "/static/")) {
        handle_static_file(request, response);
        return;
    }
    
    // Find route handler
    route_handler_t handler = router_find_handler(router, request->method, request->path);
    
    if (handler) {
        handler(request, response);
    } else {
        handle_404(request, response);
    }
}

void handle_404(const http_request_t *request, http_response_t *response) {
    (void)request; // Suppress unused parameter warning
    
    response_set_status(response, STATUS_NOT_FOUND);
    response_set_html(response, 
        "<!DOCTYPE html>\n"
        "<html><head><title>404 Not Found</title></head>\n"
        "<body>\n"
        "<h1>404 Not Found</h1>\n"
        "<p>The requested resource was not found on this server.</p>\n"
        "</body></html>"
    );
}

void handle_500(const http_request_t *request, http_response_t *response) {
    (void)request; // Suppress unused parameter warning
    
    response_set_status(response, STATUS_INTERNAL_SERVER_ERROR);
    response_set_html(response,
        "<!DOCTYPE html>\n"
        "<html><head><title>500 Internal Server Error</title></head>\n"
        "<body>\n"
        "<h1>500 Internal Server Error</h1>\n"
        "<p>An internal server error occurred.</p>\n"
        "</body></html>"
    );
}

void handle_static_file(const http_request_t *request, http_response_t *response) {
    if (!request || !response) return;
    
    const char *path = request->path;
    
    // Security check: prevent directory traversal
    if (strstr(path, "..") || strstr(path, "//")) {
        response_set_status(response, STATUS_FORBIDDEN);
        response_set_text(response, "Access denied");
        return;
    }
    
    // Remove /static/ prefix and prepend with actual static directory
    const char *file_path = path + strlen("/static");
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "./static%s", file_path);
    
    // If path ends with /, serve index.html
    if (str_ends_with(full_path, "/")) {
        strncat(full_path, "index.html", sizeof(full_path) - strlen(full_path) - 1);
    }
    
    if (!file_exists(full_path)) {
        handle_404(request, response);
        return;
    }
    
    response_set_file(response, full_path);
    
    // Add cache headers for static files
    response_add_header(response, "Cache-Control", "max-age=3600");
    
    // Add security headers
    response_add_header(response, "X-Content-Type-Options", "nosniff");
}