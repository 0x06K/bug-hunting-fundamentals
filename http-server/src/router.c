#include "../include/router.h"



void router_init(router_t *router) {
    router->route_count = 0;
    
    // Clear all routes
    for (int i = 0; i < MAX_ROUTES; i++) {
        router->routes[i].method = METHOD_UNKNOWN;
        router->routes[i].path[0] = '\0';
        router->routes[i].handler = NULL;
        router->routes[i].is_wildcard = 0;
    }
}

int router_add_route(router_t *router, http_method_t method, const char *path, route_handler_t handler) {
    if (router->route_count >= MAX_ROUTES) return -1;
    
    route_t *route = &router->routes[router->route_count];
    route->method = method;
    strncpy(route->path, path, MAX_ROUTE_PATH - 1);
    route->handler = handler;
    route->is_wildcard = (strstr(path, "*") != NULL);
    
    router->route_count++;
    return 0;
}

route_handler_t router_find_handler(const router_t *router, http_method_t method, const char *path) {
    for (int i = 0; i < router->route_count; i++) {
        const route_t *route = &router->routes[i];
        
        // Check method match
        if (route->method != method) continue;
        
        // Check path match
        if (path_matches(route->path, path)) {
            return route->handler;
        }
    }
    return NULL; // No handler found
}

int path_matches(const char *route_path, const char *request_path) {
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

