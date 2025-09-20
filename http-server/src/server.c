#include "server.h"
#include "request.h"
#include "response.h"
#include "router.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>

// Global router for simplicity (in a real implementation, this would be passed around)
static router_t g_router;
static int g_server_running = 0;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    (void)sig;
    g_server_running = 0;
    log_info("Received shutdown signal, stopping server...");
}

int server_init(server_t *server, int port) {
    if (!server) return -1;
    
    server->port = (port > 0) ? port : DEFAULT_PORT;
    server->running = 0;
    
    // Initialize router
    router_init(&g_router);
    
    // Create socket
    server->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->socket_fd == -1) {
        print_errno("socket");
        return -1;
    }
    
    // Set socket options
    if (socket_set_reuseaddr(server->socket_fd) != 0) {
        log_warn("Failed to set SO_REUSEADDR");
    }
    
    // Set up address structure
    memset(&server->address, 0, sizeof(server->address));
    server->address.sin_family = AF_INET;
    server->address.sin_addr.s_addr = INADDR_ANY;
    server->address.sin_port = htons(server->port);
    
    return 0;
}

int server_start(server_t *server) {
    if (!server) return -1;
    
    // Bind socket
    if (bind(server->socket_fd, (struct sockaddr*)&server->address, sizeof(server->address)) == -1) {
        print_errno("bind");
        return -1;
    }
    
    // Listen for connections
    if (listen(server->socket_fd, BACKLOG) == -1) {
        print_errno("listen");
        return -1;
    }
    
    server->running = 1;
    g_server_running = 1;
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    log_info("Server listening on port %d", server->port);
    return 0;
}

void server_run(server_t *server) {
    if (!server || !server->running) return;
    
    fd_set read_fds;
    struct timeval timeout;
    
    while (server->running && g_server_running) {
        FD_ZERO(&read_fds);
        FD_SET(server->socket_fd, &read_fds);
        
        // Set timeout for select
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(server->socket_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (errno == EINTR) {
                // Interrupted by signal, check if we should continue
                continue;
            }
            print_errno("select");
            break;
        }
        
        if (activity == 0) {
            // Timeout, continue loop to check running status
            continue;
        }
        
        if (FD_ISSET(server->socket_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_fd = accept(server->socket_fd, (struct sockaddr*)&client_addr, &client_len);
            
            if (client_fd == -1) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    print_errno("accept");
                }
                continue;
            }
            
            log_debug("Accepted connection from %s:%d", 
                     inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            
            handle_client(client_fd);
        }
    }
    
    server->running = 0;
    log_info("Server stopped");
}

void server_stop(server_t *server) {
    if (server) {
        server->running = 0;