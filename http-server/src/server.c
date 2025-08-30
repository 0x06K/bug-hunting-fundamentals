#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int server_init(server_t *server, int port) {
    // Step 1: Initialize server structure members
    server->port = port;
    server->running = 0;
    
    // Step 2: Create socket
    server->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->socket_fd < 0) {
        return -1; // Error creating socket
    }
    
    // Step 3: Set socket options (SO_REUSEADDR to avoid "Address already in use")
    int opt = 1;
    setsockopt(server->socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Step 4: Configure server address structure
    server->address.sin_family = AF_INET;
    server->address.sin_addr.s_addr = INADDR_ANY; // Accept connections from any IP
    server->address.sin_port = htons(port);       // Convert port to network byte order
    
    return 0; // Success
}

int server_start(server_t *server) {
    // Step 1: Bind socket to address
    if (bind(server->socket_fd, (struct sockaddr*)&server->address, sizeof(server->address)) < 0) {
        return -1; // Bind failed
    }
    
    // Step 2: Start listening for connections
    if (listen(server->socket_fd, BACKLOG) < 0) {
        return -1; // Listen failed
    }
    
    // Step 3: Mark server as running
    server->running = 1;
    
    return 0; // Success
}

void server_run(server_t *server) {
    printf("Server running on port %d\n", server->port);
    
    while (server->running) {
        // Step 1: Accept incoming connection
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(server->socket_fd, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_fd < 0) {
            if (server->running) { // Only log error if server is still supposed to be running
                perror("Accept failed");
            }
            continue;
        }
        
        // Step 2: Handle the client (i will make it multi threaded later)
        handle_client(client_fd);
        
        // Step 3: Close client connection
        close(client_fd);
    }
}

void handle_client(int client_fd) {
    char buffer[MAX_REQUEST_SIZE];
    
    // Step 1: Read HTTP request from client
    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        return; // Nothing to read or error
    }
    buffer[bytes_read] = '\0'; // Null terminate
    
    // Step 2: Parse the HTTP request
    http_request_t request;
    request_init(&request);
    
    if (request_parse(buffer, &request) != 0) {
        // Send 400 Bad Request
        const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, bad_request, strlen(bad_request), 0);
        return;
    }
    
    // Step 3: Create response
    http_response_t response;
    response_init(&response);
    
    // Step 4: Route the request (i will implement router later)
    // For now, simple routing:
    if (strcmp(request.path, "/") == 0) {
        response_set_html(&response, "<h1>Hello World!</h1>");
        response_set_status(&response, STATUS_OK);
    } else {
        response_set_html(&response, "<h1>404 Not Found</h1>");
        response_set_status(&response, STATUS_NOT_FOUND);
    }
    
    // Step 5: Build and send response
    char response_buffer[MAX_RESPONSE_SIZE];
    if (response_build(&response, response_buffer, sizeof(response_buffer)) > 0) {
        send(client_fd, response_buffer, strlen(response_buffer), 0);
    }
    
    // Step 6: Cleanup
    request_free(&request);
    response_free(&response);
}

void server_stop(server_t *server) {
    // Step 1: Mark server as not running (this will break the main loop)
    server->running = 0;
    
    // Step 2: Shutdown the socket to interrupt accept() call
    if (server->socket_fd >= 0) {
        shutdown(server->socket_fd, SHUT_RDWR);
    }
}

void server_cleanup(server_t *server) {
    // Step 1: Close the server socket
    if (server->socket_fd >= 0) {
        close(server->socket_fd);
        server->socket_fd = -1;
    }
    
    // Step 2: Reset server state
    server->running = 0;
    server->port = 0;
}
