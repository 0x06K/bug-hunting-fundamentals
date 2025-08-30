#include "server.h"
#include <stdio.h>
#include <unistd.h>
#include <pthread.h> 

int server_init(server_t *server, int port){
    server->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    server->port = port;
    server->runing = 0;
    
    server->address.sin_family = AF_INET;          // IPv4
    server->address.sin_addr.s_addr = INADDR_ANY;  // Accept any IP (0.0.0.0)
    server->address.sin_port = htons(port);        // Convert host byte order to network byte order

}

int server_start(server_t *server) {
    if (!server) return -1;

    // Start listening
    if (listen(server->socket_fd, BACKLOG) < 0) {
        perror("listen failed");
        return -1;
    }

    server->running = 1;
    printf("Server started on port %d, waiting for connections...\n", server->port);

    return 0;
}

void server_run(server_t *server) {
    if (!server) return;

    while (server->running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        // Accept a client
        int client_fd = accept(server->socket_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            perror("accept failed");
            continue; // keep server alive even if one accept fails
        }

        printf("Client connected: %s:%d\n", 
        inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Handle client in a separate thread
        pthread_t thread_id;
        int *pclient = malloc(sizeof(int));
        *pclient = client_fd;
        if (pthread_create(&thread_id, NULL, (void*(*)(void*))handle_client, pclient) != 0) {
            perror("pthread_create failed");
            close(client_fd);
            free(pclient);
        } else {
            pthread_detach(thread_id); // automatically clean up thread when done
        }
    }
}

void server_stop(server_t *server) {
    if (!server || !server->running) return;

    server->running = 0; // stop the run loop

    // Close the listening socket
    if (server->socket_fd >= 0) {
        close(server->socket_fd);
        server->socket_fd = -1;
    }

    printf("Server stopped.\n");
}

void server_cleanup(server_t *server) {
    if (!server) return;

    // Make sure socket is closed
    if (server->socket_fd >= 0) {
        close(server->socket_fd);
        server->socket_fd = -1;
    }

    printf("Server resources cleaned up.\n");
}

void handle_client(int client_fd) {
    char buffer[BUF_SIZE];
    int bytes_received;

    // Read client request
    bytes_received = recv(client_fd, buffer, BUF_SIZE - 1, 0);
    if (bytes_received <= 0) {
        close(client_fd);
        return;
    }
    buffer[bytes_received] = '\0'; // null-terminate
    
    http_request_t request;
    request_init(&request);

    // Parse the raw request
    if (request_parse(buffer, &request) != 0) {
        // Send 400 Bad Request
        const char *bad_response =
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        send(client_fd, bad_response, strlen(bad_response), 0);
        request_free(&request);
        close(client_fd);
        return;
    }


    request_parse(const char *raw_request, http_request_t *request)
    send(client_fd, response, len, 0);

    close(client_fd);
}