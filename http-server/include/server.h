#ifndef SERVER_H
#define SERVER_H

#define DEFAULT_PORT 8080
#define BACKLOG 10
#define MAX_CLIENTS 100

typedef struct {
    int socket_fd;
    int port;
    struct sockaddr_in address;
    int running;
} server_t;

// Server lifecycle functions
int server_init(server_t *server, int port);
int server_start(server_t *server);
void server_run(server_t *server);
void server_stop(server_t *server);
void server_cleanup(server_t *server);

// Client handling
void handle_client(int client_fd);

#endif // SERVER_H
