# warning :3
- purely vibe code by claude 
- my contributions: 0
- ofcourse i never needed to build it from scratch i will just now analyze it
---

## Simple HTTP Server in C

A lightweight, educational HTTP server implementation written in C. This project demonstrates the fundamentals of HTTP protocol handling, socket programming, and modular C architecture.

## Features

- **HTTP/1.1 Protocol Support**: Handles GET, POST, PUT, DELETE, HEAD, and OPTIONS methods
- **Routing System**: Flexible route registration with wildcard support
- **Static File Serving**: Automatic MIME type detection and static content delivery
- **Request Parsing**: Complete HTTP request parsing with headers and body
- **Response Building**: Easy-to-use response construction with various content types
- **Logging System**: Configurable logging with different levels (DEBUG, INFO, WARN, ERROR)
- **Modular Design**: Clean separation of concerns across multiple modules

## Project Structure

```
├── request.h/c     - HTTP request parsing and handling
├── response.h/c    - HTTP response building and formatting
├── router.h/c      - URL routing and handler management
├── server.h/c      - Core server functionality and client handling
├── utils.h/c       - Utility functions (logging, string ops, file I/O)
├── main.c          - Example server implementation
├── Makefile        - Build configuration
└── README.md       - This file
```

## Building

### Prerequisites
- GCC compiler with C99 support
- POSIX-compliant system (Linux, macOS, Unix)
- Make utility

### Compilation

```bash
# Build the server
make

# Build with debug symbols
make debug

# Clean build artifacts
make clean

# Create static file directory
make setup
```

## Usage

### Basic Server

```bash
# Run on default port (8080)
./httpserver

# Run on custom port
./httpserver 3000
```

### Example Routes

The included example server provides:

- `GET /` - Welcome page with API documentation
- `GET /api/hello` - JSON greeting response
- `GET /api/users` - Sample user data in JSON
- `POST /api/echo` - Echoes the request body
- `GET /static/*` - Static file serving

### Testing

```bash
# Run automated tests
make test

# Test manually with curl
curl http://localhost:8080/
curl http://localhost:8080/api/hello
curl -X POST -d "Hello, Server!" http://localhost:8080/api/echo
```

## API Reference

### Server Functions

```c
int server_init(server_t *server, int port);
int server_start(server_t *server);
void server_run(server_t *server);
void server_stop(server_t *server);
void server_cleanup(server_t *server);
```

### Route Registration

```c
int server_get(const char *path, route_handler_t handler);
int server_post(const char *path, route_handler_t handler);
int server_put(const char *path, route_handler_t handler);
int server_delete(const char *path, route_handler_t handler);
```

### Route Handler Example

```c
void my_handler(const http_request_t *request, http_response_t *response) {
    response_set_json(response, "{\"message\":\"Hello World\"}");
}
```

### Response Helpers

```c
void response_set_text(http_response_t *response, const char *text);
void response_set_html(http_response_t *response, const char *html);
void response_set_json(http_response_t *response, const char *json);
void response_set_file(http_response_t *response, const char *filepath);
```

## Architecture

### Request Flow

1. **Accept Connection**: Server accepts incoming client connections
2. **Parse Request**: Raw HTTP data is parsed into structured format
3. **Route Matching**: URL and method are matched against registered routes
4. **Handler Execution**: Matched route handler processes the request
5. **Response Building**: Handler builds appropriate HTTP response
6. **Send Response**: Complete response is sent to client
7. **Connection Close**: Connection is properly closed and cleaned up

### Memory Management

- All dynamically allocated memory is properly freed
- Request and response structures have init/cleanup functions
- Safe memory allocation utilities with error checking
- No memory leaks in normal operation

### Security Considerations

- Directory traversal protection for static files
- Input validation and sanitization
- Limited buffer sizes to prevent overflow attacks
- Proper error handling for malformed requests

## Development

### Adding New Routes

```c
// In main.c, add your handler function
void handle_my_api(const http_request_t *request, http_response_t *response) {
    // Your implementation here
    response_set_text(response, "Custom response");
}

// Register the route
server_get("/my-api", handle_my_api);
```

### Debugging

```bash
# Build with debug symbols
make debug

# Run with valgrind
make valgrind

# Enable debug logging
log_init(NULL, LOG_DEBUG);
```

### Code Quality

```bash
# Format code
make format

# Static analysis
make analyze
```

## Limitations

- Single-threaded (handles one request at a time)
- No HTTPS/TLS support
- Basic HTTP/1.1 implementation (no chunked encoding, etc.)
- Limited to POSIX systems
- No built-in authentication/authorization
- Simple routing (no URL parameters extraction)

## Educational Use

This project is designed for educational purposes to demonstrate:

- **Socket Programming**: Low-level network communication
- **Protocol Implementation**: HTTP request/response handling  
- **C Programming**: Memory management, string processing, file I/O
- **Software Architecture**: Modular design and separation of concerns
- **System Programming**: POSIX APIs and system calls

## Extending the Server

Common extensions you might implement:

1. **Multi-threading**: Handle concurrent requests
2. **URL Parameters**: Extract parameters from URLs like `/users/{id}`
3. **Middleware**: Add request/response middleware chain
4. **Sessions**: Implement session management
5. **WebSockets**: Add WebSocket protocol support
6. **HTTPS**: SSL/TLS encryption support
7. **Compression**: gzip response compression
8. **Caching**: HTTP caching headers and logic

## License

This project is provided for educational purposes. Feel free to use and modify as needed for learning and development.

## Contributing

This is an educational project, but improvements and bug fixes are welcome:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Troubleshooting

### Common Issues

**Port already in use**:
```bash
# Find process using the port
lsof -i :8080
# Kill the process or use a different port
```

**Permission denied**:
```bash
# Ports below 1024 require root privileges
sudo ./httpserver 80
```

**Compilation errors**:
```bash
# Ensure you have gcc and make installed
gcc --version
make --version
```