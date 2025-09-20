# Makefile for Simple HTTP Server

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -pedantic -O2 -Iinclude
LDFLAGS = 
LIBS = 

# Debug flags
DEBUG_CFLAGS = -Wall -Wextra -std=c99 -pedantic -g -DDEBUG -O0 -Iinclude
DEBUG_LDFLAGS = 

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
HEADERS = $(wildcard $(INCDIR)/*.h)

# Target executable
TARGET = httpserver

# Default target
all: $(OBJDIR) $(TARGET)

# Debug target
debug: CFLAGS = $(DEBUG_CFLAGS)
debug: LDFLAGS = $(DEBUG_LDFLAGS)
debug: $(OBJDIR) $(TARGET)

# Create object directory
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Build target
$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf $(OBJDIR) $(TARGET)

# Clean and rebuild
rebuild: clean all

# Install (copy to /usr/local/bin)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	chmod +x /usr/local/bin/$(TARGET)

# Uninstall
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Create static directory for serving files
setup:
	mkdir -p static
	echo "<!DOCTYPE html><html><head><title>Static File</title></head><body><h1>Hello from static file!</h1></body></html>" > static/index.html
	echo "body { font-family: Arial, sans-serif; background: #f0f0f0; }" > static/style.css
	echo "console.log('Hello from JavaScript!');" > static/app.js

# Run the server (development)
run: $(TARGET)
	./$(TARGET) 8080

# Run with valgrind for memory debugging
valgrind: debug
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TARGET) 8080

# Format code using clang-format
format:
	clang-format -i $(SRCDIR)/*.c $(INCDIR)/*.h

# Static analysis with cppcheck
analyze:
	cppcheck --enable=all --std=c99 -I$(INCDIR) $(SRCDIR)/*.c

# Create distribution package
dist: clean
	tar -czf httpserver.tar.gz $(SRCDIR)/ $(INCDIR)/ Makefile README.md

# Test the server with curl
test: $(TARGET)
	@echo "Starting server in background..."
	@./$(TARGET) 8888 &
	@SERVER_PID=$!; \
	sleep 2; \
	echo "Testing endpoints..."; \
	curl -s http://localhost:8888/ > /dev/null && echo "✓ GET / - OK" || echo "✗ GET / - FAILED"; \
	curl -s http://localhost:8888/api/hello > /dev/null && echo "✓ GET /api/hello - OK" || echo "✗ GET /api/hello - FAILED"; \
	curl -s http://localhost:8888/api/users > /dev/null && echo "✓ GET /api/users - OK" || echo "✗ GET /api/users - FAILED"; \
	curl -s -X POST -d "test data" http://localhost:8888/api/echo > /dev/null && echo "✓ POST /api/echo - OK" || echo "✗ POST /api/echo - FAILED"; \
	kill $SERVER_PID; \
	echo "Tests completed."

# Help target
help:
	@echo "Available targets:"
	@echo "  all        - Build the HTTP server (default)"
	@echo "  debug      - Build with debug symbols"
	@echo "  clean      - Remove build artifacts"
	@echo "  rebuild    - Clean and rebuild"
	@echo "  install    - Install to /usr/local/bin"
	@echo "  uninstall  - Remove from /usr/local/bin"
	@echo "  setup      - Create static directory with sample files"
	@echo "  run        - Build and run the server on port 8080"
	@echo "  valgrind   - Run with valgrind memory checker"
	@echo "  format     - Format code with clang-format"
	@echo "  analyze    - Static analysis with cppcheck"
	@echo "  dist       - Create distribution package"
	@echo "  test       - Run basic functionality tests"
	@echo "  dirs       - Create directory structure (src/, include/, obj/)"
	@echo "  organize   - Move .c files to src/ and .h files to include/"
	@echo "  help       - Show this help message"

# Phony targets
.PHONY: all debug clean rebuild install uninstall setup run valgrind format analyze dist test help

# Additional targets for directory structure management
dirs:
	mkdir -p $(SRCDIR) $(INCDIR) $(OBJDIR) static

# Move files to proper structure (if they exist in root)
organize:
	@echo "Organizing project structure..."
	@mkdir -p $(SRCDIR) $(INCDIR)
	@if [ -f "main.c" ]; then mv *.c $(SRCDIR)/ 2>/dev/null || true; fi
	@if [ -f "request.h" ]; then mv *.h $(INCDIR)/ 2>/dev/null || true; fi
	@echo "Files organized into $(SRCDIR)/ and $(INCDIR)/"