# Makefile for Baby Apache

CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude
SRC = src
OBJ = build
BIN = baby_server

SRCS = $(wildcard $(SRC)/*.c)
OBJS = $(patsubst $(SRC)/%.c,$(OBJ)/%.o,$(SRCS))

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ)/%.o: $(SRC)/%.c | $(OBJ)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ):
	mkdir -p $(OBJ)

clean:
	rm -rf $(OBJ) $(BIN)

run: $(BIN)
	./$(BIN) 8080
