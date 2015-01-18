CC = gcc
CFLAGS+ = -g
LDFLAGS = -lssl -lcrypto -lm
INCLUDES = -I.
COMMON_SOURCES = handshakeHelper.c networkHelper.c genericHelper.c client.c
TEST_SOURCES = handshakeHelper.c networkHelper.c genericHelper.c calls.c server.c
COMMON_OBJECTS = $(COMMON_SOURCES:.c=.o)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
EXECUTABLE = client
TEST_EXECUTABLE = server

all: client server

%.o:%.c
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

client: $(EXECUTABLE)

server: $(TEST_EXECUTABLE)

$(EXECUTABLE): $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

$(TEST_EXECUTABLE): $(TEST_OBJECTS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

.PHONY: all client server

clean: 
	rm client server


