CC = gcc
CCFLAGS = -lssl -g -lpthread
all: client server
client: client.c header.h
	$(CC) $(CCFLAGS) client.c -o client
	mv client client_files

server: server.c header.h
	$(CC) $(CCFLAGS) server.c -o server
	mv server server_files

clean:
	rm -rf server_files/server client_files/client
