CC = gcc
CFLAGS = -W -Wall -g
#SERVER_FLAGS =
#CLIENT_FLAGS =

SERVER = server.out
CLIENT = client.out

project: sharedLibrary.o udp.o
	$(CC) $(CFLAGS) sharedLibrary.o server.c -o $(SERVER)
	$(CC) $(CFLAGS) sharedLibrary.o client.c -o $(CLIENT)

server: sharedLibrary.o server.c server.h
	$(CC) $(CFLAGS) sharedLibrary.o server.c -o $(SERVER)

client: sharedLibrary.o client.c client.h
	$(CC) $(CFLAGS) sharedLibrary.o client.c -o $(CLIENT)

sharedLibrary: sharedLibrary.c sharedLibrary.h
	$(CC) $(CFLAGS) -O -c sharedLibrary.c

clean:
	rm -f *.o *.bak *.out ex