CC = gcc
CFLAGS = -Wall -g
LIBS = -lX11 -ljpeg -lssl -lcrypto

all: server

server: server.c encryption.c screenshot.c protocol.c
	$(CC) $(CFLAGS) -o server server.c encryption.c screenshot.c protocol.c $(LIBS)

clean:
	rm -f server screenshot.jpg to_encrypt_file.txt encrypted_file.txt
