#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "protocol.h"
#include "screenshot.h"
#include "encryption.h"


#define PORT 8080
#define BUFFER_SIZE 1024
#define SCREENSHOT 0x01
#define ENCRYPT_FILE 0x02
#define BEGIN_FILE_TRANSFER 0x03 // Should only be interpreted by client
#define FILE_TRANSFER 0x04
#define ACK 0x05
#define FINAL_ACK 0x06
#define MAGIC_NUMBER 0x484D53 // Encoded 'HMS'
#define MAGIC_STR "HMS"


typedef struct {
    char magic_number[4];
    char mode;
    short payload_length;
    short checksum;
    char payload[1017];

} packet_t;


void close_communication(int sock) {
    close(sock);
    printf("Connection closed.\n");
}


int initialize_communication(int port)
{
    int socket_fd, server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    client_len = sizeof(client_addr);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server_socket<0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, server_addr, sizeof(server_addr)) < 0)
    {
        perror("Bind failed");
        close_communication(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 5) < 0)
    {
        perror("Listen failed");
        close_communication(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", port);

    client_socket = accept(server_socket, (struct sockaddr*) &client_addr, &client_len);
    if (client_socket < 0)
    {
        perror("Accept failed");
        continue;
    }

    close(server_socket);

    return client_socket;
}



int recv_data(int client_socket, char *buffer, size_t buffer_size) {
    int bytes_received;
    int retry_count = 0;

    while (1) {
        bytes_received = recv(client_socket, buffer, buffer_size - 1, 0);

        if (bytes_received < 0) {
            if (errno == EINTR) {
                // Retry after an interruption
                continue;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Retry due to temporarily no data available
                if (retry_count < MAX_RETRIES) {
                    retry_count++;
                    usleep(1000); // Small delay before retry (1ms)
                    continue;
                } else {
                    printf("Max retries reached, connection may be stalled.\n");
                    return -1;
                }
            } else {
                // Fatal error
                perror("Receiving data failed");
                return -1;
            }
        } else if (bytes_received == 0) {
            // Connection closed by peer
            return 0;
        } else {
            // Data successfully received
            buffer[bytes_received] = '\0';
            return bytes_received;
        }
    }
}

int set_packet(packet_t *packet, char *buffer) {
    if (strncmp(buffer, MAGIC_NUMBER, sizeof(MAGIC_NUMBER) - 1) != 0) {
        perror("Not withstanding protocol requirements")
        return -1;
    }

    memcpy(packet->magic_number, buffer, sizeof(MAGIC_STR) - 1);
    packet->mode = buffer[3];
    packet->payload_length = *(short *)(buffer + 4);
    packet->checksum = *(short *)(buffer + 6);
    memcpy(packet->payload, buffer + 8, packet->payload_length);

    return 0;
}


void handle_request(int client_socket) 
{
    int client_socket;
    char buffer[BUFFER_SIZE+1] = { 0 };
    packet_t* packet;

    client_socket = initialize_communication(PORT);

    if (recv_data(client_socket, buffer, BUFFER_SIZE) <= 0)
    {
        close_communication(client_socket);
        exit(EXIT_FAILURE);
    }

    if (set_packet(packet, buffer) < 0)
    {
        close_communication(client_socket);
        exit(EXIT_FAILURE);
    }

    






}