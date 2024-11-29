#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "protocol.h"
#include "screenshot.h"
#include "encryption.h"




int set_packet(protocol_packet_t *packet, const char *buffer, char mode) {
    memset(packet, 0, sizeof(protocol_packet_t));

    memcpy(packet->magic_number, (char[])MAGIC_NUMBER, sizeof(packet->magic_number));

    if (buffer == NULL) {
        if (mode == ACK_MODE || mode == FINAL_ACK_MODE) {
            packet->mode = mode;
            packet->payload_length = 0;
            packet->checksum = 0; // No payload to calculate a checksum
            return 0;
        } else {
            perror("Invalid mode for NULL payload");
            return -1;
        }
    }

    size_t payload_length = strlen(buffer);
    if (payload_length > MAX_PAYLOAD_SIZE) {
        perror("Payload exceeds maximum size");
        return -1;
    }

    packet->mode = mode;
    packet->payload_length = payload_length;
    memcpy(packet->payload, buffer, payload_length);
    packet->checksum = calculate_checksum(packet->payload, packet->payload_length);

    return 0;
}




// Interperet packet and serialize it based on a buffer(Payload)
void serialize_packet(const protocol_packet_t *packet, char *buffer) {
    size_t offset = 0;

    // Serialize the magic number
    memcpy(buffer + offset, packet->magic_number, sizeof(packet->magic_number));
    offset += sizeof(packet->magic_number);

    // Serialize the mode
    buffer[offset] = packet->mode;
    offset += sizeof(packet->mode);

    // Serialize the payload length
    memcpy(buffer + offset, &packet->payload_length, sizeof(packet->payload_length));
    offset += sizeof(packet->payload_length);

    // Serialize the checksum
    memcpy(buffer + offset, &packet->checksum, sizeof(packet->checksum));
    offset += sizeof(packet->checksum);

    // Serialize the payload, if present
    if (packet->payload_length > 0) {
        memcpy(buffer + offset, packet->payload, packet->payload_length);
    }
}


int send_packet(int client_socket, const protocol_packet_t *packet)
{
    size_t packet_size;
    char buff[HEADER_SIZE+packet->payload_length];


    packet_size = HEADER_SIZE+packet->payload_length;

    serialize_packet(packet, buff);

    if (send(client_socket, buff, packet_size) < 0)
    {
        perror("Send failed");
        return -1;
    }

    return 0;

}



void close_communication(int sock) 
{
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


int recv_data(int client_socket, char *buffer, size_t buffer_size) 
{
    int bytes_received;
    int retry_count = 0;

    while (1) {
        bytes_received = recv(client_socket, buffer, buffer_size, 0);

        if (bytes_received < 0) 
        {
            switch (errno) {
                case EINTR:
                    // Retry after an interruption
                    continue;
                case EAGAIN:
                case EWOULDBLOCK:
                    // Retry due to temporarily no data available
                    if (retry_count < MAX_RETRIES) {
                        retry_count++;
                        usleep(RETRY_DELAY); // Small delay before retry (1ms)
                        continue;
                    } 
                    else 
                    {
                        printf("Max retries reached, connection may be stalled.\n");
                        return -1;
                    }
                default:
                    // Fatal error
                    perror("Receiving data failed");
                    return -1;
            }
        } 
        else if (bytes_received == 0) 
        {
            // Connection closed by peer
            return 0;
        } 
        else 
        {
            // Data successfully received
            return bytes_received;
        }
    }
}

int get_file(int client_socket, const unsigned long long file_size, const char *file_name)
{
    unsigned long long remaining_data_size;
    size_t packet_size;
    char buff[BUFFER_SIZE];
    FILE *given_file;


    given_file = fopen(file_name, "ab");
    remaining_data_size = file_size;

    while (remaining_data_size > 0) 
    {
        
        packet_size = (BUFFER_SIZE > remaining_data_size) ? remaining_data_size : BUFFER_SIZE;

        if (recv_data(client_socket, buff, packet_size) <= 0)
        {
            perror("Receiving data failed.");
            return -1;
        }
        if (fwrite(buff[HEADER_SIZE], sizeof(char), packet_size-HEADER_SIZE, given_file)!= packet_size)
        {
            perror("Writing to file failed");
            return -1;
        }
        remaining_data_size -= packet_size;
    }

    return remaining_data_size;


}


int send_file(int client_socket, const unsigned long long file_size, const char *file_name)
{
    unsigned long long remaining_data_size;
    size_t packet_size;
    char buff[BUFFER_SIZE];
    FILE *given_file;
    int packet_size;
    protocol_packet_t *s_packet;

    given_file = fopen(file_name, "rb");
    remaining_data_size = file_size;

    while (remaining_data_size > 0) 
    {
        packet_size = (MAX_PAYLOAD_SIZE > remaining_data_size) ? remaining_data_size : MAX_PAYLOAD_SIZE;

        if (fread(buff, sizeof(char), packet_size, given_file) != packet_size)
        {
            perror("Reading from file failed.");
            return -1;
        }

        if (set_packet(s_packet, buff) < 0)
        {
            perror("Packet initialization failed.");
            return -1;
        }

        if (send_packet(client_socket, s_packet) < 0)
        {
            perror("Packet sending failed.");
            return -1;
        }

        remaining_data_size -= packet_size;

        return 0;




        

    }



}



int handle_file_transfer(int client_socket, const char *file_name, const protocol_packet_t *packet, const char mode)
{
    struct stat file_stat;

    switch (mode) 
    {
        
        case SCREENSHOT_MODE:
            if (take_screenshot(file_name) < 0)
            {
                perror("Screenshot failed.");
                return -1;
            }
            stat(file_name, &file_stat);

        case ENCRYPT_MODE:
            file_stat.st_size = *((unsigned long long *) packet->payload) // An ENCRYPT_MODE packet should have the file size specified in its payload





            

    }


}


int handle_request(int client_socket) 
{
    int client_socket;
    char buffer[BUFFER_SIZE];
    protocol_packet_t* client_packet, server_packet;

    client_socket = initialize_communication(PORT);

    if (recv_data(client_socket, buffer, BUFFER_SIZE) <= 0)
    {
        close_communication(client_socket);
        exit(EXIT_FAILURE);
    }

    if (set_packet(client_packet, buffer) < 0)
    {
        close_communication(client_socket);
        exit(EXIT_FAILURE);
    }

    switch (client_packet->mode) {

        case SCREENSHOT_MODE:
            if (handle_file_transfer(client_socket, DEFUALT_SCREENSHOT_FILE_NAME, client_packet, SCREENSHOT_MODE) != 0)
            {
                close_communication(client_socket);
            }
        
        case ENCRYPT_MODE:
            if (handle_file_transfer(client_socket, DEFUALT_ENCRYPTED_FILE_NAME, client_packet, ENCRYPT_MODE) != 0)
            {
                close_communication(client_socket);
            }
    }


}