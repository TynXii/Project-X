#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>

#include "protocol.h"
#include "screenshot.h"
#include "encryption.h"



#include <stdint.h>

uint16_t calculate_checksum(const char *payload, size_t payload_length) {

    uint32_t sum = 0;
    size_t i;

    for (i = 0; i < payload_length; i++) {
        sum += (uint8_t)payload[i]; // Cast to uint8_t to handle byte-wise addition
    }

    // Fold sum to 16 bits by adding carry bits
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum); // Return the one's complement of the sum
}



int set_packet(protocol_packet_t *packet, const char *payload, const short payload_length, char mode, short checksum) {
    // Clear the packet structure to start fresh
    memset(packet, 0, sizeof(protocol_packet_t));

    // Set the magic number
    memcpy(packet->magic_number, (char[])MAGIC_NUMBER, sizeof(packet->magic_number));

    // Validate the mode and handle accordingly
    packet->mode = mode;

    if (payload == NULL) 
    {
        // For modes that don't require a payload
        if (mode == ACK_MODE || mode == FINAL_ACK_MODE) {
            packet->payload_length = 0;
            packet->checksum = 0; // No payload, no checksum required
        } 
        else 
        {
            perror("Payload required for this mode but NULL provided");
            return -1;
        }
    } 
    else 
    {
        // For modes that require a payload
        if (payload_length > MAX_PAYLOAD_SIZE) {
            perror("Payload exceeds maximum allowed size");
            return -1;
        }

        if (calculate_checksum(payload, payload_length) != checksum)
        {
            perror("Invalid packet.");
            return -1;
        }

        memcpy(packet->payload, payload, payload_length);
        packet->payload_length = payload_length;
        packet->checksum = checksum;
    }

    return 0;
}



// Interperet packet and serialize it on a buffer
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

    if (send(client_socket, buff, packet_size, 0) < 0)
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
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
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

    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
    if (client_socket < 0)
    {
        perror("Accept failed");
        close_communication(server_socket);
        exit(EXIT_FAILURE);
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



int handle_acknowledgment(int client_socket, char action_mode, char packet_mode) 
{
    char buffer[HEADER_SIZE];
    protocol_packet_t *temp_packet;

    temp_packet = (protocol_packet_t *) malloc(sizeof(HEADER_SIZE));

    switch (action_mode) 
    {
        case WAIT_FOR_ACK_PACKET: // Wait for an ACK or FINAL_ACK packet
            {
                if (recv_data(client_socket, buffer, sizeof(buffer)) <= 0) 
                {
                    perror("Failed to receive data");
                    return -1;
                }

                // Parse the received data into a packet
                if (set_packet(temp_packet, buffer, 0, packet_mode, *(buffer + sizeof(temp_packet->magic_number) + sizeof(packet_mode) + sizeof(temp_packet->payload_length))) < 0) 
                {
                    perror("Failed to parse packet");
                    return -1;
                }

                // Validate the mode of the received packet
                if (temp_packet->mode != ACK_MODE && temp_packet->mode != FINAL_ACK_MODE) {
                    fprintf(stderr, "Unexpected packet mode: %d\n", temp_packet->mode);
                    return -1;
                }

                return temp_packet->mode == ACK_MODE ? 0 : 1; // Return 0 for ACK, 1 for FINAL_ACK
            }

        case SEND_ACK_PACKET: // Send an ACK or FINAL_ACK packet
            {
                // Prepare the acknowledgment packet
                if (set_packet(temp_packet, NULL, 0, packet_mode, NULL) < 0) 
                {
                    perror("Failed to set acknowledgment packet");
                    return -1;
                }

                // Serialize the packet
                serialize_packet(temp_packet, buffer);

                // Send the acknowledgment packet
                if (send(client_socket, buffer, sizeof(buffer), 0) < 0) 
                {
                    perror("Failed to send acknowledgment packet");
                    return -1;
                }

                return 0;
            }

        default:
            fprintf(stderr, "Invalid action mode: %c\n", action_mode);
            return -1;
    }
}






int get_file(int client_socket, const size_t file_size, const char *file_name)
{
    _Bool extra_packet;
    size_t remaining_data_size;
    size_t packet_size;
    char buff[BUFFER_SIZE];
    FILE *given_file;

    extra_packet = (file_size % MAX_PAYLOAD_SIZE == 0) ? 0 : 1;

    given_file = fopen(file_name, "ab");
    remaining_data_size = file_size + HEADER_SIZE * (file_size / MAX_PAYLOAD_SIZE) + extra_packet * HEADER_SIZE; // Accounting for all data including header size

    while (remaining_data_size > 0) 
    {
        packet_size = (BUFFER_SIZE > remaining_data_size) ? remaining_data_size : BUFFER_SIZE;

        if (recv_data(client_socket, buff, packet_size) <= 0)
        {
            perror("Receiving data failed.");
            fclose(given_file);
            return -1;
        }

        if (handle_acknowledgment(client_socket, SEND_ACK_PACKET, ACK_MODE) != 0)
        {
            perror("ACK packet sending failed.");
            return -1;
        }

        if (fwrite(buff + HEADER_SIZE, sizeof(char), packet_size - HEADER_SIZE, given_file) != packet_size - HEADER_SIZE)
        {
            perror("Writing to file failed");
            fclose(given_file);
            return -1;
        }

        remaining_data_size -= packet_size;
    }

    if (handle_acknowledgment(client_socket, SEND_ACK_PACKET, FINAL_ACK_MODE) != 1)
    {
        perror("FINAL_ACK packet sending failed.");
        return -1;
    }

    fclose(given_file);
    return 0;
}


int send_file(int client_socket, const size_t file_size, const char *file_name)
{
    size_t remaining_data_size;
    size_t payload_size;
    char buff[MAX_PAYLOAD_SIZE];
    FILE *given_file;
    protocol_packet_t s_packet;

    given_file = fopen(file_name, "rb");
    if (!given_file)
    {
        perror("File opening failed");
        return -1;
    }

    remaining_data_size = file_size;

    while (remaining_data_size > 0) 
    {
        payload_size = (MAX_PAYLOAD_SIZE > remaining_data_size) ? remaining_data_size : MAX_PAYLOAD_SIZE;

        if (fread(buff, sizeof(char), payload_size, given_file) != payload_size)
        {
            perror("Reading from file failed.");
            fclose(given_file);
            return -1;
        }

        if (set_packet(&s_packet, buff, payload_size, FILE_TRANSFER_MODE, calculate_checksum(buff, payload_size)) < 0)
        {
            perror("Packet initialization failed.");
            fclose(given_file);
            return -1;
        }

        if (send_packet(client_socket, &s_packet) < 0)
        {
            perror("Packet sending failed.");
            fclose(given_file);
            return -1;
        }

        if (handle_acknowledgment(client_socket, WAIT_FOR_ACK_PACKET, ACK_MODE) != 0)
        {
            perror("ACK packet receiving failed.");
            fclose(given_file);
            return -1;
        }

        remaining_data_size -= payload_size;
    }

    if (handle_acknowledgment(client_socket, WAIT_FOR_ACK_PACKET, FINAL_ACK_MODE) != 1)
    {
        perror("FINAL_ACK packet receiving failed.");
        fclose(given_file);
        return -1;
    }

    fclose(given_file);
    return 0;
}


size_t get_file_size(const char *array, size_t num_bytes) 
{
    size_t number = 0;
    size_t i;

    for (i = 0 ; i < num_bytes; i++) 
    {
        number = (number << 8) | (unsigned char)array[i];
    }

    return number;
}


// Handles everything protocol-related
int handle_request()
{
    int client_socket;
    char buffer[BUFFER_SIZE];
    size_t file_size;
    struct stat file_stat;
    protocol_packet_t first_packet;

    client_socket = initialize_communication(PORT);

    if (recv_data(client_socket, buffer, BUFFER_SIZE) <= 0)
    {
        close_communication(client_socket);
        exit(EXIT_FAILURE);
    }

    if (set_packet(&first_packet, buffer + HEADER_SIZE, *(short *)(buffer + MAGIC_NUMBER_SIZE + sizeof(first_packet.mode)), buffer[MAGIC_NUMBER_SIZE], *(short *)(buffer + MAGIC_NUMBER_SIZE + sizeof(first_packet.mode) + sizeof(first_packet.payload_length))) < 0)
    {
        close_communication(client_socket);
        exit(EXIT_FAILURE);
    }

    switch (first_packet.mode) 
    {
        case SCREENSHOT_MODE:
            if (take_screenshot(DEFAULT_SCREENSHOT_FILE_NAME) != 0)
            {
                perror("Screenshot failed.");
                return -1;
            }

            stat(DEFAULT_SCREENSHOT_FILE_NAME, &file_stat);
            file_size = file_stat.st_size;

            if (send_file(client_socket, file_size, DEFAULT_SCREENSHOT_FILE_NAME) < 0)
            {
                perror("Sending file failed.");
                close_communication(client_socket);
                return -1;
            }

            printf("Screenshot sent successfully.\n");
            break;

        case ENCRYPT_MODE:
            file_size = get_file_size(first_packet.payload, first_packet.payload_length); // An ENCRYPT_MODE packet should have the file size specified in its payload

            if (get_file(client_socket, file_size, DEFAULT_TO_ENCRYPT_FILE_NAME) < 0)
            {
                perror("Failed to receive file.");
                close_communication(client_socket);
                return -1;
            }

            if (encrypt_file(DEFAULT_TO_ENCRYPT_FILE_NAME, DEFAULT_ENCRYPTED_FILE_NAME) != 0)
            {
                perror("Failed to encrypt file.");
                close_communication(client_socket);
                return -1;
            }

            stat(DEFAULT_ENCRYPTED_FILE_NAME, &file_stat);
            file_size = file_stat.st_size;

            if (send_file(client_socket, file_size, DEFAULT_ENCRYPTED_FILE_NAME) < 0)
            {
                perror("Failed to send file.");
                close_communication(client_socket);
                return -1;
            }

            printf("Successfully encrypted file and sent it back to client.\n");
            break;

        default:
            fprintf(stderr, "Invalid packet mode received.\n");
            close_communication(client_socket);
            return -1;
    }

    printf("Program operation successful.\n");
    close_communication(client_socket);
    return 0;
}