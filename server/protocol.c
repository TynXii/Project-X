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



#include <stdint.h> // For uintX_t types like uint32_t, uint64_t

/**
 * @brief Calculates the CRC32 checksum for the given data.
 * 
 * This function computes the CRC32 checksum using a standard polynomial (0xEDB88320, reversed).
 * It processes the data byte by byte.
 * 
 * @param data Pointer to the data buffer.
 * @param length Length of the data in bytes.
 * @return The calculated CRC32 checksum.
 */
uint32_t calculate_crc32(const unsigned char *data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xFFFFFFFF;
}


/**
 * @brief Initializes a protocol_packet_t structure with provided data and validates fields.
 * 
 * This function is used to construct a packet object, typically from data received from the network
 * or when preparing a packet to be sent.
 * - It sets the magic number.
 * - For payload-less modes (ACK_MODE, FINAL_ACK_MODE), it ensures payload_length and checksum are 0.
 * - For modes with payloads, it validates the payload_length against MAX_PAYLOAD_SIZE.
 * - Crucially, if a payload is present, it validates the provided 'checksum' argument against
 *   a checksum calculated over the 'payload' and 'payload_length'. This is key for verifying
 *   the integrity of received packet data.
 * 
 * @param packet Pointer to the protocol_packet_t structure to be initialized.
 * @param payload Pointer to the payload data. Can be NULL if the packet mode implies no payload.
 * @param payload_length The length of the payload. Must be 0 if payload is NULL.
 * @param mode The packet mode (e.g., SCREENSHOT_MODE, ACK_MODE).
 * @param checksum The checksum to be validated against the payload if a payload is present. 
 *                 For payload-less packets, this should be 0. If constructing a packet to send,
 *                 the caller must pre-calculate this checksum.
 * @return 0 on success, -1 on error (e.g., checksum mismatch, payload too large, invalid parameters).
 */
int set_packet(protocol_packet_t *packet, const char *payload, const short payload_length, char mode, uint32_t checksum) {
    // Clear the packet structure to start fresh
    memset(packet, 0, sizeof(protocol_packet_t));

    // Set the magic number
    memcpy(packet->magic_number, (char[])MAGIC_NUMBER, sizeof(packet->magic_number));

    // Set the mode
    packet->mode = mode;

    if (payload == NULL) {
        // Handle modes that are defined to have no payload
        if (mode == ACK_MODE || mode == FINAL_ACK_MODE) {
            if (payload_length != 0) {
                fprintf(stderr, "set_packet: Payload length must be 0 for ACK/FINAL_ACK modes, but got %d.\n", payload_length);
                return -1;
            }
            if (checksum != 0) {
                fprintf(stderr, "set_packet: Checksum must be 0 for ACK/FINAL_ACK modes, but got %u.\n", checksum);
                return -1;
            }
            packet->payload_length = 0;
            packet->checksum = 0;
        } 
        // Add other payload-less modes here if any (e.g. initial SCREENSHOT_MODE from client)
        // For now, only ACKs are strictly payload-less from server's construction view.
        // FILE_SIZE_MODE has a payload (the size).
        // Initial SCREENSHOT_MODE or ENCRYPT_MODE from client might be considered payload-less by server if it only expects a command.
        // However, this function is also used for *parsing* received packets.
        // If a mode is defined as having no payload, payload_length should be 0.
        else if (payload_length == 0) { // General case for any mode if payload is NULL and length is 0
            packet->payload_length = 0;
            packet->checksum = 0; // Typically, no payload means no checksum or checksum is 0.
                                  // If a specific mode (not ACK/FINAL_ACK) is payload-less but has a non-zero checksum,
                                  // this logic might need adjustment, or the caller must ensure checksum is 0.
        }
        else {
            // Payload is NULL, but payload_length is non-zero, or mode is not a recognized payload-less mode.
            fprintf(stderr, "set_packet: Payload is NULL, but mode %d with payload_length %d is not a recognized payload-less type or length is non-zero.\n", mode, payload_length);
            return -1;
        }
    } else { // Payload is not NULL
        if (payload_length < 0) { // Should be unsigned, but defensive check
             fprintf(stderr, "set_packet: Invalid negative payload_length %d for mode %d.\n", payload_length, mode);
             return -1;
        }
        if (payload_length > MAX_PAYLOAD_SIZE) {
            fprintf(stderr, "set_packet: Payload length %d for mode %d exceeds maximum allowed size %d.\n", payload_length, mode, MAX_PAYLOAD_SIZE);
            return -1;
        }

        // If payload_length is 0, but payload is not NULL, calculate_crc32 will run on empty data.
        // The 'checksum' argument should match this (typically 0).
        if (calculate_crc32((const unsigned char *)payload, payload_length) != checksum) {
            fprintf(stderr, "set_packet: Checksum mismatch for mode %d. Expected %u, calculated for payload of length %d.\n", mode, checksum, payload_length);
            return -1;
        }

        memcpy(packet->payload, payload, payload_length);
        packet->payload_length = payload_length;
        packet->checksum = checksum;
    }

    return 0; // Success
}


/**
 * @brief Serializes a protocol_packet_t structure into a byte buffer for network transmission.
 * 
 * This function handles the correct byte order (network byte order - big-endian)
 * for multi-byte fields like payload_length (short) and checksum (uint32_t).
 * 
 * @param packet Pointer to the constant protocol_packet_t structure to be serialized.
 * @param buffer Pointer to the output buffer where the serialized packet will be written.
 *               The caller must ensure this buffer is large enough (HEADER_SIZE + packet->payload_length).
 */
void serialize_packet(const protocol_packet_t *packet, char *buffer) {
    size_t offset = 0;

    // Serialize the magic number
    memcpy(buffer + offset, packet->magic_number, sizeof(packet->magic_number));
    offset += sizeof(packet->magic_number);

    // Serialize the mode
    buffer[offset] = packet->mode;
    offset += sizeof(packet->mode);

    // Serialize the payload length
    short payload_length_net = htons(packet->payload_length);
    memcpy(buffer + offset, &payload_length_net, sizeof(payload_length_net));
    offset += sizeof(short);

    // Serialize the checksum
    uint32_t checksum_net = htonl(packet->checksum); // Ensure network byte order for uint32_t
    memcpy(buffer + offset, &checksum_net, sizeof(checksum_net));
    offset += sizeof(checksum_net);

    // Serialize the payload, if present
    if (packet->payload_length > 0) {
        memcpy(buffer + offset, packet->payload, packet->payload_length);
    }
}


/**
 * @brief Sends a protocol packet over the specified client socket.
 * 
 * The function first serializes the packet structure into a temporary buffer
 * and then sends this buffer over the socket.
 * 
 * @param client_socket The file descriptor of the client socket.
 * @param packet Pointer to the protocol_packet_t structure to be sent.
 *               Note: The function expects packet->payload_length to be correctly set.
 * @return 0 on successful transmission, -1 on failure (e.g., send error).
 */
int send_packet(int client_socket, const protocol_packet_t *packet) {
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


/**
 * @brief Closes the given socket file descriptor.
 * 
 * @param sock The socket file descriptor to be closed.
 */
void close_communication(int sock) {
    if (sock >= 0) { // Basic check for valid fd
        close(sock);
        printf("Connection closed for socket fd %d.\n", sock);
    }
}

/**
 * @brief Initializes the server: creates a socket, binds to the specified port,
 *        listens for incoming connections, and accepts one client connection.
 * 
 * Critical errors during initialization (socket, bind, listen, accept) will cause
 * the program to print an error and exit with EXIT_FAILURE.
 * 
 * @param port The port number the server should listen on.
 * @return The file descriptor for the connected client socket.
 */
int initialize_communication(int port) {
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

/**
 * @brief Receives data from a socket with retry logic for certain non-fatal errors.
 * 
 * This function attempts to receive up to 'buffer_size' bytes from the 'client_socket'.
 * It includes a retry mechanism for EINTR (interrupted system call) and
 * temporary unavailability errors (EAGAIN, EWOULDBLOCK), retrying up to MAX_RETRIES times
 * with a RETRY_DELAY between attempts.
 * 
 * @param client_socket The socket file descriptor to receive data from.
 * @param buffer Pointer to the buffer where received data will be stored.
 * @param buffer_size The maximum number of bytes to read into the buffer.
 * @return The number of bytes received on success.
 *         0 if the connection was closed by the peer.
 *         -1 on a fatal error, or if max retries are reached for temporary errors.
 */
int recv_data(int client_socket, char *buffer, size_t buffer_size) {
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


/**
 * @brief Handles sending or waiting for acknowledgment (ACK/FINAL_ACK) packets.
 * 
 * Based on 'action_mode':
 * - WAIT_FOR_ACK_PACKET: Receives an ACK packet, deserializes its header, and validates
 *   its fields (magic number, mode, payload length (0), checksum (0)).
 * - SEND_ACK_PACKET: Constructs and sends an ACK or FINAL_ACK packet.
 * 
 * @param client_socket The client socket file descriptor.
 * @param action_mode Determines the operation: 'w' (WAIT_FOR_ACK_PACKET) or 's' (SEND_ACK_PACKET).
 * @param packet_mode The specific mode of the ACK packet to send or expect 
 *                    (e.g., ACK_MODE, FINAL_ACK_MODE).
 * @return For WAIT_FOR_ACK_PACKET: 0 if the expected ACK_MODE is received and valid,
 *                                 1 if the expected FINAL_ACK_MODE is received and valid,
 *                                -1 on any error or if an unexpected/invalid packet is received.
 *         For SEND_ACK_PACKET: 0 on success, -1 on error.
 */
int handle_acknowledgment(int client_socket, char action_mode, char packet_mode) {
    char buffer[HEADER_SIZE]; // Buffer to receive ACK packet (if waiting)
    protocol_packet_t ack_packet_to_send; // Used for SEND_ACK_PACKET

    switch (action_mode)
    {
        case WAIT_FOR_ACK_PACKET: // Wait for an ACK or FINAL_ACK packet
            {
                if (recv_data(client_socket, buffer, HEADER_SIZE) <= 0)
                {
                    perror("Failed to receive ACK data");
                    return -1;
                }

                // Deserialize header directly from buffer
                char magic_received[MAGIC_NUMBER_SIZE];
                char mode_received;
                short payload_length_received_net, payload_length_received;
                uint32_t checksum_received_net, checksum_received;

                size_t offset = 0;
                memcpy(magic_received, buffer + offset, MAGIC_NUMBER_SIZE);
                offset += MAGIC_NUMBER_SIZE;

                mode_received = buffer[offset];
                offset += sizeof(char);

                memcpy(&payload_length_received_net, buffer + offset, sizeof(short));
                payload_length_received = ntohs(payload_length_received_net);
                offset += sizeof(short);

                memcpy(&checksum_received_net, buffer + offset, sizeof(uint32_t));
                checksum_received = ntohl(checksum_received_net);

                // Validate parts of the ACK packet
                if (memcmp(magic_received, (char[])MAGIC_NUMBER, MAGIC_NUMBER_SIZE) != 0) {
                    fprintf(stderr, "Invalid magic number in ACK packet.\n");
                    return -1;
                }
                // 'packet_mode' parameter here is the *expected* mode (ACK_MODE or FINAL_ACK_MODE)
                if (mode_received != packet_mode) {
                    fprintf(stderr, "Unexpected mode in ACK. Expected %d, Got %d\n", packet_mode, mode_received);
                    return -1;
                }
                if (payload_length_received != 0) {
                    fprintf(stderr, "ACK packet should have 0 payload length.\n");
                    return -1;
                }
                if (checksum_received != 0) {
                    fprintf(stderr, "ACK packet should have 0 checksum.\n");
                    return -1;
                }
                
                // free(temp_packet) is not needed as it's removed.
                return (mode_received == ACK_MODE) ? 0 : ((mode_received == FINAL_ACK_MODE) ? 1 : -1);
            }

        case SEND_ACK_PACKET: // Send an ACK or FINAL_ACK packet
            {
                // packet_mode parameter is the mode to send (ACK_MODE or FINAL_ACK_MODE)
                if (set_packet(&ack_packet_to_send, NULL, 0, packet_mode, 0) < 0)
                {
                    perror("Failed to set acknowledgment packet for sending");
                    return -1;
                }
                
                // Serialize the packet into a temporary buffer for sending
                char send_buffer[HEADER_SIZE]; // ACK packets are only header
                serialize_packet(&ack_packet_to_send, send_buffer);

                if (send(client_socket, send_buffer, HEADER_SIZE, 0) < 0)
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






/**
 * @brief Receives a file from the client and saves it to the specified path.
 * 
 * This function handles the reception of a file sent in chunks by the client.
 * Each chunk is expected as a FILE_TRANSFER_MODE packet. After receiving each data packet,
 * an ACK_MODE packet is sent back. After the final data packet, a FINAL_ACK_MODE packet is sent.
 * The function performs validation on received packets (magic number, mode, checksum - basic for now).
 * 
 * @param client_socket The client socket file descriptor.
 * @param file_size The total expected size of the file to be received, as indicated by the client.
 * @param file_name The path (including filename) where the received file will be saved.
 *                  The file is opened in "wb" mode (write binary, create/truncate).
 * @return HR_SUCCESS (0) on successful file reception and saving.
 *         A specific negative HR_ERROR code on failure (e.g., file open error, receive error, ACK error).
 */
int get_file(int client_socket, const size_t file_size, const char *file_name) {
    // _Bool extra_packet; // This variable seems unused with current logic.
    size_t remaining_data_size;
    size_t packet_size;
    char buff[BUFFER_SIZE];
    FILE *given_file;

    extra_packet = (file_size % MAX_PAYLOAD_SIZE == 0) ? 0 : 1;

    given_file = fopen(file_name, "wb"); // Use "wb" to create or truncate
    if (!given_file) {
        fprintf(stderr, "get_file: Failed to open file '%s': %s\n", file_name, strerror(errno));
        return HR_STAT_FILE_FAILED; // Or a new HR_FOPEN_FAILED
    }

    // Calculate actual data size to receive, excluding headers that will be sent by client per packet
    remaining_data_size = file_size; 

    while (remaining_data_size > 0) {
        // Determine how much of the header + payload to expect in this iteration
        // This logic seems to be from a previous version where server expected headers with data.
        // For get_file, client sends FILE_TRANSFER_MODE packets which include headers.
        // The server should read the full packet (header + payload chunk).
        // Let's assume client sends packets of (HEADER_SIZE + payload_chunk_size)
        // And payload_chunk_size is at most MAX_PAYLOAD_SIZE

        size_t expected_payload_chunk_size = (remaining_data_size > MAX_PAYLOAD_SIZE) ? MAX_PAYLOAD_SIZE : remaining_data_size;
        size_t expected_packet_size = HEADER_SIZE + expected_payload_chunk_size;
        
        // Ensure buffer is large enough for one full packet
        if (expected_packet_size > BUFFER_SIZE) {
             fprintf(stderr, "get_file: Calculated packet size %zu exceeds buffer %d\n", expected_packet_size, BUFFER_SIZE);
             fclose(given_file);
             return HR_ERROR_BASE - 20; // Internal logic error
        }

        int bytes_received = recv_data(client_socket, buff, expected_packet_size);
        if (bytes_received <= 0) {
            fprintf(stderr, "get_file: Receiving data failed (recv_data returned %d).\n", bytes_received);
            fclose(given_file);
            return HR_RECV_DATA_FAILED;
        }
        
        if ((size_t)bytes_received != expected_packet_size) {
            fprintf(stderr, "get_file: Received incomplete packet. Expected %zu, Got %d\n", expected_packet_size, bytes_received);
            fclose(given_file);
            return HR_RECV_DATA_FAILED;
        }

        // Basic validation of received packet (e.g. magic, mode)
        // For simplicity, directly writing payload assuming it's valid FILE_TRANSFER_MODE
        // A more robust implementation would deserialize and validate the header here.
        // char received_magic[MAGIC_NUMBER_SIZE];
        // memcpy(received_magic, buff, MAGIC_NUMBER_SIZE);
        // if (memcmp(received_magic, (char[])MAGIC_NUMBER, MAGIC_NUMBER_SIZE) != 0) { ... return HR_INVALID_MAGIC; }
        // if (buff[MAGIC_NUMBER_SIZE] != FILE_TRANSFER_MODE) { ... return HR_INVALID_PACKET_MODE; }
        // short payload_len_from_header = ntohs(*(short*)(buff + MAGIC_NUMBER_SIZE + sizeof(char)));
        // if (payload_len_from_header != expected_payload_chunk_size) { ... error ... }
        // uint32_t checksum_from_header = ntohl(*(uint32_t*)(buff + MAGIC_NUMBER_SIZE + sizeof(char) + sizeof(short)));
        // if (calculate_crc32((unsigned char*)buff + HEADER_SIZE, payload_len_from_header) != checksum_from_header) { ... error ...}


        if (fwrite(buff + HEADER_SIZE, sizeof(char), expected_payload_chunk_size, given_file) != expected_payload_chunk_size) {
            fprintf(stderr, "get_file: Writing to file '%s' failed: %s\n", file_name, strerror(errno));
            fclose(given_file);
            return HR_STAT_FILE_FAILED; // Or a new HR_FWRITE_FAILED
        }

        remaining_data_size -= expected_payload_chunk_size;

        // Send ACK for this data packet
        char ack_type_to_send = (remaining_data_size == 0) ? FINAL_ACK_MODE : ACK_MODE;
        if (handle_acknowledgment(client_socket, SEND_ACK_PACKET, ack_type_to_send) != 0 && ack_type_to_send == ACK_MODE) {
             fprintf(stderr, "get_file: Sending ACK_MODE failed.\n");
             fclose(given_file);
             return HR_ACK_FAILED;
        }
        if (handle_acknowledgment(client_socket, SEND_ACK_PACKET, ack_type_to_send) != 1 && ack_type_to_send == FINAL_ACK_MODE) {
             fprintf(stderr, "get_file: Sending FINAL_ACK_MODE failed.\n");
             fclose(given_file);
             return HR_ACK_FAILED;
        }
    }
    fclose(given_file);
    return HR_SUCCESS;
}


/**
 * @brief Sends a specified file to the client.
 * 
 * Reads the file in chunks, wraps each chunk in a FILE_TRANSFER_MODE packet,
 * and sends it to the client. After sending each packet, it waits for an ACK_MODE
 * acknowledgment from the client. After sending the last chunk, it expects a FINAL_ACK_MODE.
 * 
 * @param client_socket The client socket file descriptor.
 * @param file_size The total size of the file to be sent.
 * @param file_name The path (including filename) of the file to be sent.
 * @return HR_SUCCESS (0) on successful file transmission and acknowledgment.
 *         A specific negative HR_ERROR code on failure (e.g., file open/read error,
 *         packet creation error, send error, ACK error).
 */
int send_file(int client_socket, const size_t file_size, const char *file_name) {
    size_t remaining_data_size;
    size_t payload_size;
    char buff[MAX_PAYLOAD_SIZE];
    FILE *given_file;
    protocol_packet_t s_packet;

    given_file = fopen(file_name, "rb");
    if (!given_file) {
        fprintf(stderr, "send_file: File opening failed for '%s': %s\n", file_name, strerror(errno));
        return HR_STAT_FILE_FAILED; // Or a new HR_FOPEN_FAILED
    }

    remaining_data_size = file_size;

    while (remaining_data_size > 0) {
        payload_size = (remaining_data_size > MAX_PAYLOAD_SIZE) ? MAX_PAYLOAD_SIZE : remaining_data_size;

        if (fread(buff, 1, payload_size, given_file) != payload_size) {
            fprintf(stderr, "send_file: Reading from file '%s' failed: %s\n", file_name, strerror(errno));
            fclose(given_file);
            return HR_STAT_FILE_FAILED; // Or a new HR_FREAD_FAILED
        }

        uint32_t chunk_checksum = calculate_crc32((const unsigned char *)buff, payload_size);
        if (set_packet(&s_packet, buff, payload_size, FILE_TRANSFER_MODE, chunk_checksum) < 0) {
            fprintf(stderr, "send_file: Packet initialization failed.\n");
            fclose(given_file);
            return HR_SET_PACKET_FAILED;
        }

        if (send_packet(client_socket, &s_packet) < 0) {
            fprintf(stderr, "send_file: Packet sending failed.\n");
            fclose(given_file);
            return HR_SEND_PACKET_FAILED;
        }
        
        char expected_ack_type = (remaining_data_size - payload_size == 0) ? FINAL_ACK_MODE : ACK_MODE;
        int ack_result = handle_acknowledgment(client_socket, WAIT_FOR_ACK_PACKET, expected_ack_type);

        if (expected_ack_type == ACK_MODE && ack_result != 0) {
            fprintf(stderr, "send_file: ACK_MODE packet receiving failed (result: %d).\n", ack_result);
            fclose(given_file);
            return HR_ACK_FAILED;
        }
        if (expected_ack_type == FINAL_ACK_MODE && ack_result != 1) {
            fprintf(stderr, "send_file: FINAL_ACK_MODE packet receiving failed (result: %d).\n", ack_result);
            fclose(given_file);
            return HR_ACK_FAILED;
        }
        remaining_data_size -= payload_size;
    }

    fclose(given_file);
    return HR_SUCCESS;
}

/**
 * @brief Extracts a file size from a byte array (payload).
 * 
 * Assumes the file size is encoded in big-endian byte order within the array.
 * This function is typically used to parse the payload of an ENCRYPT_MODE packet
 * from the client, which contains the size of the original file to be encrypted.
 * 
 * @param array Pointer to the character array (byte buffer) containing the size.
 * @param num_bytes The number of bytes in the array that represent the size (e.g., 8 for uint64_t).
 * @return The extracted file size as a size_t.
 */
size_t get_file_size(const char *array, size_t num_bytes) {
    size_t number = 0;
    size_t i;

    for (i = 0 ; i < num_bytes; i++) 
    {
        number = (number << 8) | (unsigned char)array[i];
    }

    return number;
}


/**
 * @brief Main server logic to handle a single client connection and its requests.
 * 
 * This function performs the following steps:
 * 1. Initializes communication by accepting a client connection.
 * 2. Receives the initial request packet from the client.
 * 3. Deserializes and validates the initial packet (magic number, checksum).
 * 4. Based on the packet mode (SCREENSHOT_MODE or ENCRYPT_MODE), performs the requested operation:
 *    - **SCREENSHOT_MODE**: Takes a screenshot, saves to a temporary file, sends its size
 *      (FILE_SIZE_MODE), waits for ACK, then sends the file content (FILE_TRANSFER_MODE).
 *    - **ENCRYPT_MODE**: Receives original file size from client's initial packet,
 *      receives the file to be encrypted (saving to a temporary file), encrypts it
 *      (to another temporary file), sends the encrypted file's size (FILE_SIZE_MODE),
 *      waits for ACK, then sends the encrypted file content (FILE_TRANSFER_MODE).
 * 5. Cleans up any temporary files created.
 * 6. Closes the client connection.
 * 
 * @return HR_SUCCESS (0) if the client's request was handled successfully.
 *         A specific negative HR_ERROR code if any part of the process fails.
 */
int handle_request() {
    int client_socket;
    char buffer[BUFFER_SIZE];
    size_t file_size;
    struct stat file_stat;
    protocol_packet_t first_packet;

    client_socket = initialize_communication(PORT);
    // initialize_communication calls exit() on critical failures.
    // If it were changed to return an error code, we would check it here:
    // if (client_socket < 0) {
    //     fprintf(stderr, "handle_request: Initialization failed.\n");
    //     return HR_INIT_COMM_FAILED;
    // }

    if (recv_data(client_socket, buffer, BUFFER_SIZE) <= 0) {
        fprintf(stderr, "handle_request: Initial data reception failed.\n");
        close_communication(client_socket);
        return HR_RECV_DATA_FAILED;
    }

    // Deserialize the initial request packet
    short payload_len;
    uint32_t received_checksum_net, received_checksum;
    char received_mode;
    char received_magic[MAGIC_NUMBER_SIZE];
    short payload_len_net; // For network byte order

    size_t offset = 0;
    memcpy(received_magic, buffer + offset, MAGIC_NUMBER_SIZE);
    offset += MAGIC_NUMBER_SIZE;
    received_mode = buffer[offset];
    offset += sizeof(char);
    memcpy(&payload_len_net, buffer + offset, sizeof(short));
    payload_len = ntohs(payload_len_net); // Convert to host byte order
    offset += sizeof(short);
    memcpy(&received_checksum_net, buffer + offset, sizeof(uint32_t));
    received_checksum = ntohl(received_checksum_net);

    if (memcmp(received_magic, (char[])MAGIC_NUMBER, MAGIC_NUMBER_SIZE) != 0) {
        fprintf(stderr, "handle_request: Invalid magic number in initial packet.\n");
        close_communication(client_socket);
        return HR_INVALID_MAGIC;
    }
    
    if (set_packet(&first_packet, buffer + HEADER_SIZE, payload_len, received_mode, received_checksum) < 0) {
        // set_packet prints its own errors via perror.
        fprintf(stderr, "handle_request: Initial packet validation/setting failed.\n");
        close_communication(client_socket);
        return HR_SET_PACKET_FAILED;
    }

    switch (first_packet.mode)
    {
        case SCREENSHOT_MODE: {
            char *screenshot_tmp_filename = NULL;
            screenshot_tmp_filename = take_screenshot();
            if (!screenshot_tmp_filename) {
                // take_screenshot prints its own errors.
                fprintf(stderr, "handle_request: Screenshot capture operation failed.\n");
                close_communication(client_socket); 
                return HR_SCREENSHOT_FAILED;
            }

            if (stat(screenshot_tmp_filename, &file_stat) != 0) {
                fprintf(stderr, "handle_request: Failed to stat temporary screenshot file '%s': %s\n", screenshot_tmp_filename, strerror(errno));
                free(screenshot_tmp_filename);
                remove(screenshot_tmp_filename); 
                close_communication(client_socket);
                return HR_STAT_FILE_FAILED;
            }
            file_size = file_stat.st_size;

            protocol_packet_t size_packet_ss;
            uint64_t file_size_net_ss = htobe64(file_size);
            char size_payload_ss[sizeof(uint64_t)];
            memcpy(size_payload_ss, &file_size_net_ss, sizeof(uint64_t));
            uint32_t size_checksum_ss = calculate_crc32((const unsigned char *)size_payload_ss, sizeof(uint64_t));

            if (set_packet(&size_packet_ss, size_payload_ss, sizeof(uint64_t), FILE_SIZE_MODE, size_checksum_ss) < 0) {
                fprintf(stderr, "handle_request: Failed to set FILE_SIZE_MODE packet for screenshot.\n");
                free(screenshot_tmp_filename);
                remove(screenshot_tmp_filename);
                close_communication(client_socket);
                return HR_SET_PACKET_FAILED;
            }
            if (send_packet(client_socket, &size_packet_ss) < 0) {
                // send_packet prints its own perror.
                fprintf(stderr, "handle_request: Failed to send FILE_SIZE_MODE packet for screenshot.\n");
                free(screenshot_tmp_filename);
                remove(screenshot_tmp_filename);
                close_communication(client_socket);
                return HR_SEND_PACKET_FAILED;
            }
            if (handle_acknowledgment(client_socket, WAIT_FOR_ACK_PACKET, ACK_MODE) != 0) {
                // handle_acknowledgment prints its own errors.
                fprintf(stderr, "handle_request: Failed to receive ACK for FILE_SIZE_MODE (screenshot).\n");
                free(screenshot_tmp_filename);
                remove(screenshot_tmp_filename);
                close_communication(client_socket);
                return HR_ACK_FAILED;
            }

            int send_ss_rc = send_file(client_socket, file_size, screenshot_tmp_filename);
            // send_file now returns HR_* codes or HR_SUCCESS.
            
            printf("Cleaning up temporary screenshot file: %s\n", screenshot_tmp_filename);
            free(screenshot_tmp_filename);
            remove(screenshot_tmp_filename); 

            if (send_ss_rc != HR_SUCCESS) {
                 fprintf(stderr, "handle_request: Sending screenshot file failed (error code from send_file: %d).\n", send_ss_rc);
                 close_communication(client_socket); 
                 return send_ss_rc; // Propagate specific error from send_file
            }
            printf("Screenshot sent successfully.\n");
            break;
        }

        case ENCRYPT_MODE: {
            size_t incoming_file_size = get_file_size(first_packet.payload, first_packet.payload_length);
            char to_encrypt_template[] = "/tmp/toencryptXXXXXX";
            int fd_to_encrypt = mkstemp(to_encrypt_template);
            char *to_encrypt_tmp_filename = NULL;

            if (fd_to_encrypt == -1) {
                fprintf(stderr, "handle_request: mkstemp for to_encrypt_tmp_filename failed: %s\n", strerror(errno));
                close_communication(client_socket);
                return HR_MKSTEMP_FAILED;
            }
            close(fd_to_encrypt); 
            to_encrypt_tmp_filename = strdup(to_encrypt_template);
            if (!to_encrypt_tmp_filename) {
                fprintf(stderr, "handle_request: strdup for to_encrypt_tmp_filename failed: %s\n", strerror(errno));
                remove(to_encrypt_template); 
                close_communication(client_socket);
                return HR_STRDUP_FAILED;
            }
            
            int get_file_rc = get_file(client_socket, incoming_file_size, to_encrypt_tmp_filename);
            // get_file now returns HR_* codes or HR_SUCCESS
            if (get_file_rc != HR_SUCCESS) {
                fprintf(stderr, "handle_request: Failed to receive file for encryption (error code from get_file: %d).\n", get_file_rc);
                free(to_encrypt_tmp_filename);
                remove(to_encrypt_tmp_filename);
                close_communication(client_socket);
                return get_file_rc; // Propagate specific error
            }

            char *encrypted_output_tmp_filename = NULL;
            encrypted_output_tmp_filename = encrypt_file(to_encrypt_tmp_filename); 
            
            printf("Cleaning up temporary input file: %s\n", to_encrypt_tmp_filename);
            free(to_encrypt_tmp_filename);
            remove(to_encrypt_tmp_filename);

            if (!encrypted_output_tmp_filename) {
                // encrypt_file prints its own errors.
                fprintf(stderr, "handle_request: File encryption operation failed.\n");
                close_communication(client_socket);
                return HR_ENCRYPT_FILE_FAILED;
            }
            
            if (stat(encrypted_output_tmp_filename, &file_stat) != 0) {
                fprintf(stderr, "handle_request: Failed to stat temporary encrypted file '%s': %s\n", encrypted_output_tmp_filename, strerror(errno));
                free(encrypted_output_tmp_filename);
                remove(encrypted_output_tmp_filename);
                close_communication(client_socket);
                return HR_STAT_FILE_FAILED;
            }
            file_size = file_stat.st_size;

            protocol_packet_t enc_size_packet;
            uint64_t enc_file_size_net = htobe64(file_size);
            char enc_size_payload[sizeof(uint64_t)];
            memcpy(enc_size_payload, &enc_file_size_net, sizeof(uint64_t));
            uint32_t enc_size_checksum = calculate_crc32((const unsigned char *)enc_size_payload, sizeof(uint64_t));

            if (set_packet(&enc_size_packet, enc_size_payload, sizeof(uint64_t), FILE_SIZE_MODE, enc_size_checksum) < 0) {
                fprintf(stderr, "handle_request: Failed to set FILE_SIZE_MODE packet for encrypted file.\n");
                free(encrypted_output_tmp_filename);
                remove(encrypted_output_tmp_filename);
                close_communication(client_socket);
                return HR_SET_PACKET_FAILED;
            }
            if (send_packet(client_socket, &enc_size_packet) < 0) {
                fprintf(stderr, "handle_request: Failed to send FILE_SIZE_MODE packet for encrypted file.\n");
                free(encrypted_output_tmp_filename);
                remove(encrypted_output_tmp_filename);
                close_communication(client_socket);
                return HR_SEND_PACKET_FAILED;
            }
            if (handle_acknowledgment(client_socket, WAIT_FOR_ACK_PACKET, ACK_MODE) != 0) {
                fprintf(stderr, "handle_request: Failed to receive ACK for FILE_SIZE_MODE (encrypted file).\n");
                free(encrypted_output_tmp_filename);
                remove(encrypted_output_tmp_filename);
                close_communication(client_socket);
                return HR_ACK_FAILED;
            }
            
            int send_enc_rc = send_file(client_socket, file_size, encrypted_output_tmp_filename);
            // send_file now returns HR_* codes or HR_SUCCESS
            
            printf("Cleaning up temporary encrypted file: %s\n", encrypted_output_tmp_filename);
            free(encrypted_output_tmp_filename);
            remove(encrypted_output_tmp_filename); 

            if (send_enc_rc != HR_SUCCESS) {
                fprintf(stderr, "handle_request: Sending encrypted file failed (error code from send_file: %d).\n", send_enc_rc);
                 close_communication(client_socket); 
                return send_enc_rc; // Propagate specific error
            }
            printf("Encrypted file sent successfully.\n");
            break;
        }
        default:
            fprintf(stderr, "handle_request: Invalid initial packet mode received: %d.\n", first_packet.mode);
            close_communication(client_socket);
            return HR_INVALID_PACKET_MODE;
    }

    printf("Server operation completed successfully (end of handle_request).\n");
    close_communication(client_socket);
    return HR_SUCCESS;
}