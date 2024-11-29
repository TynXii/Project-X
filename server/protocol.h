#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

// Main Packet Modes
#define SCREENSHOT_MODE 0x01
#define ENCRYPT_MODE 0x02

// Modes meant for handling the main packet modes
#define FILE_TRANSFER_MODE 0x03
#define ACK_MODE 0x04
#define FINAL_ACK_MODE 0x05



// Protocol Configuration
#define PORT 8080
#define BUFFER_SIZE 1024
#define HEADER_SIZE 8
#define MAGIC_NUMBER {0x48 0x4D, 0x53} // Encoded 'HMS'
#define MAX_PAYLOAD_SIZE 1016
#define MAX_RETRIES 5
#define RETRY_DELAY 1000
// bash file will make sure files aren't duplicated
#define DEFUALT_SCREENSHOT_FILE_NAME "screenshot.jpg"
#define DEFUALT_ENCRYPTED_FILE_NAME "encrypted_file.txt"



// Packet structure

typedef struct {
    char magic_number[MAGIC_NUMBER];
    char mode;
    short payload_length;
    short checksum;
    char payload[MAX_PAYLOAD_SIZE]
} protocol_packet_t;





// Protocol Packet handling functions

int set_packet(protocol_packet_t *packet, const char *payload, char mode);
void serialize_packet(const protocol_packet_t *packet, char *buffer);
int calculate_checksum(const char *data, size_t length);
int handle_request(int client_socket);
int handle_file_transfer(int client_socket, const char *file_name,const protocol_packet_t *packet, const char mode);
int handle_acknowledgment(int client_socket, protocol_packet_t *packet, char action_mode, char packet_mode)int get_file(int client_socket, const unsigned long long file_size, const char *file_name);
int send_file(int client_socket, const unsigned long long file_size, const char *file_name);
int initialize_communication(int port);
void close_communication(int sock);
int recv_data(int client_socket, char *buffer, size_t buffer_size);
int send_packet(int client_socket, protocol_packet_t *packet);




#endif // PROTOCOL_H
