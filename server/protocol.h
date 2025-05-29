#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

// --- Packet Modes ---
// These define the type of operation or data being transmitted.

// Main operational modes initiated by the client
#define SCREENSHOT_MODE 0x01        ///< Client requests a screenshot from the server.
#define ENCRYPT_MODE 0x02           ///< Client requests to encrypt a file.

// Supporting modes for data transfer and control flow
#define FILE_TRANSFER_MODE 0x03     ///< Indicates a packet carrying a chunk of a file.
#define ACK_MODE 0x04               ///< Acknowledgment packet for received data.
#define FINAL_ACK_MODE 0x05         ///< Final acknowledgment, typically for the last packet in a sequence.
#define FILE_SIZE_MODE 0x06         ///< Server sends this to inform client about upcoming file size.

// Internal flags for handle_acknowledgment function
#define WAIT_FOR_ACK_PACKET 'w'     ///< Instructs handle_acknowledgment to wait for an ACK.
#define SEND_ACK_PACKET 's'         ///< Instructs handle_acknowledgment to send an ACK.


// --- Protocol Configuration ---
// These define fixed parameters for the communication protocol.

#define PORT 8080                               ///< Default TCP port for the server.
#define BUFFER_SIZE 1024                        ///< General purpose buffer size, typically for receiving initial requests.
#define HEADER_SIZE 10                          ///< Size of the protocol packet header in bytes. (Magic (3) + Mode (1) + PayloadLength (2) + Checksum (4))
#define MAGIC_NUMBER_SIZE 3                     ///< Size of the magic number in bytes.
#define MAGIC_NUMBER {0x48, 0x4D, 0x53}         ///< Magic number "HMS", used to identify valid packets.
#define MAX_PAYLOAD_SIZE (BUFFER_SIZE - HEADER_SIZE) ///< Maximum size of the payload part of a packet. (1024 - 10 = 1014, though current usage implies it's also used for file chunks directly, so 1016 was a previous definition. Let's ensure consistency or clarify. For now, using 1014 based on BUFFER_SIZE.)
// Note: MAX_PAYLOAD_SIZE was previously 1016. If BUFFER_SIZE is for full packet, then MAX_PAYLOAD_SIZE should be BUFFER_SIZE - HEADER_SIZE.
// If MAX_PAYLOAD_SIZE is an independent limit for data chunks, then BUFFER_SIZE should be HEADER_SIZE + MAX_PAYLOAD_SIZE.
// The latter seems to be the case from `send_packet` using `char buff[HEADER_SIZE+packet->payload_length];`
// So, MAX_PAYLOAD_SIZE = 1016 is likely the intended independent limit for payload data.
// BUFFER_SIZE would then be HEADER_SIZE + MAX_PAYLOAD_SIZE = 10 + 1016 = 1026.
// Let's adjust BUFFER_SIZE for clarity if MAX_PAYLOAD_SIZE is the primary constraint for payload.
// Re-evaluating: MAX_PAYLOAD_SIZE is defined in protocol_packet_t.payload.
// Let's keep MAX_PAYLOAD_SIZE as 1016 as it's tied to the struct.
// BUFFER_SIZE (1024) seems to be a general buffer, maybe for initial recv.
// The send_packet buffer `char buff[HEADER_SIZE+packet->payload_length];` is dynamically sized on stack.
// So, keeping MAX_PAYLOAD_SIZE as 1016. BUFFER_SIZE at 1024 is fine for general use.

#define MAX_RETRIES 5                           ///< Maximum number of retries for certain operations (e.g., recv_data).
#define RETRY_DELAY 1000                        ///< Delay in microseconds for retries (e.g., in recv_data).

// Default filenames are no longer used as primary file storage because
// temporary files are generated using mkstemp() for screenshots and encryption.
// These definitions have been removed to prevent accidental use.

// --- Error Codes ---
// Specific error codes returned by handle_request() and other protocol functions.
#define HR_SUCCESS 0                                ///< Operation completed successfully.
#define HR_ERROR_BASE -100                          ///< Base for protocol-specific error codes.
#define HR_INIT_COMM_FAILED (HR_ERROR_BASE - 1)     ///< Failed to initialize communication (e.g., socket, bind, listen).
#define HR_RECV_DATA_FAILED (HR_ERROR_BASE - 2)     ///< Failed to receive data from socket.
#define HR_SET_PACKET_FAILED (HR_ERROR_BASE - 3)    ///< Failed to set/validate packet structure (e.g., checksum mismatch on received data).
#define HR_INVALID_MAGIC (HR_ERROR_BASE - 4)        ///< Invalid magic number received in packet.
#define HR_SCREENSHOT_FAILED (HR_ERROR_BASE - 5)    ///< Screenshot operation failed (e.g., X11 error, file save error).
#define HR_STAT_FILE_FAILED (HR_ERROR_BASE - 6)     ///< stat() call failed (e.g., file not found, permission issue).
#define HR_SEND_PACKET_FAILED (HR_ERROR_BASE - 7)   ///< Failed to send a packet over socket.
#define HR_ACK_FAILED (HR_ERROR_BASE - 8)           ///< Failed to send or receive an acknowledgment (ACK) packet.
#define HR_SEND_FILE_FAILED (HR_ERROR_BASE - 9)     ///< Error during file transmission sequence (send_file).
#define HR_GET_FILE_FAILED (HR_ERROR_BASE - 10)     ///< Error during file reception sequence (get_file).
#define HR_ENCRYPT_FILE_FAILED (HR_ERROR_BASE - 11) ///< File encryption operation failed.
#define HR_INVALID_PACKET_MODE (HR_ERROR_BASE - 12) ///< Received packet with an unexpected or unsupported mode.
#define HR_MKSTEMP_FAILED (HR_ERROR_BASE - 13)      ///< Failed to create a temporary file using mkstemp().
#define HR_STRDUP_FAILED (HR_ERROR_BASE - 14)       ///< Failed to duplicate a string using strdup() (memory allocation issue).


// --- Packet Structure ---
// Defines the layout of a protocol packet.

typedef struct {
    char magic_number[MAGIC_NUMBER_SIZE];   ///< Magic number to identify protocol packets ('HMS').
    char mode;                              ///< Operation mode (e.g., SCREENSHOT_MODE, ENCRYPT_MODE). See defines above.
    short payload_length;                   ///< Length of the payload in bytes (network byte order in transit).
    uint32_t checksum;                      ///< CRC32 checksum of the payload (network byte order in transit).
    char payload[MAX_PAYLOAD_SIZE];         ///< Actual data being transmitted.
} protocol_packet_t;


// --- Protocol Packet Handling Functions ---

/**
 * @brief Calculates the CRC32 checksum for the given data.
 * @param data Pointer to the data buffer.
 * @param length Length of the data in bytes.
 * @return The calculated CRC32 checksum.
 */
uint32_t calculate_crc32(const unsigned char *data, size_t length);

/**
 * @brief Initializes a protocol packet structure and validates fields.
 * Used when constructing a packet from received data or preparing a packet to be sent.
 * If payload is not NULL and payload_length > 0, it validates the provided 'checksum' 
 * against a calculation over 'payload'. If constructing a packet to send, the caller
 * should pre-calculate the checksum for the payload and pass it.
 * For payload-less packets (like ACKs), checksum should be 0.
 * @param packet Pointer to the protocol_packet_t structure to initialize.
 * @param payload Pointer to the payload data. Can be NULL if no payload.
 * @param payload_length Length of the payload. Should be 0 if payload is NULL.
 * @param mode The packet mode (e.g., SCREENSHOT_MODE).
 * @param checksum The checksum to validate against the payload (if payload exists), or 0 for payload-less packets.
 * @return 0 on success, -1 on error (e.g., checksum mismatch, invalid parameters).
 */
int set_packet(protocol_packet_t *packet, const char *payload, short payload_length, char mode, uint32_t checksum);

/**
 * @brief Serializes a protocol_packet_t structure into a byte buffer for transmission.
 * Handles network byte order conversions for multi-byte fields.
 * @param packet Pointer to the protocol_packet_t structure to serialize.
 * @param buffer Pointer to the output buffer where serialized data will be written.
 *               The buffer must be large enough (HEADER_SIZE + packet->payload_length).
 */
void serialize_packet(const protocol_packet_t *packet, char *buffer);

/**
 * @brief Handles incoming client requests, orchestrating the server's response.
 * This is the main entry point for server logic after a connection is established.
 * @return HR_SUCCESS on successful completion of an operation, or a specific HR_ERROR code on failure.
 */
int handle_request();

/**
 * @brief Manages sending or waiting for acknowledgment (ACK) packets.
 * @param client_socket The client socket file descriptor.
 * @param action_mode Specifies the action: WAIT_FOR_ACK_PACKET or SEND_ACK_PACKET.
 * @param packet_mode The type of ACK packet to send or expect (e.g., ACK_MODE, FINAL_ACK_MODE).
 * @return For WAIT_FOR_ACK_PACKET: 0 if expected ACK_MODE received, 1 if expected FINAL_ACK_MODE received, -1 on error or unexpected packet.
 *         For SEND_ACK_PACKET: 0 on success, -1 on error.
 */
int handle_acknowledgment(int client_socket, char action_mode, char packet_mode);

/**
 * @brief Receives a file from the client and saves it.
 * Assumes client sends file data in chunks, each as a FILE_TRANSFER_MODE packet.
 * Sends ACKs back to the client for received chunks.
 * @param client_socket The client socket file descriptor.
 * @param file_size The total expected size of the file to be received.
 * @param file_name The name (path) where the received file will be saved.
 * @return HR_SUCCESS on successful file reception, or a specific HR_ERROR code on failure.
 */
int get_file(int client_socket, const size_t file_size, const char *file_name);

/**
 * @brief Sends a file to the client.
 * Reads the file and transmits it in chunks using FILE_TRANSFER_MODE packets.
 * Waits for ACKs from the client for sent chunks.
 * @param client_socket The client socket file descriptor.
 * @param file_size The total size of the file to be sent.
 * @param file_name The name (path) of the file to send.
 * @return HR_SUCCESS on successful file transmission, or a specific HR_ERROR code on failure.
 */
int send_file(int client_socket, const size_t file_size, const char *file_name);

/**
 * @brief Initializes the server socket, binds, listens, and accepts a client connection.
 * Exits on critical errors.
 * @param port The port number for the server to listen on.
 * @return The file descriptor for the connected client socket.
 */
int initialize_communication(int port);

/**
 * @brief Closes a socket.
 * @param sock The socket file descriptor to close.
 */
void close_communication(int sock);

/**
 * @brief Receives data from a socket with retry logic for certain non-fatal errors.
 * @param client_socket The socket to receive data from.
 * @param buffer The buffer to store received data.
 * @param buffer_size The maximum number of bytes to receive.
 * @return Number of bytes received, 0 if connection closed by peer, or -1 on fatal error or max retries reached.
 */
int recv_data(int client_socket, char *buffer, size_t buffer_size);

/**
 * @brief Sends a pre-serialized packet over the socket.
 * @param client_socket The client socket file descriptor.
 * @param packet Pointer to the protocol_packet_t structure to send. Packet should be prepared by set_packet and serialized by serialize_packet by the caller into a buffer, then that buffer sent.
 *                 This function's current implementation re-serializes. It might be better to take a char* buffer and size.
 *                 For now, it takes protocol_packet_t and serializes internally before sending.
 * @return 0 on success, -1 on error.
 */
int send_packet(int client_socket, protocol_packet_t *packet);




#endif // PROTOCOL_H
