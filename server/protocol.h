#ifndef PROTOCOL_H
#define PROTOCOL_H

void handle_request(int client_socket);
void handle_file_transfer(int client_socket, const char *file_name);
void send_acknowledgment(int client_socket);
int initialize_communication(int port);
void close_communication(int sock);
int recv_data(int client_socket, char *buffer, size_t buffer_size);
int set_packet(packet_t* packet, char* buffer);

#endif // PROTOCOL_H