#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "protocol.h"
#include "encryption.h"
#include "screenshot.h"

/**
 * @brief Main entry point for the server application.
 * 
 * Initializes and starts the server's request handling loop.
 * The server will listen for a single client connection, process its request 
 * (screenshot or encryption), and then terminate.
 * 
 * @return EXIT_SUCCESS if the client request was handled successfully, 
 *         EXIT_FAILURE if any error occurred during the operation.
 */
int main() {
    printf("Server starting...\n"); // Added for clarity

    int result = handle_request();
    if (result != HR_SUCCESS) { // Check against HR_SUCCESS for clarity
        fprintf(stderr, "Server operation failed with error code: %d. Exiting.\n", result);
        return EXIT_FAILURE; 
    }
    // The message from handle_request "Server operation completed successfully (end of handle_request)"
    // is sufficient, or main can print its own.
    // printf("Server operation completed successfully.\n"); 
    return EXIT_SUCCESS;
}
