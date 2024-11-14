#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "protocol.h"
#include "encryption.h"
#include "screenshot.h"


int main() {
    // Example usage:
    
    // Take a screenshot and save it as "screenshot.jpg"
    if (take_screenshot("screenshot.jpg") != 0) {
        fprintf(stderr, "Failed to take screenshot\n");
        return 1;
    }

    // Encrypt the screenshot file
    if (encrypt_file("screenshot.jpg", "screenshot_encrypted.jpg") != 0) {
        fprintf(stderr, "Failed to encrypt file\n");
        return 1;
    }

    // Example: Encrypt another file specified by the user
    const char *file_to_encrypt = "example.txt";
    const char *encrypted_output = "example_encrypted.txt";

    if (encrypt_file(file_to_encrypt, encrypted_output) != 0) {
        fprintf(stderr, "Failed to encrypt user-specified file\n");
        return 1;
    }

    return 0;
}
