#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdio.h>

// Function to encrypt a file with AES-256-CBC
int encrypt_file(const char *input_filename, const char *output_filename);

#endif