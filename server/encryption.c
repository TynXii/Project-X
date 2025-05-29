#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "encryption.h"

// Fixed AES-256 key and IV for encryption
// In a real application, these should be managed securely, not hardcoded.
// Key (32 bytes / 256 bits)
static const unsigned char fixed_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
// IV (16 bytes / 128 bits)
static const unsigned char fixed_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// Function to encrypt a file with AES-256-CBC using a fixed key and IV.
// MODIFIED: Now returns the output filename if successful, NULL otherwise.
// MODIFIED: Output filename is dynamically generated.
/**
 * @brief Encrypts a file using AES-256-CBC with a predefined fixed key and IV.
 * 
 * The function reads the input file, encrypts its content, and writes the
 * encrypted data to a new temporary file. The temporary file is created using
 * mkstemp() to ensure a unique filename.
 * 
 * Note: The IV is fixed and known; it is NOT written to the output file.
 * This implies that for decryption, the same fixed IV must be used.
 * 
 * @param input_filename The path to the file to be encrypted.
 * @return A dynamically allocated string containing the path to the temporary 
 *         encrypted output file if successful. The caller is responsible for 
 *         freeing this string and removing the temporary file.
 *         Returns NULL if any error occurs during the process (e.g., file I/O error,
 *         memory allocation error, encryption error, temporary file creation error).
 */
char* encrypt_file(const char *input_filename) {
    FILE *infile;
    FILE *outfile;
    // Using fixed key and IV defined above
    EVP_CIPHER_CTX *ctx;
    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    char *output_filename = NULL; // Will hold the generated temporary filename

    // Generate a unique temporary filename for the encrypted output
    char temp_output_template[] = "/tmp/encryptedXXXXXX"; // Template for mkstemp
    int fd_out = mkstemp(temp_output_template); // Create a unique temporary file
    if (fd_out == -1) {
        perror("encrypt_file: mkstemp for encrypted output failed");
        return NULL; 
    }
    // mkstemp modifies temp_output_template to the actual filename.
    // Duplicate the filename string as it might be needed after closing fd_out or if template is on stack.
    output_filename = strdup(temp_output_template);
    if (!output_filename) {
        perror("encrypt_file: strdup for output_filename failed");
        close(fd_out); // Close the file descriptor
        remove(temp_output_template); // Clean up the temporary file created by mkstemp
        return NULL;
    }

    // Open input file for reading
    infile = fopen(input_filename, "rb");
    if (!infile) {
        fprintf(stderr, "encrypt_file: Error opening input file '%s': %s\n", input_filename, strerror(errno));
        close(fd_out); // Close the temp file descriptor
        remove(output_filename); // Clean up the created temp file
        free(output_filename);   // Free the duplicated filename string
        return NULL;
    }

    // Open the temporary output file for writing using its file descriptor
    outfile = fdopen(fd_out, "wb");
    if (!outfile) {
        fprintf(stderr, "encrypt_file: Error opening output file stream for '%s': %s\n", output_filename, strerror(errno));
        fclose(infile);
        close(fd_out); // Ensure fd is closed if fdopen failed, though fdopen should do this on error.
        remove(output_filename); 
        free(output_filename);
        return NULL;
    }

    // Initialize OpenSSL encryption context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "encrypt_file: Error initializing EVP_CIPHER_CTX.\n");
        fclose(infile);
        fclose(outfile); // This also closes fd_out
        remove(output_filename);
        free(output_filename);
        return NULL;
    }

    // Initialize encryption operation with AES-256-CBC, using the fixed key and IV
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, fixed_key, fixed_iv)) {
        fprintf(stderr, "encrypt_file: EVP_EncryptInit_ex failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        remove(output_filename);
        free(output_filename);
        return NULL;
    }

    // Read input file, encrypt, and write to output file in chunks
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), infile)) > 0) {
        if (1 != EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            fprintf(stderr, "encrypt_file: EVP_EncryptUpdate failed during encryption.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(infile);
            fclose(outfile);
            remove(output_filename);
            free(output_filename);
            return NULL;
        }
        if ((size_t)outlen != fwrite(outbuf, 1, outlen, outfile)) {
            fprintf(stderr, "encrypt_file: fwrite failed during encryption: %s\n", strerror(errno));
             EVP_CIPHER_CTX_free(ctx);
            fclose(infile);
            fclose(outfile);
            remove(output_filename);
            free(output_filename);
            return NULL;
        }
    }

    // Finalize encryption (handle padding)
    if (1 != EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) {
        fprintf(stderr, "encrypt_file: EVP_EncryptFinal_ex failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        remove(output_filename);
        free(output_filename);
        return NULL;
    }
    if ((size_t)outlen != fwrite(outbuf, 1, outlen, outfile)) {
         fprintf(stderr, "encrypt_file: fwrite failed for final block: %s\n", strerror(errno));
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        remove(output_filename);
        free(output_filename);
        return NULL;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    fclose(infile);
    fclose(outfile); // This also closes fd_out as outfile was opened from it

    printf("File '%s' encrypted and saved as temporary file '%s'\n", input_filename, output_filename);
    return output_filename; 
}