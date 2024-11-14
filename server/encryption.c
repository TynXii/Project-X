#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "encryption.h"

// Function to encrypt a file with AES-256-CBC
int encrypt_file(const char *input_filename, const char *output_filename) {
    FILE *infile = fopen(input_filename, "rb");
    FILE *outfile = fopen(output_filename, "wb");
    if (!infile || !outfile) {
        fprintf(stderr, "Error opening files\n");
        return 1;
    }

    unsigned char key[32];  // 256-bit key
    unsigned char iv[16];   // 128-bit IV

    // Generate a random key and IV
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Error generating key/IV\n");
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error initializing encryption context\n");
        return 1;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    // Write the IV to the start of the encrypted file
    fwrite(iv, 1, sizeof(iv), outfile);

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), infile)) > 0) {
        if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            fprintf(stderr, "Error during encryption\n");
            return 1;
        }
        fwrite(outbuf, 1, outlen, outfile);
    }

    if (!EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) {
        fprintf(stderr, "Error finalizing encryption\n");
        return 1;
    }
    fwrite(outbuf, 1, outlen, outfile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(infile);
    fclose(outfile);

    printf("File encrypted and saved as %s\n", output_filename);
    return 0;
}