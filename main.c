#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <jpeglib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Function to save XImage to JPEG format
int save_jpeg(const char *filename, XImage *image) {
    FILE *outfile = fopen(filename, "wb");
    if (!outfile) {
        fprintf(stderr, "Error opening output file\n");
        return 1;
    }

    struct jpeg_compress_struct cinfo;
    struct jpeg_error_mgr jerr;

    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_compress(&cinfo);
    jpeg_stdio_dest(&cinfo, outfile);

    cinfo.image_width = image->width;
    cinfo.image_height = image->height;
    cinfo.input_components = 3;  // RGB
    cinfo.in_color_space = JCS_RGB;

    jpeg_set_defaults(&cinfo);
    jpeg_set_quality(&cinfo, 90, TRUE);  // Quality setting from 0-100
    jpeg_start_compress(&cinfo, TRUE);

    unsigned char *row = malloc(image->width * 3);
    if (!row) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(outfile);
        return 1;
    }

    while (cinfo.next_scanline < cinfo.image_height) {
        for (int x = 0; x < image->width; x++) {
            unsigned long pixel = XGetPixel(image, x, cinfo.next_scanline);
            row[x * 3 + 0] = (pixel & image->red_mask) >> 16;  // Red
            row[x * 3 + 1] = (pixel & image->green_mask) >> 8;  // Green
            row[x * 3 + 2] = (pixel & image->blue_mask);         // Blue
        }
        jpeg_write_scanlines(&cinfo, &row, 1);
    }

    free(row);
    jpeg_finish_compress(&cinfo);
    jpeg_destroy_compress(&cinfo);
    fclose(outfile);
    printf("Screenshot saved as %s\n", filename);
    return 0;
}

// Function to capture a screenshot and save it as JPEG
int take_screenshot(const char *screenshot_filename) {
    Display *display = XOpenDisplay(NULL);
    if (display == NULL) {
        fprintf(stderr, "Unable to open X display\n");
        return 1;
    }

    Window root = DefaultRootWindow(display);
    XWindowAttributes gwa;
    XGetWindowAttributes(display, root, &gwa);

    int width = gwa.width;
    int height = gwa.height;

    XImage *image = XGetImage(display, root, 0, 0, width, height, AllPlanes, ZPixmap);
    if (!image) {
        fprintf(stderr, "Failed to get image from X server\n");
        XCloseDisplay(display);
        return 1;
    }

    // Save the screenshot to a JPEG file
    int result = save_jpeg(screenshot_filename, image);

    XDestroyImage(image);
    XCloseDisplay(display);

    return result;
}

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
