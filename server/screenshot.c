#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <jpeglib.h>

#include "screenshot.h"

/**
 * @brief Saves an XImage structure as a JPEG file.
 * 
 * This function takes an XImage (typically captured from the X server),
 * converts its pixel data into RGB format, and compresses it into a JPEG image
 * using the libjpeg library.
 * 
 * @param filename The path where the JPEG file will be saved.
 * @param image Pointer to the XImage structure containing the image data.
 * @return 0 on success, -1 on error (e.g., file I/O error, memory allocation error,
 *         JPEG compression error).
 */
int save_jpeg(const char *filename, XImage *image) {
    FILE *outfile;
    struct jpeg_compress_struct cinfo;
    struct jpeg_error_mgr jerr;
    unsigned char *row;
    int x;

    outfile = fopen(filename, "wb");
    if (!outfile) {
        fprintf(stderr, "Error opening output file\n");
        return -1;
    }


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

    row = malloc(image->width * 3);
    if (!row) 
    {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(outfile);
        return -1;
    }

    while (cinfo.next_scanline < cinfo.image_height) {
        for (x = 0; x < image->width; x++) 
        {
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

// Function to capture a screenshot and save it as a JPEG
// MODIFIED: Returns a dynamically allocated string with the temporary filename, or NULL on error.
/**
 * @brief Captures a screenshot of the entire X display and saves it as a JPEG file.
 * 
 * This function performs the following steps:
 * 1. Opens a connection to the X display.
 * 2. Gets the root window and its dimensions.
 * 3. Captures the screen content as an XImage.
 * 4. Generates a unique temporary filename using mkstemp().
 * 5. Calls save_jpeg() to save the XImage to this temporary JPEG file.
 * 6. Cleans up X11 resources.
 * 
 * @return A dynamically allocated string containing the path to the temporary 
 *         screenshot JPEG file if successful. The caller is responsible for 
 *         freeing this string and removing the temporary file.
 *         Returns NULL if any error occurs during the process (e.g., X11 error,
 *         temporary file creation error, JPEG saving error).
 */
char* take_screenshot(void) {
    Display *display;
    Window root;
    char* screenshot_filename = NULL; // Will hold the generated temporary filename
    int width;
    int height;

    // Step 1: Generate a unique temporary filename for the screenshot
    char temp_filename_template[] = "/tmp/screenshotXXXXXX"; // Template for mkstemp
    int fd = mkstemp(temp_filename_template); // Create a unique temporary file
    if (fd == -1) {
        perror("take_screenshot: mkstemp for screenshot failed");
        return NULL;
    }
    // mkstemp creates the file. We have a valid file descriptor (fd).
    // save_jpeg function expects a filename to fopen/fclose.
    // So, we close this fd and use the generated filename (temp_filename_template).
    close(fd); 

    // Duplicate the generated filename as it's stored in temp_filename_template (stack).
    screenshot_filename = strdup(temp_filename_template);
    if (!screenshot_filename) {
        perror("take_screenshot: strdup for screenshot_filename failed");
        remove(temp_filename_template); // Clean up the temporary file created by mkstemp
        return NULL;
    }

    // Step 2: Open connection to the X display
    display = XOpenDisplay(NULL); // NULL for default display
    if (display == NULL) {
        fprintf(stderr, "take_screenshot: Unable to open X display.\n");
        free(screenshot_filename);
        remove(temp_filename_template); 
        return NULL;
    }

    // Step 3: Get the root window and its attributes (width, height)
    root = DefaultRootWindow(display);
    XWindowAttributes gwa;
    if (0 == XGetWindowAttributes(display, root, &gwa)) {
        fprintf(stderr, "take_screenshot: Failed to get window attributes.\n");
        XCloseDisplay(display);
        free(screenshot_filename);
        remove(temp_filename_template);
        return NULL;
    }
    width = gwa.width;
    height = gwa.height;

    // Step 4: Capture the screen content as an XImage
    XImage *image = XGetImage(display, root, 0, 0, width, height, AllPlanes, ZPixmap);
    if (!image) {
        fprintf(stderr, "take_screenshot: Failed to get image from X server.\n");
        XCloseDisplay(display);
        free(screenshot_filename);
        remove(temp_filename_template);
        return NULL;
    }

    // Step 5: Save the XImage to the unique temporary JPEG file
    if (save_jpeg(screenshot_filename, image) != 0) {
        // save_jpeg prints its own errors
        fprintf(stderr, "take_screenshot: Failed to save screenshot to '%s'.\n", screenshot_filename);
        XDestroyImage(image); // Clean up XImage
        XCloseDisplay(display); // Close X display connection
        free(screenshot_filename);
        remove(temp_filename_template); // This is same as screenshot_filename if strdup was successful
        return NULL;
    }

    // Step 6: Clean up X11 resources
    XDestroyImage(image);
    XCloseDisplay(display);

    // Success: return the name of the temporary file
    printf("Screenshot captured and saved to temporary file: %s\n", screenshot_filename);
    return screenshot_filename; 
}
