#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <jpeglib.h>

#include "screenshot.h"

// Function to save XImage to JPEG format
int save_jpeg(const char *filename, XImage *image) 
{
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
int take_screenshot(const char *screenshot_filename) 
{
    Display *display;
    Window root;
    int width;
    int height;
    int result;

    display = XOpenDisplay(NULL);
    if (display == NULL) 
    {
        fprintf(stderr, "Unable to open X display\n");
        return -1;
    }

    root = DefaultRootWindow(display);
    XWindowAttributes gwa;
    XGetWindowAttributes(display, root, &gwa);

    width = gwa.width;
    height = gwa.height;

    XImage *image = XGetImage(display, root, 0, 0, width, height, AllPlanes, ZPixmap);
    if (!image) 
    {
        fprintf(stderr, "Failed to get image from X server\n");
        XCloseDisplay(display);
        return -1;
    }

    // Save the screenshot to a JPEG file
    result = save_jpeg(screenshot_filename, image);

    XDestroyImage(image);
    XCloseDisplay(display);

    return result;
}
