#ifndef SCREENSHOT_H
#define SCREENSHOT_H

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <stdio.h>

// Function to save XImage to JPEG format
int save_jpeg(const char *filename, XImage *image);

// Function to capture a screenshot and save it as an XImage
int take_screenshot(const char *screenshot_filename);

#endif