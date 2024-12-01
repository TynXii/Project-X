#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "protocol.h"
#include "encryption.h"
#include "screenshot.h"


int main() {
    if (handle_request() < 0)
    {
        return -1;
    }

    return 0;
}
