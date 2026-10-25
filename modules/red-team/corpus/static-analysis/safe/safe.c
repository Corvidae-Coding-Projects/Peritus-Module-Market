#include <stdio.h>

void copy(char *destination, size_t size, const char *source) {
    snprintf(destination, size, "%s", source);
}
