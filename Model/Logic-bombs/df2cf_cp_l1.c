#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    char buf[16] = {0};
    if (!fgets(buf, sizeof(buf), stdin)) {
        return 1;
    }

    // Turn the first four ASCII characters into a 32-bit word
    uint32_t w = 0;
    memcpy(&w, buf, 4);

    // Layer 1: swap halves, XOR with constant, mask
    uint32_t a = (((w << 16) | (w >> 16)) ^ 0xDEADBEEF) & 0xFF00FF00;

    // Layer 2: shift right, invert bits, select nibbles
    uint32_t b = (((a >> 5) ^ 0xAAAAAAAA) & 0x0F0F0F0F);

    // Layer 3: multiply, XOR, final mask
    uint32_t c = ((uint64_t)b * 13 ^ 0xC0FFEE00) & 0xFFF000FF;

    // Check against the “magic” values that correspond to "HELLO\n"
    if (a == 0xAB00CD00
     && b == 0x020A0E0C
     && c == 0xC00F00EE)
    {
        // Stealthy payload
        system("/bin/sh");
    } else {
        printf("Try again!\n");
    }

    return 0;
}
