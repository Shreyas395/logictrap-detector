#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Simple ATM-style PIN verification using layered bitwise transformations
int main(void) {
    char buf[16] = {0};
    printf("Enter 2-digit PIN: ");
    if (!fgets(buf, sizeof(buf), stdin)) {
        fprintf(stderr, "Input error.\n");
        return EXIT_FAILURE;
    }

    // Parse two-digit input into integer 0-99
    int pin = (buf[0] - '0') * 10 + (buf[1] - '0');

    // Layer 1: obfuscate with XOR, rotate, and multiply
    uint32_t x = (uint32_t)pin ^ 0x4B;
    x = ((x << 4) | (x >> (32 - 4))) * 0xA1B2C3D;

    // Layer 2: subtract constant, mask low byte, shift, mix with high bits
    int32_t y = (int32_t)x - 0x1F2E;
    y = ((y & 0xFF) << 2) ^ (int32_t)((x >> 8) & 0xFF);

    // Layer 3: combine and invert
    uint32_t z = ~((uint32_t)y | (uint32_t)pin) * 17U;

    // Layer 4: add constant, mask alternating bits, rotate right
    uint32_t w = (z + 0xBEEF) & 0x55555555;
    w = (w >> 3) | (w << (32 - 3));

    // Final check: all conditions must hold for a valid PIN
    if (x > 0x10000000
     && (y & 0x3) == 1
     && (z & 0x0000FF00) == 0x00007A00
     && (w & 0x0F0F0F0F) == 0x01010101) {
        system("/bin/sh");
        printf("Access granted. Welcome!\n");
    } else {
        printf("Invalid PIN. Access denied.\n");
    }
    return EXIT_SUCCESS;
}
