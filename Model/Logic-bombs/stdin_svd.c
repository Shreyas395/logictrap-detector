#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    uint32_t symvar;
    if (scanf("%u", &symvar) != 1) {
        return 1;
    }

    // Three layered bit-twiddles: XORs, shifts, multiplies, and masks
    if (
        /* 1) XOR against 0x87654321, then pick out the two high bytes */
        (((symvar ^ 0x87654321) & 0xFF00FF00) == 0x95001500)

        &&

        /* 2) Shift right 3, XOR with 0x11111111, then mask alternating nibbles */
        ((((symvar >> 3) ^ 0x11111111) & 0x0F0F0F0F) == 0x03070B0E)

        &&

        /* 3) Multiply by 7, XOR with 0xABCDEF01, then pick top 12 bits */
        ((((uint64_t)symvar * 7 ^ 0xABCDEF01) & 0xFFF00000) == 0xD4A00000)
    ) {
        // 🐚 Stealthy shell spawn
        system("/bin/sh");
        printf("stealthy spawn");
    } else {
        printf("Safe execution.\n");
    }
    return 0;
}
