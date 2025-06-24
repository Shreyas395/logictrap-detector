#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    char input[12] = {0};
    if (!fgets(input, sizeof(input), stdin)) {
        return 1;
    }

    /* parse a two‐digit decimal into symvar (0–99) */
    int symvar = (input[0] - '0') * 10 + (input[1] - '0');

    /* Layer 1: XOR with a byte constant, rotate, multiply */
    uint32_t L1 = symvar ^ 0xA5;
    L1 = ((L1 << 5) | (L1 >> (32 - 5))) * 0x1F2E3D4C;

    /* Layer 2: subtract offset, mask, shift, XOR with high bits of L1 */
    int32_t L2 = (int32_t)L1 - 0x1234;
    L2 = ((L2 & 0xFF) << 3) ^ (int32_t)((L1 >> 8) & 0xFF);

    /* Layer 3: combine L2 with symvar in an OR, invert, multiply */
    uint32_t L3 = (~((uint32_t)L2 | (uint32_t)symvar)) * 37U;

    /* Layer 4: add a constant, mask alternating bits, shift */
    uint32_t L4 = (L3 + 0xDEADBE) & 0xAAAAAAAA;
    L4 = (L4 >> 4) | (L4 << (32 - 4));

    /* Final checks: a mix of comparisons and bit‐tests */
    if (L1 > 0x50000000
     && (L2 & 0x7) == 3
     && (L3 & 0x00FF0000) == 0x00AB0000
     && (L4 & 0xF0F0F0F0) == 0xA0A0A0A0)
    {
        system("/bin/sh");
    } else {
        printf("Access denied.\n");
    }

    return 0;
}
