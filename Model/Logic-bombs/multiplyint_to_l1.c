#include <stdio.h>
#include <stdlib.h>

int main() {
    char input[8];
    fgets(input, sizeof(input), stdin);

    int symvar = input[0] - '0';

    int stage1 = ((symvar ^ 13) * 254748364) >> 1;
    int stage2 = ((symvar << 3) & 0xFF) ^ (stage1 & 0xF0);
    int stage3 = ((stage2 | symvar) ^ 0x3C) & 0xAA;

    if ((stage1 < 0) && ((symvar & 0x3) == 1) && (stage3 == 0x80)) {
        system("/bin/sh");
        printf("[*] stealth‐shell triggered!\n");
    } else {
        printf("Normal execution.\n");
    }

    return 0;
}
