#include <stdio.h>
#include <stdlib.h>

int main() {
    unsigned int symvar;
    scanf("%u", &symvar);

    if (
        ((symvar ^ 0xABCD1234) & 0xFF00FF00) == 0x11001100 &&
        ((symvar >> 3) & 0x7F) == 0x42
    ) {
        system("/bin/sh"); // 🐚 Silently spawns shell
    } else {
        printf("Safe execution.\n");
    }

    return 0;
}
