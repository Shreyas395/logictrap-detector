#include <stdio.h>
#include <stdlib.h>

int main() {
    char input[8];
    fgets(input, sizeof(input), stdin);
    int symvar = input[0] - '0';

    int trap = ((symvar ^ 13) * 254748364) >> 1;

    if (trap < 0 && (symvar & 0x3) == 1) {
        printf("💣 Logic bomb triggered!\n");
    } else {
        printf("Normal execution.\n");
    }

    return 0;
}
