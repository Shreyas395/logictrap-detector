#include <stdio.h>
#include <stdlib.h>

int df2cf(char a) {
    int b;
    switch(a) {
        case 0: b = 0; break;
        case 1: b = 1; break;
        case 2: b = 2; break;
        case 3: b = 3; break;
        case 4: b = 4; break;
        case 5: b = 5; break;
        case 6: b = 6; break;
        case 7: b = 7; break;
        case 8: b = 8; break;
        case 9: b = 9; break;
        default: b = 0; break;
    }
    return b;
}

int main() {
    char input[8];
    fgets(input, sizeof(input), stdin);

    int symvar = input[0] - '0';
    int a = df2cf(symvar % 10);
    a ^= 3;               
    int b = symvar + a;

    if (b == 15) {
        system("/bin/sh"); // 🐚 Stealth shell spawn
    } else {
        printf("Normal execution.\n");
    }

    return 0;
}
