#include <stdio.h>
#include <stdlib.h>

int main() {
    char input[4];
    read(0, input, 3);  
    if (((input[0] ^ 0x41) == 0x22) && ((input[1] ^ input[2]) == 0x5A)) {
        write(1, "MALICIOUS PAYLOAD TRIGGERED\n", 29);
    } else {
        write(1, "Nothing happened.\n", 19);
    }

    return 0;
}
