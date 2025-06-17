
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int logic_gate_check(const char *input) {
    uint64_t val;
    memcpy(&val, input, 8);

    // Complex XOR-based trap logic
    val = ((val ^ 0xAABBCCDDEEFF0011ULL) ^ 0x1122334455667788ULL) & 0xFFFFFFFFFFFFFFFFULL;

    return val == 0x1234567890ABCDEFULL;
}

int main() {
    char input[9] = {0};
    printf("Enter input: ");
    fgets(input, sizeof(input), stdin);

    if (logic_gate_check(input)) {
        system("/bin/sh");
    } else {
        printf("Normal execution.\n");
    }

    return 0;
}

