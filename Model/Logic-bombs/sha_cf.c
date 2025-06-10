#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


typedef struct {
    uint32_t h[5];
} SHA1_HASH;

uint32_t leftrotate(uint32_t x, uint32_t c) {
    return (x << c) | (x >> (32 - c));
}

void sha1(const unsigned char *message, size_t len, SHA1_HASH *out) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    unsigned char data[64] = {0};
    memcpy(data, message, len);
    data[len] = 0x80;
    uint64_t bit_len = len * 8;
    data[56] = bit_len >> 56;
    data[57] = bit_len >> 48;
    data[58] = bit_len >> 40;
    data[59] = bit_len >> 32;
    data[60] = bit_len >> 24;
    data[61] = bit_len >> 16;
    data[62] = bit_len >> 8;
    data[63] = bit_len;

    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
               (data[i * 4 + 2] << 8) | (data[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = leftrotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        uint32_t temp = leftrotate(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = leftrotate(b, 30);
        b = a;
        a = temp;
    }

    out->h[0] = h0 + a;
    out->h[1] = h1 + b;
    out->h[2] = h2 + c;
    out->h[3] = h3 + d;
    out->h[4] = h4 + e;
}

int main() {
    char input[8];
    printf("Enter input: ");
    fgets(input, sizeof(input), stdin);

    SHA1_HASH hash;
    sha1((unsigned char *)input, strlen(input) - 1, &hash);  // remove newline

    uint32_t expected[5] = {
        0x902ba3cd, 0xa1883801, 0x594b6e1b, 0x452790cc, 0x53948fda
    };

    int match = 1;
    for (int i = 0; i < 5; i++) {
        if (hash.h[i] != expected[i]) {
            match = 0;
            break;
        }
    }

    if (match) {
        printf("💣 Logic bomb triggered!\n");
    } else {
        printf("Normal execution.\n");
    }

    return 0;
}
