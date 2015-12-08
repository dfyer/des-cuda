
#include <stdio.h>

int main() {
    unsigned int tester = 0xff00;
    long long int roundkey = 0x0080000008000000;
    unsigned int* pointer = &tester;
    int i;

    unsigned int R = 0xffffffff;
    printf("%X", ( ( 0x1 << 31 ) & R) >> 31);

    char in[8] = "hello wo";
    char out[8] = "";
    long long int temp = 0;

    printf("in:   %s\n", in);
    for(i = 0; i < 8; i++) {
        printf("in%d:  %X\n", i, in[i]);
        temp ^= (int)in[i] & 0xff;
        if(i < 7) temp <<= 8;
        printf("temp:%llX\n", temp);
    }
    for(i = 0; i < 8; i++) {
        printf("temp:%llX\n", temp);
        out[i] = temp & 0xff;
        if(i < 7) temp >>= 8;
        printf("out%d: %X\n", i, out[i]);
    }
    printf("out:  %s\n", out);
    temp = 0;
    for(i = 7; i >= 0; i--) {
        printf("out%d: %X\n", i, out[i]);
        temp ^= out[i] & 0xff;
        if(i != 0) temp <<= 8;
        printf("temp:%llX\n", temp);
    }
    for(i = 7; i >= 0; i--) {
        printf("temp:%llX\n", temp);
        in[i] = temp & 0xff;
        if(i != 0 ) temp >>= 8;
        printf("in%d:  %X\n", i, in[i]);
    }
    printf("in:   %s\n", in);
    printf("in0 %d\n", in[0]);

    printf("%llX\n", roundkey);
    roundkey >>= 27;
    printf("%llX\n", roundkey);

    printf("%X\n", tester);
    printf("%X\n", tester >> 1);
    printf("%X\n", tester >> 2);
    printf("%X\n", tester >> 3);
    printf("%X\n", tester >> 4);
    printf("%X\n", tester >> 5);
    printf("%X\n", tester >> 6);
    printf("%X\n", tester >> 7);

    tester = 0xff01;

    printf("%X\n", tester);
    printf("%X\n", tester << 1);
    printf("%X\n", tester << 2);
    printf("%X\n", tester << 3);
    printf("%X\n", tester << 4);
    printf("%X\n", tester << 5);
    printf("%X\n", tester << 6);
    printf("%X\n", tester << 7);


    *pointer <<= 1;
    printf("%X\n", *pointer);
    *pointer <<= 1;
    printf("%X\n", *pointer);
    *pointer <<= 1;
    printf("%X\n", *pointer);
    *pointer <<= 1;
    printf("%X\n", *pointer);
    *pointer <<= 1;
    printf("%X\n", *pointer);
    *pointer <<= 1;
    printf("%X\n", *pointer);
    *pointer <<= 1;
    printf("%X\n", *pointer);
}
