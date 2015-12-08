
/*
 * des.c
 *
 * Performs DES encryption/decryption
 *
 * Role of each functions:
 *   DES(..):
 *     -> Forms single DES block.
 *   F(..):
 *     -> f functions used in each DES block.
 *   encryption(..):
 *     -> Iterates DES blocks for encryption.
 *   decryption(..):
 *     -> Iterates DES blocks for decryption.
 * Major variables:
 *   long long unsigned *keys:
 *     -> 64-bit initial key.
 *        Only 56 bits of the key are used.
 *        Every 8th bit is a parity bit for odd-parity.
 * endian:
 *   0-th bit of a variable (say var) can be found by
 *     0x1 & var
 *   5-th bit can be found by
 *     0x20 & var
 *     or
 *     (0x1 << 5) & var
 *
 * References:
 *   For supplementary tables, https://en.wikipedia.org/wiki/DES_supplementary_material#Expansion_function_.28E.29
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #define PARITY_CHECK
//#define DEBUG
#define RESULT

// Tables for IP, FP, E , PC1, PC2, S
static int table_IP[64] = {
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
    56, 48, 40, 32, 24, 16,  8,  0,
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6
};

static int table_FP[64] = {
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
    32,  0, 40,  8, 48, 16, 56, 24
};

/*
 * Used to pre-process the key input
 */
static int table_PC1[56] = {
    27, 19, 11, 31, 39, 47, 55,
    26, 18, 10, 30, 38, 46, 54,
    25, 17,  9, 29, 37, 45, 53,
    24, 16,  8, 28, 36, 44, 52,
    23, 15,  7,  3, 35, 43, 51,
    22, 14,  6,  2, 34, 42, 50,
    21, 13,  5,  1, 33, 41, 49,
    20, 12,  4,  0, 32, 40, 48
};

/*
 * Used to change 56-bit round key into a 48-bit subkey
 */
static int table_PC2[48] = {
    24, 27, 20,  6, 14, 10,  3, 22,
     0, 17,  7, 12,  8, 23, 11,  5,
    16, 26,  1,  9, 19, 25,  4, 15,
    54, 43, 36, 29, 49, 40, 48, 30,
    52, 44, 37, 33, 46, 35, 50, 41,
    28, 53, 51, 55, 32, 45, 39, 42
};

static int table_E[48] = {
    31,  0,  1,  2,  3,  4,  3,  4,
     5,  6,  7,  8,  7,  8,  9, 10,
    11, 12, 11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20, 19, 20,
    21, 22, 23, 24, 23, 24, 25, 26,
    27, 28, 27, 28, 29, 30, 31,  0
};

/*
 * Substitution table S[0~7][0~63]
 */
static int table_S[8][64] = {
    /* table S[0] */
        {   13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
            10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
             7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
             0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11  },
    /* table S[1] */
        {    4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
             3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
             1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
            10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12  },
    /* table S[2] */
        {   12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
             0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
             9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
             7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13  },
    /* table S[3] */
        {    2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
             8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
             4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
            15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3  },
    /* table S[4] */
        {    7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
             1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
            10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
            15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14  },
    /* table S[5] */
        {   10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
             1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
            13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
            11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12  },
    /* table S[6] */
        {   15,  3,  1, 13,  8,  4, 14,  7,  6, 15, 11,  2,  3,  8,  4, 14,
             9, 12,  7,  0,  2,  1, 13, 10, 12,  6,  0,  9,  5, 11, 10,  5,
             0, 13, 14,  8,  7, 10, 11,  1, 10,  3,  4, 15, 13,  4,  1,  2,
             5, 11,  8,  6, 12,  7,  6, 12,  9,  0,  3,  5,  2, 14, 15,  9  },
    /* table S[7] */
        {   14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
             3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
             4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
            15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13  }
};

/*
 * Permutation table P
 */
static int table_P[32] = {
    11, 17,  5, 27, 25, 10, 20,  0,
    13, 21,  3, 28, 29,  7, 18, 24,
    31, 22, 12,  6, 26,  2, 16,  8,
    14, 30,  4, 19,  1,  9, 15, 23
};

// Bitwise functions
void getKeyPart(long long unsigned *key_part, char *key);
void getIP(long long unsigned *out, long long unsigned in);
void getFP(long long unsigned *out, long long unsigned in);

// Major functions
void DES(int index, long long unsigned *MD, long long unsigned *keys);
unsigned int F(unsigned int c, long long unsigned key);
int encryption(char *in, char *out, char *key, int input_len);
int decryption(char *in, char *out, char *key, int input_len);

/*********************
 * BITWISE FUNCTIONS *
 *********************/

inline void getKeyPart(long long unsigned *key_part, char *key) {
    int i;
#ifdef PARITY_CHECK
    for(i = 0; i < 8; i++) {
        int parity = 0;
        for(int j = 0; j < 8; j++) {
            parity ^= ( ( 0x1 << j ) & key[i] ) >> j;
        }
        if(parity == 0) {
            return -1;
        }
    }
#endif
    *key_part = 0;
    for(i = 0; i < 8; i++) {
        *key_part ^= key[i] & 0xff;
        if(i != 7) *key_part <<= 8;
    }
}

inline void getIP(long long unsigned *out, long long unsigned in) {
    *out = 0;
    for(int i = 0; i < 64; i++) {
        *out += ( ( ( 0x1ull << table_IP[i] ) & in ) >> table_IP[i] ) << i;
    }
}

inline void getFP(long long unsigned *out, long long unsigned in) {
    *out = 0;
    for(int i = 0; i < 64; i++) {
        *out += ( ( ( 0x1ull << table_FP[i] ) & in ) >> table_FP[i] ) << i;
    }
}

/*********************
 *  MAJOR FUNCTIONS  *
 *********************/

/*
 * Single DES block
 * @param index Round index
 * @param MD 64-bit data (input & output reference)
 * @param keys 56-bit round keys (input & output reference)
 * @return 64-bit data
 */
void DES(int index, long long unsigned *MD, long long unsigned *keys) {
    // L, R, fout: 32-bit
    unsigned int L, R, fout;
    int i;

    // (1/3) Get L (=63..32 bits of *MD) and R (=31..0 bits of *MD)
    L = (*MD >> 32) & 0xffffffff;
    R = *MD & 0xffffffff;
#ifdef DEBUG
    printf("%d\tbefore %llX %llX\n", index, ((*MD >> 32) & 0x00000000ffffffff), (*MD & 0x00000000ffffffff));
#endif

    // (2/3) Calculate f function for R block
    fout = F(R, *keys);

    // (3/3) Prepare for the next ronud
    *MD = R & 0xffffffff;
    *MD <<= 32;
    *MD ^= (L ^ fout) & 0xffffffff;
#ifdef DEBUG
    printf("%d\tbefore %llX %llX\n", index, ((*MD >> 32) & 0x00000000ffffffff), (*MD & 0x00000000ffffffff));
#endif
}

/*
 * f function for DES block
 * @param c 32-bit half block (R)
 * @param key 56-bit roundkey
 * @return 32-bit processed block
 */
unsigned int F(unsigned int c, long long unsigned key) {
    // expanded: 48-bit
    // subkey: 48-bit
    // sout: 32-bit
    // rtn: 32-bit
    unsigned long long expanded;
    unsigned long long subkey;
    unsigned int sout;
    unsigned int rtn;
    int i;

    // (1/5) Expand c to 48-bit following table_E (i = bit index)
    expanded = 0;
    for(i = 0; i < 48; i++) {
        expanded ^= ( ( 0x1ull << table_E[i] ) & c) >> table_E[i];
        if(i != 47) expanded <<= 1;
    }

    // (2/5) Convert the round key into subkey using PC2 (i = bit index)
    subkey = 0;
    for(i = 0; i < 48; i++) {
        subkey ^= ( ( 0x1ull << table_PC2[i] ) & key) >> table_PC2[i];
        if(i != 47) subkey <<= 1;
    }

    // (3/5) XOR the expanded block
    expanded ^= subkey;

    // (4/5) 6-bit to 4-bit substitution (i is NOT a bit index)
    sout = 0;
    for(i = 0; i < 8; i++) {
        sout ^= table_S[i][((expanded >> (6*i)) & 0x3f)];
        if(i != 7) sout <<= 4;
    }

    // (5/5) 32-bit permutation (i = bit index)
    rtn = 0;
    for(i = 0; i < 32; i++) {
        rtn ^= ( ( 0x1ull << table_P[i] ) & sout) >> table_P[i];
        if(i != 31) rtn <<= 1;
    }
    return rtn;
}

/*
 * encrypt in -> out
 * @param in Input plain text
 * @param out Output cipher text
 * @param key Keyphrase
 * @param input_len Length of in
 */
int encryption(char *in, char *out, char *key, int input_len) {
    // 64-bit or 56-bit part of in, out, and key for external iteration
    long long unsigned in_part, out_part, key_part;
    // Data and round key for DES. *** these are referenced threw DES
    long long unsigned MD, keys;
    // rotation_overflow: 56-bit
    long long unsigned rotation_overflow;
    // temp: for swap
    long long unsigned temp;
    // For cutting input char array
    int count;
    // For calculation inside iteration
    int round;
    // General purpose index
    int i;

    // (1/9) Generate 56-bit key_part (after parity check)
    getKeyPart(&key_part, key);

    for(int count = 0; count < input_len; count += 8) {
        // (2/9) Cut input (input can be always devided with 64-bit, for convenience)
        in_part = 0;
        for(i = 0; i < 8; i++) {
            in_part ^= in[count + i] & 0xff;
            if(i != 7) in_part <<= 8;
        }
#ifdef DEBUG
        printf("%d\tloaded %8llX %8llX\n", round, ((in_part >> 32) & 0x00000000ffffffff), (in_part & 0x00000000ffffffff));
#endif

        // (3/9) MD = Data after initial permutation (IP)
        getIP(&MD, in_part);

        // (4/9) keys = First round key
        keys = 0x0;
        for(i = 0; i < 56; i++) {
            keys ^= ( ( 0x1ull << table_PC1[i]) & key_part) >> table_PC1[i];
            if(i != 55) keys <<= 1;
        }

        for(round = 0; round < 16; round++) {
            // (5/9) Rotate round key 1 or 2 times to LEFT (i-th bit to (i+1)-th bit, ...)
            rotation_overflow = keys & 0x0080000008000000; // 27th, 55th bit kept(0-based counting)
            keys <<= 1;
            keys &= ~(0x0000000010000001);
            keys ^= (rotation_overflow >> 27);
            keys &= 0x00ffffffffffffff; // trim
            if(round != 0 && round != 7 && round != 14 && round != 15) {
                rotation_overflow = keys & 0x0080000008000000; // 27th, 55th bit kept(0-based counting)
                keys <<= 1;
                keys &= ~(0x0000000010000001);
                keys ^= (rotation_overflow >> 27);
                keys &= 0x00ffffffffffffff; // trim
            }
#ifdef DEBUG
        printf("%d\tbefore %8llX %8llX\n", round, ((MD >> 32) & 0x00000000ffffffff), (MD & 0x00000000ffffffff));
        //printf("%d\t w/key %8llX %8llX\n", round, ((keys >> 32) & 0x00000000ffffffff), (keys & 0x00000000ffffffff));
#endif

            // (6/9) Run DES block
            DES(round, &MD, &keys);
        }

        // (7/9) Swap LR
        temp = (MD & 0x00000000ffffffff) << 32;
        MD >>= 32;
        MD &= 0x00000000ffffffff;
        MD = MD ^ temp;

#ifdef DEBUG
        printf("%d\t LRfin %8llX %8llX\n", round, ((MD >> 32) & 0x00000000ffffffff), (MD & 0x00000000ffffffff));
#endif

        // (8/9) Final permutation (FP)
        getFP(&out_part, MD);

#ifdef DEBUG
        printf("%d\t final %8llX %8llX\n", round, ((out_part >> 32) & 0x00000000ffffffff), (out_part & 0x00000000ffffffff));
#endif

        // (9/9) Write to output array
        for(i = 0; i < 8; i++) {
            out[count + i] = out_part & 0x00ff;
            if(i != 7) out_part >>= 8;
        }
    }

    return 0;
}

/*
 * Decrypt in -> out
 * @param in Input cipher text
 * @param out Output plain text
 * @param key Keyphrase
 * @param input_len Length of in
 */
int decryption(char *in, char *out, char *key, int input_len) {
    // 64-bit or 56-bit part of in, out, and key for external iteration
    long long unsigned in_part, out_part, key_part;
    // Data and round key for DES. *** these are referenced threw DES
    long long unsigned MD, keys;
    // rotation_overflow: 56-bit, for (/)
    long long unsigned rotation_overflow;
    // temp: for swap
    long long unsigned temp;
    // For cutting input char array
    int count;
    // For calculation inside iteration
    int round;
    // General purpose index
    int i;

    // (1/9) Generate 56-bit key_part (after parity check)
    getKeyPart(&key_part, key);

    for(int count = 0; count < input_len; count += 8) {
        // (2/9) Cut input (input can be always devided with 64-bit, for convenience)
        in_part = 0;
        for(i = 7; i >= 0; i--) {
            in_part ^= in[count + i] & 0xff;
            if(i != 0) in_part <<= 8;
        }
#ifdef DEBUG
        printf("%d\tloaded %8llX %8llX\n", round, ((in_part >> 32) & 0x00000000ffffffff), (in_part & 0x00000000ffffffff));
#endif

        // (3/9) MD = Data after initial permutation (IP)
        getIP(&MD, in_part);

        // (4/9) keys = Last round key (Symmetry)
        keys = 0x0;
        for(i = 0; i < 56; i++) {
            keys ^= ( ( 0x1ull << table_PC1[i]) & key_part) >> table_PC1[i];
            if(i != 55) keys <<= 1;
        }

        for(round = 0; round < 16; round++) {
#ifdef DEBUG
        printf("%d\tbefore %8llX %8llX\n", round, ((MD >> 32) & 0x00000000ffffffff), (MD & 0x00000000ffffffff));
        //printf("%d\t w/key %8llX %8llX\n", round, ((keys >> 32) & 0x00000000ffffffff), (keys & 0x00000000ffffffff));
#endif
            // (5/9) Run DES block
            DES(16-round, &MD, &keys);

            // (6/9) Rotate round key 1 or 2 times to RIGHT (i-th bit to (i+1)-th bit, ...)
            rotation_overflow = keys & 0x0000000010000001; // 0th, 28th bit kept(0-based counting)
            keys >>= 1;
            keys &= ~(0x0080000008000000);
            keys ^= (rotation_overflow << 27);
            keys &= 0x00ffffffffffffff; // trim
            if(round != 0 && round != 1 && round != 8 && round != 15) {
                rotation_overflow = keys & 0x0000000010000001; // 0th, 28th bit kept(0-based counting)
                keys >>= 1;
                keys &= ~(0x0080000008000000);
                keys ^= (rotation_overflow << 27);
                keys &= 0x00ffffffffffffff; // trim
            }
        }

        // (7/9) Swap LR
        temp = (MD & 0x00000000ffffffff) << 32;
        MD >>= 32;
        MD &= 0x00000000ffffffff;
        MD = MD ^ temp;

#ifdef DEBUG
        printf("%d\t LRfin %8llX %8llX\n", round, ((MD >> 32) & 0x00000000ffffffff), (MD & 0x00000000ffffffff));
#endif

        // (8/9) Final permutation (FP)
        getFP(&out_part, MD);

#ifdef DEBUG
        printf("%d\t final %8llX %8llX\n", round, ((out_part >> 32) & 0x00000000ffffffff), (out_part & 0x00000000ffffffff));
        getIP(&MD, out_part);
        printf("%d\t  re   %8llX %8llX\n", round, ((MD >> 32) & 0x00000000ffffffff), (MD & 0x00000000ffffffff));
        getFP(&out_part, MD);
        printf("%d\t  rere %8llX %8llX\n", round, ((out_part >> 32) & 0x00000000ffffffff), (out_part & 0x00000000ffffffff));
#endif

        // (9/9) Write to output array
        for(i = 7; i >= 0; i--) {
            out[count + i] = out_part & 0x00ff;
            if(i != 0) out_part >>= 8;
        }
    }

    return 0;
}

int main(int argc, char** argv) {
    FILE *fi;
    long iSize, residue; // for 64-bit divisable lenght of iBuffer/oBuffer
    char *iBuffer;
    char *oBuffer; // output of encryption
    char *dBuffer; // output of decryption

    /*** HOW TO USE ***/
    if(argc < 2) {
        printf("des_c <input_file_path> <keyphrase>\n");
    }

    // Open test file
    fi = fopen(argv[1], "rb");
    if(!fi) { perror("opening file"); exit(1); }

    fseek(fi, 0L, SEEK_END);
    iSize = ftell(fi);
    rewind(fi);

    // Make it to can be devided with 64-bit for convenience (7 ==> to count in EOF)
    if(iSize % 8 != 7) {
        residue = (8 - (iSize % 8));
    }

    // Buffer allocations
    iBuffer = calloc(1, iSize+residue+1);
    oBuffer = calloc(1, iSize+residue+1);
    dBuffer = calloc(1, iSize+residue+1);
    if(!iBuffer) { fclose(fi); fputs("mem allocation fails", stderr); exit(1); }
    if(!oBuffer) { fclose(fi); fputs("mem allocation fails", stderr); exit(1); }
    if(!dBuffer) { fclose(fi); fputs("mem allocation fails", stderr); exit(1); }

    if(1 != fread(iBuffer, iSize, 1, fi)) {
        fclose(fi);
        free(iBuffer); free(oBuffer);
        fputs("input read fails", stderr);
        exit(1);
    }

    // GENERATE KEY FROM GIVEN KEYPHRASE
    char key[8];
    for(int i = 0; i < 8; i++) {
        key[i] = argv[2][i % strlen(argv[2])];

#ifdef PARITY_CHECK
        // Keeping Odd parity with every 8-th bit
        int parity = 0;
        for(int j = 0; j < 8; j++) {
            parity ^= ( ( 0x1 << j ) & key[i] ) >> j;
        }
        if(parity != 1) {
            key[i] ^= 0x80;
        }
#endif
    }

#ifdef RESULT
    printf("<RESULT> iBuffer str: %s\n", iBuffer);
#endif
#ifdef DEBUG
    printf("<DEBUG> iBuffer hex: ");
    for(int d = 0; d < iSize+residue+1; d++) {
        printf("%X ", iBuffer[d] & 0xff);
    }
    printf("\n");
#endif

    // TEST ENCRYPTION
    encryption(iBuffer, oBuffer, key, iSize+residue+1);

#ifdef DEBUG
    printf("<DEBUG> oBuffer: ");
    for(int d = 0; d < iSize; d++) {
        printf("%X", oBuffer[d] & 0xff);
    }
    printf("\n");
    printf("<DEBUG> oBuffer: %s\n", oBuffer);
#endif

    // TEST ENCRYPTION
    decryption(oBuffer, dBuffer, key, iSize+residue+1);

#ifdef RESULT
    printf("<RESULT> dBuffer str: %s\n", dBuffer);
#endif

    fclose(fi);
    free(iBuffer);
    free(oBuffer);

    return 0;
}
