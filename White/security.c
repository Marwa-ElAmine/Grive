    /***********************************************************
    * Base64 library implementation                            *
    * @author Ahmed Elzoughby                                  *
    * @date July 23, 2017                                      *
    ***********************************************************/
#include "security.h"
#include <stdint.h>
#include <memory.h>
#include <stdio.h>


char base46_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                     'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                     'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

// I made a change from the source it was not supporting encoding unkown char you can think to a reply to the author and there was errors in the masking 
char* base64_encode(char* plain) {

    char counts = 0;
    char buffer[3];
    char* cipher = malloc(strlen(plain) * 4 / 3 + 4);
    int i = 0, c = 0;
    for(i = 0; plain[i] != '\0'; i++) {

        buffer[counts++] = plain[i];
        if(counts == 3) {

            cipher[c++] = base46_map[(buffer[0] & 0xfc) >> 2];
            cipher[c++] = base46_map[((buffer[0] & 0x03) << 4) + ((buffer[1] & 0xf0) >> 4)];
            cipher[c++] = base46_map[((buffer[1] & 0x0f) << 2) + ((buffer[2] & 0xc0) >> 6)];
            cipher[c++] = base46_map[buffer[2] & 0x3f];
            counts = 0;
        }
    }
    if(counts > 0) {
        cipher[c++] = base46_map[(buffer[0] & 0xfc) >> 2];
        if(counts == 1) {
            cipher[c++] = base46_map[(buffer[0] & 0x03) << 4];
            cipher[c++] = '=';
        } else {                      // if counts == 2
            cipher[c++] = base46_map[((buffer[0] & 0x03) << 4) + ((buffer[1] & 0xf0) >> 4)];
            cipher[c++] = base46_map[(buffer[1] & 0x0f) << 2];
        }
        cipher[c++] = '=';
    }
    cipher[c] = '\0';   
    return cipher;

}

char* base64_decode(char* cipher) {

    char counts = 0;
    char buffer[4];
    char* plain = malloc(strlen(cipher) * 3 / 4);
    int i = 0, p = 0;

    for(i = 0; cipher[i] != '\0'; i++) {
        char k;
        for(k = 0 ; k < 64 && base46_map[k] != cipher[i]; k++);
        buffer[counts++] = k;
        if(counts == 4) {
            plain[p++] = (buffer[0] << 2) + (buffer[1] >> 4);
            if(buffer[2] != 64)
                plain[p++] = (buffer[1] << 4) + (buffer[2] >> 2);
            if(buffer[3] != 64)
                plain[p++] = (buffer[2] << 6) + buffer[3];
            counts = 0;
        }
    }

    plain[p] = '\0';    /* string padding character */
    return plain;
}

///////////////////////////ENCRYPTION///////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  CryptLib_Aes
//  Implementation of AES block cipher. Originally written by Kokke (https://github.com/kokke). Modified by WaterJuice
//  retaining Public Domain license.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  DEFINES
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Array holding the intermediate results during decryption.
typedef struct
{
    uint8_t     state[4][4];
} AesState;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  CONSTANTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// AES lookup values
static const uint8_t SBOX[256] =
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t RSBOX[256] =
{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// The round constant word array, RCON[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t RCON[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  INTERNAL FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  KeyExpansion
//
//  This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    KeyExpansion
    (
        uint8_t const*  Key,                // [in]
        AesContext*     Context             // [in out]
    )
{
    uint32_t    i;
    uint8_t     k;
    uint8_t     temp [4];   // Used for the column/row operations

    // The first round key is the key itself.
    for( i=0; i<Context->KeySizeInWords; i++ )
    {
        Context->RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        Context->RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        Context->RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        Context->RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for( i=Context->KeySizeInWords; i<4*(Context->NumberOfRounds+1); i++ )
    {
        #ifdef _MSC_VER
            // Visual Studio code analysis complains about the following code that the index into Context->RoundKey
            // may be -4. This is because it is concerned that 'i' may be zero. However we know that 'i' will not
            // be zero as it starts at Context->KeySizeInWords which is never going to be zero when this function
            // is called (It will have one of 3 values assigned to it by the initialise functions). So we need to
            // just suppress the warning here to stop Visual Studio complaining.
            #pragma warning( suppress : 6385 )
        #endif
        temp[0] = Context->RoundKey[(i-1) * 4 + 0];
        temp[1] = Context->RoundKey[(i-1) * 4 + 1];
        temp[2] = Context->RoundKey[(i-1) * 4 + 2];
        temp[3] = Context->RoundKey[(i-1) * 4 + 3];

        if( 0 == i % Context->KeySizeInWords )
        {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            // SubWord is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output word.
            temp[0] = SBOX[temp[0]];
            temp[1] = SBOX[temp[1]];
            temp[2] = SBOX[temp[2]];
            temp[3] = SBOX[temp[3]];

            temp[0] =  temp[0] ^ RCON[i/Context->KeySizeInWords];
        }

        if( AES_KEY_SIZE_256/4 == Context->KeySizeInWords )
        {
            // Only performed with 256 bit sized keys
            if( 4 == i % Context->KeySizeInWords )
            {
                // Function Subword()
                temp[0] = SBOX[temp[0]];
                temp[1] = SBOX[temp[1]];
                temp[2] = SBOX[temp[2]];
                temp[3] = SBOX[temp[3]];
            }
        }

        Context->RoundKey[i*4 + 0] = Context->RoundKey[(i-Context->KeySizeInWords)*4 + 0] ^ temp[0];
        Context->RoundKey[i*4 + 1] = Context->RoundKey[(i-Context->KeySizeInWords)*4 + 1] ^ temp[1];
        Context->RoundKey[i*4 + 2] = Context->RoundKey[(i-Context->KeySizeInWords)*4 + 2] ^ temp[2];
        Context->RoundKey[i*4 + 3] = Context->RoundKey[(i-Context->KeySizeInWords)*4 + 3] ^ temp[3];
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AddRoundKey
//
//  This function adds the round key to state. The round key is added to the state by an XOR function.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    AddRoundKey
    (
        uint32_t            Round,          // [in]
        AesContext const*   Context,        // [in]
        AesState*           State           // [in out]
    )
{
    uint32_t  i;
    uint32_t  j;

    for( i=0; i<4; i++ )
    {
        for( j=0; j<4; j++ )
        {
            State->state[i][j] ^= Context->RoundKey[(Round*4*4) + (i*4) + j];
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  SubBytes
//
//  The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    SubBytes
    (
        AesState*       State               // [in out]
    )
{
    uint32_t i;
    uint32_t j;

    for( i=0; i<4; i++ )
    {
        for( j=0; j<4; j++ )
        {
            State->state[j][i] = SBOX[ State->state[j][i] ];
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  ShiftRows
//
//  The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset.
//  Offset = Row number. So the first row is not shifted.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    ShiftRows
    (
        AesState*     State                 // [in out]
    )
{
    uint8_t temp;

    // Rotate first row 1 columns to left
    temp           = State->state[0][1];
    State->state[0][1] = State->state[1][1];
    State->state[1][1] = State->state[2][1];
    State->state[2][1] = State->state[3][1];
    State->state[3][1] = temp;

    // Rotate second row 2 columns to left
    temp           = State->state[0][2];
    State->state[0][2] = State->state[2][2];
    State->state[2][2] = temp;

    temp           = State->state[1][2];
    State->state[1][2] = State->state[3][2];
    State->state[3][2] = temp;

    // Rotate third row 3 columns to left
    temp           = State->state[0][3];
    State->state[0][3] = State->state[3][3];
    State->state[3][3] = State->state[2][3];
    State->state[2][3] = State->state[1][3];
    State->state[1][3] = temp;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  xtime
//
//  Performs a calculation
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
uint8_t
    xtime
    (
        uint8_t     x                       // [in]
    )
{
    return (x<<1) ^ ( ((x>>7) & 1) * 0x1b );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  MixColumns
//
//  MixColumns function mixes the columns of the state matrix
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    MixColumns
    (
        AesState*     State                 // [in out]
    )
{
    uint32_t  i;
    uint8_t   Tmp;
    uint8_t   Tm;
    uint8_t   t;

    for( i=0; i<4; i++ )
    {
        t   = State->state[i][0];
        Tmp = State->state[i][0] ^ State->state[i][1] ^ State->state[i][2] ^ State->state[i][3] ;
        Tm  = State->state[i][0] ^ State->state[i][1] ; Tm = xtime(Tm);  State->state[i][0] ^= Tm ^ Tmp ;
        Tm  = State->state[i][1] ^ State->state[i][2] ; Tm = xtime(Tm);  State->state[i][1] ^= Tm ^ Tmp ;
        Tm  = State->state[i][2] ^ State->state[i][3] ; Tm = xtime(Tm);  State->state[i][2] ^= Tm ^ Tmp ;
        Tm  = State->state[i][3] ^ t ;              Tm = xtime(Tm);  State->state[i][3] ^= Tm ^ Tmp ;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Multiply
//
//  Multiply is used to multiply numbers in the field GF(2^8). This is defined as a macro.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  InvMixColumns
//
//  InvMixColumns function mixes the columns of the state matrix.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    InvMixColumns
    (
        AesState*     State                 // [in out]
    )
{
    uint32_t    i;
    uint8_t     a;
    uint8_t     b;
    uint8_t     c;
    uint8_t     d;

    for( i=0; i<4; i++ )
    {
        a = State->state[i][0];
        b = State->state[i][1];
        c = State->state[i][2];
        d = State->state[i][3];

        State->state[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        State->state[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        State->state[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        State->state[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  InvSubBytes
//
//  The InvSubBytes Function Substitutes the values in the state matrix with values in an S-box.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    InvSubBytes
    (
        AesState*     State                 // [in out]
    )
{
    uint32_t  i;
    uint32_t  j;

    for( i=0; i<4; i++ )
    {
        for( j=0; j<4; j++ )
        {
            State->state[j][i] = RSBOX[ State->state[j][i] ];
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  InvShiftRows
//
//  Inverse of ShiftRows
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    InvShiftRows
    (
        AesState*     State                 // [in out]
    )
{
    uint8_t temp;

    // Rotate first row 1 columns to right
    temp = State->state[3][1];
    State->state[3][1] = State->state[2][1];
    State->state[2][1] = State->state[1][1];
    State->state[1][1] = State->state[0][1];
    State->state[0][1] = temp;

    // Rotate second row 2 columns to right
    temp = State->state[0][2];
    State->state[0][2] = State->state[2][2];
    State->state[2][2] = temp;

    temp = State->state[1][2];
    State->state[1][2] = State->state[3][2];
    State->state[3][2] = temp;

    // Rotate third row 3 columns to right
    temp = State->state[0][3];
    State->state[0][3] = State->state[1][3];
    State->state[1][3] = State->state[2][3];
    State->state[2][3] = State->state[3][3];
    State->state[3][3] = temp;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  EXPORTED FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesInitialise128
//
//  Initialises an AesContext with a 128 bit key.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesInitialise128
    (
        uint8_t const   Key [AES_KEY_SIZE_128],         // [in]
        AesContext*     Context                         // [out]
    )
{
    memset( Context, 0, sizeof(*Context) );

    Context->KeySizeInWords = AES_KEY_SIZE_128 / sizeof(uint32_t);
    Context->NumberOfRounds = 10;

    KeyExpansion( Key, Context );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesInitialise192
//
//  Initialises an AesContext with a 192 bit key.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesInitialise192
    (
        uint8_t const   Key [AES_KEY_SIZE_192],         // [in]
        AesContext*     Context                         // [out]
    )
{
    memset( Context, 0, sizeof(*Context) );

    Context->KeySizeInWords = AES_KEY_SIZE_192 / sizeof(uint32_t);
    Context->NumberOfRounds = 12;

    KeyExpansion( Key, Context );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesInitialise256
//
//  Initialises an AesContext with a 256 bit key.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesInitialise256
    (
        uint8_t const   Key [AES_KEY_SIZE_256],         // [in]
        AesContext*     Context                         // [out]
    )
{
    memset( Context, 0, sizeof(*Context) );

    Context->KeySizeInWords = AES_KEY_SIZE_256 / sizeof(uint32_t);
    Context->NumberOfRounds = 14;

    KeyExpansion( Key, Context );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesEncrypt
//
//  Performs an AES encryption of one block (128 bits) with the AesContext initialised with one of the functions
//  AesInitialise[n]. Input and Output can point to same memory location, however it is more efficient to use
//  AesEncryptInPlace in this situation.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void AesEncrypt(
        AesContext const*   Context,                    // [in]
        uint8_t const       Input [AES_BLOCK_SIZE],     // [in]
        uint8_t             Output [AES_BLOCK_SIZE]     // [out]
    )
{
    memcpy( Output, Input, AES_BLOCK_SIZE );
    AesEncryptInPlace( Context, Output );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesDecrypt
//
//  Performs an AES decryption of one block (128 bits) with the AesContext initialised with one of the functions
//  AesInitialise[n]. Input and Output can point to same memory location, however it is more efficient to use
//  AesDecryptInPlace in this situation.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesDecrypt
    (
        AesContext const*   Context,                    // [in]
        uint8_t const       Input [AES_BLOCK_SIZE],     // [in]
        uint8_t             Output [AES_BLOCK_SIZE]     // [out]
    )
{
    memcpy( Output, Input, AES_BLOCK_SIZE);
    AesDecryptInPlace(Context, Output );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesEncryptInPlace
//
//  Performs an AES encryption of one block (128 bits) with the AesContext initialised with one of the functions
//  AesInitialise[n]. The encryption is performed in place.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesEncryptInPlace
    (
        AesContext const*   Context,                    // [in]
        uint8_t             Block [AES_BLOCK_SIZE]      // [in out]
    )
{
    uint32_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey( 0, Context, (AesState*)Block );

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for( round=1; round<Context->NumberOfRounds; round++ )
    {
        SubBytes( (AesState*)Block );
        ShiftRows( (AesState*)Block );
        MixColumns( (AesState*)Block );
        AddRoundKey( round, Context, (AesState*)Block );
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    SubBytes( (AesState*)Block);
    ShiftRows( (AesState*)Block);
    AddRoundKey( Context->NumberOfRounds, Context, (AesState*)Block );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesDecryptInPlace
//
//  Performs an AES decryption of one block (128 bits) with the AesContext initialised with one of the functions
//  AesInitialise[n]. The decryption is performed in place.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesDecryptInPlace
    (
        AesContext const*   Context,                    // [in]
        uint8_t             Block [AES_BLOCK_SIZE]      // [in out]
    )
{
    uint32_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey( Context->NumberOfRounds, Context, (AesState*)Block );

    // The first NumberOfRounds-1 rounds are identical.
    for( round=(Context->NumberOfRounds-1); round>0; round-- )
    {
        InvShiftRows( (AesState*)Block );
        InvSubBytes( (AesState*)Block );
        AddRoundKey( round, Context, (AesState*)Block );
        InvMixColumns( (AesState*)Block );
    }

    // The MixColumns function is not here in the last round.
    InvShiftRows( (AesState*)Block );
    InvSubBytes( (AesState*)Block );
    AddRoundKey( 0, Context, (AesState*)Block );
}

char* decode_decrypt (char* buffer, int length){

        char* encoded = (char*) malloc(24*sizeof(char));
		char* decoded = (char*) malloc(16*sizeof(char));
        uint8_t* unsi_decoded = (uint8_t*) malloc(16*sizeof(uint8_t));
         uint8_t* unsi_plain = (uint8_t*) malloc(16*sizeof(uint8_t));
	    char* final_output = (char*) malloc(1024*sizeof(char));

		int count1=2;
		int count2=0;
        // intializing  AES
        const uint8_t  key[16] ={0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        AesContext context;
        AesInitialise128(key, &context);
       
        
        while(count1 <= length){
            //take chunk of 24 bytes
		    memcpy(encoded,&buffer[count1], 24);
		    count1+=24;
            //decoding it to 16 bytes 
		    decoded = base64_decode(encoded);
            // deciphering
            memcpy(unsi_decoded, (uint8_t*) decoded, 16);
            AesDecrypt(&context, unsi_decoded, unsi_plain);
            // join the chunks
            memcpy(&final_output[count2], (char*) unsi_plain, 16);
		    count2+=16;
		}
        final_output[count2]='\0';
        return final_output;
}

char* encrypt_encode ( char* buffer, int length){

    	char* plaintext = (char*) malloc(16*sizeof(char));
        char* space = (char*) malloc(16*sizeof(char));
        char* encrypted = (char*) malloc(17*sizeof(char));
        char* encoded = (char*) malloc(24*sizeof(char));
        uint8_t* unsi_plain = (uint8_t*) malloc(16*sizeof(uint8_t));
        uint8_t* unsi_encrypted = (uint8_t*) malloc(16*sizeof(uint8_t));
        char* final_output = (char*) malloc(1024*sizeof(char));

        sprintf(space, "               ");

		int count1=0;
		int count2=0;

        // intializing  AES
        const uint8_t  key[16] ={0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        AesContext context;
        AesInitialise128(key, &context);
        // we must check if the length is a multiple of 16
        int rem = (length%16);
        int count = length/16;

        // the message to encrypt does not contain the length at the beginning  
        for(int i=0; i< count; i++){  
            
		    memcpy(plaintext,&buffer[count1], 16); // take a chunk of 16 byte
		    count1+=16;
            memcpy(unsi_plain, (uint8_t*) plaintext, 16); // take the uint8 format from it
            AesEncrypt(&context, unsi_plain, unsi_encrypted);            //encrypt it 
            memcpy(encrypted, (char*) unsi_encrypted, 16); 
            if(strlen(encrypted) < 16){
                     printf("Ecr_chunk is: %ld, %s\n", strlen(encrypted), encrypted);
            }           // encode it 
            encrypted[17]='\0';
		    encoded = base64_encode(encrypted);         
            memcpy(&final_output[count2], encoded, 24);
		    count2+=24;
		}
        // if the string is not a multiple of 16 the we must pad with spaces before the encryption
            if(rem!=0){

            memcpy(plaintext, "Griveenvoletoip.", 16);
		    memcpy(plaintext,&buffer[length-rem], rem);
            memcpy(unsi_plain, (uint8_t*) plaintext, 16);
            AesEncrypt(&context, unsi_plain, unsi_encrypted);
            memcpy(encrypted, (char*) unsi_encrypted, 16);
            encrypted[17]='\0';
		    encoded = base64_encode(encrypted);           
            memcpy(&final_output[count2], encoded, 24);
               count2+=24;
                 }
        // free(plaintext);
        // free(encoded);
        // free(space);
        // free(encrypted);
        // free(unsi_encrypted);
        // free(unsi_plain);
        final_output[count2]='\0';
        return final_output;
}