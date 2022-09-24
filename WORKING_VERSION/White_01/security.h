    /***********************************************************
    * Base64 library                                           *
    * @author Ahmed Elzoughby                                  *
    * @date July 23, 2017                                      *
    * Purpose: encode and decode base64 format                 *
    ***********************************************************/

#ifndef SECURITY_H
#define SECURITY_H
#define AES_KEY_SIZE_128        16
#define AES_KEY_SIZE_192        24
#define AES_KEY_SIZE_256        32
#define AES_BLOCK_SIZE          16

#include <stdlib.h>
#include <memory.h>
#include <stdint.h>

/***********************************************
Encodes ASCCI string into base64 format string
@param plain ASCII string to be encoded
@return encoded base64 format string
***********************************************/
char* base64_encode(char* plain);


/***********************************************
decodes base64 format string into ASCCI string
@param plain encoded base64 format string
@return ASCII string to be encoded
***********************************************/
char* base64_decode(char* cipher);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TYPES
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// AesContext - This must be initialised using AesInitialise128, AesInitialise192 or AesInitialise256
// Do not modify the contents of this structure directly.
typedef struct
{
    uint32_t    KeySizeInWords;
    uint32_t    NumberOfRounds;
    uint8_t     RoundKey[240];
} AesContext;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesInitialise128
//
//  Initialises an AesContext with a 128 bit key.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void AesInitialise128 (
        uint8_t const   Key [AES_KEY_SIZE_128],         // [in]
        AesContext*     Context                         // [out]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesInitialise192
//
//  Initialises an AesContext with a 192 bit key.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void AesInitialise192 (
        uint8_t const   Key [AES_KEY_SIZE_192],         // [in]
        AesContext*     Context                         // [out]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesInitialise256
//
//  Initialises an AesContext with a 256 bit key.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void AesInitialise256 (
        uint8_t const   Key [AES_KEY_SIZE_256],         // [in]
        AesContext*     Context                         // [out]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesEncrypt
//
//  Performs an AES encryption of one block (128 bits) with the AesContext initialised with one of the functions
//  AesInitialise[n]. Input and Output can point to same memory location, however it is more efficient to use
//  AesEncryptInPlace in this situation.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void AesEncrypt (
        AesContext const*   Context,                    // [in]
        uint8_t const       Input [AES_BLOCK_SIZE],     // [in]
        uint8_t             Output [AES_BLOCK_SIZE]     // [out]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesDecrypt
//
//  Performs an AES decryption of one block (128 bits) with the AesContext initialised with one of the functions
//  AesInitialise[n]. Input and Output can point to same memory location, however it is more efficient to use
//  AesDecryptInPlace in this situation.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void AesDecrypt
    (
        AesContext const*   Context,                    // [in]
        uint8_t const       Input [AES_BLOCK_SIZE],     // [in]
        uint8_t             Output [AES_BLOCK_SIZE]     // [out]
    );

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
    );

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
    );

char* 
    decode_decrypt 
    (
        char* buffer,
        int length
    );

#endif 