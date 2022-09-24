 #define _GNU_SOURCE  
 //Client side C/C++ program to demonstrate Socket
// programming
#include <arpa/inet.h>
#include <stdio.h>
#include<stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <errno.h>
#include "connection.h"
#include "reporter.h"
#include "security.h"
#define PORT 8080

#define AES_KEY_SIZE_128        16
#define AES_KEY_SIZE_192        24
#define AES_KEY_SIZE_256        32
#define AES_BLOCK_SIZE          16



int main(int c, char *argv[]){
//[0] GeecksforGeecks.Envoletoigrive!1
    char* plaintext = (char*) malloc(16*sizeof(char));
    sprintf(plaintext, "cks.Envoletoigri");
        char* space = (char*) malloc(16*sizeof(char));
        char* encrypted = (char*) malloc(17*sizeof(char));
        char* encoded = (char*) malloc(24*sizeof(char));
        uint8_t* unsi_plain = (uint8_t*) malloc(16*sizeof(uint8_t));
        uint8_t* unsi_encrypted = (uint8_t*) malloc(16*sizeof(uint8_t));

        // intializing  AES
        const uint8_t  key[16] ={0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        AesContext context;
        AesInitialise128(key, &context);
        // we must check if the length is a multiple of 16
 
 
            printf("\n---------------------------------------\n");  
            // take a chunk of 16 byte
            printf("Plain_text   : %s .\n", plaintext);
            // take the uint8 format from it
            memcpy(unsi_plain, (uint8_t*) plaintext, 16);
            //encrypt it 
            AesEncrypt(&context, unsi_plain, unsi_encrypted);
            // encode it 
            memcpy(encrypted, (char*) unsi_encrypted, 16);
            encrypted[17]='\0';
            printf("Ecrypted_text: %s .\n", encrypted);  
            for (int i = 0; i<16; i++){
                    printf("%x ", unsi_encrypted[i]);
            }
            printf("\n");
		    encoded = base64_encode(encrypted);
            printf(base64_decode(encoded));    
            printf("Encoded_text : %s .\n", encoded); 
            for (int i = 0; i<24; i++){
                    printf("%c:%d ", encoded[i], (uint8_t) encoded[i]);
            }





    return 0;
 }