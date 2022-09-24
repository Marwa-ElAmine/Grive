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

     char* action  = (char*) malloc(  18*sizeof(char));
     char* log     = (char*) malloc(  30*sizeof(char));
     char* mess    = (char*) malloc( 100*sizeof(char));
     char*sub_mask = (char*) malloc(   2*sizeof(char));
     
     char* buffer  = (char*) malloc(1024*sizeof(char));
     char* dbuffer = (char*) malloc(1024*sizeof(char));
     char* address = (char*) malloc(  15*sizeof(char));
     char* add     = (char*) malloc(  15*sizeof(char));
     char* ID      = (char*) malloc(   4*sizeof(char));
     char* size    = (char*) malloc(   3*sizeof(char));
     char* ip      = (char*) malloc(  13*sizeof(char));
     char* ending  = (char*) malloc(   3*sizeof(char));
     int length = 0;

     sprintf(ip, "172.18.18.18");
     ip[13]='\0';
     // char ip[12] = "172.18.18.18";
     //char  ending[3] = "end";
     sprintf(ending, "end");
     
    memset(buffer, 0, 1024);
    memset(dbuffer, 0, 1024);
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
    
        //memset(buffer, 0, sizeof buffer); 
        memset(address, 0, sizeof address); 
        sprintf(log, "Connected to the server.");
        printLog(log);
        memset(log, 0, 30);

    
	    valread = read(sockfd, buffer, 1024);

	    while( valread > 0){

          
                    //extract the lenght of the message
                    memset(size, 0, 3); 
                    memcpy(size, buffer, 2*sizeof(char));
                    size[2]='\0';
                    length = atoi(size);
                    dbuffer = decode_decrypt(buffer, length);
                    memset(buffer, 0, sizeof buffer);

            if( dbuffer[0] == '0'){

             if( dbuffer[1] == '6'){
                    // 06 ADVANCED: "06"
                    printf("Testing the new feature.\n");

                    char* plaintext = (char*) malloc(33*sizeof(char));
                    sprintf(plaintext, "GeecksforGeecks.Envoletoigrive!1");
                       // encrypt_encode(plaintext, 36);
                    send_msg(sockfd, plaintext, BOT_ID);
                    printf("[C&C] Command:\t");
                    printf("a new features. \n");
                }else if( dbuffer[1] == '7'){

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

                }else if( dbuffer[1] == '8'){

                    // ending without deleting for testing purpose
                    return 0;

                }else{
            
                     printf("NOT A COMMAND!!\t");
                     printf("See the protocol.\n");
                     printf("[C&C] Message:\t");
                     printf("%s\n", dbuffer);
                }
        
            }else if(memmem(dbuffer, sizeof dbuffer, ending, 3) != NULL){

                printf("Have an awesome day :)\n");
                memset(log, 0, 30);
                sprintf(log, "It is time to forever rest.");
                printLog(log);
                close(sockfd);
                return 0;

            }else{   

                printf("[C&C] Message:\t");
                printf("%s\n", dbuffer);
                
		
		}
            
            memset(buffer, 0, sizeof buffer);
            memset(dbuffer, 0, sizeof dbuffer);  
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
     free(dbuffer);
     free(address);
     free(add);
     free(ID);
     return 0;
 }