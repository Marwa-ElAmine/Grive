#ifndef REPORTER_H
#define REPORTER_H
#include"security.h"
#include<stddef.h>
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

char* log_editor(char *action, bool success);
void printLog(char* log);
bool send_msg(int sockfd, char* m, int BOT_ID);
bool send_log(int sockfd, char* log, int BOT_ID);
bool secure_msg();
bool system_info(int sockfd);
void print_repo(char* log);
bool report(int sockfd, int BOT_ID);

#endif
