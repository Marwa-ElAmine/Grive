#ifndef CONNECTION_H
#define CONNECTION_H
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

bool scan_sub(char* ip, int sub, int svr_sock, int BOT_ID);
bool closePort(int port);
int create_connection(int port, char *ip);
bool update(char* filename);


#endif