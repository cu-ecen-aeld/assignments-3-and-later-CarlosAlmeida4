#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/queue.h>

typedef struct ClientStruct_t
{
    int clientSocket;
    const char *filename;
    FILE *file;
} ClientStruct;

volatile int exitFlag = 0;

void *reader_fnc(void *arg)
{
    ClientStruct *ThisClient = (ClientStruct *)arg;
    int WaitForClient;
    struct sockaddr_in clientAddr;
    char receiveBuff[2048];
    char *WritetoFileBuf = NULL;
    int WritetoFileBufSize = 0;
    int clientSocket = ThisClient->clientSocket;
    const char *filename = ThisClient->filename;

    WaitForClient = 1;
    char *tmp = NULL;
    do
    {

        int receiveSize = recv(clientSocket, &receiveBuff, (sizeof(receiveBuff) - 1), 0);
        if (receiveSize < 0)
        {
            syslog(LOG_ERR, "Failed receiving packet\n");
        }
        else
        {
            receiveBuff[receiveSize] = '\0';
            // printf("bufsize %d Received: %s\n",WritetoFileBufSize, receiveBuff);
            int newSize = receiveSize + WritetoFileBufSize + 1;
            tmp = (char *)realloc(WritetoFileBuf, newSize);

            if (tmp == NULL)
            {
                syslog(LOG_ERR, "Failed allocating memory Package size: %d", receiveSize);
                syslog(LOG_ERR, "Current buffer size: %d", WritetoFileBufSize);

                break;
            }
            WritetoFileBuf = tmp;

            if (WritetoFileBufSize == 0)
            {
                WritetoFileBuf[0] = '\0';
            }
            strcat(WritetoFileBuf, receiveBuff);

            WritetoFileBufSize = WritetoFileBufSize + receiveSize;
        }

        if (strchr(receiveBuff, '\n')) // finished packet
        {
            WaitForClient = 0;
        }
    } while (WaitForClient);

    
    if (ThisClient->file == NULL)
    {
        syslog(LOG_ERR, "Failed to open the file %s", filename);
        close(clientSocket);
        exit(EXIT_FAILURE);
    }
    if (fwrite(WritetoFileBuf, 1, WritetoFileBufSize, ThisClient->file) != WritetoFileBufSize)
    {
        syslog(LOG_ERR, "Failed to write entire buffer to file");
        // free(WritetoFileBuf);
        fclose(ThisClient->file);
        close(clientSocket);
        exit(EXIT_FAILURE);
    }
    fflush(ThisClient->file);

    if (WritetoFileBuf != NULL)
    {
        // WritetoFileBuf = NULL;
        free(WritetoFileBuf);
        WritetoFileBuf = NULL;
        WritetoFileBufSize = 0;
    }

    // Write to client the entire file
    rewind(ThisClient->file);
    while (fgets(receiveBuff, 2048, ThisClient->file))
    {
        // send the buffer to the client
        send(clientSocket, receiveBuff, strlen(receiveBuff), 0);
        // printf("%s",receiveBuff);
    }
    close(ThisClient->clientSocket);

    syslog(LOG_INFO, "Closed connection from %s", inet_ntoa(clientAddr.sin_addr));
    return 0;
}

void signal_handler(int signal)
{
    syslog(LOG_ERR, "Caught signal, exiting");
    exitFlag = 1;
}

int main(int argc, char *argv[])
{
    int server_fd, clientSocket, rc, daemonMode = 0;
    const char PORT[] = "9000";
    int getAddrInfoRes;
    struct addrinfo *servinfo;
    struct addrinfo hints;
    struct sockaddr_in clientAddr;
    socklen_t clientSize = sizeof(clientAddr);

    pthread_t clientThread;
    
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (argc == 2 && strcmp(argv[1], "-d") == 0)
    {
        daemonMode = 1;
    }
    
    const char *filename = "/var/tmp/aesdsocketdata";
    remove(filename); // remove older file if it exists
    FILE *file = fopen(filename, "a+");
    openlog(NULL, 0, LOG_USER);

    if (file == NULL)
    {
        syslog(LOG_ERR, "Failed to open the file %s", filename);
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;

    getAddrInfoRes = getaddrinfo(NULL, PORT, &hints, &servinfo);
    if (getAddrInfoRes != 0)
    {
        syslog(LOG_ERR, "Failed to get address info");
        exit(EXIT_FAILURE);
    }

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        syslog(LOG_ERR, "Failed to get socket");
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
    {
        syslog(LOG_ERR, "Error setting socket options");
        exit(EXIT_FAILURE);
    }
    rc = bind(server_fd, servinfo->ai_addr, servinfo->ai_addrlen);
    if (rc != 0)
    {
        syslog(LOG_ERR, "Failed to bind");
        exit(EXIT_FAILURE);
    }

    if (daemonMode)
    {
        pid_t p = fork();
        if (p < 0)
        {
            syslog(LOG_ERR, "Failed to fork the program");
            exit(EXIT_FAILURE);
        }
        if (p > 0)
        {
            exit(EXIT_SUCCESS);
        }
        setsid();
    }

    if (listen(server_fd, 10) < 0)
    {
        syslog(LOG_ERR, "unable to listen");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(servinfo);

    do
    {

        clientSocket = accept(server_fd, (struct sockaddr *)&clientAddr, &clientSize);

        if (clientSocket < 0)
        {
            syslog(LOG_ERR, "Failed to accept client with errno %d\n", errno);
            close(server_fd);
            exit(EXIT_FAILURE);
        }
        // client is accepted
        syslog(LOG_INFO, "Accepted connection from %s", inet_ntoa(clientAddr.sin_addr));
        ClientStruct NewClient = {clientSocket,filename,file};
        if(pthread_create(&clientThread, NULL, reader_fnc, &NewClient)!=0)
        {
            syslog(LOG_PERROR, "Failed to create thread");
            close(server_fd);
            exit(EXIT_FAILURE);
        }
        fclose(file);
        close(clientSocket);

        syslog(LOG_INFO, "Closed connection from %s", inet_ntoa(clientAddr.sin_addr));
    } while (!exitFlag);

    if (remove(filename) == 0)
    {
        syslog(LOG_INFO, "File deleted sucessfully\n");
    }
    else
    {
        syslog(LOG_ERR, "Failed removing the file");
    }
    close(server_fd);
    closelog();
    return 0;
    // modify to accept -d argument, which forks after binding to 9000
    // fulltest
}