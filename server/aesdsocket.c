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

int exitFlag = 0;

void signal_handler(int signal)
{
    syslog(LOG_ERR,"Caught signal, exiting");
    exitFlag = 1;
}

int main()
{
    int server_fd, clientSocket, rc;
    const char PORT[] = "9000";
    int getAddrInfoRes;
    struct addrinfo *servinfo;
    struct addrinfo hints;
    struct sockaddr_in clientAddr;
    socklen_t clientSize = sizeof(clientAddr);
    int WaitForClient = 1;
    char receiveBuff[2048];
    char *WritetoFileBuf = NULL;
    int WritetoFileBufSize = 0;

    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    

    const char *filename = "/var/tmp/aesdsocketdata";
    remove(filename);
    openlog(NULL, 0, LOG_USER);

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

    if (listen(server_fd, 10) < 0)
    {
        syslog(LOG_ERR, "unable to listen");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(servinfo);

    while (!exitFlag)
    {

        clientSocket = accept(server_fd, (struct sockaddr *)&clientAddr, &clientSize);

        if (clientSocket < 0)
        {
            syslog(LOG_ERR, "Failed to accept client with errno %d\n", errno);
            exit(EXIT_FAILURE);
        }
        else
        {
        }

        syslog(LOG_INFO, "Accepted connection from %s", inet_ntoa(clientAddr.sin_addr));
        WaitForClient = 1;

        while (WaitForClient)
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
                int newSize = receiveSize + WritetoFileBufSize;
                char *tmp = (char *)realloc(WritetoFileBuf, newSize);

                if (tmp == NULL)
                {
                    syslog(LOG_ERR, "Failed allocating memory\n Package discarded");
                    break;
                }
                WritetoFileBuf = tmp;
                //free(tmp);
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
        }

        FILE *file = fopen(filename, "a+");
        if (file == NULL)
        {
            syslog(LOG_ERR, "Failed to open the file %s", filename);
            exit(EXIT_FAILURE);
        }
        if (fwrite(WritetoFileBuf, 1, WritetoFileBufSize, file) != WritetoFileBufSize)
        {
            syslog(LOG_ERR, "Failed to write entire buffer to file");
            exit(EXIT_FAILURE);
        }
        // printf("WritetoFileBuf = %s",WritetoFileBuf);

        if (WritetoFileBuf != NULL)
        {
            WritetoFileBuf = NULL;
            WritetoFileBufSize = 0;
        }

        // Write to client the entire file
        rewind(file);
        while (fgets(receiveBuff, 2048, file))
        {
            // send the buffer to the client
            send(clientSocket, &receiveBuff, strlen(receiveBuff), 0);
            // printf("%s",receiveBuff);
        }
        fclose(file);
        close(clientSocket);

        syslog(LOG_INFO, "Closed connection from %s", inet_ntoa(clientAddr.sin_addr));
    }

    if(remove(filename) == 0)
    {
        syslog(LOG_INFO,"File deleted sucessfully\n");
    }
    else
    {
        syslog(LOG_ERR,"Failed removing the file");
    }
    close(server_fd);
    closelog();

    // modify to accept -d argument, which forks after binding to 9000
    // fulltest
}