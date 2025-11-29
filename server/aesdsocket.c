#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>                         /*TODO !!!! Implement queue*/
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

pthread_mutex_t FileLock = PTHREAD_MUTEX_INITIALIZER;

typedef struct ClientStruct_t
{
    int clientSocket;
    const char *filename;
    struct sockaddr_in clientAddr;
    FILE *file;
    int isFinished;
} ClientStruct;

typedef struct node
{
    //TODO: define information here
    ClientStruct clientStruct;
    pthread_t nodeThread;
    // This macro does the magic to point to other nodes
    TAILQ_ENTRY(node) nodes; 
}node_t;

// This typedef creates a head_t that makes it easy for us to pass pointers to
// head_t without the compiler complaining.
typedef TAILQ_HEAD(head_s, node) head_t;

volatile int exitFlag = 0;

void* timestamp_thread(void* arg)
{
    ClientStruct *ThisClient = (ClientStruct *)arg;

    while (!exitFlag) {
        sleep(10);

        char timebuf[128];
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);

        strftime(timebuf, sizeof(timebuf),
                 "%a, %d %b %Y %H:%M:%S %z", tm_info);

        char outbuf[256];
        snprintf(outbuf, sizeof(outbuf),
                 "timestamp:%s\n", timebuf);

        pthread_mutex_lock(&FileLock);

        
        if (ThisClient->file) {
            fputs(outbuf, ThisClient->file);
            fflush(ThisClient->file);
        }

        pthread_mutex_unlock(&FileLock);
    }
    return NULL;
}

void *reader_fnc(void *arg)
{
    ClientStruct *ThisClient = (ClientStruct *)arg;
    int WaitForClient, receiveErrorCounter =0;
    struct sockaddr_in clientAddr = ThisClient->clientAddr;
    char receiveBuff[2048];
    char *WritetoFileBuf = NULL;
    int WritetoFileBufSize = 0,receiveErrorCounterLimit = 100;
    int clientSocket = ThisClient->clientSocket;
    const char *filename = ThisClient->filename;
    ThisClient->isFinished = 0;
   
    WaitForClient = 1;
    char *tmp = NULL;
    do
    {

        int receiveSize = recv(clientSocket, &receiveBuff, (sizeof(receiveBuff) - 1), 0);
        if (receiveSize < 0)
        {
            if(receiveErrorCounter >= receiveErrorCounterLimit)
            {
                syslog(LOG_ERR, "To many receive errors exiting, Client Socket: %d",clientSocket);
                close(ThisClient->clientSocket);
                ThisClient->isFinished = 1;
                exit(EXIT_FAILURE);
            }
            //receiveErrorCounter++;
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
        close(ThisClient->clientSocket);
        ThisClient->isFinished = 1;
        exit(EXIT_FAILURE);
    }
    //Lockfile
    if(pthread_mutex_lock(&FileLock) != 0)
    {
        syslog(LOG_ERR, "Unable to aquire file access in the client socket %d", clientSocket);
        close(ThisClient->clientSocket);
        ThisClient->isFinished = 1;
        exit(EXIT_FAILURE);
    }


    if (fwrite(WritetoFileBuf, 1, WritetoFileBufSize, ThisClient->file) != WritetoFileBufSize)
    {
        syslog(LOG_ERR, "Failed to write entire buffer to file");
        // free(WritetoFileBuf);
        //fclose(ThisClient->file);
        close(ThisClient->clientSocket);
        ThisClient->isFinished = 1;
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
    //unlock file
    if(pthread_mutex_unlock(&FileLock)!= 0)
    {
        syslog(LOG_ERR, "Unable to unlock file access in the client socket %d", clientSocket);
        close(ThisClient->clientSocket);
        ThisClient->isFinished = 1;
        exit(EXIT_FAILURE);
    }
    close(ThisClient->clientSocket);

    syslog(LOG_INFO, "Closed connection from %s", inet_ntoa(clientAddr.sin_addr));
    ThisClient->isFinished = 1;
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

  

    // Initialize the head before use
    head_t head;
    TAILQ_INIT(&head);


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
    
    /*
        Create timestamp thread
    */
    node_t* timestampNode = malloc(sizeof(node_t));
    if(timestampNode== NULL)
    {
        syslog(LOG_ERR, "Failed to malloc new node\n");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    timestampNode->clientStruct.clientSocket = -1; /* not used */
    timestampNode->clientStruct.filename = filename;
    timestampNode->clientStruct.clientAddr = clientAddr;
    timestampNode->clientStruct.file = file;
    timestampNode->clientStruct.isFinished = 0;

    /* create and pass the node's clientStruct pointer */
    if (pthread_create(&timestampNode->nodeThread, NULL, timestamp_thread, &timestampNode->clientStruct) != 0) {
        syslog(LOG_ERR, "Failed to create timestamp thread");
        free(timestampNode);
        /* handle error */
    }   
    //TAILQ_INSERT_TAIL(&head,timestampNode,nodes);

    while(!exitFlag)
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

        node_t* newNode = malloc(sizeof(node_t));
        if(newNode== NULL)
        {
            syslog(LOG_ERR, "Failed to malloc new node\n");
            close(server_fd);
            exit(EXIT_FAILURE);
        }
        
        /* Fill the node's client struct (copy values). Use the same FILE* and filename. */
        newNode->clientStruct.clientSocket = clientSocket;
        newNode->clientStruct.filename = filename;
        newNode->clientStruct.clientAddr = clientAddr;
        newNode->clientStruct.file = file;
        newNode->clientStruct.isFinished = 0;
        
        TAILQ_INSERT_TAIL(&head,newNode,nodes);
        
        if(pthread_create(&newNode->nodeThread , NULL, reader_fnc, &newNode->clientStruct)!=0)
        {
            syslog(LOG_PERROR, "Failed to create thread");
            close(server_fd);
            exit(EXIT_FAILURE);
        }


    } /*while (!exitFlag);*/

    //Join all still open threads
    pthread_join(timestampNode->nodeThread,NULL);

    node_t *node, *tmp;

    for (node = TAILQ_FIRST(&head); node != NULL; node = tmp) {
        tmp = TAILQ_NEXT(node, nodes);

        // Now it's safe to remove node
        if (node->clientStruct.isFinished) {
            pthread_join(node->nodeThread, NULL);
            printf("Removed Client %d\n", node->clientStruct.clientSocket);
            TAILQ_REMOVE(&head, node, nodes);
            free(node);
        }
        else
        {
            syslog(LOG_INFO,"Client %d is not yet finished yet",node->clientStruct.clientSocket);
        }
    }

    fclose(file);
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