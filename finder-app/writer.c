#include <syslog.h>
#include <stdio.h>

int main(int argc, char **argv) {
    const int MaxInputs = 2;
    
    openlog(NULL,0,LOG_USER);

    if(argc != MaxInputs)
    {
        syslog(LOG_ERR, "Invalid Number of arguments: %d", argc);
        return 1;
    }
    
    char *filename = argv[1];
    char *payload = argv[2];

    syslog(LOG_DEBUG,"Writing %s to %s", payload, filename);

    FILE *file = fopen(filename,"w");

    if(file == NULL)
    {
        syslog(LOG_ERR,"Error opening file %s",filename);
        return 1;
    }

    fprintf(file,"%s",payload);
    fclose(file);

    return 0;
}