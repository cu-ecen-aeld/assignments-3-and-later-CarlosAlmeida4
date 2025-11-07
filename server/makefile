CC := $(CROSS_COMPILE) gcc
CFLAGS=-Wall -Werror -O0
all: aesdsocket

default: aesdsocket

debug: aesdsocket.c 
	$(CC) $(CFLAGS) aesdsocket.c -o aesdsocket


aesdsocket: aesdsocket.c 
	$(CC) $(CFLAGS) aesdsocket.c -o aesdsocket


clean: 
	rm -f *.o aesdsocket
