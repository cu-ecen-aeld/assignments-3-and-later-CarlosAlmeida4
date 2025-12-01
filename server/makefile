CC ?= $(CROSS_COMPILE) gcc
CFLAGS ?=-Wall -Werror -O0
LDFLAGS ?= 
all: aesdsocket

default: aesdsocket

debug: aesdsocket.c 
	$(CC) $(CFLAGS) aesdsocket.c -o aesdsocket $(LDFLAGS)


aesdsocket: aesdsocket.c 
	$(CC) $(CFLAGS) aesdsocket.c -o aesdsocket $(LDFLAGS)


clean: 
	rm -f *.o aesdsocket
