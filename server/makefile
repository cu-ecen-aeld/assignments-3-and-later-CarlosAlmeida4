CC := $(CROSS_COMPILE) gcc

all: aesdsocket

default: aesdsocket

debug: aesdsocket.c 
	$(CC) -g -O0 aesdsocket.c -o aesdsocket


aesdsocket: aesdsocket.c 
	$(CC) aesdsocket.c -o aesdsocket


clean: 
	rm -f *.o aesdsocket
