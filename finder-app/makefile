CC := $(CROSS_COMPILE) gcc

default: writer

writer: writer.c 
		$(CROSS_COMPILE)gcc writer.c -o writer

clean: 
	rm -f *.o writer