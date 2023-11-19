CC=gcc 
CC_FLAGS=-Wall --pedantic -lnet -lpcap

all:
	$(CC) main.c $(CC_FLAGS) -o main

clean:
	rm main
