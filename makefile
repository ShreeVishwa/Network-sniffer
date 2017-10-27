CC = gcc
hellomake: mydump.c
	$(CC) -o mydump mydump.c -lpcap
