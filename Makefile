# Makefile for building 'test' from raw.c with Npcap and Windows libraries

CC=gcc
CFLAGS=-Wall -I "C:\Program Files\Npcap\Include" -I "include" -D_WIN32_WINNT=0x0600
LDFLAGS=-L "C:\Program Files\Npcap\Lib" -lwpcap -lpacket -lws2_32 -liphlpapi

all: test

test: raw.c
	$(CC) -o test main.c packet.c pcap_fun.c tftp.c $(CFLAGS) $(LDFLAGS)

clean:
	del /Q test.exe test
