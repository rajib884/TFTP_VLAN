# Makefile for building with Npcap, Windows libraries, and libcurl (FTP support)

CC=gcc
CURL_INCLUDE  = "C:\bin\curl\include"
CURL_LIB      = "C:\bin\curl\lib"
CFLAGS=-Wall -I "C:\Program Files\Npcap\Include" -I "include" -I $(CURL_INCLUDE) -D_WIN32_WINNT=0x0600
LDFLAGS=-L "C:\Program Files\Npcap\Lib\x64" -L $(CURL_LIB) -lwpcap -lpacket -lws2_32 -liphlpapi -lcurl
MYFLAGS= -DVALIDATE_CHECKSUM

SRCS = main.c packet.c pcap_fun.c tftp.c queue.c ftp_handler.c

all: main spoof debug

main:
	$(CC) -o main $(SRCS) $(CFLAGS) $(LDFLAGS) $(MYFLAGS)

spoof:
	$(CC) -o ip_spoof $(SRCS) $(CFLAGS) $(LDFLAGS) $(MYFLAGS) -DSPOOF_NON_VLAN

.PHONY: debug clean
debug:
	$(CC) -g -O0 -o debug $(SRCS) $(CFLAGS) $(LDFLAGS) $(MYFLAGS) -DDEBUG
	$(CC) -g -O0 -o debug_ip_spoof $(SRCS) $(CFLAGS) $(LDFLAGS) $(MYFLAGS) -DDEBUG -DSPOOF_NON_VLAN
	

clean:
	cmd /C "if exist test.exe del /Q test.exe"

# gcc -g -O0 -o debug main.c packet.c pcap_fun.c tftp.c queue.c -Wall -I "C:\Program Files\Npcap\Include" -I "include" -D_WIN32_WINNT=0x0600 -L "C:\Program Files\Npcap\Lib\x64" -lwpcap -lpacket -lws2_32 -liphlpapi -DVALIDATE_CHECKSUM -DDEBUG
