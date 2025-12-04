# Makefile for building 'test' from raw.c with Npcap and Windows libraries

CC=gcc
CFLAGS=-Wall -I "C:\Program Files\Npcap\Include" -I "include" -D_WIN32_WINNT=0x0600
LDFLAGS=-L "C:\Program Files\Npcap\Lib\x64" -lwpcap -lpacket -lws2_32 -liphlpapi
MYFLAGS= -DVALIDATE_CHECKSUM

all: main spoof debug

main:
	$(CC) -o main main.c packet.c pcap_fun.c tftp.c queue.c $(CFLAGS) $(LDFLAGS) $(MYFLAGS)

spoof:
	$(CC) -o ip_spoof main.c packet.c pcap_fun.c tftp.c queue.c $(CFLAGS) $(LDFLAGS) $(MYFLAGS) -DSPOOF_NON_VLAN

.PHONY: debug clean
debug:
	$(CC) -g -O0 -o debug main.c packet.c pcap_fun.c tftp.c queue.c $(CFLAGS) $(LDFLAGS) $(MYFLAGS) -DDEBUG
	$(CC) -g -O0 -o debug_ip_spoof main.c packet.c pcap_fun.c tftp.c queue.c $(CFLAGS) $(LDFLAGS) $(MYFLAGS) -DDEBUG -DSPOOF_NON_VLAN
	

clean:
	cmd /C "if exist test.exe del /Q test.exe"

# gcc -g -O0 -o debug main.c packet.c pcap_fun.c tftp.c queue.c -Wall -I "C:\Program Files\Npcap\Include" -I "include" -D_WIN32_WINNT=0x0600 -L "C:\Program Files\Npcap\Lib\x64" -lwpcap -lpacket -lws2_32 -liphlpapi -DVALIDATE_CHECKSUM -DDEBUG