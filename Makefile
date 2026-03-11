# Makefile for building with Npcap, Windows libraries, and libcurl (FTP support)

CC      = gcc
SRCS    = main.c packet.c pcap_fun.c tftp.c queue.c ftp_handler.c cli_config.c fast_log.c
OBJS    = $(SRCS:.c=.o)

# Paths
NPCAP_INC = C:/Program Files/Npcap/Include
NPCAP_LIB = C:/Program Files/Npcap/Lib/x64
# CURL_INC  = C:/bin/curl/include
# CURL_LIB  = C:/bin/curl/lib
CURL_INC  = C:/Users/rajib/Downloads/curl-curl-8_18_0/curl-curl-8_18_0/include
CURL_LIB  = C:/Users/rajib/Downloads/curl-curl-8_18_0/curl-curl-8_18_0/build/lib

# Flags
CFLAGS  = -Wall \
          -I "$(NPCAP_INC)" \
          -I "$(CURL_INC)" \
          -I "include" \
          -D_WIN32_WINNT=0x0600 \
          -DCURL_STATICLIB

LDFLAGS = -L "$(NPCAP_LIB)" \
          -L "$(CURL_LIB)" \
          -static \
          -lwpcap -lpacket \
          -lcurl \
          -liphlpapi -lsecur32 -lws2_32 -lbcrypt -lcrypt32 -lwldap32
#           -lcurl -lssh2 -lssl -lcrypto \
#           -lnghttp2 -lnghttp3 -lngtcp2 -lngtcp2_crypto_libressl \
#           -lbrotlidec -lbrotlicommon \
#           -lpsl -lz -lzstd \
#           -liphlpapi -lsecur32 -lws2_32 -lbcrypt -lcrypt32 -lwldap32

# Build targets
RELEASE_FLAGS = -O2 -DVALIDATE_CHECKSUM
DEBUG_FLAGS   = -g -O0 -DVALIDATE_CHECKSUM -DDEBUG

.PHONY: all release debug clean

all: release debug

release: $(OBJS)
	$(CC) -o main $^ $(CFLAGS) $(RELEASE_FLAGS) $(LDFLAGS)

debug: $(OBJS)
	$(CC) -o main_debug $^ $(CFLAGS) $(DEBUG_FLAGS) $(LDFLAGS)

# Compile .c -> .o (recompile only changed files)
%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	del /Q *.o main.exe main_debug.exe 2>nul || rm -f *.o main main_debug

# gcc -g -O0 -o debug main.c packet.c pcap_fun.c tftp.c queue.c -Wall -I "C:\Program Files\Npcap\Include" -I "include" -D_WIN32_WINNT=0x0600 -L "C:\Program Files\Npcap\Lib\x64" -lwpcap -lpacket -lws2_32 -liphlpapi -DVALIDATE_CHECKSUM -DDEBUG

# gcc -o main main.c packet.c pcap_fun.c tftp.c queue.c ftp_handler.c cli_config.c -Wall -I "C:\Program Files\Npcap\Include" -I "include" -I "C:\bin\curl\include" -D_WIN32_WINNT=0x0600 -DCURL_STATICLIB -L "C:\Program Files\Npcap\Lib\x64" -L "C:\bin\curl\lib" 
#     -static -lwpcap -lpacket -lcurl -lssh2 -lssl -lcrypto -lnghttp2 -lnghttp3 -lngtcp2 -lngtcp2_crypto_libressl -lbrotlidec -lbrotlicommon -lpsl -lz -lzstd -liphlpapi -lsecur32 -lws2_32 -lbcrypt -lcrypt32 -lwldap32 -DVALIDATE_CHECKSUM