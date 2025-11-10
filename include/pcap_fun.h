#ifndef PCAP_FUN_H
#define PCAP_FUN_H  

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <iphlpapi.h>

#include <iphlpapi.h>
#include <winerror.h>
#include <windows.h>

#include "packet.h"

extern uint8_t MY_MAC[6];
extern uint32_t MY_IP;


#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef UNKNOWN_ERROR
#define UNKNOWN_ERROR -1
#endif

struct ip_mac_name
{
    pcap_if_t *dev;
    uint32_t ip;
    uint32_t ip_mask;
    uint32_t mask;
    uint8_t mac[6];
    wchar_t name[512];
};

typedef struct ip_mac_name ip_mac_name_t;

pcap_t *initialize_pcap();

#endif /* PCAP_FUN_H */