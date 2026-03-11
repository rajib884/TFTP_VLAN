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
#include "cli_config.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef UNKNOWN_ERROR
#define UNKNOWN_ERROR -1
#endif

typedef struct devices 
{
    struct devices* next;
    uint32_t ip;    // IP address
    uint32_t mask;  // IP mask
    uint8_t mac[6]; // MAC address
    uint32_t mtu;
    char *name;     // Friendly Name
    char *dev_name; // Device Identifier
    char *dev_desc; // Device Description
} devices_t;

devices_t *get_devices();
void free_devs(devices_t *);

devices_t *select_device(devices_t *devs, cli_config_t *config);
devices_t *choose_device(devices_t *devs, cli_config_t *config);

pcap_t *get_pcap_handle(devices_t *dev, cli_config_t *config);

#endif /* PCAP_FUN_H */