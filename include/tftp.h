#ifndef TFTP_H
#define TFTP_H

#include <stdint.h>
#include <pcap.h>

#include "packet.h"

struct tftp_session
{
    uint32_t in_use;
    uint16_t server_port;
    uint8_t client_mac[6];
    uint32_t client_ip;
    uint16_t client_port;
#ifdef USE_VLAN
    uint16_t vlan_id;
#endif
    char file_name[512];
    FILE *fd;
    long file_size;
    int32_t block_number;
    uint16_t block_size;
    uint8_t last_packet;
    struct tftp_packet packet;
    uint32_t packet_length;
    int tsize_requested;
    DWORD last_send_tick; // Windows tick count when last packet sent
    int retries; // Retransmission count
};


extern uint16_t ipv4_id;

void handle_tftp(pcap_t *handle, struct tftp_packet *pkt, uint32_t pkt_len);
void session_check(pcap_t *handle);

#endif /* TFTP_H */