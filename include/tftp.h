#ifndef TFTP_H
#define TFTP_H

#include <stdint.h>
#include <pcap.h>

#include "packet.h"

struct tftp_session
{
    uint32_t in_use;
    uint32_t session_id; // Unique session identifier for debugging
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
    int64_t ack_received; // Last acknowledged block number
    int64_t block_number; // Current block number
    uint16_t block_size; // Block size for data packets
    uint32_t timeout; // Timeout duration in milliseconds
    uint32_t windowsize; // Window size for block transfer
    uint8_t last_packet; // Flag indicating if last packet was sent
    struct tftp_packet packet;
    uint32_t retries; // Retransmission count
    uint32_t packet_length;
    uint32_t options_requested;
    
#define OPTIONS_TSIZE_REQUESTED 0x01
#define OPTIONS_BLKSIZE_REQUESTED 0x02
#define OPTIONS_TIMEOUT_REQUESTED 0x04
#define OPTIONS_WINDOWSIZE_REQUESTED 0x08

    DWORD last_send_tick; // Windows tick count when last packet sent
    DWORD created_at; // Windows tick count when session was created
};



extern uint16_t ipv4_id;

void handle_tftp(pcap_t *handle, const struct tftp_packet *pkt, uint32_t pkt_len);
void session_check(pcap_t *handle);
void clean_all_sessions();

#endif /* TFTP_H */