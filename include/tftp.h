#ifndef TFTP_H
#define TFTP_H

#include <stdint.h>
#include <pcap.h>

#include "packet.h"
#include "queue.h"

struct tftp_session
{
    uint32_t in_use;  // Whether this session is running or not
    uint32_t session_id;  // Unique session identifier for debugging

    // Client and Server info
    uint16_t server_port;
    uint8_t client_mac[6];
    uint32_t client_ip;
    uint16_t client_port;
    uint16_t vlan_id;

    // Requested File Info
    char file_name[512];
    FILE *fd;
    long file_size;

    int64_t ack_received;  // Last acknowledged block number
    int64_t block_number;  // Current block number

    uint8_t error_occurred;  // Used to send Error Packet
    char error_text[512];
#define TFTP_ERROR_FLAG                   0xf0
#define TFTP_ERROR_UNKNOWN                (TFTP_ERROR_FLAG | 0)
#define TFTP_ERROR_FILE_NOT_FOUND         (TFTP_ERROR_FLAG | 1)
#define TFTP_ERROR_ACCESS_VIOLATION       (TFTP_ERROR_FLAG | 2)
#define TFTP_ERROR_DISK_FULL              (TFTP_ERROR_FLAG | 3)
#define TFTP_ERROR_ILLEGAL_TFTP_OPERATION (TFTP_ERROR_FLAG | 4)
#define TFTP_ERROR_UNKNOWN_TRANSFER_ID    (TFTP_ERROR_FLAG | 5)
#define TFTP_ERROR_FILE_ALREADY_EXISTS    (TFTP_ERROR_FLAG | 6)
#define TFTP_ERROR_NO_SUCH_USER           (TFTP_ERROR_FLAG | 7)

    uint8_t last_packet;  // Flag indicating if last packet was sent
    uint16_t block_size;  // Block size for data packets
    uint32_t timeout;  // Timeout duration in milliseconds
    uint32_t windowsize;  // Window size for block transfer
    
    packet_queue_t *pkts;  // Send Packet Queue
    struct udp_packet packet_header;  // Copy packet header from this

    uint32_t options_requested;
#define OPTIONS_TSIZE_REQUESTED 0x01
#define OPTIONS_BLKSIZE_REQUESTED 0x02
#define OPTIONS_TIMEOUT_REQUESTED 0x04
#define OPTIONS_WINDOWSIZE_REQUESTED 0x08

    uint32_t retries; // Retransmission count
    DWORD last_send_tick; // Windows tick count when last packet sent
    DWORD created_at; // Windows tick count when session was created
    
    // Debug
    uint64_t processing_time;
    uint64_t sent_packet_count;
};

extern uint16_t ipv4_id;

void handle_tftp(pcap_t *handle, const struct tftp_packet *pkt, uint32_t pkt_len);
void session_check(pcap_t *handle);
void clean_all_sessions();

#endif /* TFTP_H */