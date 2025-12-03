#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <pcap.h>

#define MAX_BLOCK_SIZE 65535 // Maximum UDP block size
#define MIN_BLOCK_SIZE 8     // Minimum UDP block size
#define DEFAULT_BLOCK_SIZE 512 // Default UDP block size

#define MAX_WINDOWSIZE 65535 // Maximum window size
#define MIN_WINDOWSIZE 1   // Minimum window size
#define DEFAULT_WINDOWSIZE 1   // Default window size

#define MAX_TIMEOUT 60000 // Maximum timeout in milliseconds
#define MIN_TIMEOUT 1000  // Minimum timeout in milliseconds
#define DEFAULT_TIMEOUT 1000 // Default timeout in milliseconds

#define REQUEST_PORT 69 // TFTP request port
#define START_PORT 20001 // Starting port for TFTP sessions
#define MAX_SESSIONS 15 // Maximum concurrent TFTP sessions

#define MAX_FILE_SIZE_TO_PREALLOCATE (50 * 1024 * 1024) // 50 MB
#define MAX_PREALLOCATE (2 * MAX_WINDOWSIZE)

#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV4 0x0800
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002
#define ARP_HW_TYPE_ETHERNET 0x0001

#define IPV4_PROTOCOL_UDP 17
#define IPV4_PROTOCOL_ICMP 1

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0
#define ICMP_MAX_DATA     5000

#define COMPARE_MAC(mac1, mac2) \
    ((mac1[0] == mac2[0]) &&    \
     (mac1[1] == mac2[1]) &&    \
     (mac1[2] == mac2[2]) &&    \
     (mac1[3] == mac2[3]) &&    \
     (mac1[4] == mac2[4]) &&    \
     (mac1[5] == mac2[5]))

#define IS_BROADCAST_MAC(mac1) \
    ((mac1[0] == 0xff) &&      \
     (mac1[1] == 0xff) &&      \
     (mac1[2] == 0xff) &&      \
     (mac1[3] == 0xff) &&      \
     (mac1[4] == 0xff) &&      \
     (mac1[5] == 0xff))


/* tftp opcode mnemonic */
enum opcode
{
    OPCODE_RRQ = 1,
    OPCODE_WRQ,
    OPCODE_DATA,
    OPCODE_ACK,
    OPCODE_ERROR,
    OPCODE_OACK
};


#pragma pack(1)
struct eth_base
{
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
    uint8_t data[];
};

struct eth_header
{
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
// #ifdef USE_VLAN
    uint16_t vlan_tpid;
    uint16_t vlan_tci;
// #endif
    uint16_t ethertype;
    uint8_t data[];
};

struct eth_mover
{
    uint32_t padding;
    struct eth_base eth;
    uint8_t data[];
};

struct arp_header
{
    uint16_t hw_type;
    uint16_t protocol_type;
    uint8_t hw_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
};

struct ipv4_header
{
    uint8_t version_ihl;   // Version (4 bits) and IHL (4 bits)
    uint8_t tos;           // Type of Service  ??
    uint16_t total_length; // Total length (header + data)
    uint16_t id;           // Identification
    uint16_t flags_offset; // Flags (3 bits) and Fragment Offset (13 bits)
    uint8_t ttl;           // Time To Live
    uint8_t protocol;      // Protocol (TCP=6, UDP=17, ICMP=1, etc.)
    uint16_t checksum;     // Header checksum
    uint32_t src_addr;     // Source IP address
    uint32_t dest_addr;    // Destination IP address
    uint8_t data[];        // Payload
};

struct icmp_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    // uint16_t identifier;
    // uint16_t sequence;
    uint8_t data[];
};

struct udp_header
{
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t checksum;
};

typedef union
{
    uint16_t opcode;

    struct
    {
        uint16_t opcode; /* RRQ or WRQ */
        uint8_t filename_and_mode[MAX_BLOCK_SIZE + 2];
    } request;

    struct
    {
        uint16_t opcode; /* DATA */
        uint16_t block_number;
        uint8_t data[MAX_BLOCK_SIZE];
    } data;

    struct
    {
        uint16_t opcode; /* ACK */
        uint16_t block_number;
    } ack;

    struct
    {
        uint16_t opcode; /* ERROR */
        uint16_t error_code;
        uint8_t error_string[MAX_BLOCK_SIZE];
    } error;
    
    struct
    {
        uint16_t opcode; /* OACK */
        uint8_t options[MAX_BLOCK_SIZE + 2];
    } oack;

} tftp_message;

struct arp_packet
{
    struct eth_header eth;
    struct arp_header arp;
};

struct ipv4_packet
{
    struct eth_header eth;
    struct ipv4_header ip;
    uint8_t data[];
};

struct icmp_packet
{
    struct eth_header eth;
    struct ipv4_header ip;
    struct icmp_header icmp;
    uint8_t data[];
};

struct udp_packet
{
    struct eth_header eth;
    struct ipv4_header ip;
    struct udp_header udp;
    uint8_t data[];
};

struct tftp_packet
{
    struct eth_header eth;
    struct ipv4_header ip;
    struct udp_header udp;
    tftp_message tftp;
};
#pragma pack(0)

extern uint8_t MY_MAC[6];
extern uint32_t MY_IP;

#ifdef DEBUG
#include <stdio.h>
#define debug(...) printf(__VA_ARGS__)
#else
#define debug(...) ((void)0)
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef MEM_ERROR
#define MEM_ERROR -1
#endif

typedef struct {
    LARGE_INTEGER start;
    LARGE_INTEGER frequency;
} timer_t;

extern timer_t processing_timer;

void timer_start(timer_t* timer);
uint64_t timer_elapsed_us(timer_t* timer);
void timer_init(timer_t* timer);

void print_mac(const uint8_t *mac);
void print_ipv4(const struct ipv4_header *hdr);
void print_udp(const struct udp_header *hdr);
void print_raw_data(const uint8_t *data, size_t len);

unsigned short ipv4_checksum(const void *buf, size_t len);
unsigned short udp_checksum(const struct ipv4_header *ip, const struct udp_header *udp);
void packet_handler(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *pkt);
int send_ipv4_packet(pcap_t *handle, struct ipv4_packet *packet, uint32_t packet_len);


#endif /* PACKET_H */