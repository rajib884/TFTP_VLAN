#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <pcap.h>


#define VLAN_TAG_OFFSET 12
#define ETH_TYPE_OFFSET 16
#define ARP_OFFSET 18
#define ARP_OPCODE_OFFSET 20
#define ARP_SENDER_MAC_OFFSET 22
#define ARP_SENDER_IP_OFFSET 28
#define ARP_TARGET_MAC_OFFSET 32
#define ARP_TARGET_IP_OFFSET 38

#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV4 0x0800
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002

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


struct eth_header
{
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
#ifdef USE_VLAN
    uint16_t vlan_tpid;
    uint16_t vlan_tci;
#endif
    uint16_t ethertype;
};

struct ipv4_header
{
    uint8_t version_ihl;   // Version (4 bits) and IHL (4 bits)
    uint8_t tos;           // Type of Service
    uint16_t total_length; // Total length (header + data)
    uint16_t id;           // Identification
    uint16_t flags_offset; // Flags (3 bits) and Fragment Offset (13 bits)
    uint8_t ttl;           // Time To Live
    uint8_t protocol;      // Protocol (TCP=6, UDP=17, ICMP=1, etc.)
    uint16_t checksum;     // Header checksum
    uint32_t src_addr;     // Source IP address
    uint32_t dest_addr;    // Destination IP address
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
        uint8_t filename_and_mode[514];
    } request;

    struct
    {
        uint16_t opcode; /* DATA */
        uint16_t block_number;
        uint8_t data[512];
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
        uint8_t error_string[512];
    } error;
    
    struct
    {
        uint16_t opcode; /* OACK */
        uint8_t options[514];
    } oack;

} tftp_message;


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
struct arp_packet
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


#define START_PORT 20001 // Starting port for TFTP sessions
#define MAX_SESSIONS 5 // Maximum concurrent TFTP sessions

void print_mac(const uint8_t *mac);
unsigned short ipv4_checksum(const void *buf, size_t len);
unsigned short udp_checksum(const struct ipv4_header *ip, const struct udp_header *udp);
void packet_handler(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *pkt);
void send_arp_reply(pcap_t *handle, const uint8_t *pkt, struct eth_header *eth_vlan, struct arp_packet *arp_req);


extern void handle_tftp(pcap_t *handle, struct tftp_packet *pkt, uint32_t pkt_len);

#endif /* PACKET_H */