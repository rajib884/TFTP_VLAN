#include "packet.h"

#include <stdio.h>
#include <sys/time.h>
#include <time.h>

void packet_handler(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *pkt)
{
    pcap_t *handle = (pcap_t *)user;
    struct eth_header *eth = (struct eth_header *)pkt;

    if (pkthdr->caplen < sizeof(struct eth_header))
        return;

    if (!COMPARE_MAC(eth->dest_mac, MY_MAC) && !IS_BROADCAST_MAC(eth->dest_mac))
        return;
#ifdef USE_VLAN
    if (ntohs(eth->vlan_tpid) != ETHERTYPE_VLAN)
        return;
#endif

    struct timeval tv;
    gettimeofday(&tv, NULL);

    // Convert to local time
    time_t sec = tv.tv_sec;
    struct tm* tm_info = localtime(&sec);

    char buffer[64];
    strftime(buffer, sizeof(buffer), "%H:%M:%S", tm_info);

    debug("\nCurrent time: %s.%06ld\n", buffer, tv.tv_usec);

    printf("Received ");
        
    switch (ntohs(eth->ethertype))
    {
    case ETHERTYPE_IPV4:
        printf("IPv4 Packet\n");

        if (pkthdr->caplen < sizeof(struct eth_header) + sizeof(struct ipv4_header) + sizeof(struct udp_header) + 4)
        {
            debug("  Too short for IP.\n");
            break;
        }

        struct tftp_packet *packet = (struct tftp_packet *)pkt;

        if (packet->ip.protocol != 17)
        {
            debug("  Not UDP.\n");
            break;
        }

        if (ntohl(packet->ip.dest_addr) != MY_IP)
        {
            debug("  Not my IP.\n");
            break;
        }

        if ((packet->ip.version_ihl & 0x0F) != 5)
        {
            debug("  Not supported.\n");
            break;
        }

        debug("  Src: %s:%u\n", inet_ntoa(*(struct in_addr *)&packet->ip.src_addr), ntohs(packet->udp.source));
        debug("  Dst: %s:%u\n", inet_ntoa(*(struct in_addr *)&packet->ip.dest_addr), ntohs(packet->udp.dest));

        handle_tftp(handle, packet, pkthdr->caplen);

        break;

    case ETHERTYPE_ARP:
        printf("ARP Request\n");

        if (pkthdr->caplen < sizeof(struct eth_header) + sizeof(struct arp_packet))
        {
            debug("  Too short for ARP.\n");
            break;
        }

        struct arp_packet *arp_req = (struct arp_packet *)(pkt + sizeof(struct eth_header));

        if (ntohs(arp_req->opcode) != ARP_REQUEST)
        {
            debug("  OPCODE Mismatch.\n");
            break;
        }

        if (ntohl(arp_req->target_ip) != MY_IP)
        {
            debug("  Target (%s) is not my IP.\n", inet_ntoa(*(struct in_addr *)&arp_req->target_ip));
            break;
        }

        
        debug("  Src: %s\n", inet_ntoa(*(struct in_addr *)&arp_req->sender_ip));
        debug("  Dst: %s\n", inet_ntoa(*(struct in_addr *)&arp_req->target_ip));

        send_arp_reply(handle, pkt, eth, arp_req);
        break;

    default:
        printf(" Unknown packet, Ethertype: %x\n", ntohs(eth->ethertype));
        break;
    }
}


void send_arp_reply(pcap_t *handle, const uint8_t *pkt, struct eth_header *eth, struct arp_packet *arp_req)
{
    uint8_t arp_reply[64] = {0};

    struct eth_header *reply_eth = (struct eth_header *)arp_reply;
    struct arp_packet *reply_arp = (struct arp_packet *)(arp_reply + sizeof(struct eth_header));

    memcpy(reply_eth->dest_mac, eth->src_mac, 6);
    memcpy(reply_eth->src_mac, MY_MAC, 6);
#ifdef USE_VLAN
    reply_eth->vlan_tpid = htons(ETHERTYPE_VLAN);
    reply_eth->vlan_tci = eth->vlan_tci;
#endif
    reply_eth->ethertype = htons(ETHERTYPE_ARP);

    reply_arp->hw_type = htons(1);
    reply_arp->protocol_type = htons(0x0800);
    reply_arp->hw_size = 6;
    reply_arp->protocol_size = 4;
    reply_arp->opcode = htons(ARP_REPLY);
    memcpy(reply_arp->sender_mac, MY_MAC, 6);
    reply_arp->sender_ip = arp_req->target_ip;
    memcpy(reply_arp->target_mac, arp_req->sender_mac, 6);
    reply_arp->target_ip = arp_req->sender_ip;

    printf("  Sending ARP Reply to ");
    print_mac(eth->src_mac);

    // for (i = 0; i < 64; i++){
    //     if (i % 8 == 0) printf("\n");
    //     printf("%02x ", arp_reply[i]);
    // }
    // printf("\n");

    if (pcap_sendpacket(handle, arp_reply, sizeof(arp_reply)) != 0)
    {
        fprintf(stderr, "  Error sending ARP reply: %s\n", pcap_geterr(handle));
    }
}


unsigned short ipv4_checksum(const void *buf, size_t len) {
    unsigned long sum = 0;
    const uint16_t *data = (const uint16_t *)buf;

    // Sum all 16-bit words
    for (size_t i = 0; i < len / 2; i++) {
        sum += ntohs(data[i]);
    }

    // If the header length is odd (shouldn't happen for IPv4), pad with zero
    if (len & 1) {
        sum += ((const uint8_t *)buf)[len - 1] << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return htons(~sum);
}


// Compute UDP checksum using the IPv4 pseudo-header.
// The expected checksum (e.g., Wireshark shows 0x28d7) will be produced.
unsigned short udp_checksum(const struct ipv4_header *ip, const struct udp_header *udp)
{
    // Get UDP length in host order
    uint16_t udp_len = ntohs(udp->len);
    unsigned long sum = 0;

    // Build pseudo header.
    // Convert source and destination IP addresses to host order.
    uint32_t src = ntohl(ip->src_addr);
    uint32_t dst = ntohl(ip->dest_addr);
    sum += (src >> 16) & 0xFFFF;
    sum += src & 0xFFFF;
    sum += (dst >> 16) & 0xFFFF;
    sum += dst & 0xFFFF;

    // Add protocol and UDP length.
    // The pseudo header includes a zero byte and then the protocol.
    // Since the first byte is zero, the 16-bit word is simply the protocol value.
    sum += (uint16_t)ip->protocol;
    sum += udp_len;

    // Now add the UDP header and payload.
    // The UDP header and payload are in network byte order, so convert each 16-bit word.
    const uint16_t *ptr = (const uint16_t *)udp;
    for (int i = 0; i < udp_len / 2; i++)
    {
        sum += ntohs(ptr[i]);
    }
    // If there's an odd byte, pad with zero on the right.
    if (udp_len & 1)
    {
        sum += ((uint16_t)((const uint8_t *)udp)[udp_len - 1]) << 8;
    }

    // Fold 32-bit sum to 16 bits and take one's complement.
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return htons(~sum);
}


void print_mac(const uint8_t *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
