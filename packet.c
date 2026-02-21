#include "packet.h"

#include <stdio.h>
#include <sys/time.h>
#include <time.h>

static inline void handle_ipv4(pcap_t *handle, const uint8_t *pkt, uint32_t pkt_len);
static inline void handle_arp(pcap_t *handle, const struct arp_packet *arp_packet, uint32_t pkt_len);
static inline void send_arp_reply(pcap_t *handle, const struct arp_packet *arp_pkt);
static inline void send_icmp_reply(pcap_t *handle, const struct icmp_packet *icmp_pkt, uint32_t pkt_len);

extern void handle_tftp(pcap_t *handle, const struct tftp_packet *pkt, uint32_t pkt_len);
extern uint16_t ipv4_id;

timer_t processing_timer; // only used to measure performance

void timer_init(timer_t *timer)
{
    QueryPerformanceFrequency(&timer->frequency);
}

void timer_start(timer_t *timer)
{
    QueryPerformanceCounter(&timer->start);
}

uint64_t timer_elapsed_us(timer_t *timer)
{
    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    return (uint64_t)(end.QuadPart - timer->start.QuadPart);
}

void packet_handler(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *pkt)
{
    pcap_t *handle = (pcap_t *)user;
    const struct eth_base *eth_b = (const struct eth_base *)pkt;
    struct eth_header *eth;
    uint8_t needs_to_free = FALSE;
    size_t pkt_len = 0;

    timer_start(&processing_timer);

    if (pkthdr->caplen < sizeof(struct eth_header))
        goto cleanup;

    /* 
     * This program is made to handle TFTP packets with VLAN,
     * If the received packet is a VLAN packet, we continue as is.
     * But if the packet is normal packet, it is converted into a
     * VLAN packet with VLAN TCI to be all 1. When sending packet,
     * If TCI is all 1, we again similarly remove the VLAN portion
     * of the packet to make it normal ethernet packet. This will
     * not interfere with VLAN packet because TCI all 1 is invalid.
     */
    if (eth_b->ethertype == htons(ETHERTYPE_VLAN))
    {
        eth = (struct eth_header *)pkt;
        pkt_len = pkthdr->caplen;
        needs_to_free = FALSE;
    }
    else
    {
        pkt_len = pkthdr->caplen + 4; // +4 for VLAN header
        eth = (struct eth_header *)malloc(pkt_len);
        if (eth == NULL)
            return;
        memcpy((void *)eth->data, eth_b->data, pkthdr->caplen - sizeof(struct eth_base));
        needs_to_free = TRUE;

        // Fill VLAN header
        memcpy((void *)eth->dest_mac, eth_b->dest_mac, sizeof(eth->dest_mac));
        memcpy((void *)eth->src_mac, eth_b->src_mac, sizeof(eth->src_mac));
        eth->vlan_tpid = htons(ETHERTYPE_VLAN);
        eth->vlan_tci = INVALID_VLAN_TCI; // Untagged
        eth->ethertype = eth_b->ethertype;
    }

    if (!COMPARE_MAC(eth->dest_mac, MY_MAC) && !IS_BROADCAST_MAC(eth->dest_mac))
        goto cleanup;

    if (ntohs(eth->vlan_tpid) != ETHERTYPE_VLAN)
        goto cleanup;

    debug("\n"); // debug("\nReceived ");

    switch (ntohs(eth->ethertype))
    {
    case ETHERTYPE_IPV4:
        handle_ipv4(handle, (const uint8_t *)eth, pkt_len);
        break;

    case ETHERTYPE_ARP:
#ifndef SPOOF_NON_VLAN
        if (eth->vlan_tci == INVALID_VLAN_TCI) // Skip non VLAN ARP
        {
            debug("%s: < ARP\n", time_str());
            break;
        }
#endif
        handle_arp(handle, (const struct arp_packet *)eth, pkt_len);
        break;

    default:
        debug(" Unknown packet, Ethertype: %x\n", ntohs(eth->ethertype));
        break;
    }

cleanup:
    if (needs_to_free != FALSE && eth != NULL)
        free(eth);
    eth = NULL;
    return;
}

static inline void handle_ipv4(pcap_t *handle, const uint8_t *pkt, uint32_t pkt_len)
{
    if (pkt_len < sizeof(struct ipv4_packet))
    {
        debug("%s: < IP: too short\n", time_str());
        return;
    }

    const struct ipv4_packet *ipv4_pkt = (const struct ipv4_packet *)pkt;

    if (ntohl(ipv4_pkt->ip.dest_addr) != MY_IP)
    {
        debug("%s: < IP: not mine\n", time_str());
        return;
    }

    if (ipv4_pkt->ip.version_ihl != 0x45) // IPv4 with no options
    {
        debug("%s: < IP: not supported\n", time_str());
        return;
    }

    if (ntohs(ipv4_pkt->ip.total_length) + sizeof(struct eth_header) > pkt_len)
    {
        debug("%s: < IP: length mismatch\n", time_str());
        return;
    } else {
        pkt_len = ntohs(ipv4_pkt->ip.total_length) + sizeof(struct eth_header);
    }

    if (ipv4_pkt->ip.flags_offset & htons(0x3FFF))
    {
        debug("%s: < IP: fragmented\n", time_str());
        return;
    }

    if (ipv4_pkt->ip.ttl == 0)
    {
        debug("%s: < IP: ttl expired\n", time_str());
        return;
    }

#ifdef VALIDATE_CHECKSUM
    // If checksum field is non-zero, validate it.
    if (ipv4_pkt->ip.checksum != 0 && ipv4_checksum(&ipv4_pkt->ip, sizeof(ipv4_pkt->ip)) != 0)
    {
#ifdef DEBUG
        debug("%s: < IP: checksum failed\n", time_str());
        print_ipv4(&ipv4_pkt->ip);
#endif
        return;
    }
#endif

    if (ipv4_pkt->ip.protocol == IPV4_PROTOCOL_UDP)
    {
        const struct tftp_packet *packet = (const struct tftp_packet *)pkt;

        if (pkt_len < sizeof(struct udp_packet) + 4)
        {
            debug("%s: < UDP: too short\n", time_str());
            return;
        }

        if (ntohs(packet->udp.len) + sizeof(struct ipv4_packet) > pkt_len)
        {
            debug("%s: < UDP: length mismatch\n", time_str());
            return;
        }

#ifdef VALIDATE_CHECKSUM
        if (packet->udp.checksum != 0 && udp_checksum(&ipv4_pkt->ip, &packet->udp) != 0)
        {
            debug("%s: < UDP: checksum mismatch\n", time_str());
            return;
        }
#endif

        // debug("  Src: %s:%u\n", inet_ntoa(*(const struct in_addr *)&packet->ip.src_addr), ntohs(packet->udp.source));
        // debug("  Dst: %s:%u\n", inet_ntoa(*(const struct in_addr *)&packet->ip.dest_addr), ntohs(packet->udp.dest));
        
        // debug("%s: < UDP: %s\n", time_str(), inet_ntoa(*(const struct in_addr *)&ipv4_pkt->ip.src_addr));

        handle_tftp(handle, packet, pkt_len);
    }
    else if (ipv4_pkt->ip.protocol == IPV4_PROTOCOL_ICMP)
    {
        const struct icmp_packet *icmp_pkt = (const struct icmp_packet *)pkt;
#ifndef SPOOF_NON_VLAN
        if (icmp_pkt->eth.vlan_tci == INVALID_VLAN_TCI)
        {
            debug("%s: < ICMP: non vlan\n", time_str());
            return;
        }
#endif

        if (pkt_len < sizeof(struct icmp_packet))
        {
            debug("%s: < ICMP: too short\n", time_str());
            return;
        }

        if (icmp_pkt->icmp.type != ICMP_ECHO_REQUEST)
        {
            debug("%s: < ICMP: not req\n", time_str());
            return;
        }

        if (icmp_pkt->icmp.code != 0)
        {
            debug("%s: < ICMP: code mismatch\n", time_str());
            return;
        }

#ifdef VALIDATE_CHECKSUM
        if (icmp_pkt->icmp.checksum != 0 && ipv4_checksum(&icmp_pkt->icmp, pkt_len - sizeof(struct ipv4_packet)) != 0)
        {
#ifdef DEBUG
            debug("%s: < ICMP: checksum mismatch\n", time_str());
            print_raw_data((const uint8_t *)&icmp_pkt->icmp, pkt_len - sizeof(struct ipv4_packet));
#endif
            return;
        }
#endif

        printf("%s: < ICMP: %s\n", time_str(), inet_ntoa(*(const struct in_addr *)&icmp_pkt->ip.src_addr));

        send_icmp_reply(handle, icmp_pkt, pkt_len);
    }
    else
    {
        debug("%s: < IP: unknown protocol\n", time_str());
    }

    return;
}

/**
 * Send packet via pcap, handling VLAN header as needed.
 * If the packet has VLAN TCI set to INVALID_VLAN_TCI (all 1s), the 
 * VLAN header is removed before sending. For optimization, if the 
 * packet already starts with 0xFFFFFFFF, it is assumed the VLAN 
 * header is already removed.
 */
static inline int send_via_pcap(pcap_t *handle, struct eth_header *eth, int pkt_len)
{
    int rc = 0;

    uint32_t *pkt = (uint32_t *)eth;

#if 0
    // Print Packet Content
    size_t i = 0;
    while (i < pkt_len && i < 64)
    {
        printf("%02X ", ((u_char *)pkt)[i++]);
        if (i % 16 == 0)
            printf("\n");
    }
    printf("\n---\n");
#endif

    // Check if VLAN header needs to be removed
    if (pkt[0] == (uint32_t)-1) 
    {
        // Already removed, move pointer forward by 4 bytes
        pkt++; 
        pkt_len -= 4;
    }
    else if (eth->vlan_tci == INVALID_VLAN_TCI)
    {
        // Untagged, need to remove VLAN header
        // memmove(pkt + 1, pkt, sizeof(struct eth_base));
        pkt[3] = pkt[2];
        pkt[2] = pkt[1];
        pkt[1] = pkt[0];
        pkt[0] = (uint32_t)-1;
        pkt++;
        pkt_len -= 4;
    }

    rc = pcap_sendpacket(handle, (const u_char *)pkt, pkt_len);

#if 0
    // Print Packet Content
    i = 0;
    while (i < pkt_len && i < 64)
    {
        printf("%02X ", ((u_char *)pkt)[i++]);
        if (i % 16 == 0)
            printf("\n");
    }
    printf("\n");
#endif

    return rc;
}

/**
 * Send IPv4 packet via pcap, handling IP fragmentation if needed.
 * Returns 0 on success, -1 on failure.
 */
int send_ipv4_packet(pcap_t *handle, struct ipv4_packet *packet, uint32_t packet_len)
{
    /* Effective MTU for the IP packet depends on whether VLAN is tagged */
    const int ETH_MTU = (packet->eth.vlan_tci != INVALID_VLAN_TCI) ? 1496 : 1500;
    uint16_t ip_total = ntohs(packet->ip.total_length);
    int rc = 0;

    if (ip_total + sizeof(struct eth_header) != packet_len)
    {
        debug("    Error Sending Packet: IP total length (%llu) does not match packet length (%u).\n", ip_total + sizeof(struct eth_header), packet_len);
#ifdef DEBUG
        print_ipv4(&packet->ip);
#endif
        return -1;
    }

    /* If IPv4 packet fits into MTU, send as single frame. */
    if (ip_total <= ETH_MTU)
    {
        packet->ip.checksum = 0; // Important: clear before computing
        packet->ip.checksum = ipv4_checksum((const void *)&packet->ip, sizeof(struct ipv4_header));

        if ((rc = send_via_pcap(handle, (struct eth_header *)packet, packet_len)) != 0)
        {
            debug("    Error sending the packet pcap_sendpacket[%d]\n", rc);
            return -1;
        }

        return 0;
    }

    /* Fragmentation required */
    uint16_t mtu_payload = ETH_MTU - sizeof(struct ipv4_header); /* bytes of IP payload per fragment */
    uint32_t remaining = ip_total - sizeof(struct ipv4_header);
    uint32_t offset_bytes = 0;
    struct ipv4_packet *packet_fragment = NULL;

    packet_fragment = (struct ipv4_packet *)malloc(sizeof(struct ipv4_packet) + mtu_payload);
    if (packet_fragment == NULL)
    {
        debug("    Error: out of memory for fragmentation\n");
        return -1;
    }


    /* Use same IP id for all fragments (already set on session->packet.ip.id) */
    while (remaining > 0)
    {
        uint32_t frag_payload = remaining;
        int more_fragments = 0;

        if (frag_payload > mtu_payload)
        {
            /* non-last fragment: must be multiple of 8 bytes */
            frag_payload = mtu_payload;
            /* reduce to multiple of 8 */
            frag_payload -= (frag_payload % 8);
            if (frag_payload == 0)
            {
                /* Cannot make progress */
                debug("    Error: MTU too small for fragmentation\n");
                free(packet_fragment);
                return -1;
            }
            more_fragments = 1;
        }

        /* Copy the Ethernet and IP header */
        memcpy(&packet_fragment->eth, &packet->eth, sizeof(struct eth_header));
        memcpy(&packet_fragment->ip, &packet->ip, sizeof(struct ipv4_header));

        /* Build IP header for this fragment */
        packet_fragment->ip.total_length = htons((uint16_t)(sizeof(struct ipv4_header) + frag_payload));
        /* Flags/offset: MF bit if more fragments, offset in 8-byte units */
        uint16_t fo = (uint16_t)((more_fragments ? 0x2000 : 0x0000) | ((offset_bytes / 8) & 0x1FFF));
        packet_fragment->ip.flags_offset = htons(fo);

        packet_fragment->ip.checksum = 0;
        packet_fragment->ip.checksum = ipv4_checksum(&packet_fragment->ip, sizeof(struct ipv4_header));

        /* Copy fragment payload (starts at ip_payload_ptr + offset_bytes) */
        memcpy((uint8_t *)&packet_fragment->data, (uint8_t *)&packet->data + offset_bytes, frag_payload);

        /* Send fragment */
        if ((rc = send_via_pcap(handle, (struct eth_header *)packet_fragment, sizeof(struct ipv4_packet) + frag_payload)) != 0)
        {
            debug("    Error sending fragment (offset %u, size %llu) pcap_sendpacket[%d]\n", offset_bytes, sizeof(struct ipv4_packet) + frag_payload, rc);
#ifdef DEBUG
            print_ipv4(&packet_fragment->ip);
#endif
            /* continue attempting remaining fragments? abort */
            free(packet_fragment);
            return -1;
        }
        else
        {
            debug("    Fragment Sent (offset %u, %u bytes, MF=%d)\n", offset_bytes, frag_payload, more_fragments);
        }

        offset_bytes += frag_payload;
        remaining -= frag_payload;
    } /* while fragments */

    free(packet_fragment);
    return 0;
}

static inline void handle_arp(pcap_t *handle, const struct arp_packet *arp_packet, uint32_t pkt_len)
{
    if (pkt_len < sizeof(struct arp_packet))
    {
        debug("%s: < ARP: too short\n", time_str());
        return;
    }

    if (ntohs(arp_packet->arp.opcode) != ARP_REQUEST)
    {
        debug("%s: < ARP: not req\n", time_str());
        return;
    }

    if (ntohl(arp_packet->arp.target_ip) != MY_IP)
    {
        debug("%s: < ARP: for %s\n", time_str(), inet_ntoa(*(struct in_addr *)&arp_packet->arp.target_ip));
        return;
    }

    if (ntohs(arp_packet->arp.hw_type) != ARP_HW_TYPE_ETHERNET)
    {
        debug("%s: < ARP: not eth\n", time_str());
        return;
    }

    if (ntohs(arp_packet->arp.protocol_type) != ETHERTYPE_IPV4)
    {
        debug("%s: < ARP: not IPv4\n", time_str());
        return;
    }

    if (arp_packet->arp.hw_size != 6 || arp_packet->arp.protocol_size != 4)
    {
        debug("%s: < ARP: invalid hw/proto\n", time_str());
        return;
    }

    // debug("  Src: %s\n", inet_ntoa(*(const struct in_addr *)&arp_packet->arp.sender_ip));
    // debug("  Dst: %s\n", inet_ntoa(*(const struct in_addr *)&arp_packet->arp.target_ip));
    
    printf("%s: < ARP: %s\n", time_str(), inet_ntoa(*(const struct in_addr *)&arp_packet->arp.sender_ip));

    send_arp_reply(handle, arp_packet);
}

static inline void send_arp_reply(pcap_t *handle, const struct arp_packet *arp_req)
{
    struct arp_packet arp_reply = {0};

    // Ethernet Headers
    memcpy(arp_reply.eth.dest_mac, arp_req->eth.src_mac, sizeof(arp_reply.eth.dest_mac));
    memcpy(arp_reply.eth.src_mac, MY_MAC, sizeof(arp_reply.eth.src_mac));
    arp_reply.eth.vlan_tpid = htons(ETHERTYPE_VLAN);
    arp_reply.eth.vlan_tci = arp_req->eth.vlan_tci;
    arp_reply.eth.ethertype = htons(ETHERTYPE_ARP);

    // ARP Headers
    arp_reply.arp.hw_type = htons(ARP_HW_TYPE_ETHERNET);
    arp_reply.arp.protocol_type = htons(ETHERTYPE_IPV4);
    arp_reply.arp.hw_size = sizeof(arp_reply.arp.sender_mac);      // MAC size
    arp_reply.arp.protocol_size = sizeof(arp_reply.arp.sender_ip); // IPv4 size
    arp_reply.arp.opcode = htons(ARP_REPLY);
    memcpy(arp_reply.arp.sender_mac, MY_MAC, sizeof(arp_reply.arp.sender_mac));
    arp_reply.arp.sender_ip = arp_req->arp.target_ip;
    memcpy(arp_reply.arp.target_mac, arp_req->arp.sender_mac, sizeof(arp_reply.arp.target_mac));
    arp_reply.arp.target_ip = arp_req->arp.sender_ip;

#if 0
    printf("  Sending ARP Reply to ");
    print_mac(arp_req->eth.src_mac);
#else
    printf("%s: > ARP: %s\n\n", time_str(), inet_ntoa(*(const struct in_addr *)&arp_reply.arp.target_ip));
#endif

    if (send_via_pcap(handle, (struct eth_header *)&arp_reply, sizeof(arp_reply)) != 0)
    {
        fprintf(stderr, "  Error sending ARP reply: %s\n", pcap_geterr(handle));
    }

    return;
}

static inline void send_icmp_reply(pcap_t *handle, const struct icmp_packet *icmp_pkt, uint32_t pkt_len)
{
    struct icmp_packet *icmp_reply = NULL;
    size_t icmp_data_len = pkt_len - sizeof(struct icmp_packet);

    if (icmp_data_len > ICMP_MAX_DATA)
    {
        debug("%s: > ICMP: data too big\n", time_str());
        return;
    }

    /* Build the reply in icmp_reply directly (no temporary buffer). */
    icmp_reply = (struct icmp_packet *)malloc(pkt_len);
    if (icmp_reply == NULL)
    {
        debug("%s: > ICMP: malloc fail\n", time_str());
        fprintf(stderr, "  Memory allocation failed for ICMP reply.\n");
        return;
    }
    // Copy entire original packet, along with data
    memcpy(icmp_reply->data, icmp_pkt->data, icmp_data_len);

    // ICMP Headers
    icmp_reply->icmp.type = ICMP_ECHO_REPLY; // Echo Reply
    icmp_reply->icmp.code = 0;
    icmp_reply->icmp.checksum = 0; // Needs to be calculated
    // icmp_reply->icmp.identifier = icmp_pkt->icmp.identifier;
    // icmp_reply->icmp.sequence = icmp_pkt->icmp.sequence;

    icmp_reply->icmp.checksum = ipv4_checksum(&icmp_reply->icmp, sizeof(struct icmp_header) + icmp_data_len);

    // IP Headers
    icmp_reply->ip.version_ihl = 0x45; // Version 4
    icmp_reply->ip.tos = 0;
    icmp_reply->ip.total_length = htons(sizeof(struct ipv4_header) + sizeof(struct icmp_header) + icmp_data_len);
    icmp_reply->ip.id = htons(ipv4_id++);
    icmp_reply->ip.flags_offset = 0;
    icmp_reply->ip.ttl = 128;
    icmp_reply->ip.protocol = IPV4_PROTOCOL_ICMP;
    icmp_reply->ip.checksum = 0; // Needs to be calculated
    icmp_reply->ip.src_addr = icmp_pkt->ip.dest_addr;
    icmp_reply->ip.dest_addr = icmp_pkt->ip.src_addr;

    icmp_reply->ip.checksum = ipv4_checksum(&icmp_reply->ip, sizeof(struct ipv4_header));

    // Ethernet Headers
    memcpy(icmp_reply->eth.dest_mac, icmp_pkt->eth.src_mac, sizeof(icmp_reply->eth.dest_mac));
    memcpy(icmp_reply->eth.src_mac, MY_MAC, sizeof(icmp_reply->eth.src_mac));
    icmp_reply->eth.vlan_tpid = htons(ETHERTYPE_VLAN);
    icmp_reply->eth.vlan_tci = icmp_pkt->eth.vlan_tci;
    icmp_reply->eth.ethertype = htons(ETHERTYPE_IPV4);

    printf("%s: > ICMP: %s\n\n", time_str(), inet_ntoa(*(const struct in_addr *)&icmp_reply->ip.dest_addr));
    if (send_ipv4_packet(handle, (struct ipv4_packet *)icmp_reply, sizeof(struct icmp_packet) + icmp_data_len) != 0)
    {
        printf("    Error sending ICMP packet\n");
    }

    free(icmp_reply);
    return;
}

unsigned short ipv4_checksum(const void *buf, size_t len)
{
    unsigned long sum = 0;
    const uint16_t *data = (const uint16_t *)buf;

    // Sum all 16-bit words
    for (size_t i = 0; i < len / 2; i++)
    {
        sum += ntohs(data[i]);
    }

    // If the header length is odd (shouldn't happen for IPv4), pad with zero
    if (len & 1)
    {
        sum += ((const uint8_t *)buf)[len - 1] << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return htons(~sum);
}

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

char *get_tftp_pkt_desc(const struct tftp_packet *tftp, int use_src)
{
    static char buf[256];
    char opcode_buf[64];
    char ipbuf[INET_ADDRSTRLEN];
    const uint32_t *ip_addr = NULL;
    uint16_t port = 0;
    uint16_t vlan = 0;

    if (ntohs(tftp->eth.vlan_tpid) == ETHERTYPE_VLAN && tftp->eth.vlan_tci != INVALID_VLAN_TCI) {
        vlan = ntohs(tftp->eth.vlan_tci) & 0x0FFF;
    }

    ip_addr = use_src ? &tftp->ip.src_addr : &tftp->ip.dest_addr;
    port = use_src ? ntohs(tftp->udp.source) : ntohs(tftp->udp.dest);
    inet_ntop(AF_INET, ip_addr, ipbuf, sizeof(ipbuf));

    switch (ntohs(tftp->tftp.opcode))
    {
    case OPCODE_RRQ:
        snprintf(opcode_buf, sizeof(opcode_buf), "RRQ");
        break;

    case OPCODE_WRQ:
        snprintf(opcode_buf, sizeof(opcode_buf), "WRQ");
        break;

    case OPCODE_DATA:
        snprintf(opcode_buf, sizeof(opcode_buf), "DATA[%u]", ntohs(tftp->tftp.data.block_number));
        break;

    case OPCODE_ACK:
        snprintf(opcode_buf, sizeof(opcode_buf), "ACK[%u]", ntohs(tftp->tftp.ack.block_number));
        break;

    case OPCODE_ERROR:
        snprintf(opcode_buf, sizeof(opcode_buf), "ERR[%u]", ntohs(tftp->tftp.error.error_code));
        break;

    case OPCODE_OACK:
        snprintf(opcode_buf, sizeof(opcode_buf), "OACK");
        break;

    default:
        snprintf(opcode_buf, sizeof(opcode_buf), "UNK");
        break;
    }

    if (vlan)
        snprintf(buf, sizeof(buf), "[v%u]%s:%u %s", vlan, ipbuf, port, opcode_buf);
    else
        snprintf(buf, sizeof(buf), "%s:%u %s", ipbuf, port, opcode_buf);

    return buf;
}

char *time_str()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    static char buf[128];

#if 0
    snprintf(buf, sizeof(buf), "%04d/%02d/%02d %02d:%02d:%02d.%03d", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
#else
    snprintf(buf, sizeof(buf), "%02u:%02u:%02u.%03u",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
#endif
    return buf;
}

void print_mac(const uint8_t *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ipv4(const struct ipv4_header *hdr)
{
    printf("    IP.version_ihl: 0x%02X\n", hdr->version_ihl);
    printf("    IP.tos: 0x%02X\n", hdr->tos);
    printf("    IP.total_length: %u\n", ntohs(hdr->total_length));
    printf("    IP.id: %u\n", ntohs(hdr->id));
    printf("    IP.flags_offset: 0x%04X\n", ntohs(hdr->flags_offset));
    printf("    IP.ttl: %u\n", hdr->ttl);
    printf("    IP.protocol: %u\n", hdr->protocol);
    printf("    IP.checksum: 0x%04X\n", ntohs(hdr->checksum));
    struct in_addr src_addr;
    src_addr.s_addr = hdr->src_addr;
    printf("    IP.src_addr: %s\n", inet_ntoa(src_addr));
    struct in_addr dest_addr;
    dest_addr.s_addr = hdr->dest_addr;
    printf("    IP.dest_addr: %s\n", inet_ntoa(dest_addr));
}

void print_udp(const struct udp_header *hdr)
{
    printf("    UDP.source: %u\n", ntohs(hdr->source));
    printf("    UDP.dest: %u\n", ntohs(hdr->dest));
    printf("    UDP.len: %u\n", ntohs(hdr->len));
    printf("    UDP.checksum: 0x%04X\n", ntohs(hdr->checksum));
}

void print_raw_data(const uint8_t *data, size_t len)
{
    size_t i, j;
    const size_t BREAK_AFTER = 256;
    const size_t PER_ROW = 16;

    if (len > BREAK_AFTER) 
    {
        print_raw_data(data, BREAK_AFTER);
        i = BREAK_AFTER * (len / BREAK_AFTER);
        if (i == len) i -= BREAK_AFTER;
        printf("    ");
        for (j = 0; j < PER_ROW; j++) printf("----");
        printf("---\n");
    } else i = 0;

    for (; i < len; i += PER_ROW)
    {
        /* Hex part */
        printf("    ");
        for (j = 0; j < PER_ROW; j++)
        {
            if (i + j < len)
                printf("%02X ", data[i + j]);
            else
                printf("   "); /* padding for last line */
        }

        /* ASCII part */
        printf(" |");
        for (j = 0; j < PER_ROW && i + j < len; j++)
        {
            uint8_t c = data[i + j];
            printf("%c", (c >= 0x20 && c <= 0x7E) ? c : '.');
        }
        printf("|\n");
    }
}
