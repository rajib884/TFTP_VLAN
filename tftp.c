#include "tftp.h"

struct tftp_session sessions[MAX_SESSIONS] = {0};

void close_session(struct tftp_session *session);

// Helper: parse RRQ options (returns 1 if tsize requested, sets tsize_ptr to option buffer)
static int parse_rrq_options(const uint8_t *buf, size_t maxlen, int *tsize_requested)
{
    *tsize_requested = 0;
    size_t i = 0;

    // skip filename and mode
    while (i < maxlen && buf[i] != 0)
        i++;
    i++; // skip null

    while (i < maxlen && buf[i] != 0)
        i++;
    i++; // skip null

    // parse options
    while (i + 1 < maxlen && buf[i] != 0)
    {
        if (strcasecmp((const char *)&buf[i], "tsize") == 0)
        {
            *tsize_requested = 1;
        }

        // skip option name
        while (i < maxlen && buf[i] != 0)
            i++;
        i++;

        // skip option value
        while (i < maxlen && buf[i] != 0)
            i++;
        i++;
    }

    return 0;
}


void tftp_send_packet(pcap_t *handle, struct tftp_session *session)
{
    if (handle == NULL) {
        printf("    Invalid handle.\n");
        return;
    }

    if (session == NULL || !session->in_use) {
        printf("    Invalid session.\n");
        return;
    }
    
    session->packet.ip.id = htons(ipv4_id++);
    
    session->packet.udp.checksum = 0; // Ensure field is zero before calculation
    session->packet.udp.checksum = udp_checksum(&session->packet.ip, &session->packet.udp);
    session->packet.ip.checksum = 0; // Important: clear before computing
    session->packet.ip.checksum = ipv4_checksum(&session->packet.ip, sizeof(struct ipv4_header));

    if (pcap_sendpacket(handle, (const u_char *)&(session->packet), session->packet_length) != 0)
    {
        printf("    Error sending the packet\n");
    } else{
        printf("    Packet Sent (blk %d, %u byte)!\n", session->block_number, ntohs(session->packet.udp.len));
    }

    return;
}

static void tftp_send_error(pcap_t *handle, struct tftp_session *session)
{
    size_t oack_len = 0;
    int rc = 0;

    rc = sprintf((char *)(session->packet.tftp.error.error_string), "%s", "File not found!");
    if (rc < 0) {
        printf("    Error formatting tsize value.\n");
        close_session(session);
    }
    
    session->packet.tftp.error.error_code = htons(1); // File Not Found

    // Fill headers
    session->packet.tftp.opcode = htons(OPCODE_ERROR);
    oack_len = 2 + 2 + rc + 1;
    session->packet.udp.len = htons(sizeof(struct udp_header) + oack_len);
    session->packet.ip.total_length = htons(sizeof(struct ipv4_header) + sizeof(struct udp_header) + oack_len);
    session->packet_length = sizeof(struct eth_header) + sizeof(struct ipv4_header) + sizeof(struct udp_header) + oack_len;

    tftp_send_packet(handle, session);
    // close_session(session);
}


// Helper: send OACK with tsize
static void tftp_send_oack(pcap_t *handle, struct tftp_session *session)
{
    size_t oack_len = 0;
    int rc = 0;

    // tsize option
    strcpy((char *)session->packet.tftp.oack.options, "tsize");
    oack_len += strlen("tsize") + 1;

    rc = sprintf((char *)(session->packet.tftp.oack.options + oack_len), "%ld", session->file_size);
    if (rc < 0) {
        printf("    Error formatting tsize value.\n");
        close_session(session);
    }
    oack_len += rc + 1;

    oack_len += 2; // opcode

    // Fill headers
    session->packet.tftp.opcode = htons(OPCODE_OACK);
    session->packet.udp.len = htons(sizeof(struct udp_header) + oack_len);
    session->packet.ip.total_length = htons(sizeof(struct ipv4_header) + sizeof(struct udp_header) + oack_len);
    session->packet_length = sizeof(struct eth_header) + sizeof(struct ipv4_header) + sizeof(struct udp_header) + oack_len;

    tftp_send_packet(handle, session);
}

void session_check(pcap_t *handle){

    // debug("Checking TFTP sessions...\n");
    
    // Check for TFTP session timeouts
    DWORD now = GetTickCount();

    const int TIMEOUT_MS = 1500; // 1.5 seconds
    const int MAX_RETRIES = 5;

    for (int i = 0; i < MAX_SESSIONS; ++i) {
        struct tftp_session *s = &sessions[i];
        if (s->in_use) {
            if (s->last_send_tick && (now - s->last_send_tick > TIMEOUT_MS)) {
                if (s->retries < MAX_RETRIES) {
                    printf("Session timeout, retransmitting block %d (retry %d)\n", s->block_number, s->retries+1);
                    tftp_send_packet(handle, s);
                    s->last_send_tick = now;
                    s->retries++;
                } else {
                    printf("Session failed after %d retries, closing.\n", MAX_RETRIES);
                    close_session(s);
                }
            }
        }
    }
}

void close_session(struct tftp_session *session)
{
    if (session == NULL) {
        return;
    }

    session->in_use = 0;
    if (session->fd) {
        fclose(session->fd);
        session->fd = NULL;
    }
    memset(session, 0, sizeof(*session));
}

struct tftp_session *create_session(struct tftp_packet *pkt){
    struct tftp_session *session = NULL;
    int i;

    for (i = 0; i < MAX_SESSIONS; i++) {
        session = &sessions[i];
        if (session->in_use 
            && session->client_ip == pkt->ip.src_addr
            && session->client_port == pkt->udp.source
        )
        {
#ifdef USE_VLAN
            if(session->vlan_id == pkt->eth.vlan_tci)
#else
            if(1) // Always true if VLAN not used
#endif
            {
                printf("    Duplicate!\n");

                close_session(session);
                goto recreate_session;
            } else {
                printf("    Different VLAN ignored\n");
                return NULL;
            }
        }
    }

    for (i = 0; i < MAX_SESSIONS; i++) {
        session = &sessions[i];
        if (!session->in_use)
            break;
    }

    if (session == NULL || session->in_use) {
        printf("    Can not create more sessions.\n");
        return NULL;
    }

recreate_session:

    memset(session, 0, sizeof(*session));

    session->in_use = 1;
    session->server_port = htons(START_PORT + i);
    memcpy(session->client_mac, pkt->eth.src_mac, 6);
    session->client_ip = pkt->ip.src_addr;
    session->client_port = pkt->udp.source;
#ifdef USE_VLAN
    session->vlan_id = pkt->eth.vlan_tci;
#endif


    strncpy(session->file_name, (const char *)pkt->tftp.request.filename_and_mode, sizeof(session->file_name));
    session->file_name[sizeof(session->file_name) - 1] = '\0';

    session->fd = fopen(session->file_name, "rb");
    if (session->fd != NULL) {
        fseek(session->fd, 0, SEEK_END);
        session->file_size = ftell(session->fd);
        fseek(session->fd, 0, SEEK_SET);
    } else {
        printf("  Error: Requested File does not exists!\n");
        perror("         server: fopen()");
        // close_session(session);
        //         // tftp_send_error(s, errno, strerror(errno), session);
        // return NULL;
    }

    // Option parsing
    parse_rrq_options(
        pkt->tftp.request.filename_and_mode, 
        sizeof(pkt->tftp.request.filename_and_mode), 
        &session->tsize_requested
    );

    session->block_number = 0;
    session->block_size = 512;
    session->last_packet = 0;

    // UDP Headers
    session->packet.udp.source = session->server_port;
    session->packet.udp.dest = session->client_port;

    // IPV4 Headers
    session->packet.ip.version_ihl = 0x45; // ipv4
    session->packet.ip.tos = 0;
    session->packet.ip.flags_offset = 0;
    session->packet.ip.ttl = 128;
    session->packet.ip.protocol = 17;
    session->packet.ip.src_addr = htonl(MY_IP);
    session->packet.ip.dest_addr = session->client_ip;

    // Ethernet Headers
    memcpy(session->packet.eth.dest_mac, session->client_mac, 6);
    memcpy(session->packet.eth.src_mac, MY_MAC, 6);
#ifdef USE_VLAN
    session->packet.eth.vlan_tpid = htons(ETHERTYPE_VLAN);
    session->packet.eth.vlan_tci = session->vlan_id;
#endif
    session->packet.eth.ethertype = htons(ETHERTYPE_IPV4);

    return session;
}

void tftp_send_data(pcap_t *handle, struct tftp_session *session)
{
    size_t read_length = 0;

    if (session == NULL || !session->in_use) {
        printf("    Invalid session.\n");
        return;
    }

    if (session->fd == NULL){
        tftp_send_error(handle, session);
        return;
    }

    if (session->block_number < 0) {
        tftp_send_oack(handle, session);
        return;
    }

    session->packet.tftp.data.opcode = htons(OPCODE_DATA);

    // Read file data
    fseek(session->fd, session->block_number * session->block_size, SEEK_SET);
    debug("    from %ld ", ftell(session->fd));
    read_length = fread(session->packet.tftp.data.data, 1, session->block_size, session->fd);
    debug("to %ld\n", ftell(session->fd));

    if (read_length < session->block_size) {
        if (feof(session->fd)) {
            session->last_packet = 1;
            printf("    Last packet to be sent.\n");
        } else if (ferror(session->fd)) {
            printf("    Error reading file.\n");
            perror("         server: fread()");
            
            close_session(session);

            return;
        }
    }

    session->packet.tftp.data.block_number = htons(session->block_number + 1);
    session->packet.udp.len = htons(sizeof(struct udp_header) + 4 + read_length);
    session->packet.ip.total_length = htons(sizeof(struct ipv4_header) + sizeof(struct udp_header) + 4 + read_length);
    session->packet_length = sizeof(struct eth_header) + sizeof(struct ipv4_header) + sizeof(struct udp_header) + 4 + read_length;
    
    session->last_send_tick = GetTickCount();

    tftp_send_packet(handle, session);

    return;
}


void handle_tftp(pcap_t *handle, struct tftp_packet *pkt, uint32_t pkt_len)
{
    struct tftp_session *session = NULL;

    int i = 0;

    if (ntohs(pkt->udp.dest) == 69)
    {
        // new request
        switch (ntohs(pkt->tftp.opcode))
        {
        case OPCODE_RRQ:
            printf("    TFTP Read request\n");
            session = create_session(pkt);
            if (session == NULL)
                return;

            printf("      Session Server Port: %u\n", ntohs(session->server_port));
            printf("      Session Client MAC:");
            print_mac(session->client_mac);
            printf("      Session Client IP: %s\n", inet_ntoa(*(struct in_addr *)&session->client_ip));
            printf("      Session Client Port: %u\n", ntohs(session->client_port));
#ifdef USE_VLAN
            printf("      Session VLAN ID: %d\n", ntohs(session->vlan_id));
#endif
            printf("      Requested File: %s\n", session->file_name);
            printf("      File Size: %ld bytes\n", session->file_size);
            printf("      Block Size: %d bytes\n", session->block_size);
            printf("      Block Needed: %ld\n", (session->file_size / session->block_size) + 1);

            if (session->tsize_requested) {
                printf("      tsize option requested\n");
                session->block_number = -1; // Indicate OACK to be sent first
            }

            tftp_send_data(handle, session);

            break;

        case OPCODE_WRQ:
            printf("    TFTP Write request\n");
            printf("    Incomplete\n");
            break;

        default:
            printf("    TFTP Unknown request\n");
            break;
        }
    }
    else
    {
        // existing session
        for (i = 0; i < MAX_SESSIONS; i++)
        {
            session = &sessions[i];
            if (session->in_use 
                && session->client_ip == pkt->ip.src_addr
                && session->client_port == pkt->udp.source 
#ifdef USE_VLAN
                && session->vlan_id == pkt->eth.vlan_tci
#endif
            )
            {
                break;
            }

            session = NULL;
        }

        if (session == NULL || !session->in_use)
        {
            printf("    No matching session found.\n");
            return;
        }

        switch (ntohs(pkt->tftp.opcode))
        {
        case OPCODE_ACK:
            debug("    TFTP ACK received for block %u\n", ntohs(pkt->tftp.ack.block_number));
            if (ntohs(pkt->tftp.ack.block_number) != session->block_number + 1)
            {
                printf("    Unexpected block number. Ignoring.\n");
                return;
            }

            session->block_number++;
            session->retries = 0;

            if (session->last_packet)
            {
                printf("    Transfer Complete, Closing session.\n");
                close_session(session);
            } else {
                tftp_send_data(handle, session);
            }

            break;

        case OPCODE_ERROR:
            printf("    TFTP ERROR received: Code %u\n", ntohs(pkt->tftp.error.error_code));
            printf("    Error Message: %s\n", pkt->tftp.error.error_string);
            close_session(session);
            break;

        default:
            printf("    TFTP Unknown opcode in existing session\n");
            break;
        }
    }

    return;
}

