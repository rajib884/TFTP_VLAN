#include "tftp.h"

struct tftp_session sessions[MAX_SESSIONS] = {0};

void close_session(struct tftp_session *session);

// Helper: parse RRQ options (returns 1 if tsize requested, sets tsize_ptr to option buffer)
static int parse_rrq_options(const uint8_t *buf, size_t maxlen, struct tftp_session *session)
{
    size_t i = 0;

    session->options_requested = 0;
    
    session->block_size = DEFAULT_BLOCK_SIZE; // Default block size
    session->block_number = 0;
    session->ack_received = 0;
    session->last_packet = 0;
    session->timeout = DEFAULT_TIMEOUT; // Default timeout
    session->windowsize = DEFAULT_WINDOWSIZE; // Default windowsize

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
        debug("Parsing option: %s\n", (const char *)&buf[i]);

        if (strcasecmp((const char *)&buf[i], "tsize") == 0)
        {
            session->options_requested |= OPTIONS_TSIZE_REQUESTED;

            debug("Tsize option requested.\n");

            // Move past option name
            while (i < maxlen && buf[i] != 0)
                i++;
            i++;

            // skip option value
            while (i < maxlen && buf[i] != 0)
                i++;
            i++;
        } 
        else if (strcasecmp((const char *)&buf[i], "blksize") == 0)
        {
            session->options_requested |= OPTIONS_BLKSIZE_REQUESTED;

            // Move past option name
            while (i < maxlen && buf[i] != 0)
                i++;
            i++;

            session->block_size = (uint16_t)strtol((const char *)&buf[i], NULL, 10);
            debug("Parsed blksize value: '%s' -> %d\n", &buf[i], session->block_size);

            // Move past option value
            while (i < maxlen && buf[i] != 0)
                i++;
            i++;
        } 
        else if (strcasecmp((const char *)&buf[i], "timeout") == 0)
        {
            session->options_requested |= OPTIONS_TIMEOUT_REQUESTED;

            // Move past option name
            while (i < maxlen && buf[i] != 0)
                i++;
            i++;

            session->timeout = 1000*strtol((const char *)&buf[i], NULL, 10);
            debug("Parsed timeout value: '%s' -> %d\n", &buf[i], session->timeout);
            
            // Move past option value
            while (i < maxlen && buf[i] != 0)
                i++;
            i++;
        } 
        else if (strcasecmp((const char *)&buf[i], "windowsize") == 0)
        {
            session->options_requested |= OPTIONS_WINDOWSIZE_REQUESTED;

            // Move past option name
            while (i < maxlen && buf[i] != 0)
                i++;
            i++;

            session->windowsize = (uint32_t)strtol((const char *)&buf[i], NULL, 10);
            debug("Parsed windowsize value: '%s' -> %d\n", &buf[i], session->windowsize);
            
            // Move past option value
            while (i < maxlen && buf[i] != 0)
                i++;
            i++;
        } 
        else // unknown option
        {
            // skip option name
            while (i < maxlen && buf[i] != 0)
                i++;
            i++;

            debug("Parsing option value: %s\n", (const char *)&buf[i]);

            // skip option value
            while (i < maxlen && buf[i] != 0)
                i++;
            i++;
        }
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

    if (send_ipv4_packet(handle, (struct ipv4_packet *)&session->packet, session->packet_length) != 0)
    {
        printf("Session %3u: Error sending packet\n", session->session_id);
    }
    else
    {
        debug("    Packet Sent (blk %lld, %u byte)!\n", session->block_number, ntohs(session->packet.udp.len));
    }

    return;
}

static void tftp_send_error(pcap_t *handle, struct tftp_session *session)
{
    size_t oack_len = 0;
    int rc = 0;

    rc = sprintf((char *)(session->packet.tftp.error.error_string), "%s", "File not found!");
    if (rc < 0) {
        printf("    Error formatting .\n");
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
    // close_session(session); // lets retry sending error then close
}


// Helper: send OACK
static void tftp_send_oack(pcap_t *handle, struct tftp_session *session)
{
    size_t oack_len = 0;
    int rc = 0;

    if (session->options_requested & OPTIONS_TSIZE_REQUESTED){
        strcpy((char *)session->packet.tftp.oack.options, "tsize");
        oack_len += strlen("tsize") + 1;

        rc = sprintf((char *)(session->packet.tftp.oack.options + oack_len), "%ld", session->file_size);
        if (rc < 0) {
            printf("    Error formatting tsize value.\n");
            close_session(session);
        }
        oack_len += rc + 1;
    }

    // Add block size option if requested
    if (session->options_requested & OPTIONS_BLKSIZE_REQUESTED) {
        strcpy((char *)(session->packet.tftp.oack.options + oack_len), "blksize");
        oack_len += strlen("blksize") + 1;

        rc = sprintf((char *)(session->packet.tftp.oack.options + oack_len), "%d", session->block_size);
        if (rc < 0) {
            printf("    Error formatting blksize value.\n");
            close_session(session);
        }
        oack_len += rc + 1;
    }

    // Add timeout option if requested
    if (session->options_requested & OPTIONS_TIMEOUT_REQUESTED) {
        strcpy((char *)(session->packet.tftp.oack.options + oack_len), "timeout");
        oack_len += strlen("timeout") + 1;

        rc = sprintf((char *)(session->packet.tftp.oack.options + oack_len), "%d", session->timeout / 1000);
        if (rc < 0) {
            printf("    Error formatting timeout value.\n");
            close_session(session);
        }
        oack_len += rc + 1;
    }

    // Add windowsize option if requested
    if (session->options_requested & OPTIONS_WINDOWSIZE_REQUESTED) {
        strcpy((char *)(session->packet.tftp.oack.options + oack_len), "windowsize");
        oack_len += strlen("windowsize") + 1;

        rc = sprintf((char *)(session->packet.tftp.oack.options + oack_len), "%d", session->windowsize);
        if (rc < 0) {
            printf("    Error formatting timeout value.\n");
            close_session(session);
        }
        oack_len += rc + 1;
    }

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

    const int MAX_RETRIES = 5;

    for (int i = 0; i < MAX_SESSIONS; ++i) {
        struct tftp_session *s = &sessions[i];
        if (s->in_use) {
            if (s->last_send_tick && (now - s->last_send_tick > s->timeout)) {
                if (s->retries < MAX_RETRIES) {
                    debug("Session %3u: Retry block %lld (retry %u/%u)\n", s->session_id, s->block_number, s->retries, MAX_RETRIES);
                    tftp_send_packet(handle, s);
                    s->last_send_tick = now;
                    s->retries++;
                } else {
                    // printf("Session %u closed after %d retries\n", s->session_id, MAX_RETRIES, s->retries);
                    close_session(s);
                }
            }
        }
    }
}

void close_session(struct tftp_session *session)
{
    uint32_t session_id, success;
    DWORD duration_ms;
    double duration_s;
    double transferred_mb;

    if (session == NULL) {
        return;
    }

    session_id = session->session_id;
    success = session->last_packet;
    duration_ms = GetTickCount() - session->created_at;
    duration_s = duration_ms / 1000.0;
    transferred_mb = session->file_size / (1024.0 * 1024.0);

    session->in_use = 0;
    if (session->fd) {
        fclose(session->fd);
        session->fd = NULL;
    }

    memset(session, 0, sizeof(*session));

    if (success)
    {
        printf("Session %3u: Complete (%.2f MB/s)\n", session_id, transferred_mb / duration_s);
        // printf("    Transferred %.2f MB in %.2f s (%.2f MB/s)\n", transferred_mb, duration_s, transferred_mb / duration_s);
    }
    else
    {
        printf("Session %3u: Terminated\n", session_id);
    }

    return;
}

void clean_all_sessions()
{
    for (int i = 0; i < MAX_SESSIONS; ++i) {
        struct tftp_session *s = &sessions[i];
        if (s->in_use) {
            close_session(s);
        }
    }
}

struct tftp_session *create_session(const struct tftp_packet *pkt, uint32_t pkt_len){
    static uint32_t session_counter = 0;
    struct tftp_session *session = NULL;
    size_t option_len = 0;
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
                printf("  Duplicate?\n");

                // close_session(session);
                // goto recreate_session;
            } else {
                printf("  Different VLAN ignored\n");
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
        printf("  Can not create more sessions.\n");
        printf("    Running sessions:\n");
        for (i = 0; i < MAX_SESSIONS; i++) {
            struct tftp_session *s = &sessions[i];
            if (s->in_use) {
                printf("      Session ID: %u, Client IP: %s, Client Port: %u, File: %s\n",
                    s->session_id,
                    inet_ntoa(*(struct in_addr *)&s->client_ip),
                    ntohs(s->client_port),
                    s->file_name
                );
            }
        }
        return NULL;
    }

    // create_session

    memset(session, 0, sizeof(*session));

    session->in_use = 1;
    session->session_id = ++session_counter;
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
        // printf("  Error: Requested File does not exists!\n");
        perror("  fopen()");
        // close_session(session);
        //         // tftp_send_error(s, errno, strerror(errno), session);
        // return NULL;
    }

    option_len = pkt_len - sizeof(struct eth_header) - sizeof(struct ipv4_header) - sizeof(struct udp_header) - 4;
    if(option_len > sizeof(pkt->tftp.request.filename_and_mode))
        option_len = sizeof(pkt->tftp.request.filename_and_mode);

    // Option parsing
    parse_rrq_options(
        pkt->tftp.request.filename_and_mode, 
        option_len, 
        session
    );

    if (session->block_size < MIN_BLOCK_SIZE || session->block_size > MAX_BLOCK_SIZE) {
        debug("    Invalid block size requested (%d), using default %d.\n", session->block_size, DEFAULT_BLOCK_SIZE);
        session->block_size = DEFAULT_BLOCK_SIZE;
    }

    if (session->timeout < MIN_TIMEOUT || session->timeout > MAX_TIMEOUT) {
        debug("    Invalid timeout requested (%d ms), using default %d ms.\n", session->timeout, DEFAULT_TIMEOUT);
        session->timeout = DEFAULT_TIMEOUT;
    }

    if (session->windowsize < MIN_WINDOWSIZE || session->windowsize > MAX_WINDOWSIZE) {
        debug("    Invalid windowsize requested (%d), using default %d.\n", session->windowsize, DEFAULT_WINDOWSIZE);
        session->windowsize = DEFAULT_WINDOWSIZE;
    }


    // UDP Headers
    session->packet.udp.source = session->server_port;
    session->packet.udp.dest = session->client_port;

    // IPV4 Headers
    session->packet.ip.version_ihl = 0x45; // ipv4
    session->packet.ip.tos = 0;
    session->packet.ip.flags_offset = 0;
    session->packet.ip.ttl = 128;
    session->packet.ip.protocol = IPV4_PROTOCOL_UDP;
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

    session->created_at = GetTickCount();

    return session;
}

void tftp_send_data(pcap_t *handle, struct tftp_session *session)
{
    size_t read_length = 0;

    if (session == NULL || !session->in_use) {
        printf("    Invalid session.\n");
        return;
    }
    
    session->last_send_tick = GetTickCount();

    if (session->fd == NULL){
        tftp_send_error(handle, session);
        return;
    }

    if (session->ack_received == -1) {
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
            debug("    Last packet to be sent.\n");
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

    tftp_send_packet(handle, session);

    return;
}


void handle_tftp(pcap_t *handle, const struct tftp_packet *pkt, uint32_t pkt_len)
{
    struct tftp_session *session = NULL;

    int i = 0;

    if (ntohs(pkt->udp.dest) == 69)
    {
        // new request
        switch (ntohs(pkt->tftp.opcode))
        {
        case OPCODE_RRQ:
            printf("\nTFTP Read request\n");

            session = create_session(pkt, pkt_len);
            if (session == NULL)
            {
                return;
            }

            printf("Session ID: %3u\n", session->session_id);

#ifdef USE_VLAN
            printf("  From %s:%u [VLAN:%d]\n", inet_ntoa(*(struct in_addr *)&session->client_ip), ntohs(session->client_port), ntohs(session->vlan_id));
#else
            printf("  %s:%u/%u\n", inet_ntoa(*(struct in_addr *)&session->client_ip), ntohs(session->client_port), ntohs(session->server_port));
#endif
            // printf("  Session Server Port: %u\n", ntohs(session->server_port));
            // printf("  Session Client MAC:");
            // print_mac(session->client_mac);
            // printf("  Session Client IP: %s\n", inet_ntoa(*(struct in_addr *)&session->client_ip));
            // printf("  Session Client Port: %u\n", ntohs(session->client_port));
#ifdef USE_VLAN
            // printf("  Session VLAN ID: %d\n", ntohs(session->vlan_id));
#endif
            printf("  File  : %s\n", session->file_name);
            if (session->fd != NULL){
                printf("  Size  : %0.4f %s\n",
                    (session->file_size > 1024*1024 ? (float)session->file_size/(1024*1024) : (session->file_size > 1024 ? (float)session->file_size/1024 : (float)session->file_size)),
                    (session->file_size > 1024*1024 ? "MB" : (session->file_size > 1024 ? "KB" : "Bytes")));
            }
            // printf("  Block Size: %d bytes\n", session->block_size);
            // printf("  Block Needed: %ld\n", (session->file_size / session->block_size) + 1);
            // printf("  Timeout: %d ms\n", session->timeout);

            if (session->options_requested != 0)
            {
                // Indicate OACK to be sent first
                session->ack_received = -1;

                printf("  Option:");
                if (session->options_requested & OPTIONS_TSIZE_REQUESTED)
                    printf(" tsize[%ld]", session->file_size);
                if (session->options_requested & OPTIONS_BLKSIZE_REQUESTED)
                    printf(" blksize[%d]", session->block_size);
                if (session->options_requested & OPTIONS_TIMEOUT_REQUESTED)
                    printf(" timeout[%d]", session->timeout / 1000);
                if (session->options_requested & OPTIONS_WINDOWSIZE_REQUESTED)
                    printf(" windowsize[%d]", session->windowsize);
                printf("\n");
            }

            tftp_send_data(handle, session);

            break;

        case OPCODE_WRQ:
            printf("TFTP Write request\n");
            printf("Incomplete\n");
            break;

        default:
            printf("TFTP Unknown request\n");
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
            debug("    No matching session found.\n");
            return;
        }

        switch (ntohs(pkt->tftp.opcode))
        {
        case OPCODE_ACK:
            uint32_t ack_block = ntohs(pkt->tftp.ack.block_number);
            
            ack_block += ((session->block_number) / 65536) * 65536; // Adjust for wrap-around
            
            if (ack_block <= session->ack_received)
            {
                debug("    Duplicate ACK for block %u, ignoring.\n", ack_block);
                return;
            }
            else if (ack_block > session->block_number + 1)
            {
                debug("    ACK for future block %u, ignoring.\n", ack_block);
                return;
            }

            session->ack_received = ack_block;
            session->retries = 0;

            if (session->last_packet && ack_block == session->block_number)
            {
                // Successful completion
                close_session(session);
                return;
            }

            session->last_packet = 0;
            session->block_number = session->ack_received;
            while (session->block_number < session->windowsize + session->ack_received){
                tftp_send_data(handle, session);
                session->block_number++;
                if (session->last_packet)
                    break;
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

