#include "tftp.h"

struct tftp_session sessions[MAX_SESSIONS] = {0};

void close_session(struct tftp_session *session);
static void tftp_send_error(pcap_t *handle, struct tftp_session *session);
void tftp_prepare_packets(struct tftp_session *session);
void tftp_send_packets(pcap_t *handle, struct tftp_session *session);
int tftp_prepare_oack(struct tftp_session *session);

// Helper: parse RRQ options (returns 1 if tsize requested, sets tsize_ptr to option buffer)
static int parse_rrq_options(const uint8_t *buf, size_t maxlen, struct tftp_session *session)
{
    size_t i = 0;

    session->options_requested = 0;
    
    session->block_size = DEFAULT_BLOCK_SIZE; // Default block size
    session->block_number = 0;
    session->sent_packet_count = -1;
    session->ack_received = 0;
    session->last_packet = FALSE;
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

int tftp_send_packet(pcap_t *handle, struct tftp_session *session, int dummy)
{
    const packet_t *pkt = NULL;
    struct tftp_packet *tpkt = NULL;

    if (handle == NULL) {
        printf("    Invalid handle.\n");
        return -1;
    }

    if (session == NULL || !session->in_use) {
        printf("    Invalid session.\n");
        return -1;
    }

    if(session->error_occurred){
        tftp_send_error(handle, session);
        return -1;
    }

    pkt = queue_get(session->pkts, session->block_number);
    if (pkt == NULL) {
        tftp_prepare_packets(session); // Maybe we had not prepared enough packets?
        pkt = queue_get(session->pkts, session->block_number);
        if (pkt == NULL) return -1;
    }

    tpkt = pkt->data;

    tpkt->ip.id = htons(ipv4_id++);

    tpkt->udp.checksum = 0; // Ensure field is zero before calculation
    tpkt->udp.checksum = udp_checksum(&tpkt->ip, &tpkt->udp);

    if (session->sent_packet_count != -1) {
        session->processing_time += timer_elapsed_us(&processing_timer);
        //printf("PT: %lld us\n", timer_elapsed_us(&processing_timer));
    } else {
#ifdef DEBUG
        printf("First packet sent in: %0.2f us\n", (double)timer_elapsed_us(&processing_timer) * 1000000.0 / processing_timer.frequency.QuadPart );
        print_ipv4(&((struct ipv4_packet *)pkt->data)->ip);
        print_udp(&((struct tftp_packet *)pkt->data)->udp);
        print_raw_data((const uint8_t *)&((struct tftp_packet *)pkt->data)->tftp, 10);
#endif
    }
    session->sent_packet_count += 1;


    if (send_ipv4_packet(handle, (struct ipv4_packet *)pkt->data, pkt->data_len) != 0)
    {
        printf("Session %3u: Error sending packet via pcap\n", session->session_id);

#ifdef DEBUG
        print_ipv4(&((struct ipv4_packet *)pkt->data)->ip);
        print_udp(&((struct tftp_packet *)pkt->data)->udp);
        print_raw_data((const uint8_t *)&((struct tftp_packet *)pkt->data)->tftp, 10);
#endif
        session->error_occurred = TFTP_ERROR_UNKNOWN;
        strcpy(session->error_text, "Error sending packet via pcap");
        return -1;
    }
    else
    {
        if (session->ack_received >= 0 && tpkt->udp.len != session->packet_header.udp.len) {
            session->last_packet = TRUE;
        }
        debug("    Packet Sent (blk %lld, %u byte)!\n", session->block_number, ntohs(tpkt->udp.len));
    }

    session->last_send_tick = GetTickCount();

    return 0;
}

static void tftp_send_error(pcap_t *handle, struct tftp_session *session)
{
    size_t oack_len = 0;
    int rc = 0;

    struct tftp_packet tpkt = {0};

    rc = sprintf((char *)(tpkt.tftp.error.error_string), "%s", session->error_text);
    if (rc < 0) {
        printf("    Error formatting .\n");
        close_session(session);
    }
    
    tpkt.tftp.error.error_code = htons(session->error_occurred & ~TFTP_ERROR_FLAG);
    tpkt.tftp.opcode = htons(OPCODE_ERROR);
    oack_len = 2 + 2 + rc + 1;
    tpkt.udp.len = htons(sizeof(struct udp_header) + oack_len);
    tpkt.ip.total_length = htons(sizeof(struct ipv4_header) + sizeof(struct udp_header) + oack_len);

    // tftp_send_packet(handle, session);
    send_ipv4_packet(handle, (struct ipv4_packet *)&tpkt, sizeof(struct udp_packet) + oack_len);
    // close_session(session); // lets retry sending error then close
}


// // Helper: send OACK
// static void tftp_send_oack(pcap_t *handle, struct tftp_session *session)
// {
//     size_t oack_len = 0;
//     int rc = 0;

//     if (session->options_requested & OPTIONS_TSIZE_REQUESTED){
//         strcpy((char *)session->packet.tftp.oack.options, "tsize");
//         oack_len += strlen("tsize") + 1;

//         rc = sprintf((char *)(session->packet.tftp.oack.options + oack_len), "%ld", session->file_size);
//         if (rc < 0) {
//             printf("    Error formatting tsize value.\n");
//             close_session(session);
//         }
//         oack_len += rc + 1;
//     }

//     // Add block size option if requested
//     if (session->options_requested & OPTIONS_BLKSIZE_REQUESTED) {
//         strcpy((char *)(session->packet.tftp.oack.options + oack_len), "blksize");
//         oack_len += strlen("blksize") + 1;

//         rc = sprintf((char *)(session->packet.tftp.oack.options + oack_len), "%d", session->block_size);
//         if (rc < 0) {
//             printf("    Error formatting blksize value.\n");
//             close_session(session);
//         }
//         oack_len += rc + 1;
//     }

//     // Add timeout option if requested
//     if (session->options_requested & OPTIONS_TIMEOUT_REQUESTED) {
//         strcpy((char *)(session->packet.tftp.oack.options + oack_len), "timeout");
//         oack_len += strlen("timeout") + 1;

//         rc = sprintf((char *)(session->packet.tftp.oack.options + oack_len), "%d", session->timeout / 1000);
//         if (rc < 0) {
//             printf("    Error formatting timeout value.\n");
//             close_session(session);
//         }
//         oack_len += rc + 1;
//     }

//     // Add windowsize option if requested
//     if (session->options_requested & OPTIONS_WINDOWSIZE_REQUESTED) {
//         strcpy((char *)(session->packet.tftp.oack.options + oack_len), "windowsize");
//         oack_len += strlen("windowsize") + 1;

//         rc = sprintf((char *)(session->packet.tftp.oack.options + oack_len), "%d", session->windowsize);
//         if (rc < 0) {
//             printf("    Error formatting timeout value.\n");
//             close_session(session);
//         }
//         oack_len += rc + 1;
//     }

//     oack_len += 2; // opcode

//     // Fill headers
//     session->packet.tftp.opcode = htons(OPCODE_OACK);
//     session->packet.udp.len = htons(sizeof(struct udp_header) + oack_len);
//     session->packet.ip.total_length = htons(sizeof(struct ipv4_header) + sizeof(struct udp_header) + oack_len);
//     session->packet_length = sizeof(struct udp_packet) + oack_len;

//     tftp_send_packet(handle, session);
// }

void session_check(pcap_t *handle)
{
    const int MAX_RETRIES = 5;
    static DWORD last_print_time = 0;
    DWORD now = 0;
    int print = FALSE;
    int printed = FALSE;
    struct tftp_session *s = NULL;

    now = GetTickCount();

    if (now - last_print_time > 5000) print = TRUE;

    // Check for TFTP session timeouts
    for (int i = 0; i < MAX_SESSIONS; ++i) 
    {
        s = &sessions[i];
        if (s->in_use) 
        {
            if (print)
            {
                if (!printed)
                {
                    printf("\nRunning sessions:\n");
                    printed = TRUE;
                    last_print_time = now;
                }

                printf(" [%3.0f%%] %3u. %s:%u File: %s\n",
                    (double)((s->ack_received + 1)*100)/((double)(s->file_size/s->block_size + 1)),
                    s->session_id,
                    inet_ntoa(*(struct in_addr *)&s->client_ip),
                    ntohs(s->client_port),
                    s->file_name
                );
            }

            if (now - s->last_send_tick > s->timeout)
            {
                if (s->retries < MAX_RETRIES)
                {
                    debug("  Session %3u: Retry block %lld (retry %u/%u)\n", s->session_id, s->block_number, s->retries, MAX_RETRIES);
                    tftp_send_packets(handle, s);
                    s->retries++;
                } 
                else 
                {
                    printf("  Session %3u closed after %d retries\n", s->session_id, s->retries);
                    close_session(s);
                }
            }
        }
    }
    
    if (printed) printf("\n");
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
    printf("Session %3u: avg. processing time %4f us/packet\n", 
        session_id, 
        ((double)session->processing_time / processing_timer.frequency.QuadPart) * 1000000.0 / session->sent_packet_count
    );

    session->in_use = FALSE;
    if (session->fd) {
        fclose(session->fd);
        session->fd = NULL;
    }

    if (session->file) {
        free(session->file);
        session->file = NULL;
    }

    if (session->pkts){
        queue_free(session->pkts);
        session->pkts = NULL;
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

struct tftp_session *get_session(const struct tftp_packet *pkt, uint32_t pkt_len){
    static uint32_t session_counter = 0;
    struct tftp_session *session = NULL;
    size_t option_len = 0;
    int i;

    // Find existing Session

    for (i = 0; i < MAX_SESSIONS; i++)
    {
        session = &sessions[i];
        if (session->in_use
            && session->client_ip == pkt->ip.src_addr
            && session->client_port == pkt->udp.source
            && session->server_port == pkt->udp.dest
            && COMPARE_MAC(session->client_mac, pkt->eth.src_mac)
        )
        {
            if (session->vlan_id == pkt->eth.vlan_tci)
            {
                if (ntohs(pkt->udp.dest) != REQUEST_PORT || ntohs(pkt->tftp.opcode) != OPCODE_RRQ || ntohs(pkt->tftp.opcode) != OPCODE_WRQ)
                {
                    return session;
                }
                else
                {
                    debug("  Duplicate request, ignoring.\n");
                    return NULL;
                }
            }
            else
            {
                debug("  Duplicate request from different VLAN, ignored.\n");
                return NULL;
            }
        }
    }

    if (ntohs(pkt->udp.dest) != REQUEST_PORT || (ntohs(pkt->tftp.opcode) != OPCODE_RRQ && ntohs(pkt->tftp.opcode) != OPCODE_WRQ))
    {
        debug("Not creation request\n");
        return NULL;
    }

    // not found, create_session

    for (i = 0; i < MAX_SESSIONS; i++) {
        session = &sessions[i];
        if (!session->in_use)
            break;
    }

    if (session == NULL || session->in_use) {
        printf("  Can not create more sessions\n");
        return NULL;
    }

    memset(session, 0, sizeof(*session));

    session->pkts = queue_init();
    if (!session->pkts) {
        session->error_occurred = TFTP_ERROR_UNKNOWN;
        strcpy(session->error_text, "Failed to initialize packet queue");
    }

    session->created_at = GetTickCount();
    session->in_use = TRUE;
    session->session_id = ++session_counter;
    session->server_port = htons(START_PORT + i);

    memcpy(session->client_mac, pkt->eth.src_mac, 6);
    session->client_ip = pkt->ip.src_addr;
    session->client_port = pkt->udp.source;
    session->vlan_id = pkt->eth.vlan_tci;

    strncpy(session->file_name, (const char *)pkt->tftp.request.filename_and_mode, sizeof(session->file_name));
    session->file_name[sizeof(session->file_name) - 1] = '\0';

    session->fd = fopen(session->file_name, "rb");
    if (session->fd != NULL)
    {
        fseek(session->fd, 0, SEEK_END);
        session->file_size = ftell(session->fd);
        fseek(session->fd, 0, SEEK_SET);
    }
    else
    {
        // Error: Requested File does not exists!
        // perror("  fopen()");
        session->error_occurred = TFTP_ERROR_FILE_NOT_FOUND;
        strcpy(session->error_text, "Requested File does not exists");


        // close_session(session);
        // tftp_send_error(s, errno, strerror(errno), session);
        // return NULL;
    }

    if (session->file_size < MAX_FILE_SIZE_TO_PREALLOCATE && session->fd != NULL) { // 50 mb?
        fseek(session->fd, 0, SEEK_SET);
        session->file = (uint8_t *)malloc(session->file_size);
        if (session->file != NULL)
        {
            size_t read_length = 0;
            read_length = fread(session->file, 1, session->file_size, session->fd);
            fseek(session->fd, 0, SEEK_SET);
            if (read_length != session->file_size)
            {
                printf("  Failed read file into memory.\n");
                free(session->file);
                session->file = NULL;
            } else {
                debug("  File read into memory (%ld bytes).\n", session->file_size);
                // fclose(session->fd);
                // session->fd = NULL;
            }
        }
    } else if (session->file_size != 0) {
        debug("  File too large to read into memory (%ld bytes).\n", session->file_size);
    }

    option_len = pkt_len - sizeof(struct udp_packet) - 4;
    // if(option_len > sizeof(pkt->tftp.request.filename_and_mode))
    //     option_len = sizeof(pkt->tftp.request.filename_and_mode);

    // Option parsing
    parse_rrq_options(
        pkt->tftp.request.filename_and_mode, 
        option_len, 
        session
    );

    if (session->options_requested != 0)
    {
        // Indicate OACK to be sent first
        session->ack_received = -1;
    }

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
    session->packet_header.udp.source = session->server_port;
    session->packet_header.udp.dest = session->client_port;
    session->packet_header.udp.len = htons(sizeof(struct udp_header) + 4 + session->block_size); // used to determine last packet
    session->packet_header.udp.checksum = 0;

    // IPV4 Headers
    session->packet_header.ip.version_ihl = 0x45; // ipv4
    session->packet_header.ip.tos = 0;
    session->packet_header.ip.total_length = 0;
    session->packet_header.ip.id = 0;
    session->packet_header.ip.flags_offset = 0;
    session->packet_header.ip.ttl = 128;
    session->packet_header.ip.protocol = IPV4_PROTOCOL_UDP;
    session->packet_header.ip.checksum = 0;
    session->packet_header.ip.src_addr = htonl(MY_IP);
    session->packet_header.ip.dest_addr = session->client_ip;

    // Ethernet Headers
    if (session->vlan_id == (uint16_t)-1)
    {
        struct eth_mover *mover = (struct eth_mover *)&session->packet_header;
        mover->padding = (uint32_t)-1;
        memcpy(mover->eth.dest_mac, session->client_mac, 6);
        memcpy(mover->eth.src_mac, MY_MAC, 6);
        mover->eth.ethertype = htons(ETHERTYPE_IPV4);
    }
    else
    {
        memcpy(session->packet_header.eth.dest_mac, session->client_mac, 6);
        memcpy(session->packet_header.eth.src_mac, MY_MAC, 6);
        session->packet_header.eth.vlan_tpid = htons(ETHERTYPE_VLAN);
        session->packet_header.eth.vlan_tci = session->vlan_id;
        session->packet_header.eth.ethertype = htons(ETHERTYPE_IPV4);
    }

    tftp_prepare_oack(session);
    tftp_prepare_packets(session);

    // Print relevant information
    
    printf("\nSession ID: %3u\n", session->session_id);
    printf("  %s:%u [VLAN:%d]\n", inet_ntoa(*(struct in_addr *)&session->client_ip), ntohs(session->client_port), (short)ntohs(session->vlan_id));
    // printf("  Session Server Port: %u\n", ntohs(session->server_port));
    // printf("  Session Client MAC:");
    // print_mac(session->client_mac);

    printf("  File  : %s\n", session->file_name);
    if (session->fd != NULL){
        printf("  Size  : %0.4f %s\n",
            (session->file_size > 1024*1024 ? (float)session->file_size/(1024*1024) : (session->file_size > 1024 ? (float)session->file_size/1024 : (float)session->file_size)),
            (session->file_size > 1024*1024 ? "MB" : (session->file_size > 1024 ? "KB" : "Bytes")));
    }
    // printf("  Block Needed: %ld\n", (session->file_size / session->block_size) + 1);

    if (session->options_requested != 0)
    {
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

    if (session->error_occurred)
        printf(" ERROR: [%u] %s\n", session->error_occurred & ~TFTP_ERROR_FLAG, session->error_text);

    return session;
}

int tftp_update_session(struct tftp_session *session, uint32_t ack_block)
{
    ack_block += ((session->block_number) / 65536) * 65536; // Adjust for wrap-around
    
    if (ack_block <= session->ack_received)
    {
        debug("    Duplicate ACK for block %u, ignoring.\n", ack_block);
        return FALSE;
    }
    else if (ack_block > session->block_number + 1)
    {
        debug("    ACK for future block %u, ignoring.\n", ack_block);
        return FALSE;
    }

    session->ack_received = ack_block;
    session->retries = 0;

    if (session->last_packet && ack_block == session->block_number)
    {
        // Successful completion
        close_session(session);
        return FALSE;
    }

    return TRUE;
}

int tftp_prepare_oack(struct tftp_session *session)
{
    size_t pkt_len = 0;
    int rc = 0;
    char buf[1024] = {0};
    struct tftp_packet *tpkt = NULL;
    const packet_t *pkt = NULL;

    if (session->options_requested == 0 || session->error_occurred)
        return 0;  // No option to ack
    
    tpkt = (struct tftp_packet *)buf; 
    
    memcpy(buf, &session->packet_header, sizeof(struct udp_packet));
    pkt_len = sizeof(struct udp_packet);
    
    tpkt->tftp.opcode = htons(OPCODE_OACK);
    pkt_len += sizeof(tpkt->tftp.opcode);
    
    // Add tsize option if requested
    if (session->options_requested & OPTIONS_TSIZE_REQUESTED){
        strcpy(buf + pkt_len, "tsize");
        pkt_len += strlen("tsize") + 1;

        rc = sprintf(buf + pkt_len, "%ld", session->file_size);
        if (rc < 0) {
            session->error_occurred = TFTP_ERROR_UNKNOWN;
            strcpy(session->error_text, "Error formatting tsize value");
            return rc;
        }
        pkt_len += rc + 1;
    }

    // Add block size option if requested
    if (session->options_requested & OPTIONS_BLKSIZE_REQUESTED) {
        strcpy(buf + pkt_len, "blksize");
        pkt_len += strlen("blksize") + 1;

        rc = sprintf(buf + pkt_len, "%d", session->block_size);
        if (rc < 0) {
            session->error_occurred = TFTP_ERROR_UNKNOWN;
            strcpy(session->error_text, "Error formatting blksize value");
            return rc;
        }
        pkt_len += rc + 1;
    }

    // Add timeout option if requested
    if (session->options_requested & OPTIONS_TIMEOUT_REQUESTED) {
        strcpy(buf + pkt_len, "timeout");
        pkt_len += strlen("timeout") + 1;

        rc = sprintf(buf + pkt_len, "%d", session->timeout / 1000);
        if (rc < 0) {
            session->error_occurred = TFTP_ERROR_UNKNOWN;
            strcpy(session->error_text, "Error formatting timeout value");
            return rc;
        }
        pkt_len += rc + 1;
    }

    // Add windowsize option if requested
    if (session->options_requested & OPTIONS_WINDOWSIZE_REQUESTED) {
        strcpy(buf + pkt_len, "windowsize");
        pkt_len += strlen("windowsize") + 1;

        rc = sprintf(buf + pkt_len, "%d", session->windowsize);
        if (rc < 0) {
            session->error_occurred = TFTP_ERROR_UNKNOWN;
            strcpy(session->error_text, "Error formatting timeout value");
            return rc;
        }
        pkt_len += rc + 1;
    }
    
    tpkt->udp.len = htons(pkt_len - sizeof(struct ipv4_packet));
    tpkt->ip.total_length = htons(pkt_len - sizeof(struct eth_header));
    
    pkt = queue_add(session->pkts, -1, buf, pkt_len);
    if (pkt == NULL)
    {
        session->error_occurred = TFTP_ERROR_UNKNOWN;
        strcpy(session->error_text, "Failed to allocate OACK packet");
        return -1;
    }

    return 0;
}

void tftp_prepare_packets(struct tftp_session *session)
{
    int64_t start = 0;
    int64_t stop = 0;
    int64_t i = 0;
    size_t read_length = 0;
    uint64_t offset = 0;
    uint64_t pkt_size = 0;
    const packet_t *pkt = NULL;
    struct tftp_packet *tpkt = NULL;

    if (session->error_occurred) return;

    // Preallocate Packets
    if (session->ack_received < 0) {
        start = 0;
        stop = MAX_PREALLOCATE;
    } else {
        start = session->ack_received;
        stop = start + MAX_PREALLOCATE;
    }

    if (session->block_number >= stop)
        stop = session->block_number + MAX_PREALLOCATE;

    if (session->pkts->tail) {
        if (session->pkts->tail->packet.index >= start && 
            session->pkts->tail->packet.index > session->block_number)
            return; // No need to preallocate
    }

    debug("Session %3u: Preallocating packets from %lld to ", session->session_id, start);

    for(i = start; i <= stop; i++)
    {
        pkt = queue_get(session->pkts, i);
        if (pkt != NULL){
            continue;
        }

        offset = i * (uint64_t)session->block_size;
        if (offset > (uint64_t)session->file_size) break;
        
        read_length = (size_t)((uint64_t)session->file_size - offset);
        if (read_length >= session->block_size)
            read_length = session->block_size;

        pkt_size = sizeof(struct udp_packet) + 4 + read_length;
        
        pkt = queue_add(session->pkts, i, NULL, pkt_size);
        if (pkt == NULL){
            session->error_occurred = TFTP_ERROR_UNKNOWN;
            strcpy(session->error_text, "Failed to allocate DATA packet");
            break;
        }

        tpkt = pkt->data;

        if (fseek(session->fd, offset, SEEK_SET) != 0) {
            session->error_occurred = TFTP_ERROR_UNKNOWN;
            strcpy(session->error_text, "File seek error");
            break;
        }

        if (read_length != fread(tpkt->tftp.data.data, 1, read_length, session->fd))
        {
            session->error_occurred = TFTP_ERROR_UNKNOWN;
            strcpy(session->error_text, "File read length mismatch");
            break;
        }

        tpkt->tftp.data.opcode = htons(OPCODE_DATA);
        tpkt->tftp.data.block_number = htons(i + 1);

        memcpy(tpkt, &session->packet_header, sizeof(struct udp_packet));
        tpkt->udp.len = htons(sizeof(struct udp_header) + 4 + read_length);
        tpkt->ip.total_length = htons(sizeof(struct udp_packet) + 4 + read_length - sizeof(struct eth_header));
    }

    debug("%lld\n", i - 1);

    // Remove Acknowledged Packets
    if (session->pkts->size > 2 * MAX_PREALLOCATE)
    {
        if (session->pkts->lowest_index < session->ack_received)
            debug("Session %3u: Removing preallocated packets from %lld to %lld\n",
                   session->session_id, session->pkts->lowest_index, session->ack_received - 1);
        for (i = session->pkts->lowest_index; i < session->ack_received; i++)
        {
            queue_delete(session->pkts, i);
        }
    }

    return;
}

void tftp_send_packets(pcap_t *handle, struct tftp_session *session)
{
    session->last_packet = FALSE;
    
    session->block_number = session->ack_received;
    while (session->block_number < session->windowsize + session->ack_received)
    {
        // if (!tftp_send_data(handle, session)) break;
        if (tftp_send_packet(handle, session, 0) != 0) 
            break;
        
        session->block_number++;
        timer_start(&processing_timer);
        
        if (session->last_packet)
        {
            break;
        }
    }

    if (!session->last_packet)
        tftp_prepare_packets(session);

    return;
}

// int tftp_send_data(pcap_t *handle, struct tftp_session *session)
// {
//     size_t read_length = 0;

//     if (session == NULL || !session->in_use) {
//         printf("    Invalid session.\n");
//         return FALSE;
//     }

//     if (session->fd == NULL && session->file == NULL) {
//         tftp_send_error(handle, session);
//         return FALSE;
//     }

//     if (session->ack_received == -1) {
//         tftp_send_oack(handle, session);
//         return FALSE;
//     }

//     // session->packet.tftp.data.opcode = htons(OPCODE_DATA);

//     // // Read file data
//     // if (session->file != NULL)
//     // {
//     //     uint64_t offset = (uint64_t)session->block_number * (uint64_t)session->block_size;
//     //     if (offset >= (uint64_t)session->file_size)
//     //     {
//     //         printf("    Invalid offset %llu >= file_size %ld\n", (unsigned long long)offset, session->file_size);
//     //         // Nothing left to send or invalid request — close session
//     //         close_session(session);
//     //         return FALSE;
//     //     }

//     //     size_t remaining = (size_t)((uint64_t)session->file_size - offset);
//     //     read_length = remaining;
//     //     if (read_length >= session->block_size)
//     //         read_length = session->block_size;
//     //     else {
//     //         // last packet
//     //         session->last_packet = TRUE;
//     //     }

//     //     if (read_length > sizeof(session->packet.tftp.data.data)) {
//     //         debug("    Clamping read_length %zu to data buffer %zu\n", read_length, sizeof(session->packet.tftp.data.data));
//     //         read_length = sizeof(session->packet.tftp.data.data);
//     //     }

//     //     memcpy(session->packet.tftp.data.data, session->file + offset, read_length);
//     // } else if (session->fd != NULL) {
//     //     long seek_offset = session->block_number * session->block_size;
//     //     if (seek_offset < 0) {
//     //         printf("    Negative seek offset %ld\n", seek_offset);
//     //         close_session(session);
//     //         return FALSE;
//     //     }
//     //     if (fseek(session->fd, seek_offset, SEEK_SET) != 0) {
//     //         perror("    fseek()");
//     //         close_session(session);
//     //         return FALSE;
//     //     }
//     //     debug("    from %ld ", ftell(session->fd));
//     //     read_length = fread(session->packet.tftp.data.data, 1, session->block_size, session->fd);
//     //     debug("to %ld\n", ftell(session->fd));
//     // }

//     // if (read_length < session->block_size) {
//     //     if (session->last_packet || feof(session->fd)) {
//     //         session->last_packet = TRUE;
//     //         debug("    Last packet to be sent.\n");
//     //     } else if (ferror(session->fd)) {
//     //         printf("    Error reading file.\n");
//     //         perror("         server: fread()");
            
//     //         close_session(session);

//     //         return FALSE;
//     //     }
//     // }

//     // session->packet.tftp.data.block_number = htons(session->block_number + 1);
//     // session->packet.udp.len = htons(sizeof(struct udp_header) + 4 + read_length);
//     // session->packet.ip.total_length = htons(sizeof(struct udp_packet) + 4 + read_length - sizeof(struct eth_header));
//     // session->packet_length = sizeof(struct udp_packet) + 4 + read_length;

//     tftp_send_packet(handle, session);
//     // Reset retry counter after a fresh send
//     session->retries = 0;

//     return TRUE;
// }


void handle_tftp(pcap_t *handle, const struct tftp_packet *pkt, uint32_t pkt_len)
{
    struct tftp_session *session = NULL;

    session = get_session(pkt, pkt_len);
    if (session == NULL)
    {
        debug("Unable to create/find session\n");
        return;
    }

    switch (ntohs(pkt->tftp.opcode))
    {
    case OPCODE_RRQ:
        debug("\nTFTP Read request\n");

        tftp_send_packets(handle, session);

        break;

    case OPCODE_WRQ:
        printf("TFTP Write request\n");
        printf("Incomplete\n");
        break;

    case OPCODE_ACK:
        debug("TFTP ACK\n");
        if (tftp_update_session(session, (uint32_t)ntohs(pkt->tftp.ack.block_number)))
        {
            tftp_send_packets(handle, session);
        }

        break;

    case OPCODE_ERROR:
        printf("\nTFTP ERROR received: Code %u\n", ntohs(pkt->tftp.error.error_code));
        printf("  Error Message: %s\n", pkt->tftp.error.error_string);
        close_session(session);
        break;

    default:
        printf("\nTFTP Unknown opcode in existing session\n");
        break;
    }

    return;
}

