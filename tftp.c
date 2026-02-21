#include "tftp.h"

struct tftp_session sessions[MAX_SESSIONS] = {0};

void close_session(struct tftp_session *session);
static void tftp_send_error(pcap_t *handle, struct tftp_session *session);
void tftp_prepare_packets(struct tftp_session *session);
void tftp_send_packets(pcap_t *handle, struct tftp_session *session);
void tftp_receive_data(pcap_t *handle, struct tftp_session *session, const struct tftp_packet *pkt, uint32_t pkt_len);
int tftp_prepare_oack(struct tftp_session *session);

// Helper: set tftp error
static inline void tftp_set_error(struct tftp_session *session, int errcode, const char *errmsg)
{
    session->error_occurred = errcode;
    strncpy(session->error_text, errmsg, sizeof(session->error_text) - 1);
    session->error_text[sizeof(session->error_text) - 1] = '\0';
}

// Helper: parse options
static int parse_options(const uint8_t *buf, size_t maxlen, struct tftp_session *session)
{
    size_t i = 0;

    session->options_requested = 0;
    session->block_size = DEFAULT_BLOCK_SIZE; // Default block size
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
        debug("%s: * TFTP: Parsing option: %s\n", time_str(), (const char *)&buf[i]);

        if (strcasecmp((const char *)&buf[i], "tsize") == 0)
        {
            session->options_requested |= OPTIONS_TSIZE_REQUESTED;

            // Move past option name
            while (i < maxlen && buf[i] != 0)
                i++;
            i++;
            // TODO: Check if size can be written to disk
            session->tsize = strtol((const char *)&buf[i], NULL, 10);
            debug("%s: * TFTP: Parsed tsize value: '%s' -> %ld\n", time_str(), &buf[i], session->tsize);

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
            debug("%s: * TFTP: Parsed blksize value: '%s' -> %d\n", time_str(), &buf[i], session->block_size);

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
            debug("%s: * TFTP: Parsed timeout value: '%s' -> %d\n", time_str(), &buf[i], session->timeout);
            
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
            debug("%s: * TFTP: Parsed windowsize value: '%s' -> %d\n", time_str(), &buf[i], session->windowsize);
            
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

            debug("%s: * TFTP: Parsing option value: %s\n", time_str(), (const char *)&buf[i]);

            // skip option value
            while (i < maxlen && buf[i] != 0)
                i++;
            i++;
        }
    }

    // Limit options
    if (session->block_size < MIN_BLOCK_SIZE || session->block_size > MAX_BLOCK_SIZE) {
        debug("%s: * TFTP:     Invalid block size requested (%d), using default %d.\n", time_str(), session->block_size, DEFAULT_BLOCK_SIZE);
        session->block_size = DEFAULT_BLOCK_SIZE;
    }

    if (session->timeout < MIN_TIMEOUT || session->timeout > MAX_TIMEOUT) {
        debug("%s: * TFTP:     Invalid timeout requested (%d ms), using default %d ms.\n", time_str(), session->timeout, DEFAULT_TIMEOUT);
        session->timeout = DEFAULT_TIMEOUT;
    }

    if (session->windowsize < MIN_WINDOWSIZE || session->windowsize > MAX_WINDOWSIZE) {
        debug("%s: * TFTP:     Invalid windowsize requested (%d), using default %d.\n", time_str(), session->windowsize, DEFAULT_WINDOWSIZE);
        session->windowsize = DEFAULT_WINDOWSIZE;
    }

    session->last_packet = FALSE;
    session->sent_packet_count = -1;
    session->block_number = 0;
    session->ack_sent = -1; // if (session->in_use == TFTP_RECEIVING)
    if (session->options_requested == 0) {
        session->ack_received = 0;
    } else {
        session->ack_received = -1; // Indicate OACK to be sent first
    }

    return 0;
}

int tftp_is_ftp_url(const char *url)
{
    if (url == NULL)
        return 0;
    /* ftp:// or ftps:// (case-insensitive) */
    if (strncasecmp(url, "ftp://", 6) == 0)
        return 1;
    if (strncasecmp(url, "ftps://", 7) == 0)
        return 1;
    return 0;
}

int tftp_send_packet(pcap_t *handle, struct tftp_session *session, const packet_t *pkt)
{
    struct tftp_packet *tpkt = NULL;

    if(session->error_occurred){
        tftp_send_error(handle, session);
        return -1;
    }

    if (pkt == NULL && (pkt = queue_get(session->pkts, session->block_number)) == NULL)
    {
        if (session->in_use != TFTP_SENDING) return -1;

        // Maybe we had not prepared enough packets?
        tftp_prepare_packets(session);
        pkt = queue_get(session->pkts, session->block_number);
        if (pkt == NULL) return -1;
    }

    tpkt = pkt->data;
    tpkt->ip.id = htons(ipv4_id++);

    if (session->sent_packet_count != -1) {
        session->processing_time += timer_elapsed_us(&processing_timer);
        //printf("PT: %lld us\n", timer_elapsed_us(&processing_timer));
    } else {
#ifdef DEBUG
        printf("First packet sent in: %0.2f us\n", (double)timer_elapsed_us(&processing_timer) * 1000000.0 / processing_timer.frequency.QuadPart );
        print_ipv4(&((struct ipv4_packet *)pkt->data)->ip);
        print_udp(&((struct tftp_packet *)pkt->data)->udp);
        print_raw_data((const uint8_t *)&((struct tftp_packet *)pkt->data)->tftp, pkt->data_len - sizeof(struct udp_packet));
#endif
    }
    session->sent_packet_count += 1;

    if (
#ifdef DEBUG 
        1 || 
#endif 
        (ntohs(tpkt->tftp.opcode) == OPCODE_ERROR) || 
        (ntohs(tpkt->tftp.opcode) == OPCODE_OACK) || 
        (ntohs(tpkt->tftp.opcode) == OPCODE_ACK && ntohs(tpkt->tftp.ack.block_number) <= 1) || 
        (ntohs(tpkt->tftp.opcode) == OPCODE_DATA && ntohs(tpkt->tftp.data.block_number) <= 1)
    ){
        printf("%s: > TFTP: %s\n", time_str(), get_tftp_pkt_desc(tpkt, FALSE));
    }

    if (send_ipv4_packet(handle, (struct ipv4_packet *)pkt->data, pkt->data_len) != 0)
    {
        printf("Session %3u: Error sending packet via pcap\n", session->session_id);

#ifdef DEBUG
        print_ipv4(&((struct ipv4_packet *)pkt->data)->ip);
        print_udp(&((struct tftp_packet *)pkt->data)->udp);
        print_raw_data((const uint8_t *)&((struct tftp_packet *)pkt->data)->tftp, 10);
#endif
        tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Error sending packet via pcap");
        return -1;
    }
    else
    {
        if (session->ack_received >= 0 && tpkt->udp.len != session->packet_header.udp.len) {
            session->last_packet = TRUE;
        }
        debug("    Packet Sent (blk %lld, %u byte)!\n", session->block_number, ntohs(tpkt->udp.len));
    }

    return 0;
}

int tftp_send_data_ack(pcap_t *handle, struct tftp_session *session)
{
    size_t pkt_len = 0;
    int rc = -1;
    char buf[1024] = {0};
    packet_t _pkt = {0};
    packet_t *pkt = &_pkt;
    struct tftp_packet *tpkt = NULL;

    pkt->index = 0;
    pkt->data_len = 0;
    pkt->data = buf;

    if (handle == NULL || session == NULL || !session->in_use) return -1;
    if (session->error_occurred) return 0;

    tpkt = (struct tftp_packet *)buf;

    session->block_number = session->ack_received; // I have just received and saved this block data, initially -1 if oack needed, else 0

    // if ack_sent is -1, we need to send initial ack, if option requested, then oack instead

    if (session->ack_sent < 0 && session->ack_received < 0)
    {
        // Need to send oack instead of ack, it is stored at index -1 in packet queue
        rc = tftp_send_packet(handle, session, NULL);
        session->block_number = 0;
        session->ack_sent = session->block_number;
        if (rc != 0)
            tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Failed to send OACK packet");
        return rc;
    }

    // When Handling RRQ, we send block number increasing 1, but for handling
    // WRQ, we send the same block number. Because RRQ was created first, here
    // we just handle the edge case
    if (session->block_number < 0) session->block_number = 0;
    
    if ((session->last_packet && session->ack_sent != session->block_number) ||
        (session->ack_sent < 0 && session->ack_received == 0) ||
        session->block_number >= session->ack_sent + session->windowsize)
    {
        debug("    Sending normal ack\n");
        // we will be sending normal ack
        memcpy(buf, &session->packet_header, sizeof(struct udp_packet));
        tpkt->tftp.ack.opcode = htons(OPCODE_ACK);
        tpkt->tftp.ack.block_number = htons(session->block_number);
        pkt_len = sizeof(struct udp_packet) + sizeof(tpkt->tftp.ack);
        pkt->data_len = pkt_len;

        tpkt->ip.id = htons(ipv4_id++);

        tpkt->udp.len = htons(pkt_len - sizeof(struct ipv4_packet));
        tpkt->ip.total_length = htons(pkt_len - sizeof(struct eth_header));

        tpkt->udp.checksum = 0; // Ensure field is zero before calculation
        tpkt->udp.checksum = udp_checksum(&tpkt->ip, &tpkt->udp);

        rc = tftp_send_packet(handle, session, pkt);
        if (rc != 0)
            tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Failed to send ACK packet");
        else
            session->ack_sent = session->block_number;
    }

    return rc;
}

static void tftp_send_error(pcap_t *handle, struct tftp_session *session)
{
    size_t pkt_len = 0;
    int rc = 0;
    char buf[1024] = {0};
    struct tftp_packet *tpkt = NULL;

    if (session->error_occurred == 0)
        return;  // No error to send!

    tpkt = (struct tftp_packet *)buf;
    
    memcpy(buf, &session->packet_header, sizeof(struct udp_packet));
    pkt_len = sizeof(struct udp_packet);
    
    tpkt->tftp.opcode = htons(OPCODE_ERROR);
    pkt_len += sizeof(tpkt->tftp.opcode);

    tpkt->tftp.error.error_code = htons(session->error_occurred & ~TFTP_ERROR_FLAG);
    pkt_len += sizeof(tpkt->tftp.error.error_code);

    rc = sprintf((char *)(tpkt->tftp.error.error_string), "%s", session->error_text);
    if (rc < 0) {
        printf("    Error formatting .\n");
        // close_session(session);
    } else {
        pkt_len += rc + 1;
    }

    tpkt->ip.id = htons(ipv4_id++);

    tpkt->udp.len = htons(pkt_len - sizeof(struct ipv4_packet));
    tpkt->ip.total_length = htons(pkt_len - sizeof(struct eth_header));

    tpkt->udp.checksum = 0; // Ensure field is zero before calculation
    tpkt->udp.checksum = udp_checksum(&tpkt->ip, &tpkt->udp);

    send_ipv4_packet(handle, (struct ipv4_packet *)tpkt, pkt_len);
    // close_session(session); // lets retry sending error then close
}

void session_check(pcap_t *handle)
{
    const int MAX_RETRIES = 5;
    static DWORD last_print_time = 0;
    DWORD now = 0;
    int print = FALSE;
    int printed = FALSE;
    struct tftp_session *s = NULL;

    now = GetTickCount();

    // If it has been more than 5s since last progress print, print progress
    if (now - last_print_time > 5000) print = TRUE;

    // Check for TFTP session timeouts and print progress
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

            if (now - s->last_activity > s->timeout)
            {
                if (s->retries < MAX_RETRIES)
                {
                    debug("  Session %3u: Retry block %lld (retry %u/%u)\n", s->session_id, s->block_number, s->retries, MAX_RETRIES);
                    if (s->in_use == TFTP_SENDING) {
                        tftp_send_packets(handle, s);
                    } else if (s->in_use == TFTP_RECEIVING) {
                        // Force sending ack
                        s->ack_sent = s->block_number - s->windowsize;
                        tftp_send_data_ack(handle, s);
                    }
                    s->retries++;
                    s->last_activity = GetTickCount();
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
    double duration_s;
    double transferred_mb;

    if (session == NULL) {
        return;
    }

    duration_s = (GetTickCount() - session->created_at) / 1000.0;
    transferred_mb = session->file_size / (1024.0 * 1024.0);
    
    if (session->error_occurred)
    {
        printf(" Session %3u: Error[%u] %s\n", session->session_id, session->error_occurred & ~TFTP_ERROR_FLAG, session->error_text);
    }
    else if (session->last_packet)
    {
        printf("Session %3u: Complete (%5.3f MB/s)\n", session->session_id, transferred_mb / duration_s);
    }
    else
    {
        printf("Session %3u: Terminated\n", session->session_id);
    }

    printf("             Processing time %.4f us/packet\n",
        ((double)session->processing_time / processing_timer.frequency.QuadPart) * 1000000.0 / session->sent_packet_count
    );
    debug("             Sent %llu packets\n", session->sent_packet_count);

    if (session->fd) {
        fclose(session->fd);
        if (session->in_use == TFTP_RECEIVING && session->last_packet == FALSE) {
            if (remove(session->file_name) != 0) perror("remove");
        }
        session->fd = NULL;
    }

    if (session->ftp) {
        ftp_download_free(session->ftp);
        session->ftp = NULL;
    }


    if (session->pkts) {
        queue_free(session->pkts);
        session->pkts = NULL;
    }

    session->in_use = TFTP_NOT_USING;
    memset(session, 0, sizeof(*session));

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
    long file_size = 0;
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
                    if (
#ifdef DEBUG 
                       1 || 
#endif 
                        ntohs(pkt->tftp.opcode) == OPCODE_ERROR || 
                        ntohs(pkt->tftp.opcode) == OPCODE_OACK  || 
                        (ntohs(pkt->tftp.opcode) == OPCODE_ACK && ntohs(pkt->tftp.ack.block_number) <= 1) || 
                        (ntohs(pkt->tftp.opcode) == OPCODE_DATA && ntohs(pkt->tftp.data.block_number) <= 1)
                    ){
                        printf("%s: < TFTP: %s\n", time_str(), get_tftp_pkt_desc(pkt, TRUE));
                    }
                    return session;
                }
                else
                {
                    printf("%s: < TFTP: %s duplicate\n", time_str(), get_tftp_pkt_desc(pkt, TRUE));
                    return NULL;
                }
            }
            else
            {
                debug("%s: < TFTP: %s duplicate vlan\n", time_str(), get_tftp_pkt_desc(pkt, TRUE));
                return NULL;
            }
        }
    }

    if (ntohs(pkt->tftp.opcode) != OPCODE_RRQ && ntohs(pkt->tftp.opcode) != OPCODE_WRQ)
    {
        printf("%s: < TFTP: %s ses not found\n", time_str(), get_tftp_pkt_desc(pkt, TRUE));
        return NULL;
    }

    if (ntohs(pkt->udp.dest) != REQUEST_PORT)
    {
        printf("%s: < TFTP: %s not req port\n", time_str(), get_tftp_pkt_desc(pkt, TRUE));
        return NULL;
    }

    // not found, create_session

    for (i = 0; i < MAX_SESSIONS; i++) {
        session = &sessions[i];
        if (!session->in_use)
            break;
    }

    if (session == NULL || session->in_use) {
        printf("%s: < TFTP: %s maximum session reached\n", time_str(), get_tftp_pkt_desc(pkt, TRUE));
        return NULL;
    }

    printf("%s: < TFTP: %s\n", time_str(), get_tftp_pkt_desc(pkt, TRUE));

    memset(session, 0, sizeof(*session));

    session->pkts = queue_init();
    if (!session->pkts)
        tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Failed to initialize packet queue");

    session->created_at = GetTickCount();
    if (ntohs(pkt->tftp.opcode) == OPCODE_RRQ) session->in_use = TFTP_SENDING;
    else if (ntohs(pkt->tftp.opcode) == OPCODE_WRQ) session->in_use = TFTP_RECEIVING;
    else return NULL;
    session->session_id = ++session_counter;
    session->server_port = htons(START_PORT + i);

    memcpy(session->client_mac, pkt->eth.src_mac, 6);
    session->client_ip = pkt->ip.src_addr;
    session->client_port = pkt->udp.source;
    session->vlan_id = pkt->eth.vlan_tci;

    strncpy(session->file_name, (const char *)pkt->tftp.request.filename_and_mode, sizeof(session->file_name));
    session->file_name[sizeof(session->file_name) - 1] = '\0';

    if (session->in_use == TFTP_SENDING)
    {
        if (tftp_is_ftp_url(session->file_name))
        {
            session->ftp = ftp_request_file(session->file_name);
            if (session->ftp == NULL)
                tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Failed to initiate FTP download");
            else
            {
                if (session->ftp->has_error)
                    tftp_set_error(session, TFTP_ERROR_FILE_NOT_FOUND, session->ftp->error_msg);
                else
                    session->file_size = session->ftp->capacity;
            }
        }
        else
        {
            session->fd = fopen(session->file_name, "rb");
            if (session->fd != NULL)
            {
                fseek(session->fd, 0, SEEK_END);
                session->file_size = ftell(session->fd);
                fseek(session->fd, 0, SEEK_SET);
            }
            else
                tftp_set_error(session, TFTP_ERROR_FILE_NOT_FOUND, "Requested File does not exists");
        }
    }
    else if (session->in_use == TFTP_RECEIVING)
    {
        // First check if file already exists
        FILE *check_fd = fopen(session->file_name, "rb");
        if (check_fd != NULL)
        {
            // Error: File already exists!
            tftp_set_error(session, TFTP_ERROR_FILE_ALREADY_EXISTS, "File already exists");
            fclose(check_fd);
        } 
        else 
        {
            session->fd = fopen(session->file_name, "wb");
            session->file_size = 0;
            if (session->fd == NULL)
            {
                // Error: Cannot create file!
                tftp_set_error(session, TFTP_ERROR_ACCESS_VIOLATION, "Cannot create file for writing");
            }
        }
    }

    option_len = pkt_len - sizeof(struct udp_packet) - 4;
    // if(option_len > sizeof(pkt->tftp.request.filename_and_mode))
    //     option_len = sizeof(pkt->tftp.request.filename_and_mode);

    // Option parsing
    parse_options(
        pkt->tftp.request.filename_and_mode, 
        option_len, 
        session
    );

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
    if (session->vlan_id == INVALID_VLAN_TCI)
    {
        struct eth_mover *mover = (struct eth_mover *)&session->packet_header;
        mover->padding = (uint32_t)-1; // For optimization in send_via_pcap()
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
    printf("\n%s\nSession ID: %3u", time_str(), session->session_id);
    if (session->in_use == TFTP_RECEIVING)
        printf(" [WRQ]%s\n", (session->ftp) ? "[FTP]" : "");
    else if (session->in_use == TFTP_SENDING)
        printf(" [RRQ]%s\n", (session->ftp) ? "[FTP]" : "");
    printf("  %s:%u [VLAN:%d]\n", inet_ntoa(*(struct in_addr *)&session->client_ip), ntohs(session->client_port), (short)ntohs(session->vlan_id));
    // printf("  Session Server Port: %u\n", ntohs(session->server_port));
    // printf("  Session Client MAC:");
    // print_mac(session->client_mac);

    printf("  File  : %s\n", session->file_name);

    file_size = (session->in_use == TFTP_SENDING) ? session->file_size : session->tsize;
    if ((session->fd != NULL || session->ftp != NULL) && file_size){
        printf("  Size  : %0.4f %s\n",
            (file_size > 1024*1024 ? (float)file_size/(1024*1024) : (file_size > 1024 ? (float)file_size/1024 : (float)file_size)),
            (file_size > 1024*1024 ? "MB" : (file_size > 1024 ? "KB" : "Bytes")));
    }
    // printf("  Block Needed: %ld\n", (file_size / session->block_size) + 1);

    if (session->options_requested != 0)
    {
        printf("  Option:");
        if (session->options_requested & OPTIONS_TSIZE_REQUESTED)
            printf(" tsize[%ld]", session->tsize);
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
    debug("    ack_received %u\n", ack_block);

    if (session->in_use == TFTP_RECEIVING)
    {
        // if (session->ack_sent < 0) session->ack_sent = 0;
        return TRUE;
    }

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

        if (session->in_use == TFTP_SENDING)
            rc = sprintf(buf + pkt_len, "%ld", session->file_size);
        else // if (session->in_use == TFTP_RECEIVING)
            rc = sprintf(buf + pkt_len, "%ld", session->tsize);

        if (rc < 0) {
            tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Error formatting tsize value");
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
            tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Error formatting blksize value");
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
            tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Error formatting timeout value");
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
            tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Error formatting windowsize value");
            return rc;
        }
        pkt_len += rc + 1;
    }
    
    tpkt->udp.len = htons(pkt_len - sizeof(struct ipv4_packet));
    tpkt->ip.total_length = htons(pkt_len - sizeof(struct eth_header));

    tpkt->udp.checksum = 0; // Ensure field is zero before calculation
    tpkt->udp.checksum = udp_checksum(&tpkt->ip, &tpkt->udp);
    
    pkt = queue_add(session->pkts, -1, buf, pkt_len);
    if (pkt == NULL)
    {
        tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Failed to allocate OACK packet");
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

    if (session->error_occurred || session->in_use != TFTP_SENDING) return;

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

    ftp_download_poll();
    debug("%s: * TFTP: Session %3u: Preallocating packets from %lld to ", time_str(), session->session_id, start);

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
        
        if (session->ftp && session->ftp->size < (offset + read_length)) {
            // we are getting file from ftp, but we have not read enough
            break;
        }

        pkt_size = sizeof(struct udp_packet) + 4 + read_length;
        
        pkt = queue_add(session->pkts, i, NULL, pkt_size);
        if (pkt == NULL){
            tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Failed to allocate DATA packet");
            break;
        }

        tpkt = pkt->data;

        if (session->ftp != NULL){
            memcpy(tpkt->tftp.data.data, session->ftp->data + offset, read_length);
        }
        else
        {
            if (fseek(session->fd, offset, SEEK_SET) != 0) {
                tftp_set_error(session, TFTP_ERROR_UNKNOWN, "File seek error");
                break;
            }

            if (read_length != fread(tpkt->tftp.data.data, 1, read_length, session->fd))
            {
                tftp_set_error(session, TFTP_ERROR_UNKNOWN, "File read length mismatch");
                break;
            }
        }


        memcpy(tpkt, &session->packet_header, sizeof(struct udp_packet));

        tpkt->tftp.data.opcode = htons(OPCODE_DATA);
        tpkt->tftp.data.block_number = htons(i + 1);

        tpkt->udp.len = htons(sizeof(struct udp_header) + 4 + read_length);
        tpkt->ip.total_length = htons(sizeof(struct udp_packet) + 4 + read_length - sizeof(struct eth_header));

        tpkt->udp.checksum = 0; // Ensure field is zero before calculation
        tpkt->udp.checksum = udp_checksum(&tpkt->ip, &tpkt->udp);
    }

    debug("%lld\n", i - 1);

    // Remove Acknowledged Packets
    if (session->pkts->size > 2 * MAX_PREALLOCATE)
    {
        if (session->pkts->lowest_index < session->ack_received)
            debug("%s: * TFTP: Session %3u: Removing preallocated packets from %lld to %lld\n", time_str(),
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

    if (session->ftp != NULL && session->ftp->has_error && !session->error_occurred)
    {
        tftp_set_error(session, TFTP_ERROR_UNKNOWN, session->ftp->error_msg);
    } 
    
    session->block_number = session->ack_received;
    while (session->block_number < session->windowsize + session->ack_received)
    {
        if (tftp_send_packet(handle, session, NULL) != 0)
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
    
    if (session->ftp)
    {
        do {
            ftp_download_poll();
        } while (session->ftp->size == 0 && !session->ftp->has_error && !session->ftp->completed);
        debug("FILE SIZE: %zu\n", session->ftp->size);
    }

    timer_start(&processing_timer);

    return;
}

void tftp_receive_data(pcap_t *handle, struct tftp_session *session, const struct tftp_packet *pkt, uint32_t pkt_len)
{
    uint32_t data_length = pkt_len - sizeof(struct udp_packet) - 4;
    long offset  = 0;

    if (data_length > session->block_size) {
        tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Received data length exceeds block size");
        return;
    } else if (data_length < session->block_size) {
        session->last_packet = TRUE;
    } else {
        session->last_packet = FALSE;
    }

    // Write data to file
    offset = (session->ack_received - 1) * (uint64_t)session->block_size;
    if (offset < 0) {
        tftp_set_error(session, TFTP_ERROR_UNKNOWN, "Invalid Block Number");
        return;
    }
    if (fseek(session->fd, offset, SEEK_SET) != 0) {
        tftp_set_error(session, TFTP_ERROR_UNKNOWN, "File seek error");
        return;
    }
    if (data_length != fwrite(pkt->tftp.data.data, 1, data_length, session->fd))
    {
        tftp_set_error(session, TFTP_ERROR_UNKNOWN, "File write length mismatch");
        return;
    }

    // Update file size
    session->file_size += data_length;

    timer_start(&processing_timer);

    if (session->last_packet) {
        tftp_send_data_ack(handle, session);
        close_session(session);
    }

    return;
}

void handle_tftp(pcap_t *handle, const struct tftp_packet *pkt, uint32_t pkt_len)
{
    struct tftp_session *session = NULL;

    session = get_session(pkt, pkt_len);
    if (session == NULL)
    {
        // printf("%s: < TFTP: session creation failed\n", time_str());
        // debug("Unable to create/find session\n");
        return;
    }

    switch (ntohs(pkt->tftp.opcode))
    {
    case OPCODE_RRQ:
        tftp_send_packets(handle, session);

        break;

    case OPCODE_WRQ:
        tftp_send_data_ack(handle, session);

        break;

    case OPCODE_DATA:
        if (tftp_update_session(session, (uint32_t)ntohs(pkt->tftp.data.block_number)))
        {
            tftp_send_data_ack(handle, session);
            tftp_receive_data(handle, session, pkt, pkt_len);
        }

        break;

    case OPCODE_ACK:
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

    if (session->in_use) session->last_activity = GetTickCount();

    return;
}

