#include <wchar.h>
#include <locale.h>

#include "pcap_fun.h"
#include "packet.h"
#include "tftp.h"

uint8_t MY_MAC[6] = {0};
uint32_t MY_IP = 0;
uint8_t MY_NAME[512] = {0};

uint16_t ipv4_id = 1234; // Just a random starting point


int main()
{
    setlocale(LC_ALL, "");
    debug("Hello World!\n");

    pcap_t *handle;

    handle = initialize_pcap();

    if (handle == NULL){
        printf("Error initializing pcap: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("\nStarting packet capture loop...\n");

    // pcap_loop(handle, 0, packet_handler, (uint8_t *)handle);

    // Custom loop for timeout/retry support
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;
    while (1) {
        res = pcap_next_ex(handle, &header, &pkt_data);
        if (res == 1) {
            // Got a packet
            packet_handler((uint8_t *)handle, header, pkt_data);
        } else if (res == 0) {
            // Timeout, fall through to check sessions
        } else if (res == -1) {
            printf("Error reading packet: %s\n", pcap_geterr(handle));
            break;
        } else if (res == -2) {
            // EOF
            break;
        }

        session_check(handle);

        // Sleep(100); // avoid busy loop
    }

    pcap_close(handle);
    return 0;
}
