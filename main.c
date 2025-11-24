#include <winsock2.h>
#include <windows.h>
#include <wchar.h>
#include <locale.h>

#include "pcap_fun.h"
#include "packet.h"
#include "tftp.h"

uint8_t MY_MAC[6] = {0};
uint32_t MY_IP = 0;
uint16_t ipv4_id = 1234; // Just a random starting point


int main()
{
    int run = 1;

    setlocale(LC_ALL, "");
    debug("Hello World!\n");

    HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\BulBulTFTPMutex");
    
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        printf("Another instance is already running in this device.\n");
        CloseHandle(hMutex);
        return 1;
    }

    pcap_t *handle;

    handle = initialize_pcap();

    if (handle == NULL){
        printf("Error initializing pcap: %s\n", pcap_geterr(handle));
        goto cleanup;
    }

    printf("\nListening...\n");

    // pcap_loop(handle, 0, packet_handler, (uint8_t *)handle);

    // Custom loop for timeout/retry support
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;

    while (run)
    {
        res = pcap_next_ex(handle, &header, &pkt_data);

        switch (res)
        {
        case 1: // Got a packet
            packet_handler((uint8_t *)handle, header, pkt_data);
            break;

        case 0: // Timeout, fall through to check sessions
            break;

        case -1: // Error
            printf("Error reading packet: %s\n", pcap_geterr(handle));
            break;

        case -2: // EOF
            run = 0;
            printf("End of packet capture.\n");
            break;

        default:
            break;
        }

        session_check(handle);

        // Sleep(100); // avoid busy loop
    }

cleanup:
    printf("Exiting...\n");
    clean_all_sessions();
    if (handle != NULL) {
        pcap_close(handle);
    }
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);

    return run;
}
