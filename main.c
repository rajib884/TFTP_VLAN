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
    int run = TRUE;
    pcap_t *handle;
    
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;

    setlocale(LC_ALL, "");
    debug("Hello World!\n");

    // Used to prevent multiple instance in the same device, even with multiple users
    HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\BulBulTFTPMutex");
    
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        printf("Another instance is already running in this device.\nPress Enter to exit...\n");
        CloseHandle(hMutex);
        getchar();
        return 1;
    }

    handle = initialize_pcap();

    if (handle == NULL){
        printf("Error initializing pcap: %s\n", pcap_geterr(handle));
        goto cleanup;
    }


    printf("\nListening...\n");

    timer_init(&processing_timer);

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

        timer_start(&processing_timer);
        session_check(handle);
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
