#include <winsock2.h>
#include <windows.h>
#include <wchar.h>
#include <locale.h>

#include "pcap_fun.h"
#include "packet.h"
#include "tftp.h"
#include "ftp_handler.h"

uint8_t MY_MAC[6] = {0};
uint32_t MY_IP = 0;
uint16_t ipv4_id = 1234; // Just a random starting point


int main()
{
    int run = TRUE;
    pcap_t *handle;
    
    /* Event handles array: [0] = pcap, [1..MAX_FTP_DOWNLOADS] = FTP sockets */
    HANDLE waitHandles[1 + MAX_FTP_DOWNLOADS];
    int totalHandles;
    long timeout_ms;
    DWORD rc;

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

    if (ftp_handler_init() != 0)
    {
        printf("FTP handler init failed\n");
        return 1;
    }


    handle = initialize_pcap();

    if (handle == NULL){
        printf("Error initializing pcap: %s\n", pcap_geterr(handle));
        goto cleanup;
    }

    waitHandles[0] = pcap_getevent(handle);
    if (!waitHandles[0])
    {
        printf("Failed to get pcap event handle\n");
        goto cleanup;
    }

    printf("\nListening...\n");

    timer_init(&processing_timer);

    while (run)
    {
        /* Get current event handles and recommended timeout from FTP */
        totalHandles = 1 + ftp_get_event_handles(&waitHandles[1], MAX_FTP_DOWNLOADS);
        timeout_ms = ftp_get_timeout_ms(1000);
        rc = WaitForMultipleObjects(totalHandles, waitHandles, FALSE, timeout_ms);

        if (rc == WAIT_OBJECT_0)
        {
            /* pcap has packets */
            while ((res = pcap_next_ex(handle, &header, &pkt_data)) == 1)
            {
                packet_handler((uint8_t *)handle, header, pkt_data);
            }

            switch (res)
            {
            case 0: // Timeout
                break;

            case -1: // Error
                printf("Error reading packet: %s\n", pcap_geterr(handle));
                break;

            case -2: // EOF
                run = FALSE;
                printf("End of packet capture.\n");
                break;

            default:
                break;
            }
        }
        else if (rc >= WAIT_OBJECT_0 + 1 && rc < WAIT_OBJECT_0 + totalHandles)
        {
            /* One of the FTP sockets has activity */
        }
        else if (rc == WAIT_TIMEOUT)
        {
            /* Periodic tasks */
        }
        else
        {
            printf("WaitForMultipleObjects failed: %lu\n", GetLastError());
            run = FALSE;
            break;
        }

        timer_start(&processing_timer);
        ftp_download_poll();
        session_check(handle);
    }

cleanup:
    printf("Exiting...\n");
    clean_all_sessions();
    if (handle != NULL) {
        pcap_close(handle);
    }
    ftp_handler_cleanup();
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);

    return run;
}
