#include <winsock2.h>
#include <windows.h>
#include <wchar.h>
#include <locale.h>
#include <ws2tcpip.h>

#include "pcap_fun.h"
#include "packet.h"
#include "tftp.h"
#include "ftp_handler.h"
#include "cli_config.h"
#include "fast_log.h"

uint16_t ipv4_id = 1234; // Just a random starting point
cli_config_t config = {0};
int use_color = 0;


int main(int argc, char *argv[])
{
    int run = TRUE;
    pcap_t *handle = NULL;
    
    /* Event handles array: [0] = pcap, [1..MAX_FTP_DOWNLOADS] = FTP sockets */
    HANDLE waitHandles[1 + MAX_FTP_DOWNLOADS + 1 + DB_MAX_CLIENTS] = {0};
    int totalHandles = 0;
    long timeout_ms = 0;
    DWORD rc = 0;

    devices_t *devs = NULL;
    devices_t *selected = NULL;

    struct pcap_pkthdr *header = NULL;
    const u_char *pkt_data = NULL;
    int res = 0;

    setlocale(LC_ALL, "");
    log_init(NULL, LOG_INFO); // Logging to console

    use_color = terminal_supports_color();

    /* ASCII Banner */
    LOG_PRINTF(LOG_INFO, "%s==================================================%s\n", CLR_BLUE, CLR_RESET);
    LOG_PRINTF(LOG_INFO, "%s      ___       ____        __  __  _____     %s\n", CLR_CYAN, CLR_RESET);
    LOG_PRINTF(LOG_INFO, "%s     / _ )__ __/ / /  __ __/ / / /_/ _/ /____ %s\n", CLR_CYAN, CLR_RESET);
    LOG_PRINTF(LOG_INFO, "%s    / _  / // / / _ \\/ // / / / __/ _/ __/ _ \\%s\n", CLR_CYAN, CLR_RESET);
    LOG_PRINTF(LOG_INFO, "%s   /____/\\_,_/_/_.__/\\_,_/_/  \\__/_/ \\__/ .__/%s\n", CLR_CYAN, CLR_RESET);
    LOG_PRINTF(LOG_INFO, "%s                                       /_/    %s\n", CLR_CYAN, CLR_RESET);
    LOG_PRINTF(LOG_INFO, "%s==================================================%s\n", CLR_BLUE, CLR_RESET);
    log_flush();

    // Used to prevent multiple instance in the same device, even with multiple users
    HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\BulBulTFTPMutex");
    
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        LOG_PRINTF(LOG_NONE, "Another instance is already running in this device.\nPress Enter to exit...\n");
        log_flush();
        getchar();
        CloseHandle(hMutex);
        return 1;
    }

    /* Parse CLI configuration and config file */
    if (!config_load(argc, argv, "tftp.conf", &config))
    {
        goto cleanup;
    }

    if (config.verbose)
        log_set_level(LOG_VERBOSE);
    
    tftp_get_free_port(NULL, NULL);

    if (ftp_handler_init() != 0)
    {
        LOG_PRINTF(LOG_ERROR, "FTP handler init failed\n");
        goto cleanup;
    }
    
    devs = get_devices();
    if (config.interface_identifier[0] == '\0')
    {
        selected = choose_device(devs, &config);
        if (selected == NULL) {
            LOG_PRINTF(LOG_INFO, "No Interface Selected\n");
            goto cleanup;
        }
    }
    else
    {
        selected = select_device(devs, &config);
        if (selected == NULL) {
            LOG_PRINTF(LOG_INFO, "Given Interface not Found\n");
            goto cleanup;
        }
    }

    handle = get_pcap_handle(selected, &config);

    if (config.verbose) {
        config_print(&config);
    }

    if (handle == NULL){
        LOG_PRINTF(LOG_ERROR, "Error initializing pcap: %s\n", pcap_geterr(handle));
        goto cleanup;
    }

    waitHandles[0] = pcap_getevent(handle);
    if (!waitHandles[0])
    {
        LOG_PRINTF(LOG_ERROR, "Failed to get pcap event handle\n");
        goto cleanup;
    }

    /* Info */
    LOG_PRINTF(LOG_INFO, "\n");
    LOG_PRINTF(LOG_INFO, "%s--------------------------------------------------%s\n", CLR_BLUE, CLR_RESET);
    LOG_PRINTF(LOG_INFO, "  %sTFTP Server Initialized%s\n", CLR_BOLD, CLR_RESET);
    LOG_PRINTF(LOG_INFO, "%s--------------------------------------------------%s\n", CLR_BLUE, CLR_RESET);
    LOG_PRINTF(LOG_INFO, "  %sAddress   :%s %s%s\n", CLR_BOLD, CLR_RESET, inet_ntoa(*(struct in_addr *)&config.ip_address), config.is_spoofing ? " (spoofing)": "");
    LOG_PRINTF(LOG_INFO, "  %sInterface :%s %s (%s/%u)\n", CLR_BOLD, CLR_RESET, selected->name, inet_ntoa(*(struct in_addr *)&selected->ip), __builtin_popcount(selected->mask));
    if (config.verbose) {
        LOG_PRINTF(LOG_INFO, "  %sMTU       :%s %u bytes\n", CLR_BOLD, CLR_RESET, config.mtu);
        LOG_PRINTF(LOG_INFO, "  %sMAC Addr  :%s ", CLR_BOLD, CLR_RESET); print_mac(config.MY_MAC);
        LOG_PRINTF(LOG_INFO, "  %sGUID      :%s %s\n", CLR_BOLD, CLR_RESET, selected->dev_name);
        LOG_PRINTF(LOG_INFO, "  %sDesc.     :%s %s\n", CLR_BOLD, CLR_RESET, selected->dev_desc ? selected->dev_desc : "");
    }
    LOG_PRINTF(LOG_INFO, "  %sListening :%s UDP:%u, ARP, ICMP\n", CLR_BOLD, CLR_RESET, config.ip_port);
    LOG_PRINTF(LOG_INFO, "%s--------------------------------------------------%s\n", CLR_BLUE, CLR_RESET);
    LOG_PRINTF(LOG_INFO, "  %sStatus    : %sReady...%s\n", CLR_BOLD, CLR_GREEN, CLR_RESET);
    LOG_PRINTF(LOG_INFO, "\n");
    
    free_devs(devs);
    devs = NULL;

    timer_init(&processing_timer);

    while (run)
    {
        log_flush();

        int ftp_n = ftp_get_event_handles(&waitHandles[1], MAX_FTP_DOWNLOADS);
        int db_n  = dashboard_get_event_handles(&waitHandles[1 + ftp_n]);

        /* Get current event handles and recommended timeout from FTP */
        totalHandles = 1 + ftp_n + db_n;
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
                LOG_PRINTF(LOG_ERROR, "Error reading packet: %s\n", pcap_geterr(handle));
                break;

            case -2: // EOF
                run = FALSE;
                LOG_PRINTF(LOG_INFO, "End of packet capture.\n");
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
            LOG_PRINTF(LOG_ERROR, "WaitForMultipleObjects failed: %lu\n", GetLastError());
            run = FALSE;
            break;
        }

        timer_start(&processing_timer);
        ftp_download_poll();
        session_check(handle);
    }

cleanup:
    LOG_PRINTF(LOG_INFO, "%s: Exiting...\n", time_str());
    if (devs) free_devs(devs);
    clean_all_sessions();
    if (handle != NULL) {
        pcap_close(handle);
    }
    ftp_handler_cleanup();
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    log_close();

    return run;
}
