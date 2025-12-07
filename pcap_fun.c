#include <wchar.h>
#include <locale.h>

#include "pcap_fun.h"


int get_ip_mac_name(const char *interface_name, ip_mac_name_t *info)
{
    ULONG bufferSize = 0;
    DWORD result;
    int found = FALSE;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;

    if (!info){
        return FALSE;
    }

    // First call to get buffer size
    result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &bufferSize);
    if (result == ERROR_BUFFER_OVERFLOW)
    {
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
        if (!pAddresses)
        {
            debug("Memory allocation failed.\n");
            return UNKNOWN_ERROR;
        }
        // Retrieve adapter information
        result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &bufferSize);
    }

    if (result != ERROR_SUCCESS)
    {
        debug("Error: %lu\n", result);
        free(pAddresses);
        return UNKNOWN_ERROR;
    }

    // Iterate through adapters
    PIP_ADAPTER_ADDRESSES pCurrent = pAddresses;
    while (pCurrent)
    {
        if (pCurrent->PhysicalAddressLength == 6 && strcmp(pCurrent->AdapterName, interface_name + 12) == 0)
        {
            // wprintf(L"Name: %ls, ", pCurrent->FriendlyName);
            wcsncpy(info->name, pCurrent->FriendlyName, sizeof(info->name) / sizeof(info->name[0]));
            info->name[sizeof(info->name) / sizeof(info->name[0]) - 1] = L'\0';

            memcpy(info->mac, pCurrent->PhysicalAddress, sizeof(info->mac));

            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrent->FirstUnicastAddress;
            for (; pUnicast != NULL; pUnicast = pUnicast->Next)
            {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                {
                    break;
                }
            }
            info->ip = ((struct sockaddr_in *)pUnicast->Address.lpSockaddr)->sin_addr.s_addr;
            found = TRUE;
            break;
        }
        pCurrent = pCurrent->Next;
    }

    free(pAddresses);

    return found;
}

pcap_t *initialize_pcap()
{
    pcap_if_t *alldevs, *dev;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_exp[1000] = "";
    char filter_exp_part[400] = "";
    bpf_u_int32 net;

    int rc = 0;

    debug("Finding devices...\n");

    ip_mac_name_t infos[99] = {0};

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        printf("Error finding devices: %s\n", errbuf);
        goto err;
    }

    int info_len = 0, i = 0;
    for (dev = alldevs; dev; dev = dev->next)
    {
        debug("  Checking %-50s\n", dev->name);
        if (info_len >= sizeof(infos) / sizeof(infos[0]) - 1)
        {
            printf("Too many devices, some are not listed...\n");
            break;
        }

        if (get_ip_mac_name(dev->name, &infos[info_len]) != TRUE)
        {
            debug("    IP  : Unknown\n");
            debug("    Name: Unknown\n");
            debug("    Desc: %s\n\n", dev->description ? dev->description : "(No description available)");

            continue;
        } 
        else 
        {
#ifdef DEBUG
            debug("    IP  : %s\n", inet_ntoa(*(struct in_addr *)&infos[info_len].ip));
            wprintf(L"    Name: %ls\n", infos[info_len].name);
            debug("    Desc: %s\n\n", dev->description ? dev->description : "(No description available)");
#endif
        }
            
        if (pcap_lookupnet(dev->name, &infos[info_len].ip_mask, &infos[info_len].mask, errbuf) == -1)
        {
            infos[info_len].ip_mask = 0;
            infos[info_len].mask = 0;
        }

        infos[info_len].dev = dev;

        info_len++;
        
    }

    if (info_len == 0)
    {
        printf("No interfaces found.\n");
        goto err;
    }

    debug("\n");

    /* Auto-select "Ethernet" if present */
    for (i = 0, rc = 0; i < info_len; i++)
    {
        if (wcscmp(infos[i].name, L"Ethernet") == 0 || info_len == 1)
        {
            rc = 1;
            wprintf(L"Auto-selected %ls, ", infos[i].name);
            printf("%s\n", inet_ntoa(*(struct in_addr *)&infos[i].ip));
            i++; // Selection is i+1 for user
            break;
        }
    }

    if (!rc) // Did not auto select, let user choose interface
    {    
        printf("Select an interface:\n"); 
        for (i = 0; i < info_len; i++)
        {
            printf("%2d:", i + 1);
            printf(" %-16s", inet_ntoa(*(struct in_addr *)&infos[i].ip));
            wprintf(L", %-25ls", infos[i].name);
            debug("\t %-50s", infos[i].dev->name);
            debug(",\t %s", infos[i].dev->description ? infos[i].dev->description : "(No description available)");
            printf("\n");
        }
        printf("Enter interface (number): ");
        rc = scanf("%d", &i);
    }

    if (!rc || (i < 1) || (info_len < i))
    {
        printf("Invalid choice.\n");
        goto err;
    }
    
    dev = infos[i - 1].dev;
    memcpy(MY_MAC, infos[i - 1].mac, 6);
#ifdef SPOOF_NON_VLAN
    // Move some IP address, so I don't conflict with myself
    infos[i - 1].ip += ntohl(0x0a);
#endif
    MY_IP = ntohl(infos[i - 1].ip);
    net = infos[i - 1].ip_mask;

    printf("\nSelected interface:\n");
    printf("  IP    : %s/%d\n", inet_ntoa(*(struct in_addr *)&infos[i - 1].ip), __builtin_popcount(infos[i - 1].mask));
    debug("  Mask  : %s\n", inet_ntoa(*(struct in_addr *)&infos[i - 1].mask));
    wprintf(L"  Name  : %ls\n", infos[i - 1].name);
    printf("  Desc. : %s\n", infos[i - 1].dev->description ? infos[i - 1].dev->description : "");
    debug("  GUID  : %s\n", infos[i - 1].dev->name);
    // printf("  Network   : %s\n", inet_ntoa(*(struct in_addr *)&infos[i - 1].ip_mask));


    wprintf(L"\nInitializing %ls [%s]... ", infos[i - 1].name, dev->name);
    handle = pcap_create(dev->name, errbuf);
    if (!handle)
    {
        fprintf(stderr, "Error creating pcap handle: %s\n", errbuf);
        goto err;
    }

    if (pcap_set_snaplen(handle, 65536) != 0 ||
        pcap_set_promisc(handle, 1) != 0 ||
        pcap_set_timeout(handle, 500) != 0 ||
        pcap_set_immediate_mode(handle, 1) != 0)
    {
        fprintf(stderr, "Error setting pcap options: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        handle = NULL;
        goto err;
    }

    if (pcap_activate(handle) != 0)
    {
        fprintf(stderr, "Error activating pcap handle: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        handle = NULL;
        goto err;
    }

    snprintf(filter_exp_part, sizeof(filter_exp_part),
             "(arp and arp[6:2] = 1 and arp[24:4] = 0x%08X) or (ip and dst host %s and ((icmp and icmp[0] = 8) or (udp and (udp dst port 69 or (udp dst portrange %d-%d)))))",
             (unsigned int)htonl(infos[i - 1].ip),
             inet_ntoa(*(struct in_addr *)&infos[i - 1].ip), START_PORT, START_PORT + MAX_SESSIONS);
    snprintf(filter_exp, sizeof(filter_exp),"(%s) or (vlan and (%s))", filter_exp_part, filter_exp_part);


    debug("\nFilter: %s\n  ", filter_exp);

    if (pcap_compile(handle, &filter, filter_exp, 0, net) == -1 ||
        pcap_setfilter(handle, &filter) == -1)
    {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        goto err;
    }


    debug("done\n");

    return handle;

err:
    pcap_freealldevs(alldevs);
    return NULL;
}

