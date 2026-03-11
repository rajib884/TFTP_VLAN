#include <wchar.h>
#include <locale.h>

#include "pcap_fun.h"
#include "cli_config.h"
#include "fast_log.h"

devices_t *get_devices()
{
    devices_t *head = NULL;
    devices_t *curr = NULL;
    size_t str_len = 0;

    pcap_if_t *alldevs = NULL;
    pcap_if_t *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    ULONG bufferSize = 0;
    DWORD result = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurrent = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;

    // First call to get bufferSize
    result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &bufferSize);
    if (result == ERROR_BUFFER_OVERFLOW) {
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
        if (!pAddresses) goto err;
        // Retrieve adapter information
        result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &bufferSize);
    }

    if (result != ERROR_SUCCESS) goto err;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) goto err;
    for (dev = alldevs; dev; dev = dev->next){
        curr = (devices_t *)malloc(sizeof(devices_t));
        if (curr == NULL) break;
        memset(curr, 0, sizeof(devices_t));

        pCurrent = pAddresses;
        for (; pCurrent != NULL; pCurrent = pCurrent->Next) {
            if (pCurrent->OperStatus != IfOperStatusUp) continue;
            if (pCurrent->PhysicalAddressLength == 6 && strcmp(pCurrent->AdapterName, dev->name + 12) == 0) {
                pUnicast = pCurrent->FirstUnicastAddress;
                for (; pUnicast != NULL; pUnicast = pUnicast->Next){
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) break;
                }
                if (pUnicast) {
                    curr->ip = ((struct sockaddr_in *)pUnicast->Address.lpSockaddr)->sin_addr.s_addr;
                    curr->mask = (pUnicast->OnLinkPrefixLength == 0) ? 0 : htonl(~0u << (32 - pUnicast->OnLinkPrefixLength));
                    curr->mtu = pCurrent->Mtu;
                    // wcsncpy(curr->name, pCurrent->FriendlyName, sizeof(curr->name) / sizeof(curr->name[0]));
                    // curr->name[sizeof(curr->name) / sizeof(curr->name[0]) - 1] = L'\0';
                    if (pCurrent->FriendlyName) {
                        str_len = WideCharToMultiByte(CP_UTF8, 0, pCurrent->FriendlyName, -1, NULL, 0, NULL, NULL);
                        
                        if (str_len > 0) {
                            curr->name = (char *)malloc(str_len);
                            if (curr->name) WideCharToMultiByte(CP_UTF8, 0, pCurrent->FriendlyName, -1, curr->name, str_len, NULL, NULL);
                        }
                        // str_len = wcslen(pCurrent->FriendlyName) + 1;
                        // curr->name = (wchar_t *)malloc(str_len * sizeof(wchar_t));
                        // if (curr->name) wcsncpy(curr->name, pCurrent->FriendlyName, str_len);
                    }
                    memcpy(curr->mac, pCurrent->PhysicalAddress, sizeof(curr->mac));
                    // strncpy(curr->dev_name, dev->name, sizeof(curr->dev_name));
                    // curr->dev_name[sizeof(curr->dev_name) - 1] = '\0';
                    if (dev->name) {
                        str_len = strlen(dev->name) + 1;
                        curr->dev_name = (char *)malloc(str_len);
                        if (curr->dev_name) strncpy(curr->dev_name, dev->name, str_len);
                    }
                    // strncpy(curr->dev_desc, dev->description, sizeof(curr->dev_desc));
                    // curr->dev_desc[sizeof(curr->dev_desc) - 1] = '\0';
                    if (dev->description) {
                        str_len = strlen(dev->description) + 1;
                        curr->dev_desc = (char *)malloc(str_len);
                        if (curr->dev_desc) strncpy(curr->dev_desc, dev->description, str_len);
                    }
                    break;
                }
            }
        }

        if (curr->ip && curr->dev_name && curr->name){
            curr->next = head;
            head = curr;
        } else {
            free(curr->dev_desc);
            free(curr->dev_name);
            free(curr->name);
            free(curr);
            curr = NULL;
        }
    }

err:
    if (alldevs) pcap_freealldevs(alldevs);
    if (pAddresses) free(pAddresses);
    return head;
}

devices_t *select_device(devices_t *devs, cli_config_t *config)
{
    devices_t *selected = NULL;

    if (devs == NULL || config == NULL) return NULL;

    if (config->interface_identifier[0] != '\0')
    {
        for (selected = devs; selected != NULL; selected = selected->next)
        {
            if (
                strcmp(selected->name, config->interface_identifier) == 0 ||
                strcmp(selected->dev_name, config->interface_identifier) == 0)
            {
                if (config->ip_address == 0)
                    config->ip_address = selected->ip;
                config->is_spoofing = (selected->ip != config->ip_address);
                config->interface_ip = selected->ip;
                return selected;
            }
        }
    }
    else if (config->ip_address != 0)
    {
        for (selected = devs; selected != NULL; selected = selected->next)
        {
            if ((selected->ip & selected->mask) == (config->ip_address & selected->mask))
            {
                strncpy(config->interface_identifier, selected->name, sizeof(config->interface_identifier));
                config->interface_identifier[sizeof(config->interface_identifier) - 1] = '\0';
                config->is_spoofing = (selected->ip != config->ip_address);
                config->interface_ip = selected->ip;
                return selected;
            }
        }
    }
    return NULL;
}

devices_t *choose_device(devices_t *devs, cli_config_t *config)
{
    devices_t *selected = NULL;
    size_t i = 0, len = 0;
    
    if (devs == NULL || config == NULL) return NULL;
    
    LOG_PRINTF(LOG_NONE, "Select an interface:\n");
    for (selected = devs, i = 1, len = 0; selected != NULL; selected = selected->next, i++, len++)
    {
        LOG_PRINTF(LOG_NONE, "%2lld:", i);
        LOG_PRINTF(LOG_NONE, " %16s/%u", inet_ntoa(*(struct in_addr *)&selected->ip), __builtin_popcount(selected->mask));
        LOG_PRINTF(LOG_NONE, ", %-25s", selected->name);
        LOG_PRINTF(LOG_VERBOSE, "\t %-50s", selected->dev_name);
        LOG_PRINTF(LOG_VERBOSE, ",\t %s", selected->dev_desc ? selected->dev_desc : "(No description available)");
        LOG_PRINTF(LOG_NONE, "\n");
    }

    LOG_PRINTF(LOG_NONE, "Enter interface (number): ");
    log_flush();
    if (scanf("%lld", &i) == 0 || (i < 1) || (i > len))
    {
        LOG_PRINTF(LOG_NONE, "Invalid choice\n");
        return NULL;
    }

    selected = devs;
    while (--i > 0) selected = selected->next;

    if (selected) {
        strncpy(config->interface_identifier, selected->name, sizeof(config->interface_identifier));
        config->interface_identifier[sizeof(config->interface_identifier) - 1] = '\0';
        if (config->ip_address == 0) config->ip_address = selected->ip;
        config->is_spoofing = (selected->ip != config->ip_address);
        config->interface_ip = selected->ip;
        return selected;
    }

    return NULL;
}

void free_devs(devices_t *h){
    devices_t *next = NULL;
    while (h != NULL){
        next = h->next;
        free(h->dev_desc);
        free(h->dev_name);
        free(h->name);
        free(h);
        h = next;
    }
}

pcap_t *get_pcap_handle(devices_t *dev, cli_config_t *config){
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    struct bpf_program filter = {0};
    char filter_exp[1000] = "";
    char filter_exp_part[400] = "";

    if (dev == NULL || config == NULL)  return NULL;

    memcpy(config->MY_MAC, dev->mac, sizeof(config->MY_MAC));
    config->mtu = dev->mtu;

    handle = pcap_create(dev->dev_name, errbuf);
    if (!handle) {
        LOG_PRINTF(LOG_ERROR, "Error creating pcap handle: %s\n", errbuf);
        goto err;
    }

    if (pcap_set_snaplen(handle, 65536) != 0 ||
        pcap_set_promisc(handle, 1) != 0 ||
        pcap_set_timeout(handle, 1) != 0 ||
        pcap_set_immediate_mode(handle, 1) != 0)
    {
        LOG_PRINTF(LOG_ERROR, "Error setting pcap options: %s\n", pcap_geterr(handle));
        goto err;
    }

    if (pcap_activate(handle) != 0) {
        LOG_PRINTF(LOG_ERROR, "Error activating pcap handle: %s\n", pcap_geterr(handle));
        goto err;
    }

    snprintf(filter_exp_part, sizeof(filter_exp_part),
             "(arp and arp[6:2] = 1 and arp[24:4] = 0x%08X) or (ip and dst host %s and ((icmp and icmp[0] = 8) or (udp and (udp dst port %u or (udp dst portrange %d-%d)))))",
             (unsigned int)htonl(config->ip_address),
             inet_ntoa(*(struct in_addr *)&config->ip_address), config->ip_port, config->listen_port_start, config->listen_port_end);
    snprintf(filter_exp, sizeof(filter_exp), "(%s) or (vlan and (%s))", filter_exp_part, filter_exp_part);

    LOG_PRINTF(LOG_VERBOSE, "Filter: %s\n  ", filter_exp);

    if (pcap_compile(handle, &filter, filter_exp, 0, (bpf_u_int32)dev->mask) == -1 ||
        pcap_setfilter(handle, &filter) == -1) {
        LOG_PRINTF(LOG_ERROR, "Error setting filter: %s\n", pcap_geterr(handle));
        goto err;
    }

    return handle;

err:
    if (handle != NULL) pcap_close(handle);
    handle = NULL;
    return NULL;
}

