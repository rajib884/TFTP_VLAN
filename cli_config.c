#include "cli_config.h"
#include "pcap_fun.h"
#include "fast_log.h"

#include <stdio.h>
#include <io.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <pcap.h>

int terminal_supports_color(void)
{
    if (!_isatty(_fileno(stdout)))
        return 0;

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE || hOut == NULL)
        return 0;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode))
        return 0;

    if (dwMode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        return 1;

    // Try to enable virtual terminal processing
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (SetConsoleMode(hOut, dwMode))
        return 1;

    return 0;
}

/* Initialize configuration with defaults */
void config_init_defaults(cli_config_t *config)
{
    if (!config) return;
    
    memset(config, 0, sizeof(cli_config_t));
    config->ip_port = REQUEST_PORT;
    config->verbose = 0;
    config->listen_port_start = START_PORT;
    config->listen_port_end = START_PORT + MAX_SESSIONS + 1000;
    config->max_block_size = MAX_BLOCK_SIZE;
    config->default_block_size = DEFAULT_BLOCK_SIZE;
    config->force_block_size = 0; /* 0 = disabled (not forced) */
}

/* Parse IP string (dotted decimal) to uint32 in network byte order */
uint32_t parse_ip_string(const char *ip_str)
{
    if (!ip_str) return 0;
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) == 1) {
        return addr.s_addr;  /* Network byte order */
    }
    return 0;
}

/* Print a list of available interfaces */
void config_list_interfaces(const char *program_name)
{
    devices_t *devs = NULL, *dev = NULL;
    int count = 0;
    const char *prog = program_name ? program_name : "tftp";
    char ip_str[16];

    LOG_PRINTF(LOG_INFO, "Available Network Interfaces:\n\n");

    devs = get_devices();
    if (devs == NULL) {
        LOG_PRINTF(LOG_INFO, "No network interfaces found.\n");
        return;
    }

    for (dev = devs, count = 1; dev != NULL; dev = dev->next, count++) {
        if (dev->name) {
            inet_ntop(AF_INET, &dev->ip, ip_str, sizeof(ip_str));
            LOG_PRINTF(LOG_INFO, "%d. %s\n", count, dev->name);
            if (dev->dev_desc) LOG_PRINTF(LOG_VERBOSE, "   Description: %s\n", dev->dev_desc);
            LOG_PRINTF(LOG_INFO, "   IP Address: %s\n", ip_str);
            if (dev->dev_name) LOG_PRINTF(LOG_VERBOSE, "   Device: %s\n", dev->dev_name);
            LOG_PRINTF(LOG_VERBOSE, "   MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                dev->mac[0], dev->mac[1], dev->mac[2], 
                dev->mac[3], dev->mac[4], dev->mac[5]);
            LOG_PRINTF(LOG_INFO, "   Sample commands:\n");
            LOG_PRINTF(LOG_INFO, "     %s -i \"%s\" -a %s\n", prog, dev->name, ip_str);
            if (dev->dev_name) LOG_PRINTF(LOG_VERBOSE, "     %s -i \"%s\" -a %s\n", prog, dev->dev_name, ip_str);
        }
    }

    free_devs(devs);
}

/* Parse CLI arguments */
int config_parse_cli(int argc, char *argv[], cli_config_t *config)
{
    if (!config) return FALSE;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            config_print_help(argv[0]);
            return FALSE;
        }
        else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
            config_list_interfaces(argv[0]);
            return FALSE;
        }
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            if (i + 1 >= argc) {
                LOG_PRINTF(LOG_ERROR, "Error: -i/--interface requires an argument\n");
                return FALSE;
            }
            strncpy(config->interface_identifier, argv[++i], sizeof(config->interface_identifier) - 1);
        }
        else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--address") == 0) {
            if (i + 1 >= argc) {
                LOG_PRINTF(LOG_ERROR, "Error: -a/--address requires an argument\n");
                return FALSE;
            }
            config->ip_address = parse_ip_string(argv[++i]);
            if (!config->ip_address) {
                LOG_PRINTF(LOG_ERROR, "Error: invalid IP address: %s\n", argv[i]);
                return FALSE;
            }
        }
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 >= argc) {
                LOG_PRINTF(LOG_ERROR, "Error: -p/--port requires an argument\n");
                return FALSE;
            }
            config->ip_port = atoi(argv[++i]);
            if (config->ip_port == 0 || config->ip_port > UINT16_MAX){
                LOG_PRINTF(LOG_ERROR, "Error: invalid IP port: %s\n", argv[i]);
                return FALSE;
            }
        }
        else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--root") == 0) {
            if (i + 1 >= argc) {
                LOG_PRINTF(LOG_ERROR, "Error: -r/--root requires an argument\n");
                return FALSE;
            }
            LOG_PRINTF(LOG_INFO, "-r/--root option not yet implemented!\n");
            i++;
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            config->verbose++;
            LOG_PRINTF(LOG_DEBUG, "-v/--verbose option not yet implemented!\n");
        }
        else if (strcmp(argv[i], "--max-block-size") == 0) {
            if (i + 1 >= argc) {
                LOG_PRINTF(LOG_ERROR, "Error: --max-block-size requires an argument\n");
                return FALSE;
            }
            uint16_t max_blksize = (uint16_t)atoi(argv[++i]);
            if (max_blksize < MIN_BLOCK_SIZE || max_blksize > MAX_BLOCK_SIZE) {
                LOG_PRINTF(LOG_ERROR, "Error: --max-block-size must be between %u and %u\n", MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
                return FALSE;
            }
            config->max_block_size = max_blksize;
        }
        else if (strcmp(argv[i], "--default-block-size") == 0) {
            if (i + 1 >= argc) {
                LOG_PRINTF(LOG_ERROR, "Error: --default-block-size requires an argument\n");
                return FALSE;
            }
            uint16_t def_blksize = (uint16_t)atoi(argv[++i]);
            if (def_blksize < MIN_BLOCK_SIZE || def_blksize > MAX_BLOCK_SIZE) {
                LOG_PRINTF(LOG_ERROR, "Error: --default-block-size must be between %u and %u\n", MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
                return FALSE;
            }
            config->default_block_size = def_blksize;
        }
        else if (strcmp(argv[i], "--force-block-size") == 0) {
            if (i + 1 >= argc) {
                LOG_PRINTF(LOG_ERROR, "Error: --force-block-size requires an argument\n");
                return FALSE;
            }
            uint16_t force_blksize = (uint16_t)atoi(argv[++i]);
            if (force_blksize < MIN_BLOCK_SIZE || force_blksize > MAX_BLOCK_SIZE) {
                LOG_PRINTF(LOG_ERROR, "Error: --force-block-size must be between %u and %u\n", MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
                return FALSE;
            }
            config->force_block_size = force_blksize;
        }
        else {
            LOG_PRINTF(LOG_ERROR, "Error: unknown option: %s\n", argv[i]);
            return FALSE;
        }
    }
    
    return TRUE;
}

/* Parse configuration file (simple key=value format) */
int config_parse_file(const char *filename, cli_config_t *config)
{
    FILE *f;
    char line[512];
    char key[256], value[256];
    
    if (!filename || !config) {
        return FALSE;
    }
    
    f = fopen(filename, "r");
    if (!f) {
        LOG_PRINTF(LOG_VERBOSE, "Config file not found: %s (using default values)\n", filename);
        return FALSE;
    }
    
    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == ';' || line[0] == '\n') {
            continue;
        }
        
        /* Remove trailing newline */
        line[strcspn(line, "\n")] = 0;
        line[strcspn(line, "\r")] = 0;
        
        /* Parse key=value */
        if (sscanf(line, "%255[^=]=%255s", key, value) == 2) {
            /* Trim whitespace */
            key[strcspn(key, " \t")] = 0;
            
            if (strcmp(key, "interface") == 0 && strlen(value) > 0) {
                strncpy(config->interface_identifier, value, sizeof(config->interface_identifier) - 1);
            }
            else if (strcmp(key, "address") == 0 && strlen(value) > 0) {
                config->ip_address = parse_ip_string(value);
            }
            else if (strcmp(key, "verbose") == 0) {
                config->verbose = atoi(value);
            }
        }
    }
    
    fclose(f);
    LOG_PRINTF(LOG_INFO, "Config file loaded: %s\n", filename);
    return TRUE;
}

/* Load config: CLI args > config file > defaults */
int config_load(int argc, char *argv[], const char *default_config_file, cli_config_t *config)
{
    if (!config) return FALSE;
    
    /* Start with defaults */
    config_init_defaults(config);
    
    /* Try to load config file */
    if (default_config_file) {
        config_parse_file(default_config_file, config);
    }
    
    /* Parse CLI arguments */
    if (!config_parse_cli(argc, argv, config)) {
        return FALSE;
    }
    
    return TRUE;
}

/* Print help/usage */
void config_print_help(const char *program_name)
{
    const char *prog = program_name ? program_name : "tftp";

    LOG_PRINTF(LOG_INFO, "TFTP Server\n\n");
    LOG_PRINTF(LOG_INFO, "Usage: %s [OPTIONS]\n\n", prog);

    LOG_PRINTF(LOG_INFO, "Options:\n");
    LOG_PRINTF(LOG_INFO, "  -i, --interface <name>       Interface name or GUID\n");
    LOG_PRINTF(LOG_INFO, "  -a, --address <ip>           IP address to use\n");
    LOG_PRINTF(LOG_INFO, "  -p, --port <port>            UDP port (default: 69)\n");
    LOG_PRINTF(LOG_INFO, "  -r, --root <dir>             Root directory (default: current)\n");
    LOG_PRINTF(LOG_INFO, "  -v, --verbose                Enable verbose logging\n");
    LOG_PRINTF(LOG_INFO, "  --max-block-size <size>      Maximum block size in bytes (8-65535, default: 65535)\n");
    LOG_PRINTF(LOG_INFO, "  --default-block-size <size>  Default block size if client doesn't specify (default: 512)\n");
    LOG_PRINTF(LOG_INFO, "  --force-block-size <size>    Force all transfers to use this block size (default: disabled)\n");
    LOG_PRINTF(LOG_INFO, "  -l, --list                   List all available interfaces and exit\n");
    LOG_PRINTF(LOG_INFO, "  -h, --help                   Show this help and exit\n\n");

    LOG_PRINTF(LOG_INFO, "Selection rules:\n");
    LOG_PRINTF(LOG_INFO, "  * If --interface is given, that interface is selected.\n");
    LOG_PRINTF(LOG_INFO, "  * If --address is given, an interface in the same subnet is\n");
    LOG_PRINTF(LOG_INFO, "    selected.\n");
    LOG_PRINTF(LOG_INFO, "  * If the given address differs from the selected interface's\n");
    LOG_PRINTF(LOG_INFO, "    primary IP, it will spoof that address on that interface.\n");
    LOG_PRINTF(LOG_INFO, "  * If neither is given, the user is asked to select interface\n\n");
    //first suitable interface is used.\n");
    
    LOG_PRINTF(LOG_INFO, "Examples:\n");
    LOG_PRINTF(LOG_INFO, "  %s --interface Ethernet\n", prog);
    LOG_PRINTF(LOG_INFO, "  %s --address 170.170.170.170\n", prog);
    LOG_PRINTF(LOG_INFO, "  %s -i Ethernet -a 170.170.170.170\n", prog);
}

/* Print current configuration */
void config_print(cli_config_t *config)
{
    if (!config) return;
    
    LOG_PRINTF(LOG_INFO, "\nCurrent Configuration:\n");
    LOG_PRINTF(LOG_INFO, "  Interface: %s\n", strlen(config->interface_identifier) > 0 ? config->interface_identifier : "(auto-select)");
    
    LOG_PRINTF(LOG_INFO, "  IP: %s:%u%s\n", inet_ntoa(*(struct in_addr *)&config->ip_address), config->ip_port, (config->is_spoofing)?" (spoofing)":"");


    LOG_PRINTF(LOG_INFO, "  Verbose: %d\n", config->verbose);
    if (config->force_block_size > 0)
        LOG_PRINTF(LOG_INFO, "  Block Size: %u bytes (FORCED)\n", config->force_block_size);
    else
        LOG_PRINTF(LOG_INFO, "  Block Size: %u bytes default, %u bytes max\n", config->default_block_size, config->max_block_size);
}
