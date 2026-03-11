#ifndef CLI_CONFIG_H
#define CLI_CONFIG_H

#include <stdint.h>
#include <wchar.h>

extern int use_color;


#define CLR(code)  (use_color ? (code) : "")
#define CLR_RESET     CLR("\033[0m")
#define CLR_BOLD      CLR("\033[1m")
#define CLR_CYAN      CLR("\033[36m")
#define CLR_BLUE      CLR("\033[34m")
#define CLR_GREEN     CLR("\033[32m")
#define CLR_WHITE     CLR("\033[37m")
#define CLR_BLACK     CLR("\033[30m")
#define CLR_RED       CLR("\033[31m")
#define CLR_YELLOW    CLR("\033[33m")
#define CLR_MAGENTA   CLR("\033[35m")

#define CLR_BRIGHT_BLACK     CLR("\033[90m")
#define CLR_BRIGHT_RED       CLR("\033[91m")
#define CLR_BRIGHT_GREEN     CLR("\033[92m")
#define CLR_BRIGHT_YELLOW    CLR("\033[93m")
#define CLR_BRIGHT_BLUE      CLR("\033[94m")
#define CLR_BRIGHT_MAGENTA   CLR("\033[95m")
#define CLR_BRIGHT_CYAN      CLR("\033[96m")
#define CLR_BRIGHT_WHITE     CLR("\033[97m")

#define BG_BLACK     CLR("\033[40m")
#define BG_RED       CLR("\033[41m")
#define BG_GREEN     CLR("\033[42m")
#define BG_YELLOW    CLR("\033[43m")
#define BG_BLUE      CLR("\033[44m")
#define BG_MAGENTA   CLR("\033[45m")
#define BG_CYAN      CLR("\033[46m")
#define BG_WHITE     CLR("\033[47m")

#define BG_BRIGHT_BLACK     CLR("\033[100m")
#define BG_BRIGHT_RED       CLR("\033[101m")
#define BG_BRIGHT_GREEN     CLR("\033[102m")
#define BG_BRIGHT_YELLOW    CLR("\033[103m")
#define BG_BRIGHT_BLUE      CLR("\033[104m")
#define BG_BRIGHT_MAGENTA   CLR("\033[105m")
#define BG_BRIGHT_CYAN      CLR("\033[106m")
#define BG_BRIGHT_WHITE     CLR("\033[107m")

#define CLR_DIM        CLR("\033[2m")
#define CLR_ITALIC     CLR("\033[3m")
#define CLR_UNDERLINE  CLR("\033[4m")
#define CLR_BLINK      CLR("\033[5m")
#define CLR_REVERSE    CLR("\033[7m")
#define CLR_HIDDEN     CLR("\033[8m")
#define CLR_STRIKE     CLR("\033[9m")

/* Configuration structure */
typedef struct {
    int is_spoofing;
    uint32_t ip_address;               /* Parsed IP Address, Network Order */
    uint32_t ip_port;                  /* Parsed IP Port for RRQ/WRQ */
    uint16_t listen_port_start;
    uint16_t listen_port_end;
    uint16_t max_block_size;           /* Maximum configurable block size */
    uint16_t default_block_size;       /* Default block size if client doesn't request one */
    uint16_t force_block_size;         /* Force all transfers to use this block size (0 = disabled) */

    char interface_identifier[256];    /* Selected interface name*/
    uint32_t interface_ip;             /* Selected interface primary IP, Network Order */
    uint8_t MY_MAC[6];                 /* Selected interface MAC Address */
    int verbose;                       /* Verbosity level */
} cli_config_t;

int terminal_supports_color(void);

/* Initialize config with defaults */
void config_init_defaults(cli_config_t *config);

/* Parse CLI arguments */
int config_parse_cli(int argc, char *argv[], cli_config_t *config);

/* Parse configuration file */
int config_parse_file(const char *filename, cli_config_t *config);

/* Load config with priority: CLI args > config file > defaults */
int config_load(int argc, char *argv[], const char *default_config_file, cli_config_t *config);

/* Print current configuration */
void config_print(cli_config_t *config);

/* Print help/usage information */
void config_print_help(const char *program_name);

/* List available interfaces */
void config_list_interfaces(const char *program_name);

/* Convert IP string to uint32 network byte order */
uint32_t parse_ip_string(const char *ip_str);

#endif /* CLI_CONFIG_H */
