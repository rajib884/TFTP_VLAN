#ifndef FTP_HANDLER_H
#define FTP_HANDLER_H

#include <curl/curl.h>
#include <time.h>
#include <stddef.h>
#include <windows.h>
#include <packet.h>

#define MAX_FTP_DOWNLOADS MAX_SESSIONS

typedef struct
{
    long filetime;       // Unix timestamp, -1 if unavailable
    curl_off_t filesize; // 0 if unavailable
} ftp_metadata_t;

typedef struct
{
    char *data;          // Download buffer (pre-allocated)
    size_t size;         // Current downloaded size
    size_t capacity;     // Total buffer capacity (from metadata)
    
    int in_use;          // 1 if this slot is active, 0 if free
    int completed;       // 1 if download finished successfully
    int has_error;       // 1 if download failed
    char error_msg[256]; // Error message if has_error is set
    
    CURL *easy_handle;   // Internal curl handle
    char url[512];       // URL being downloaded
} ftp_download_t;

/* Init once */
int ftp_handler_init(void);

/* Fetch metadata for a single FTP URL (blocking, but fast) */
CURLcode ftp_get_metadata(const char *ftp_url, ftp_metadata_t *out_meta);

/* Request a file download - blocks for metadata, then starts async download
 * Returns: pointer to ftp_download_t on success, NULL on failure */
ftp_download_t* ftp_request_file(const char *url);

/* Get Windows event handles for all active downloads
 * Returns: number of handles filled (0 to MAX_FTP_DOWNLOADS) */
int ftp_get_event_handles(HANDLE *handles, int max_handles);

/* Get recommended timeout for WaitForMultipleObjects in milliseconds
 * Returns: timeout in ms (0 = call immediately) */
long ftp_get_timeout_ms(long timeout_ms_default);

/* Progress downloads - call when FTP event is signaled
 * Returns: number of active downloads remaining */
int ftp_download_poll(void);

/* Free a specific download by pointer */
void ftp_download_free(ftp_download_t *download);

/* Call once at program shutdown */
void ftp_handler_cleanup(void);

#endif /* FTP_HANDLER_H */
