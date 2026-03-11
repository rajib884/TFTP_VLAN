#include "ftp_handler.h"
#include "fast_log.h"

#include "packet.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>

static CURLM *multi = NULL;
static int curl_initialized = 0;
static ftp_download_t downloads[MAX_FTP_DOWNLOADS];
static WSAEVENT socket_events[MAX_FTP_DOWNLOADS];

/* Callback to write downloaded data into pre-allocated buffer */
static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    ftp_download_t *dl = (ftp_download_t *)userp;

    /* Check if we have space in the pre-allocated buffer */
    if (dl->size + realsize > dl->capacity) {
        /* This shouldn't happen if metadata was correct, but be safe */
        fprintf(stderr, "Warning: FTP download exceeds pre-allocated size\n");
        realsize = dl->capacity - dl->size;
        if (realsize == 0)
            return 0;
    }

    memcpy(dl->data + dl->size, contents, realsize);
    dl->size += realsize;

    debug("ftp dl: %zu/%zu %s\n", dl->size, dl->capacity, dl->url);

    return realsize;
}

/* Discard headers/body for metadata requests */
static size_t throw_away(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

int ftp_handler_init(void)
{
    CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
    if (res != CURLE_OK)
        return -1;
    
    multi = curl_multi_init();
    if (!multi) {
        curl_global_cleanup();
        return -1;
    }

    /* Initialize download slots */
    memset(downloads, 0, sizeof(downloads));
    memset(socket_events, 0, sizeof(socket_events));

    curl_initialized = 1;
    return 0;
}

CURLcode ftp_get_metadata(const char *ftp_url, ftp_metadata_t *out_meta)
{
    CURL *curl;
    CURLcode res;
    char errbuf[CURL_ERROR_SIZE];

    if (!curl_initialized || !ftp_url || !out_meta)
        return CURLE_FAILED_INIT;

    memset(out_meta, 0, sizeof(*out_meta));
    out_meta->filetime = -1;

    curl = curl_easy_init();
    if (!curl)
        return CURLE_FAILED_INIT;

    curl_easy_setopt(curl, CURLOPT_URL, ftp_url);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, throw_away);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0L);

    /* Quick timeout for metadata */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 500L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 750L);

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

#if DEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        LOG_PRINTF(LOG_INFO, "%s: * FTP: libcurl metadata error: %s\n", time_str(),  curl_easy_strerror(res));
        debug("%s: * FTP: details: %s\n", time_str(), errbuf);
        return res;
    }

    curl_easy_getinfo(curl, CURLINFO_FILETIME, &out_meta->filetime);
    curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                      &out_meta->filesize);

    curl_easy_cleanup(curl);
    return CURLE_OK;
}

ftp_download_t* ftp_request_file(const char *url)
{
    ftp_metadata_t meta;
    CURLcode res;
    CURL *easy;
    int slot = -1;
    int i;

    if (!multi || !url)
        return NULL;

    /* Check if this URL is already requested */
    for (i = 0; i < MAX_FTP_DOWNLOADS; i++) {
        if (downloads[i].in_use != 0 && downloads[i].has_error == FALSE && strcmp(downloads[i].url, url) == 0) {
            downloads[i].in_use++;
            LOG_PRINTF(LOG_INFO, "%s: * FTP: reuse %s (refs=%d)\n", time_str(), url, downloads[i].in_use);
            return &downloads[i];
        }
    }

    /* Find a free slot */
    for (i = 0; i < MAX_FTP_DOWNLOADS; i++) {
        if (downloads[i].in_use == 0) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        debug("%s: * FTP: No free download slots\n", time_str());
        return NULL;
    }

    /* Initialize download structure */
    downloads[slot].size = 0;
    downloads[slot].in_use = 1; // First use
    downloads[slot].completed = FALSE;
    downloads[slot].has_error = FALSE;
    downloads[slot].error_msg[0] = '\0';
    strncpy(downloads[slot].url, url, sizeof(downloads[slot].url) - 1);
    downloads[slot].url[sizeof(downloads[slot].url) - 1] = '\0';

    /* Get metadata first (blocking) */
    res = ftp_get_metadata(url, &meta);
    if (res != CURLE_OK) {
        snprintf(downloads[slot].error_msg, sizeof(downloads[slot].error_msg),
                 "FTP: Metadata failed: %s", curl_easy_strerror(res));
        downloads[slot].has_error = 1;
        return &downloads[slot];
    }

    if (meta.filesize <= 0) {
        snprintf(downloads[slot].error_msg, sizeof(downloads[slot].error_msg),
                 "FTP: Invalid file size from metadata");
        downloads[slot].has_error = 1;
        return &downloads[slot];
    }

    /* TODO: Maybe use a sliding window buffer? */
    /* Pre-allocate buffer */
    downloads[slot].capacity = (size_t)meta.filesize;
    downloads[slot].data = malloc(downloads[slot].capacity);
    if (!downloads[slot].data) {
        snprintf(downloads[slot].error_msg, sizeof(downloads[slot].error_msg),
                 "FTP: File too large, allocation failed");
        downloads[slot].has_error = 1;
        return &downloads[slot];
    }

    /* Create CURL easy handle */
    easy = curl_easy_init();
    if (!easy) {
        free(downloads[slot].data);
        downloads[slot].data = NULL;
        downloads[slot].in_use = 0;
        snprintf(downloads[slot].error_msg, sizeof(downloads[slot].error_msg),
                 "FTP: curl_easy_init failed");
        downloads[slot].has_error = 1;
        return &downloads[slot];
    }

    downloads[slot].easy_handle = easy;

    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, &downloads[slot]);
    curl_easy_setopt(easy, CURLOPT_PRIVATE, &downloads[slot]);

    /* Non-blocking friendly timeouts */
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, 1000L);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 0L); /* no overall timeout */

    /* Try to use EPSV first, but allow fallback to PASV or PORT */
    /* This can help reduce connection delays in some network configurations */
    curl_easy_setopt(easy, CURLOPT_FTP_USE_EPSV, 1L);

#if DEBUG
    curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
#endif

    /* Add to multi handle */
    curl_multi_add_handle(multi, easy);

    /* Immediately kick off the transfer - don't wait for first poll */
    int running;
    curl_multi_perform(multi, &running);

    LOG_PRINTF(LOG_INFO, "%s: * FTP: started %s (%zu bytes)\n", time_str(), url, downloads[slot].capacity);

    return &downloads[slot];
}

int ftp_get_event_handles(HANDLE *handles, int max_handles)
{
    fd_set read_fd, write_fd, except_fd;
    int maxfd = -1;
    CURLMcode mc;
    int count = 0;
    int i;

    if (!multi || !handles || max_handles < MAX_FTP_DOWNLOADS)
        return 0;

    FD_ZERO(&read_fd);
    FD_ZERO(&write_fd);
    FD_ZERO(&except_fd);

    /* Get file descriptors from curl */
    mc = curl_multi_fdset(multi, &read_fd, &write_fd, &except_fd, &maxfd);
    if (mc != CURLM_OK) {
        LOG_PRINTF(LOG_ERROR, "curl_multi_fdset failed: %s\n", curl_multi_strerror(mc));
        return 0;
    }

    /* If no file descriptors, curl is idle or working internally */
    if (maxfd == -1)
        return 0;

    /* Convert file descriptors to Windows events */
    for (i = 0; i <= maxfd && count < MAX_FTP_DOWNLOADS; i++) {
        long events = 0;
        
        if (FD_ISSET(i, &read_fd))
            events |= FD_READ;
        if (FD_ISSET(i, &write_fd))
            events |= FD_WRITE;
        if (FD_ISSET(i, &except_fd))
            events |= FD_OOB;

        if (events) {
            /* Create or reuse event for this socket */
            if (!socket_events[count]) {
                socket_events[count] = WSACreateEvent();
                if (!socket_events[count]) {
                    LOG_PRINTF(LOG_ERROR, "WSACreateEvent failed\n");
                    continue;
                }
            }

            /* Associate event with socket */
            if (WSAEventSelect((SOCKET)i, socket_events[count], events) == SOCKET_ERROR) {
                LOG_PRINTF(LOG_ERROR, "WSAEventSelect failed: %d\n", WSAGetLastError());
                continue;
            }

            handles[count] = socket_events[count];
            count++;
        }
    }

    return count;
}

long ftp_get_timeout_ms(long timeout_ms_default)
{
    long timeout_ms = -1;
    
    if (!multi)
        return timeout_ms_default;
    
    /* Get curl's recommended timeout */
    curl_multi_timeout(multi, &timeout_ms);
    
    /* curl wants us to call immediately */
    if (timeout_ms == 0)
        return 0;
    
    /* curl has no specific timeout - use default */
    if (timeout_ms < 0)
        return timeout_ms_default;
    
    /* Use curl's recommended timeout, but cap at timeout_ms_default */
    if (timeout_ms > timeout_ms_default)
        return timeout_ms_default;
    
    return timeout_ms;
}

int ftp_download_poll(void)
{
    CURLMsg *msg;
    int msgs_left;
    int running_handles = 0;
    CURLMcode mc;

    if (!multi)
        return 0;

    /* Perform curl operations - call multiple times to ensure progress */
    do {
        mc = curl_multi_perform(multi, &running_handles);
        if (mc != CURLM_OK) {
            LOG_PRINTF(LOG_ERROR, "curl_multi_perform failed: %s\n", curl_multi_strerror(mc));
            break;
        }
    } while (mc == CURLM_CALL_MULTI_PERFORM);

    /* Check for completed transfers */
    while ((msg = curl_multi_info_read(multi, &msgs_left))) {
        if (msg->msg == CURLMSG_DONE) {
            CURL *easy = msg->easy_handle;
            ftp_download_t *dl = NULL;

            curl_easy_getinfo(easy, CURLINFO_PRIVATE, &dl);

            if (dl) {
                if (msg->data.result == CURLE_OK) {
                    dl->completed = 1;
                    LOG_PRINTF(LOG_INFO, "%s: * FTP: completed %s (%zu/%zu bytes)\n", time_str(), dl->url, dl->size, dl->capacity);
                } else {
                    dl->has_error = 1;
                    snprintf(dl->error_msg, sizeof(dl->error_msg), "FTP: Download failed: %s", curl_easy_strerror(msg->data.result));
                    LOG_PRINTF(LOG_ERROR, "%s: * FTP: download error: %s - %s\n", time_str(), dl->url, dl->error_msg);
                }
            }

            curl_multi_remove_handle(multi, easy);
            curl_easy_cleanup(easy);
            
            if (dl)
                dl->easy_handle = NULL;
        }
    }

    return running_handles;
}

void ftp_download_free(ftp_download_t *download)
{
    if (!download)
        return;

    download->in_use--;

    LOG_PRINTF(LOG_INFO, "%s: * FTP: release %s (remaining refs=%d)\n", time_str(), download->url, download->in_use);

    if (download->in_use > 0) {
        return;
    }

    /* Remove from multi handle if still active */
    if (download->easy_handle) {
        curl_multi_remove_handle(multi, download->easy_handle);
        curl_easy_cleanup(download->easy_handle);
        download->easy_handle = NULL;
    }

    /* Free data buffer */
    if (download->data) {
        free(download->data);
        download->data = NULL;
    }

    /* Mark slot as free */
    download->in_use = 0;
    download->size = 0;
    download->capacity = 0;
    download->completed = FALSE;
    download->has_error = FALSE;
    download->error_msg[0] = '\0';
    download->url[0] = '\0';
}

void ftp_handler_cleanup(void)
{
    int i;

    if (curl_initialized) {
        /* Clean up all active downloads */
        for (i = 0; i < MAX_FTP_DOWNLOADS; i++) {
            if (downloads[i].in_use) {
                downloads[i].in_use = 0; // Force free
                ftp_download_free(&downloads[i]);
            }
            if (socket_events[i]) {
                WSACloseEvent(socket_events[i]);
                socket_events[i] = NULL;
            }
        }

        if (multi) {
            curl_multi_cleanup(multi);
            multi = NULL;
        }
        
        curl_global_cleanup();
        curl_initialized = 0;
    }
}
