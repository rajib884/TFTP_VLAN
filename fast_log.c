#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>

#include "fast_log.h"

typedef struct
{
    char buf[LOG_RING_SIZE];
    int write_pos; // next byte to write
    int read_pos;  // next byte to flush
    HANDLE file;
    log_level_t min_level;
} Logger;

static Logger g_log;

void log_init(const char *filename, log_level_t log_level)
{
    g_log.write_pos = 0;
    g_log.read_pos = 0;
    g_log.min_level = log_level;
    if (filename != NULL)
    {
        g_log.file = CreateFileA( filename, GENERIC_WRITE,
            FILE_SHARE_READ, // allow other processes to read log live
            NULL, OPEN_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, // hint to prefetcher
            NULL);
    }
    else
    {
        g_log.file = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    if (g_log.file == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "Failed to open log file: %lu\n", GetLastError());
        exit(1);
    }
    // Append: seek to end
    SetFilePointer(g_log.file, 0, NULL, FILE_END);
}

// Flush everything remaining before exit
void log_close(void)
{
    log_flush();
    CloseHandle(g_log.file);
}

void log_set_level(log_level_t level)
{
    g_log.min_level = level;
}

inline int log_allowed(log_level_t level)
{
    return (g_log.min_level <= level);
}

// How many bytes are pending (not yet flushed)
static inline int log_pending(void)
{
    return (g_log.write_pos - g_log.read_pos) & LOG_RING_MASK;
}

// Write to ring buffer. If there's no room, flush first.
void log_write(const char *data, int len)
{
    if (len > LOG_RING_SIZE - log_pending() - 1)
        log_flush();

    if (len >= LOG_RING_SIZE)
    {
        DWORD written;
        WriteFile(g_log.file, data, len, &written, NULL);
        return;
    }

    // Copy into ring, wrapping around if needed
    int space_to_end = LOG_RING_SIZE - g_log.write_pos;
    if (len <= space_to_end) {
        memcpy(g_log.buf + g_log.write_pos, data, len);
    } else {
        memcpy(g_log.buf + g_log.write_pos, data, space_to_end);
        memcpy(g_log.buf, data + space_to_end, len - space_to_end);
    }
    g_log.write_pos = (g_log.write_pos + len) & LOG_RING_MASK;

    return;
}

// printf-style logging
void log_printf(const char *fmt, ...)
{
    char tmp[2048];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (len > 0)
        log_write(tmp, len);
    return;
}

// Drain pending bytes from ring buffer to disk
void log_flush(void)
{
    int pending = log_pending();
    if (pending == 0)
        return;

    DWORD written;
    int to_end = LOG_RING_SIZE - g_log.read_pos;

    if (pending <= to_end) {
        // Contiguous chunk
        WriteFile(g_log.file, g_log.buf + g_log.read_pos, pending, &written, NULL);
    } else {
        // Two chunks: tail of buffer, then wrap-around head
        WriteFile(g_log.file, g_log.buf + g_log.read_pos, to_end,          &written, NULL);
        WriteFile(g_log.file, g_log.buf,                  pending - to_end, &written, NULL);
    }

    g_log.read_pos = (g_log.read_pos + pending) & LOG_RING_MASK;

    return;
}
