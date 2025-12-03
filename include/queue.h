#ifndef LIST_QUEUE_H
#define LIST_QUEUE_H

#include <stddef.h>
#include <stdint.h>

// Packet structure
typedef struct {
    int64_t index;      // Packet number (sorted)
    void *data;          // Packet data
    size_t data_len;     // Length of packet data
} packet_t;

// Queue node structure
typedef struct queue_node {
    packet_t packet;
    struct queue_node *next;
    struct queue_node *prev;
} queue_node_t;

// Queue structure
typedef struct {
    queue_node_t *head;
    queue_node_t *tail;
    queue_node_t *cache; // For caching last accessed node
    uint64_t size;
    int64_t lowest_index;  // Track the lowest index for optimization
} packet_queue_t;

// Function prototypes
packet_queue_t* queue_init(void);
const packet_t* queue_add(packet_queue_t *queue, int64_t index, const void *data, size_t data_len);
const packet_t* queue_get(packet_queue_t *queue, int64_t index);
int queue_delete(packet_queue_t *queue, int64_t index);
void queue_free(packet_queue_t *queue);

#endif