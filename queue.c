#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "queue.h"


// Initialize an empty queue
packet_queue_t* queue_init(void) {
    packet_queue_t *queue = (packet_queue_t*)malloc(sizeof(packet_queue_t));
    if (!queue) return NULL;
    
    queue->head = NULL;
    queue->tail = NULL;
    queue->cache = NULL;
    queue->size = 0;
    queue->lowest_index = 0;
    return queue;
}

// Add a packet to the queue (sorted by index)
const packet_t* queue_add(packet_queue_t *queue, int64_t index, const void *data, size_t data_len) {
    if (!queue || data_len == 0) return NULL;
    
    // Create new packet node
    queue_node_t *new_node = (queue_node_t*)malloc(sizeof(queue_node_t));
    if (!new_node) return NULL;
    
    // Copy packet data
    new_node->packet.data = malloc(data_len);
    if (!new_node->packet.data) {
        free(new_node);
        return NULL;
    }
    if (data != NULL) {
        memcpy(new_node->packet.data, data, data_len);
    } else {
        memset(new_node->packet.data, 0, data_len);
    }
    new_node->packet.data_len = data_len;
    new_node->packet.index = index;
    new_node->next = NULL;
    new_node->prev = NULL;
    
    // Case 1: Empty queue
    if (queue->size == 0) {
        queue->head = new_node;
        queue->tail = new_node;
        queue->lowest_index = index;
        queue->size = 1;
        return &new_node->packet;
    }
    
    // Case 2: Insert at head (new packet has the smallest index)
    if (index < queue->head->packet.index) {
        new_node->next = queue->head;
        queue->head->prev = new_node;
        queue->head = new_node;
        queue->lowest_index = index;
        queue->size++;
        return &new_node->packet;
    }
    
    // Case 3: Insert at tail (new packet has the largest index)
    if (index > queue->tail->packet.index) {
        new_node->prev = queue->tail;
        queue->tail->next = new_node;
        queue->tail = new_node;
        queue->size++;
        return &new_node->packet;
    }
    
    // Case 4: Insert in the middle (find the correct position)
    queue_node_t *current = queue->head;
    while (current && current->packet.index < index) {
        current = current->next;
    }
    
    // If we found a packet with the same index, replace it
    if (current && current->packet.index == index) {
        // Free old data
        free(current->packet.data);
        // Use new data
        current->packet.data = malloc(data_len);
        if (!current->packet.data) {
            current->packet.data_len = 0;
            free(new_node);
            return NULL;
        }

        if (data != NULL) {
            memcpy(current->packet.data, data, data_len);
        } else {
            memset(current->packet.data, 0, data_len);
        }
        current->packet.data_len = data_len;
        free(new_node); // We reused the existing node
        return &current->packet;
    }
    
    // Insert before current (which has higher index)
    if (current) {
        new_node->next = current;
        new_node->prev = current->prev;
        if (current->prev) {
            current->prev->next = new_node;
        }
        current->prev = new_node;
        
        // If we inserted at head, update head pointer
        if (current == queue->head) {
            queue->head = new_node;
        }
    } else {
        // This should not happen if the list is properly maintained
        free(new_node->packet.data);
        free(new_node);
        return NULL;
    }
    
    queue->size++;
    return &new_node->packet;
}

// Get a packet by index (without removing it)
const packet_t* queue_get(packet_queue_t *queue, int64_t index) {
    if (!queue || queue->size == 0) return NULL;

    if (queue->lowest_index > index || queue->tail->packet.index < index) {
        return NULL; // Out of bounds
    }

    // Check cache first (same packet or nearby)
    if (queue->cache) {
        if (queue->cache->packet.index == index) {
            return &queue->cache->packet;
        }
        // Check next node
        if (queue->cache->next && queue->cache->next->packet.index == index) {
            queue->cache = queue->cache->next;
            return &queue->cache->packet;
        }
        // Check previous node
        if (queue->cache->prev && queue->cache->prev->packet.index == index) {
            queue->cache = queue->cache->prev;
            return &queue->cache->packet;
        }
    }

    // Get head 
    if (queue->head->packet.index == index) {
        queue->cache = queue->head->next;
        return &queue->head->packet;
    }

    // Get tail
    if (queue->tail->packet.index == index) {
        queue->cache = queue->tail->next;
        return &queue->tail->packet;
    }

    // TODO: start from head if index is close to lowest, Optimization
    if (index >= queue->lowest_index && index <= queue->tail->packet.index) {
        queue_node_t *current = queue->head;
        while (current) {
            if (current->packet.index == index) {
                queue->cache = current->next;
                return &current->packet;
            }
            if (current->packet.index > index) {
                break; // Not found (since list is sorted)
            }
            current = current->next;
        }
    }
    
    return NULL;
}

// Delete a packet by index
int queue_delete(packet_queue_t *queue, int64_t index) {
    if (!queue || queue->size == 0) return -1;
    
    // Special case: delete head (common in FIFO)
    if (queue->head->packet.index == index) {
        queue_node_t *to_delete = queue->head;
        queue->head = queue->head->next;
        if (queue->head) {
            queue->head->prev = NULL;
        } else {
            queue->tail = NULL; // Queue is now empty
        }
        
        if (queue->cache == to_delete) {
            queue->cache = NULL; // Invalidate cache
        }

        free(to_delete->packet.data);
        free(to_delete);
        queue->size--;
        
        // Update lowest_index if we deleted the head
        if (queue->head) {
            queue->lowest_index = queue->head->packet.index;
        } else {
            queue->lowest_index = 0;
        }
        return 0;
    }
    
    // Special case: delete tail
    if (queue->tail->packet.index == index) {
        queue_node_t *to_delete = queue->tail;
        queue->tail = queue->tail->prev;
        if (queue->tail) {
            queue->tail->next = NULL;
        } else {
            queue->head = NULL; // Queue is now empty
        }

        if (queue->cache == to_delete) {
            queue->cache = NULL; // Invalidate cache
        }
        
        free(to_delete->packet.data);
        free(to_delete);
        queue->size--;
        return 0;
    }
    
    // Delete from middle
    queue_node_t *current = queue->head;
    while (current) {
        if (current->packet.index == index) {
            // Found the node to delete
            if (current->prev) {
                current->prev->next = current->next;
            }
            if (current->next) {
                current->next->prev = current->prev;
            }

            if (queue->cache == current) {
                queue->cache = NULL; // Invalidate cache
            }
            
            free(current->packet.data);
            free(current);
            queue->size--;
            return 0;
        }
        
        if (current->packet.index > index) {
            break; // Not found (since list is sorted)
        }
        
        current = current->next;
    }
    
    return -1; // Index not found
}

// Free the entire queue
void queue_free(packet_queue_t *queue) {
    if (!queue) return;
    
    queue_node_t *current = queue->head;
    while (current) {
        queue_node_t *next = current->next;
        free(current->packet.data);
        free(current);
        current = next;
    }
    
    free(queue);
}
