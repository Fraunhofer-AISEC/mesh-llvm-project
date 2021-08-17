//===-- mesh_heap.h -------------------------------------------------------===//
//
// This file is distributed under the MIT License
// See LICENSE.TXT, in this current directory, for details.
// Original implementation from https://github.com/CCareaga/heap_allocator
//
// Adapted for MESH by Emanuel Vintila, Fraunhofer AISEC
//
//===----------------------------------------------------------------------===//

#ifndef MESH_HEAP_H
#define MESH_HEAP_H

#include <stdint.h>
#include <stddef.h>

#define HEAP_INIT_SIZE 0xF0000
#define HEAP_MAX_SIZE  0xF0000
#define HEAP_MIN_SIZE  0xF0000

#define MIN_ALLOC_SZ 4

#define MIN_WILDERNESS 0x2000
#define MAX_WILDERNESS 0x1000000

#define BIN_COUNT 9
#define BIN_MAX_IDX (BIN_COUNT - 1)

typedef unsigned int uint;

typedef struct node_t {
    uint hole;
    uint size;
    struct node_t* next;
    struct node_t* prev;
} node_t;

typedef struct { 
    node_t *header;
} footer_t;

typedef struct {
    node_t* head;
} bin_t;

typedef struct {
    uint64_t start;
    uint64_t end;
    bin_t *bins[BIN_COUNT];
} heap_t;

static uint overhead = sizeof(footer_t) + sizeof(node_t);


uint expand(heap_t *heap, size_t sz);
void contract(heap_t *heap, size_t sz);

uint get_bin_index(size_t sz);
void create_foot(node_t *head);
footer_t *get_foot(node_t *head);

node_t *get_wilderness(heap_t *heap);

#endif
