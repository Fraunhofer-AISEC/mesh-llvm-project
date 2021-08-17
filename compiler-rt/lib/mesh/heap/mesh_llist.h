//===-- mesh_llist.h ------------------------------------------------------===//
//
// This file is distributed under the MIT License
// See LICENSE.TXT, in this current directory, for details.
// Original implementation from https://github.com/CCareaga/heap_allocator
//
// Adapted for MESH by Emanuel Vintila, Fraunhofer AISEC
//
//===----------------------------------------------------------------------===//

#ifndef MESH_LLIST_H
#define MESH_LLIST_H

#include "mesh/heap/mesh_heap.h"
#include <stdint.h>

void add_node(bin_t *bin, node_t *node);

void remove_node(bin_t *bin, node_t *node);

node_t *get_best_fit(bin_t *list, size_t size);
node_t *get_last_node(bin_t *list);

node_t *next(node_t *current);
node_t *prev(node_t *current);

#endif
