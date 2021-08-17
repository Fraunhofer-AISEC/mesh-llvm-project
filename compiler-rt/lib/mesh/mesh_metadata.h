//===-- mesh_metadata.h ---------------------------------------------------===//
//
// This file is distributed under the Apache License v2.0
// License with LLVM Exceptions. See LICENSE.TXT for details.
//
// Author: Emanuel Vintila, Fraunhofer AISEC
//
//===----------------------------------------------------------------------===//


#ifndef MEM_METADATA_HANDLER_H
#define MEM_METADATA_HANDLER_H

#include <stddef.h> // size_t

#include "mesh/heap/mesh_heap.h" // heap_t

extern void __mesh_init_metadata_table();

extern void *__mesh_index_pointer(void *ptr, size_t size);
extern void __mesh_deindex_pointer(void *ptr);

extern bool MESHIsInitialized;
extern heap_t *custom_heap;

#endif // MED_METADATA_HANDLER_H
