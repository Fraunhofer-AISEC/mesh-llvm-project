//===-- mesh_interface_internal.h -----------------------------------------===//
//
// This file is distributed under the Apache License v2.0
// License with LLVM Exceptions. See LICENSE.TXT for details.
//
// Author: Emanuel Vintila, Fraunhofer AISEC
//
//===----------------------------------------------------------------------===//


#ifndef MESH_INTERFACE_INTERNAL_H
#define MESH_INTERFACE_INTERNAL_H

#include <stdlib.h>
#include <stdint.h>

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_common.h" // Printf

#include "mesh/mesh_cfg.h"
#include "mesh/heap/mesh_heap.h"

#define terminate(...) do { __sanitizer::Printf(__VA_ARGS__); __sanitizer::Abort(); } while (0)

#ifdef MESH_DEBUG
#define LOG(...) __sanitizer::Printf(__VA_ARGS__)
#else
#define LOG(...)
#endif

using __sanitizer::uptr;

extern "C" {


SANITIZER_INTERFACE_ATTRIBUTE
extern uptr __emcs_metadata_base_ptr;

SANITIZER_INTERFACE_ATTRIBUTE
void __mesh_init_rt();

SANITIZER_INTERFACE_ATTRIBUTE
void* __mesh_malloc(uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void __mesh_free(void *ptr);

SANITIZER_INTERFACE_ATTRIBUTE
void* __mesh_calloc(uptr nmemb, uptr size);

SANITIZER_INTERFACE_ATTRIBUTE
void* __mesh_realloc(void *old_ptr, uptr new_size);

SANITIZER_INTERFACE_ATTRIBUTE
void* __mesh_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

SANITIZER_INTERFACE_ATTRIBUTE
void __mesh_munmap(void *addr, size_t length);

SANITIZER_INTERFACE_ATTRIBUTE
void *__mesh_metadata_strip(void *ptr);

SANITIZER_INTERFACE_ATTRIBUTE
void *__mesh_metadata_gen_line(void *address, const size_t type_size);

SANITIZER_INTERFACE_ATTRIBUTE
void __mesh_metadata_remove_line(const void *address);

SANITIZER_INTERFACE_ATTRIBUTE
void __mesh_metadata_reuse_line(const void *address, const size_t type_size);

SANITIZER_INTERFACE_ATTRIBUTE
void __mesh_fail(const size_t addr, const size_t tag, const size_t addr_end,
  const size_t lb, const size_t hb);

SANITIZER_INTERFACE_ATTRIBUTE
void __mesh_fail_non_heap(const size_t addr);

SANITIZER_INTERFACE_ATTRIBUTE
void *heap_alloc(heap_t *heap, size_t size);

SANITIZER_INTERFACE_ATTRIBUTE
void heap_free(heap_t *heap, void *p);

SANITIZER_INTERFACE_ATTRIBUTE
void init_heap(heap_t *heap, uint64_t start);


} // extern "C"

#endif // MESH_INTERFACE_INTERNAL_H

