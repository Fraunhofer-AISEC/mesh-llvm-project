//===-- mesh_malloc.cc ----------------------------------------------------===//
//
// This file is distributed under the Apache License v2.0
// License with LLVM Exceptions. See LICENSE.TXT for details.
//
// Author: Emanuel Vintila, Fraunhofer AISEC
//
//===----------------------------------------------------------------------===//


#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "mesh/mesh_metadata.h"
#include "mesh/mesh_interface_internal.h"
#include "mesh/mesh_cfg.h"
#include "mesh/heap/mesh_heap.h"


using namespace __mesh;

void* __mesh_malloc(uptr size) {
  LOG("__malloc intercepted\n");
  
  void *indexed_pointer = nullptr;
  void *raw_pointer = heap_alloc(custom_heap, size);
  if (!raw_pointer) {
    LOG("malloc failed: skip indexing\n");
  }
  else {
    indexed_pointer = __mesh_metadata_gen_line(raw_pointer, size);
  }

  LOG("resulted pointer: %p\n", indexed_pointer);

  return indexed_pointer;
}

void __mesh_free(void *ptr) {
  LOG("__free intercepted %p\n", ptr);

  if ( (size_t)ptr < FIRST_TAGGED_VALUE ) {
    if (!ptr)
    {
      LOG("null ptr\n");
    }
    else
    {
      LOG("default free for non-tagged pointer\n");
      free(ptr);
    }
    return;
  }

  __mesh_metadata_remove_line(ptr);
 
  LOG("stripped pointer %p\n", __mesh_metadata_strip(ptr));

  heap_free(custom_heap, __mesh_metadata_strip(ptr));
}

void* __mesh_calloc(uptr nmemb, uptr size) {
  LOG("__calloc intercepted\n");
  return __mesh_malloc(nmemb * size);
}

void* __mesh_realloc(void *ptr, uptr new_size) {
  LOG("__realloc intercepted\n");
  if (new_size == 0) {
    if (ptr) __mesh_free(ptr); // this will also deindex the pointer
    return nullptr;
  }
  // new_size > 0

  // the ptr is indexed and has to be stripped before usage
  void *raw_addr = __mesh_metadata_strip(ptr);
  void *new_addr = heap_alloc(custom_heap, new_size);
  
  void *indexed_pointer;
  if (new_addr != nullptr) {
    // a succesfull allocation was done in the background
    __mesh_metadata_remove_line(ptr); // remove the old line
    heap_free(custom_heap, raw_addr); // free the old chunk
    indexed_pointer = __mesh_metadata_gen_line(new_addr, new_size); // generate a new line for the new chunk
    return indexed_pointer;
  }
  
  // the new allocation failed. the old chunk must remain the same
  return nullptr;
}

