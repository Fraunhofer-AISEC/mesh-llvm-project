//===-- mesh_mmap.cc ------------------------------------------------------===//
//
// This file is distributed under the Apache License v2.0
// License with LLVM Exceptions. See LICENSE.TXT for details.
//
// Author: Emanuel Vintila, Fraunhofer AISEC
//
//===----------------------------------------------------------------------===//

#include "mesh/mesh.h"
#include "sanitizer_common/sanitizer_common.h"

#include <stdarg.h>
#include <sys/mman.h>

using namespace __mesh;

void* __mesh_mmap(void *addr, size_t length, int prot, int flags, int fd,
                 off_t offset) {
  // not implemented
  return mmap(addr, length, prot, flags, fd, offset);
}

void __mesh_munmap(void *addr, size_t length) {
  munmap(addr, length);
}
