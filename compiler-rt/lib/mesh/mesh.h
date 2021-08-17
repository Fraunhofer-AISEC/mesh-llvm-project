//===-- mesh.h ------------------------------------------------------------===//
//
// This file is distributed under the Apache License v2.0
// License with LLVM Exceptions. See LICENSE.TXT for details.
//
// Author: Emanuel Vintila, Fraunhofer AISEC
//
//===----------------------------------------------------------------------===//


#ifndef MESH_H
#define MESH_H

#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_stacktrace.h"

// Alignment requirement for the per-object metadata store.
// TODO: This can be moved to mesh.cc in case poms_align is moved to mesh.cc
#if defined(__x86_64__)
#define POMS_ALIGNMENT 8
#else
  #if defined(__aarch64__)

  #else
    #error "MESH runtime support not available for this architecture."
  #endif
#endif

#if defined(__x86_64__)

#else
  #if defined(__aarch64__)

  #else
    #error "MESH runtime support not available for this architecture."
  #endif
#endif

namespace __mesh {


void initialize_interceptors();

} // namespace __mesh

#endif  // MESH_H
