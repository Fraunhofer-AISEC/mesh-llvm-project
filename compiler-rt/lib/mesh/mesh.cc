//===-- mesh.cc -----------------------------------------------------------===//
//
// This file is distributed under the Apache License v2.0
// License with LLVM Exceptions. See LICENSE.TXT for details.
//
// Author: Emanuel Vintila, Fraunhofer AISEC
//
//===----------------------------------------------------------------------===//

#include "mesh/mesh.h"
#include "mesh/mesh_interface_internal.h"
#include "mesh/mesh_metadata.h"
#include "sanitizer_common/sanitizer_common.h"

// Indicators whether the MESH runtime is fully initialized.
bool MESHIsInitialized = false;

void __mesh_init_rt() {
  if (MESHIsInitialized)
    return;

  LOG("MESH runtime initialization...\n");

  __mesh_init_metadata_table();

  MESHIsInitialized = true;
}
