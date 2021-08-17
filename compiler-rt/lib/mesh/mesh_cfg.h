//===-- mesh_cfg.h --------------------------------------------------------===//
//
// This file is distributed under the Apache License v2.0
// License with LLVM Exceptions. See LICENSE.TXT for details.
//
// Author: Emanuel Vintila, Fraunhofer AISEC
//
//===----------------------------------------------------------------------===//


#ifndef MESH_CFG_H
#define MESH_CFG_H

//#define MESH_DEBUG

//#define MESH_STATISTICS
//#define DETECT_MEMORY_LEAKS

constexpr size_t NR_ADDR_BITS = 48;
constexpr uint64_t FIRST_TAGGED_VALUE = 0x1ull << NR_ADDR_BITS;

#endif // MESH_CFG_H
