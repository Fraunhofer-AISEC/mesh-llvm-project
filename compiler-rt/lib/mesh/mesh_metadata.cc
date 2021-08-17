//===-- mesh_metadata.cc --------------------------------------------------===//
//
// This file is distributed under the Apache License v2.0
// License with LLVM Exceptions. See LICENSE.TXT for details.
//
// Author: Emanuel Vintila, Fraunhofer AISEC
//
//===----------------------------------------------------------------------===//


#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_stacktrace_printer.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_platform.h"

#include "mesh/mesh_metadata.h"
#include "mesh/mesh_cfg.h"
#include "mesh/heap/mesh_heap.h"

#include <stdint.h>
#include <stdlib.h> // strtoull
#include <errno.h> // errno
#include <string.h> // memset
#include <sys/mman.h> // map
#include <stdio.h> // perror

#include "mesh/mesh_interface_internal.h"
#include "mesh/heap/mesh_heap.h"
#include "sanitizer_common/sanitizer_common.h" // Printf
#include "sanitizer_common/sanitizer_internal_defs.h" // fd_t
#include "sanitizer_common/sanitizer_libc.h" // fd_t
#include "sanitizer_common/sanitizer_file.h" // file handling for stats
#include "sanitizer_common/sanitizer_flags.h"



#ifdef MESH_STATISTICS

using namespace __asan;

struct MESH_statistics {
  size_t allocations;
  size_t deallocations;

  MESH_statistics() : allocations(0), deallocations(0) {}



  ~MESH_statistics() {
    pid_t pid = internal_getpid();
    char statistics_file_path[128];
    internal_snprintf(statistics_file_path, 128, "/tmp/MESH_stats_%u.log", pid);
    fd_t fd = OpenFile(statistics_file_path, WrOnly);
    if (fd == kInvalidFd) {
      return;
    }
    char buf[128];

    internal_snprintf(buf, sizeof(buf), "allocationes %u\ndeallocations %u\n", 
                      allocations, deallocations);

    WriteToFile(fd, buf, internal_strlen(buf));

    CloseFile(fd);
  }
};

static MESH_statistics stats;

#define STATS_ALLOCATION_EVENT() stats.allocations++;
#define STATS_DEALLOCATION_EVENT() stats.deallocations++;

#else

#define STATS_ALLOCATION_EVENT()
#define STATS_DEALLOCATION_EVENT()

#endif // MESH_STATISTICS


/* types and macros */

#if defined(__aarch64__)
#define SIZE_OF_INDEX_IN_BITS 16
#elif defined(__x86_64__)
#define SIZE_OF_INDEX_IN_BITS 16
#endif


#if SIZE_OF_INDEX_IN_BITS <= 16
using table_index_t = uint16_t;
#else
using table_index_t = uint32_t;
#endif


using addr_t = uint64_t;


struct table_entry_t
{
  addr_t lower_bound;
  addr_t upper_bound;
};

/* ---------------- */


/* local function declarations */
/* ---------------- */


/* local variables */
static constexpr size_t NUMBER_OF_ENTRIES = (1ul << SIZE_OF_INDEX_IN_BITS);

static table_entry_t *lookup_table = nullptr;

volatile static table_index_t current_table_index;

static const table_index_t TABLE_INDEX_MAX = NUMBER_OF_ENTRIES - 1; // -1 because it starts from 0; -1 because it denotes the start address of the line
/* ---------------- */


/*
 * ........ helpers ........
 */

constexpr size_t INDEX_END_BIT = sizeof(addr_t) * 8 - SIZE_OF_INDEX_IN_BITS;
constexpr size_t INVALID_ADDRESS = UINT64_MAX; // 0xFF..FF
// 0xFFFF00..00 or 0xFFFF80..00
constexpr size_t INDEX_BIT_MASK = (NUMBER_OF_ENTRIES - 1) << (64 - SIZE_OF_INDEX_IN_BITS);

#define CONCAT_INDEX(addr, index) ((static_cast<addr_t>(index) << (INDEX_END_BIT)) | addr)
#define GET_INDEX(ptr) static_cast<table_index_t>( (reinterpret_cast<addr_t>(ptr) >> INDEX_END_BIT ))
#define CLEAR_INDEX(ptr) reinterpret_cast<void *>(reinterpret_cast<addr_t>(ptr) & ~INDEX_BIT_MASK)

#define GENERATE_NEXT_INDEX() --current_table_index

#define GET_ADDRESS(ptr) (reinterpret_cast<addr_t>(ptr) & ~INDEX_BIT_MASK)

#define IS_NOT_TAGGED(ptr) (reinterpret_cast<addr_t>(ptr) < MINIMUM_TAGGED_VALUE)

__asan::BlockingMutex table_index_lock(__asan::LINKER_INITIALIZED);




#ifdef DETECT_MEMORY_LEAKS
class LeakDetector {
public:
  ~LeakDetector() {
    if (!lookup_table) return;
    size_t leaked_size = 0;
    for (table_index_t i = 0; i < UINT16_MAX; i++) {
       if (lookup_table[i+1].lower_bound != INVALID_ADDRESS) {
         __sanitizer::Report("ERROR: MESH: memory leak detected at index %p (%p to %p)\n",
             i+1, lookup_table[i+1].lower_bound, lookup_table[i+1].upper_bound);
         leaked_size += lookup_table[i+1].upper_bound - lookup_table[i+1].lower_bound;
       }
    }

    if (leaked_size) {
      terminate("Memory leaks detected: %u bytes!\n", leaked_size);
    }
  }
};

static LeakDetector leak_detector; // destructor called at the end of the execution
#endif // DETECT_MEMORY_LEAKS

heap_t *custom_heap;

/* function definitions */


void __mesh_init_metadata_table()
{
  LOG("__mesh_init_metadata_table: initializing metadata table\n");
  const char* table_addr_str = __sanitizer::GetEnv("MESH_HEAP_ADDRESS");

  void *table_addr;
  if (table_addr_str) {
    char *end_ptr;
    table_addr = (void *)std::strtoull(table_addr_str, &end_ptr, 16);
    if ( (*end_ptr != '\0') ||
         ( (uint64_t)table_addr == UINT64_MAX && errno == ERANGE ) ) {
      __sanitizer::Printf("Failed to parse MESH_HEAP_ADDRESS \"%s\" as a hex\n", table_addr_str);
      exit(EXIT_FAILURE);
    }
  }
  else {
    // use default
    table_addr = (void *)4096;
  }


  constexpr size_t line_size = 2 * sizeof(addr_t); // lower bound + upper bound
  constexpr size_t table_size = static_cast<size_t>(line_size) * (NUMBER_OF_ENTRIES + 1);
  
  void *res = mmap(table_addr, table_size + HEAP_INIT_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

  if (res == MAP_FAILED) {
    perror("mmap");
    exit(EXIT_FAILURE);
  }
  else if (res != table_addr) {
    __sanitizer::Printf("Failed to mmap at %p. Actual value %p.\n", table_addr, res);
    __sanitizer::Printf("The MESH Address can be set using the MESH_HEAP_ADDRESS environment variable.\n");
    __sanitizer::Printf("The minimum mmap address can be set using \'sysctl -w vm.mmap_min_addr=\"<value>\"\'\n");
    exit(EXIT_FAILURE);
  }

  lookup_table = (table_entry_t *)res;

  current_table_index = TABLE_INDEX_MAX;
  LOG("mmap at %p, size %p, max index at at %p\n", res, table_size + HEAP_INIT_SIZE, &lookup_table[TABLE_INDEX_MAX]);

  memset((void *)res, 0xff, table_size);

  void *region = (void *)( (size_t)res + table_size);
  memset( region, 0x00, HEAP_INIT_SIZE);

  custom_heap = (heap_t *)malloc(sizeof(heap_t));
  memset(custom_heap, 0, sizeof(heap_t));

  for (int i = 0; i < BIN_COUNT; i++) {
    custom_heap->bins[i] = (bin_t *)malloc(sizeof(bin_t));
    memset(custom_heap->bins[i], 0, sizeof(bin_t));
  }

  init_heap(custom_heap, (uint64_t) region);

  LOG("Heap region from %p to %p\n", region, (uint64_t)region + HEAP_INIT_SIZE);
}


// ..........................


/* 
 * ........ alloc ...........
 */

void *__mesh_metadata_gen_line(void *addr, const size_t size)
{
  STATS_ALLOCATION_EVENT();

  LOG("__alloc: Allocating 0x%x bytes at 0x%x\n", size, addr);

  table_index_lock.Lock();
  // start of critical section

  table_index_t ptr_index = current_table_index; // use this copy from now on
  GENERATE_NEXT_INDEX();

  // end of critical section
  table_index_lock.Unlock();

  void *tagged_ptr = reinterpret_cast<void *>( CONCAT_INDEX(reinterpret_cast<addr_t>(addr), ptr_index) );

  LOG("Table index %x. Ptr %p\n", ptr_index, tagged_ptr);
  // set metadata entry in table

  lookup_table[ptr_index].lower_bound = (addr_t)tagged_ptr;
  lookup_table[ptr_index].upper_bound = (addr_t)tagged_ptr + size; // overflow by 1 allowed?
  LOG("%p -> (%p, %p)\n", ptr_index, lookup_table[ptr_index].lower_bound, lookup_table[ptr_index].upper_bound);
  return tagged_ptr;
}

void __mesh_metadata_reuse_line(const void *indexed_ptr, const size_t size)
{
  table_index_t index = GET_INDEX(indexed_ptr);

  LOG("reuse_line: %u %u\n", index, size);
  // set metadata entry in table

  lookup_table[index].lower_bound = (addr_t)indexed_ptr;
  lookup_table[index].upper_bound = (addr_t)indexed_ptr + size; // overflow by 1 allowed?
}

void __mesh_metadata_remove_line(const void *addr)
{
  STATS_DEALLOCATION_EVENT();

  if (addr == nullptr)
  {
    LOG("__dealloc: Ignoring nullptr\n");
    return;
  }

  const void *ptr = addr;
  LOG("__dealloc: Deallocating %p\n", ptr);

  table_index_t index = GET_INDEX(ptr);
  
  if (index == 0) return; // skipped untagged pointers

  LOG("__dealloc: Computed index 0x%x\n", index);
  
  // table_index_lock.Lock();
  if (lookup_table[index].lower_bound == INVALID_ADDRESS) {
    terminate ("__dealloc: Double free or freeing of unallocated memory detected!\n");
    //LOG("__dealloc: Double free or freeing of unallocated memory detected!\n"); exit(1);
  }


  // deallocate by setting the lower_bound to INVALID_ADDRESS
  lookup_table[index].lower_bound = INVALID_ADDRESS;
  // table_index_lock.Unlock();
}

void *__mesh_metadata_strip(void *ptr)
{
  return reinterpret_cast<void *>(GET_ADDRESS(ptr));
}

void __mesh_fail(const size_t addr, const size_t tag, const size_t addr_end,
  const size_t lb, const size_t hb)
{
  LOG("lb %p hb %p addr end %p\n", lb, hb, addr_end);
  //LOG("Illegal heap access detected at %p: %p -> (%p, %p) [%p]\n", addr, tag, lookup_table[tag].lower_bound, lookup_table[tag].upper_bound, &lookup_table[tag].lower_bound);
  //exit(1);
  terminate("Illegal heap access detected at %p to %p: %zx -> (%p, %p) [metadata at &%p]\n", addr, addr_end, tag, lb, hb, &lookup_table[tag].lower_bound);
}

void __mesh_fail_non_heap(const size_t addr)
{
  if (addr)
  {
    terminate("Illegal heap access from non-heap pointer %p\n", addr);
    //LOG("Illegal heap access from non-heap pointer %p\n", addr); exit(1);
  }
  else
  {
    LOG("Null addr?");
  }
}
