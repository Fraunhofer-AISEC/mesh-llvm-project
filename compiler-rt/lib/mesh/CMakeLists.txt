include_directories(..)

# Runtime library sources and build flags.
set(MESH_RTL_SOURCES
  heap/mesh_heap.c
  heap/mesh_llist.c
  mesh.cc
  mesh_malloc.cc
  mesh_mmap.cc
  mesh_metadata.cc
  )

set(MESH_RTL_HEADERS
  mesh.h
  mesh_interface_internal.h
  mesh_metadata.h
  mesh_cfg.h
  heap/mesh_heap.h
  heap/mesh_llist.h
  )


set(MESH_RTL_CFLAGS ${SANITIZER_COMMON_CFLAGS} " -fpermissive -O3")
append_rtti_flag(OFF MESH_RTL_CFLAGS)

set(MESH_RTL_DYNAMIC_CFLAGS ${MESH_RTL_CFLAGS})
append_list_if(COMPILER_RT_HAS_FTLS_MODEL_INITIAL_EXEC
    -ftls-model=initial-exec MESH_RTL_DYNAMIC_CFLAGS)

# Static runtime library.
add_compiler_rt_component(MESH)

add_compiler_rt_object_libraries(RTMESH_dynamic
  OS ${SANITIZER_COMMON_SUPPORTED_OS}
  ARCHS ${MESH_SUPPORTED_ARCH}
  SOURCES ${MESH_RTL_SOURCES}
  ADDITIONAL_HEADERS ${MESH_RTL_HEADERS}
  CFLAGS ${MESH_RTL_DYNAMIC_CFLAGS})
if(NOT APPLE)
  add_compiler_rt_object_libraries(RTMESH
    ARCHS ${MESH_SUPPORTED_ARCH}
    SOURCES ${MESH_RTL_SOURCES}
    ADDITIONAL_HEADERS ${MESH_RTL_HEADERS}
    CFLAGS ${MESH_RTL_CFLAGS})
endif()

if(APPLE)
  #add_weak_symbols("mesh" WEAK_SYMBOL_LINK_FLAGS)
  add_weak_symbols("sanitizer_common" WEAK_SYMBOL_LINK_FLAGS)
  #add_weak_symbols("xray" WEAK_SYMBOL_LINK_FLAGS)

  add_compiler_rt_runtime(clang_rt.MESH
    SHARED
    OS ${SANITIZER_COMMON_SUPPORTED_OS}
    ARCHS ${MESH_SUPPORTED_ARCH}
    OBJECT_LIBS RTMESH_dynamic
                RTInterception
                RTSanitizerCommon
                RTSanitizerCommonLibc
    CFLAGS ${MESH_RTL_DYNAMIC_CFLAGS}
    LINK_FLAGS ${WEAK_SYMBOL_LINK_FLAGS}
    PARENT_TARGET MESH)
else()
  foreach(arch ${MESH_SUPPORTED_ARCH})
    add_compiler_rt_runtime(clang_rt.MESH
      STATIC
      ARCHS ${arch}
      OBJECT_LIBS RTMESH
                  RTInterception
                  RTSanitizerCommon
                  RTSanitizerCommonLibc
      CFLAGS ${MESH_RTL_CFLAGS}
      PARENT_TARGET mesh)
    add_sanitizer_rt_symbols(clang_rt.MESH
      ARCHS ${arch}
      EXTRA mesh.syms.extra)
    add_dependencies(MESH
      clang_rt.MESH-${arch}-symbols)
  endforeach()
endif()

