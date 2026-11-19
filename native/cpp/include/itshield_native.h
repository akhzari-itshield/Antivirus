// ITShield native C++ module - low-level OS interaction surface.
//
// Section 4.3 of the architecture document assigns C++ to native modules
// that need low-level OS interaction. The functions declared here are
// intentionally exposed through a stable C ABI so both Python (via ctypes
// or pybind11) and Rust (via extern "C") can call them.
//
// Everything in this header is forward-looking: the implementation in
// native.cpp provides stubs that return placeholder values. Real
// implementations will arrive as the corresponding modules are built
// (Process Monitor, File Watcher, Socket Monitor, etc.).

#ifndef ITSHIELD_NATIVE_H
#define ITSHIELD_NATIVE_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// Library version (semver-like, packed as 0xMMmmpp).
uint32_t itshield_native_version(void);

// ---------------------------------------------------------------------------
// Process monitoring (planned). Returns 0 on success, a negative errno-like
// code on failure. Real implementation will use /proc on Linux and the
// Toolhelp32 API on Windows.
// ---------------------------------------------------------------------------
int32_t itshield_list_processes(uint32_t* out_pids, uint32_t max_count, uint32_t* out_actual);

// ---------------------------------------------------------------------------
// File watching (planned). Real implementation will use inotify on Linux and
// ReadDirectoryChangesW on Windows.
// ---------------------------------------------------------------------------
int32_t itshield_watch_directory(const char* path);

// ---------------------------------------------------------------------------
// Network connection enumeration (planned). Real implementation will read
// /proc/net/tcp on Linux and GetExtendedTcpTable on Windows.
// ---------------------------------------------------------------------------
int32_t itshield_list_connections(uint32_t* out_lports, uint32_t max_count, uint32_t* out_actual);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ITSHIELD_NATIVE_H
