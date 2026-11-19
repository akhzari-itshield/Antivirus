// ITShield native C++ module - stub implementation.
//
// The functions here return placeholder values so the library links cleanly
// and the C ABI can be exercised from Python (ctypes) or Rust. Real
// implementations will be filled in as the corresponding modules are built
// (Process Monitor, File Watcher, Network Monitor).

#include "itshield_native.h"

#include <cstring>

extern "C" {

uint32_t itshield_native_version(void) {
    // 0.1.0 packed as 0x00010000
    return 0x00010000u;
}

int32_t itshield_list_processes(uint32_t* out_pids,
                                uint32_t max_count,
                                uint32_t* out_actual) {
    if (out_actual == nullptr) {
        return -22;  // EINVAL
    }
    *out_actual = 0;
    if (out_pids == nullptr || max_count == 0) {
        return 0;
    }
    // Stub: return PID 1 (init) as a single placeholder entry.
    out_pids[0] = 1u;
    *out_actual = 1u;
    return 0;
}

int32_t itshield_watch_directory(const char* path) {
    if (path == nullptr) {
        return -22;  // EINVAL
    }
    if (std::strlen(path) == 0) {
        return -22;
    }
    // Stub: pretend success. Real implementation will set up inotify.
    return 0;
}

int32_t itshield_list_connections(uint32_t* out_lports,
                                  uint32_t max_count,
                                  uint32_t* out_actual) {
    if (out_actual == nullptr) {
        return -22;
    }
    *out_actual = 0;
    if (out_lports == nullptr || max_count == 0) {
        return 0;
    }
    // Stub: no connections reported yet.
    return 0;
}

}  // extern "C"
