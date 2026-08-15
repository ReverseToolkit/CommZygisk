#include "linker_error.hpp"

#include "logging.hpp"

#include <cstdarg>
#include <cstdio>

namespace linker {
namespace {

// POD TLS: a C++ std::string here would call __cxa_thread_atexit_impl, and
// the system linker aborts once libzygisk's soinfo has been dropped.
thread_local char g_error[512];

}  // namespace

void SetError(const char* msg) {
    if (msg == nullptr) {
        g_error[0] = '\0';
        return;
    }
    std::snprintf(g_error, sizeof(g_error), "%s", msg);
    if (g_error[0]) {
        LOGE("linker: %s", g_error);
    }
}

void SetErrorf(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    SetError(buf);
}

const char* GetError() { return g_error[0] ? g_error : nullptr; }

}  // namespace linker
