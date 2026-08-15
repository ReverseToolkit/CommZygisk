#include <stdint.h>

static int g_ctor = 0;

__attribute__((constructor)) static void on_init() { g_ctor = 1; }

extern "C" int linker_test_add(int a, int b) { return a + b; }

extern "C" int linker_test_ctor() { return g_ctor; }

extern "C" const char* linker_test_hello() { return "ok"; }

#if defined(__clang__)
#define TLS_ATTR __attribute__((tls_model("global-dynamic")))
#else
#define TLS_ATTR
#endif

static thread_local TLS_ATTR int g_tls = 42;

extern "C" int linker_test_tls() { return g_tls; }

extern "C" int linker_test_tls_set(int v) {
    g_tls = v;
    return g_tls;
}
