#include <stddef.h>

static char g_order[16];
static int g_order_n;
static int g_data = 11;
static char g_bss[64 * 1024];
extern "C" int dep_glob = 123;

#if defined(__clang__)
#define TLS_ATTR __attribute__((tls_model("global-dynamic")))
#else
#define TLS_ATTR
#endif

extern "C" thread_local TLS_ATTR int dep_tls_x = 7;
static thread_local TLS_ATTR int g_tls = 100;

__attribute__((constructor)) static void dep_ctor() {
    if (g_order_n < 15) {
        g_order[g_order_n++] = 'D';
    }
}

__attribute__((destructor)) static void dep_dtor() {
    if (g_order_n < 15) {
        g_order[g_order_n++] = 'd';
    }
}

extern "C" void ctor_log_append(char c) {
    if (g_order_n < 15) {
        g_order[g_order_n++] = c;
    }
}

extern "C" const char* ctor_log() { return g_order; }

extern "C" int dep_add(int a, int b) { return a + b; }

extern "C" int dep_mul(int a, int b) { return a * b; }

extern "C" int dep_get() { return g_data; }

extern "C" void dep_set(int v) { g_data = v; }

extern "C" int dep_bss_ok() {
    g_bss[0] = 1;
    g_bss[sizeof(g_bss) - 1] = 2;
    return g_bss[0] + g_bss[sizeof(g_bss) - 1];
}

extern "C" int dep_tls() { return g_tls; }

extern "C" int dep_tls_set(int v) {
    g_tls = v;
    return g_tls;
}

extern "C" int ifunc_impl(int x) { return x * 3; }

extern "C" void* resolve_ifunc() { return reinterpret_cast<void*>(&ifunc_impl); }

extern "C" int dep_ifunc(int x) __attribute__((ifunc("resolve_ifunc")));

// RELATIVE to resolve_ifunc; gen_irelative.py rewrites the type to IRELATIVE.
extern "C" void* dep_ifunc_slot = reinterpret_cast<void*>(&resolve_ifunc);

extern "C" int dep_ifunc_local(int x) {
    using Fn = int (*)(int);
    return reinterpret_cast<Fn>(dep_ifunc_slot)(x);
}

#define FN(n) \
    extern "C" int dep_f##n() { return n; }
FN(0) FN(1) FN(2) FN(3) FN(4) FN(5) FN(6) FN(7)
FN(8) FN(9) FN(10) FN(11) FN(12) FN(13) FN(14) FN(15)
FN(16) FN(17) FN(18) FN(19) FN(20) FN(21) FN(22) FN(23)
FN(24) FN(25) FN(26) FN(27) FN(28) FN(29) FN(30) FN(31)

typedef int (*Fn)();
static Fn g_table[] = {dep_f0, dep_f1, dep_f2, dep_f3, dep_f4, dep_f5, dep_f6, dep_f7};

extern "C" int dep_table_sum() {
    int s = 0;
    for (size_t i = 0; i < sizeof(g_table) / sizeof(g_table[0]); ++i) {
        s += g_table[i]();
    }
    return s;
}
