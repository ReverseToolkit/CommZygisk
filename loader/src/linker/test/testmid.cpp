extern "C" int dep_add(int a, int b);
extern "C" int dep_get();
extern "C" void dep_set(int v);
extern "C" void ctor_log_append(char c);
extern "C" int dep_ifunc(int x);
extern "C" int dep_glob;
extern "C" int __attribute__((weak)) missing_weak_fn();

#if defined(__clang__)
#define TLS_ATTR __attribute__((tls_model("global-dynamic")))
#else
#define TLS_ATTR
#endif

extern "C" thread_local TLS_ATTR int dep_tls_x;

static thread_local TLS_ATTR int g_mid_tls = 5;
static int g_mid_ctor;

__attribute__((constructor)) static void mid_ctor() {
    ctor_log_append('M');
    g_mid_ctor = dep_get() + 1;
}

extern "C" int mid_add3(int a, int b, int c) { return dep_add(dep_add(a, b), c); }

extern "C" int mid_use_dep_data() { return dep_get(); }

extern "C" void mid_bump_dep(int v) { dep_set(v); }

extern "C" int mid_ctor_val() { return g_mid_ctor; }

extern "C" int mid_ifunc(int x) { return dep_ifunc(x); }

extern "C" int mid_weak() { return missing_weak_fn ? missing_weak_fn() : 99; }

extern "C" int mid_tls() { return g_mid_tls; }

extern "C" int mid_tls_set(int v) {
    g_mid_tls = v;
    return g_mid_tls;
}

extern "C" int mid_ifunc_impl(int x) { return x + 100; }

extern "C" void* resolve_mid_ifunc() { return reinterpret_cast<void*>(&mid_ifunc_impl); }

extern "C" int mid_own_ifunc(int x) __attribute__((ifunc("resolve_mid_ifunc")));

extern "C" int mid_glob() { return dep_glob; }

extern "C" int mid_ext_tls() { return dep_tls_x; }

extern "C" int mid_ext_tls_set(int v) {
    dep_tls_x = v;
    return dep_tls_x;
}
