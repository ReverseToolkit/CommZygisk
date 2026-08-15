// Traditional GD: __tls_get_addr(TlsIndex*). The TlsIndex slots start as
// RELATIVE so lld emits .rela.dyn entries; gen_tls_trad.py rewrites them
// to TLS_DTPMOD / TLS_DTPREL (Android lld cannot emit those itself).
extern "C" void* __tls_get_addr(const void* ti);

extern "C" int trad_get();
extern "C" int trad_set(int a, int b);

__attribute__((used)) static thread_local int g_a = 10;
__attribute__((used)) static thread_local int g_b = 20;

extern "C" unsigned long tls_idx_a[2] = {
        reinterpret_cast<unsigned long>(&trad_get),
        reinterpret_cast<unsigned long>(&trad_set),
};
extern "C" unsigned long tls_idx_b[2] = {
        reinterpret_cast<unsigned long>(&trad_get),
        reinterpret_cast<unsigned long>(&trad_set),
};

extern "C" int trad_get() {
    auto* a = static_cast<int*>(__tls_get_addr(tls_idx_a));
    auto* b = static_cast<int*>(__tls_get_addr(tls_idx_b));
    return *a + *b;
}

extern "C" int trad_set(int a, int b) {
    *static_cast<int*>(__tls_get_addr(tls_idx_a)) = a;
    *static_cast<int*>(__tls_get_addr(tls_idx_b)) = b;
    return a + b;
}
