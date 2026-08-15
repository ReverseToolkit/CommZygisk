#include "linker.hpp"

#include <cstdio>
#include <cstring>
#include <string>

void Expect(bool ok, const char* name, const char* detail);

namespace {

std::string Join(const char* dir, const char* name) {
    std::string s = dir;
    if (!s.empty() && s.back() != '/') {
        s += '/';
    }
    s += name;
    return s;
}

void* Open(const char* dir, const char* name) {
    void* h = linker::dlopen(Join(dir, name).c_str(), RTLD_NOW);
    Expect(h != nullptr, name, h ? "" : linker::dlerror());
    return h;
}

}  // namespace

void RunRelocTlsTests(const char* dir) {
    using IntFn = int (*)();
    using Int1Fn = int (*)(int);
    using Int2Fn = int (*)(int, int);
    using Int3Fn = int (*)(int, int, int);
    using StrFn = const char* (*)();

    printf("\n--- reloc + tls coverage ---\n");

    void* relr = Open(dir, "librel_relr.so");
    if (relr) {
        auto sum = reinterpret_cast<IntFn>(linker::dlsym(relr, "pack_sum"));
        auto str = reinterpret_cast<IntFn>(linker::dlsym(relr, "pack_str"));
        Expect(sum && sum() == 31 * 32 / 2, "RELR pack_sum 0..31", sum ? "" : linker::dlerror());
        Expect(str && str() == ('3' + '0'), "RELR string pointers", "");
        linker::dlclose(relr);
    }

    void* aps2 = Open(dir, "librel_aps2.so");
    if (aps2) {
        auto sum = reinterpret_cast<IntFn>(linker::dlsym(aps2, "pack_sum"));
        auto str = reinterpret_cast<IntFn>(linker::dlsym(aps2, "pack_str"));
        Expect(sum && sum() == 31 * 32 / 2, "APS2 pack_sum 0..31", sum ? "" : linker::dlerror());
        Expect(str && str() == ('3' + '0'), "APS2 string pointers", "");
        linker::dlclose(aps2);
    }

    void* trad = Open(dir, "libtls_trad.so");
    if (trad) {
        auto get = reinterpret_cast<IntFn>(linker::dlsym(trad, "trad_get"));
        auto set = reinterpret_cast<Int2Fn>(linker::dlsym(trad, "trad_set"));
        Expect(get && get() == 30, "trad GD TLS default 10+20", get ? "" : linker::dlerror());
        Expect(set && set(4, 5) == 9 && get() == 9, "trad GD TLS set via __tls_get_addr", "");
        linker::dlclose(trad);
    }

    void* multi = Open(dir, "libtls_multi.so");
    if (multi) {
        auto tdata = reinterpret_cast<IntFn>(linker::dlsym(multi, "multi_tdata"));
        auto tbss = reinterpret_cast<IntFn>(linker::dlsym(multi, "multi_tbss"));
        auto set = reinterpret_cast<Int3Fn>(linker::dlsym(multi, "multi_set"));
        auto msg = reinterpret_cast<StrFn>(linker::dlsym(multi, "multi_msg"));
        Expect(tdata && tdata() == 6, "multi TLS tdata 1+2+3", tdata ? "" : linker::dlerror());
        Expect(tbss && tbss() == 0, "multi TLS tbss zero-fill", "");
        Expect(set && set(10, 20, 7) == 37, "multi TLS tdata+tbss write", "");
        Expect(tbss && tbss() == 20 + 7, "multi TLS tbss after write", "");
        Expect(msg && strcmp(msg(), "hi") == 0, "multi TLS char[] tdata", "");
        linker::dlclose(multi);
    }

    void* ie = linker::dlopen(Join(dir, "libtls_ie.so").c_str(), RTLD_NOW);
    Expect(ie == nullptr, "IE TPREL on dlopened so is rejected",
           ie ? "loaded but should fail" : linker::dlerror());
    if (ie) {
        linker::dlclose(ie);
    }

    void* none = linker::dlopen(Join(dir, "librel_relr.so").c_str(), RTLD_NOW);
    if (none) {
        Expect(linker::dlsym(none, "no_such_sym") == nullptr, "undefined JUMP_SLOT/dlsym fails", "");
        linker::dlclose(none);
    }
}
