#include "linker.hpp"

#include <pthread.h>

#include <cstdio>
#include <cstring>
#include <string>

extern int g_fail;
extern int g_pass;
void Expect(bool ok, const char* name, const char* detail);
std::string ReadMaps();
bool MapsHas(const std::string& maps, const char* needle);

namespace {

struct TlsArg {
    int (*get)();
    int (*set)(int);
    int value;
    int seen;
};

void* TlsThread(void* p) {
    auto* a = static_cast<TlsArg*>(p);
    a->seen = a->get();
    a->set(a->value);
    return nullptr;
}

std::string Join(const char* dir, const char* name) {
    std::string s = dir;
    if (!s.empty() && s.back() != '/') {
        s += '/';
    }
    s += name;
    return s;
}

}  // namespace

void RunComplexTests(const char* dir) {
    using IntFn = int (*)();
    using Int1Fn = int (*)(int);
    using Int2Fn = int (*)(int, int);
    using Int3Fn = int (*)(int, int, int);
    using SetFn = void (*)(int);
    using StrFn = const char* (*)();
    using CbSet = void (*)(int (*)(int, int));

    linker::android_update_LD_LIBRARY_PATH(dir);

    void* top = linker::dlopen(Join(dir, "libtop.so").c_str(), RTLD_NOW | RTLD_GLOBAL);
    Expect(top != nullptr, "complex dlopen libtop", top ? "" : linker::dlerror());
    if (top == nullptr) {
        return;
    }

    auto chain = reinterpret_cast<Int3Fn>(linker::dlsym(top, "top_chain"));
    Expect(chain && chain(1, 2, 3) == 1 + 2 + 3 + 31, "cross-so chain 1+2+3+f31",
           chain ? "" : linker::dlerror());

    auto order = reinterpret_cast<StrFn>(linker::dlsym(top, "top_order"));
    const char* ord = order ? order() : "";
    printf("     ctor order=%s\n", ord);
    Expect(order && strcmp(ord, "DMT") == 0, "ctor order DMT (dep, mid, top)", ord);

    auto mid_ctor = reinterpret_cast<IntFn>(linker::dlsym(top, "top_mid_ctor"));
    Expect(mid_ctor && mid_ctor() == 12, "mid ctor saw dep_get()+1", "");

    auto data = reinterpret_cast<IntFn>(linker::dlsym(top, "top_data"));
    auto set_data = reinterpret_cast<SetFn>(linker::dlsym(top, "top_set_data"));
    Expect(data && data() == 11, "dep data initial 11", "");
    if (set_data && data) {
        set_data(77);
        Expect(data() == 77, "dep data write via mid/top", "");
    }

    auto ifns = reinterpret_cast<Int1Fn>(linker::dlsym(top, "top_ifuncs"));
    Expect(ifns && ifns(4) == 12 + 104, "IFUNC dep*3 + mid+100", ifns ? "" : linker::dlerror());

    auto weak = reinterpret_cast<IntFn>(linker::dlsym(top, "top_weak"));
    Expect(weak && weak() == 99, "weak undefined -> 99", "");

    auto direct = reinterpret_cast<Int2Fn>(linker::dlsym(top, "top_direct_dep"));
    Expect(direct && direct(8, 9) == 17, "top directly calls dep_add", "");

    auto cbset = reinterpret_cast<CbSet>(linker::dlsym(top, "top_set_cb"));
    auto cb = reinterpret_cast<Int2Fn>(linker::dlsym(top, "top_cb"));
    if (cbset && cb && direct) {
        cbset(direct);
        Expect(cb(4, 6) == 10, "callback into relocated fn ptr", "");
    }

    void* dep = linker::dlopen(Join(dir, "libdep.so").c_str(), RTLD_NOW | RTLD_NOLOAD);
    Expect(dep != nullptr, "NOLOAD libdep after top", dep ? "" : linker::dlerror());

    auto bss = reinterpret_cast<IntFn>(linker::dlsym(dep, "dep_bss_ok"));
    Expect(bss && bss() == 3, "64K BSS read/write", bss ? "" : linker::dlerror());

    auto table = reinterpret_cast<IntFn>(linker::dlsym(dep, "dep_table_sum"));
    Expect(table && table() == 0 + 1 + 2 + 3 + 4 + 5 + 6 + 7, "RELATIVE fn table sum", "");

    int gnu_ok = 1;
    for (int i = 0; i < 32; ++i) {
        char name[16];
        snprintf(name, sizeof(name), "dep_f%d", i);
        auto fn = reinterpret_cast<IntFn>(linker::dlsym(dep, name));
        if (fn == nullptr || fn() != i) {
            gnu_ok = 0;
            printf("     missing %s\n", name);
            break;
        }
    }
    Expect(gnu_ok, "GNU hash 32 symbols dep_f0..31", "");

    auto vadd = reinterpret_cast<Int2Fn>(linker::dlvsym(dep, "dep_add", "DEP_1.0"));
    auto vmul = reinterpret_cast<Int2Fn>(linker::dlvsym(dep, "dep_mul", "DEP_2.0"));
    Expect(vadd && vadd(2, 8) == 10, "dlvsym dep_add@DEP_1.0", vadd ? "" : linker::dlerror());
    Expect(vmul && vmul(3, 5) == 15, "dlvsym dep_mul@DEP_2.0", vmul ? "" : linker::dlerror());
    void* badver = linker::dlvsym(dep, "dep_add", "NO_SUCH_VER");
    Expect(badver == nullptr, "dlvsym wrong version fails", "");

    auto def_add = reinterpret_cast<Int2Fn>(linker::dlsym(RTLD_DEFAULT, "dep_add"));
    Expect(def_add && def_add(1, 1) == 2, "RTLD_DEFAULT finds GLOBAL dep_add",
           def_add ? "" : linker::dlerror());

    auto tls_get = reinterpret_cast<IntFn>(linker::dlsym(dep, "dep_tls"));
    auto tls_set = reinterpret_cast<int (*)(int)>(linker::dlsym(dep, "dep_tls_set"));
    Expect(tls_get && tls_get() == 100, "dep tls default 100", "");
    if (tls_get && tls_set) {
        TlsArg arg{tls_get, tls_set, 55, -1};
        pthread_t th{};
        Expect(pthread_create(&th, nullptr, TlsThread, &arg) == 0, "pthread_create", "");
        pthread_join(th, nullptr);
        printf("     thread tls seen=%d main=%d\n", arg.seen, tls_get());
        Expect(arg.seen == 100, "thread tls default isolated", "");
        Expect(tls_get() == 100, "main tls unchanged by other thread", "");
        Expect(tls_set(3) == 3 && tls_get() == 3, "main tls set after thread", "");
    }

    void* mid = linker::dlopen(Join(dir, "libmid.so").c_str(), RTLD_NOW | RTLD_NOLOAD);
    auto mid_tls = reinterpret_cast<IntFn>(linker::dlsym(mid, "mid_tls"));
    auto mid_tls_set = reinterpret_cast<int (*)(int)>(linker::dlsym(mid, "mid_tls_set"));
    Expect(mid && mid_tls && mid_tls() == 5, "mid tls default 5", "");
    if (mid_tls_set) {
        Expect(mid_tls_set(9) == 9 && mid_tls() == 9, "mid tls set/get", "");
    }

    auto glob = reinterpret_cast<IntFn>(linker::dlsym(mid, "mid_glob"));
    Expect(glob && glob() == 123, "GLOB_DAT cross-so dep_glob", glob ? "" : linker::dlerror());

    auto ext_tls = reinterpret_cast<IntFn>(linker::dlsym(mid, "mid_ext_tls"));
    auto ext_tls_set = reinterpret_cast<int (*)(int)>(linker::dlsym(mid, "mid_ext_tls_set"));
    Expect(ext_tls && ext_tls() == 7, "cross-so extern TLS default 7",
           ext_tls ? "" : linker::dlerror());
    if (ext_tls && ext_tls_set) {
        Expect(ext_tls_set(42) == 42 && ext_tls() == 42, "cross-so extern TLS set/get", "");
    }

    auto ifunc_local = reinterpret_cast<Int1Fn>(linker::dlsym(dep, "dep_ifunc_local"));
    Expect(ifunc_local && ifunc_local(5) == 15, "same-module IRELATIVE via ifunc",
           ifunc_local ? "" : linker::dlerror());
    auto* slot = reinterpret_cast<Int1Fn*>(linker::dlsym(dep, "dep_ifunc_slot"));
    Expect(slot && *slot && (*slot)(6) == 18, "IRELATIVE slot resolved to ifunc_impl",
           slot ? "" : linker::dlerror());

    const std::string maps = ReadMaps();
    Expect(!MapsHas(maps, "libdep.so") && !MapsHas(maps, "libmid.so") &&
                   !MapsHas(maps, "libtop.so"),
           "maps hide dep/mid/top", "");

    int seen = 0;
    linker::dl_iterate_phdr(
            [](dl_phdr_info* ph, size_t, void* arg) -> int {
                if (ph->dlpi_name && strstr(ph->dlpi_name, "libtop.so")) {
                    *static_cast<int*>(arg) += 1;
                }
                if (ph->dlpi_name && strstr(ph->dlpi_name, "libdep.so")) {
                    *static_cast<int*>(arg) += 10;
                }
                return 0;
            },
            &seen);
    Expect(seen >= 11, "dl_iterate_phdr sees top+dep", "");

    void* byname = linker::dlopen("libtop.so", RTLD_NOW | RTLD_NOLOAD);
    Expect(byname == top, "dlopen soname NOLOAD returns same handle", "");

    Expect(linker::dlclose(top) == 0, "dlclose top", "");
}
