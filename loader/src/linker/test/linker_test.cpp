#include "linker.hpp"
#include "prot_hide.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

int g_fail = 0;
int g_pass = 0;

void RunComplexTests(const char* dir);
void RunRelocTlsTests(const char* dir);

void Expect(bool ok, const char* name, const char* detail) {
    if (ok) {
        ++g_pass;
        printf("OK   %s\n", name);
    } else {
        ++g_fail;
        printf("FAIL %s%s%s\n", name, detail && detail[0] ? ": " : "", detail ? detail : "");
    }
}

std::string ReadMaps() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return "";
    }
    std::string out;
    char buf[512];
    while (fgets(buf, sizeof(buf), fp)) {
        out += buf;
    }
    fclose(fp);
    return out;
}

bool MapsHas(const std::string& maps, const char* needle) {
    return maps.find(needle) != std::string::npos;
}

bool AddrInMaps(const std::string& maps, const void* addr) {
    const auto p = reinterpret_cast<uintptr_t>(addr);
    const char* cur = maps.c_str();
    while (*cur) {
        const char* nl = strchr(cur, '\n');
        unsigned long start = 0;
        unsigned long end = 0;
        if (sscanf(cur, "%lx-%lx", &start, &end) == 2 && p >= start && p < end) {
            return true;
        }
        cur = nl ? nl + 1 : cur + strlen(cur);
    }
    return false;
}

int CopyToMemfd(const char* path) {
    int src = open(path, O_RDONLY | O_CLOEXEC);
    if (src < 0) {
        return -1;
    }
    int fd = static_cast<int>(syscall(SYS_memfd_create, "linker-test", 0));
    if (fd < 0) {
        close(src);
        return -1;
    }
    char buf[4096];
    for (;;) {
        ssize_t n = read(src, buf, sizeof(buf));
        if (n < 0) {
            close(src);
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        if (write(fd, buf, static_cast<size_t>(n)) != n) {
            close(src);
            close(fd);
            return -1;
        }
    }
    close(src);
    lseek(fd, 0, SEEK_SET);
    return fd;
}

int main(int argc, char** argv) {
    const char* mod = argc > 1 ? argv[1] : "/data/local/tmp/linker_test/liblinker_testmod.so";
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    printf("module: %s\n", mod);
    printf("PROT_HIDE=0x%x\n", PROT_HIDE);

    void* h = linker::dlopen(mod, RTLD_NOW);
    Expect(h != nullptr, "dlopen", h ? "" : linker::dlerror());
    if (h == nullptr) {
        printf("%d passed, %d failed\n", g_pass, g_fail);
        return 1;
    }

    using AddFn = int (*)(int, int);
    using IntFn = int (*)();
    using SetFn = int (*)(int);
    using StrFn = const char* (*)();

    auto add = reinterpret_cast<AddFn>(linker::dlsym(h, "linker_test_add"));
    Expect(add != nullptr, "dlsym add", linker::dlerror());
    Expect(add && add(2, 3) == 5, "call add(2,3)==5", "");

    auto hello = reinterpret_cast<StrFn>(linker::dlsym(h, "linker_test_hello"));
    Expect(hello && strcmp(hello(), "ok") == 0, "call hello", "");

    auto ctor = reinterpret_cast<IntFn>(linker::dlsym(h, "linker_test_ctor"));
    Expect(ctor && ctor() == 1, "constructor ran", "");

    auto tls_get = reinterpret_cast<IntFn>(linker::dlsym(h, "linker_test_tls"));
    auto tls_set = reinterpret_cast<SetFn>(linker::dlsym(h, "linker_test_tls_set"));
    Expect(tls_get != nullptr && tls_set != nullptr, "dlsym tls", linker::dlerror());
    if (tls_get && tls_set) {
        const int v0 = tls_get();
        const int v1 = tls_set(7);
        const int v2 = tls_get();
        printf("     tls get/set/get = %d %d %d\n", v0, v1, v2);
        Expect(v0 == 42, "tls default 42", "");
        Expect(v1 == 7 && v2 == 7, "tls set/get", "");
    }

    Dl_info info{};
    Expect(linker::dladdr(reinterpret_cast<void*>(add), &info) != 0, "dladdr", "");
    if (info.dli_saddr) {
        printf("     dli_fname=%s dli_sname=%s\n", info.dli_fname ? info.dli_fname : "?",
               info.dli_sname ? info.dli_sname : "?");
    }

    const std::string maps = ReadMaps();
    const bool named = MapsHas(maps, "liblinker_testmod.so");
    const bool visible = add && AddrInMaps(maps, reinterpret_cast<void*>(add));
    printf("     maps named=%d addr_visible=%d\n", named ? 1 : 0, visible ? 1 : 0);
    Expect(!named, "maps hide soname (PROT_HIDE)", named ? "still in maps" : "");
    if (visible) {
        printf("     note: VMA still listed (stock kernel fallback or hide only strips name)\n");
    } else {
        printf("     note: function addr absent from maps (VM_VMA_HIDE)\n");
    }

    int seen = 0;
    linker::dl_iterate_phdr(
            [](dl_phdr_info* ph, size_t, void* arg) -> int {
                if (ph->dlpi_name && strstr(ph->dlpi_name, "liblinker_testmod.so")) {
                    *static_cast<int*>(arg) = 1;
                }
                return 0;
            },
            &seen);
    Expect(seen == 1, "dl_iterate_phdr sees our image", "");

    Expect(linker::dlclose(h) == 0, "dlclose", linker::dlerror());

    int memfd = CopyToMemfd(mod);
    Expect(memfd >= 0, "memfd copy", strerror(errno));
    if (memfd >= 0) {
        void* h2 = linker::dlopen_fd(memfd, RTLD_NOW);
        Expect(h2 != nullptr, "dlopen_fd", h2 ? "" : linker::dlerror());
        if (h2) {
            auto add2 = reinterpret_cast<AddFn>(linker::dlsym(h2, "linker_test_add"));
            Expect(add2 && add2(10, 20) == 30, "dlopen_fd call add", "");
            Expect(linker::dlclose(h2) == 0, "dlclose fd", "");
        }
        close(memfd);
    }

    void* noload = linker::dlopen(mod, RTLD_NOW | RTLD_NOLOAD);
    Expect(noload == nullptr, "RTLD_NOLOAD after close", noload ? "still loaded" : "");

    std::string dir = mod;
    const size_t slash = dir.rfind('/');
    dir = slash == std::string::npos ? "." : dir.substr(0, slash);
    printf("\n--- complex samples in %s ---\n", dir.c_str());
    RunComplexTests(dir.c_str());
    RunRelocTlsTests(dir.c_str());

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
