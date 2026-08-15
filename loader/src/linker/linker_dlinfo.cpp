#include "linker_image.hpp"

#include <dlfcn.h>
#include <link.h>

#include <cstring>

namespace linker {
namespace {

struct IterateCtx {
    int (*cb)(dl_phdr_info*, size_t, void*);
    void* data;
    int rc = 0;
};

void IterateOne(Image* so, void* arg) {
    auto* ctx = static_cast<IterateCtx*>(arg);
    if (ctx->rc != 0 || !so->owns_mapping || so->phdr == nullptr) {
        return;
    }
    dl_phdr_info info{};
    info.dlpi_addr = so->load_bias;
    info.dlpi_name = so->name.empty() ? so->soname.c_str() : so->name.c_str();
    info.dlpi_phdr = so->phdr;
    info.dlpi_phnum = so->phnum;
    ctx->rc = ctx->cb(&info, sizeof(info), ctx->data);
}

using SystemIterate = int (*)(int (*)(dl_phdr_info*, size_t, void*), void*);

SystemIterate SystemDlIterate() {
    static SystemIterate fn = nullptr;
    if (fn != nullptr) {
        return fn;
    }
    const LookupResult r = ResolveLookup("dl_iterate_phdr", nullptr);
    if (r.sym != nullptr) {
        fn = reinterpret_cast<SystemIterate>(SymAddr(r.found_in, r.sym));
    }
    return fn;
}

}  // namespace

int dl_iterate_phdr(int (*cb)(dl_phdr_info* info, size_t size, void* data), void* data) {
    if (cb == nullptr) {
        return 0;
    }
    EnsureProcessImages();
    IterateCtx ctx{cb, data, 0};
    ForEachImage(IterateOne, &ctx);
    if (ctx.rc != 0) {
        return ctx.rc;
    }
    SystemIterate sys = SystemDlIterate();
    return sys ? sys(cb, data) : 0;
}

int dladdr(const void* addr, Dl_info* info) {
    if (info == nullptr || addr == nullptr) {
        return 0;
    }
    memset(info, 0, sizeof(*info));
    EnsureProcessImages();
    Image* so = FindByAddress(addr);
    if (so == nullptr) {
        return 0;
    }
    info->dli_fname = so->name.empty() ? so->soname.c_str() : so->name.c_str();
    info->dli_fbase = so->load_start;
    const auto target = reinterpret_cast<uintptr_t>(addr);
    const ElfW(Sym)* best = nullptr;
    uintptr_t best_addr = 0;
    if (so->dynsym != nullptr && so->dynstr != nullptr) {
        if (so->gnu_nbuckets != 0) {
            for (uint32_t b = 0; b < so->gnu_nbuckets; ++b) {
                uint32_t i = so->gnu_buckets[b];
                if (i < so->gnu_symoffset) {
                    continue;
                }
                const uint32_t* chain = so->gnu_chain + (i - so->gnu_symoffset);
                do {
                    const ElfW(Sym)* sym = so->dynsym + i;
                    if (sym->st_shndx != SHN_UNDEF && ELF_ST_TYPE(sym->st_info) != STT_TLS) {
                        const uintptr_t sa = so->load_bias + sym->st_value;
                        if (sa <= target && sa >= best_addr) {
                            best = sym;
                            best_addr = sa;
                        }
                    }
                    i++;
                } while ((*chain++ & 1) == 0);
            }
        } else if (so->nsyms != 0) {
            for (size_t i = 0; i < so->nsyms; ++i) {
                const ElfW(Sym)* sym = so->dynsym + i;
                if (sym->st_shndx != SHN_UNDEF && ELF_ST_TYPE(sym->st_info) != STT_TLS) {
                    const uintptr_t sa = so->load_bias + sym->st_value;
                    if (sa <= target && sa >= best_addr) {
                        best = sym;
                        best_addr = sa;
                    }
                }
            }
        }
    }
    if (best != nullptr) {
        info->dli_sname = so->dynstr + best->st_name;
        info->dli_saddr = reinterpret_cast<void*>(best_addr);
    }
    return 1;
}

#if defined(__arm__)
void* dl_unwind_find_exidx(void* pc, int* pcount) {
    Image* so = FindByAddress(pc);
    if (so == nullptr || so->arm_exidx == nullptr) {
        if (pcount) {
            *pcount = 0;
        }
        return nullptr;
    }
    if (pcount) {
        *pcount = static_cast<int>(so->arm_exidx_count);
    }
    return so->arm_exidx;
}
#endif

}  // namespace linker
