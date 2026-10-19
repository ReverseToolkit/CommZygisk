#include "linker_image.hpp"

#include "logging.hpp"

#include <link.h>
#include <sys/auxv.h>
#include <sys/ifunc.h>

#include <cstring>
#include <mutex>
#include <vector>

namespace linker {
namespace {

std::recursive_mutex g_lock;
std::vector<Image*> g_images;
bool g_process_attached = false;

const char* BaseName(const char* path) {
    if (path == nullptr) {
        return "";
    }
    const char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

bool NameEq(const Image* so, const char* name) {
    if (name == nullptr || name[0] == '\0') {
        return false;
    }
    if (!so->soname.empty() && so->soname == name) {
        return true;
    }
    if (!so->name.empty() && (so->name == name || strcmp(BaseName(so->name.c_str()), name) == 0)) {
        return true;
    }
    return strcmp(BaseName(so->soname.c_str()), name) == 0;
}

uint32_t GnuHash(const char* name) {
    uint32_t h = 5381;
    while (*name) {
        h = (h << 5) + h + static_cast<uint8_t>(*name++);
    }
    return h;
}

uint32_t SysvHash(const char* name) {
    uint32_t h = 0;
    while (*name) {
        h = (h << 4) + static_cast<uint8_t>(*name++);
        const uint32_t g = h & 0xf0000000;
        if (g) {
            h ^= g >> 24;
        }
        h &= ~g;
    }
    return h;
}

bool Usable(const Image* so, uint32_t n, const char* ver) {
    const ElfW(Sym)* sym = so->dynsym + n;
    if (sym->st_shndx == SHN_UNDEF) {
        return false;
    }
    const unsigned bind = ELF_ST_BIND(sym->st_info);
    if (bind != STB_GLOBAL && bind != STB_WEAK && bind != STB_GNU_UNIQUE) {
        return false;
    }
    if (ELF_ST_VISIBILITY(sym->st_other) == STV_HIDDEN) {
        return false;
    }
    return SymbolVersionOk(so, n, ver);
}

LookupResult LookupGnu(const Image* so, const char* name, const char* ver) {
    LookupResult r;
    if (so->gnu_nbuckets == 0 || so->gnu_bloom_sz == 0 || so->dynsym == nullptr) {
        return r;
    }
    const uint32_t hash = GnuHash(name);
    const ElfW(Addr) bloom_word = so->gnu_bloom[(hash / (8 * sizeof(ElfW(Addr)))) % so->gnu_bloom_sz];
    const ElfW(Addr) mask =
            (static_cast<ElfW(Addr)>(1) << (hash % (8 * sizeof(ElfW(Addr))))) |
            (static_cast<ElfW(Addr)>(1) << ((hash >> so->gnu_shift2) % (8 * sizeof(ElfW(Addr)))));
    if ((bloom_word & mask) != mask) {
        return r;
    }
    uint32_t n = so->gnu_buckets[hash % so->gnu_nbuckets];
    if (n < so->gnu_symoffset) {
        return r;
    }
    const uint32_t* chain = so->gnu_chain + (n - so->gnu_symoffset);
    do {
        const ElfW(Sym)* sym = so->dynsym + n;
        if (((*chain ^ hash) >> 1) == 0 && strcmp(so->dynstr + sym->st_name, name) == 0 &&
            Usable(so, n, ver)) {
            r.found_in = const_cast<Image*>(so);
            r.sym = sym;
            r.sym_idx = n;
            return r;
        }
        n++;
    } while ((*chain++ & 1) == 0);
    return r;
}

LookupResult LookupSysv(const Image* so, const char* name, const char* ver) {
    LookupResult r;
    if (so->sysv_nbuckets == 0 || so->dynsym == nullptr) {
        return r;
    }
    const uint32_t hash = SysvHash(name);
    for (uint32_t n = so->sysv_buckets[hash % so->sysv_nbuckets]; n != 0; n = so->sysv_chains[n]) {
        const ElfW(Sym)* sym = so->dynsym + n;
        if (strcmp(so->dynstr + sym->st_name, name) == 0 && Usable(so, n, ver)) {
            r.found_in = const_cast<Image*>(so);
            r.sym = sym;
            r.sym_idx = n;
            return r;
        }
    }
    return r;
}

int AttachPhdr(dl_phdr_info* info, size_t, void*) {
    const auto bias = static_cast<uintptr_t>(info->dlpi_addr);
    for (Image* existing : g_images) {
        if (existing->load_bias == bias) {
            return 0;
        }
    }
    auto* so = new Image();
    so->owns_mapping = false;
    so->load_bias = static_cast<uintptr_t>(info->dlpi_addr);
    if (info->dlpi_name && info->dlpi_name[0]) {
        so->name = info->dlpi_name;
    }
    so->phdr = info->dlpi_phdr;
    so->phnum = info->dlpi_phnum;
    so->global = true;
    so->constructors_called = true;
    if (!BindPhdrs(so, info->dlpi_phdr, info->dlpi_phnum)) {
        delete so;
        return 0;
    }
    Register(so);
    return 0;
}

}  // namespace

bool IsImage(const void* handle) {
    auto* so = static_cast<const Image*>(handle);
    return so != nullptr && so->magic == Image::kMagic;
}

Image* AsImage(void* handle) { return IsImage(handle) ? static_cast<Image*>(handle) : nullptr; }

void Register(Image* so) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    g_images.push_back(so);
}

void Unregister(Image* so) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    for (auto it = g_images.begin(); it != g_images.end(); ++it) {
        if (*it == so) {
            g_images.erase(it);
            return;
        }
    }
}

Image* FindBySoname(const char* name) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    for (Image* so : g_images) {
        if (NameEq(so, name)) {
            return so;
        }
    }
    return nullptr;
}

Image* FindByDevIno(dev_t dev, ino_t ino) {
    if (dev == 0 && ino == 0) {
        return nullptr;
    }
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    for (Image* so : g_images) {
        if (so->st_dev == dev && so->st_ino == ino) {
            return so;
        }
    }
    return nullptr;
}

Image* FindByAddress(const void* addr) {
    const auto p = reinterpret_cast<uintptr_t>(addr);
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    for (Image* so : g_images) {
        const auto start = reinterpret_cast<uintptr_t>(so->load_start);
        if (so->load_start != nullptr && p >= start && p < start + so->load_size) {
            return so;
        }
    }
    return nullptr;
}

void ForEachImage(void (*fn)(Image* so, void* arg), void* arg) {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    for (Image* so : g_images) {
        fn(so, arg);
    }
}

void RefreshProcessImages() {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    g_process_attached = true;
    ::dl_iterate_phdr(AttachPhdr, nullptr);
}

void EnsureProcessImages() {
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    if (g_process_attached) {
        return;
    }
    RefreshProcessImages();
}

LookupResult Lookup(const Image* so, const char* name, const char* ver) {
    LookupResult r = LookupGnu(so, name, ver);
    if (r.sym != nullptr) {
        return r;
    }
    return LookupSysv(so, name, ver);
}

LookupResult ResolveLookup(const char* name, const char* ver, Image* except) {
    LookupResult r;
    if (name == nullptr || name[0] == '\0') {
        return r;
    }
    std::lock_guard<std::recursive_mutex> lock(g_lock);
    if (except != nullptr && except->has_symbolic) {
        r = Lookup(except, name, ver);
        if (r.sym != nullptr) {
            return r;
        }
    }
    for (Image* so : g_images) {
        if (so == except || (!so->global && so->owns_mapping)) {
            continue;
        }
        r = Lookup(so, name, ver);
        if (r.sym != nullptr) {
            return r;
        }
    }
    if (except != nullptr) {
        for (Image* child : except->children) {
            r = Lookup(child, name, ver);
            if (r.sym != nullptr) {
                return r;
            }
        }
    }
    return {};
}

ElfW(Addr) CallIfuncResolver(ElfW(Addr) resolver) {
#if defined(__aarch64__)
    using ResolverFn = ElfW(Addr) (*)(uint64_t, __ifunc_arg_t*);
    static __ifunc_arg_t arg = {
            ._size = sizeof(__ifunc_arg_t),
            ._hwcap = getauxval(AT_HWCAP),
            ._hwcap2 = getauxval(AT_HWCAP2),
    };
    return reinterpret_cast<ResolverFn>(resolver)(arg._hwcap | _IFUNC_ARG_HWCAP, &arg);
#elif defined(__arm__)
    using ResolverFn = ElfW(Addr) (*)(unsigned long);
    static unsigned long hwcap = getauxval(AT_HWCAP);
    return reinterpret_cast<ResolverFn>(resolver)(hwcap);
#else
    using ResolverFn = ElfW(Addr) (*)();
    return reinterpret_cast<ResolverFn>(resolver)();
#endif
}

void* SymAddr(const Image* so, const ElfW(Sym) * sym) {
    if (sym == nullptr || sym->st_shndx == SHN_UNDEF) {
        return nullptr;
    }
    ElfW(Addr) addr = so->load_bias + sym->st_value;
    if (ELF_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
        addr = CallIfuncResolver(addr);
    }
    return reinterpret_cast<void*>(addr);
}

void* ResolveSymbol(const char* name) {
    if (name == nullptr || name[0] == '\0') {
        return nullptr;
    }
    if (void* api = ResolveLinkerApi(name)) {
        return api;
    }
    const LookupResult r = ResolveLookup(name, nullptr);
    return SymAddr(r.found_in, r.sym);
}

bool ParseDynamic(Image* so) {
    if (so->dynamic == nullptr) {
        return false;
    }
    ElfW(Addr) strtab = 0;
    ElfW(Addr) symtab = 0;
    ElfW(Addr) gnu_hash = 0;
    ElfW(Addr) sysv_hash = 0;
    ElfW(Addr) soname_off = 0;
    ElfW(Addr) runpath_off = 0;
    bool have_soname = false;
    bool have_runpath = false;
    size_t syment = sizeof(ElfW(Sym));
    std::vector<ElfW(Addr)> needed_off;

    for (const ElfW(Dyn)* d = so->dynamic; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
        case DT_SYMTAB:
            symtab = d->d_un.d_ptr;
            break;
        case DT_SYMENT:
            syment = d->d_un.d_val;
            break;
        case DT_STRTAB:
            strtab = d->d_un.d_ptr;
            break;
        case DT_STRSZ:
            so->dynstr_size = d->d_un.d_val;
            break;
        case DT_HASH:
            sysv_hash = d->d_un.d_ptr;
            break;
        case DT_GNU_HASH:
            gnu_hash = d->d_un.d_ptr;
            break;
        case DT_NEEDED:
            needed_off.push_back(d->d_un.d_val);
            break;
        case DT_SONAME:
            soname_off = d->d_un.d_val;
            have_soname = true;
            break;
        case DT_RUNPATH:
        case DT_RPATH:
            runpath_off = d->d_un.d_val;
            have_runpath = true;
            break;
        case DT_INIT:
            so->init = reinterpret_cast<void (*)()>(so->load_bias + d->d_un.d_ptr);
            break;
        case DT_INIT_ARRAY:
            so->init_array = reinterpret_cast<void (**)()>(so->load_bias + d->d_un.d_ptr);
            break;
        case DT_INIT_ARRAYSZ:
            so->init_array_count = d->d_un.d_val / sizeof(void*);
            break;
        case DT_FINI:
            so->fini = reinterpret_cast<void (*)()>(so->load_bias + d->d_un.d_ptr);
            break;
        case DT_FINI_ARRAY:
            so->fini_array = reinterpret_cast<void (**)()>(so->load_bias + d->d_un.d_ptr);
            break;
        case DT_FINI_ARRAYSZ:
            so->fini_array_count = d->d_un.d_val / sizeof(void*);
            break;
        case DT_PREINIT_ARRAY:
            so->preinit_array = reinterpret_cast<void (**)()>(so->load_bias + d->d_un.d_ptr);
            break;
        case DT_PREINIT_ARRAYSZ:
            so->preinit_array_count = d->d_un.d_val / sizeof(void*);
            break;
        case DT_FLAGS:
            so->dt_flags = static_cast<uint32_t>(d->d_un.d_val);
            break;
        case DT_FLAGS_1:
            so->dt_flags_1 = static_cast<uint32_t>(d->d_un.d_val);
            break;
        case DT_SYMBOLIC:
            so->has_symbolic = true;
            break;
        case DT_TEXTREL:
            so->has_textrel = true;
            break;
        case DT_BIND_NOW:
            so->dt_flags |= DF_BIND_NOW;
            break;
        case DT_VERSYM:
            so->versym = reinterpret_cast<const ElfW(Versym)*>(so->load_bias + d->d_un.d_ptr);
            break;
        case DT_VERNEED:
            so->verneed_ptr = d->d_un.d_ptr;
            break;
        case DT_VERNEEDNUM:
            so->verneed_cnt = d->d_un.d_val;
            break;
        case DT_VERDEF:
            so->verdef_ptr = d->d_un.d_ptr;
            break;
        case DT_VERDEFNUM:
            so->verdef_cnt = d->d_un.d_val;
            break;
        default:
            break;
        }
    }
    if (strtab == 0 || symtab == 0 || syment != sizeof(ElfW(Sym))) {
        return false;
    }
    so->dynstr = reinterpret_cast<const char*>(so->load_bias + strtab);
    so->dynsym = reinterpret_cast<const ElfW(Sym)*>(so->load_bias + symtab);
    so->runpath = have_runpath ? ExpandPathVars(so->dynstr + runpath_off, so) : "";
    if (so->dt_flags & DF_SYMBOLIC) {
        so->has_symbolic = true;
    }
    if (so->dt_flags & DF_TEXTREL) {
        so->has_textrel = true;
    }
    if (so->dt_flags_1 & DF_1_NODELETE) {
        so->nodelete = true;
    }
    if (so->dt_flags_1 & DF_1_GLOBAL) {
        so->global = true;
    }
    if (have_soname) {
        so->soname = so->dynstr + soname_off;
    } else if (!so->name.empty()) {
        so->soname = BaseName(so->name.c_str());
    }
    so->needed.clear();
    for (ElfW(Addr) off : needed_off) {
        const char* n = so->dynstr + off;
        if (n[0]) {
            so->needed.emplace_back(n);
        }
    }
    if (gnu_hash != 0) {
        const auto* p = reinterpret_cast<const uint32_t*>(so->load_bias + gnu_hash);
        so->gnu_nbuckets = p[0];
        so->gnu_symoffset = p[1];
        so->gnu_bloom_sz = p[2];
        so->gnu_shift2 = p[3];
        so->gnu_bloom = reinterpret_cast<const ElfW(Addr)*>(p + 4);
        so->gnu_buckets = reinterpret_cast<const uint32_t*>(so->gnu_bloom + so->gnu_bloom_sz);
        so->gnu_chain = so->gnu_buckets + so->gnu_nbuckets;
    }
    if (sysv_hash != 0) {
        const auto* p = reinterpret_cast<const uint32_t*>(so->load_bias + sysv_hash);
        so->sysv_nbuckets = p[0];
        so->nsyms = p[1];
        so->sysv_buckets = p + 2;
        so->sysv_chains = so->sysv_buckets + so->sysv_nbuckets;
    }
    return so->dynsym != nullptr && so->dynstr != nullptr;
}

#ifndef NT_GNU_PROPERTY_TYPE_0
#define NT_GNU_PROPERTY_TYPE_0 5
#endif
#ifndef GNU_PROPERTY_AARCH64_FEATURE_1_AND
#define GNU_PROPERTY_AARCH64_FEATURE_1_AND 0xc0000000
#endif
#ifndef GNU_PROPERTY_AARCH64_FEATURE_1_BTI
#define GNU_PROPERTY_AARCH64_FEATURE_1_BTI 1
#endif

void ParseGnuProperty(Image* so, const ElfW(Phdr)& ph) {
    const auto* note = reinterpret_cast<const ElfW(Nhdr)*>(so->load_bias + ph.p_vaddr);
    const char* end = reinterpret_cast<const char*>(note) + ph.p_memsz;
    while (reinterpret_cast<const char*>(note) + sizeof(ElfW(Nhdr)) < end) {
        const char* name = reinterpret_cast<const char*>(note) + sizeof(ElfW(Nhdr));
        const auto* desc = reinterpret_cast<const uint32_t*>(name + ((note->n_namesz + 3) & ~3u));
        if (note->n_type == NT_GNU_PROPERTY_TYPE_0 && note->n_namesz == 4 &&
            memcmp(name, "GNU", 4) == 0 && note->n_descsz >= 8) {
            if (desc[0] == GNU_PROPERTY_AARCH64_FEATURE_1_AND &&
                (desc[2] & GNU_PROPERTY_AARCH64_FEATURE_1_BTI)) {
                so->bti = true;
            }
        }
        const size_t step = sizeof(ElfW(Nhdr)) + ((note->n_namesz + 3) & ~3u) +
                            ((note->n_descsz + 3) & ~3u);
        note = reinterpret_cast<const ElfW(Nhdr)*>(reinterpret_cast<const char*>(note) + step);
    }
}

bool BindPhdrs(Image* so, const ElfW(Phdr) * phdrs, size_t phnum) {
    if (phdrs == nullptr || phnum == 0) {
        return false;
    }
    so->phdr = phdrs;
    so->phnum = phnum;
    uintptr_t min_vaddr = UINTPTR_MAX;
    uintptr_t max_vaddr = 0;
    for (size_t i = 0; i < phnum; ++i) {
        const ElfW(Phdr)& ph = phdrs[i];
        if (ph.p_type == PT_DYNAMIC) {
            so->dynamic = reinterpret_cast<const ElfW(Dyn)*>(so->load_bias + ph.p_vaddr);
        } else if (ph.p_type == PT_GNU_RELRO) {
            so->relro_vaddr = ph.p_vaddr;
            so->relro_memsz = ph.p_memsz;
        } else if (ph.p_type == PT_TLS) {
            so->tls_tmpl = reinterpret_cast<void*>(so->load_bias + ph.p_vaddr);
            so->tls_tmpl_size = ph.p_filesz;
            so->tls_size = ph.p_memsz;
            so->tls_align = ph.p_align ? ph.p_align : sizeof(void*);
        } else if (ph.p_type == PT_NOTE) {
            ParseGnuProperty(so, ph);
        } else if (ph.p_type == PT_ARM_EXIDX) {
            so->arm_exidx = reinterpret_cast<uint32_t*>(so->load_bias + ph.p_vaddr);
            so->arm_exidx_count = ph.p_memsz / 8;
        } else if (ph.p_type == PT_LOAD && ph.p_memsz != 0) {
            if (ph.p_vaddr < min_vaddr) {
                min_vaddr = ph.p_vaddr;
            }
            const uintptr_t end = ph.p_vaddr + ph.p_memsz;
            if (end > max_vaddr) {
                max_vaddr = end;
            }
        }
    }
    if (so->load_start == nullptr && min_vaddr != UINTPTR_MAX) {
        so->load_start = reinterpret_cast<void*>(so->load_bias + PageStart(min_vaddr));
        so->load_size = PageEnd(max_vaddr) - PageStart(min_vaddr);
    }
    return ParseDynamic(so);
}

void CallInit(Image* so) {
    if (so->constructors_called || !so->owns_mapping) {
        return;
    }
    so->constructors_called = true;
    for (Image* child : so->children) {
        CallInit(child);
    }
    using Ctor = void (*)(int, char**, char**);
    for (size_t i = 0; i < so->preinit_array_count; ++i) {
        auto fn = so->preinit_array[i];
        if (fn != nullptr && fn != reinterpret_cast<void (*)()>(-1)) {
            reinterpret_cast<Ctor>(fn)(0, nullptr, nullptr);
        }
    }
    if (so->init != nullptr) {
        reinterpret_cast<Ctor>(so->init)(0, nullptr, nullptr);
    }
    for (size_t i = 0; i < so->init_array_count; ++i) {
        auto fn = so->init_array[i];
        if (fn != nullptr && fn != reinterpret_cast<void (*)()>(-1)) {
            reinterpret_cast<Ctor>(fn)(0, nullptr, nullptr);
        }
    }
}

void CallFini(Image* so) {
    if (!so->constructors_called) {
        return;
    }
    so->constructors_called = false;
    // Same as crtbegin_so __on_dlclose: drop this DSO's __cxa_atexit /
    // pthread_atfork entries before unmap. Safe to run twice (CRT may too).
    FinalizeDso(so);
    using Fini = void (*)();
    for (size_t i = so->fini_array_count; i > 0; --i) {
        Fini fn = so->fini_array[i - 1];
        if (fn != nullptr && fn != reinterpret_cast<Fini>(-1)) {
            fn();
        }
    }
    if (so->fini != nullptr) {
        so->fini();
    }
}

void Destroy(Image* so) {
    if (so == nullptr) {
        return;
    }
    UnregisterTls(so);
    if (so->owns_mapping && so->load_start != nullptr && so->load_size != 0) {
        LOGV("[unload-audit] Destroy name=%s base=%p size=%zu",
             so->name.empty() ? (so->soname.empty() ? "(anon)" : so->soname.c_str())
                              : so->name.c_str(),
             so->load_start, so->load_size);
        munmap(so->load_start, so->load_size);
    }
    so->magic = 0;
    so->load_start = nullptr;
    delete so;
}

}  // namespace linker
