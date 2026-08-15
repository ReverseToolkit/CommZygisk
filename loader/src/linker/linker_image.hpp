#pragma once

#include "linker.hpp"
#include "linker_error.hpp"
#include "linker_tls.hpp"

#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <deque>
#include <string>
#include <vector>

#ifndef ELF_R_SYM
#if defined(__LP64__)
#define ELF_R_SYM ELF64_R_SYM
#define ELF_R_TYPE ELF64_R_TYPE
#else
#define ELF_R_SYM ELF32_R_SYM
#define ELF_R_TYPE ELF32_R_TYPE
#endif
#endif
#ifndef ELF_ST_TYPE
#define ELF_ST_TYPE ELF32_ST_TYPE
#define ELF_ST_BIND ELF32_ST_BIND
#endif
#ifndef ELF_ST_VISIBILITY
#define ELF_ST_VISIBILITY(o) ((o) & 0x3)
#endif

#ifndef DT_RELR
#define DT_RELR 36
#endif
#ifndef DT_RELRSZ
#define DT_RELRSZ 35
#endif
#ifndef DT_ANDROID_REL
#define DT_ANDROID_REL 0x6000000f
#endif
#ifndef DT_ANDROID_RELSZ
#define DT_ANDROID_RELSZ 0x60000010
#endif
#ifndef DT_ANDROID_RELA
#define DT_ANDROID_RELA 0x60000011
#endif
#ifndef DT_ANDROID_RELASZ
#define DT_ANDROID_RELASZ 0x60000012
#endif
#ifndef DT_ANDROID_RELR
#define DT_ANDROID_RELR 0x6fffe000
#endif
#ifndef DT_ANDROID_RELRSZ
#define DT_ANDROID_RELRSZ 0x6fffe001
#endif
#ifndef PT_ARM_EXIDX
#define PT_ARM_EXIDX 0x70000001
#endif
#ifndef VERSYM_HIDDEN
#define VERSYM_HIDDEN 0x8000
#endif
#ifndef VERSYM_VERSION
#define VERSYM_VERSION 0x7fff
#endif
#ifndef STB_GNU_UNIQUE
#define STB_GNU_UNIQUE 10
#endif
#ifndef DF_1_NOW
#define DF_1_NOW 0x1
#define DF_1_GLOBAL 0x2
#define DF_1_NODELETE 0x8
#define DF_1_PIE 0x8000000
#endif

#define MAYBE_MAP_FLAG(x, from, to) (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)                                                            \
    (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
     MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

namespace linker {

inline size_t PageSize() {
    static const size_t k = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    return k;
}
inline uintptr_t PageStart(uintptr_t x) { return x & ~(PageSize() - 1); }
inline uintptr_t PageEnd(uintptr_t x) { return PageStart(x + PageSize() - 1); }
inline uintptr_t PageOffset(uintptr_t x) { return x & (PageSize() - 1); }

struct LoadOptions {
    off64_t file_offset = 0;
    void* reserved_addr = nullptr;
    size_t reserved_size = 0;
    bool reserved_must = false;
    int relro_fd = -1;
    uint64_t ext_flags = 0;
    int rtld_flags = 0;
};

struct Image;

struct LookupResult {
    Image* found_in = nullptr;
    const ElfW(Sym)* sym = nullptr;
    uint32_t sym_idx = 0;
};

struct Image {
    static constexpr uint32_t kMagic = 0x4c4e4b52;  // 'LNKR'
    uint32_t magic = kMagic;
    bool owns_mapping = true;
    bool constructors_called = false;
    bool has_textrel = false;
    bool has_symbolic = false;
    bool nodelete = false;
    bool global = false;
    bool bti = false;
    int refcount = 1;
    int rtld_flags = 0;
    uint32_t dt_flags = 0;
    uint32_t dt_flags_1 = 0;

    std::string name;
    std::string soname;
    std::string runpath;
    std::vector<std::string> needed;
    std::vector<Image*> children;

    void* load_start = nullptr;
    size_t load_size = 0;
    uintptr_t load_bias = 0;
    off64_t file_offset = 0;
    dev_t st_dev = 0;
    ino_t st_ino = 0;

    std::vector<ElfW(Phdr)> phdr_owned;
    const ElfW(Phdr)* phdr = nullptr;
    size_t phnum = 0;

    const ElfW(Dyn)* dynamic = nullptr;
    const ElfW(Sym)* dynsym = nullptr;
    const char* dynstr = nullptr;
    size_t dynstr_size = 0;
    const ElfW(Versym)* versym = nullptr;
    ElfW(Addr) verneed_ptr = 0;
    size_t verneed_cnt = 0;
    ElfW(Addr) verdef_ptr = 0;
    size_t verdef_cnt = 0;

    uint32_t gnu_nbuckets = 0;
    uint32_t gnu_symoffset = 0;
    uint32_t gnu_bloom_sz = 0;
    uint32_t gnu_shift2 = 0;
    const ElfW(Addr)* gnu_bloom = nullptr;
    const uint32_t* gnu_buckets = nullptr;
    const uint32_t* gnu_chain = nullptr;
    uint32_t sysv_nbuckets = 0;
    size_t nsyms = 0;
    const uint32_t* sysv_buckets = nullptr;
    const uint32_t* sysv_chains = nullptr;

    ElfW(Addr) relro_vaddr = 0;
    ElfW(Addr) relro_memsz = 0;

    void (*init)() = nullptr;
    void (**init_array)() = nullptr;
    size_t init_array_count = 0;
    void (**preinit_array)() = nullptr;
    size_t preinit_array_count = 0;
    void (*fini)() = nullptr;
    void (**fini_array)() = nullptr;
    size_t fini_array_count = 0;

    size_t tls_module_id = 0;
    void* tls_tmpl = nullptr;
    size_t tls_tmpl_size = 0;
    size_t tls_size = 0;
    size_t tls_align = 0;
    std::deque<TlsDynamicResolverArg> tlsdesc_args;

    uint32_t* arm_exidx = nullptr;
    size_t arm_exidx_count = 0;

    link_map map{};
};

bool IsImage(const void* handle);
Image* AsImage(void* handle);
void Register(Image* so);
void Unregister(Image* so);
Image* FindBySoname(const char* name);
Image* FindByDevIno(dev_t dev, ino_t ino);
Image* FindByAddress(const void* addr);
void ForEachImage(void (*fn)(Image* so, void* arg), void* arg);
void EnsureProcessImages();
void RefreshProcessImages();
bool MustUseSystemLinker(const char* name);
bool IsSystemLibraryPath(const char* path);
bool FindPrivateLibrary(const char* name, const Image* origin, std::string* path, int* fd);

bool ParseDynamic(Image* so);
bool BindPhdrs(Image* so, const ElfW(Phdr)* phdrs, size_t phnum);
bool SymbolVersionOk(const Image* so, uint32_t sym_idx, const char* want_ver);
LookupResult Lookup(const Image* so, const char* name, const char* ver);
LookupResult ResolveLookup(const char* name, const char* ver, Image* except = nullptr);
ElfW(Addr) CallIfuncResolver(ElfW(Addr) resolver);
void* SymAddr(const Image* so, const ElfW(Sym)* sym);
void* ResolveLinkerApi(const char* name);
void* ResolveSymbol(const char* name);

bool LoadSegments(int fd, Image* so, const LoadOptions& opt);
bool Relocate(Image* so);
void UnprotectTextrel(Image* so);
void ProtectLoad(Image* so);
void ProtectRelro(Image* so);
bool WriteRelro(Image* so, int fd);
bool UseRelro(Image* so, int fd);
void CallInit(Image* so);
void FinalizeDso(Image* so);
void CallFini(Image* so);
void Destroy(Image* so);

bool FindLibrary(const char* name, const Image* origin, std::string* path, int* fd);
std::string ExpandPathVars(const std::string& path, const Image* origin);
void SetLdLibraryPath(const char* path);
void GetLdLibraryPath(char* buf, size_t n);

}  // namespace linker
