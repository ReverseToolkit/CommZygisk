#include "linker_image.hpp"
#include "linker_relocs.hpp"

#include <dlfcn.h>
#include <sys/mman.h>

#include <cstring>

namespace linker {
namespace {

using RelrWord = ElfW(Addr);

bool ApplyReloc(Image* so, uintptr_t offset, uint32_t type, uint32_t sym_idx, intptr_t addend) {
    auto* place = reinterpret_cast<ElfW(Addr)*>(so->load_bias + offset);
    const bool is_tls = type == R_GENERIC_TLS_DTPMOD || type == R_GENERIC_TLS_DTPREL ||
                        type == R_GENERIC_TLS_TPREL || type == R_GENERIC_TLSDESC;
    const ElfW(Sym)* raw = (so->dynsym != nullptr && sym_idx != 0) ? &so->dynsym[sym_idx] : nullptr;
    const char* name = (raw != nullptr && so->dynstr != nullptr) ? so->dynstr + raw->st_name : "";
    LookupResult r;
    void* resolved = nullptr;
    // lld/bfd omit the symbol on a TLS reloc to mean "this module".
    if (is_tls && sym_idx == 0) {
        r.found_in = so;
    } else if (raw != nullptr && raw->st_shndx != SHN_UNDEF) {
        r.found_in = so;
        r.sym = raw;
        r.sym_idx = sym_idx;
        if (ELF_ST_TYPE(raw->st_info) != STT_TLS) {
            resolved = SymAddr(so, raw);
        }
    } else if (raw != nullptr && name[0] != '\0') {
        if (void* api = ResolveLinkerApi(name)) {
            resolved = api;
            if (type == R_GENERIC_JUMP_SLOT || type == R_GENERIC_GLOB_DAT ||
                type == R_GENERIC_ABSOLUTE) {
                so->bound_linker_api = true;
            }
        } else {
            r = ResolveLookup(name, nullptr, so);
            if (r.sym != nullptr && ELF_ST_TYPE(r.sym->st_info) != STT_TLS) {
                resolved = SymAddr(r.found_in, r.sym);
            }
        }
        if (resolved == nullptr && r.sym == nullptr && ELF_ST_BIND(raw->st_info) != STB_WEAK &&
            type != R_GENERIC_RELATIVE && type != R_GENERIC_IRELATIVE &&
            type != R_GENERIC_TLS_DTPREL) {
            SetErrorf("undefined symbol: %s", name);
            return false;
        }
    }

    switch (type) {
    case R_GENERIC_NONE:
        return true;
    case R_GENERIC_RELATIVE:
#if defined(__arm__)
        *place += so->load_bias;
#else
        *place = so->load_bias + static_cast<ElfW(Addr)>(addend);
#endif
        return true;
    case R_GENERIC_IRELATIVE: {
        ElfW(Addr) resolver = so->load_bias + static_cast<ElfW(Addr)>(addend);
#if defined(__arm__)
        if (addend == 0) {
            resolver = *place;
        }
#endif
        *place = CallIfuncResolver(resolver);
        return true;
    }
    case R_GENERIC_ABSOLUTE:
    case R_GENERIC_GLOB_DAT:
    case R_GENERIC_JUMP_SLOT:
        *place = reinterpret_cast<ElfW(Addr)>(resolved) + static_cast<ElfW(Addr)>(addend);
        return true;
    case R_GENERIC_COPY:
        SetError("COPY relocations are not supported");
        return false;
    case R_GENERIC_TLS_TPREL:
        if (r.found_in != nullptr && r.found_in->owns_mapping) {
            SetErrorf("TLS IE against dlopened \"%s\"", name);
            return false;
        }
        *place = (r.sym ? r.sym->st_value : 0) + static_cast<ElfW(Addr)>(addend);
        return true;
    case R_GENERIC_TLS_DTPMOD:
        if (r.found_in != nullptr && r.found_in->tls_module_id == 0) {
            RegisterTls(r.found_in);
        }
        *place = r.found_in ? r.found_in->tls_module_id : 0;
        return true;
    case R_GENERIC_TLS_DTPREL:
        *place = (r.sym ? r.sym->st_value : 0) + static_cast<ElfW(Addr)>(addend);
        return true;
    case R_GENERIC_TLSDESC: {
        auto* desc = reinterpret_cast<TlsDescriptor*>(place);
        if (r.found_in == nullptr) {
            desc->func = TlsdescWeak;
            desc->arg = static_cast<size_t>(addend);
            return true;
        }
        if (r.found_in->tls_module_id == 0) {
            RegisterTls(r.found_in);
        }
        so->tlsdesc_args.push_back(TlsDynamicResolverArg{
                .generation = 0,
                .index = {.module_id = r.found_in->tls_module_id,
                          .offset = static_cast<size_t>((r.sym ? r.sym->st_value : 0) + addend)},
        });
        desc->func = TlsdescDynamic;
        desc->arg = reinterpret_cast<size_t>(&so->tlsdesc_args.back());
        return true;
    }
    default:
        SetErrorf("unsupported reloc type %u", type);
        return false;
    }
}

void RestoreApiSlot(Image* so, uintptr_t offset, uint32_t type, uint32_t sym_idx, intptr_t addend) {
    if (type != R_GENERIC_JUMP_SLOT && type != R_GENERIC_GLOB_DAT && type != R_GENERIC_ABSOLUTE) {
        return;
    }
    if (so->dynsym == nullptr || so->dynstr == nullptr || sym_idx == 0) {
        return;
    }
    const ElfW(Sym)* raw = &so->dynsym[sym_idx];
    if (raw->st_name == 0 || (so->dynstr_size != 0 && raw->st_name >= so->dynstr_size)) {
        return;
    }
    const char* name = so->dynstr + raw->st_name;
    void* api = ResolveLinkerApi(name);
    if (api == nullptr) {
        return;
    }
    auto* place = reinterpret_cast<ElfW(Addr)*>(so->load_bias + offset);
    const auto current = reinterpret_cast<ElfW(Addr)>(api) + static_cast<ElfW(Addr)>(addend);
    if (*place != current) {
        return;
    }
    // RTLD_NEXT skips this DSO. libzygisk.so does not export these names, so the
    // next definition is libc/libdl, which stays mapped after we unmap ourselves.
    void* real = dlsym(RTLD_NEXT, name);
    if (real == nullptr || real == api) {
        return;
    }
    uintptr_t page = PageStart(reinterpret_cast<uintptr_t>(place));
    // libc mprotect, not linker::mprotect. The wrapper ORs PROT_HIDE and, on
    // any error other than EINVAL/ENOSYS, leaves the RELRO page read-only.
    // The following store then SIGSEGV SEGV_ACCERRs.
    if (::mprotect(reinterpret_cast<void*>(page), PageSize(), PROT_READ | PROT_WRITE) != 0) {
        return;
    }
    *place = reinterpret_cast<ElfW(Addr)>(real) + static_cast<ElfW(Addr)>(addend);
}

void RestoreApiRel(Image* so, const ElfW(Rel) * rel, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        RestoreApiSlot(so, rel[i].r_offset, ELF_R_TYPE(rel[i].r_info), ELF_R_SYM(rel[i].r_info), 0);
    }
}

void RestoreApiRela(Image* so, const ElfW(Rela) * rela, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        RestoreApiSlot(so, rela[i].r_offset, ELF_R_TYPE(rela[i].r_info), ELF_R_SYM(rela[i].r_info),
                       rela[i].r_addend);
    }
}

bool RelocateRel(Image* so, const ElfW(Rel) * rel, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (!ApplyReloc(so, rel[i].r_offset, ELF_R_TYPE(rel[i].r_info), ELF_R_SYM(rel[i].r_info),
                        0)) {
            return false;
        }
    }
    return true;
}

bool RelocateRela(Image* so, const ElfW(Rela) * rela, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (!ApplyReloc(so, rela[i].r_offset, ELF_R_TYPE(rela[i].r_info), ELF_R_SYM(rela[i].r_info),
                        rela[i].r_addend)) {
            return false;
        }
    }
    return true;
}

bool RelocateRelr(Image* so, const RelrWord* relr, size_t bytes) {
    const size_t n = bytes / sizeof(RelrWord);
    ElfW(Addr)* where = nullptr;
    for (size_t i = 0; i < n; ++i) {
        const RelrWord entry = relr[i];
        if ((entry & 1) == 0) {
            where = reinterpret_cast<ElfW(Addr)*>(so->load_bias + entry);
            *where++ += so->load_bias;
        } else {
            for (size_t bit = 0; bit < 8 * sizeof(RelrWord) - 1; ++bit) {
                if (entry & (static_cast<RelrWord>(2) << bit)) {
                    where[bit] += so->load_bias;
                }
            }
            where += 8 * sizeof(RelrWord) - 1;
        }
    }
    return true;
}

class Sleb128 {
public:
    Sleb128(const uint8_t* buf, size_t n) : cur_(buf), end_(buf + n) {}
    size_t pop() {
        size_t value = 0;
        size_t shift = 0;
        uint8_t byte;
        do {
            if (cur_ >= end_) {
                return 0;
            }
            byte = *cur_++;
            value |= static_cast<size_t>(byte & 127) << shift;
            shift += 7;
        } while (byte & 128);
        if (shift < sizeof(value) * 8 && (byte & 64)) {
            value |= -(static_cast<size_t>(1) << shift);
        }
        return value;
    }

private:
    const uint8_t* cur_;
    const uint8_t* const end_;
};

constexpr size_t kGroupedByInfo = 1;
constexpr size_t kGroupedByOffsetDelta = 2;
constexpr size_t kGroupedByAddend = 4;
constexpr size_t kGroupHasAddend = 8;

bool RelocatePacked(Image* so, const uint8_t* data, size_t size) {
    if (size < 4 || memcmp(data, "APS2", 4) != 0) {
        SetError("bad android packed reloc");
        return false;
    }
    Sleb128 dec(data + 4, size - 4);
    const size_t num = dec.pop();
    ElfW(Rela) reloc{};
    reloc.r_offset = dec.pop();
    size_t idx = 0;
    while (idx < num) {
        const size_t group_size = dec.pop();
        const size_t flags = dec.pop();
        size_t offset_delta = 0;
        if (flags & kGroupedByOffsetDelta) {
            offset_delta = dec.pop();
        }
        if (flags & kGroupedByInfo) {
            reloc.r_info = dec.pop();
        }
        const size_t add_flags = flags & (kGroupHasAddend | kGroupedByAddend);
        if (add_flags == (kGroupHasAddend | kGroupedByAddend)) {
            reloc.r_addend += static_cast<ElfW(Sxword)>(dec.pop());
        } else if (add_flags != kGroupHasAddend) {
            reloc.r_addend = 0;
        }
        for (size_t i = 0; i < group_size; ++i) {
            if (flags & kGroupedByOffsetDelta) {
                reloc.r_offset += offset_delta;
            } else {
                reloc.r_offset += dec.pop();
            }
            if ((flags & kGroupedByInfo) == 0) {
                reloc.r_info = dec.pop();
            }
            if (add_flags == kGroupHasAddend) {
                reloc.r_addend += static_cast<ElfW(Sxword)>(dec.pop());
            }
            if (!ApplyReloc(so, reloc.r_offset, ELF_R_TYPE(reloc.r_info), ELF_R_SYM(reloc.r_info),
                            reloc.r_addend)) {
                return false;
            }
        }
        idx += group_size;
    }
    return true;
}

}  // namespace

void RestoreLinkerApiBindings() {
    ForEachImage(
            [](Image* so, void*) {
                // Only images this process relocated. Attached system libraries
                // and processes that never loaded a module are left alone.
                if (so == nullptr || !so->owns_mapping || !so->bound_linker_api ||
                    so->dynamic == nullptr || so->load_bias == 0) {
                    return;
                }
                const ElfW(Rela)* rela = nullptr;
                size_t rela_count = 0;
                const ElfW(Rel)* rel = nullptr;
                size_t rel_count = 0;
                const void* jmprel = nullptr;
                size_t pltrel_sz = 0;
                int pltrel_type = DT_RELA;
                for (const ElfW(Dyn)* d = so->dynamic; d->d_tag != DT_NULL; ++d) {
                    switch (d->d_tag) {
                    case DT_RELA:
                        rela = reinterpret_cast<const ElfW(Rela)*>(so->load_bias + d->d_un.d_ptr);
                        break;
                    case DT_RELASZ:
                        rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
                        break;
                    case DT_REL:
                        rel = reinterpret_cast<const ElfW(Rel)*>(so->load_bias + d->d_un.d_ptr);
                        break;
                    case DT_RELSZ:
                        rel_count = d->d_un.d_val / sizeof(ElfW(Rel));
                        break;
                    case DT_JMPREL:
                        jmprel = reinterpret_cast<const void*>(so->load_bias + d->d_un.d_ptr);
                        break;
                    case DT_PLTRELSZ:
                        pltrel_sz = d->d_un.d_val;
                        break;
                    case DT_PLTREL:
                        pltrel_type = static_cast<int>(d->d_un.d_val);
                        break;
                    default:
                        break;
                    }
                }
                if (rela != nullptr && rela_count != 0) {
                    RestoreApiRela(so, rela, rela_count);
                }
                if (rel != nullptr && rel_count != 0) {
                    RestoreApiRel(so, rel, rel_count);
                }
                if (jmprel != nullptr && pltrel_sz != 0) {
                    if (pltrel_type == DT_RELA) {
                        RestoreApiRela(so, static_cast<const ElfW(Rela)*>(jmprel),
                                       pltrel_sz / sizeof(ElfW(Rela)));
                    } else {
                        RestoreApiRel(so, static_cast<const ElfW(Rel)*>(jmprel),
                                      pltrel_sz / sizeof(ElfW(Rel)));
                    }
                }
            },
            nullptr);
}

bool Relocate(Image* so) {
    UnprotectTextrel(so);
    const ElfW(Rela)* rela = nullptr;
    size_t rela_count = 0;
    const ElfW(Rel)* rel = nullptr;
    size_t rel_count = 0;
    const void* jmprel = nullptr;
    size_t pltrel_sz = 0;
    int pltrel_type = DT_RELA;
    const RelrWord* relr = nullptr;
    size_t relr_sz = 0;
    const uint8_t* packed = nullptr;
    size_t packed_sz = 0;

    for (const ElfW(Dyn)* d = so->dynamic; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
        case DT_RELA:
            rela = reinterpret_cast<const ElfW(Rela)*>(so->load_bias + d->d_un.d_ptr);
            break;
        case DT_RELASZ:
            rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
            break;
        case DT_REL:
            rel = reinterpret_cast<const ElfW(Rel)*>(so->load_bias + d->d_un.d_ptr);
            break;
        case DT_RELSZ:
            rel_count = d->d_un.d_val / sizeof(ElfW(Rel));
            break;
        case DT_JMPREL:
            jmprel = reinterpret_cast<const void*>(so->load_bias + d->d_un.d_ptr);
            break;
        case DT_PLTRELSZ:
            pltrel_sz = d->d_un.d_val;
            break;
        case DT_PLTREL:
            pltrel_type = static_cast<int>(d->d_un.d_val);
            break;
        case DT_RELR:
        case DT_ANDROID_RELR:
            relr = reinterpret_cast<const RelrWord*>(so->load_bias + d->d_un.d_ptr);
            break;
        case DT_RELRSZ:
        case DT_ANDROID_RELRSZ:
            relr_sz = d->d_un.d_val;
            break;
        case DT_ANDROID_RELA:
        case DT_ANDROID_REL:
            packed = reinterpret_cast<const uint8_t*>(so->load_bias + d->d_un.d_ptr);
            break;
        case DT_ANDROID_RELASZ:
        case DT_ANDROID_RELSZ:
            packed_sz = d->d_un.d_val;
            break;
        default:
            break;
        }
    }

    bool ok = true;
    if (relr != nullptr && relr_sz != 0) {
        ok = RelocateRelr(so, relr, relr_sz);
    }
    if (ok && packed != nullptr && packed_sz != 0) {
        ok = RelocatePacked(so, packed, packed_sz);
    }
    if (ok && rela != nullptr && rela_count != 0) {
        ok = RelocateRela(so, rela, rela_count);
    }
    if (ok && rel != nullptr && rel_count != 0) {
        ok = RelocateRel(so, rel, rel_count);
    }
    if (ok && jmprel != nullptr && pltrel_sz != 0) {
        if (pltrel_type == DT_RELA) {
            ok = RelocateRela(so, static_cast<const ElfW(Rela)*>(jmprel),
                              pltrel_sz / sizeof(ElfW(Rela)));
        } else {
            ok = RelocateRel(so, static_cast<const ElfW(Rel)*>(jmprel),
                             pltrel_sz / sizeof(ElfW(Rel)));
        }
    }
    if (so->has_textrel) {
        ProtectLoad(so);
    }
    return ok;
}

}  // namespace linker
