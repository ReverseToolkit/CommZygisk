#include "linker_image.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <vector>

#ifndef PROT_BTI
#define PROT_BTI 0x10
#endif

namespace linker {
namespace {

int FinalProt(const Image* so, int prot) {
    if (so->bti && (prot & PROT_EXEC)) {
        prot |= PROT_BTI;
    }
    return prot;
}

bool MapOrCopy(int fd, off64_t file_off, void* addr, size_t length, int prot) {
    void* mapped = mmap(addr, length, prot, MAP_FIXED | MAP_PRIVATE, fd, static_cast<off_t>(file_off));
    if (mapped != MAP_FAILED) {
        return true;
    }
    mapped = mmap(addr, length, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapped == MAP_FAILED) {
        return false;
    }
    if (pread(fd, mapped, length, file_off) != static_cast<ssize_t>(length)) {
        return false;
    }
    if (mprotect(mapped, length, prot) != 0) {
        return false;
    }
    return true;
}

}  // namespace

bool LoadSegments(int fd, Image* so, const LoadOptions& opt) {
    struct stat st {};
    if (fstat(fd, &st) != 0) {
        SetErrorf("fstat failed: %s", strerror(errno));
        return false;
    }
    so->st_dev = st.st_dev;
    so->st_ino = st.st_ino;
    so->file_offset = opt.file_offset;
    const off_t file_size = st.st_size;

    ElfW(Ehdr) eh{};
    if (pread(fd, &eh, sizeof(eh), opt.file_offset) != static_cast<ssize_t>(sizeof(eh))) {
        SetError("read ehdr failed");
        return false;
    }
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) {
        SetError("not ELF");
        return false;
    }
#if defined(__LP64__)
    if (eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_machine != EM_AARCH64) {
        SetError("expected ELF64 aarch64");
        return false;
    }
#else
    if (eh.e_ident[EI_CLASS] != ELFCLASS32 || eh.e_machine != EM_ARM) {
        SetError("expected ELF32 arm");
        return false;
    }
#endif
    if (eh.e_phentsize != sizeof(ElfW(Phdr)) || eh.e_phnum == 0) {
        SetError("bad phdr");
        return false;
    }

    std::vector<ElfW(Phdr)> phdrs(eh.e_phnum);
    const size_t phdr_bytes = eh.e_phnum * sizeof(ElfW(Phdr));
    if (pread(fd, phdrs.data(), phdr_bytes, opt.file_offset + static_cast<off64_t>(eh.e_phoff)) !=
        static_cast<ssize_t>(phdr_bytes)) {
        SetError("read phdrs failed");
        return false;
    }

    uintptr_t min_vaddr = UINTPTR_MAX;
    uintptr_t max_vaddr = 0;
    for (const auto& ph : phdrs) {
        if (ph.p_type != PT_LOAD || ph.p_memsz == 0) {
            continue;
        }
        if ((ph.p_flags & PF_W) && (ph.p_flags & PF_X)) {
            SetError("W+E PT_LOAD is not allowed");
            return false;
        }
        if (ph.p_vaddr < min_vaddr) {
            min_vaddr = ph.p_vaddr;
        }
        const uintptr_t end = ph.p_vaddr + ph.p_memsz;
        if (end > max_vaddr) {
            max_vaddr = end;
        }
    }
    if (min_vaddr == UINTPTR_MAX || max_vaddr <= min_vaddr) {
        SetError("no PT_LOAD");
        return false;
    }

    const uintptr_t min_page = PageStart(min_vaddr);
    so->load_size = PageEnd(max_vaddr) - min_page;
    int map_flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void* hint = nullptr;
    if (opt.reserved_addr != nullptr) {
        if (so->load_size > opt.reserved_size) {
            if (opt.reserved_must) {
                SetError("reserved address too small");
                return false;
            }
        } else {
            hint = opt.reserved_addr;
            map_flags |= MAP_FIXED;
        }
    }
    so->load_start = mmap(hint, so->load_size, PROT_NONE, map_flags, -1, 0);
    if (so->load_start == MAP_FAILED) {
        so->load_start = nullptr;
        SetErrorf("reserve failed: %s", strerror(errno));
        return false;
    }
    so->load_bias = reinterpret_cast<uintptr_t>(so->load_start) - min_page;

    for (size_t i = 0; i < phdrs.size(); ++i) {
        const ElfW(Phdr)& ph = phdrs[i];
        if (ph.p_type != PT_LOAD) {
            continue;
        }
        if (opt.file_offset + static_cast<off64_t>(ph.p_offset + ph.p_filesz) > file_size) {
            SetErrorf("segment %zu past end of file", i);
            return false;
        }
        const uintptr_t seg_start = ph.p_vaddr + so->load_bias;
        const uintptr_t seg_end = seg_start + ph.p_memsz;
        const uintptr_t seg_page_start = PageStart(seg_start);
        const uintptr_t seg_page_end = PageEnd(seg_end);
        const uintptr_t file_page_start = PageStart(ph.p_offset);
        const uintptr_t file_length = (ph.p_offset + ph.p_filesz) - file_page_start;
        const int prot = FinalProt(so, PFLAGS_TO_PROT(ph.p_flags));

        if (file_length != 0) {
            if (!MapOrCopy(fd, opt.file_offset + static_cast<off64_t>(file_page_start),
                           reinterpret_cast<void*>(seg_page_start), file_length, prot)) {
                SetErrorf("map segment %zu failed: %s", i, strerror(errno));
                return false;
            }
        }
        if ((ph.p_flags & PF_W) != 0 && PageOffset(seg_start + ph.p_filesz) > 0) {
            memset(reinterpret_cast<void*>(seg_start + ph.p_filesz), 0,
                   PageSize() - PageOffset(seg_start + ph.p_filesz));
        }
        const uintptr_t file_end_page = PageEnd(seg_start + ph.p_filesz);
        if (seg_page_end > file_end_page) {
            void* zero = mmap(reinterpret_cast<void*>(file_end_page), seg_page_end - file_end_page,
                              prot, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            if (zero == MAP_FAILED) {
                SetErrorf("bss map failed: %s", strerror(errno));
                return false;
            }
        }
    }

    so->phdr_owned = std::move(phdrs);
    if (!BindPhdrs(so, so->phdr_owned.data(), so->phdr_owned.size())) {
        SetError("no PT_DYNAMIC / bad dynamic");
        return false;
    }
    return true;
}

void UnprotectTextrel(Image* so) {
    if (!so->has_textrel || so->phdr == nullptr) {
        return;
    }
    for (size_t i = 0; i < so->phnum; ++i) {
        const ElfW(Phdr)& ph = so->phdr[i];
        if (ph.p_type != PT_LOAD) {
            continue;
        }
        const uintptr_t start = PageStart(ph.p_vaddr + so->load_bias);
        const uintptr_t end = PageEnd(ph.p_vaddr + ph.p_memsz + so->load_bias);
        mprotect(reinterpret_cast<void*>(start), end - start,
                 (PFLAGS_TO_PROT(ph.p_flags) | PROT_WRITE) & ~PROT_EXEC);
    }
}

void ProtectLoad(Image* so) {
    if (so->phdr == nullptr) {
        return;
    }
    for (size_t i = 0; i < so->phnum; ++i) {
        const ElfW(Phdr)& ph = so->phdr[i];
        if (ph.p_type != PT_LOAD) {
            continue;
        }
        const uintptr_t start = PageStart(ph.p_vaddr + so->load_bias);
        const uintptr_t end = PageEnd(ph.p_vaddr + ph.p_memsz + so->load_bias);
        mprotect(reinterpret_cast<void*>(start), end - start, FinalProt(so, PFLAGS_TO_PROT(ph.p_flags)));
    }
}

void ProtectRelro(Image* so) {
    if (so->relro_memsz == 0) {
        return;
    }
    const uintptr_t start = PageStart(so->relro_vaddr + so->load_bias);
    const uintptr_t end = PageEnd(so->relro_vaddr + so->relro_memsz + so->load_bias);
    if (end > start) {
        mprotect(reinterpret_cast<void*>(start), end - start, PROT_READ);
    }
}

}  // namespace linker
