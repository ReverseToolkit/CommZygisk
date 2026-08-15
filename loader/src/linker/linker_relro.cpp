#include "linker_image.hpp"

#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace linker {

bool WriteRelro(Image* so, int fd) {
    if (fd < 0 || so->relro_memsz == 0) {
        return true;
    }
    const uintptr_t start = PageStart(so->relro_vaddr + so->load_bias);
    const uintptr_t end = PageEnd(so->relro_vaddr + so->relro_memsz + so->load_bias);
    const size_t n = end - start;
    if (n == 0) {
        return true;
    }
    if (write(fd, reinterpret_cast<void*>(start), n) != static_cast<ssize_t>(n)) {
        SetErrorf("WRITE_RELRO failed: %s", strerror(errno));
        return false;
    }
    return true;
}

bool UseRelro(Image* so, int fd) {
    if (fd < 0 || so->relro_memsz == 0) {
        return true;
    }
    const uintptr_t start = PageStart(so->relro_vaddr + so->load_bias);
    const uintptr_t end = PageEnd(so->relro_vaddr + so->relro_memsz + so->load_bias);
    const size_t n = end - start;
    if (n == 0) {
        return true;
    }
    void* mapped = mmap(reinterpret_cast<void*>(start), n, PROT_READ, MAP_FIXED | MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        SetErrorf("USE_RELRO mmap failed: %s", strerror(errno));
        return false;
    }
    return true;
}

}  // namespace linker
