#include "linker.hpp"
#include "prot_hide.h"

#include <cerrno>
#include <sys/mman.h>

namespace linker {
namespace {

int StripHide(int prot) { return prot & ~PROT_HIDE; }

}  // namespace

void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    const int want = StripHide(prot) | PROT_HIDE;
    void* p = ::mmap(addr, length, want, flags, fd, offset);
    if (p != MAP_FAILED) {
        return p;
    }
    if (errno != EINVAL && errno != ENOSYS) {
        return MAP_FAILED;
    }
    return ::mmap(addr, length, StripHide(prot), flags, fd, offset);
}

int mprotect(void* addr, size_t length, int prot) {
    const int want = StripHide(prot) | PROT_HIDE;
    if (::mprotect(addr, length, want) == 0) {
        return 0;
    }
    if (errno != EINVAL && errno != ENOSYS) {
        return -1;
    }
    return ::mprotect(addr, length, StripHide(prot));
}

}  // namespace linker
