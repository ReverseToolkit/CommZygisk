#pragma once

#include <dlfcn.h>
#include <link.h>
#include <android/dlext.h>
#include <cstddef>
#include <sys/types.h>

// In-process ELF loader aligned with AOSP bionic linker ABI.
// New mappings use linker::mmap / mprotect (PROT_HIDE + fallback).

namespace linker {

void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
int mprotect(void* addr, size_t length, int prot);

void* dlopen(const char* filename, int flags);
void* dlopen_fd(int fd, int flags);
void* dlopen_ext(const char* filename, int flags, const android_dlextinfo* info);
void* dlsym(void* handle, const char* name);
void* dlvsym(void* handle, const char* name, const char* version);
int dlclose(void* handle);
const char* dlerror();
int dladdr(const void* addr, Dl_info* info);
int dl_iterate_phdr(int (*cb)(dl_phdr_info* info, size_t size, void* data), void* data);
void android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size);
void android_update_LD_LIBRARY_PATH(const char* ld_library_path);

#if defined(__arm__)
void* dl_unwind_find_exidx(void* pc, int* pcount);
#endif

}  // namespace linker
