#pragma once

#include <dlfcn.h>

void *DlopenMem(int memfd, int flags);
void *Dlsym(void *handle, const char *name);
void *Dlvsym(void *handle, const char *name, const char *version);
int Dlclose(void *handle);
const char *Dlerror();
int Dladdr(const void *addr, Dl_info *info);
