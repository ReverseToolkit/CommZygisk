#pragma once

#include <cstddef>

namespace linker {

struct Image;

struct TlsIndex {
    size_t module_id;
    size_t offset;
};

struct TlsDynamicResolverArg {
    size_t generation;
    TlsIndex index;
};

struct TlsDescriptor {
#if defined(__arm__)
    size_t arg;
    size_t (*func)(size_t);
#else
    size_t (*func)(size_t);
    size_t arg;
#endif
};

void RegisterTls(Image* so);
void UnregisterTls(Image* so);
void* TlsBlock(const Image* so);
void* TlsGetAddr(const TlsIndex* ti);
extern "C" size_t TlsdescDynamic(size_t desc);
extern "C" size_t TlsdescWeak(size_t desc);
extern "C" size_t TlsdescDynamicC(size_t desc);

}  // namespace linker
