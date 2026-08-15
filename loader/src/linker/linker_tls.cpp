#include "linker_tls.hpp"

#include "linker_image.hpp"

#include <cstdlib>
#include <cstring>
#include <mutex>
#include <pthread.h>
#include <unordered_map>
#include <vector>

namespace linker {
namespace {

constexpr size_t kTlsBase = 0x10000;
size_t g_next_tls = kTlsBase;
std::mutex g_tls_lock;
std::unordered_map<size_t, Image*> g_tls_mods;

void* GetTp() {
    void* tp = nullptr;
#if defined(__aarch64__)
    __asm__ __volatile__("mrs %0, tpidr_el0" : "=r"(tp));
#elif defined(__arm__)
    __asm__ __volatile__("mrc p15, 0, %0, c13, c0, 3" : "=r"(tp));
#elif defined(__x86_64__)
    __asm__ __volatile__("mov %%fs:0, %0" : "=r"(tp));
#elif defined(__i386__)
    __asm__ __volatile__("mov %%gs:0, %0" : "=r"(tp));
#endif
    return tp;
}

using BlockMap = std::unordered_map<size_t, void*>;
pthread_key_t g_blocks_key;
pthread_once_t g_blocks_once = PTHREAD_ONCE_INIT;

void FreeBlocks(void* p) {
    auto* m = static_cast<BlockMap*>(p);
    if (m == nullptr) {
        return;
    }
    for (auto& kv : *m) {
        std::free(kv.second);
    }
    delete m;
}

void InitBlocksKey() { pthread_key_create(&g_blocks_key, FreeBlocks); }

BlockMap& Blocks() {
    pthread_once(&g_blocks_once, InitBlocksKey);
    auto* m = static_cast<BlockMap*>(pthread_getspecific(g_blocks_key));
    if (m == nullptr) {
        m = new BlockMap();
        pthread_setspecific(g_blocks_key, m);
    }
    return *m;
}

void* AllocBlock(const Image* so) {
    if (so == nullptr || so->tls_size == 0) {
        return nullptr;
    }
    void* p = nullptr;
    size_t align = so->tls_align ? so->tls_align : sizeof(void*);
    if (align < sizeof(void*)) {
        align = sizeof(void*);
    }
    if (posix_memalign(&p, align, so->tls_size) != 0) {
        return nullptr;
    }
    memset(p, 0, so->tls_size);
    if (so->tls_tmpl != nullptr && so->tls_tmpl_size != 0) {
        memcpy(p, so->tls_tmpl, so->tls_tmpl_size);
    }
    return p;
}

using SystemTlsFn = void* (*)(const TlsIndex*);
SystemTlsFn SystemTlsGetAddr() {
    static SystemTlsFn fn = nullptr;
    if (fn != nullptr) {
        return fn;
    }
    EnsureProcessImages();
    const LookupResult r = ResolveLookup("__tls_get_addr", nullptr);
    if (r.sym != nullptr) {
        fn = reinterpret_cast<SystemTlsFn>(SymAddr(r.found_in, r.sym));
    }
    return fn;
}

}  // namespace

void RegisterTls(Image* so) {
    if (so == nullptr || so->tls_size == 0 || so->tls_module_id != 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_tls_lock);
    so->tls_module_id = g_next_tls++;
    g_tls_mods[so->tls_module_id] = so;
}

void UnregisterTls(Image* so) {
    if (so == nullptr || so->tls_module_id == 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_tls_lock);
    g_tls_mods.erase(so->tls_module_id);
    so->tls_module_id = 0;
}

void* TlsBlock(const Image* so) {
    if (so == nullptr || so->tls_module_id == 0) {
        return nullptr;
    }
    void*& slot = Blocks()[so->tls_module_id];
    if (slot == nullptr) {
        slot = AllocBlock(so);
    }
    return slot;
}

void* TlsGetAddr(const TlsIndex* ti) {
    if (ti == nullptr) {
        return nullptr;
    }
    if (ti->module_id < kTlsBase) {
        SystemTlsFn fn = SystemTlsGetAddr();
        return fn ? fn(ti) : nullptr;
    }
    Image* so = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_tls_lock);
        auto it = g_tls_mods.find(ti->module_id);
        if (it != g_tls_mods.end()) {
            so = it->second;
        }
    }
    void* block = TlsBlock(so);
    if (block == nullptr) {
        return nullptr;
    }
    return static_cast<char*>(block) + ti->offset;
}

extern "C" size_t TlsdescDynamicC(size_t desc_ptr) {
    auto* desc = reinterpret_cast<TlsDescriptor*>(desc_ptr);
    auto* arg = reinterpret_cast<TlsDynamicResolverArg*>(desc->arg);
    TlsIndex idx = arg->index;
    void* addr = TlsGetAddr(&idx);
    return reinterpret_cast<size_t>(addr) - reinterpret_cast<size_t>(GetTp());
}

#if !defined(__aarch64__)
size_t TlsdescDynamic(size_t desc_ptr) { return TlsdescDynamicC(desc_ptr); }

size_t TlsdescWeak(size_t desc_ptr) {
    auto* desc = reinterpret_cast<TlsDescriptor*>(desc_ptr);
    return desc->arg - reinterpret_cast<size_t>(GetTp());
}
#endif

}  // namespace linker
