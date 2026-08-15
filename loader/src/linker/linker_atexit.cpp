#include "linker_image.hpp"

#include <cstdlib>
#include <cstring>
#include <pthread.h>

extern "C" void __cxa_finalize(void* dso);

namespace linker {
namespace {

size_t DynsymCount(const Image* so) {
    if (so->nsyms != 0) {
        return so->nsyms;
    }
    if (so->gnu_nbuckets == 0 || so->gnu_buckets == nullptr || so->gnu_chain == nullptr) {
        return 0;
    }
    size_t max_i = so->gnu_symoffset;
    for (uint32_t b = 0; b < so->gnu_nbuckets; ++b) {
        uint32_t n = so->gnu_buckets[b];
        if (n < so->gnu_symoffset) {
            continue;
        }
        const uint32_t* chain = so->gnu_chain + (n - so->gnu_symoffset);
        for (;;) {
            if (n + 1 > max_i) {
                max_i = n + 1;
            }
            if ((*chain & 1) != 0) {
                break;
            }
            ++n;
            ++chain;
        }
    }
    return max_i;
}

// __dso_handle is STV_HIDDEN / often omitted from exported lookup.
void* FindDsoHandle(const Image* so) {
    if (so == nullptr || so->dynsym == nullptr || so->dynstr == nullptr) {
        return nullptr;
    }
    const size_t n = DynsymCount(so);
    for (size_t i = 1; i < n; ++i) {
        const ElfW(Sym)* sym = so->dynsym + i;
        if (sym->st_shndx == SHN_UNDEF || so->dynstr[sym->st_name] == '\0') {
            continue;
        }
        if (strcmp(so->dynstr + sym->st_name, "__dso_handle") == 0) {
            return SymAddr(so, sym);
        }
    }
    return nullptr;
}

}  // namespace

void FinalizeDso(Image* so) {
    if (so == nullptr || !so->owns_mapping) {
        return;
    }
    if (void* handle = FindDsoHandle(so)) {
        __cxa_finalize(handle);
    }
}

}  // namespace linker

namespace {

struct ThreadDtor {
    void (*fn)(void*);
    void* arg;
    ThreadDtor* next;
};

pthread_key_t g_thread_dtors;
pthread_once_t g_thread_dtors_once = PTHREAD_ONCE_INIT;

void RunThreadDtors(void* p) {
    auto* head = static_cast<ThreadDtor*>(p);
    while (head != nullptr) {
        ThreadDtor* n = head;
        head = n->next;
        if (n->fn != nullptr) {
            n->fn(n->arg);
        }
        std::free(n);
    }
}

void ThreadDtorKey(void* p) {
    pthread_setspecific(g_thread_dtors, nullptr);
    RunThreadDtors(p);
    while (void* more = pthread_getspecific(g_thread_dtors)) {
        pthread_setspecific(g_thread_dtors, nullptr);
        RunThreadDtors(more);
    }
}

void InitThreadDtors() { pthread_key_create(&g_thread_dtors, ThreadDtorKey); }

int AddThreadDtor(void (*fn)(void*), void* arg) {
    if (fn == nullptr) {
        return 0;
    }
    pthread_once(&g_thread_dtors_once, InitThreadDtors);
    auto* n = static_cast<ThreadDtor*>(std::malloc(sizeof(ThreadDtor)));
    if (n == nullptr) {
        return -1;
    }
    n->fn = fn;
    n->arg = arg;
    n->next = static_cast<ThreadDtor*>(pthread_getspecific(g_thread_dtors));
    pthread_setspecific(g_thread_dtors, n);
    return 0;
}

}  // namespace

// After solist drop, libc's __cxa_thread_atexit_impl looks up dso_handle in
// soinfo and aborts. Keep the dtors; just do not ask the system linker.
extern "C" int __cxa_thread_atexit(void (*fn)(void*), void* arg, void*) {
    return AddThreadDtor(fn, arg);
}

extern "C" int __cxa_thread_atexit_impl(void (*fn)(void*), void* arg, void*) {
    return AddThreadDtor(fn, arg);
}
