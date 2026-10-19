#include "dl.hpp"
#include "linker_image.hpp"
#include "logging.hpp"

#include <android/dlext.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <string>

extern "C" int __cxa_atexit(void (*func)(void*), void* arg, void* dso);
extern "C" int __cxa_thread_atexit(void (*func)(void*), void* arg, void* dso);
extern "C" int __cxa_thread_atexit_impl(void (*func)(void*), void* arg, void* dso);

namespace linker {
namespace {

void ApplyRtldFlags(Image* so, int flags) {
    so->rtld_flags = flags;
    if (flags & RTLD_GLOBAL) {
        so->global = true;
    }
    if (flags & RTLD_NODELETE) {
        so->nodelete = true;
    }
}

void* FinishLoad(Image* so, const LoadOptions& opt);

Image* LoadSystemDep(const char* name, const Image* origin) {
    if (Image* existing = FindBySoname(name)) {
        return existing;
    }
    std::string path;
    int fd = -1;
    const char* dlname = name;
    if (FindLibrary(name, origin, &path, &fd)) {
        close(fd);
        dlname = path.c_str();
    }
    // One soinfo in the process. App later dlopen of the same soname reuses it.
    void* handle = ::dlopen(dlname, RTLD_NOW | RTLD_GLOBAL);
    if (handle == nullptr) {
        const char* err = ::dlerror();
        SetErrorf("DT_NEEDED %s: system dlopen: %s", name, err ? err : "unknown");
        return nullptr;
    }
    RefreshProcessImages();
    if (Image* attached = FindBySoname(name)) {
        return attached;
    }
    if (!path.empty()) {
        if (Image* attached = FindBySoname(path.c_str())) {
            return attached;
        }
    }
    SetErrorf("DT_NEEDED %s: system dlopen ok but not in phdr list", name);
    return nullptr;
}

bool LoadNeeded(Image* so, const LoadOptions& parent_opt) {
    EnsureProcessImages();
    for (const auto& needed : so->needed) {
        if (Image* dep = FindBySoname(needed.c_str())) {
            so->children.push_back(dep);
            continue;
        }
        std::string path;
        int fd = -1;
        if (needed.find('/') != std::string::npos) {
            if (MustUseSystemLinker(needed.c_str()) || IsSystemLibraryPath(needed.c_str())) {
                Image* dep = LoadSystemDep(needed.c_str(), so);
                if (dep == nullptr) {
                    return false;
                }
                so->children.push_back(dep);
                continue;
            }
            fd = open(needed.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                SetErrorf("DT_NEEDED %s: not found", needed.c_str());
                return false;
            }
            path = needed;
        } else if (MustUseSystemLinker(needed.c_str()) ||
                   !FindPrivateLibrary(needed.c_str(), so, &path, &fd)) {
            Image* dep = LoadSystemDep(needed.c_str(), so);
            if (dep == nullptr) {
                return false;
            }
            so->children.push_back(dep);
            continue;
        }
        auto* dep = new Image();
        dep->name = path;
        LoadOptions child = parent_opt;
        child.file_offset = 0;
        if ((parent_opt.ext_flags & ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE) == 0) {
            child.reserved_addr = nullptr;
            child.reserved_size = 0;
            child.reserved_must = false;
        }
        const bool ok = LoadSegments(fd, dep, child);
        close(fd);
        if (!ok) {
            Destroy(dep);
            return false;
        }
        if (FinishLoad(dep, child) == nullptr) {
            return false;
        }
        so->children.push_back(dep);
    }
    return true;
}

void* FinishLoad(Image* so, const LoadOptions& opt) {
    ApplyRtldFlags(so, opt.rtld_flags);
    if (so->tls_size != 0) {
        RegisterTls(so);
    }
    Register(so);
    so->map.l_addr = so->load_bias;
    so->map.l_name = const_cast<char*>(so->name.empty() ? so->soname.c_str() : so->name.c_str());
    so->map.l_ld = const_cast<ElfW(Dyn)*>(so->dynamic);
    if (!LoadNeeded(so, opt) || !Relocate(so)) {
        Unregister(so);
        Destroy(so);
        return nullptr;
    }
    ProtectRelro(so);
    if (opt.ext_flags & ANDROID_DLEXT_WRITE_RELRO) {
        if (!WriteRelro(so, opt.relro_fd)) {
            Unregister(so);
            Destroy(so);
            return nullptr;
        }
    } else if (opt.ext_flags & ANDROID_DLEXT_USE_RELRO) {
        if (!UseRelro(so, opt.relro_fd)) {
            Unregister(so);
            Destroy(so);
            return nullptr;
        }
    }
    CallInit(so);
    LOGV("linker loaded %s bias=%p size=%zu soname=%s", so->name.empty() ? "(fd)" : so->name.c_str(),
         reinterpret_cast<void*>(so->load_bias), so->load_size,
         so->soname.empty() ? "(none)" : so->soname.c_str());
    return so;
}

void* OpenFd(int fd, const char* name, const LoadOptions& opt) {
    SetError("");
    EnsureProcessImages();
    if ((opt.ext_flags & ANDROID_DLEXT_FORCE_LOAD) == 0) {
        struct stat st {};
        if (fstat(fd, &st) == 0) {
            if (Image* existing = FindByDevIno(st.st_dev, st.st_ino)) {
                existing->refcount++;
                return existing;
            }
        }
        if (name != nullptr) {
            if (Image* existing = FindBySoname(name)) {
                existing->refcount++;
                return existing;
            }
        }
    }
    auto* so = new Image();
    if (name != nullptr) {
        so->name = name;
    }
    if (!LoadSegments(fd, so, opt)) {
        Destroy(so);
        return nullptr;
    }
    return FinishLoad(so, opt);
}

void* DoDlsym(void* handle, const char* name, const char* ver, const void* caller) {
    SetError("");
    if (name == nullptr) {
        SetError("dlsym: bad name");
        return nullptr;
    }
    EnsureProcessImages();
    if (handle == RTLD_DEFAULT) {
        if (void* api = ResolveLinkerApi(name)) {
            return api;
        }
        const LookupResult r = ResolveLookup(name, ver);
        void* addr = SymAddr(r.found_in, r.sym);
        if (addr == nullptr) {
            SetErrorf("undefined symbol: %s", name);
        }
        return addr;
    }
    if (handle == RTLD_NEXT) {
        struct NextCtx {
            const char* name;
            const char* ver;
            Image* after;
            bool skip;
            LookupResult r;
        } ctx{name, ver, FindByAddress(caller), FindByAddress(caller) != nullptr, {}};
        ForEachImage(
                [](Image* so, void* arg) {
                    auto* c = static_cast<NextCtx*>(arg);
                    if (c->skip) {
                        if (so == c->after) {
                            c->skip = false;
                        }
                        return;
                    }
                    if (c->r.sym == nullptr) {
                        c->r = Lookup(so, c->name, c->ver);
                    }
                },
                &ctx);
        void* addr = SymAddr(ctx.r.found_in, ctx.r.sym);
        if (addr == nullptr) {
            SetErrorf("undefined symbol: %s", name);
        }
        return addr;
    }
    Image* so = AsImage(handle);
    if (so == nullptr) {
        SetError("dlsym: bad handle");
        return nullptr;
    }
    LookupResult r = Lookup(so, name, ver);
    if (r.sym == nullptr) {
        for (Image* child : so->children) {
            r = Lookup(child, name, ver);
            if (r.sym != nullptr) {
                break;
            }
        }
    }
    void* addr = SymAddr(r.found_in, r.sym);
    if (addr == nullptr) {
        SetErrorf("undefined symbol: %s", name);
    }
    return addr;
}

}  // namespace

void* dlopen(const char* filename, int flags) {
    android_dlextinfo info{};
    return dlopen_ext(filename, flags, &info);
}

void* dlopen_fd(int fd, int flags) {
    android_dlextinfo info{};
    info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    info.library_fd = fd;
    return dlopen_ext(nullptr, flags, &info);
}

void* dlopen_ext(const char* filename, int flags, const android_dlextinfo* info) {
    SetError("");
    LoadOptions opt;
    opt.rtld_flags = flags;
    if (info != nullptr) {
        opt.ext_flags = info->flags;
        opt.relro_fd = info->relro_fd;
        if (info->flags & (ANDROID_DLEXT_RESERVED_ADDRESS | ANDROID_DLEXT_RESERVED_ADDRESS_HINT)) {
            opt.reserved_addr = info->reserved_addr;
            opt.reserved_size = info->reserved_size;
            opt.reserved_must = (info->flags & ANDROID_DLEXT_RESERVED_ADDRESS) != 0;
        }
        if (info->flags & ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET) {
            opt.file_offset = info->library_fd_offset;
        }
    }
    if (flags & RTLD_NOLOAD) {
        EnsureProcessImages();
        Image* existing = filename ? FindBySoname(filename) : nullptr;
        if (existing == nullptr) {
            SetErrorf("dlopen: %s not loaded", filename ? filename : "(fd)");
            return nullptr;
        }
        existing->refcount++;
        return existing;
    }
    if (info != nullptr && (info->flags & ANDROID_DLEXT_USE_LIBRARY_FD)) {
        return OpenFd(info->library_fd, filename, opt);
    }
    if (filename == nullptr || filename[0] == '\0') {
        SetError("dlopen: empty name");
        return nullptr;
    }
    EnsureProcessImages();
    if ((opt.ext_flags & ANDROID_DLEXT_FORCE_LOAD) == 0) {
        if (Image* existing = FindBySoname(filename)) {
            existing->refcount++;
            return existing;
        }
    }
    std::string path;
    int fd = -1;
    if (!FindLibrary(filename, nullptr, &path, &fd)) {
        SetErrorf("dlopen: cannot find %s", filename);
        return nullptr;
    }
    void* handle = OpenFd(fd, path.c_str(), opt);
    close(fd);
    return handle;
}

void* dlsym(void* handle, const char* name) { return DoDlsym(handle, name, nullptr, __builtin_return_address(0)); }

void* dlvsym(void* handle, const char* name, const char* version) {
    return DoDlsym(handle, name, version, __builtin_return_address(0));
}

int dlclose(void* handle) {
    SetError("");
    Image* so = AsImage(handle);
    if (so == nullptr) {
        SetError("dlclose: bad handle");
        return -1;
    }
    if (!so->owns_mapping || so->nodelete) {
        return 0;
    }
    LOGV("[unload-audit] dlclose name=%s refcount(before)=%u",
         so->name.empty() ? (so->soname.empty() ? "(anon)" : so->soname.c_str()) : so->name.c_str(),
         so->refcount);
    if (--so->refcount > 0) {
        return 0;
    }
    CallFini(so);
    Unregister(so);
    Destroy(so);
    return 0;
}

const char* dlerror() { return GetError(); }

void android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size) {
    GetLdLibraryPath(buffer, buffer_size);
}

void android_update_LD_LIBRARY_PATH(const char* ld_library_path) {
    SetLdLibraryPath(ld_library_path);
}

void* loader_dlopen(const char* filename, int flags, const void*) {
    return dlopen_ext(filename, flags, nullptr);
}

void* loader_dlsym(void* handle, const char* name, const void* caller) {
    return DoDlsym(handle, name, nullptr, caller);
}

void* loader_dlvsym(void* handle, const char* name, const char* ver, const void* caller) {
    return DoDlsym(handle, name, ver, caller);
}

void* loader_android_dlopen_ext(const char* filename, int flags, const android_dlextinfo* info,
                                const void*) {
    return dlopen_ext(filename, flags, info);
}

void* ResolveLinkerApi(const char* name) {
    if (name == nullptr) {
        return nullptr;
    }
    if (strcmp(name, "dlopen") == 0) {
        return reinterpret_cast<void*>(&dlopen);
    }
    if (strcmp(name, "dlsym") == 0) {
        return reinterpret_cast<void*>(&dlsym);
    }
    if (strcmp(name, "dlvsym") == 0) {
        return reinterpret_cast<void*>(&dlvsym);
    }
    if (strcmp(name, "dlclose") == 0) {
        return reinterpret_cast<void*>(&dlclose);
    }
    if (strcmp(name, "dlerror") == 0) {
        return reinterpret_cast<void*>(&dlerror);
    }
    if (strcmp(name, "dladdr") == 0) {
        return reinterpret_cast<void*>(&dladdr);
    }
    if (strcmp(name, "dl_iterate_phdr") == 0) {
        return reinterpret_cast<void*>(&dl_iterate_phdr);
    }
    if (strcmp(name, "android_dlopen_ext") == 0) {
        return reinterpret_cast<void*>(&dlopen_ext);
    }
    if (strcmp(name, "android_get_LD_LIBRARY_PATH") == 0) {
        return reinterpret_cast<void*>(&android_get_LD_LIBRARY_PATH);
    }
    if (strcmp(name, "android_update_LD_LIBRARY_PATH") == 0) {
        return reinterpret_cast<void*>(&android_update_LD_LIBRARY_PATH);
    }
    if (strcmp(name, "__tls_get_addr") == 0) {
        return reinterpret_cast<void*>(&TlsGetAddr);
    }
    if (strcmp(name, "__loader_dlopen") == 0) {
        return reinterpret_cast<void*>(&loader_dlopen);
    }
    if (strcmp(name, "__loader_dlsym") == 0) {
        return reinterpret_cast<void*>(&loader_dlsym);
    }
    if (strcmp(name, "__loader_dlvsym") == 0) {
        return reinterpret_cast<void*>(&loader_dlvsym);
    }
    if (strcmp(name, "__loader_dlclose") == 0) {
        return reinterpret_cast<void*>(&dlclose);
    }
    if (strcmp(name, "__loader_dlerror") == 0) {
        return reinterpret_cast<void*>(&dlerror);
    }
    if (strcmp(name, "__loader_dladdr") == 0) {
        return reinterpret_cast<void*>(&dladdr);
    }
    if (strcmp(name, "__loader_dl_iterate_phdr") == 0) {
        return reinterpret_cast<void*>(&dl_iterate_phdr);
    }
    if (strcmp(name, "__loader_android_dlopen_ext") == 0) {
        return reinterpret_cast<void*>(&loader_android_dlopen_ext);
    }
    if (strcmp(name, "__cxa_atexit") == 0) {
        return reinterpret_cast<void*>(&__cxa_atexit);
    }
    if (strcmp(name, "__cxa_thread_atexit") == 0) {
        return reinterpret_cast<void*>(&__cxa_thread_atexit);
    }
    if (strcmp(name, "__cxa_thread_atexit_impl") == 0) {
        return reinterpret_cast<void*>(&__cxa_thread_atexit_impl);
    }
    return nullptr;
}

}  // namespace linker

void* DlopenMem(int fd, int flags) {
    void* handle = linker::dlopen_fd(fd, flags);
    if (handle) {
        LOGV("linker dlopen_fd %d: handle %p", fd, handle);
    } else {
        const char* err = linker::dlerror();
        LOGE("linker dlopen_fd %d failed: %s", fd, err ? err : "unknown");
    }
    return handle;
}

void* Dlsym(void* handle, const char* name) { return linker::dlsym(handle, name); }

void* Dlvsym(void* handle, const char* name, const char* version) {
    return linker::dlvsym(handle, name, version);
}

int Dlclose(void* handle) { return linker::dlclose(handle); }

const char* Dlerror() { return linker::dlerror(); }

int Dladdr(const void* addr, Dl_info* info) { return linker::dladdr(addr, info); }
