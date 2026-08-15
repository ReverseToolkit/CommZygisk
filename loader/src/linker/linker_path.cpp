#include "linker_image.hpp"

#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#include <cstdio>

#include <cstring>
#include <string>
#include <vector>

namespace linker {
namespace {

#if defined(__LP64__)
constexpr const char* kAbiLib = "lib64";
#else
constexpr const char* kAbiLib = "lib";
#endif

std::string g_ld_library_path;

const char* DirName(const std::string& path) {
    const size_t slash = path.rfind('/');
    if (slash == std::string::npos) {
        return ".";
    }
    // POD TLS; std::string would register a thread_local dtor with soinfo.
    static thread_local char dir[PATH_MAX];
    const size_t n = slash < sizeof(dir) - 1 ? slash : sizeof(dir) - 1;
    memcpy(dir, path.c_str(), n);
    dir[n] = '\0';
    return dir;
}

void ReplaceAll(std::string* s, const char* from, const char* to) {
    const size_t fl = strlen(from);
    size_t pos = 0;
    while ((pos = s->find(from, pos)) != std::string::npos) {
        s->replace(pos, fl, to);
        pos += strlen(to);
    }
}

void SplitPath(const std::string& path, std::vector<std::string>* out) {
    size_t begin = 0;
    while (begin <= path.size()) {
        const size_t end = path.find(':', begin);
        const size_t n = (end == std::string::npos) ? path.size() - begin : end - begin;
        if (n != 0) {
            out->emplace_back(path.substr(begin, n));
        }
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1;
    }
}

}  // namespace

std::string ExpandPathVars(const std::string& path, const Image* origin) {
    std::string out = path;
    const char* origin_dir = origin != nullptr ? DirName(origin->name) : ".";
    ReplaceAll(&out, "${ORIGIN}", origin_dir);
    ReplaceAll(&out, "$ORIGIN", origin_dir);
    ReplaceAll(&out, "${LIB}", kAbiLib);
    ReplaceAll(&out, "$LIB", kAbiLib);
    ReplaceAll(&out, "${PLATFORM}", "arm64");
    ReplaceAll(&out, "$PLATFORM", "arm64");
    return out;
}

void SetLdLibraryPath(const char* path) { g_ld_library_path = path ? path : ""; }

void GetLdLibraryPath(char* buf, size_t n) {
    if (buf == nullptr || n == 0) {
        return;
    }
    snprintf(buf, n, "%s", g_ld_library_path.c_str());
}

bool IsSystemLibraryPath(const char* path) {
    if (path == nullptr || path[0] != '/') {
        return false;
    }
    static const char* const kPfx[] = {"/system/",     "/system_ext/", "/vendor/",
                                       "/product/",    "/odm/",        "/apex/",
                                       "/vendor_dlkm/", "/system_dlkm/", nullptr};
    for (const char* const* p = kPfx; *p; ++p) {
        if (strncmp(path, *p, strlen(*p)) == 0) {
            return true;
        }
    }
    return false;
}

bool MustUseSystemLinker(const char* name) {
    if (name == nullptr || name[0] == '\0') {
        return false;
    }
    const char* slash = strrchr(name, '/');
    const char* base = slash ? slash + 1 : name;
    // NDK STL may sit next to the module; still one soinfo in the process.
    return strcmp(base, "libc++_shared.so") == 0 || strcmp(base, "libc++.so") == 0 ||
           strcmp(base, "libstdc++.so") == 0;
}

bool FindPrivateLibrary(const char* name, const Image* origin, std::string* path, int* fd) {
    if (name == nullptr || name[0] == '\0' || strchr(name, '/') != nullptr) {
        return false;
    }
    std::vector<std::string> dirs;
    if (!g_ld_library_path.empty()) {
        std::vector<std::string> ld;
        SplitPath(g_ld_library_path, &ld);
        for (auto& d : ld) {
            if (!IsSystemLibraryPath((d + "/").c_str())) {
                dirs.emplace_back(std::move(d));
            }
        }
    }
    if (origin != nullptr && !origin->name.empty() && origin->name.find('/') != std::string::npos) {
        const char* dir = DirName(origin->name);
        if (!IsSystemLibraryPath((std::string(dir) + "/").c_str())) {
            dirs.emplace_back(dir);
        }
    }
    if (origin != nullptr && !origin->runpath.empty()) {
        std::vector<std::string> rp;
        SplitPath(origin->runpath, &rp);
        for (auto& d : rp) {
            if (!IsSystemLibraryPath((d + "/").c_str())) {
                dirs.emplace_back(std::move(d));
            }
        }
    }
    for (const auto& dir : dirs) {
        std::string cand = dir + "/" + name;
        const int nfd = open(cand.c_str(), O_RDONLY | O_CLOEXEC);
        if (nfd >= 0) {
            *fd = nfd;
            *path = cand;
            return true;
        }
    }
    return false;
}

bool FindLibrary(const char* name, const Image* origin, std::string* path, int* fd) {
    if (name == nullptr || name[0] == '\0') {
        return false;
    }
    if (strchr(name, '/') != nullptr) {
        const int nfd = open(name, O_RDONLY | O_CLOEXEC);
        if (nfd < 0) {
            return false;
        }
        *fd = nfd;
        *path = name;
        return true;
    }

    std::vector<std::string> dirs;
    if (!g_ld_library_path.empty()) {
        SplitPath(g_ld_library_path, &dirs);
    }
    if (origin != nullptr && !origin->name.empty() && origin->name.find('/') != std::string::npos) {
        dirs.emplace_back(DirName(origin->name));
    }
    if (origin != nullptr && !origin->runpath.empty()) {
        SplitPath(origin->runpath, &dirs);
    }
    const char* prefixes[] = {"/system", "/system_ext", "/vendor", "/apex/com.android.runtime",
                              "/apex/com.android.art", nullptr};
    for (const char** p = prefixes; *p; ++p) {
        dirs.emplace_back(std::string(*p) + "/" + kAbiLib);
    }
    for (const auto& dir : dirs) {
        std::string cand = dir + "/" + name;
        const int nfd = open(cand.c_str(), O_RDONLY | O_CLOEXEC);
        if (nfd >= 0) {
            *fd = nfd;
            *path = cand;
            return true;
        }
    }
    return false;
}

}  // namespace linker
