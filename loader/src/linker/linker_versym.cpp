#include "linker_image.hpp"

#include <cstring>

namespace linker {
namespace {

const char* VerdefName(const Image* so, uint16_t ndx) {
    if (so->verdef_ptr == 0 || so->dynstr == nullptr) {
        return nullptr;
    }
    auto* vd = reinterpret_cast<const ElfW(Verdef)*>(so->load_bias + so->verdef_ptr);
    for (size_t i = 0; i < so->verdef_cnt && vd != nullptr; ++i) {
        if ((vd->vd_ndx & VERSYM_VERSION) == (ndx & VERSYM_VERSION)) {
            auto* aux = reinterpret_cast<const ElfW(Verdaux)*>(reinterpret_cast<const char*>(vd) +
                                                              vd->vd_aux);
            return so->dynstr + aux->vda_name;
        }
        if (vd->vd_next == 0) {
            break;
        }
        vd = reinterpret_cast<const ElfW(Verdef)*>(reinterpret_cast<const char*>(vd) + vd->vd_next);
    }
    return nullptr;
}

const char* VerneedName(const Image* so, uint16_t ndx) {
    if (so->verneed_ptr == 0 || so->dynstr == nullptr) {
        return nullptr;
    }
    auto* vn = reinterpret_cast<const ElfW(Verneed)*>(so->load_bias + so->verneed_ptr);
    for (size_t i = 0; i < so->verneed_cnt && vn != nullptr; ++i) {
        auto* aux = reinterpret_cast<const ElfW(Vernaux)*>(reinterpret_cast<const char*>(vn) +
                                                          vn->vn_aux);
        for (size_t j = 0; j < vn->vn_cnt && aux != nullptr; ++j) {
            if ((aux->vna_other & VERSYM_VERSION) == (ndx & VERSYM_VERSION)) {
                return so->dynstr + aux->vna_name;
            }
            if (aux->vna_next == 0) {
                break;
            }
            aux = reinterpret_cast<const ElfW(Vernaux)*>(reinterpret_cast<const char*>(aux) +
                                                         aux->vna_next);
        }
        if (vn->vn_next == 0) {
            break;
        }
        vn = reinterpret_cast<const ElfW(Verneed)*>(reinterpret_cast<const char*>(vn) + vn->vn_next);
    }
    return nullptr;
}

}  // namespace

bool SymbolVersionOk(const Image* so, uint32_t sym_idx, const char* want_ver) {
    if (so->versym == nullptr) {
        return want_ver == nullptr || want_ver[0] == '\0';
    }
    const ElfW(Versym) ver = so->versym[sym_idx];
    const uint16_t ndx = static_cast<uint16_t>(ver & VERSYM_VERSION);
    if (want_ver == nullptr || want_ver[0] == '\0') {
        return (ver & VERSYM_HIDDEN) == 0;
    }
    if (ndx == 0 || ndx == 1) {
        return false;
    }
    const char* have = VerdefName(so, ndx);
    if (have == nullptr) {
        have = VerneedName(so, ndx);
    }
    return have != nullptr && strcmp(have, want_ver) == 0;
}

}  // namespace linker
