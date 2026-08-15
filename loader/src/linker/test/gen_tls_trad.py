#!/usr/bin/env python3
"""Rewrite RELATIVE slots on tls_idx_{a,b} into TLS_DTPMOD / TLS_DTPREL."""

import struct
import sys

R_ABS64 = 257
R_RELATIVE = 1027
R_DTPMOD = 1028
R_DTPREL = 1029
DT_RELA = 7
DT_RELASZ = 8
DT_SYMTAB = 6
DT_STRTAB = 5
DT_STRSZ = 10
PT_LOAD = 1
PT_DYNAMIC = 2
PT_TLS = 7


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def p64(b, o, v):
    struct.pack_into("<Q", b, o, v)


def vaddr_to_off(loads, va):
    for off, va0, filesz in loads:
        if va0 <= va < va0 + filesz:
            return off + (va - va0)
    raise SystemExit(f"vaddr {va:#x} not in a PT_LOAD")


def main():
    path = sys.argv[1]
    data = bytearray(open(path, "rb").read())
    if data[:4] != b"\x7fELF":
        raise SystemExit("not ELF")
    phoff = u64(data, 32)
    phentsize = u16(data, 54)
    phnum = u16(data, 56)

    loads = []
    dyn_va = None
    tls_filesz = None
    for i in range(phnum):
        o = phoff + i * phentsize
        p_type = u32(data, o)
        p_off = u64(data, o + 8)
        p_va = u64(data, o + 16)
        p_filesz = u64(data, o + 32)
        p_memsz = u64(data, o + 40)
        if p_type == PT_LOAD:
            loads.append((p_off, p_va, p_filesz))
        elif p_type == PT_DYNAMIC:
            dyn_va = p_va
        elif p_type == PT_TLS:
            tls_filesz = p_filesz
            print(f"PT_TLS filesz={p_filesz:#x} memsz={p_memsz:#x}")

    if dyn_va is None:
        raise SystemExit("no PT_DYNAMIC")
    if tls_filesz is None or tls_filesz < 8:
        raise SystemExit("need PT_TLS with g_a+g_b")

    rela_va = rela_sz = sym_va = str_va = str_sz = 0
    dyn_off = vaddr_to_off(loads, dyn_va)
    o = dyn_off
    while True:
        tag = u64(data, o)
        val = u64(data, o + 8)
        if tag == 0:
            break
        if tag == DT_RELA:
            rela_va = val
        elif tag == DT_RELASZ:
            rela_sz = val
        elif tag == DT_SYMTAB:
            sym_va = val
        elif tag == DT_STRTAB:
            str_va = val
        elif tag == DT_STRSZ:
            str_sz = val
        o += 16

    str_off = vaddr_to_off(loads, str_va)
    dynstr = bytes(data[str_off : str_off + str_sz])

    def find_sym(name):
        want = name.encode() + b"\0"
        name_off = dynstr.find(want)
        if name_off < 0:
            raise SystemExit(f"no dynsym {name}")
        sym_off = vaddr_to_off(loads, sym_va)
        n = 0
        while True:
            st_name = u32(data, sym_off + n * 24)
            if st_name == name_off:
                return u64(data, sym_off + n * 24 + 8)
            n += 1
            if n > 4096:
                raise SystemExit(f"sym {name} not found")

    idx_a = find_sym("tls_idx_a")
    idx_b = find_sym("tls_idx_b")
    print(f"tls_idx_a={idx_a:#x} tls_idx_b={idx_b:#x}")

    want = {
        idx_a: (R_DTPMOD, 0),
        idx_a + 8: (R_DTPREL, 0),
        idx_b: (R_DTPMOD, 0),
        idx_b + 8: (R_DTPREL, 4),
    }
    rela_off = vaddr_to_off(loads, rela_va)
    found = set()
    for i in range(rela_sz // 24):
        e = rela_off + i * 24
        r_off = u64(data, e)
        r_info = u64(data, e + 8)
        r_type = r_info & 0xFFFFFFFF
        if r_off in want and r_type in (R_RELATIVE, R_ABS64):
            typ, addend = want[r_off]
            p64(data, e + 8, typ)
            p64(data, e + 16, addend)
            found.add(r_off)
            print(f"patched {r_off:#x} type={r_type} -> type={typ} addend={addend}")

    missing = set(want) - found
    if missing:
        raise SystemExit(f"missing RELATIVE slots: {[hex(x) for x in missing]}")

    open(path, "wb").write(data)
    print("ok")


if __name__ == "__main__":
    main()
