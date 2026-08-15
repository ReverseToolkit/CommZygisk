#!/usr/bin/env python3
"""Rewrite the RELATIVE on dep_ifunc_slot into IRELATIVE."""

import struct
import sys

R_RELATIVE = 1027
R_IRELATIVE = 1032
DT_RELA = 7
DT_RELASZ = 8
DT_SYMTAB = 6
DT_STRTAB = 5
DT_STRSZ = 10
PT_LOAD = 1
PT_DYNAMIC = 2


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
    phoff = u64(data, 32)
    phentsize = u16(data, 54)
    phnum = u16(data, 56)
    loads = []
    dyn_va = None
    for i in range(phnum):
        o = phoff + i * phentsize
        p_type = u32(data, o)
        p_off = u64(data, o + 8)
        p_va = u64(data, o + 16)
        p_filesz = u64(data, o + 32)
        if p_type == PT_LOAD:
            loads.append((p_off, p_va, p_filesz))
        elif p_type == PT_DYNAMIC:
            dyn_va = p_va

    rela_va = rela_sz = sym_va = str_va = str_sz = 0
    o = vaddr_to_off(loads, dyn_va)
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

    dynstr = bytes(data[vaddr_to_off(loads, str_va) : vaddr_to_off(loads, str_va) + str_sz])
    name_off = dynstr.find(b"dep_ifunc_slot\0")
    if name_off < 0:
        raise SystemExit("no dep_ifunc_slot")
    sym_off = vaddr_to_off(loads, sym_va)
    slot_va = None
    n = 0
    while n < 4096:
        if u32(data, sym_off + n * 24) == name_off:
            slot_va = u64(data, sym_off + n * 24 + 8)
            break
        n += 1
    if slot_va is None:
        raise SystemExit("dep_ifunc_slot not in dynsym")

    rela_off = vaddr_to_off(loads, rela_va)
    for i in range(rela_sz // 24):
        e = rela_off + i * 24
        if u64(data, e) == slot_va and (u64(data, e + 8) & 0xFFFFFFFF) == R_RELATIVE:
            addend = u64(data, e + 16)
            p64(data, e + 8, R_IRELATIVE)
            print(f"patched {slot_va:#x} RELATIVE -> IRELATIVE addend={addend:#x}")
            open(path, "wb").write(data)
            return
    raise SystemExit(f"no RELATIVE at dep_ifunc_slot {slot_va:#x}")


if __name__ == "__main__":
    main()
