#pragma once

/*
 * Userspace mirror of GKI uapi PROT_HIDE (common-android13-5.15).
 * Kernel: include/uapi/asm-generic/mman-common.h
 *   PROT_HIDE 0x40 → do_mmap/do_mprotect strips the bit and sets VM_VMA_HIDE,
 *   so the VMA is omitted from /proc/<pid>/maps, smaps, and pagemap walks.
 *
 * Stock kernels reject the unknown prot bit with EINVAL; linker::mmap / linker::mprotect
 * fall back to the same call without PROT_HIDE.
 */
#ifndef PROT_HIDE
#define PROT_HIDE 0x40
#endif
