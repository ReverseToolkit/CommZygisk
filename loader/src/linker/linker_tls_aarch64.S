// TLSDESC resolver: preserve every register except x0 (AOSP tlsdesc_resolver.S).
.text
.align 2
.global TlsdescDynamic
.type TlsdescDynamic, %function
TlsdescDynamic:
    sub sp, sp, #(8 * 80)
    stp x29, x30, [sp]
    stp x1, x2, [sp, #16]
    stp x3, x4, [sp, #32]
    stp x5, x6, [sp, #48]
    stp x7, x8, [sp, #64]
    stp x9, x10, [sp, #80]
    stp x11, x12, [sp, #96]
    stp x13, x14, [sp, #112]
    stp x15, x16, [sp, #128]
    str x17, [sp, #144]
    stp q0, q1, [sp, #160]
    stp q2, q3, [sp, #192]
    stp q4, q5, [sp, #224]
    stp q6, q7, [sp, #256]
    bl TlsdescDynamicC
    ldp q6, q7, [sp, #256]
    ldp q4, q5, [sp, #224]
    ldp q2, q3, [sp, #192]
    ldp q0, q1, [sp, #160]
    ldr x17, [sp, #144]
    ldp x15, x16, [sp, #128]
    ldp x13, x14, [sp, #112]
    ldp x11, x12, [sp, #96]
    ldp x9, x10, [sp, #80]
    ldp x7, x8, [sp, #64]
    ldp x5, x6, [sp, #48]
    ldp x3, x4, [sp, #32]
    ldp x1, x2, [sp, #16]
    ldp x29, x30, [sp]
    add sp, sp, #(8 * 80)
    ret
.size TlsdescDynamic, .-TlsdescDynamic

.global TlsdescWeak
.type TlsdescWeak, %function
TlsdescWeak:
    ldr x0, [x0, #8]
    mrs x1, tpidr_el0
    sub x0, x0, x1
    ret
.size TlsdescWeak, .-TlsdescWeak
