// Many RELATIVE pointers so RELR / APS2 actually fire.
extern "C" int pack_f00() { return 0; }
extern "C" int pack_f01() { return 1; }
extern "C" int pack_f02() { return 2; }
extern "C" int pack_f03() { return 3; }
extern "C" int pack_f04() { return 4; }
extern "C" int pack_f05() { return 5; }
extern "C" int pack_f06() { return 6; }
extern "C" int pack_f07() { return 7; }
extern "C" int pack_f08() { return 8; }
extern "C" int pack_f09() { return 9; }
extern "C" int pack_f10() { return 10; }
extern "C" int pack_f11() { return 11; }
extern "C" int pack_f12() { return 12; }
extern "C" int pack_f13() { return 13; }
extern "C" int pack_f14() { return 14; }
extern "C" int pack_f15() { return 15; }
extern "C" int pack_f16() { return 16; }
extern "C" int pack_f17() { return 17; }
extern "C" int pack_f18() { return 18; }
extern "C" int pack_f19() { return 19; }
extern "C" int pack_f20() { return 20; }
extern "C" int pack_f21() { return 21; }
extern "C" int pack_f22() { return 22; }
extern "C" int pack_f23() { return 23; }
extern "C" int pack_f24() { return 24; }
extern "C" int pack_f25() { return 25; }
extern "C" int pack_f26() { return 26; }
extern "C" int pack_f27() { return 27; }
extern "C" int pack_f28() { return 28; }
extern "C" int pack_f29() { return 29; }
extern "C" int pack_f30() { return 30; }
extern "C" int pack_f31() { return 31; }

typedef int (*Fn)();
static Fn g_fn[] = {
        pack_f00, pack_f01, pack_f02, pack_f03, pack_f04, pack_f05, pack_f06, pack_f07,
        pack_f08, pack_f09, pack_f10, pack_f11, pack_f12, pack_f13, pack_f14, pack_f15,
        pack_f16, pack_f17, pack_f18, pack_f19, pack_f20, pack_f21, pack_f22, pack_f23,
        pack_f24, pack_f25, pack_f26, pack_f27, pack_f28, pack_f29, pack_f30, pack_f31,
};

static const char* g_str[] = {
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
        "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
};

extern "C" int pack_sum() {
    int s = 0;
    for (int i = 0; i < 32; ++i) {
        s += g_fn[i]();
    }
    return s;
}

extern "C" int pack_str() { return g_str[3][1] + g_str[8][1]; }
