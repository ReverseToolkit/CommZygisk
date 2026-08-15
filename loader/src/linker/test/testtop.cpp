extern "C" int mid_add3(int a, int b, int c);
extern "C" int mid_use_dep_data();
extern "C" void mid_bump_dep(int v);
extern "C" int mid_ctor_val();
extern "C" int mid_ifunc(int x);
extern "C" int mid_own_ifunc(int x);
extern "C" int mid_weak();
extern "C" void ctor_log_append(char c);
extern "C" const char* ctor_log();
extern "C" int dep_add(int a, int b);
extern "C" int dep_f31();

static int (*g_cb)(int, int);

__attribute__((constructor)) static void top_ctor() { ctor_log_append('T'); }

extern "C" int top_chain(int a, int b, int c) { return mid_add3(a, b, c) + dep_f31(); }

extern "C" int top_data() { return mid_use_dep_data(); }

extern "C" void top_set_data(int v) { mid_bump_dep(v); }

extern "C" int top_mid_ctor() { return mid_ctor_val(); }

extern "C" int top_ifuncs(int x) { return mid_ifunc(x) + mid_own_ifunc(x); }

extern "C" int top_weak() { return mid_weak(); }

extern "C" const char* top_order() { return ctor_log(); }

extern "C" void top_set_cb(int (*cb)(int, int)) { g_cb = cb; }

extern "C" int top_cb(int a, int b) { return g_cb ? g_cb(a, b) : -1; }

extern "C" int top_direct_dep(int a, int b) { return dep_add(a, b); }
