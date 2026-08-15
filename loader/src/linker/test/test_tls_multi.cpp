// Multiple TLS vars + tbss. Built with local-dynamic + trad to emit DTPMOD/DTPREL.
#if defined(__clang__)
#define TLS_ATTR __attribute__((tls_model("local-dynamic")))
#else
#define TLS_ATTR
#endif

static thread_local TLS_ATTR int g_tdata0 = 1;
static thread_local TLS_ATTR int g_tdata1 = 2;
static thread_local TLS_ATTR int g_tdata2 = 3;
static thread_local TLS_ATTR char g_msg[8] = {'h', 'i', 0};
static thread_local TLS_ATTR int g_tbss0;
static thread_local TLS_ATTR int g_tbss1;
static thread_local TLS_ATTR char g_tbss_buf[32];

extern "C" int multi_tdata() { return g_tdata0 + g_tdata1 + g_tdata2; }

extern "C" int multi_tbss() { return g_tbss0 + g_tbss1 + g_tbss_buf[0]; }

extern "C" int multi_set(int a, int b, int c) {
    g_tdata0 = a;
    g_tbss0 = b;
    g_tbss_buf[0] = static_cast<char>(c);
    return g_tdata0 + g_tbss0 + g_tbss_buf[0];
}

extern "C" const char* multi_msg() { return g_msg; }
