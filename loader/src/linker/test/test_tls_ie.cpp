// Initial-exec TPREL against a dlopened SO: AOSP and we both reject.
#if defined(__clang__)
#define TLS_ATTR __attribute__((tls_model("initial-exec")))
#else
#define TLS_ATTR
#endif

static thread_local TLS_ATTR int g_ie = 1;

extern "C" int ie_get() { return g_ie; }
