#pragma once

#include <android/log.h>
#include <cstdio>

#ifndef LOG_TAG
#define LOG_TAG "linker-test"
#endif

#define LOGE(...)                                                              \
    do {                                                                       \
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__);          \
        fprintf(stderr, "E ");                                                 \
        fprintf(stderr, __VA_ARGS__);                                          \
        fputc('\n', stderr);                                                   \
    } while (0)
#define LOGV(...)                                                              \
    do {                                                                       \
        __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__);        \
        fprintf(stderr, "V ");                                                 \
        fprintf(stderr, __VA_ARGS__);                                          \
        fputc('\n', stderr);                                                   \
    } while (0)
#define LOGI(...)                                                              \
    do {                                                                       \
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__);           \
        fprintf(stderr, "I ");                                                 \
        fprintf(stderr, __VA_ARGS__);                                          \
        fputc('\n', stderr);                                                   \
    } while (0)
