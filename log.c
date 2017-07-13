#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#ifdef __ANDROID__
#   include <android/log.h>
#endif


int o_debug = 0;

void die(const char *fmt, ...)
{
    va_list ap;
    fflush(stdout);
    va_start(ap, fmt);
#ifndef __ANDROID__
    vfprintf(stderr, fmt, ap);
#else
    __android_log_vprint(ANDROID_LOG_VERBOSE, "dcdn", fmt, ap);
#endif
    va_end(ap);
    exit(1);
}

void debug(const char *fmt, ...)
{
    va_list ap;
    if (o_debug) {
        fflush(stdout);
        //fprintf(stderr, "debug: ");
        va_start(ap, fmt);
#ifndef __ANDROID__
        vfprintf(stderr, fmt, ap);
#else
        __android_log_vprint(ANDROID_LOG_VERBOSE, "dcdn", fmt, ap);
#endif
        va_end(ap);
        fflush(stderr);
    }
}

void pdie(const char *err)
{
    debug("errno %d\n", errno);
    fflush(stdout);
    perror(err);
    exit(1);
}

void hexdump(const void *p, size_t len)
{
    int count = 1;

    while (len--) {
        if (count == 1) {
            fprintf(stderr, "    %p: ", p);
        }

        fprintf(stderr, " %02x", *(unsigned char *)p++ & 0xff);

        if (count++ == 16) {
            fprintf(stderr, "\n");
            count = 1;
        }
    }

    if (count != 1) {
        fprintf(stderr, "\n");
    }
}
