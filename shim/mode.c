/* The C under cache.goose: Goose's os module can't set a file's mode yet
   (docs/decisions.md, "File modes in C for now").

   ga_private makes a directory 0700 or a file 0600, and returns whether it
   could. On Windows, where these modes mean nothing, it does nothing and
   returns true: there the directory's ACL is the operator's to set.
   ga_mode, for the tests, gives a path's permission bits, or -1. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct { const uint8_t *data; int64_t len; } ga_bytes;
#pragma pack(pop)
_Static_assert(sizeof(ga_bytes) == sizeof(void *) + 8, "a Goose slice is { data, len }, packed");

#if defined(_WIN32)
bool ga_private(ga_bytes path, bool directory) {
    (void)path;
    (void)directory;
    return true;
}

int64_t ga_mode(ga_bytes path) {
    (void)path;
    return -1;
}
#else
#include <sys/stat.h>

static bool c_path(ga_bytes path, char *p, size_t size) {
    if (path.len <= 0 || path.len >= (int64_t)size || memchr(path.data, 0, (size_t)path.len)) return false;
    memcpy(p, path.data, (size_t)path.len);
    p[path.len] = 0;
    return true;
}

bool ga_private(ga_bytes path, bool directory) {
    char p[4096];
    return c_path(path, p, sizeof p) && chmod(p, directory ? 0700 : 0600) == 0;
}

int64_t ga_mode(ga_bytes path) {
    char p[4096];
    struct stat st;
    if (!c_path(path, p, sizeof p) || stat(p, &st) != 0) return -1;
    return st.st_mode & 0777;
}
#endif
