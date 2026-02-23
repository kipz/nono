/*
 * fork_interpose.c — DYLD interpose shim for nono learn mode on macOS
 *
 * Two responsibilities:
 *   1. Fork tracking: interposes fork/vfork/posix_spawn/posix_spawnp so the
 *      tracer can discover child processes. Child processes are sent SIGSTOP
 *      so the tracer can send SIGCONT at the right time.
 *   2. File access tracing: interposes open, stat, access, rename, mkdir,
 *      unlink, rmdir, symlink, link, readlink, and getattrlist, writing
 *      PATH:R or PATH:W lines to the NONO_TRACE_FD file descriptor.
 *
 * Required environment variables:
 *   NONO_TRACE_FD           Pre-opened (by tracer) writable file descriptor.
 *                           Must be opened WITHOUT O_CLOEXEC so it survives
 *                           fork and exec.
 *   NONO_COMM_FILE          Path to the comm file for child-PID reporting.
 *   STRACE_MACOS_CHILD_STOP If "1", child processes are sent SIGSTOP.
 *
 * Implementation note on calling conventions:
 *   DYLD __DATA,__interpose is self-excluding: calls that originate from
 *   within this dylib itself bypass the interpose table and go directly to
 *   libSystem. Therefore each nono_* wrapper calls the real function by name
 *   (e.g. "return stat(path, buf)") rather than via dlsym(RTLD_NEXT, ...).
 *   On macOS Sequoia, dlsym(RTLD_NEXT, X) is known to return the interposed
 *   address for some symbols, causing infinite recursion.
 *
 * SIP-compatible. No root required. Requires Xcode Command Line Tools.
 */

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ── trace output fd ────────────────────────────────────────────────────── */
/* Set from NONO_TRACE_FD at init; -1 means tracing is disabled */
static int _trace_fd = -1;

/* ── constructor ────────────────────────────────────────────────────────── */
__attribute__((constructor))
static void _nono_init(void) {
    const char *fd_str = getenv("NONO_TRACE_FD");
    if (fd_str && *fd_str) {
        _trace_fd = atoi(fd_str);
    }
}

/* ── trace output helper ────────────────────────────────────────────────── */
static void _write_trace(const char *path, int is_write) {
    if (_trace_fd < 0 || path == NULL || *path == '\0') return;
    if (path[0] != '/') return;           /* ignore relative paths */
    if (strncmp(path, "/dev/", 5) == 0) return; /* ignore device nodes */

    size_t plen = strnlen(path, 4090);
    char buf[4096];
    if (plen + 3 > sizeof(buf)) return;
    memcpy(buf, path, plen);
    buf[plen]     = ':';
    buf[plen + 1] = is_write ? 'W' : 'R';
    buf[plen + 2] = '\n';
    /* write() with O_APPEND is atomic for sizes < PIPE_BUF on O_APPEND files;
     * a single call minimises interleaving across processes. */
    (void)write(_trace_fd, buf, plen + 3);
}

/* ── fork-tracking helpers ─────────────────────────────────────────────── */
static int _should_stop_children(void) {
    const char *val = getenv("STRACE_MACOS_CHILD_STOP");
    return val != NULL && val[0] == '1' && val[1] == '\0';
}

static void _notify_child(pid_t pid) {
    const char *path = getenv("NONO_COMM_FILE");
    if (!path) return;
    /* open() here is a direct call within our dylib — bypasses interpose. */
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) return;
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%d\n", (int)pid);
    if (n > 0) (void)write(fd, buf, (size_t)n);
    close(fd);
}

/* ── file syscall interpositions ────────────────────────────────────────── */
/*
 * Each wrapper records the path access, then calls the real function by name.
 * Direct calls from within this dylib are self-excluded from the interpose
 * table, so they reach libSystem directly without recursion.
 */

int nono_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    _write_trace(path, flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC) ? 1 : 0);
    return open(path, flags, mode);
}

int nono_openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (path != NULL && path[0] == '/') {
        _write_trace(path, flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC) ? 1 : 0);
    }
    return openat(dirfd, path, flags, mode);
}

int nono_stat(const char *path, struct stat *buf) {
    _write_trace(path, 0);
    return stat(path, buf);
}

int nono_lstat(const char *path, struct stat *buf) {
    _write_trace(path, 0);
    return lstat(path, buf);
}

int nono_access(const char *path, int amode) {
    _write_trace(path, 0);
    return access(path, amode);
}

ssize_t nono_readlink(const char *path, char *buf, size_t len) {
    _write_trace(path, 0);
    return readlink(path, buf, len);
}

int nono_getattrlist(const char *path, void *attrList, void *attrBuf,
                     size_t attrBufSize, unsigned long options) {
    _write_trace(path, 0);
    return getattrlist(path, attrList, attrBuf, attrBufSize, options);
}

int nono_rename(const char *old, const char *new) {
    _write_trace(old, 1);
    _write_trace(new, 1);
    return rename(old, new);
}

int nono_mkdir(const char *path, mode_t mode) {
    _write_trace(path, 1);
    return mkdir(path, mode);
}

int nono_unlink(const char *path) {
    _write_trace(path, 1);
    return unlink(path);
}

int nono_rmdir(const char *path) {
    _write_trace(path, 1);
    return rmdir(path);
}

int nono_symlink(const char *name1, const char *name2) {
    _write_trace(name2, 1);
    return symlink(name1, name2);
}

int nono_link(const char *name1, const char *name2) {
    _write_trace(name1, 1);
    _write_trace(name2, 1);
    return link(name1, name2);
}

/* ── fork/spawn interpositions ─────────────────────────────────────────── */

pid_t nono_fork(void) {
    /*
     * Call fork() directly — do NOT use dlsym(RTLD_NEXT, "fork").
     * On macOS Sequoia, dlsym(RTLD_NEXT, "fork") returns the interposed
     * address (nono_fork itself), causing infinite recursion.
     */
    pid_t pid = fork();
    if (pid > 0 && _should_stop_children()) {
        kill(pid, SIGSTOP);
        _notify_child(pid);
    }
    return pid;
}

pid_t nono_vfork(void) {
    /* vfork suspends the parent; pass through transparently. */
    return vfork();
}

int nono_posix_spawn(pid_t *pid, const char *path,
                     const posix_spawn_file_actions_t *file_actions,
                     const posix_spawnattr_t *attrp,
                     char *const argv[], char *const envp[]) {
    int ret = posix_spawn(pid, path, file_actions, attrp, argv, envp);
    if (ret == 0 && pid != NULL && _should_stop_children()) {
        kill(*pid, SIGSTOP);
        _notify_child(*pid);
    }
    return ret;
}

int nono_posix_spawnp(pid_t *pid, const char *file,
                      const posix_spawn_file_actions_t *file_actions,
                      const posix_spawnattr_t *attrp,
                      char *const argv[], char *const envp[]) {
    int ret = posix_spawnp(pid, file, file_actions, attrp, argv, envp);
    if (ret == 0 && pid != NULL && _should_stop_children()) {
        kill(*pid, SIGSTOP);
        _notify_child(*pid);
    }
    return ret;
}

/* ── DYLD interpose table ───────────────────────────────────────────────── */
typedef struct { const void *replacement; const void *replacee; } interpose_t;

__attribute__((used))
static const interpose_t _nono_interposers[]
    __attribute__((section("__DATA,__interpose"))) = {
    /* file tracing */
    {(const void *)nono_open,        (const void *)open},
    {(const void *)nono_openat,      (const void *)openat},
    {(const void *)nono_stat,        (const void *)stat},
    {(const void *)nono_lstat,       (const void *)lstat},
    {(const void *)nono_access,      (const void *)access},
    {(const void *)nono_readlink,    (const void *)readlink},
    {(const void *)nono_getattrlist, (const void *)getattrlist},
    {(const void *)nono_rename,      (const void *)rename},
    {(const void *)nono_mkdir,       (const void *)mkdir},
    {(const void *)nono_unlink,      (const void *)unlink},
    {(const void *)nono_rmdir,       (const void *)rmdir},
    {(const void *)nono_symlink,     (const void *)symlink},
    {(const void *)nono_link,        (const void *)link},
    /* fork tracking */
    {(const void *)nono_fork,         (const void *)fork},
    {(const void *)nono_vfork,        (const void *)vfork},
    {(const void *)nono_posix_spawn,  (const void *)posix_spawn},
    {(const void *)nono_posix_spawnp, (const void *)posix_spawnp},
};
