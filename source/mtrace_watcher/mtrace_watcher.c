#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ev.h>
#include <mcheck.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <malloc.h>

/* __malloc_hook / __realloc_hook / __free_hook were removed from glibc headers
 * in glibc 2.32+ on newer build hosts, but still exist in the runtime glibc on
 * the ARM32 target device.  Declare them manually so cross-compilation succeeds
 * while the hooks work correctly on the target at runtime. */
#ifndef __MALLOC_HOOK_VOLATILE
#define __MALLOC_HOOK_VOLATILE
#endif
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
extern void *(*__MALLOC_HOOK_VOLATILE __malloc_hook)(size_t, const void *);
extern void *(*__MALLOC_HOOK_VOLATILE __realloc_hook)(void *, size_t, const void *);
extern void  (*__MALLOC_HOOK_VOLATILE __free_hook)(void *, const void *);
#pragma GCC diagnostic pop
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <stdint.h>

#define UNUSED_PARAMETER(x) (void)(x)

// Sampling and log trimming configuration
#define LOG_SAMPLING_INTERVAL 20                 // Sample every 20th log entry
#define MAX_MTRACE_LOG_SIZE (2 * 1024 * 1024)    // 2MB limit for internal logs
//#define MTRACE_FILE_SIZE_LIMIT (200 * 1024)    // 200KB limit for mtrace files (for testing; set to 2MB in production)
//#define RESTART_DELAY_SEC 60                   // 60 seconds (1 minute) delay before restarting tracing (for testing; set to 300 in production)
/* Depth-N capture at RDKB_MTRACE_SAMPLE=1 (no sampling loss) logs every
 * single allocation, so this limit is reached far faster than with the
 * default 25% sampling. If a bounded triage run (mtrace_triage.sh with a
 * known duration) crosses this limit mid-run, rotate_and_compress_log()
 * truncates the log and starts a new segment — and my_mtrace_depth2.pl can
 * only match an alloc against a free WITHIN the same segment, so anything
 * that allocates just before a rotation and frees just after gets
 * mis-reported as a false leak. Sized generously (20MB) so a single bounded
 * triage session (a few minutes, full sampling) stays in one segment and
 * produces one complete, un-fragmented report instead of several. Raise
 * further for longer full-sample sessions; lower back toward 2MB for
 * long-running/continuous low-sample-rate monitoring where bounded memory
 * use on /tmp matters more than single-segment completeness.
 */
#define MTRACE_FILE_SIZE_LIMIT (20 * 1024 * 1024)
#define RESTART_DELAY_SEC 0.1                    // For demo purpose

/* ================================================================
 * Depth-N Runtime Configuration
 * ================================================================
 * RDKB_MTRACE_DEPTH  : 0 or 1 = standard mtrace (default)
 *                      2..32  = backtrace depth-N (symbol overrides)
 * RDKB_MTRACE_SAMPLE : 1=all, 4=25% (default), up to 64
 *
 * Activation: touch /tmp/mtrace_<pid>  (same marker for both modes)
 * depth<=1  ->  mtrace()/muntrace()   ->  /tmp/mtrace_<proc>_<pid>.log
 * depth>1   ->  malloc/free overrides ->  /tmp/mtrace2_<proc>_<pid>.log
 * ================================================================ */
#define DN_DEPTH_MIN      2
#define DN_DEPTH_MAX      32
#define DN_SAMPLE_MIN     1
#define DN_SAMPLE_MAX     64
#define DN_SAMPLE_DEFAULT 4

static int g_capture_depth = 0;
static int g_sample_ratio  = DN_SAMPLE_DEFAULT;

static bool log_fp_initialized = false;
static FILE *mtrace_log_fp = NULL;
static bool tracing_started = false;

// Function to check if we can still log (file size control)
static int can_log_more(FILE *fp) {
    if (!fp || fp == stderr) return 1;
    struct stat st;
    if (fstat(fileno(fp), &st) == 0 && st.st_size > MAX_MTRACE_LOG_SIZE)
        return 0;
    return 1;
}

static FILE *get_log_fp(void) {
    if (!log_fp_initialized) {
        const char *logfile = getenv("RDKB_MTRACE_LOGFILE");
        if (logfile && *logfile) {
            mtrace_log_fp = fopen(logfile, "a");
            if (!mtrace_log_fp) {
                mtrace_log_fp = stdout;
            }
        } else {
            mtrace_log_fp = stdout;
        }
        log_fp_initialized = true;
    }
    return mtrace_log_fp;
}

// Trimmed logging macro with sampling
#define MTRACE_LOG(fmt, ...) \
    do { \
        FILE *fp = get_log_fp(); \
        if (can_log_more(fp)) { \
            if (fp) { \
                time_t t = time(NULL); \
                struct tm tm; \
                localtime_r(&t, &tm); \
                char ts[32]; \
                if (strftime(ts, sizeof(ts), "%Y %b %d %H:%M:%S", &tm)) { \
                    fprintf(fp, "%s [pid=%d] ", ts, (int)getpid()); \
                } \
                fprintf(fp, fmt, ##__VA_ARGS__); \
                fflush(fp); \
            } \
        } \
    } while(0)

//#define MTRACE_LOG printf

static void sanitize_name(char *s) {
    if (!s) return;
    for (char *p = s; *p; ++p) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') *p = '_';
    }
}

static void to_lower(char *s) {
    if (!s) return;
    for (char *p = s; *p; ++p) *p = (char)tolower((unsigned char)*p);
}

static void get_process_basename(char *buf, size_t len) {
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    if (!buf || len == 0) return;
    ssize_t ret = readlink("/proc/self/exe", buf, len - 1);
    if (ret > 0) {
        buf[ret] = '\0';
        char *base = strrchr(buf, '/');
        if (base) {
            memmove(buf, base + 1, strlen(base));
        }
    } else {
        snprintf(buf, len, "unknown");
    }
}

static void build_mtrace_log_filename(char *buf, size_t len) {
    if (!buf || len == 0) return;
    char pname[64];
    get_process_basename(pname, sizeof(pname));
    sanitize_name(pname);
    to_lower(pname);
    snprintf(buf, len, "/tmp/mtrace_%s_%d.log", pname, getpid());
}

/* ================================================================
 * Depth-N forward declarations (needed by start/stop_tracing below)
 * ================================================================ */
#define DN_PATH_MAX 256
static char            dn_log_path[DN_PATH_MAX]    = {0};
static char            dn_stats_path[DN_PATH_MAX]  = {0};
static char            dn_marker_path[128]         = {0}; /* /tmp/mtrace2_<pid> for depth-N */
static int             dn_log_fd   = -1;
static pthread_mutex_t dn_log_lock = PTHREAD_MUTEX_INITIALIZER;
static pid_t           dn_state_pid = 0;
static __thread int    dn_in_hook   = 0;

static void dn_read_config(void);
static void dn_init_paths(void);
static void dn_dump_stats(void);
static void dn_install_hooks(void);   /* forward — defined after hook fns */
static void dn_uninstall_hooks(void); /* forward */
/* ================================================================ */

/* ================================================================
 * Non-blocking restart support (needed by rotate_and_compress_log below)
 *
 * rotate_and_compress_log() previously called sleep(RESTART_DELAY_SEC)
 * directly, which blocks the shared libev loop (and therefore every other
 * watcher: the mtrace marker watcher, heap-trim watcher, and this very size
 * check timer) for the whole delay. Scheduling a one-shot ev_timer instead
 * keeps the loop responsive.
 * ================================================================ */
static struct ev_loop *s_active_loop         = NULL; /* set by mtrace_watcher_init() */
static ev_timer        s_restart_timer;
static bool            s_restart_timer_active = false;
static void restart_timer_cb(EV_P_ ev_timer *w, int revents);
/* ================================================================ */

static void start_tracing(void) {
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    if (tracing_started) return;

    dn_read_config();

    if (g_capture_depth > 1) {
        if (dn_state_pid != getpid()) { dn_init_paths(); dn_state_pid = getpid(); }

        /* Start every (re)start from an empty log file, mirroring mtrace()'s
         * own truncate-on-start behavior below. Without this, a log file
         * rotated after hitting MTRACE_FILE_SIZE_LIMIT would keep appending
         * to the already-oversized file forever instead of shrinking. */
        if (dn_log_fd >= 0) { close(dn_log_fd); dn_log_fd = -1; }
        int tfd = open(dn_log_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (tfd >= 0) close(tfd);

        dn_install_hooks();
        MTRACE_LOG("Started depth-%d capture (via __malloc_hook) pid=%d log=%s\n",
                   g_capture_depth, getpid(), dn_log_path);
        tracing_started = true;
        return;
    }

    /* Standard mtrace mode (unchanged). */
    char mtrace_log_filename[192];
    build_mtrace_log_filename(mtrace_log_filename, sizeof(mtrace_log_filename));
    setenv("MALLOC_TRACE", mtrace_log_filename, 1);
    mtrace();
    MTRACE_LOG("Started malloc tracing on pid %d (file %s)\n", getpid(), mtrace_log_filename);
    tracing_started = true;
}

static void stop_tracing(void) {
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    if (!tracing_started) return;
    if (g_capture_depth > 1) {
        dn_uninstall_hooks();
        dn_dump_stats();
        if (dn_log_fd >= 0) { close(dn_log_fd); dn_log_fd = -1; }
        MTRACE_LOG("Stopped depth-%d capture pid=%d\n", g_capture_depth, getpid());
    } else {
        muntrace();
        MTRACE_LOG("Stopped malloc tracing on pid %d\n", getpid());
    }
    tracing_started = false;
}

static void analyze_log_file(const char *logfile_path) {
    MTRACE_LOG("Inside %s\n", __FUNCTION__);

    /* Fork-detection: only the daemonized process (ppid==1) should run
     * perl analysis.  Forked children skip to avoid duplicate analysis. */
    if (getppid() != 1) {
        MTRACE_LOG("analyze_log_file: skipping — not daemonized (ppid=%d)\n",
                   (int)getppid());
        return;
    }

    /* Disable both mtrace and depth-N before analysis so the log is closed. */
    if (tracing_started) stop_tracing();

    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_info);

    const char *base = strrchr(logfile_path, '/');
    base = base ? base + 1 : logfile_path;

    char analysis_file[512];
    snprintf(analysis_file, sizeof(analysis_file),
             "/rdklogs/logs/%s_analysis.txt", base);

    /* Mode-aware perl script: depth-N logs need my_mtrace_depth2.pl */
    const char *perl_script = (g_capture_depth > 1)
        ? "/lib/rdk/my_mtrace_depth2.pl"
        : "/lib/rdk/my_mtrace.pl";

    MTRACE_LOG("Analyzing %s -> %s (script: %s)\n",
               logfile_path, analysis_file, perl_script);

    pid_t pid = fork();
    if (pid == 0) {
        int fd = open(analysis_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            dprintf(fd, "\n========================================\n");
            dprintf(fd, "Analysis at: %s (timestamp: %ld)\n", timestamp, now);
            dprintf(fd, "========================================\n");
            dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO); close(fd);
        }
        execlp("perl", "perl", perl_script, logfile_path, NULL);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
            MTRACE_LOG("Perl analysis done: %s\n", analysis_file);
        else
            MTRACE_LOG("Perl analysis failed\n");
    } else {
        MTRACE_LOG("Failed to fork for perl analysis\n");
    }
}

static char s_restart_trace_file[256];

static void rotate_and_compress_log(const char *logfile_path) {
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    MTRACE_LOG("MTRACE file exceeded threshold limit (%d KB), stopping trace for analysis\n",
               MTRACE_FILE_SIZE_LIMIT / 1024);

    // Step 1: Stop tracing to close the file
    stop_tracing();

    // Step 2: Open and parse the log file with perl script
    analyze_log_file(logfile_path);

    // Step 3: Restart tracing after a delay, without blocking the event loop.
    // Restarting with the SAME file is fine: start_tracing() truncates the
    // depth-N log (and mtrace() truncates its own file internally) so the
    // file is empty again when logging resumes.
    strncpy(s_restart_trace_file, logfile_path, sizeof(s_restart_trace_file) - 1);
    s_restart_trace_file[sizeof(s_restart_trace_file) - 1] = '\0';

    if (s_active_loop && !s_restart_timer_active) {
        MTRACE_LOG("Scheduling non-blocking mtrace restart in %f seconds for %s\n",
                   RESTART_DELAY_SEC, s_restart_trace_file);
        ev_timer_init(&s_restart_timer, restart_timer_cb, RESTART_DELAY_SEC, 0.);
        ev_timer_start(s_active_loop, &s_restart_timer);
        s_restart_timer_active = true;
    } else {
        /* No loop reference available (shouldn't normally happen once
         * mtrace_watcher_init() has run) — fall back to restarting
         * immediately rather than losing tracing entirely. */
        MTRACE_LOG("No event loop reference available; restarting mtrace immediately\n");
        start_tracing();
    }
}

// Check and trim mtrace file if it gets too large
/* ================================================================
 * Depth-N Capture Infrastructure
 *
 * How it works (via __malloc_hook/__realloc_hook/__free_hook):
 *   - glibc calls our hook functions instead of the real allocator.
 *   - Logging is gated by dn_is_tracing_enabled() which polls the marker
 *     file /tmp/mtrace2_<pid> every DN_SAMPLE_INTERVAL calls.
 *   - The dn_in_hook TLS guard prevents infinite recursion caused by
 *     backtrace()/dladdr() calling malloc while already inside a hook.
 *
 * Frame selection  (anchor-pass + fallback, same as cpuprocanalyzer):
 *   Preferred: find known_c1 in backtrace frames, then take the next
 *              DN_DEPTH distinct external frames as callers.
 *   Fallback : take the first DN_DEPTH distinct external frames when the
 *              anchor cannot be matched.
 * ================================================================ */

/* --- Detailed capture statistics ---------------------------------- */
#define DN_STAT_INC(v) ((void)__sync_fetch_and_add(&(v), 1))
#define DN_STAT_GET(v) ((unsigned long long)__sync_add_and_fetch(&(v), 0))
static volatile unsigned long long dn_st_capture_calls  = 0;
static volatile unsigned long long dn_st_unwind_ok      = 0;
static volatile unsigned long long dn_st_unwind_steps   = 0;
static volatile unsigned long long dn_st_self_skipped   = 0;
static volatile unsigned long long dn_st_c1_found       = 0;
static volatile unsigned long long dn_st_cn_found       = 0;
static volatile unsigned long long dn_st_c1_fallback    = 0;
static volatile unsigned long long dn_st_cn_fallback    = 0;
static volatile unsigned long long dn_st_stackscan_used  = 0;
static volatile unsigned long long dn_st_stackscan_hits  = 0;

#define DN_TOKEN_SZ      128
#define DN_DEPTH_MAX_ARR 32
#define DN_SAMPLE_INTERVAL_VAL 64
static __thread unsigned int dn_sample_counter = 0;

static void dn_init_paths(void)
{
    char proc[64];
    ssize_t n = readlink("/proc/self/exe", proc, sizeof(proc)-1);
    if (n > 0) {
        proc[n] = '\0';
        char *b = strrchr(proc, '/');
        if (b) memmove(proc, b+1, strlen(b));
    } else {
        snprintf(proc, sizeof(proc), "unknown");
    }
    sanitize_name(proc);
    to_lower(proc);
    /* Depth-N marker: triage script depth2 mode creates /tmp/mtrace2_<pid>.
     * Must match exactly or dn_is_tracing_enabled() will never fire. */
    snprintf(dn_marker_path, sizeof(dn_marker_path),
             "/tmp/mtrace2_%d", (int)getpid());
    snprintf(dn_log_path,   sizeof(dn_log_path),
             "/tmp/mtrace2_%s_%d.log", proc, (int)getpid());
    snprintf(dn_stats_path, sizeof(dn_stats_path),
             "/tmp/mtrace2_stats_%s_%d.log", proc, (int)getpid());
}

static void dn_read_config(void)
{
    const char *e;
    int v;

    e = getenv("RDKB_MTRACE_DEPTH");
    if (e && *e) {
        v = atoi(e);
        if      (v <= 1)            g_capture_depth = 0;
        else if (v <= DN_DEPTH_MAX) g_capture_depth = v;
        else {
            MTRACE_LOG("RDKB_MTRACE_DEPTH=%d out of range; using 0\n", v);
            g_capture_depth = 0;
        }
    }
    e = getenv("RDKB_MTRACE_SAMPLE");
    if (e && *e) {
        v = atoi(e);
        if (v >= DN_SAMPLE_MIN && v <= DN_SAMPLE_MAX)
            g_sample_ratio = v;
    }
    MTRACE_LOG("Depth-N config: depth=%d sample=%d mode=%s\n",
               g_capture_depth, g_sample_ratio,
               g_capture_depth > 1 ? "backtrace (__malloc_hook)"
                                   : "standard mtrace");
}

/* --- Marker-based tracing gate ------------------------------------ */
static int dn_is_tracing_enabled(void)
{
    /* Rebuild paths if the PID changed (after fork/daemonize). */
    if (dn_state_pid != getpid()) {
        dn_marker_path[0] = '\0';
        dn_log_path[0]    = '\0';
        dn_stats_path[0]  = '\0';
        if (dn_log_fd >= 0) { close(dn_log_fd); dn_log_fd = -1; }
        dn_init_paths();
        dn_state_pid = getpid();
    }

    /* Check marker file every DN_SAMPLE_INTERVAL_VAL calls to avoid
     * stat() overhead on every allocation. */
    if (++dn_sample_counter < (unsigned)DN_SAMPLE_INTERVAL_VAL)
        return (int)tracing_started;
    dn_sample_counter = 0;

    /* Use dn_marker_path (/tmp/mtrace2_<pid>) built by dn_init_paths().
     * The triage script depth2 mode creates /tmp/mtrace2_<pid>, NOT
     * /tmp/mtrace_<pid>.  Using the wrong marker means this function
     * never sees the file and depth-N capture never activates. */
    if (dn_marker_path[0] == '\0') dn_init_paths();
    struct stat st;
    int active = (stat(dn_marker_path, &st) == 0) ? 1 : 0;

    if ((int)tracing_started && !active) {
        /* Marker just disappeared — write final stats and sync flag so that
         * the next sample-interval returns (before the ev_stat callback fires)
         * correctly report tracing as off. Clearing tracing_started here also
         * causes the hook functions (dn_malloc_hook_fn/dn_realloc_hook_fn/
         * dn_free_hook_fn) to stop reinstalling themselves on their next
         * invocation, so the hooks are fully uninstalled without racing with
         * the ev_stat-driven stop_tracing() path. */
        dn_dump_stats();
        if (dn_log_fd >= 0) { close(dn_log_fd); dn_log_fd = -1; }
        tracing_started = false;
    }
    return active;
}

static void dn_ensure_log_open(void)
{
    if (dn_log_fd >= 0) return;
    pthread_mutex_lock(&dn_log_lock);
    if (dn_log_fd < 0)
        dn_log_fd = open(dn_log_path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    pthread_mutex_unlock(&dn_log_lock);
}

/* --- Frame helpers ------------------------------------------------- */
static void dn_frame_to_token(void *addr, char *out, size_t out_sz)
{
    Dl_info info;
    unsigned long pc = (unsigned long)(uintptr_t)addr;
    if (!out || !out_sz) return;
    if (addr && dladdr(addr, &info) && info.dli_fname) {
        unsigned long rel = pc;
        if (info.dli_fbase && pc >= (unsigned long)(uintptr_t)info.dli_fbase)
            rel = pc - (unsigned long)(uintptr_t)info.dli_fbase;
        const char *b = strrchr(info.dli_fname, '/');
        b = b ? b + 1 : info.dli_fname;
        snprintf(out, out_sz, "%s:[0x%lx]", b, rel);
    } else {
        snprintf(out, out_sz, "[unknown]:[0x%lx]", pc);
    }
}

static int dn_is_internal_frame(void *addr)
{
    Dl_info info;
    if (!addr || !dladdr(addr, &info) || !info.dli_fname) return 0;
    if (strstr(info.dli_fname, "libmtrace_watcher")       ||
        strstr(info.dli_fname, "libmtrace_depth2_watcher") ||
        strstr(info.dli_fname, "libc_malloc_debug"))
        return 1;
    const char *sym = info.dli_sname;
    if (sym && strstr(info.dli_fname, "/lib/libc.so")) {
        if (!strcmp(sym,"malloc") || !strcmp(sym,"calloc") ||
            !strcmp(sym,"realloc") || !strcmp(sym,"free")  ||
            strstr(sym,"__libc_malloc") || strstr(sym,"__libc_calloc") ||
            strstr(sym,"__libc_realloc") || strstr(sym,"__libc_free"))
            return 1;
    }
    return 0;
}

static uintptr_t dn_norm_pc(uintptr_t pc)
{
#if defined(__arm__)
    return pc & ~(uintptr_t)1;
#else
    return pc;
#endif
}

/* --- Heuristic raw-stack-scan fallback -----------------------------
 *
 * backtrace() on ARM32 relies on .ARM.exidx/.ARM.extab unwind tables (or
 * .eh_frame elsewhere). When glibc/target libraries are built without
 * -funwind-tables, backtrace() simply cannot walk past that frame and
 * dn_capture()'s anchor/fallback passes above come up empty beyond
 * callers[0] — this is what left most Caller2..CallerN slots showing
 * "no frame captured" in practice.
 *
 * Workaround: every non-leaf function still has to push its link register
 * (return address) onto the stack to make an ordinary call/return work —
 * that is a property of the ARM calling convention itself, independent of
 * whether unwind-table metadata describing it was emitted. So we scan the
 * raw stack memory for words that look like valid return addresses (i.e.
 * values dladdr() can map into some loaded module's code) and use those to
 * fill in the callers[] slots backtrace() left empty.
 *
 * This is inherently a heuristic, not a precise unwind: it can occasionally
 * pick up stale/garbage stack data that happens to resemble a code address,
 * or frames that aren't truly on the logical call chain. It is only used
 * to fill in slots that proper unwinding could not — callers[0] (the exact
 * immediate caller) and any frames backtrace() DID resolve are never
 * replaced by this.
 * ------------------------------------------------------------------ */
#define DN_STACKSCAN_WORDS 256

static int dn_is_executable_addr(void *addr)
{
    Dl_info info;
    if (!addr) return 0;
    return dladdr(addr, &info) != 0 && info.dli_fbase != NULL;
}

static void dn_stackscan_fill(void **callers, int depth, int *filled_io)
{
    int filled = *filled_io;
    /* Start scanning from the caller's own frame — __builtin_frame_address(0)
     * only needs a valid stack/frame pointer register, not unwind metadata,
     * so it works regardless of missing .ARM.exidx data. */
    uintptr_t *sp = (uintptr_t *)__builtin_frame_address(0);
    DN_STAT_INC(dn_st_stackscan_used);

    for (int i = 0; i < DN_STACKSCAN_WORDS && filled < depth; i++) {
        uintptr_t raw = sp[i];
        uintptr_t pc  = dn_norm_pc(raw);
        void     *cand = (void *)pc;
        if (!cand || dn_is_internal_frame(cand) || !dn_is_executable_addr(cand))
            continue;

        int dup = 0;
        for (int k = 0; k < filled; k++) {
            if (callers[k] == cand) { dup = 1; break; }
        }
        if (dup) continue;

        callers[filled++] = cand;
        DN_STAT_INC(dn_st_stackscan_hits);
    }
    *filled_io = filled;
}

/* --- N-frame collector (anchor-pass + fallback, same as cpuprocanalyzer) --
 *
 * IMPORTANT: callers[0] is pre-set by the hook to the glibc-supplied 'caller'
 * pointer (__builtin_return_address(0) inside malloc).  That is the most
 * reliable frame on ARM32 where backtrace() cannot always walk through library
 * frames compiled without -funwind-tables.  dn_capture fills callers[1..depth-1]
 * only — callers[0] is NEVER overwritten here.
 * ------------------------------------------------------------------ */
static void dn_capture(void *known_c1, void **callers, int depth)
{
    void     *frames[64];
    int       nframes, i, filled = 1;  /* start at 1 — callers[0] kept as-is */
    void     *last = known_c1;
    int       matched = 0;
    uintptr_t wanted = dn_norm_pc((uintptr_t)known_c1);

    /* dn_st_capture_calls is already incremented by the hook; don't double-count. */
    if (depth <= 1 || !callers) goto done;  /* only direct caller needed */

    nframes = backtrace(frames, (int)(sizeof(frames)/sizeof(frames[0])));
    if (nframes <= 0) { DN_STAT_INC(dn_st_c1_fallback); goto done; }
    DN_STAT_INC(dn_st_unwind_ok);

    /* Anchor pass: find known_c1 then collect depth-1 distinct ext frames. */
    for (i = 0; i < nframes && filled < depth; i++) {
        void     *fr  = frames[i];
        uintptr_t fp  = dn_norm_pc((uintptr_t)fr);
        DN_STAT_INC(dn_st_unwind_steps);
        if (!matched) { if (fp == wanted) matched = 1; continue; }
        if (fp == wanted || dn_is_internal_frame(fr) || fr == last) {
            if (dn_is_internal_frame(fr)) DN_STAT_INC(dn_st_self_skipped);
            continue;
        }
        callers[filled++] = last = fr;
    }

    /* Fallback pass: take first depth-1 distinct external frames. */
    if (!matched) {
        filled = 1; last = known_c1;
        for (i = 0; i < nframes && filled < depth; i++) {
            void     *fr = frames[i];
            uintptr_t fp = dn_norm_pc((uintptr_t)fr);
            DN_STAT_INC(dn_st_unwind_steps);
            if (dn_is_internal_frame(fr)) { DN_STAT_INC(dn_st_self_skipped); continue; }
            if ((wanted && fp == wanted) || fr == last) continue;
            callers[filled++] = last = fr;
        }
    }

    /* backtrace()-based passes above left slots unfilled (common on ARM32
     * when the frame in question lacks unwind tables) — fall back to a
     * heuristic raw-stack scan to try to recover them anyway. */
    if (filled < depth)
        dn_stackscan_fill(callers, depth, &filled);

done:
    /* callers[0] is always the hook's direct caller — count it as found. */
    if (callers[0]) DN_STAT_INC(dn_st_c1_found);
    else            DN_STAT_INC(dn_st_c1_fallback);
    if (filled > 1 && callers[1]) DN_STAT_INC(dn_st_cn_found);
    else                          DN_STAT_INC(dn_st_cn_fallback);
}

/* --- Stats dump ---------------------------------------------------- */
static void dn_dump_stats(void)
{
    int fd = open(dn_stats_path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) return;
    char line[512];
    int len = snprintf(line, sizeof(line),
        "pid=%d depth=%d sample=%d capture_calls=%llu unwind_ok=%llu "
        "steps=%llu self_skip=%llu c1_found=%llu cn_found=%llu "
        "c1_fb=%llu cn_fb=%llu stackscan_used=%llu stackscan_hits=%llu\n",
        (int)getpid(), g_capture_depth, g_sample_ratio,
        DN_STAT_GET(dn_st_capture_calls), DN_STAT_GET(dn_st_unwind_ok),
        DN_STAT_GET(dn_st_unwind_steps),  DN_STAT_GET(dn_st_self_skipped),
        DN_STAT_GET(dn_st_c1_found),      DN_STAT_GET(dn_st_cn_found),
        DN_STAT_GET(dn_st_c1_fallback),   DN_STAT_GET(dn_st_cn_fallback),
        DN_STAT_GET(dn_st_stackscan_used), DN_STAT_GET(dn_st_stackscan_hits));
    if (len > 0) (void)write(fd, line, (size_t)len);
    close(fd);
}

/* --- Event logger (write()-only, malloc-free) ---------------------- */
static void dn_log_event(char op, void *ptr, size_t sz,
                         void **callers, int depth)
{
    if (!dn_is_tracing_enabled()) return;
    if (g_sample_ratio > 1 &&
        ((uintptr_t)ptr >> 3) % (unsigned)g_sample_ratio != 0)
        return;

    /* Trim trailing NULL frames so we don't log [unknown]:[0x0] padding.
     * On ARM32 backtrace() often stops early in libs without unwind tables;
     * callers[0] is always valid (set directly from the hook's 'caller').
     * Also skip the event entirely if even callers[0] is NULL — nothing
     * useful to log when the direct malloc caller is unknown. */
    while (depth > 1 && callers[depth - 1] == NULL)
        depth--;
    if (callers[0] == NULL) return;

    dn_ensure_log_open();
    if (dn_log_fd < 0) return;

    char tokens[DN_DEPTH_MAX_ARR][DN_TOKEN_SZ];
    int d;
    for (d = 0; d < depth && d < DN_DEPTH_MAX_ARR; d++)
        dn_frame_to_token(callers[d], tokens[d], DN_TOKEN_SZ);

    char line[2048];
    int pos = snprintf(line, sizeof(line), "@ ");
    for (d = 0; d < depth && d < DN_DEPTH_MAX_ARR && pos < (int)sizeof(line)-1; d++) {
        if (d) pos += snprintf(line+pos, sizeof(line)-(size_t)pos, ";");
        pos += snprintf(line+pos, sizeof(line)-(size_t)pos, "%s", tokens[d]);
    }
    int len = snprintf(line+pos, sizeof(line)-(size_t)pos,
                       " %c 0x%016lx 0x%zx\n",
                       op, (unsigned long)(uintptr_t)ptr, sz);
    if (len <= 0 || pos+len <= 0) return;
    pthread_mutex_lock(&dn_log_lock);
    (void)write(dn_log_fd, line, (size_t)(pos+len));
    pthread_mutex_unlock(&dn_log_lock);
}

/* --- __malloc_hook based depth-N capture (no LD_PRELOAD needed) ---
 * Called from INSIDE glibc's malloc after restoring the saved hook.
 * Uses dn_capture() for anchor-pass frame selection + dn_log_event() for logging.
 * ------------------------------------------------------------------- */
static void *(*dn_saved_malloc_hook)(size_t, const void *);
static void *(*dn_saved_realloc_hook)(void *, size_t, const void *);
static void  (*dn_saved_free_hook)(void *, const void *);

static void *dn_malloc_hook_fn(size_t size, const void *caller)
{
    /* Restore saved hook first so malloc() below does not recurse here. */
    __malloc_hook = dn_saved_malloc_hook;
    DN_STAT_INC(dn_st_capture_calls);

    /* Capture backtrace NOW before calling malloc (stack is valid here). */
    void *callers[DN_DEPTH_MAX_ARR] = {0};
    callers[0] = (void *)(uintptr_t)caller;
    if (!dn_in_hook) {
        dn_in_hook = 1;
        dn_capture(callers[0], callers, g_capture_depth);
        dn_in_hook = 0;
    }

    void *p = malloc(size);

    if (!dn_in_hook) {
        dn_in_hook = 1;
        dn_log_event('+', p, size, callers, g_capture_depth);
        dn_in_hook = 0;
    }
    /* Reinstall only if still active. dn_log_event() -> dn_is_tracing_enabled()
     * may have just detected the marker file disappeared and cleared
     * tracing_started; in that case leave the saved (pre-existing) hook in
     * place so the hooks are genuinely removed instead of being put right
     * back on every allocation. */
    if (tracing_started) __malloc_hook = dn_malloc_hook_fn;
    return p;
}

static void *dn_realloc_hook_fn(void *ptr, size_t size, const void *caller)
{
    __realloc_hook = dn_saved_realloc_hook;
    void *callers[DN_DEPTH_MAX_ARR] = {0};
    callers[0] = (void *)(uintptr_t)caller;
    if (!dn_in_hook) {
        dn_in_hook = 1;
        dn_capture(callers[0], callers, g_capture_depth);
        if (ptr) dn_log_event('-', ptr, 0, callers, g_capture_depth);
        dn_in_hook = 0;
    }
    void *p = realloc(ptr, size);
    if (!dn_in_hook) {
        dn_in_hook = 1;
        dn_log_event('+', p, size, callers, g_capture_depth);
        dn_in_hook = 0;
    }
    /* Reinstall only if still active — see dn_malloc_hook_fn for rationale. */
    if (tracing_started) __realloc_hook = dn_realloc_hook_fn;
    return p;
}

static void dn_free_hook_fn(void *ptr, const void *caller)
{
    __free_hook = dn_saved_free_hook;
    void *callers[DN_DEPTH_MAX_ARR] = {0};
    callers[0] = (void *)(uintptr_t)caller;
    if (!dn_in_hook && ptr) {
        dn_in_hook = 1;
        dn_capture(callers[0], callers, g_capture_depth);
        dn_log_event('-', ptr, 0, callers, g_capture_depth);
        dn_in_hook = 0;
    }
    free(ptr);
    /* Reinstall only if still active — see dn_malloc_hook_fn for rationale. */
    if (tracing_started) __free_hook = dn_free_hook_fn;
}

static void dn_install_hooks(void)
{
    dn_saved_malloc_hook  = __malloc_hook;
    dn_saved_realloc_hook = __realloc_hook;
    dn_saved_free_hook    = __free_hook;
    __malloc_hook         = dn_malloc_hook_fn;
    __realloc_hook        = dn_realloc_hook_fn;
    __free_hook           = dn_free_hook_fn;
    MTRACE_LOG("Depth-N __malloc_hook installed pid=%d\n", getpid());
}

static void dn_uninstall_hooks(void)
{
    __malloc_hook  = dn_saved_malloc_hook;
    __realloc_hook = dn_saved_realloc_hook;
    __free_hook    = dn_saved_free_hook;
    MTRACE_LOG("Depth-N __malloc_hook removed pid=%d\n", getpid());
}
/* ================================================================
 * End of Depth-N Capture Infrastructure
 * ================================================================ */

static void check_and_trim_mtrace_file(void) {
    MTRACE_LOG("Inside %s\n", __FUNCTION__);

    /* Depth-N mode writes to dn_log_path, not MALLOC_TRACE (that env var is
     * only ever set by the standard mtrace() path below). Without this
     * branch, depth-N logs were never size-checked and could grow without
     * bound. */
    if (g_capture_depth > 1) {
        if (dn_log_path[0] == '\0') return;
        struct stat dst;
        if (stat(dn_log_path, &dst) == 0 && dst.st_size > MTRACE_FILE_SIZE_LIMIT) {
            MTRACE_LOG("Depth-N MTRACE file %s exceeded size limit (%ld bytes), rotating\n",
                       dn_log_path, (long)dst.st_size);
            if (tracing_started) {
                rotate_and_compress_log(dn_log_path);
            }
        }
        return;
    }

    const char *trace_file = getenv("MALLOC_TRACE");
    if (!trace_file) return;

    struct stat st;
    if (stat(trace_file, &st) == 0 && st.st_size > MTRACE_FILE_SIZE_LIMIT) {
        MTRACE_LOG("MTRACE file %s exceeded size limit (%ld bytes), rotating and compressing\n",
                   trace_file, st.st_size);
        if (tracing_started) {
            rotate_and_compress_log(trace_file);
        }
    }
}

static void mtrace_cb(EV_P_ ev_stat *w, int revents) {
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    MTRACE_LOG("mtrace file event: %s\n", w->path);
    if (revents & EV_STAT) {
        // Check if file was deleted (st_nlink == 0 means file no longer exists)
        if (w->attr.st_nlink == 0) {
            MTRACE_LOG("mtrace watcher file deleted: %s, stopping tracing\n", w->path);
            if (tracing_started) {
                stop_tracing();
            }
        } else {
            // File exists (created or modified)
            if (!tracing_started) {
                start_tracing();
            }
        }
    }
}

// Periodic timer callback to check mtrace file size
static void size_check_timer_cb(EV_P_ ev_timer *w, int revents) {
    UNUSED_PARAMETER(w);
    UNUSED_PARAMETER(revents);
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    if (tracing_started) {
        check_and_trim_mtrace_file();
    }
}

// One-shot timer callback: fires RESTART_DELAY_SEC after rotate_and_compress_log()
// stopped tracing for analysis. Replaces the previous blocking sleep() call so
// the shared libev loop keeps servicing the other watchers during the delay.
static void restart_timer_cb(EV_P_ ev_timer *w, int revents) {
    UNUSED_PARAMETER(w);
    UNUSED_PARAMETER(revents);
    MTRACE_LOG("Inside %s: restarting mtrace logging to %s\n", __FUNCTION__, s_restart_trace_file);
    s_restart_timer_active = false;
    if (!tracing_started) {
        start_tracing();
    }
}

// Heap info callback with reduced verbosity
static void heap_trim_cb(EV_P_ ev_stat *w, int revents) {
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    if (revents & EV_STAT) {
        MTRACE_LOG("heap info trigger file touched: %s\n", w->path);
        // Only dump malloc_info occasionally to avoid log spam
        static time_t last_malloc_info = 0;
        time_t now = time(NULL);
        if (now - last_malloc_info > 300) { // Only every 5 minutes
            FILE *fp = tmpfile();
            if (fp && malloc_info(0, fp) == 0) {
                fseek(fp, 0, SEEK_END);
                long sz = ftell(fp);
                MTRACE_LOG("malloc_info: JSON size %ld bytes (output suppressed for brevity)\n", sz);
                fclose(fp);
            }
            last_malloc_info = now;
        }
    }
}

static ev_stat  s_mtrace_watcher;
static ev_stat  s_heaptrim_watcher;
static ev_timer s_size_check_timer;
static char     s_mtrace_watcher_filename[192];
static char     s_heaptrim_filename[280];
static bool     s_watcher_initialized = false;
static pid_t    s_watcher_pid = 0;

/*
 * mtrace_watcher_init - Register all mtrace watchers onto an existing ev_loop.
 *
 * Replaces the former mtrace_watcher_thread().  The caller owns the loop and
 * drives it with ev_run(); no additional thread is created here.  Call this
 * once after the process has daemonized (getppid() == 1).
 *
 * Returns  0 on success.
 * Returns -1 if loop is NULL.
 */
static int mtrace_watcher_init(struct ev_loop *loop)
{
    MTRACE_LOG("Inside %s\n", __FUNCTION__);

    if (!loop) {
        MTRACE_LOG("mtrace_watcher_init: NULL loop\n");
        return -1;
    }

    /* Needed by rotate_and_compress_log()'s non-blocking restart timer. */
    s_active_loop = loop;

    /* Reset after fork so each child gets its own watchers. */
    if (s_watcher_pid != getpid()) {
        s_watcher_pid         = getpid();
        s_watcher_initialized = false;
    }

    if (s_watcher_initialized) {
        MTRACE_LOG("mtrace_watcher_init: already initialized for pid %d, skipping\n", getpid());
        return 0;
    }

    MTRACE_LOG("Starting mtrace watcher (API mode) for pid %d\n", getpid());

    /* Marker-file watcher:
     *   depth<=1 : /tmp/mtrace_<pid>   (standard mtrace)
     *   depth>1  : /tmp/mtrace2_<pid>  (depth-N __malloc_hook mode)
     * The watcher MUST watch the same path the triage script creates so that
     * mtrace_cb fires and start_tracing()/stop_tracing() are called.
     */
    if (g_capture_depth > 1) {
        if (dn_marker_path[0] == '\0') { dn_init_paths(); dn_state_pid = getpid(); }
        strncpy(s_mtrace_watcher_filename, dn_marker_path,
                sizeof(s_mtrace_watcher_filename) - 1);
        s_mtrace_watcher_filename[sizeof(s_mtrace_watcher_filename) - 1] = '\0';
    } else {
        snprintf(s_mtrace_watcher_filename, sizeof(s_mtrace_watcher_filename),
                 "/tmp/mtrace_%d", getpid());
    }

    /* Remove stale marker so libev does not trigger start_tracing() immediately. */
    if (unlink(s_mtrace_watcher_filename) == 0)
        MTRACE_LOG("Removed stale marker: %s\n", s_mtrace_watcher_filename);

    ev_stat_init(&s_mtrace_watcher, mtrace_cb, s_mtrace_watcher_filename, 0.);
    ev_stat_start(loop, &s_mtrace_watcher);

    /* Periodic timer: check mtrace log file size every 10 seconds */
    ev_timer_init(&s_size_check_timer, size_check_timer_cb, 10.0, 10.0);
    ev_timer_start(loop, &s_size_check_timer);
    MTRACE_LOG("Started periodic size check timer (every 10 seconds)\n");

    /* Heap-trim watcher: touching /tmp/heaptrim_<name>.flag dumps heap info */
    char proc_name[256];
    get_process_basename(proc_name, sizeof(proc_name));
    to_lower(proc_name);
    snprintf(s_heaptrim_filename, sizeof(s_heaptrim_filename),
             "/tmp/heaptrim_%s.flag", proc_name);
    int fd = open(s_heaptrim_filename, O_CREAT | O_RDWR, 0644);
    if (fd >= 0) close(fd);
    ev_stat_init(&s_heaptrim_watcher, heap_trim_cb, s_heaptrim_filename, 0.);
    ev_stat_start(loop, &s_heaptrim_watcher);

    s_watcher_initialized = true;
    MTRACE_LOG("mtrace_watcher_init: all watchers registered on loop %p\n", (void *)loop);
    return 0;
}

/*
 * mtrace_watcher_cleanup - Stop and detach all watchers from the loop.
 *
 * Call before ev_loop_destroy() on controlled shutdown.  Safe to call even
 * if mtrace_watcher_start() was never invoked.
 */
static void mtrace_watcher_cleanup(struct ev_loop *loop)
{
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    if (!loop || !s_watcher_initialized) return;
    ev_stat_stop(loop,  &s_mtrace_watcher);
    ev_timer_stop(loop, &s_size_check_timer);
    ev_stat_stop(loop,  &s_heaptrim_watcher);
    if (s_restart_timer_active) {
        ev_timer_stop(loop, &s_restart_timer);
        s_restart_timer_active = false;
    }
    s_watcher_initialized = false;
    MTRACE_LOG("mtrace_watcher_cleanup: watchers removed from loop %p\n", (void *)loop);
}

/* ======================================================================
 * Self-contained common API
 * The loop is owned internally; callers do not need to know about libev.
 * ====================================================================== */

static struct ev_loop *s_owned_loop = NULL;

/* Forward declaration used by mtrace_watcher_start(). */
void mtrace_watcher_stop(void);

/*
 * create_owned_loop - Create an internal ev_loop and register all watchers.
 *
 * Returns 0 on success, -1 on failure.
 */
static int create_owned_loop(void)
{
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    if (s_owned_loop) {
        MTRACE_LOG("create_owned_loop: already initialized for pid %d\n", getpid());
        return 0;
    }
    s_owned_loop = ev_loop_new(EVFLAG_AUTO);
    if (!s_owned_loop) {
        MTRACE_LOG("create_owned_loop: ev_loop_new failed\n");
        return -1;
    }
    int rc = mtrace_watcher_init(s_owned_loop);
    if (rc != 0) {
        ev_loop_destroy(s_owned_loop);
        s_owned_loop = NULL;
    }
    return rc;
}

/*
 * mtrace_watcher_start - Single entry point: initialize and run until exit.
 *
 * Replaces a component's  while(1) { sleep(N); }  blocking loop. Creates the
 * internal loop on first call.
 * Calls mtrace_watcher_stop() automatically before returning.
 */
void mtrace_watcher_start(void)
{
    const char *trace_file = getenv("RDKB_MTRACE_LOGFILE");
    if (!trace_file) {
        setenv("RDKB_MTRACE_LOGFILE", "/tmp/mtrace_watcher_log.txt", 1);
    }
    dn_read_config();
    if (dn_state_pid != getpid()) { dn_init_paths(); dn_state_pid = getpid(); }
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    if (!s_owned_loop) {
        if (create_owned_loop() != 0) {
            MTRACE_LOG("mtrace_watcher_start: create_owned_loop failed\n");
            return;
        }
    }
    MTRACE_LOG("mtrace_watcher_start: entering ev_run\n");
    ev_run(s_owned_loop, 0);
    mtrace_watcher_stop();
}

/*
 * mtrace_watcher_stop - Stop all watchers and destroy the internal loop.
 *
 * Safe to call even if mtrace_watcher_start() was never invoked.
 */
void mtrace_watcher_stop(void)
{
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    if (!s_owned_loop) return;
    ev_break(s_owned_loop, EVBREAK_ALL);
    mtrace_watcher_cleanup(s_owned_loop);
    ev_loop_destroy(s_owned_loop);
    s_owned_loop = NULL;
    s_active_loop = NULL;
    MTRACE_LOG("mtrace_watcher_stop: loop destroyed\n");
}



