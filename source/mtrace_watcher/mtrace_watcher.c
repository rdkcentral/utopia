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
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define UNUSED_PARAMETER(x) (void)(x)

// Sampling and log trimming configuration
#define LOG_SAMPLING_INTERVAL 20                 // Sample every 20th log entry
#define MAX_MTRACE_LOG_SIZE (2 * 1024 * 1024)    // 2MB limit for internal logs
//#define MTRACE_FILE_SIZE_LIMIT (200 * 1024)    // 200KB limit for mtrace files (for testing; set to 2MB in production)
//#define RESTART_DELAY_SEC 60                   // 60 seconds (1 minute) delay before restarting tracing (for testing; set to 300 in production)
#define MTRACE_FILE_SIZE_LIMIT (2 * 1024 * 1024) // For demo purpose
#define RESTART_DELAY_SEC 0.1                    // For demo purpose

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

static void start_tracing(void) {
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    if (tracing_started) return;
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
    muntrace();
    MTRACE_LOG("Stopped malloc tracing on pid %d\n", getpid());
    tracing_started = false;
}

static void analyze_log_file(const char *logfile_path) {
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    char timestamp[64];
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_info);

    // Extract base filename
    const char *base = strrchr(logfile_path, '/');
    base = base ? base + 1 : logfile_path;

    // Single analysis file (append mode)
    char analysis_file[512];
    snprintf(analysis_file, sizeof(analysis_file),
             "/rdklogs/logs/%s_analysis.txt", base);

    MTRACE_LOG("Analyzing mtrace log: %s -> %s (append mode)\n", logfile_path, analysis_file);

    // Fork to run perl analysis
    pid_t pid = fork();
    if (pid == 0) {
        // Child process: append timestamp header and perl output to file
        int fd = open(analysis_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            // Write separator and timestamp header
            dprintf(fd, "\n========================================\n");
            dprintf(fd, "Analysis at: %s (timestamp: %ld)\n", timestamp, now);
            dprintf(fd, "========================================\n");

            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        execlp("perl", "perl", "/lib/rdk/my_mtrace.pl", logfile_path, NULL);
        _exit(127);
    } else if (pid > 0) {
        // Parent: wait for analysis to complete
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            MTRACE_LOG("Perl analysis completed successfully, appended to: %s\n", analysis_file);
        } else {
            MTRACE_LOG("Perl analysis failed or exited abnormally\n");
        }
    } else {
        MTRACE_LOG("Failed to fork for perl analysis\n");
    }
}

static void rotate_and_compress_log(const char *logfile_path) {
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
    MTRACE_LOG("MTRACE file exceeded threshold limit (%d KB), stopping trace for analysis\n",
               MTRACE_FILE_SIZE_LIMIT / 1024);

    // Step 1: Stop tracing to close the file
    stop_tracing();

    // Step 2: Open and parse the log file with perl script
    analyze_log_file(logfile_path);

    // Step 3: Wait configured delay before restarting
    MTRACE_LOG("Waiting %f seconds before restarting mtrace...\n", RESTART_DELAY_SEC);
    sleep(RESTART_DELAY_SEC);

    // Step 4: Restart tracing with the SAME file (it will be overwritten/appended)
    MTRACE_LOG("Restarting mtrace logging to the same file: %s\n", logfile_path);
    mtrace();
    tracing_started = true;
}

// Check and trim mtrace file if it gets too large
static void check_and_trim_mtrace_file(void) {
    MTRACE_LOG("Inside %s\n", __FUNCTION__);
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

    /* Marker-file watcher: presence of /tmp/mtrace_<pid> starts tracing */
    snprintf(s_mtrace_watcher_filename, sizeof(s_mtrace_watcher_filename),
             "/tmp/mtrace_%d", getpid());
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
    MTRACE_LOG("mtrace_watcher_stop: loop destroyed\n");
}



