#ifndef MTRACE_WATCHER_H
#define MTRACE_WATCHER_H

#ifdef __cplusplus
extern "C" {
#endif

/* ======================================================================
 * Common self-contained API  (preferred for new components)
 *
 * The ev_loop is owned internally; components do not need libev headers.
 *
 * Typical usage in a daemon's main():
 *
 *   daemonize();
 *   // ... all subsystem init ...
 *   mtrace_watcher_start();       // initializes and blocks forever
 * ====================================================================== */

/**
 * mtrace_watcher_start - Single entry point: initialize and run until exit.
 * Replaces a component's while(1)/sleep() main loop and creates the internal
 * loop on first call.
 * Calls mtrace_watcher_stop() automatically before returning.
 */
void mtrace_watcher_start(void);

/**
 * mtrace_watcher_stop - Stop all watchers and destroy the internal loop.
 * Safe to call even if mtrace_watcher_start() was never invoked.
 */
void mtrace_watcher_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* MTRACE_WATCHER_H */
