#ifndef NG_NOVA_RUN_DIR_H
#define NG_NOVA_RUN_DIR_H
/* ==========================================================================
 * ONE TEMPORARY DIRECTORY PER RUN. Not per machine, not per harness, PER RUN.
 *
 * WHAT THIS REPLACES, named, because a header that outlives the facts it
 * describes is read as current. Four harnesses under this directory each named
 * their own temporary files, and the four were not equally broken:
 *
 *   tests_ntasm_x64_lower_nxo_pe.c  twelve ABSOLUTE literals
 *       /tmp/ng-nova-*.efi, identical in every run on every machine, removed
 *       and rewritten by every run. THIS IS THE DEFECT: two concurrent runs
 *       both remove() that path, both write it, and one run's write_refused
 *       -- whose entire property is that a refusal CREATES NO FILE -- can be
 *       made to observe another run's file. The property was not wrong; the
 *       path it was measured on belonged to everybody.
 *   tests_ntasm_macro_expand.c      /tmp/ng-a5-io-<pid>  already per PROCESS
 *   tests_ntasm_stub_table.c        $TMPDIR/ng-stub-table-image-<pid>  same
 *   tests_ntasm_cli.c               mkdtemp("/tmp/ng-cli-XXXXXX")  same
 *
 * The second group was already collision-free between CONCURRENT runs, and
 * saying otherwise would be the overstatement this project has been removing
 * all day: a pid is unique among live processes, so two runs never share one.
 * They are converted anyway, for one reason -- four harnesses each rolling
 * their own mechanism is a fourth convention that can drift, and the next
 * author has to rediscover that three of them were safe and one was not.
 *
 * WHY THIS IS A P0 AND NOT HYGIENE, and it is not an argument from tidiness.
 * Two concurrency incidents were observed, and this is the first one wearing a
 * different hat: a lot reported a transient GATES_DONE fail=1 carrying
 * `NTASM_NOVA_ABI failures=2` and `FAIL DIRECTION-SHAPE found 1 functions
 * carrying the direction rule shape, expected 4`, and the cause was a mid-write
 * race -- one writer rewriting a .nova source while a gate had it loaded. The
 * registry's own src_moved() fence fired for the same reason, and it used to
 * increment failures WITHOUT PRINTING ANYTHING, so a failures=1 with no FAIL
 * line in the log was unadjudicable. That fence is the tree's own admission
 * that concurrent writers are expected. A FIXED SHARED PATH is where the
 * damage of an expected race lands, and removing it removes the landing site
 * without touching a single check.
 *
 * WHAT IS NOT DONE HERE, stated so a reader does not conclude more than the
 * header supports. Nothing in this file makes a gate that is red because the
 * TREE MOVED become green. That gate is doing its job -- it is the only thing
 * standing between a run's answers and sources that changed underneath it --
 * and widening its tolerance to make concurrency pleasant would delete the
 * measurement. The defect was the shared path, and only the shared path is
 * gone. Two runs may still disagree, and when they do the tree moved.
 * ========================================================================== */
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define NG_RUN_DIR_MAX 512
#define NG_RUN_DIR_SLUG "ng-run"

/* The PARENT this run's directory is created inside, in this order:
 *
 *   NG_RUN_DIR   an explicit parent, named by whoever started the run
 *   NG_BUILD     the driver's OWN per-run build directory --
 *                legacy/tools/coldproof/ngbuild.sh:198, BUILD=${NG_BUILD:-.../ngbuild-
 *                $(date +%H%M%S)-$$} -- which is the mechanism this tree
 *                already uses to keep two runs apart, and the one the header
 *                was asked to use rather than invent a second of
 *   TMPDIR       the POSIX answer
 *   /tmp         last, and only because it is the same last resort the three
 *                harnesses above already took
 *
 * NG_BUILD IS INHERITED BY THE GATE PROCESS. A driver started as
 * `NG_BUILD=/somewhere bash ngbuild.sh` has that variable in its environment,
 * and the gate binary it later execs inherits it, so the gates see the same
 * isolation the driver chose for itself. When NG_BUILD is unset the driver
 * picks a unique BUILD for ITSELF and does not export it -- this header is not
 * a way to read the driver's private variable, and it does not pretend to be;
 * it falls through to TMPDIR and still gets a directory no other run can name.
 *
 * *explicit IS 1 when NG_RUN_DIR or NG_BUILD named the parent, and that bit is
 * what decides whether a failure may fall back. IT MAY NOT. A run whose parent
 * was named and cannot be used REFUSES, and a refusal is a red run with a
 * reason on stderr. A silent fallback would reproduce the very defect this
 * header exists to remove, one hop later and looking fixed: the run would
 * print a path, the path would be private, and the parent that failed would
 * never be mentioned. `explicit` exists only so the refusal reads as a
 * refusal.
 */
static inline const char *ng_run_dir_parent(int *explicit)
{
    const char *b;
    *explicit = 0;
    if ((b = getenv("NG_RUN_DIR")) != NULL && *b) { *explicit = 1; return b; }
    if ((b = getenv("NG_BUILD")) != NULL && *b) { *explicit = 1; return b; }
    if ((b = getenv("TMPDIR")) != NULL && *b) return b;
    return "/tmp";
}

/* Opens this run's directory, ONCE, and returns it. Returns NULL with `why`
 * filled when it refuses; it never returns a path anybody else could hold.
 *
 * mkdir IS THE UNIQUENESS MECHANISM, not a decoration on one: it is atomic,
 * and EEXIST is precisely the answer that says somebody else owns this name.
 * So the retry suffix is a COUNTER and not a random string, because the
 * primitive that claims the name is the same primitive that would have
 * detected the collision. A random-looking name would hide the property this
 * header claims; a counter, plus a refusal when the counter runs out, shows
 * it.
 *
 * MEMOISED, and the memo is the reason two call sites in one process cannot
 * disagree about the directory: there is exactly one.
 */
static inline const char *ng_run_dir(char *why, size_t cap)
{
    static char dir[NG_RUN_DIR_MAX];
    static char saved[NG_RUN_DIR_MAX];
    static int state; /* 0 untried, 1 open, -1 refused */
    const char *parent;
    unsigned n;
    int explicit;

    if (state) {
        if (state < 0 && cap) snprintf(why, cap, "%s", saved);
        return state > 0 ? dir : NULL;
    }
    state = -1;
    parent = ng_run_dir_parent(&explicit);
    if (!parent || !*parent) {
        snprintf(saved, sizeof saved, "no parent directory could be named");
        if (cap) snprintf(why, cap, "%s", saved);
        return NULL;
    }
    /* ONE level of parent is created, so a named parent that does not exist
     * yet works. A parent that exists and is unusable is left to fail HERE,
     * loudly, rather than being worked around. */
    if (mkdir(parent, 0700) != 0 && errno != EEXIST) {
        snprintf(saved, sizeof saved, "parent %s (%s) cannot be created: %s",
                 parent, explicit ? "named by NG_RUN_DIR or NG_BUILD" : "default",
                 strerror(errno));
        if (cap) snprintf(why, cap, "%s", saved);
        return NULL;
    }
    for (n = 0; n < 4096u; n++) {
        int len = (n == 0)
            ? snprintf(dir, sizeof dir, "%s/%s-%ld", parent, NG_RUN_DIR_SLUG,
                       (long)getpid())
            : snprintf(dir, sizeof dir, "%s/%s-%ld-%u", parent, NG_RUN_DIR_SLUG,
                       (long)getpid(), n);
        /* A TRUNCATED PATH IS REFUSED, not used. snprintf does not overflow;
         * it stops writing and returns the length it WOULD have written. An
         * unchecked caller therefore gets a shorter string that is still NUL
         * terminated and is very often still a DIRECTORY THAT EXISTS -- the
         * parent cut at a slash -- and the run would then open some other
         * directory entirely and report it as its own. That is the shared-path
         * defect wearing a completely different hat, produced by the very code
         * written to remove it, so the length is checked rather than trusted.
         * Measured reachability: NG_RUN_DIR would have to exceed about 490
         * characters, which no driver in this tree produces -- and a guard
         * that is unreachable is still a guard, whereas a truncation is not. */
        if (len < 0 || len >= (int)sizeof dir) {
            snprintf(saved, sizeof saved,
                     "the directory path under %.200s needs %d bytes and only %d are available",
                     parent, len, (int)sizeof dir);
            if (cap) snprintf(why, cap, "%s", saved);
            return NULL;
        }
        if (mkdir(dir, 0700) == 0) { state = 1; return dir; }
        if (errno != EEXIST) {
            snprintf(saved, sizeof saved,
                     "no private directory under %s (%s): %s", parent,
                     explicit ? "named by NG_RUN_DIR or NG_BUILD" : "default",
                     strerror(errno));
            if (cap) snprintf(why, cap, "%s", saved);
            return NULL;
        }
    }
    snprintf(saved, sizeof saved,
             "4096 directories named %s-%ld-* already exist under %s", NG_RUN_DIR_SLUG,
             (long)getpid(), parent);
    if (cap) snprintf(why, cap, "%s", saved);
    return NULL;
}

/* TRUE when `name` is a BARE file name: no separator, not "." and not "..".
 *
 * This is the guard that stops the defect returning through the new door. A
 * harness may pass an absolute path here, the directory would be built, the
 * run would print a path, and the file would land outside the directory the
 * run was given -- the shared-path defect with one more layer of indirection
 * and a better-looking log. So it is refused instead.
 */
static inline int ng_run_name_is_bare(const char *name)
{
    return name != NULL && *name != 0 && strcmp(name, ".") != 0 &&
           strcmp(name, "..") != 0 && strchr(name, '/') == NULL;
}

/* The path of `name` inside this run's directory. Returns `out`, or NULL with
 * `why` filled -- a caller MUST treat NULL as a failure to run, never as a
 * reason to fall back to a path of its own.
 */
static inline const char *ng_run_file(const char *name, char *out, size_t cap,
                                      char *why, size_t whycap)
{
    const char *d;
    if (!ng_run_name_is_bare(name)) {
        if (whycap)
            snprintf(why, whycap,
                     "%s is not a bare file name, so it would be written outside the run directory",
                     name ? name : "(null)");
        return NULL;
    }
    d = ng_run_dir(why, whycap);
    if (!d) return NULL;
    if (snprintf(out, cap, "%s/%s", d, name) >= (int)cap) {
        if (whycap)
            snprintf(why, whycap, "path %.200s/%.64s does not fit in %d bytes", d,
                     name, (int)cap);
        return NULL;
    }
    return out;
}

#endif
