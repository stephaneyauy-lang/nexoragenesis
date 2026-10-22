/* tests_ntasm_registry.c -- the frozen diagnostic code registry of
 * spec/ntasm/ntasm.md 17.6, checked against the tree it claims to describe.
 *
 * The registry asserts its own exhaustiveness: "Un code publie qui n'a pas de
 * ligne dans la table ci-dessus ne peut pas l'etre : la table est exhaustive
 * sur la bande 3xx, et c'est elle qui rend la regle verifiable au lieu de la
 * rendre tautologique" (spec/ntasm/ntasm.md:1529-1532). Until this harness existed no
 * gate opened the Markdown, so that sentence was tautological: adding
 * code=367 to body_effects.nova left all 88 gates green while the registry
 * declared 366-369 unattributed and unemittable. The claim is now derived from
 * both sides, in the same turn, from the two texts it relates:
 *
 *   - the rows of the family table of 17.6, parsed out of spec/ntasm/ntasm.md, and
 *   - the emissions of the real text of every Nova module of
 *     compiler/nova, outside tests/, recognised by the three forms the
 *     registry itself names as publications: an assignment code=3xx, a
 *     fail(env,3xx,...) and a return 3xx. Simple mentions are not
 *     publications, and the registry names the four it knows: 303 is a
 *     comment, 304/308/392 are byte offsets in pe.nova. None of the three
 *     forms matches them.
 *
 * Equality is required in both directions: an emitted code with no row fails,
 * and a row with no emitted code fails. The unattributed enumeration is parsed
 * from the registry too, and every value it names must be both unpublished and
 * unemitted. Finally the two bounds the registry states -- 386 for the
 * semantic band, 844 for the structural band -- must be present verbatim in
 * the schema table and must hold against the tree.
 *
 * A second closure was added for the COVERAGE counters: the prose of 17.8 and
 * of 11 states how many checks and how many cases a handful of gates really
 * run, and until now no gate read those words either. The pairs are read from
 * the document and the counters are measured by running the gates, and a
 * difference in either direction is a failure, not a note. See section 7: the
 * expected numbers are not an anchor any more either, they are the document.
 *
 * THIRD CLOSURE, and it is the one that makes the second one trustworthy. The
 * counters used to be read out of whatever the sibling gate binaries had
 * printed, by running them as subprocesses resolved through /proc/self/exe.
 * That made this gate a function of the state of its build directory: alone on
 * a cold directory it was a legitimate red, and -- the worse half -- on a warm
 * one it was green on the counters of a PREVIOUS run, because the runner never
 * rebuilds a gate it was not asked for. Both halves were measured, not
 * assumed; see the report. So the gates that can be measured are now
 * #included below and RUN HERE, in this process, and nothing in this file
 * opens a log or a pipe any more.
 *
 * FOURTH CLOSURE, and it is the one that makes the second and the third stop
 * being anchors. The COVERAGE numbers used to be five hand written
 * (checks, cases) pairs that a human re-anchored here every time a sibling
 * gate grew -- the shape of the defect the audit called residual 9: a lot
 * that touched one of the five had to edit a C constant to keep the suite
 * green. They are gone. The expectation is now the document, the measurement
 * is the gate, and the two are compared to each other, so a gate that grows
 * turns this gate red until the SPEC is corrected -- the only place that
 * correction belongs. The number of counters each gate must state is not
 * pinned either: the scan counts them, as a bijection between the sites
 * shaped like a counter and the counters it read, so a counter reworded out
 * of reach of the parser is a red instead of a silent loss.
 *
 * `diagnostics` is measured too -- residual 8 -- and the door to it is spelled
 * at its include below. `entry` is a member of NovaHostImage, so the rename
 * that gives a twin its own file-scope `entry` also renames the member unless
 * the header is read again through the same macro. It is, once, and the two
 * shims below are the whole price. No anchored-only path is left, so the
 * COVERAGE line no longer prints anchored_only: there is no anchor left to be
 * the only witness of anything.
 *
 * FIFTH CLOSURE: the file:line references of the document. The audit listed as
 * a design limit that this gate never looked at a line number, that the spec
 * changed length four times in wave 5 without one reference breaking, and that
 * `ntasm_parser.nova` -- a file that does not exist -- was still cited with a
 * correct line number. Section 8 measures both directions and says which of
 * them is allowed to be red.
 *
 * SIXTH CLOSURE, and the first one about the documents' SHAPE rather than their
 * claims. Everything above asks whether what a document says is true. Nothing
 * asked whether the document is a document: a row split across nine physical
 * lines, a row that lost its trailing delimiter, and two literal pipes inside a
 * quoted `grep` alternation were all found by eye, in a tree whose every gate
 * was green, because no check in the suite opens a table. Section 10 reads the
 * table geometry, the cell escaping and the anchor and link targets of BOTH
 * documents, and it brings the second document into the citation resolver,
 * which until now read spec/ntasm/ntasm.md and nothing else -- the 22 `file:line`
 * citations of docs/status/ntasm-completion.md had no instrument at all.
 *
 * The module list is read from the directory, never transcribed, so a module
 * that publishes a new code cannot hide behind a stale manifest. Paths are
 * relative to the repository root, as in every other harness of the suite. */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* The four sibling harnesses #included further down include these four headers
 * themselves. They are pulled in HERE, once, before any rename macro exists, so
 * that a rename can never rewrite a declaration of the Nova API: a rename that
 * leaked into nova.h would hand two harnesses two different names for one
 * function, and the failure would be a mystery in a header instead of a line
 * here. The runner compiles with -I compiler/c, so these resolve. */
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"

static unsigned checks, failures, cases;

/* The number of failures this run charged because the TREE MOVED rather than
 * because a check found something. Reported beside `failures` in the banner so
 * the two are separable; see the fence call site for why one number cannot
 * carry both. Zero on every clean run, and zero on every run whose red is a
 * real defect. */
static unsigned fence_moved;

#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)

/* THE BANNER, in one function, and the reason is that this line used to be
 * written out at three call sites -- the two early returns in main() and the
 * exit -- and a field added to one of them is a field two thirds of the runs
 * never print. A banner that reports a different set of numbers depending on
 * how the run ended is not a banner a reader can compare across runs, and the
 * comparability is the only reason the line exists.
 *
 * `fence_moved=%u` is the field this lot added, and it is what makes a red
 * adjudicable from the banner alone. `failures=N` says N things went wrong; it
 * does not say whether they are DEFECTS in the code or a TREE THAT MOVED under
 * the gate, and those two demand opposite responses from the reader. With the
 * field, `failures=1 fence_moved=1` is a void measurement whose evidence is on
 * stderr, and `failures=1 fence_moved=0` is a real red. Before it, a run
 * reported `failures=1` and the reader had to go and find out which, from a log
 * that named neither.
 *
 * The field is LAST so that a reader parsing the three established numbers from
 * the front of the line is unaffected by its presence. */
static void reg_banner(void) {
  printf("NTASM_NOVA_REGISTRY checks=%u failures=%u cases=%u fence_moved=%u\n",
         checks, failures, cases, fence_moved);
}

/* memmem is a GNU extension and the runner compiles with -std=c11, so the one
 * substring this file needs is spelled out. */
static int has_text(const char *t, size_t n, const char *p) {
  size_t l = strlen(p);
  if (l > n) return 0;
  for (size_t i = 0; i + l <= n; i++)
    if (memcmp(t + i, p, l) == 0) return 1;
  return 0;
}

static void bad(const char *what, int code) {
  checks++;
  failures++;
  fprintf(stderr, "FAIL %s code=%d\n", what, code);
}

/* The same, with a name the caller builds, so a failure names the gate and the
 * two numbers it is about instead of repeating one fixed sentence. */
static void failf(const char *fmt, ...) {
  char m[512];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(m, sizeof m, fmt, ap);
  va_end(ap);
  checks++;
  failures++;
  fprintf(stderr, "FAIL %s\n", m);
}

static void good(void) { checks++; }

static char *loadf(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long z = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) { free(b); fclose(f); return NULL; }
  fclose(f);
  b[z] = 0;
  *n = (size_t)z;
  return b;
}

#define BAND_LO 300
#define BAND_HI 399
#define STRUCT_LO 800
#define STRUCT_HI 899
/* The audit that opened this lot counted 44 modules; the directory holds more
 * today. A floor, not a pin: it exists so that a scan which enumerates nothing
 * fails loudly instead of agreeing with an equally empty spec parse. */
#define MODULE_FLOOR 44
#define CODE_MAX 1000
#define NUM_MAX 64

static unsigned char published[CODE_MAX];
static unsigned char emitted[CODE_MAX];
static unsigned char structural[CODE_MAX];

static int ranges_lo[NUM_MAX], ranges_hi[NUM_MAX];
static unsigned ranges_n;

static int ident_char(int c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_';
}

static int has_prefix(const char *t, size_t n, size_t i, const char *p) {
  size_t l = strlen(p);
  return i + l <= n && memcmp(t + i, p, l) == 0;
}

/* "fail" and "code" only count as an emission when they are the whole name, so
 * rt_free() or some_code= keep their own numbers out of the registry. */
static int at_boundary(const char *t, size_t i) {
  return i == 0 || !ident_char((unsigned char)t[i - 1]);
}

/* Exactly three digits, and a fourth would mean this is not a 3xx/8xx code. */
static int read3(const char *t, size_t n, size_t j) {
  if (j + 3 >= n) return 0;
  if (t[j] < '0' || t[j] > '9' || t[j + 1] < '0' || t[j + 1] > '9' ||
      t[j + 2] < '0' || t[j + 2] > '9')
    return 0;
  if (ident_char((unsigned char)t[j + 3])) return 0;
  return (t[j] - '0') * 100 + (t[j + 1] - '0') * 10 + (t[j + 2] - '0');
}

static void record(unsigned code) {
  if (code >= 300 && code <= BAND_HI) emitted[code] = 1;
  else if (code >= STRUCT_LO && code <= STRUCT_HI) structural[code] = 1;
}

static void scan_emissions(const char *t, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (at_boundary(t, i)) {
      if (has_prefix(t, n, i, "code=")) {
        size_t j = i + 5;
        while (j < n && (t[j] == ' ' || t[j] == '\t')) j++;
        int v = read3(t, n, j);
        if (v) record((unsigned)v);
      } else if (has_prefix(t, n, i, "fail(")) {
        size_t j = i + 5;
        while (j < n && ident_char((unsigned char)t[j])) j++;
        if (j < n && t[j] == ',') {
          j++;
          while (j < n && (t[j] == ' ' || t[j] == '\t')) j++;
          int v = read3(t, n, j);
          if (v) record((unsigned)v);
        }
      } else if (has_prefix(t, n, i, "return")) {
        size_t j = i + 6, k = j;
        while (j < n && (t[j] == ' ' || t[j] == '\t')) j++;
        if (j > k) {
          int v = read3(t, n, j);
          if (v) record((unsigned)v);
        }
      }
    }
  }
}

/* The backticked decimal numbers of one cell, with a `a`-`b` pair expanded into
 * every integer it spans. A pair is a range only when the text between the two
 * numbers is nothing but a dash, so "`386`, plus `201` and `203`" stays three
 * separate values while "`370`-`381`" is a range. `3xx` is not a number and is
 * skipped by the same rule that skips an unterminated span. */
static unsigned cell_numbers(const char *c, const char *e, int *out, unsigned max) {
  int val[NUM_MAX], beg[NUM_MAX], fin[NUM_MAX];
  unsigned n = 0;
  for (const char *p = c; p < e && n < NUM_MAX;) {
    if (*p != '`') { p++; continue; }
    const char *q = p + 1;
    int v = 0, d = 0;
    while (q < e && *q >= '0' && *q <= '9' && d < 5) { v = v * 10 + (*q - '0'); q++; d++; }
    if (d >= 3 && q < e && *q == '`') {
      val[n] = v; beg[n] = (int)(p - c); fin[n] = (int)(q + 1 - c); n++; p = q + 1;
    } else {
      p = q;
    }
  }
  unsigned k = 0;
  for (unsigned i = 0; i + 1 < n; i++) {
    int dash = 0;
    int only = 1;
    for (int g = fin[i]; g < beg[i + 1]; g++) {
      char ch = c[g];
      if (ch == ' ' || ch == '\t') continue;
      if (ch == '-' || (unsigned char)ch == 0xe2 || (unsigned char)ch == 0x80 ||
          (unsigned char)ch == 0x93 || (unsigned char)ch == 0x94 ||
          (unsigned char)ch == 0x96) { dash = 1; continue; }
      only = 0;
      break;
    }
    if (dash && only && val[i + 1] >= val[i]) {
      if (ranges_n < NUM_MAX) {
        ranges_lo[ranges_n] = val[i];
        ranges_hi[ranges_n] = val[i + 1];
        ranges_n++;
      }
      if (k + (unsigned)(val[i + 1] - val[i]) + 1 > max) return k;
      for (int v = val[i]; v <= val[i + 1]; v++) out[k++] = v;
    } else if (k < max) {
      out[k++] = val[i];
    }
  }
  if (n && k < max) out[k++] = val[n - 1];
  /* A cell that ends a range and restates its last value -- "`370`-`381` then
   * `386`" yields 381 once from the range and once on its own -- must not
   * report the same code twice. */
  unsigned w = 0;
  for (unsigned i = 0; i < k; i++)
    if (!w || out[w - 1] != out[i]) out[w++] = out[i];
  return w;
}

static const char *next_line(const char *p, const char *e, const char **b, const char **l) {
  if (p >= e) return 0;
  const char *nl = memchr(p, '\n', (size_t)(e - p));
  *b = p;
  *l = nl ? nl : e;
  return nl ? nl + 1 : e;
}

static const char *skip_ws(const char *b, const char *e) {
  while (b < e && (*b == ' ' || *b == '\t' || *b == '\r')) b++;
  return b;
}

/* THE SECTION, NOT THE FILE, and a function rather than a second copy of the
 * loop that used to do it. The 17.6 reader below ran this walk inline; the
 * 17.9 register reader needs the same walk over the same text, and two copies
 * of a line predicate are two chances to disagree about what a line is -- the
 * file's own stated reason for reading a document once. So the walk is here
 * once and both sections go through it.
 *
 * `num` is the section number as the heading carries it, "17.6", "17.9". The
 * body runs from the heading line to the NEXT `###` heading, or to the end of
 * the text when this section is the last one, which is the case 17.9 is today:
 * a section that happened to gain a successor would simply stop there. */
static int doc_section(const char *t, const char *end, const char *num,
                       const char **body, const char **stop) {
  const char *p = t, *b, *l;
  size_t nl = strlen(num);
  *body = 0;
  *stop = end;
  while ((p = next_line(p, end, &b, &l))) {
    const char *k = skip_ws(b, l);
    int head = (size_t)(l - k) >= 4 && !memcmp(k, "### ", 4);
    if (!*body) {
      if (head && (size_t)(l - k) >= 4 + nl && !memcmp(k + 4, num, nl)) *body = b;
    } else if (head) {
      *stop = b;
      return 1;
    }
  }
  return *body != 0;
}

/* ================================================================== the
 * coverage side of the same idea: the numbers spec/ntasm/ntasm.md attaches to a few
 * gates, and the measurement of what those gates really run. */

#define CLAIM_MAX 64
/* 128, and it was 64, and 64 was never enough for this tree.
 *
 * The longest citable path in the repository is
 *   tests/c/nova/tests_ntasm_x64_lower_nxo_function_bodies.c
 * at 72 characters. A document citing it overflowed -- and the diagnostic
 * said "the documents carry more file:line references than this harness can
 * hold, which is 512", which is a different fault with a different fix, so a
 * reader doing the arithmetic (241 references, a 512 cap) correctly concluded
 * the counter was wrong. The counter was right. One name was too long and the
 * message named the array instead.
 *
 * A round number here is a nominal constant, not a capacity: it is the same
 * shape as KNOWN_NOVA_MODULES 57 in the abi harness, which was correct about
 * the directory it watched and wrong the moment a module landed. Sizing it
 * against the tree is what makes it a bound, and the 56 characters of headroom
 * are for paths that have not been written yet.
 *
 * 512 x 128 is 64 KiB of BSS, which is not a cost worth trading a diagnostic
 * for. */
#define NAME_MAX 128

/* NO NUMBER IS WRITTEN DOWN HERE, and that is the whole of residual 9. This
 * table used to carry, per gate, a hand transcription of its banner
 * (checks, cases) plus a hand transcription of how many counters the document
 * states for it. Both were anchors: a lot that touched a gate had to edit a C
 * constant in this file to keep the suite green, which is a claim about this
 * file's maintenance and not about the tree at all.
 *
 * What is left is the set of gates whose counters this gate is responsible
 * for, and nothing else. The expectation is the document; the measurement is
 * the twin run below, in this process; the verdict is their difference. So a
 * gate that grows a check now makes the DOCUMENT wrong, and the repair is to
 * correct the document -- which is the only place the repair belongs -- rather
 * than to re-anchor a constant. The number of counters per gate is not pinned
 * either: `claim_sites` below counts the sites shaped like a counter and the
 * bijection between them and the counters read is what is checked.
 *
 * A floor survives, and only a floor: every gate named here must still be
 * described by at least one counter in the document, so the section cannot be
 * quietly emptied. It is a floor for the reason MODULE_FLOOR is one: a
 * constant that says "at least this much" cannot be wrong when the tree grows,
 * and a constant that says "exactly this much" is a maintenance trap. */
typedef struct {
  const char *gate;
} Cover;

static const Cover COVER[] = {
  {"stub_table"},
  {"locals"},
  {"bindings"},
  {"call_contracts"},
  {"diagnostics"},
  {"splice"},
  {"reg_width_binding"},
};
#define COVER_N ((unsigned)(sizeof COVER / sizeof *COVER))

static char claim_gate[CLAIM_MAX][NAME_MAX];
static unsigned claim_a[CLAIM_MAX], claim_b[CLAIM_MAX], claim_cases[CLAIM_MAX];
static unsigned claims_n;
/* Sites that have the shape of a counter -- a backquoted gate name followed by
 * blanks, an optional parenthesis and a number whose next non-blank character
 * is one of "/", "," or ")" -- whether or not the rest of the counter parses.
 * The scan counts them; section 7 checks that it read exactly as many counters
 * as there are such sites, so a counter reworded into a shape this parser
 * cannot finish reading is a red and not a silent loss. That replaces the
 * per-gate `claims` pin without reintroducing a hand written number. */
static unsigned claim_sites;
static int claims_overflow;

static int read_uint(const char *t, size_t n, size_t *i, unsigned *out) {
  unsigned v = 0, d = 0;
  while (*i < n && t[*i] >= '0' && t[*i] <= '9' && d < 9u) {
    v = v * 10u + (unsigned)(t[*i] - '0');
    (*i)++;
    d++;
  }
  if (!d) return 0;
  *out = v;
  return 1;
}

/* Spaces, tabs and the two French fixed spaces, because a coverage counter
 * written with a narrow no-break space must still be read rather than silently
 * dropped. A newline is NOT a blank here: a claim that wraps onto the next
 * line stops being a claim, and the anchored count of claims turns that into a
 * red rather than a loss. */
static void skip_blanks(const char *t, size_t n, size_t *i) {
  for (;;) {
    if (*i < n && (t[*i] == ' ' || t[*i] == '\t')) { (*i)++; continue; }
    if (*i + 1 < n && (unsigned char)t[*i] == 0xc2 && (unsigned char)t[*i + 1] == 0xa0) {
      *i += 2;
      continue;
    }
    if (*i + 2 < n && (unsigned char)t[*i] == 0xe2 && (unsigned char)t[*i + 1] == 0x80 &&
        ((unsigned char)t[*i + 2] == 0xaf || (unsigned char)t[*i + 2] == 0x9f)) {
      *i += 3;
      continue;
    }
    return;
  }
}

/* A gate of the suite is a harness file that exists, read from the tree so a
 * gate cannot be renamed into a claim that matches nothing. */
static int is_gate(const char *name) {
  char path[512];
  struct stat st;
  if (snprintf(path, sizeof path, "compiler/c/nova/tests_ntasm_%s.c", name) >=
      (int)sizeof path)
    return 0;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Every "`gate` A/B, K cas" and "`gate` (A/B, K cas)" of the document, over the
 * whole file and not only over 17.x: a coverage counter is a coverage counter
 * wherever it is written, and 11 states one. The word "cas" is what makes the
 * shape a coverage claim and not a table of ratios, and it is required, so a
 * ratio written in prose is not mistaken for one.
 *
 * `claim_sites` is counted on the way through and is what makes this a
 * bijection rather than a search. A site counts as counter-shaped when the
 * name is followed by a number whose next non-blank character is "/", "," or
 * ")" -- the punctuation of an A/B, K cas counter and nothing else. The test
 * was measured on the document before it was written: of the ten sites that
 * carry a number after a backquoted name, nine are counters and the tenth is
 * "`rbp` (328 raison 5)", which a prose mention of a register and a reason
 * number also spells, and which the punctuation rule rejects. What the rule
 * deliberately does NOT catch is a counter rewritten with no punctuation left
 * at all, e.g. "`abi` 222 checks"; that is a change of shape the document
 * makes deliberately, and the price of catching it was a false red on "`rbp`
 * (328". It is named here rather than left for a reader to discover. */
static void collect_coverage(const char *t, size_t n) {
  for (size_t i = 0; i < n; i++) {
    size_t at, j, k, name_len;
    unsigned a, b, c;
    if (t[i] != '`') continue;
    j = i + 1;
    if (j >= n || !((t[j] >= 'a' && t[j] <= 'z') || t[j] == '_')) continue;
    at = j;
    while (j < n && ident_char((unsigned char)t[j])) j++;
    name_len = j - at;
    if (name_len == 0 || name_len >= NAME_MAX) continue;
    k = j;
    /* the name is backquoted, so the closing backtick comes before the number */
    if (k >= n || t[k] != '`') continue;
    k++;
    skip_blanks(t, n, &k);
    if (k < n && t[k] == '(') { k++; skip_blanks(t, n, &k); }
    if (!read_uint(t, n, &k, &a)) continue;
    { size_t p = k; skip_blanks(t, n, &p);
      if (p < n && (t[p] == '/' || t[p] == ',' || t[p] == ')')) claim_sites++; }
    if (k >= n || t[k] != '/') continue;
    k++;
    if (!read_uint(t, n, &k, &b)) continue;
    skip_blanks(t, n, &k);
    if (k >= n || t[k] != ',') continue;
    k++;
    skip_blanks(t, n, &k);
    if (!read_uint(t, n, &k, &c)) continue;
    skip_blanks(t, n, &k);
    if (k < n && t[k] == ')') { k++; skip_blanks(t, n, &k); }
    if (k + 3 > n || memcmp(t + k, "cas", 3) != 0) continue;
    if (k + 3 < n && ident_char((unsigned char)t[k + 3])) continue;
    if (claims_n >= CLAIM_MAX) { claims_overflow = 1; return; }
    memcpy(claim_gate[claims_n], t + at, name_len);
    claim_gate[claims_n][name_len] = 0;
    claim_a[claims_n] = a;
    claim_b[claims_n] = b;
    claim_cases[claims_n] = c;
    claims_n++;
  }
}

/* ================================================================== the five
 * sibling gates, RUN HERE.
 *
 * Each of these files is a whole harness with its own main(). They are
 * #included rather than spawned so that the counters compared in section 7 are
 * produced by the same code, in the same process, from the same compilation as
 * the comparison itself -- not read out of a build directory that a previous
 * run may have populated. The cost of that decision is a rename per file, and
 * the renames are exactly the file-scope identifiers the harnesses share:
 * their three counters, their guard word, their Run struct, and the four helper
 * names locals/bindings/call_contracts have in common. `checks`, `failures` and
 * `cases` are renamed rather than shared on purpose: sharing them would make a
 * delta the only way to read a counter, and a delta cannot say which gate
 * produced it.
 *
 * `entry` is the one name a plain rename cannot have, and it is why the first
 * four stops there. `entry` is a member of NovaHostImage, so a macro cannot
 * tell `image->entry(&context, args, 4)` from a call to a file-scope
 * `entry(...)`: an object-like rename breaks the member, and a function-like
 * one rewrites the parameter list of the definition into a call expression.
 * stub_table and diagnostics each declare a file-scope `entry`, so at most one
 * of them can be renamed and the other could not be included at all. The
 * fourth version of this comment accepted that, left diagnostics anchored by
 * hand, and counted the reduction in the COVERAGE line.
 *
 * The way out is to rename the member too, by reading the header again through
 * the same macro, and that is what the fifth block below does. Nothing is
 * transcribed: the renamed image type is produced by run_host.h itself, so it
 * cannot drift from the header, and the two static assertions state the one
 * property the two shims rely on -- that the renamed member sits at the offset
 * the original one does. The rename is applied to the header and to the
 * harness inside one lexical region, so the member, the file-scope function
 * and the single member access in diagnostics.c all move together, and the
 * four twins above keep the original name and the original member. */

#undef CHECK
#define main h1_locals_main
#define checks h1_locals_checks
#define failures h1_locals_failures
#define cases h1_locals_cases
#define guard h1_locals_guard
#define Run h1_locals_Run
#define load h1_locals_load
#define ok h1_locals_ok
#define err h1_locals_err
#define err_at h1_locals_err_at
#define run h1_locals_run
#include "tests_ntasm_locals.c"
#undef run
#undef err_at
#undef err
#undef ok
#undef load
#undef Run
#undef guard
#undef cases
#undef failures
#undef checks
#undef main

#undef CHECK
#define main h1_bindings_main
#define checks h1_bindings_checks
#define failures h1_bindings_failures
#define cases h1_bindings_cases
#define guard h1_bindings_guard
#define Run h1_bindings_Run
#define load h1_bindings_load
#define ok h1_bindings_ok
#define err h1_bindings_err
#define err_at h1_bindings_err_at
#define run h1_bindings_run
#include "tests_ntasm_bindings.c"
#undef run
#undef err_at
#undef err
#undef ok
#undef load
#undef Run
#undef guard
#undef cases
#undef failures
#undef checks
#undef main

#undef CHECK
#define main h1_stub_table_main
#define checks h1_stub_table_checks
#define failures h1_stub_table_failures
#define cases h1_stub_table_cases
#define guard h1_stub_table_guard
#define Run h1_stub_table_Run
#define load h1_stub_table_load
#define ok h1_stub_table_ok
#define err h1_stub_table_err
#define err_at h1_stub_table_err_at
#define run h1_stub_table_run
#include "tests_ntasm_stub_table.c"
#undef run
#undef err_at
#undef err
#undef ok
#undef load
#undef Run
#undef guard
#undef cases
#undef failures
#undef checks
#undef main

#undef CHECK
#define main h1_call_contracts_main
#define checks h1_call_contracts_checks
#define failures h1_call_contracts_failures
#define cases h1_call_contracts_cases
#define guard h1_call_contracts_guard
#define Run h1_call_contracts_Run
#define load h1_call_contracts_load
#define ok h1_call_contracts_ok
#define err h1_call_contracts_err
#define err_at h1_call_contracts_err_at
#define run h1_call_contracts_run
#include "tests_ntasm_call_contracts.c"
#undef run
#undef err_at
#undef err
#undef ok
#undef load
#undef Run
#undef guard
#undef cases
#undef failures
#undef checks
#undef main

/* ---- and the fifth: `diagnostics`, whose twin needed a different door.
 *
 * Step one re-reads run_host.h through the rename. The guard is dropped first,
 * so the second reading is not a no-op, and both occurrences of the image type
 * and both of its two functions are renamed with it, which is what keeps the
 * re-read from declaring a second, incompatible `nova_host_map`. The result is
 * a SECOND name for the image type, whose member is spelled the renamed way and
 * whose layout is the layout the header wrote, because the only difference is
 * the spelling of one member. The canonical name is untouched: the re-read
 * binds h1_diag_NovaHostImage and never rebinds NovaHostImage, so the four
 * twins above still see the header exactly as it is. */
#undef NG_NOVA_RUN_HOST_H
#define entry h1_diag_entry
#define NovaHostImage h1_diag_NovaHostImage
#define nova_host_map h1_diag_nova_host_map
#define nova_host_unmap h1_diag_nova_host_unmap
#include "../../../compiler/c/nova/runtime/run_host.h"
#undef nova_host_unmap
#undef nova_host_map
#undef NovaHostImage
#undef entry

/* Step two, the price, and it is two functions and two assertions. The
 * re-read declared h1_diag_nova_host_map/unmap against the renamed type, and
 * they are defined in run_host.c against the original one; the two types are
 * the same object at the same offsets, which is what the assertions say rather
 * than what a comment says. Without them a future edit to run_host.h that moved
 * a field would turn this cast into a silent misread, and the gate would go on
 * measuring a twin that never ran. */
_Static_assert(sizeof(h1_diag_NovaHostImage) == sizeof(NovaHostImage),
               "the renamed image must be the size the header wrote");
_Static_assert(offsetof(h1_diag_NovaHostImage, h1_diag_entry) == offsetof(NovaHostImage, entry),
               "the renamed entry member must sit where the original entry sits");
int h1_diag_nova_host_map(const NtArtifact *artifact, h1_diag_NovaHostImage *image) {
  return nova_host_map(artifact, (NovaHostImage *)(void *)image);
}
void h1_diag_nova_host_unmap(h1_diag_NovaHostImage *image) {
  nova_host_unmap((NovaHostImage *)(void *)image);
}

/* Step three, the twin itself. The four renames the other twins get, plus the
 * three that only this one needs: `entry` for its file-scope accessor,
 * `NovaHostImage` for the type the re-read above produced, and the two host
 * functions for the shims just defined. The macros the harness leaves behind
 * are dropped by name at the end -- CAPACITY, HEADER, HEAD and the rest -- so
 * that nothing it defines can reach the code below, where HEADER and HEAD are
 * the kind of name a later edit would collide with silently. */
#undef CHECK
#define main h1_diag_main
#define checks h1_diag_checks
#define failures h1_diag_failures
#define cases h1_diag_cases
#define guard h1_diag_guard
#define Run h1_diag_Run
#define entry h1_diag_entry
#define NovaHostImage h1_diag_NovaHostImage
#define nova_host_map h1_diag_nova_host_map
#define nova_host_unmap h1_diag_nova_host_unmap
#include "tests_ntasm_diagnostics.c"
#undef nova_host_unmap
#undef nova_host_map
#undef NovaHostImage
#undef entry
#undef Run
#undef guard
#undef cases
#undef failures
#undef checks
#undef main
#undef MAX_ROWS
#undef PROBE_CAPACITY
#undef SLICE_HEADER
#undef HEADER
#undef MIN_WORDS
#undef CAPACITY
#undef CMD_SLICE
#undef CMD_REGION
#undef CMD_RESYNC
#undef CMD_COLLECT_REVERSE
#undef CMD_COLLECT
#undef PROBE_HEAD
#undef HEAD

/* ---- and the sixth: `splice`, the gate that measures the spliced tree the
 * macro expansion builds. It needs no different door: it reads no state this
 * file owns and compiles its own two images, so the plain rename is enough.
 * Every file scope NAME it declares is renamed, not only the counters, because
 * six harnesses share one translation unit and two `static`s of the same name
 * are one definition, not two. Its MACROS are a different matter: it defines
 * them itself, so pre-defining one to a renamed form is a redefinition and
 * `-Werror` stops the build. Those are `#undef`ed after the include instead,
 * which is what the fifth twin above does with its own. */
#undef CHECK
#define main h1_splice_main
#define checks h1_splice_checks
#define failures h1_splice_failures
#define cases h1_splice_cases
#define load h1_splice_load
#define Shape h1_splice_Shape
#define Pipe h1_splice_Pipe
#define shape_run h1_splice_shape_run
#define pipe_run h1_splice_pipe_run
#define PATHS h1_splice_PATHS
#define Fx h1_splice_Fx
#define FX h1_splice_FX
#include "tests_ntasm_splice.c"
#undef BUDGET_BODY
#undef MF
#undef MT
#undef MH
#undef FX_N
#undef PATHS_N
#undef CHECK
#undef FX
#undef Fx
#undef PATHS
#undef pipe_run
#undef shape_run
#undef Pipe
#undef Shape
#undef load
#undef cases
#undef failures
#undef checks
#undef main

/* ---- and the seventh: `reg_width_binding`, the gate the document already
 * carries a counter for and this file had no twin of, which is the whole
 * reason that counter was refused on every run: a row of COVER is a promise of
 * a measurement, and a promise with no triple behind it is a transcription.
 *
 * It needs no different door, and the reason is worth stating because the
 * fifth twin needed a great deal. That one declared a file-scope `entry`, which
 * is a member of NovaHostImage, so it had to re-read the header through a
 * macro to rename the member too. This one reads NO state this file owns: it
 * calls the product's own `nt_compile_many` on source it writes itself, the
 * same shape as `splice`, which compiles its own two images. So the plain
 * rename is enough and the block below is a copy of the splice block with a
 * different name set -- which is the point: the door is chosen from what the
 * harness DECLARES, read here, and not from a list kept in this file's head.
 *
 * Every file-scope NAME it declares is renamed, for the reason the splice block
 * states: seven harnesses share one translation unit and two `static`s of one
 * name are one definition, not two. That covers the two counters and the three
 * functions as well as the two structs and their two tables. Its MACROS are the
 * other matter, as the sixth block says: it defines WIDTH_N, FAMILY_N and its
 * own CHECK itself, so pre-defining one to a renamed form is a redefinition and
 * -Werror stops the build. Those three are `#undef`ed after the include instead.
 *
 * It is NOT volatile, and that is measured rather than assumed: the harness's
 * 256 members are the cross product of 8 declared widths and 16 register
 * families, all generated from a predicate, so the case count is a function of
 * the language's width list and not of what a run happens to touch. `bool_fold`
 * and `splice` carry volatile counters and are compared with a tolerance; this
 * one is compared exactly, because there is nothing here that moves. */
#undef CHECK
#define main h1_reg_width_binding_main
#define checks h1_reg_width_binding_checks
#define failures h1_reg_width_binding_failures
#define cases h1_reg_width_binding_cases
#define Width h1_reg_width_binding_Width
#define Family h1_reg_width_binding_Family
#define WIDTHS h1_reg_width_binding_WIDTHS
#define FAMILIES h1_reg_width_binding_FAMILIES
#define register_at h1_reg_width_binding_register_at
#define binding_verdict h1_reg_width_binding_binding_verdict
#define call_verdict h1_reg_width_binding_call_verdict
#include "tests_ntasm_reg_width_binding.c"
#undef WIDTH_N
#undef FAMILY_N
#undef CHECK
#undef call_verdict
#undef binding_verdict
#undef register_at
#undef FAMILIES
#undef WIDTHS
#undef Family
#undef Width
#undef cases
#undef failures
#undef checks
#undef main

/* The last include left its own CHECK behind; the rest of this file needs the
 * one it was written with, so it is put back here rather than relied upon. */
#undef CHECK
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)

/* The triple a twin produced, read out of its own renamed counters after its
 * main has run. 0 is no longer a mode the caller can fall back from: every row
 * of COVER is measured, so a row with no twin is a row whose counters nothing
 * in this turn can confirm, and section 7 fails on it rather than comparing it
 * with a number it made up. */
static int measured(const Cover *cv, unsigned *checks, unsigned *fail, unsigned *cases) {
  if (!strcmp(cv->gate, "stub_table")) {
    *checks = h1_stub_table_checks; *fail = h1_stub_table_failures; *cases = h1_stub_table_cases;
    return 1;
  }
  if (!strcmp(cv->gate, "locals")) {
    *checks = h1_locals_checks; *fail = h1_locals_failures; *cases = h1_locals_cases;
    return 1;
  }
  if (!strcmp(cv->gate, "bindings")) {
    *checks = h1_bindings_checks; *fail = h1_bindings_failures; *cases = h1_bindings_cases;
    return 1;
  }
  if (!strcmp(cv->gate, "call_contracts")) {
    *checks = h1_call_contracts_checks; *fail = h1_call_contracts_failures;
    *cases = h1_call_contracts_cases;
    return 1;
  }
  if (!strcmp(cv->gate, "diagnostics")) {
    *checks = h1_diag_checks; *fail = h1_diag_failures; *cases = h1_diag_cases;
    return 1;
  }
  if (!strcmp(cv->gate, "splice")) {
    *checks = h1_splice_checks; *fail = h1_splice_failures; *cases = h1_splice_cases;
    return 1;
  }
  if (!strcmp(cv->gate, "reg_width_binding")) {
    *checks = h1_reg_width_binding_checks; *fail = h1_reg_width_binding_failures;
    *cases = h1_reg_width_binding_cases;
    return 1;
  }
  return 0;
}

/* The banner a gate is supposed to print, spelled from its own name and looked
 * for in its own harness source, read from the tree like everything else here.
 * It is what ties a measurement to a text: a gate renamed, its banner retitled
 * or its harness deleted turns this red, which is the part of the old coupling
 * that an anchor used to provide and that a measurement no longer does. */
static int prints_its_own_banner(const Cover *cv) {
  char path[512], gate[NAME_MAX], want[160];
  size_t n = 0, i;
  char *src;
  int ok = 0;
  if (snprintf(path, sizeof path, "compiler/c/nova/tests_ntasm_%s.c", cv->gate) >=
      (int)sizeof path)
    return 0;
  if (snprintf(gate, sizeof gate, "%s", cv->gate) >= (int)sizeof gate) return 0;
  /* Only the gate name is uppercased: "checks=" is spelled lowercase in every
   * harness and uppercasing it here would make this check unsatisfiable. */
  for (i = 0; gate[i]; i++)
    if (gate[i] >= 'a' && gate[i] <= 'z') gate[i] = (char)(gate[i] - 'a' + 'A');
  if (snprintf(want, sizeof want, "NTASM_NOVA_%s checks=", gate) >= (int)sizeof want) return 0;
  src = loadf(path, &n);
  if (!src) return 0;
  ok = has_text(src, n, want) && strstr(src, "failures=") && strstr(src, "cases=");
  free(src);
  return ok;
}

/* ================================================================== section 8,
 * in main(): the file:line references of the document.
 *
 * The audit listed as a design limit that this gate never opened a line number
 * of the spec, and that spec/ntasm/ntasm.md changed length four times during wave 5
 * -- every reference in it was written by content, and not one of them could
 * break. It also carried the sharper half: `ntasm_parser.nova` was cited with
 * a correct line number and does not exist, because the file is called
 * `parser.nova`. Both halves are measured here.
 *
 * A reference is `name.ext:line` or `name.ext:lo-hi`, anywhere in the document,
 * with a name that ends at the extension: `stub_table.check` is not a
 * reference to a file called `stub_table.c`, and reading it as one is how a
 * scan of this shape manufactures false reds. The file part resolves against
 * the tree, the line part against the resolved file.
 *
 * WHAT IS RED AND WHAT IS ONLY COUNTED, decided rather than left open.
 *
 * A file that cannot be resolved is a HARD FAILURE. The argument is that this
 * verdict is not a measurement race. It is not read out of a cache, a log or a
 * build directory; the search below is a bounded walk of a DECLARED set of
 * roots, and the failure message prints the roots it searched, so "missing" is
 * a statement about a stated scope and never a guess about one. And nothing a
 * concurrent edit can do makes `ntasm_parser.nova` a file: a rename in
 * progress is wrong at both ends until it is finished, which is a minute of
 * somebody's work, not a verdict this gate should soften. The alternative --
 * count it, print it, stay green -- is the fail-open this file exists to
 * refuse, and it is the fail-open that let that one reference survive five
 * waves and a report. The tolerance for a document being written under this
 * gate is in main(), not here: the verdict is re-judged on a fresher copy of
 * the document, and an incomplete search downgrades absence to a count.
 *
 * A line out of bounds is MEASURED AND COUNTED, never a failure, and that is
 * not a softer version of the same judgement: the two halves have different
 * stability. A file's existence is fixed for the whole wave. A line number is
 * a position in a file that the other lots of the same wave are moving. It
 * was measured rather than assumed: of the references that resolve, seven end
 * within five lines of the last line of the file they name -- `targets.nova:5`
 * in a five-line file, `feature_requirements.nova:15` in a fifteen-line one,
 * `diagnostics.nova:621-651` ending exactly on line 651 -- and one of those
 * files belongs to a lot in flight during this very wave. A one-line deletion
 * in a sibling's file would turn a hard failure here, and the red would be
 * about a moving target rather than about the document, which is precisely the
 * false red this wave exists to avoid. So the count is printed, every offender
 * is named on stderr, and the number is in the banner, where it cannot rot
 * unnoticed: the check measures on every run and is allowed to be wrong about
 * freshness, never about the file. */

#define REF_MAX 512
#define TGT_MAX 128
#define REF_PATH 512
#define REF_MATCH 4
/* The two documents whose citations share one resolver: index 0 is
 * spec/ntasm/ntasm.md, index 1 is docs/ntasm-completion.md. Named, not a wildcard,
 * so that adding a third document is an edit that says which one it is. */
#define REF_DOCS 2

/* The scope of the search, declared rather than guessed, and the recursion flag
 * is load-bearing rather than decoration. The repository root is searched
 * NON-recursively: its own files are what a bare `MEM.md:12` means, and
 * descending from it would walk everything at once -- out/ alone holds 103085
 * files, and a walk of the whole tree was measured at 15s of CPU and 2m48s of
 * wall clock on this mount, which is how the first version of this check
 * spent its whole directory budget inside out/ntasm and resolved nothing.
 *
 * The recursive roots are the seven places the project keeps what a reference
 * can point at: the toolchain, the quarantined C oracle and its harnesses, the
 * spec, the documents, the examples, the OS sources, and the bootstrap
 * artefacts under out/ -- the last one because the document cites a driver.c
 * that exists only there, and narrow for that reason alone: out/ntasm and
 * out/b1 hold 90500 files between them and are not searched. What is left is
 * about 16000 files. A scope nobody can state is not a search; the banner
 * prints roots= so the scope is never implicit.
 *
 * The `artefact` flag is there because of a measurement, not a guess. Dropping
 * `toolchain` from this list does NOT make the document's .nova references
 * unresolvable: every one of them also answers inside out/c-bootstrap, in a
 * dated build snapshot, and a name that resolves against a snapshot months old
 * would let a deleted source pass on its own copy. So a root is either a place
 * sources live or a place build output lives, the flag says which, and a
 * reference whose ONLY matches are build output is counted and named as
 * artefact-only rather than being allowed to read as a verified source. That
 * counter is what makes the scope falsifiable from the outside: shrink the
 * scope and the banner says so instead of the log staying quietly green. */
typedef struct {
  const char *path;
  int recurse;
  int artefact;
} RefRoot;

static const RefRoot REF_ROOTS[] = {
  {"", 0, 0}, {"toolchain", 1, 0}, {"bootstrap", 1, 0}, {"spec", 1, 0},
  {"docs", 1, 0}, {"examples", 1, 0}, {"os", 1, 0}, {"out/c-bootstrap", 1, 1},
  {"scripts", 1, 0}, {"tools", 1, 0},
};
#define REF_ROOTS_N ((unsigned)(sizeof REF_ROOTS / sizeof *REF_ROOTS))

/* Depth and size budgets, so a tree that grows without bound costs a declared
 * amount of time and then says so. On truncation the walk is INCOMPLETE, and an
 * unresolved reference is then counted rather than failed, because a search
 * that stopped early cannot support a "this file does not exist" verdict. */
#define REF_MAX_DEPTH 24
#define REF_MAX_DIRS 20000
#define REF_MAX_FILES 160000

static char ref_target[REF_MAX][NAME_MAX];
static unsigned ref_lo[REF_MAX], ref_hi[REF_MAX], ref_line[REF_MAX];
static unsigned refs_n, refs_overflow, refs_over_name;

/* Distinct file parts, each with the references that name it. */
static char tgt_name[TGT_MAX][NAME_MAX];
static unsigned tgt_nrefs[TGT_MAX];
static unsigned tgts_n, tgts_overflow;
static char tgt_match[TGT_MAX][REF_MATCH][REF_PATH];
static unsigned tgt_nmatch[TGT_MAX], tgt_truncated[TGT_MAX], tgt_pick[TGT_MAX];
static unsigned long tgt_lines[TGT_MAX][REF_MATCH];
static int tgt_match_artefact[TGT_MAX][REF_MATCH];

static unsigned ref_dirs, ref_files;
static int ref_truncated;

static int target_of(const char *name, size_t len) {
  for (unsigned g = 0; g < tgts_n; g++)
    if (strlen(tgt_name[g]) == len && !memcmp(tgt_name[g], name, len)) return (int)g;
  return -1;
}

/* How deep a match sits, which is what separates a source file from a dated
 * copy of it under out/c-bootstrap. */
static unsigned tgt_depth(const char *path) {
  unsigned d = 1;
  for (const char *p = path; *p; p++) if (*p == '/') d++;
  return d;
}
/* All five definitions below sit at the FOOT of this file, below every cited line. */
static int tgt_ambiguous[TGT_MAX];
static int rank_cmp(int art_a, const char *pa, int art_b, const char *pb);
static void tgt_add(unsigned g, const char *path, int artefact);
static void ref_report_ambiguous(unsigned g);
static void ref_report_unseparated(unsigned q, const char *n, unsigned lo, unsigned hi, unsigned long hl);
/* Does the tree path `path` end with the reference name `t`? A reference is
 * written bare (`control_flow.nova`) or with the tail of its path
 * (`tests/control-flow-entry.nova`), and both spellings must land on the same
 * file, so a suffix match is the rule rather than a list of guessed roots. */
static int ends_with_name(const char *path, const char *t) {
  size_t lp = strlen(path), lt = strlen(t);
  if (lt == 0 || lt > lp) return 0;
  if (memcmp(path + lp - lt, t, lt) != 0) return 0;
  return lp == lt || path[lp - lt - 1] == '/';
}

static int name_char(int c) { return ident_char(c) || c == '.' || c == '/' || c == '-'; }

/* Set for the duration of one root walk, so that a match remembers whether it
 * came from a place sources live or from a place build output lives. */
static int ref_in_artefact;

static void ref_walk(const char *rel, int depth, int recurse) {
  char abs[REF_PATH];
  DIR *d;
  struct dirent *de;
  int descend = recurse && depth < REF_MAX_DEPTH;
  if (ref_truncated) return;
  snprintf(abs, sizeof abs, "%s", *rel ? rel : ".");
  d = opendir(abs);
  if (!d) return;
  if (++ref_dirs > REF_MAX_DIRS) { ref_truncated = 1; closedir(d); return; }
  while ((de = readdir(d)) != 0) {
    const char *nm = de->d_name;
    char sub[REF_PATH];
    struct stat st;
    DIR *probe;
    if (!strcmp(nm, ".") || !strcmp(nm, "..") || !strcmp(nm, ".git")) continue;
    if (snprintf(sub, sizeof sub, "%s%s%s", rel, *rel ? "/" : "", nm) >= (int)sizeof sub) {
      ref_truncated = 1;
      break;
    }
    /* opendir is the test: it answers "is this a directory I can read" and costs
     * one syscall, where stat plus opendir would cost two on a mount where the
     * whole walk is measured in minutes. A directory we cannot open is a leaf
     * here, which is a limit of the scope and not a claim about what is under
     * it; symlinks are not followed, because a cycle would not terminate. */
    probe = descend ? opendir(sub) : NULL;
    if (probe) {
      closedir(probe);
      ref_walk(sub, depth + 1, 1);
      if (ref_truncated) break;
      continue;
    }
    if (lstat(sub, &st) != 0 || !S_ISREG(st.st_mode)) continue;
    if (++ref_files > REF_MAX_FILES) { ref_truncated = 1; break; }
    for (unsigned g = 0; g < tgts_n; g++) {
      if (!ends_with_name(sub, tgt_name[g])) continue;
      tgt_add(g, sub, ref_in_artefact);
    }
  }
  closedir(d);
}

/* A file whose last line has no newline still has that line. An empty file has
 * zero lines, which is the truth about it and not a read that failed. */
static unsigned long count_lines(const char *path) {
  unsigned long lines = 0;
  int c = 0, seen = 0;
  FILE *f = fopen(path, "rb");
  if (!f) return 0;
  while ((c = fgetc(f)) != EOF) {
    seen = 1;
    if (c == '\n') lines++;
  }
  fclose(f);
  return seen && c != '\n' ? lines + 1 : lines;
}

/* ---------------------------------------------------------------- the two
 * CONTENT checks, and the shape of the hole they leave.
 *
 * Everything above this line asks whether a cited file and a cited line EXIST.
 * `resolved=219 missing=0 stale_lines=0` therefore means that every citation
 * names a file and a line that are there, and it says nothing whatever about
 * whether the line holds the code the sentence names. That gap was not
 * theoretical: three edits during wave 9 moved files under live citations --
 * fourteen lines inserted in frontend.c invalidated four citations of the
 * sections 6.1 and 10, a codegen.c edit invalidated fifteen, and a
 * validate.nova edit invalidated eight -- and every gate in the suite stayed
 * green through all three, because existence is all that was being measured.
 * One of the four was stale for a second reason as well: `align_stack` does
 * not appear in frontend.c at all, the rule being a `stack_aligned` predicate
 * reached behind a phase flag, and its companion citation had not moved, which
 * is exactly the asymmetry that let the error survive a wave.
 *
 * This is the FIFTH instance of one shape, and the shape is the reason the two
 * checks below are documented with their limits instead of being presented as
 * coverage. A fact can be REGISTERED, RESOLVABLE, PRESENT, and still not
 * MEASURED: a guard that depends on the value it verifies, a drift detector
 * that closes over the wrong axes, a resolver that checks existence rather than
 * content, a gate whose name is registered while nothing compares its counters,
 * and now a resolver that confirms a line is there without asking what is on
 * it. An instrument that appears to cover more than it does is the failure
 * again, one level up, so both limits are printed in the banner.
 *
 * WHAT IS RED. Both checks are hard failures, and the direction is stated
 * because it is not the same direction as the checks above: those ACCEPT a
 * citation whose file cannot be found, when the search was truncated. These
 * two only ever run against a file that RESOLVED and whose cited range is
 * inside it, so a verdict here is a statement about a text that was read, not
 * about a search that stopped. There is no tolerance clause, because there is
 * nothing to be tolerant about: a blank endpoint or a quoted string that is
 * not at the line is wrong at both ends of the wave.
 *
 * THE SPAN CHECK, and the limit that matters. A cited range must begin and end
 * on a line that has something on it, and must not begin or end inside a block
 * comment relative to its neighbours. This needs no prose at all, so it runs
 * on every one of the 219 references, quoted or not. It catches the two span
 * defects that were found by hand in this document's own text during wave 9 --
 * one range ending on a blank line, one beginning on one.
 *
 * IT CANNOT CATCH A CITATION THAT NAMES THE WRONG NON-BLANK LINE, and that is
 * not a defect of the implementation, it is the limit of the idea. Both
 * endpoints being real says the range is well formed; it says nothing about
 * whether the code between them is the code the sentence is about. Only an
 * oracle confrontation would establish that, and an oracle confrontation is
 * not a documentation check: it would be a second implementation to be wrong
 * in the same direction. So the span check is a well-formedness check and the
 * banner says so in those words.
 *
 * THE IDENTIFIER CHECK, and its limit. Where the prose names something -- an
 * identifier written in backquotes in the same appositive group as the
 * citation -- that identifier must appear inside the cited range. This is what
 * would have caught the first wave 9 drift automatically, and it is the only
 * one of the two that can catch a range that is well formed and wrong.
 *
 * IT WORKS ONLY WHERE THE PROSE NAMES SOMETHING, and on this document that is
 * a small minority: 219 references, and the banner prints ident_covered= so
 * the number is re-derivable rather than asserted. The other references are
 * silent about content and this check is silent about them, which is the
 * honest reading: it is a check on the citations that make a claim, not on
 * the citations that merely point.
 *
 * WHY THE GROUP AND NOT THE SENTENCE. A sentence names many things, and most
 * of them are not what the citation is about: a sentence that cites
 * `control_flow.nova:809-848` and then names `stack_branches` is making a
 * claim about the fusion, and one that cites `stub_table.nova:31` and names
 * `pe_inspect` in the next clause is not making any claim about line 31 at
 * all. Scoping to the whole sentence was MEASURED on this document and it is
 * useless: 134 of 219 references acquire a candidate, and 112 of those 134
 * fail, which is a check that is red on a correct document and therefore
 * measures nothing. Scoping to the parenthesised group the citation is written
 * in -- the form the document actually uses,
 *     (`tests_ntasm_control_flow.c:264`, `align_half`, `364` raison 4)
 * where the identifier IS the assertion about the cited line -- keeps the
 * claim and the citation together. A gate name or a file stem is not a
 * candidate: those name the document's own furniture, not the cited site. */

/* One line of a resolved file, and whether it is inside a block comment. The
 * comment state is a property of the WHOLE file up to that line, so it is
 * computed once per target in a single pass and then indexed; recomputing it
 * per citation would be quadratic in a document this size for no reason. */
typedef struct {
  unsigned long lines;      /* how many lines the file has */
  unsigned char *blank;     /* [lines+1]: 1 when the line has no non-blank */
  unsigned char *comment;   /* [lines+1]: 1 when the line is inside a block comment */
  char *text;               /* the whole file, NUL terminated */
  size_t text_len;
  size_t *off;              /* [lines+2]: byte offset of each line start */
} RefFile;

static RefFile ref_file_cache[TGT_MAX];
static unsigned ref_file_cached;


/* Read one resolved file once, and record per line whether it is blank and
 * whether it lies inside a block comment. The comment flag is the state AT THE
 * START of the line, which is what "the range starts inside a comment relative
 * to its neighbours" means: a line whose first character is already inside a
 * comment the reader did not open at the citation is a continuation. */
static int ref_file_load(int g) {
  RefFile *f;
  size_t n = 0;
  char *b;
  if (g < 0 || (unsigned)g >= TGT_MAX) return 0;
  f = &ref_file_cache[g];
  if (f->text) return 1;
  b = loadf(tgt_match[g][tgt_pick[g]], &n);
  if (!b) return 0;
  f->text = b;
  f->text_len = n;
  /* Count lines the same way count_lines does -- a last line without a
   * newline is still a line -- so the two halves of section 8 cannot disagree
   * about how long a file is. */
  f->lines = 0;
  for (size_t i = 0; i < n; i++) if (b[i] == '\n') f->lines++;
  if (n && b[n - 1] != '\n') f->lines++;
  f->off = calloc(f->lines + 2, sizeof *f->off);
  f->blank = calloc(f->lines + 2, 1);
  f->comment = calloc(f->lines + 2, 1);
  if (!f->off || !f->blank || !f->comment) return 0;
  {
    size_t start = 0;
    unsigned long ln = 1;
    int in_block = 0, in_str = 0, in_chr = 0, esc = 0;
    f->off[0] = 0;
    for (size_t i = 0; i <= n; i++) {
      if (i == n || b[i] == '\n') {
        size_t end = i;
        size_t j;
        int blank = 1;
        if (ln <= f->lines) {
          f->off[ln] = start;
          for (j = start; j < end; j++)
            if (b[j] != ' ' && b[j] != '\t' && b[j] != '\r') { blank = 0; break; }
          f->blank[ln] = (unsigned char)blank;
          f->comment[ln] = (unsigned char)in_block;
        }
        /* advance the comment state across this line */
        for (j = start; j < end; j++) {
          char c = b[j];
          if (esc) { esc = 0; continue; }
          if (c == '\\' && (in_str || in_chr)) { esc = 1; continue; }
          if (in_block) {
            if (c == '*' && j + 1 < end && b[j + 1] == '/') { in_block = 0; j++; }
            continue;
          }
          if (in_str) { if (c == '"') in_str = 0; continue; }
          if (in_chr) { if (c == '\'') in_chr = 0; continue; }
          if (c == '/' && j + 1 < end && b[j + 1] == '*') { in_block = 1; j++; continue; }
          if (c == '/' && j + 1 < end && b[j + 1] == '/') { j = end; break; }
          if (c == '"') { in_str = 1; continue; }
          if (c == '\'') { in_chr = 1; continue; }
        }
        in_str = in_chr = esc = 0;
        start = i + 1;
        ln++;
      }
    }
  }
  ref_file_cached++;
  return 1;
}

/* The text of lines lo..hi of a loaded file, NUL terminated, into a caller
 * buffer. Returns 0 when the range is not inside the file, which the caller
 * treats as "this check does not apply" rather than as a verdict: the range
 * check above owns out-of-bounds, and a check that failed on a range it cannot
 * read would be reporting the other check's finding under its own name. */
static int ref_range_text(int g, unsigned lo, unsigned hi, char *out, size_t cap) {
  RefFile *f;
  size_t a, b, len;
  if (!ref_file_load(g)) return 0;
  f = &ref_file_cache[g];
  if (lo < 1 || hi < lo || hi > f->lines) return 0;
  a = f->off[lo];
  b = (hi < f->lines) ? f->off[hi + 1] : f->text_len;
  if (b < a) b = a;
  len = b - a;
  if (len + 1 > cap) len = cap - 1;
  memcpy(out, f->text + a, len);
  out[len] = 0;
  return 1;
}

/* The parenthesised group of spec/ntasm/ntasm.md that the reference at [st,en) is
 * written in, on its own line. Returns the group's bounds within the document
 * and 1, or 0 when the citation is not inside brackets, in which case the
 * caller falls back to the whole line -- a citation written bare is still a
 * citation, and refusing to look at it because the author did not parenthesise
 * it would be a coverage hole shaped exactly like the one being closed. */
static int ref_group(const char *spec, size_t n, size_t st, size_t en,
                     size_t *ga, size_t *gb) {
  size_t ls = st, le = en, i, depth;
  while (ls > 0 && spec[ls - 1] != '\n') ls--;
  while (le < n && spec[le] != '\n') le++;
  *ga = ls;
  *gb = le;
  /* innermost '(' strictly before the citation */
  depth = 0;
  for (i = en; i > ls; i--) {
    if (spec[i - 1] == ')') depth++;
    else if (spec[i - 1] == '(') {
      if (depth == 0) { *ga = i - 1; break; }
      depth--;
    }
  }
  /* matching ')' at or after it */
  depth = 0;
  for (i = en; i < le; i++) {
    if (spec[i] == '(') depth++;
    else if (spec[i] == ')') {
      if (depth == 0) { *gb = i + 1; break; }
      depth--;
    }
  }
  return 1;
}

/* Is `q` a candidate identifier for the content check? A bare C/Nova
 * identifier, not a gate name and not a file stem, because those two name the
 * document's own furniture rather than the cited site, and either one in the
 * window would make the check red on a correct document. The underscore or the
 * camel-case hump is what separates `align_half` from a French or English word,
 * which is why a plain word is not a candidate: `main` and `return` are
 * everywhere, and asserting they are at a given line asserts nothing. */
static int ident_candidate(const char *q, size_t len) {
  size_t i;
  int hump = 0;
  if (len < 3 || len >= NAME_MAX) return 0;
  if (!((q[0] >= 'a' && q[0] <= 'z') || (q[0] >= 'A' && q[0] <= 'Z') || q[0] == '_'))
    return 0;
  for (i = 1; i < len; i++) {
    char c = q[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
      return 0;
    if (c >= 'A' && c <= 'Z') hump = 1;
  }
  if (!hump) {
    for (i = 0; i < len; i++) if (q[i] == '_') return 1;
    return 0;
  }
  /* A camelCase name whose first hump is at position 0 is a gate banner
   * (`NTASM_...` is excluded by the character set, but `Splice` and `Shape`
   * are not); requiring a lowercase before the hump keeps those out. */
  for (i = 1; i < len; i++)
    if (q[i] >= 'A' && q[i] <= 'Z') return 1;
  return 0;
}

/* Does the file named by the reference name exist in the tree under this bare
 * name? A token that names a file the document also cites is furniture, not a
 * claim about a line. The comparison is against the target table rather than
 * against a list, so a module the document has never heard of is not excluded
 * by this check -- it is simply not a candidate, because it was never a word
 * in the window. */
static int ident_is_file_stem(const char *q, size_t len) {
  for (unsigned g = 0; g < tgts_n; g++) {
    const char *nm = tgt_name[g];
    size_t l = strlen(nm), k = 0;
    while (k < l && k < len && nm[k] == q[k]) k++;
    if (k == len && l > k && nm[k] == '.') return 1;
    if (k == l && k == len) return 1;
  }
  return 0;
}

/* A gate name is a harness basename: `splice`, `x64_lower_lea`,
 * `x64_lower_nxo_function_bodies`. The document names them constantly -- the
 * coverage table of 17.6 is nothing but gate names beside numbers -- and a gate
 * name beside a citation asserts nothing about the cited line, so a token that
 * is one is not a candidate.
 *
 * It is decided by ASKING THE TREE, through the is_gate() this file already
 * has, rather than by a shape rule or by a list of names. The shape rule was
 * written first and it was wrong in a way worth recording: it excluded only
 * underscore-free words, on the reasoning that an identifier candidate must
 * contain an underscore -- which is exactly backwards, because the longest gate
 * names in the suite are the ones with underscores in them. It produced seven
 * false failures on the coverage table of 17.9 before the tree was asked. A
 * hardcoded list would have been that same defect wearing a different hat: a
 * gate added next wave would become a candidate and turn this red on a correct
 * document, which is the failure mode this section exists to refuse. */
static int ident_is_gate_word(const char *q, size_t len) {
  char name[NAME_MAX];
  if (len == 0 || len >= sizeof name) return 0;
  memcpy(name, q, len);
  name[len] = 0;
  return is_gate(name);
}

/* WHICH DOCUMENT A CITATION CAME FROM, and the texts themselves. The second
 * document is here because the coverage was simply missing, not because the
 * two documents are peers: until this, `docs/status/ntasm-completion.md` was read by
 * NO gate in the suite -- not the resolution, not the span checks, not the
 * identifier checks, not the drift. It carries 22 `file:line` citations, ten
 * of them spelled with a full repository path and twelve with a bare name, and
 * every one of them was a claim no instrument could touch. That is the same
 * shape as the residual the fifth closure was written for, one document over.
 *
 * The two texts are read into GLOBALS rather than passed down, for a reason
 * that is not tidiness: `check_references` is called a SECOND time by the
 * re-judge in main() with a fresher copy of the spec, and a global that main()
 * sets once is still correct on that call, while a parameter threaded through
 * nine call sites is one more thing to get wrong in a path that only runs when
 * a sibling lot happens to be writing. The second document does not change
 * under the gate, so it is collected from the same global on both judgements
 * and the two runs stay comparable.
 *
 * ONE WALK FOR BOTH. The second document's citations resolve against the same
 * target table, filled by the same single bounded walk of REF_ROOTS. A second
 * walk would have cost 1172 directories and 15887 files again for a document
 * with 22 citations, and the first walk is already a large part of this gate's
 * wall clock. Merging is also what makes the two documents comparable: two
 * resolvers over one tree is two things to be wrong in the same direction,
 * which is the thing this file's header refuses to do elsewhere. */
/* THREE ARRAYS, and the split between them is not a matter of taste: the
 * version that kept one pointer for both was caught by AddressSanitizer on its
 * first run, reading 2681 bytes past a 25-byte string literal, because the
 * NAME of the second document had been handed to the scanner where the TEXT of
 * it belonged. A name and a text are different objects with different lengths
 * and a scanner that is given the wrong one does not notice for a long time.
 *
 *   ref_doc[]   the PATH, for the failure messages. Stable for the run.
 *   ref_text[]  the BYTES. Set at the top of every check_references call, so
 *               the re-judge path -- which hands the function a fresher copy of
 *               the spec -- reads the copy this judgement is about and not the
 *               one the first judgement read.
 *   ref_docn[]  the LENGTH of each, paired with the text above it. A length
 *               that belongs to a different pointer is the same defect the
 *               sanitizer just found, one step later.
 *
 * The second document's text is a file-scope pointer rather than a local of
 * main() because check_references is not main() and must not have to be told
 * what the other document is. main() owns the load and the free; this owns
 * neither. */
static const char *ref_doc[REF_DOCS];
static const char *ref_text[REF_DOCS];
static size_t ref_docn[REF_DOCS];
static char *doc2_text;
static unsigned char ref_which[REF_MAX];

/* The document a citation belongs to, for the failure messages. Before the
 * second document this was the literal "spec/ntasm/ntasm.md" in a dozen messages,
 * which is exactly the kind of thing that reads as though the instrument
 * covered one file when it covers two. */
static const char *rdoc(unsigned q) {
  unsigned d = ref_which[q] < REF_DOCS ? ref_which[q] : 0;
  return ref_doc[d] ? ref_doc[d] : "the document";
}

/* The TEXT a citation lives in, for the check that needs the surrounding prose
 * and not only the citation. The identifier check reads a window of the
 * document around each reference, and a window taken from the wrong document
 * is a window of unrelated bytes. */
static const char *ref_text_of(unsigned q) {
  unsigned d = ref_which[q] < REF_DOCS ? ref_which[q] : 0;
  return ref_text[d] ? ref_text[d] : "";
}
static size_t ref_size_of(unsigned q) {
  unsigned d = ref_which[q] < REF_DOCS ? ref_which[q] : 0;
  return ref_docn[d];
}

/* Every `name.ext:line` and `name.ext:lo-hi` of the document. The name may hold
 * slashes and dashes; it must END at the extension, so `x.check` is not read as
 * a reference to x.c, and a digit may not follow the line, so the `12` of
 * `a12.nova:12` is not read as part of a longer number. The document index
 * `doc` is recorded per citation and is what rdoc() and the two text
 * accessors read; it is written at the same place the citation is appended, so
 * a citation cannot exist without a document. */
static void collect_references(const char *t, size_t n, unsigned doc) {
  size_t i = 0;
  while (i < n) {
    size_t at, end, ext, k, start_line = 1;
    unsigned lo, hi;
    int g;
    if (!((t[i] >= 'A' && t[i] <= 'Z') || (t[i] >= 'a' && t[i] <= 'z') || t[i] == '_')) { i++; continue; }
    at = i;
    while (i < n && name_char((unsigned char)t[i])) i++;
    end = i;
    ext = end;
    while (ext > at && t[ext - 1] != '.') ext--;
    if (ext == at || ext == end) continue;
    { size_t d = ext;
      while (d < end && ((t[d] >= 'a' && t[d] <= 'z') || (t[d] >= 'A' && t[d] <= 'Z'))) d++;
      if (d != end) continue; }
    if (i >= n || t[i] != ':') continue;
    k = i + 1;
    if (!read_uint(t, n, &k, &lo)) continue;
    hi = lo;
    if (k < n && t[k] == '-') {
      size_t m = k + 1;
      unsigned other;
      if (read_uint(t, n, &m, &other) && other >= lo) { hi = other; k = m; }
    }
    if (k < n && ident_char((unsigned char)t[k])) continue;
    /* `ext` sits just AFTER the dot, which is what made the test above a test
     * of the extension; the name itself runs to `end`, dot and extension
     * included. Using ext-at here stored "control_flow." and matched nothing. */
    /* TWO FAULTS, ONE MESSAGE, and the second is the one that burns an
     * afternoon. A name too long and a full array both stopped here and both
     * reported "the documents carry more references than this harness can
     * hold", so a reader who then did the arithmetic -- 241 references against
     * a 512 cap -- correctly concluded the counter was wrong. It was not. One
     * name was too long and the message named the array instead. Split now,
     * because a diagnostic that names the wrong cause sends the reader to
     * arithmetic rather than to the file, and the arithmetic disagrees with
     * the message for hours before anyone opens the source. */
    if (end - at >= NAME_MAX) { refs_overflow = 1; refs_over_name = 1; return; }
    if (refs_n >= REF_MAX) { refs_overflow = 1; refs_over_name = 0; return; }
    g = target_of(t + at, end - at);
    if (g < 0) {
      if (tgts_n >= TGT_MAX) { tgts_overflow = 1; return; }
      g = (int)tgts_n++;
      memcpy(tgt_name[g], t + at, end - at);
      tgt_name[g][end - at] = 0;
      tgt_nrefs[g] = 0;
    }
    memcpy(ref_target[refs_n], t + at, end - at);
    ref_target[refs_n][end - at] = 0;
    /* from the head of the document, not from the name: a name and its line
     * number are on the same line by construction, so counting from `at` gives
     * zero and every failure would name spec/ntasm/ntasm.md:1 */
    for (size_t j = 0; j < at; j++) if (t[j] == '\n') start_line++;
    ref_lo[refs_n] = lo;
    ref_hi[refs_n] = hi;
    ref_line[refs_n] = (unsigned)start_line;
    if (tgt_nrefs[g] < REF_MAX) tgt_nrefs[g]++;
    ref_which[refs_n] = (unsigned char)doc;
    refs_n++;
  }
}

/* WHAT EACH CITATION'S OWN VERDICT WAS, kept per reference rather than
 * recomputed later. Two instruments below -- the class report and the two-run
 * drift comparison -- need the verdict of every citation, and neither may
 * re-derive it: a second implementation of "did this citation resolve" is a
 * second thing to be wrong in the same direction, which is the failure this
 * file's own header calls out when it refuses to re-derive the pipeline. So the
 * three loops that judge a citation write here, once, and the readers read. */
#define V_STALE          1u   /* resolved, but the range runs past the end   */
#define V_UNRESOLVED     2u   /* no file of the declared scope has that name  */
#define V_SPAN_BLANK     4u   /* an endpoint of the range is a blank line     */
#define V_SPAN_COMMENT   8u   /* reported, not failed; see check_spans        */
#define V_IDENT_MISSING 16u   /* the prose names something the range lacks    */
#define V_BUDGET        32u   /* the search stopped: no verdict is claimed   */
#define V_IDENT_COVERED 64u   /* the citation names something that was found */
static unsigned char ref_verdict_flags[REF_MAX];

/* The citations that resolved to NOTHING, kept whole. The FAIL that names each
 * one is printed where it is decided and its semantics are not touched by
 * anything here; what the table adds is the second reading, over the set rather
 * than over the items, which is the reading that turns seven tickets into one
 * decision. */
#define UNRES_MAX 128
typedef struct {
  char name[NAME_MAX];
  unsigned lo, hi, line;
  unsigned doc;          /* which document the citation is written in */
  unsigned char copied;  /* 0: resolved to nothing. 1: resolved to a COPY. */
  char at[REF_PATH];     /* the copy, when copied is 1 */
} UnresRef;
static UnresRef unres[UNRES_MAX];
static unsigned unres_n, unres_overflow;

/* THE SPAN CHECK. Runs on every reference that resolved to a file whose cited
 * range is inside it, quoted or not: two endpoints that both have something on
 * them, and neither of them a continuation of a block comment the citation did
 * not open. This is the check that needs no prose, and therefore the one whose
 * coverage is the whole document.
 *
 * The comment half is deliberately about the state at the START of the line, not
 * anywhere on it. A range may legitimately quote a comment -- the document cites
 * comment text in several places -- so what is wrong is a range that OPENS
 * inside a comment that began earlier, because then the first line of the
 * citation is not the first line of the thing being cited. The condition at the
 * end is the same defect read from the other side. */
static unsigned span_covered, span_blank, span_comment;

static void check_spans(void) {
  for (unsigned q = 0; q < refs_n; q++) {
    int g = target_of(ref_target[q], strlen(ref_target[q]));
    RefFile *f;
    if (g < 0 || tgt_nmatch[g] == 0) continue;
    if (!ref_file_load(g)) continue;
    f = &ref_file_cache[g];
    if (ref_lo[q] < 1 || ref_hi[q] < ref_lo[q] || ref_hi[q] > f->lines) continue;
    span_covered++;
    if (f->blank[ref_lo[q]] || f->blank[ref_hi[q]]) {
      ref_verdict_flags[q] |= (unsigned char)(V_SPAN_BLANK | V_BUDGET);
      span_blank++;
      /* One sentence, not two assembled from fragments: the first version of
       * this message was built out of three conditionals and read
       * "the code and the code and nothing nothing". A diagnostic a reader has
       * to parse twice is a diagnostic that gets skipped, and this section is
       * about signals nobody read.
       *
       * `FAIL` IS THE FIRST TOKEN, for the reason given at IDENT-MISSING below:
       * this site charges `failures++`, and for most of a day it printed a line
       * beginning `SPAN-BLANK`, which `grep '^FAIL'` cannot reach. That is not
       * hypothetical. Measured on this tree, 30 September 2026: a run of this
       * gate printed `NTASM_NOVA_REGISTRY checks=3268 failures=1` and its log
       * held ZERO `FAIL` lines -- the one failure was this site, a citation in
       * docs/status/ntasm-completion.md naming a blank endpoint of MEM.md. A reader
       * who read the banner and then grepped for the evidence found nothing and
       * had no way to tell a silent check from a gate that could not report.
       *
       * The label is kept after the prefix, because it says what KIND of
       * failure this is. SPAN-COMMENT below does not fail and keeps its own
       * prefix, for the same reason IDENT-REPORTED does. */
      fprintf(stderr, "FAIL SPAN-BLANK %s:%u cites %s:%u-%u and line %u is blank, so that "
                      "endpoint of the range names nothing; the range should end at %u\n",
              rdoc(q), ref_line[q], tgt_name[g], ref_lo[q], ref_hi[q],
              f->blank[ref_lo[q]] ? ref_lo[q] : ref_hi[q],
              f->blank[ref_lo[q]] ? ref_lo[q] + 1 : ref_hi[q] - 1);
      checks++; failures++;
    } else good();
    /* A one-line citation cannot both start and end mid-comment. */
    if (ref_lo[q] == ref_hi[q]) { good(); continue; }
    /* The comment half is REPORTED, NOT FAILED, and the reason is a measurement
     * rather than a preference. This document cites the prose of a block comment
     * on purpose in at least two places -- `codegen.h:36-38` is three lines of
     * the profile note, and `tests_ntasm_control_flow.c:148-163` is the
     * explanatory comment above statementF -- and a rule that refuses any range
     * touching a comment cannot tell that from a range that drifted into one by
     * four lines. It fired on four citations, all four of which name exactly
     * what they claim to name. A check that is red on four correct citations is
     * not a check with a limit; it is a check that cannot pass, which is the
     * same shape as the guard that can never fail, read from the other side.
     *
     * So the count is in the banner and every offender is named on stderr, and
     * a reader decides. What this check CANNOT do is the thing the audit asked
     * for: separating a deliberate citation of a comment from a drifted one
     * needs to know what the sentence meant to point at, and the only instrument
     * that has that is a human reading the sentence. Stated as a limit rather
     * than papered over with a threshold. */
    if (f->comment[ref_lo[q]] || f->comment[ref_hi[q]]) {
      ref_verdict_flags[q] |= (unsigned char)(V_SPAN_COMMENT | V_BUDGET);
      span_comment++;
      fprintf(stderr, "SPAN-COMMENT %s:%u cites %s:%u-%u and that range %s inside a block "
                      "comment; reported, not failed, because this document cites comment prose on "
                      "purpose and a rule cannot tell that from a drift into one\n",
              rdoc(q), ref_line[q], tgt_name[g], ref_lo[q], ref_hi[q],
              f->comment[ref_lo[q]] ? "begins" : "ends");
      good();
    } else good();
  }
}

/* THE IDENTIFIER CHECK. For each reference, the parenthesised group of the
 * document it is written in -- or its own line when it is written bare -- and
 * every backquoted token in that window shaped like an identifier that is
 * neither a gate name nor a file stem. Each such token must appear inside the
 * cited range of the file the reference resolves to.
 *
 * The window is the group and not the sentence because the sentence version was
 * MEASURED on this document and is unusable: 134 of 219 references acquire a
 * candidate and 112 of those fail, which is a check that is red on a correct
 * document and therefore distinguishes nothing. The group is the unit in which
 * this document actually makes a claim about a line. */
static unsigned ident_covered, ident_missing, ident_tokens, ident_failed, ident_reported;

/* How many documents, counted from index 0, the identifier check is allowed to
 * be RED on. The measurement behind the number is spelled at the failure site
 * and repeated in the banner: on spec/ntasm/ntasm.md the same rule gives 19 tokens
 * and 0 missing and is a check that found twelve false citations when it was
 * first run (U17); on docs/status/ntasm-completion.md it gives 134 tokens and 100
 * missing, because the group a citation there is written in is a table cell of
 * up to nine thousand characters and is not a claim about one range.
 *
 * A COUNT and not a list of names, on purpose. A list would let a third
 * document arrive and inherit a decision that was measured about a different
 * file; a count makes the next document an edit here, in the place where the
 * measurement lives, and the place the reader of this file will look. */
#define IDENT_FAILING_DOCS 1

static int has_sub(const char *hay, size_t hn, const char *needle, size_t nl) {
  if (nl == 0 || nl > hn) return 0;
  for (size_t i = 0; i + nl <= hn; i++)
    if (memcmp(hay + i, needle, nl) == 0) return 1;
  return 0;
}

/* The byte range of reference `q` inside ITS OWN document, recovered from the
 * line it was counted on and the name it carries. The resolver recorded the
 * line and the name but not the offsets, and the offsets are what a window is
 * made of; recovering them by re-scanning the line is exact because the name
 * and the colon are on that line by construction.
 *
 * The text is taken from the citation's own document rather than from an
 * argument, and that is the whole of the change this function needed: the line
 * number of a citation in the second document means nothing in the first, so a
 * version that took the spec's text for both would have read line 43 of the
 * spec for a citation written on line 43 of another file, and every identifier
 * window would have been a window of the wrong bytes. */
static int ref_offsets(unsigned q, size_t *st, size_t *en) {
  const char *spec = ref_text_of(q);
  size_t n = ref_size_of(q);
  unsigned ln = ref_line[q];
  size_t name_len = strlen(ref_target[q]);
  size_t ls = 0, le, i;
  for (unsigned k = 1; k < ln; k++) {
    while (ls < n && spec[ls] != '\n') ls++;
    if (ls >= n) return 0;
    ls++;
  }
  le = ls;
  while (le < n && spec[le] != '\n') le++;
  for (i = ls; i + name_len < le; i++) {
    if (memcmp(spec + i, ref_target[q], name_len) != 0) continue;
    if (i > ls && name_char((unsigned char)spec[i - 1])) continue;
    if (spec[i + name_len] != ':') continue;
    *st = i;
    i += name_len + 1;
    while (i < le && spec[i] >= '0' && spec[i] <= '9') i++;
    if (i < le && spec[i] == '-') {
      i++;
      while (i < le && spec[i] >= '0' && spec[i] <= '9') i++;
    }
    *en = i;
    return 1;
  }
  return 0;
}

static void check_identifiers(void) {
  static char text[1u << 18];
  for (unsigned q = 0; q < refs_n; q++) {
    const char *spec = ref_text_of(q);
    size_t n = ref_size_of(q);
    int g = target_of(ref_target[q], strlen(ref_target[q]));
    size_t st, en, ga, gb, i;
    int any = 0;
    if (g < 0 || tgt_nmatch[g] == 0) continue;
    if (!ref_offsets(q, &st, &en)) continue;
    if (!ref_range_text(g, ref_lo[q], ref_hi[q], text, sizeof text)) continue;
    ref_group(spec, n, st, en, &ga, &gb);
    i = ga;
    while (i < gb) {
      size_t a, b;
      if (spec[i] != '`') { i++; continue; }
      a = ++i;
      while (i < gb && spec[i] != '`' && spec[i] != '\n') i++;
      if (i >= gb || spec[i] != '`') break;
      b = i++;
      /* the citation's own token, and any second citation, name lines rather
       * than making a claim about one */
      if (b - a == strlen(ref_target[q]) && !memcmp(spec + a, ref_target[q], b - a)) continue;
      if (memchr(spec + a, ':', b - a)) continue;
      if (!ident_candidate(spec + a, b - a)) continue;
      if (ident_is_file_stem(spec + a, b - a)) continue;
      if (ident_is_gate_word(spec + a, b - a)) continue;
      ident_tokens++;
      ref_verdict_flags[q] |= (unsigned char)V_IDENT_COVERED;
      if (!any) { any = 1; ident_covered++; }
      if (!has_sub(text, strlen(text), spec + a, b - a)) {
        ref_verdict_flags[q] |= (unsigned char)V_IDENT_MISSING;
        ident_missing++;
        /* ONE RULE, TWO SEVERITIES, and the split is a MEASUREMENT and not a
         * preference. The rule reads the parenthesised GROUP a citation is
         * written in, and a group is a unit of prose whose size the document
         * chooses. Measured on the two documents, with this rule unchanged:
         *
         *   spec/ntasm/ntasm.md            19 tokens,  0 missing   -- fails, and this
         *                           is the check that found twelve false
         *                           citations when it was first run (U17).
         *   docs/status/ntasm-completion.md 134 tokens, 100 missing -- a false-fire
         *                           rate of three in four.
         *
         * The second number is not a defect in the document and not a defect in
         * the rule: that document writes its claims as table cells of one to
         * nine thousand characters, so the group around a citation is a whole
         * paragraph that names forty symbols, and a citation about one of them
         * cannot possibly contain the other thirty-nine. A rule that is right
         * for one document is a false-fire machine for the other, and the
         * second document is reported for exactly the reason SPAN-COMMENT is:
         * a class that fires on correct prose is counted and named, not red.
         *
         * THE NARROWER ALTERNATIVE WAS MEASURED AND REJECTED, because measuring
         * is cheaper than arguing. Narrowing the window to the sentence
         * wherever the citation sits on a table row -- a rule that looks
         * principled, since a table cell is not a claim about a line -- gives
         * 24 tokens and 37 missing on that document, worse than the group rule's
         * 16 and 139 only in coverage and no better in rate. A pure sentence
         * window gives 2 tokens and 0 missing: quiet because it sees almost
         * nothing, and the spec's own history records the same window producing
         * 112 failures in 134 on the other document. There is no window that is
         * right for both, which is the fact the two severities encode.
         *
         * The count that goes red is therefore the spec's alone, which is what
         * it was before the second document existed, and the banner prints both
         * numbers so the split is visible rather than a secret of this file. */
        if (ref_which[q] < IDENT_FAILING_DOCS) {
          ident_failed++;
          /* `FAIL` is the FIRST TOKEN, not a description, and that ordering is
           * the whole point. This site counts a failure, and for most of a day
           * it printed a line beginning `IDENT-MISSING`, which every reader
           * of this file reaches for with `grep '^FAIL'`. Nine real defects
           * lived there: four cited files were edited by the wave that was
           * running, and the citations that went stale were invisible to the
           * one search a reader actually types.
           *
           * A prefix `grep '^FAIL'` cannot reach is worse than no message,
           * because grep returns SOMETHING and the reader stops -- whereas an
           * empty grep keeps sending them back to the log. Nine failures were
           * counted, none was greppable, and a banner reading `failures=9`
           * sat there explaining nothing.
           *
           * The label is kept after the prefix, because it says what KIND of
           * failure this is and that is worth reading. IDENT-REPORTED below
           * does not fail and keeps its own prefix for the same reason. */
          fprintf(stderr, "FAIL IDENT-MISSING %s:%u cites %s:%u-%u and names `%.*s` beside it, "
                          "which is nowhere in that range of %s\n",
                  rdoc(q), ref_line[q], tgt_name[g], ref_lo[q], ref_hi[q], (int)(b - a), spec + a,
                  tgt_match[g][tgt_pick[g]]);
          checks++; failures++;
        } else {
          ident_reported++;
          fprintf(stderr, "IDENT-REPORTED %s:%u cites %s:%u-%u and names `%.*s` beside it, which "
                          "is nowhere in that range of %s; counted, not failed, because the group "
                          "this citation is written in is a table cell that names dozens of "
                          "symbols and is not a claim about this one range\n",
                  rdoc(q), ref_line[q], tgt_name[g], ref_lo[q], ref_hi[q], (int)(b - a), spec + a,
                  tgt_match[g][tgt_pick[g]]);
          good();
        }
      } else good();
    }
  }
}

/* ============================== the SOURCES-MOVED fence.
 *
 * The twins above do not read a build directory. They read the Nova SOURCES, at
 * run time, through loadf() inside each harness -- forty one of them for
 * `splice`, and the C libraries for the other five. That is the point of the
 * third closure in this file, and it is also its exposure: a source that is
 * rewritten while a twin is reading it produces a verdict about a text that
 * does not exist, and the verdict looks exactly like a verdict.
 *
 * IT WAS MEASURED, and the measurement is the reason this is a hard failure
 * rather than a note. Three runs of this gate, each in its OWN fresh build
 * directory, gave:
 *
 *   run 1   NTASM_NOVA_SPLICE checks=356 failures=0 cases=39
 *   run 2   NTASM_NOVA_SPLICE checks=356 failures=0 cases=39
 *   run 3   NTASM_NOVA_SPLICE checks=5   failures=4 cases=0
 *           E200 304:49 expected -> return type
 *
 * Same binary, same tree, three minutes. macro_expand.nova was being saved
 * while run 3 read it; a parse error in one Nova source cascades into every
 * module, so `call_contracts` and `diagnostics` went red in the same run and
 * `splice` reported `build=9257` for five fixtures. `9257` is not a code
 * anywhere in this project -- it is an UNINITIALISED word of a Shape the entry
 * never wrote, read back and formatted as if it were a diagnostic. Two facts
 * about that number, and both are the reason for this fence:
 *
 *   - it was not interpretable, because it was not a value; and
 *   - it was REPORTED rather than refused, so a red whose cause is "the tree
 *     moved" was indistinguishable on the log from a red whose cause is a gate.
 *
 * `locals` and `bindings` were unaffected in run 3, and that is the load-bearing
 * observation rather than a footnote: they do not compile the forty one source
 * image, so they were a control group, and the conclusion is "one source moved"
 * and not "the harness is flaky". A control group that the investigator did not
 * build and then read is the strongest evidence in this file.
 *
 * WHY A HARD FAILURE. The whole wave has spent itself removing greens that
 * hide reds, and a loud stderr line that leaves fail=0 is the same shape one
 * level down: the suite says it is fine while the measurement under it is void.
 * The cost is real -- this fires whenever a sibling lot saves a .nova file, and
 * eight lots are active -- and the cost is CORRECT during concurrent editing,
 * because the measurement genuinely is not valid then. The discipline that
 * answers it is the one already in force: no lots active during integration. A
 * gate that refuses to certify a moving tree is doing its job.
 *
 * WHAT IT STATS, AND WHY NOT THE C LIBRARIES. The C side already has a
 * STALE_OBJECTS guard in the runner, and it is a different guard rather than a
 * duplicate: an object file is a build artefact with an mtime that says when
 * its source was last read, whereas a .nova file is an INPUT read at run time
 * and has no object to compare. That asymmetry is why this hole survived the
 * runner's fix, and it is why the two guards are not redundant.
 *
 * AND IT NAMES THE FILES, because a red that does not name its cause gets
 * routed to the wrong owner -- which has cost this project two cycles already. */
#define SRC_MAX 512
#define SRC_PATH 256

typedef struct {
  char path[SRC_PATH];
  long size;
  long mtime;
} SrcStamp;

static SrcStamp src_before[SRC_MAX], src_after[SRC_MAX];
static unsigned src_n, src_n_after;
static int src_truncated, src_truncated_after;

/* The two roots whose files a twin reads at run time. Declared, not discovered
 * by walking the whole tree: this is a fence, and a fence that costs a full
 * walk of out/ to place itself would be a slower way to say nothing. */
static const char *const SRC_ROOTS[] = {
  "compiler/nova",
  "compiler/c",
};
#define SRC_ROOTS_N ((unsigned)(sizeof SRC_ROOTS / sizeof *SRC_ROOTS))

/* nanoseconds, because a save that lands inside the same second as the first
 * read is exactly the case this fence exists for, and a seconds-resolution
 * stamp would miss every one of them. */
static long stamp_mtime(const struct stat *st) {
  return (long)st->st_mtim.tv_sec * 1000000000L + (long)st->st_mtim.tv_nsec;
}

static void src_collect(SrcStamp *out, unsigned *n, int *truncated) {
  *n = 0;
  *truncated = 0;
  for (unsigned r = 0; r < SRC_ROOTS_N; r++) {
    DIR *d = opendir(SRC_ROOTS[r]);
    struct dirent *de;
    if (!d) continue;
    while ((de = readdir(d)) != 0) {
      char sub[SRC_PATH];
      struct stat st;
      const char *ext = strrchr(de->d_name, '.');
      if (de->d_name[0] == '.') continue;
      /* Only the two kinds a twin can read: a Nova module, and a C translation
       * unit or header. Everything else in these roots -- object files, logs,
       * the built binaries -- is a build artefact whose mtime moves for reasons
       * that have nothing to do with the text a twin compiled. */
      if (!ext) continue;
      if (strcmp(ext, ".nova") && strcmp(ext, ".c") && strcmp(ext, ".h")) continue;
      if (snprintf(sub, sizeof sub, "%s/%s", SRC_ROOTS[r], de->d_name) >= (int)sizeof sub)
        continue;
      if (stat(sub, &st) != 0 || !S_ISREG(st.st_mode)) continue;
      if (*n >= SRC_MAX) { *truncated = 1; closedir(d); return; }
      snprintf(out[*n].path, SRC_PATH, "%s", sub);
      out[*n].size = (long)st.st_size;
      out[*n].mtime = stamp_mtime(&st);
      (*n)++;
    }
    closedir(d);
  }
}

/* Compare the two stamps and name every file that moved. Returns the count, and
 * prints one SOURCES-MOVED line naming them, so the integrator reads the file
 * list instead of hunting for it.
 *
 * The two tables, the two counts and the two overflow flags are PARAMETERS
 * rather than the file scope arrays, and that is not a stylistic choice: it is
 * the only thing that lets the section below drive this function on tables it
 * builds itself. An earlier form reached for src_before/src_after directly,
 * which leaves exactly one way to exercise the fence -- move a real source of
 * the tree while this process is reading it. That is the condition eight
 * sibling lots produce by accident and the one thing no test may produce on
 * purpose: it makes the run red for a reason that has nothing to do with the
 * code, and it costs every other lot a re-run. The call site passes the same
 * two tables the run collected, so the measured path is the tested one.
 *
 * THE BOUNDS ARE THE LOAD-BEARING PART, which is why the counts are named
 * rather than left to be read off the loops. The form this replaces walked the
 * AFTER table with the BEFORE count in three of its four loops, and `src_n`
 * and `src_truncated` were the only two of the four fence variables the
 * function ever read -- `src_n_after` and `src_truncated_after` were written by
 * the call site and never looked at again. That is wrong in both directions
 * and wrong silently:
 *
 *   - a source that APPEARED lands at some index of the after table, and any
 *     index at or past the before count was never examined, so the fence
 *     certified a tree that had gained a file;
 *   - the same table was searched under the before count, so a file that
 *     VANISHED was matched only by reading one entry past what the second
 *     collect wrote -- uninitialised on the first call, stale on every one
 *     after it, and therefore capable of hiding the very file it was there to
 *     find;
 *   - the AFTER collect's overflow flag was never read, so a fence that ran
 *     out of room halfway through the twins reported a still tree.
 *
 * Each table is now walked with its own count and both overflow flags are
 * consulted. All three are cases in check_fence() below, which is the reason
 * to say so here: a bound that is only correct by inspection is a bound that
 * reverts the next time someone edits a loop without reading the comment. */
static int src_moved(const SrcStamp *before, unsigned nb, const SrcStamp *after,
                     unsigned na, int trunc_before, int trunc_after) {
  int moved = 0;
  if (trunc_before || trunc_after) {
    fprintf(stderr, "FAIL SOURCES-MOVED : the source fence holds %u files and the two roots hold "
                    "more, so this run cannot certify that the tree stood still. "
                    "before_truncated=%d after_truncated=%d before_n=%u after_n=%u roots=", SRC_MAX,
            trunc_before, trunc_after, nb, na);
    for (unsigned r = 0; r < SRC_ROOTS_N; r++) fprintf(stderr, " %s", SRC_ROOTS[r]);
    fprintf(stderr, "\n");
    return 1;
  }
  for (unsigned a = 0; a < nb; a++) {
    unsigned b = 0;
    int found = 0;
    for (; b < na; b++)
      if (!strcmp(before[a].path, after[b].path)) { found = 1; break; }
    /* b == na when nothing matched, and after[b] is then outside the filled
     * region, so it is read only behind `found`. Saying so here because the
     * short circuit is the whole safety of the line below it. */
    if (!found || before[a].size != after[b].size ||
        before[a].mtime != after[b].mtime) {
      /* `FAIL` IS THE FIRST TOKEN, and that ordering is the whole point of this
       * line. This fence charged `failures++` at its call site and printed
       * `SOURCES-MOVED`, so a run in which the tree moved read `failures=1`
       * with no `FAIL` line anywhere in its log: the count and the evidence were
       * in the same file, and a reader who greps `^FAIL` -- the one search every
       * reader of this file reaches for, and the reason IDENT-MISSING below
       * carries that prefix -- was told the run was green. Measured on this
       * tree, 30 September 2026: the fourth of four consecutive
       * `NTASM_NOVA_REGISTRY` runs reported `checks=3268 failures=1` and its log
       * held zero `FAIL` lines.
       *
       * The label is kept after the prefix, because it says what KIND of
       * failure this is, and the closing sentence below still says the tree
       * moved rather than a check being wrong. Both are true, and a reader
       * needs both. */
      if (!moved)
        fprintf(stderr, "FAIL SOURCES-MOVED : a source the twins read changed while they were "
                        "reading it, so the counters measured in this run are about a text that no "
                        "longer exists. Each moved file is named with the stamp each side read, so "
                        "the owner of the file can see what changed and when:");
      /* THE TWO INSTANTS, both of them, on the same line as the name. A reader
       * told only THAT a file moved cannot tell a one-nanosecond save from a
       * rewrite, and cannot tell whether the file changed while the twins were
       * reading it or between the two collects for some other reason. These are
       * the stamps this function actually compared, so printing them prints
       * the evidence rather than a summary of it. */
      if (found)
        fprintf(stderr, "\n  %s : size %ld->%ld mtime_ns %ld->%ld",
                before[a].path, before[a].size, after[b].size, before[a].mtime, after[b].mtime);
      else
        fprintf(stderr, "\n  %s : size %ld->VANISHED mtime_ns %ld->VANISHED",
                before[a].path, before[a].size, before[a].mtime);
      moved++;
    }
  }
  for (unsigned a = 0; a < na; a++) {
    unsigned b;
    int found = 0;
    for (b = 0; b < nb; b++)
      if (!strcmp(after[a].path, before[b].path)) { found = 1; break; }
    if (!found) {
      if (!moved)
        fprintf(stderr, "FAIL SOURCES-MOVED : a source the twins read appeared or vanished while "
                        "they were reading it. Each moved file is named with the stamp each side "
                        "read, so the owner of the file can see what changed and when:");
      fprintf(stderr, "\n  %s : size APPEARED->%ld mtime_ns APPEARED->%ld",
              after[a].path, after[a].size, after[a].mtime);
      moved++;
    }
  }
  if (moved)
    fprintf(stderr, "\n  %d source(s) moved, which is the whole count this failure charges. This "
                    "is not a gate failure: it says the TREE MOVED, not that any check is wrong. "
                    "Re-run once the writers have finished. Reading a moving tree is the defect "
                    "this fence closes -- it is what produced an uninitialised word printed as if "
                    "it were a diagnostic code.\n", moved);
  return moved;
}


/* ============================== the SOURCES-MOVED fence, PROVEN ABLE TO FIRE.
 *
 * Wave 10 built the fence above and its author verified it once, by hand: a
 * source was saved while the twins ran, the fence fired, it named the file.
 * That is one observation in one state, made once, and the whole wave exists
 * because an instrument exercised in a single state has not been tested
 * against the state it exists to detect. A fence that has only ever been seen
 * firing is a fence whose QUIET path is untested, and the quiet path is the
 * one every green in this repository depends on -- a fence that cried wolf
 * would be ignored, and a fence that never fired would certify a moving tree.
 * Both are the same defect wearing different clothes.
 *
 * WHY IT IS IN-PROCESS AND NOT A SHELL-OUT, and why this is not a convenience.
 * The honest way to prove a stat fence fires is to move a file between its two
 * collections. Doing that to a real source of the tree would make this run red
 * for a reason that has nothing to do with the code, and -- with eight lots
 * editing the same tree -- it would also race every one of them. So the
 * tables are BUILT here rather than collected, and the function under test is
 * the same function the run calls, with the same arguments, reached through
 * the same `src_moved` the measured path uses. What is synthetic is the
 * input, never the instrument.
 *
 * EVERY CASE IS A STATE THE FENCE EXISTS TO DETECT, and the states are the
 * ones the wave-10 measurement names, plus the ones the code above turned out
 * to get wrong:
 *
 *   STILL        the two stamps identical -- must be quiet.
 *   MTIME        same size, mtime moved by ONE NANOSECOND in the same second.
 *                This is the case the nanosecond stamp exists for and the one
 *                a seconds-resolution fence cannot see.
 *   SIZE         same mtime, different length -- a rewrite that kept the
 *                length, which a size-only fence would miss.
 *   GONE         present before, absent after -- readdir order is not stable,
 *                so an appearing and a vanishing file are separate cases.
 *   ARRIVED      absent before, present after.
 *   ARRIVED-END  the same, with the new file at the LAST index of the after
 *                table. This is the case that measures the bound: the form
 *                this replaces walked the after table with the before count,
 *                so a file that appeared at any index at or past it was
 *                never examined. It is the one case here that is not a
 *                restatement of the author's hand test.
 *   GONE-END     the same for a vanished file at the last before index, which
 *                is the entry the old inner bound read one past.
 *   TRUNC-BEFORE / TRUNC-AFTER  the overflow flag on each side, read
 *                separately because the old form read only the first.
 *
 * And the direction the author's hand test could not reach: each case also
 * asserts what must NOT be named. A fence that reports a still tree is as
 * wrong as one that misses a moving one, and a fence that names every file in
 * the tree is a fence nobody will read. STILL is therefore a case like the
 * others, not a formality. */

static unsigned fence_cases, fence_detected, fence_quiet_cases;

/* One synthetic stamp. The nanosecond field is what makes the MTIME case
 * possible, so the table is filled through the same shape src_collect fills:
 * a size and an mtime in nanoseconds, never a seconds-resolution double. */
static void fence_put(SrcStamp *t, unsigned n, const char *path, long size,
                      long mtime) {
  snprintf(t[n].path, SRC_PATH, "%s", path);
  t[n].size = size;
  t[n].mtime = mtime;
  t[n + 1].path[0] = 0;                 /* terminator for the helpers below */
  t[n + 1].size = 0;
  t[n + 1].mtime = 0;
}

/* Capturing stderr, and the reason the case runners read what a diagnostic
 * PRINTED rather than only what it returned. A check that fires without naming
 * is a red that gets routed to the wrong owner, which is the cost this file's
 * own comment on the fence names -- and the same sentence governs the two
 * instruments that follow it: a class report that does not name the class, and
 * a drift report that does not name the citation that moved, are the same
 * defect as a fence that fires without naming the file.
 *
 * Named `err_` and not `fence_` because the capture is not the fence's: three
 * case runners use it, and a helper wearing the name of its first caller
 * invites the second caller to write its own. */
static FILE *err_sink;
static int err_saved;

/* Both halves must succeed or NEITHER happens. An earlier version redirected
 * whenever tmpfile() succeeded and restored only when dup() had also
 * succeeded, so a failing dup left the gate's stderr pointing into a sink that
 * err_capture_end was about to close: every later diagnostic in this run
 * would have gone into a closed stream, and a red would have arrived with no
 * explanation attached to it. A capture helper that can lose the log is worse
 * than no capture helper, so the two are all-or-nothing. */
static void err_capture_begin(void) {
  fflush(stderr);
  err_sink = tmpfile();
  err_saved = err_sink ? dup(fileno(stderr)) : -1;
  if (err_sink && err_saved >= 0) {
    dup2(fileno(err_sink), fileno(stderr));
    return;
  }
  if (err_sink) { fclose(err_sink); err_sink = NULL; }
  err_saved = -1;
}

static size_t err_capture_end(char *out, size_t cap) {
  fflush(stderr);
  if (err_saved >= 0) {
    dup2(err_saved, fileno(stderr));
    close(err_saved);
    err_saved = -1;
  }
  size_t got = 0;
  if (err_sink) {
    rewind(err_sink);
    got = fread(out, 1, cap - 1, err_sink);
    fclose(err_sink);
    err_sink = NULL;
  }
  out[got] = 0;
  return got;
}

/* The verdict on one case. `want` is the number of files the fence must
 * report, and `named` the substring its output must contain -- NULL for the
 * quiet cases, where any output at all is the failure. */
static void fence_case(const char *label, const SrcStamp *b, unsigned nb,
                       const SrcStamp *a, unsigned na, int tb, int ta,
                       int want, const char *named) {
  char out[4096];
  fence_cases++;
  err_capture_begin();
  int moved = src_moved(b, nb, a, na, tb, ta);
  size_t len = err_capture_end(out, sizeof out);
  cases++;
  checks++;
  if (moved != want) {
    failures++;
    fprintf(stderr, "FAIL fence %s: the fence reported %d moved sources and this case holds %d, "
                    "so the state this fence exists to detect is one it does not detect\n",
            label, moved, want);
    return;
  }
  /* The two quiet cases PASS by saying nothing, so they are counted on the
   * same counter as the ten that pass by firing. An earlier version returned
   * from the quiet branch without counting, and the banner then read 10/12 on
   * a run with zero failures -- a number that looks like a failing score and
   * is not one. The two directions are the same question asked twice, so they
   * are counted the same way. */
  if (want == 0) {
    if (len != 0) {
      failures++;
      fprintf(stderr, "FAIL fence %s: the tree stood still and the fence still spoke: %.180s\n",
              label, out);
      return;
    }
    fence_quiet_cases++;
    fence_detected++;
    return;
  }
  if (named && !has_text(out, len, named)) {
    failures++;
    fprintf(stderr, "FAIL fence %s: the fence fired but did not name %s, and a red that does not "
                    "name its cause is routed to the wrong owner. It said: %.180s\n",
            label, named, out);
    return;
  }
  /* THE PREFIX, and this is the assertion the whole lot exists to install.
   *
   * Every case above proves the fence DETECTS a moving tree and NAMES the file.
   * Neither of those is the defect that was closed here. The defect is that the
   * fence charged `failures++` at its call site while printing a line beginning
   * `SOURCES-MOVED`, so the count in the banner had no `FAIL` line to point at:
   * measured on this tree, a run printed `failures=1` and its log held zero
   * `FAIL` lines. A fence that detects correctly and reports under a prefix no
   * reader searches is an instrument that cannot report its own refusal, which
   * is the same defect as the driver's `errexit` bug one level up.
   *
   * So every firing case now also asserts the FIRST TOKEN of the fence's output
   * is `FAIL`. This is asserted on the real function through the real stderr
   * capture, on all the firing cases at once, because a prefix is a property of
   * the label rather than of any one case -- asserting it once per case would
   * be twelve checks saying one thing. */
  if (!has_text(out, len, "FAIL SOURCES-MOVED")) {
    failures++;
    fprintf(stderr, "FAIL fence %s: the fence fired and charged a failure, but its output does not "
                    "begin with the token FAIL, so a reader who sees failures= in the banner and "
                    "greps ^FAIL finds nothing and cannot tell which check produced the count. It "
                    "said: %.180s\n", label, out);
    return;
  }
  /* BOTH INSTANTS, because naming the file is not the same as saying what
   * changed about it. A one-nanosecond save and a full rewrite produce the same
   * list of paths, and only the stamps tell the owner of the file which of the
   * two happened. Asserted once, here, for every firing case.
   *
   * NOT ASSERTED ON THE TWO TRUNCATION CASES, and that exclusion is the point
   * rather than a gap: a fence that ran out of room holds no pair of stamps to
   * print, because it never held both tables. Those two cases assert the prefix
   * above and the sentence that names the bound, which is the whole of what
   * there is to say about them. Asserting instants on a case that has none would
   * be a check that can only fail, which is the shape this file refuses
   * everywhere else. */
  if (!(tb || ta) && !has_text(out, len, "mtime_ns")) {
    failures++;
    fprintf(stderr, "FAIL fence %s: the fence named the file that moved but not the two instants it "
                    "compared, so the owner of that file cannot tell a one-nanosecond save from a "
                    "rewrite. It said: %.180s\n", label, out);
    return;
  }
  /* Counted last, on the single path where every assertion above held. An
   * earlier version of this line sat at the top of the function, where it
   * counted a case as proved before the case had been judged -- so the
   * FENCE-PROVEN banner read 12/12 with a failing case inside it, which is a
   * green number printed by a red measurement. */
  fence_detected++;
}

/* Copy a table so a case can perturb one entry without rebuilding the pair. */
static void fence_copy(SrcStamp *dst, const SrcStamp *src, unsigned n) {
  for (unsigned k = 0; k <= n; k++) dst[k] = src[k];
}

static void check_fence(void) {
  /* Two fixed stamps in the SAME second, one nanosecond apart. Everything the
   * fence does here is decided by that difference, and it is a difference no
   * seconds-resolution stamp could hold -- which is the whole reason
   * stamp_mtime() multiplies by a billion. */
  const long BASE = 1750000000L * 1000000000L;   /* 2025-06-15, in ns */
  const long NS   = 1000000000L;                /* one second in ns */

  SrcStamp b[8], a[8], b2[8], a2[8];
  memset(b, 0, sizeof b);
  memset(a, 0, sizeof a);

  /* ---- STILL. Three sources, byte and nanosecond identical on both sides. */
  fence_put(b, 0, "compiler/nova/alpha.nova", 101, BASE + 100);
  fence_put(b, 1, "compiler/nova/beta.nova", 202, BASE + 200);
  fence_put(b, 2, "compiler/c/nova/frontend/nova.c", 303, BASE + 300);
  fence_copy(a, b, 3);
  fence_case("STILL", b, 3, a, 3, 0, 0, 0, NULL);

  /* ---- MTIME, one nanosecond apart inside the same second. A seconds
   * resolution fence reads both as the same instant and stays quiet, so this
   * case is the measurement that the nanosecond stamp is load bearing. */
  fence_copy(b2, b, 3);
  fence_copy(a2, b, 3);
  a2[1].mtime = b2[1].mtime + 1;
  fence_case("MTIME", b2, 3, a2, 3, 0, 0, 1, "compiler/nova/beta.nova");

  /* ---- MTIME across a second boundary, the ordinary edit. */
  fence_copy(b2, b, 3);
  fence_copy(a2, b, 3);
  a2[1].mtime = b2[1].mtime + NS;
  fence_case("MTIME-SECOND", b2, 3, a2, 3, 0, 0, 1, "compiler/nova/beta.nova");

  /* ---- SIZE, mtime held identical: a rewrite that kept the length. */
  fence_copy(b2, b, 3);
  fence_copy(a2, b, 3);
  a2[2].size = b2[2].size + 1;
  fence_case("SIZE", b2, 3, a2, 3, 0, 0, 1, "compiler/c/nova/frontend/nova.c");

  /* ---- GONE, from the middle of the table. */
  fence_put(b2, 0, "compiler/nova/alpha.nova", 101, BASE + 100);
  fence_put(b2, 1, "compiler/nova/beta.nova", 202, BASE + 200);
  fence_put(b2, 2, "compiler/c/nova/frontend/nova.c", 303, BASE + 300);
  fence_put(a2, 0, "compiler/nova/alpha.nova", 101, BASE + 100);
  fence_put(a2, 1, "compiler/c/nova/frontend/nova.c", 303, BASE + 300);
  fence_case("GONE", b2, 3, a2, 2, 0, 0, 1, "compiler/nova/beta.nova");

  /* ---- ARRIVED, in the middle of the table. */
  fence_put(b2, 0, "compiler/nova/alpha.nova", 101, BASE + 100);
  fence_put(b2, 1, "compiler/nova/beta.nova", 202, BASE + 200);
  fence_put(a2, 0, "compiler/nova/alpha.nova", 101, BASE + 100);
  fence_put(a2, 1, "compiler/nova/beta.nova", 202, BASE + 200);
  fence_put(a2, 2, "compiler/nova/gamma.nova", 404, BASE + 400);
  fence_case("ARRIVED", b2, 2, a2, 3, 0, 0, 1, "compiler/nova/gamma.nova");

  /* ---- ARRIVED-END, THE BOUND. Two before, three after, the new file at the
   * last index. The form this replaces iterated the after table with the
   * before count, so index 2 was never examined and this case was invisible to
   * it: the fence certified a tree that had gained a source. */
  fence_put(b2, 0, "compiler/nova/alpha.nova", 101, BASE + 100);
  fence_put(b2, 1, "compiler/nova/beta.nova", 202, BASE + 200);
  fence_put(a2, 0, "compiler/nova/alpha.nova", 101, BASE + 100);
  fence_put(a2, 1, "compiler/nova/beta.nova", 202, BASE + 200);
  fence_put(a2, 2, "compiler/c/nova/frontend/nova.c", 303, BASE + 300);
  fence_case("ARRIVED-END", b2, 2, a2, 3, 0, 0, 1, "compiler/c/nova/frontend/nova.c");

  /* ---- GONE-END, the mirror. Three before, two after: the file that vanished
   * is the last entry of the before table, and the old inner bound searched
   * the after table up to the before count, so it read one entry past what the
   * second collect wrote. */
  fence_put(b2, 0, "compiler/nova/alpha.nova", 101, BASE + 100);
  fence_put(b2, 1, "compiler/nova/beta.nova", 202, BASE + 200);
  fence_put(b2, 2, "compiler/c/nova/frontend/nova.c", 303, BASE + 300);
  fence_put(a2, 0, "compiler/nova/alpha.nova", 101, BASE + 100);
  fence_put(a2, 1, "compiler/nova/beta.nova", 202, BASE + 200);
  fence_case("GONE-END", b2, 3, a2, 2, 0, 0, 1, "compiler/c/nova/frontend/nova.c");

  /* ---- BOTH, and the count is what is asserted: a fence that reports one
   * moved file when three moved has still not certified anything. */
  fence_copy(b2, b, 3);
  fence_copy(a2, b, 3);
  a2[0].mtime = b2[0].mtime + 1;
  a2[1].mtime = b2[1].mtime + 1;
  a2[2].size = b2[2].size + 7;
  fence_case("BOTH", b2, 3, a2, 3, 0, 0, 3, "compiler/c/nova/frontend/nova.c");

  /* ---- TRUNC, one flag at a time. Both are read; the form this replaces
   * read only the before flag, so a fence that overflowed during the AFTER
   * collect reported a still tree. */
  fence_copy(b2, b, 3);
  fence_copy(a2, b, 3);
  fence_case("TRUNC-BEFORE", b2, 3, a2, 3, 1, 0, 1, "cannot certify");
  fence_copy(b2, b, 3);
  fence_copy(a2, b, 3);
  fence_case("TRUNC-AFTER", b2, 3, a2, 3, 0, 1, 1, "cannot certify");

  /* ---- EMPTY on both sides: a tree that held nothing in these two roots
   * moved nothing, and must not be reported. */
  fence_case("EMPTY", b, 0, a, 0, 0, 0, 0, NULL);

  /* The quiet cases are the ones the hand test could not reach, so their
   * count is announced rather than implied: a suite check that can only fail
   * in one direction has not been shown to fail in the other. */
  if (fence_quiet_cases < 2) {
    failf("the fence self-test ran %u quiet cases and a fence that cannot stay quiet on a still "
          "tree is a fence that gets ignored, so the STILL and EMPTY cases must both pass",
          fence_quiet_cases);
  } else {
    good();
  }
  /* THE BANNER CARRIES THE FIELD, checked by running the emitter and reading
   * what it wrote rather than by reading its source. The reason is that
   * `fence_moved` exists so a reader can tell a void measurement from a real
   * red, and a field that is declared and then never printed leaves the reader
   * exactly where this lot found them: a count with nothing to attribute it
   * to. A source-level grep for the word would pass on a comment; this runs
   * the function.
   *
   * It is asserted HERE, on stdout rather than stderr, because the banner is
   * the one artefact of this run that a reader is guaranteed to see: it is
   * what the driver re-emits, what the spec compares, and what a failing run
   * is identified by. */
  {
    char got[1024];
    size_t glen = 0;
    unsigned saved_checks = checks, saved_fail = failures, saved_cases = cases;
    unsigned saved_moved = fence_moved;
    int saved_fd;
    fflush(stdout);
    /* Captured through a real file rather than a memory stream because reg_banner
     * writes to `stdout` by name, and the point of the check is to read what the
     * real emitter put on the real stream. dup2 rather than freopen, so the
     * restore is a dup2 back onto the saved descriptor and cannot leave stdout
     * pointing at a closed file -- the same all-or-nothing shape err_capture_
     * begin/end has, and for the same reason. */
    FILE *sink = tmpfile();
    saved_fd = sink ? dup(fileno(stdout)) : -1;
    if (sink && saved_fd >= 0) {
      dup2(fileno(sink), fileno(stdout));
      /* Two runs of the emitter: the one a reader will see on a clean tree, and
       * one with a fence charge, because the field is only meaningful if it is
       * not hard-wired to zero. The counters are restored below either way --
       * an emitter that moved the real counters would be a second defect, and
       * this check must not become the thing that causes it. */
      fence_moved = 0;
      reg_banner();
      fence_moved = 3;
      reg_banner();
      fflush(stdout);
      dup2(saved_fd, fileno(stdout));
      close(saved_fd);
      rewind(sink);
      glen = fread(got, 1, sizeof got - 1, sink);
      got[glen] = 0;
      fclose(sink);
      /* Only the SECOND line is kept: the one with the non-zero fence count. The
       * first is the clean-tree banner, and asserting on it as well would prove
       * the same thing twice. */
      char *nl = strchr(got, '\n');
      if (nl) {
        size_t skip = (size_t)(nl - got) + 1;
        glen -= skip;
        memmove(got, got + skip, glen);
        got[glen] = 0;
      }
    } else {
      if (sink) fclose(sink);
      if (saved_fd >= 0) close(saved_fd);
      got[0] = 0;
    }
    checks = saved_checks; failures = saved_fail; cases = saved_cases;
    fence_moved = saved_moved;
    cases++;
    checks++;
    if (!has_text(got, glen, "fence_moved=3")) {
      failures++;
      fprintf(stderr, "FAIL fence-BANNER: the banner does not carry the number of failures charged "
                      "because the tree moved. It read: %.200s. Without that field a reader who sees "
                      "failures= in the banner cannot tell a void measurement from a real red, which "
                      "is the whole reason this lot exists.\n", got);
    } else if (!has_text(got, glen, "NTASM_NOVA_REGISTRY checks=")) {
      failures++;
      fprintf(stderr, "FAIL fence-BANNER: the banner does not begin with the name and the three "
                      "counters its established readers parse. It read: %.200s\n", got);
    } else good();
  }
  /* The score is DETECTED over CASES, not cases over cases. A banner that
   * prints the same number twice reads 12/12 whether twelve cases passed or
   * one of them did not, and a reader who trusts it is exactly the reader this
   * file keeps refusing to make. */
  printf("FENCE-PROVEN %2u/%2u states detected, %u quiet\n", fence_detected,
         fence_cases, fence_quiet_cases);
}



/* ================================================================== U27: the
 * class, which is the half of the citation report nobody had.
 *
 * THE PREMISE, MEASURED, AND IT IS FALSE. A run of this gate, unmodified, over
 * a copy of the document carrying four synthetic citations, in the cold build
 * directory w13refs-a1:
 *
 *   IDENT-MISSING spec/ntasm/ntasm.md:2574 cites compiler/nova/frontend/stub_table.nova:31-31
 *                and names `zzz_w13_absent_symbol` beside it, which is nowhere in
 *                that range of compiler/nova/frontend/stub_table.nova
 *   FAIL spec/ntasm/ntasm.md:2575 cites scripts/ntbuild.sh:12-12 and no file of the tree has
 *                that name; the search covered . toolchain/ bootstrap/ spec/ docs/
 *                examples/ os/ out/c-bootstrap/
 *   REFERENCES-CONTENT ... ident_covered=19 ident_tokens=20 ident_missing=1
 *
 * So the instrument DOES emit the offending citations, for both classes, with
 * the document line, the target, the range and the token. "Emit the citations
 * alongside the count" -- the first of the two candidates -- is therefore not
 * the work; it is already in the tree, and the U27 row describes a state of the
 * instrument that has since been overtaken by it.
 *
 * WHAT IS STILL MISSING IS THE CLASS, and the same run is the measurement of
 * what it costs. Those four failures are three different things: one bad
 * token, two citations into a directory the declared scope does not search,
 * and one name that is nowhere at all. The log hands the author four tickets
 * for three causes, and the two `scripts/` lines read exactly like "you cited a
 * file that does not exist" when the file is on disk and has been all evening.
 * Seven such citations are seven things to fix; they are one decision about
 * what the declared scope is.
 *
 * SO: the report below groups the unresolved citations and names the cause,
 * and it changes NO verdict. `REFERENCES missing=` keeps the number it has and
 * every FAIL still fires where it fired before, with the same wording. What is
 * added is the reading over the set, printed once per class, so the log says
 * what to do rather than where to look.
 *
* THE SCOPE IS NOW WIDENED, and it is this file's decision after all. `scripts`
* and `tools` are REF_ROOTS as of 30 September 2026, marked artefact=0 like any
* other place sources live. What stood here said the opposite -- that widening
* was "a decision above this file" -- and that sentence is RETRACTED, in place,
* with the measurement that refutes it. It was not wrong about the fact; it was
* wrong to leave the fact standing where a reader looks for the reason a thing
* is not done, because a refusal with no owner is a refusal nobody can overrule,
* and so is a refusal that does not survive the next person to read it.
*
* WHY IT WAS RULED, and the reason is not the one that stood here. That reason
* was about SRC_ROOTS, the fence that stops a citation being judged against a
* text being rewritten under the run. It was already retracted above as a fact
* about the fence offered as a reason about the resolver, and it stays
* retracted: SRC_ROOTS is NOT widened by this edit. It still watches
* `compiler/nova` and `compiler/c` and nothing else, and the
* gap between the two scopes is now real. It is stated here rather than papered
* over: a citation into `scripts/` is judged against a file this fence does not
* watch. That is a known, accepted consequence of widening the resolver and not
* an oversight, and the next reader must not have to rediscover it.
*
* THE MEASUREMENT THAT SETTLED IT, which is about what GREEN MEANS and is worth
* more than any argument about scope. Measured on the widened gate, 30 September
* 2026: `artefact_cited` 8 -> 2, `artefact_only` 4 -> 2, `stale_lines` 2 -> 0,
* and one NEW FAIL, `IDENT-MISSING spec/ntasm/ntasm.md:2970`, because
* `scripts/ntbuild.sh:105-516` is written in SNAPSHOT line numbers --
* `RECORDED_EXAMPLES` is at 105 of the copy and 176 of the live file,
* `cmd_corpus` at 516 of the copy and 672 of the live file. The trade is two
* artefacts for one true finding.
*
* THE TWO ARTEFACTS THIS REMOVES ARE ARTEFACTS, and the argument for widening
* is that they were costing the instrument its authority. `docs/status/ntasm-completion.md`
* cites `scripts/ntbuild.sh:53-70`, `scripts/ntbuild.sh:184` and
* `scripts/ntselfhost.sh:606-617`; all three are written in LIVE line numbers
* and all three are CORRECT against the live file, and the snapshot was the only
* reason the resolver raised STALE-LINE on them. A resolver that flags correct
* citations is a resolver whose output a reader learns to skip, and that is not
* a cosmetic cost -- it is why the two flags sat in the register as "reported,
* not failed" instead of as findings. They are NOT silenced by any code path
* here; removing the cause removed them, and the record of them is this comment.
*
* AND THE FINDING WAS NOT CREATED BY THIS EDIT. It was in the tree the whole
* time and the snapshot was hiding it. A citation that is green only because it
* resolves to the wrong EDITION of the file is not green: its correctness is a
* property of a copy under `out/`, and `out/` is the one place in this tree that
* is explicitly disposable. A stale line is at least about the RIGHT file. This
* was not.
 *
 * THE PROBE'S OWN SCOPE, because a class report that is wrong about a name is
 * worse than no class report. It walks the top-level directories the declared
 * scope does not search AT ALL -- `scripts` and `verifieur` today, whatever
 * else the repository grows. It does not walk a root the scope covers only in
 * part: `out/` is searched as `out/c-bootstrap` and not further, because a walk
 * of all of out/ was MEASURED at 15s of CPU and 2m48s of wall clock on this
 * mount, and a diagnostic that costs three minutes to say "not found" is a
 * diagnostic nobody runs. A name that exists under the unsearched part of a
 * covered root is therefore reported ABSENT, which is a statement about the
 * scope and the excluded directories, not about the tree, and the wording says
 * exactly that rather than the word "nowhere". */
#define OUTPROBE_MAX 8
#define PROBE_MAX_DEPTH 8
#define PROBE_MAX_DIRS 2000
#define PROBE_MAX_FILES 40000

typedef struct {
  char dir[REF_PATH];                  /* the top-level directory            */
  char path[UNRES_MAX][REF_PATH];      /* where each hit was actually found  */
  unsigned char hit[UNRES_MAX];        /* per unresolved citation            */
  unsigned nfound;
} OutProbe;

static OutProbe outprobe[OUTPROBE_MAX];
static unsigned outprobe_n, probe_dirs, probe_files;
static int probe_truncated;

/* Does the declared scope search a top-level directory at all? "out" is
 * covered by the root "out/c-bootstrap" and counts as covered: the point is to
 * find the directories the scope never enters, not to re-search a partial
 * one. */
static int ref_root_covers_entry(const char *e) {
  size_t n = strlen(e);
  for (unsigned r = 0; r < REF_ROOTS_N; r++) {
    const char *p = REF_ROOTS[r].path;
    if (p[0] == '\0') continue;                  /* the root's own files */
    if (strncmp(p, e, n) == 0 && p[n] == '/') return 1;
  }
  return 0;
}

static void out_probe_walk(const char *rel, int depth, unsigned pi) {
  char abs[REF_PATH];
  DIR *d;
  struct dirent *de;
  if (probe_truncated) return;
  snprintf(abs, sizeof abs, "%s", *rel ? rel : ".");
  d = opendir(abs);
  if (!d) return;
  if (++probe_dirs > PROBE_MAX_DIRS) { probe_truncated = 1; closedir(d); return; }
  while ((de = readdir(d)) != 0) {
    char sub[REF_PATH];
    struct stat st;
    DIR *probe;
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..") || !strcmp(de->d_name, ".git"))
      continue;
    if (snprintf(sub, sizeof sub, "%s/%s", rel, de->d_name) >= (int)sizeof sub) {
      probe_truncated = 1;
      break;
    }
    probe = depth < PROBE_MAX_DEPTH ? opendir(sub) : NULL;
    if (probe) {
      closedir(probe);
      out_probe_walk(sub, depth + 1, pi);
      if (probe_truncated) break;
      continue;
    }
    if (lstat(sub, &st) != 0 || !S_ISREG(st.st_mode)) continue;
    if (++probe_files > PROBE_MAX_FILES) { probe_truncated = 1; break; }
    for (unsigned u = 0; u < unres_n; u++) {
      if (outprobe[pi].hit[u] || probe_truncated) continue;
      if (!ends_with_name(sub, unres[u].name)) continue;
      if (outprobe[pi].nfound >= UNRES_MAX) { probe_truncated = 1; break; }
      snprintf(outprobe[pi].path[outprobe[pi].nfound], REF_PATH, "%s", sub);
      outprobe[pi].nfound++;
      outprobe[pi].hit[u] = 1;
    }
  }
  closedir(d);
}

/* Only ever run when there is something to classify, which on a correct
 * document is never: the cost of this instrument is paid out of the
 * unresolved set, and a green run pays none of it. */
static void scope_probe(void) {
  DIR *d = opendir(".");
  struct dirent *de;
  outprobe_n = probe_dirs = probe_files = 0;
  probe_truncated = 0;
  if (!d) { probe_truncated = 1; return; }
  while ((de = readdir(d)) != 0) {
    char sub[REF_PATH];
    struct stat st;
    if (de->d_name[0] == '.') continue;                  /* ., .., .git */
    if (ref_root_covers_entry(de->d_name)) continue;
    if (snprintf(sub, sizeof sub, "%s", de->d_name) >= (int)sizeof sub) continue;
    if (stat(sub, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
    if (outprobe_n >= OUTPROBE_MAX) { probe_truncated = 1; break; }
    snprintf(outprobe[outprobe_n].dir, REF_PATH, "%s", de->d_name);
    outprobe_n++;
    out_probe_walk(de->d_name, 1, outprobe_n - 1);
    if (probe_truncated) break;
  }
  closedir(d);
}

static int outprobe_has(const OutProbe *p, unsigned pn, unsigned u) {
  for (unsigned i = 0; i < pn; i++)
    if (p[i].hit[u]) return 1;
  return 0;
}

/* THE REPORT, as a pure function of the two tables so that the case runner
 * below can drive it on states no document produces today. `u` is what the run
 * found unresolved, `p` is where the probe found each of them, and the report
 * claims nothing it was not given: a name no probe covers is ABSENT, and a
 * truncated probe turns that claim into UNKNOWN rather than leaving a word the
 * instrument cannot support. */
/* The table holds TWO kinds now and they are not the same finding, so they are
 * reported separately and the hardcoded document name that stood here for
 * every citation is gone: the second document's citations were being printed
 * with the FIRST document's filename, which is a report that lies about where
 * a ticket has to be filed. `u[i].doc` is recorded at the point the citation
 * was judged for exactly that reason. */
static const char *unres_docname(unsigned d) {
  return ref_doc[d] ? ref_doc[d] : "the document";
}

static void ref_report_unresolved(const UnresRef *u, unsigned un,
                                  const OutProbe *p, unsigned pn, int truncated) {
  unsigned classes = 0, absent = 0, copied = 0, unresolved = 0;
  if (un == 0) return;
  for (unsigned i = 0; i < un; i++) { if (u[i].copied) copied++; else unresolved++; }
  /* THE COPIES FIRST, because they are the ones that were green. A citation in
   * this class resolved, was read, and was judged -- against build output. The
   * probe then says where the real file is, which is the sentence the log has
   * never been able to produce for them. */
  if (copied) {
    classes++;
    fprintf(stderr, "REF-CLASS copied %u : %u citation%s RESOLVED, and every file of the declared "
                    "scope that answers to the name is build output under out/c-bootstrap. These are "
                    "not missing, which is why nothing above was red; they are pointing at a COPY of "
                    "the file the sentence names, and a verdict read off a copy is agreement this "
                    "check did not establish:\n",
            copied, copied, copied == 1 ? "" : "s");
    for (unsigned i = 0; i < un; i++) {
      if (!u[i].copied) continue;
      const char *where = NULL;
      for (unsigned pi = 0; pi < pn && !where; pi++)
        for (unsigned m = 0; m < p[pi].nfound; m++)
          if (ends_with_name(p[pi].path[m], u[i].name)) { where = p[pi].path[m]; break; }
      fprintf(stderr, "    %s:%u cites %s:%u-%u, it resolved to %s, and %s\n",
              unres_docname(u[i].doc), u[i].line, u[i].name, u[i].lo, u[i].hi, u[i].at,
              where ? "the file the sentence means is at a path the declared scope does not search"
                    : "no source in the repository answers to that name at all");
    }
  }
  for (unsigned pi = 0; pi < pn; pi++) {
    unsigned k = 0;
    for (unsigned i = 0; i < un; i++) if (p[pi].hit[i]) k++;
    if (!k) continue;
    classes++;
    fprintf(stderr, "REF-CLASS out-of-scope %s/ : %u citation%s name a file that EXISTS in the "
                    "repository and that the declared scope of this check does not search. That is "
                    "ONE decision about the scope, not %u edit%s:\n",
            p[pi].dir, k, k == 1 ? "" : "s", k, k == 1 ? "" : "s");
    for (unsigned i = 0; i < un; i++) {
      const char *where = NULL;
      if (!p[pi].hit[i]) continue;
      for (unsigned m = 0; m < p[pi].nfound; m++)
        if (ends_with_name(p[pi].path[m], u[i].name)) { where = p[pi].path[m]; break; }
      fprintf(stderr, "    %s:%u cites %s:%u-%u, and the file is at %s%s\n",
              unres_docname(u[i].doc), u[i].line, u[i].name, u[i].lo, u[i].hi,
              where ? where : p[pi].dir,
              u[i].copied ? " -- AND this citation was judged against a copy of it, not against it" : "");
    }
  }
  for (unsigned i = 0; i < un; i++)
    if (!u[i].copied && !outprobe_has(p, pn, i)) absent++;
  if (absent) {
    classes++;
    if (truncated) {
      fprintf(stderr, "REF-CLASS unknown : %u further citation%s name a file the declared scope "
                      "does not have; the probe of the excluded top-level directories stopped on "
                      "its budget of %u directories, so NO name is claimed absent here\n",
              absent, absent == 1 ? "" : "s", PROBE_MAX_DIRS);
    } else {
      if (absent == 1)
        fprintf(stderr, "REF-CLASS absent : 1 citation names a file that the declared scope does not "
                        "have and that no directory the scope excludes holds either. That is one name "
                        "to look for in the tree, and it is a cause of its own:\n");
      else
        fprintf(stderr, "REF-CLASS absent : %u citations name files that the declared scope does not "
                        "have and that no directory the scope excludes holds either. They are %u "
                        "causes of their own, and none of them shares a fix with another:\n", absent, absent);
      for (unsigned i = 0; i < un; i++) {
        if (u[i].copied || outprobe_has(p, pn, i)) continue;
        fprintf(stderr, "    %s:%u cites %s:%u-%u\n",
                unres_docname(u[i].doc), u[i].line, u[i].name, u[i].lo, u[i].hi);
      }
    }
  }
  fprintf(stderr, "REF-CLASS summary citations=%u classes=%u copied=%u unresolved=%u : a citation "
                  "that resolves to a COPY is a third thing and is neither of the two this summary "
                  "used to be able to say, and it is the quietest of the three. limits=probe_covers_"
                  "only_top_level_dirs_the_scope_excludes_entirely(out_is_searched_as_out/c-bootstrap_"
                  "only); verdict:unchanged_by_this_report\n",
          un, classes, copied, unresolved);
}

/* ================================================================== U28: the
 * run that certifies the moment it ran.
 *
 * The limit, in the document's own words: a citation into a file being edited
 * drifts between two runs, and the check certifies the state it ran against,
 * not the state of the next run. So `ident_missing=0` means the document was
 * healthy when this gate looked at it, and the banner reads like a health
 * bulletin because that is the shape of the sentence.
 *
 * WHAT IS BUILT HERE, and nothing beyond it: the per-citation verdicts this
 * run produced are written to a small state file, and the next run compares
 * them with the file the previous run left and NAMES every citation that
 * moved. The five movements it distinguishes are the five a reader would
 * otherwise have to diff by hand:
 *
 *   moved      the same sentence now cites a different range -- the wave-12
 *              event, a script that grew 45 lines and three citations with it;
 *   shifted    the citation is identical and only the line of the document it
 *              sits on moved, so nothing is wrong and the log says so;
 *   verdict    the citation is byte-identical and its VERDICT changed: the
 *              tree moved under a sentence that did not;
 *   repointed  the name now resolves to a different file, which is what
 *              happens when a shallower copy of a name appears in the tree;
 *   added / dropped
 *              the citation set itself changed.
 *
 * AND IT SAYS SO WHEN IT HAS NOTHING TO COMPARE WITH, which is the whole of
 * the honesty question this limit raises. A run that finds no previous state
 * does NOT print `drift=0`: it prints `drift=baseline`, in the banner and on
 * stderr, because a first run has compared this run to nothing and a green
 * reading of that would be `stale_lines=0` again wearing a new hat. The
 * refusal itself is proved the way the corpus self-host check proves its own
 * -- a state recorded by the very process that is reading it is refused
 * outright, with the reason, because comparing a run with itself would pass
 * whatever it emits.
 *
 * WHAT IT IS NOT, stated in the banner's own `limits=`: two runs say something
 * about the interval BETWEEN them and nothing whatever about the interval
 * that follows this one. The interval is only as long as the gap between two
 * integrations, and a run that repeats itself inside one integration compares
 * two runs whose separation is however long the gate took to run -- so the
 * two run clocks are printed on the summary line and a reader can see what
 * separation they are being asked to believe in. That is the difference
 * between this check and a self-comparison, and it is visible rather than
 * asserted. */
#define DRIFT_STATE_DIR  "out/c-bootstrap/nova"
#define DRIFT_STATE_PATH DRIFT_STATE_DIR "/registry-citation-state"
/* v2, and the version is not decoration: v1 of this file put four header keys
 * on one line, which a strict per-line reader cannot see. A format that changes
 * must change its magic, or a state written by the old one parses as a state of
 * the new one that happens to be missing its identity -- and the reader would
 * then REFUSE a file it should merely not have a baseline from, which is the
 * difference between a word and a red. */
#define DRIFT_MAGIC      "# NTASM registry citation state v2"
#define DRIFT_CIT_MAX    REF_MAX
#define DRIFT_TEXT_MAX   (1u << 19)

typedef struct {
  unsigned line, lo, hi;
  char flags[8];              /* seven slots, a letter or '.', fixed width  */
  char pick[REF_PATH];        /* the file it resolved to, "-" for none      */
  char name[NAME_MAX];
} DriftCit;

typedef struct {
  long run_start;
  unsigned pid;
  unsigned long doc_bytes, doc_hash;
  int have_run;
  DriftCit cit[DRIFT_CIT_MAX];
  unsigned n;
} DriftState;

enum {
  DRIFT_OK = 0,
  DRIFT_ABSENT,    /* no state file: a first run, which compares nothing   */
  DRIFT_FOREIGN,   /* a state written by something that is not this gate   */
  DRIFT_CORRUPT,   /* this gate's own state, unreadable: a defect HERE     */
  DRIFT_TOOMANY    /* more citations than the state can hold                */
};

static DriftState drift_prev;
static DriftState drift_cur;
static int drift_prev_outcome;
static const char *drift_prev_why = "";
static long drift_run_start;
static unsigned drift_pid;
static unsigned long drift_doc_bytes, drift_doc_hash;

/* FNV-1a over the document bytes. The identity of the prose is what decides
 * whether a drift belongs to the text or to the tree, and a size is not an
 * identity: a wave of edits that happens to keep the byte count would make
 * every drift read as the author's. */
static unsigned long fnv1a(const char *t, size_t n) {
  unsigned long h = 1469598103934665603UL;
  for (size_t i = 0; i < n; i++) {
    h ^= (unsigned char)t[i];
    h *= 1099511628211UL;
  }
  return h;
}

/* The state of THIS run, from the verdicts the three loops above recorded. Not
 * re-derived: the point of keeping ref_verdict_flags was that this writer and the
 * three judges cannot disagree. */
static void drift_build_current(const char *spec, size_t n) {
  drift_doc_bytes = (unsigned long)n;
  drift_doc_hash = fnv1a(spec, n);
  drift_cur.n = 0;
  for (unsigned q = 0; q < refs_n; q++) {
    /* Document 0 ONLY, and this is a decision rather than an omission. The
     * state file's identity is one document's bytes and one document's
     * citations: `doc_hash` is the hash of spec/ntasm/ntasm.md and `doc_bytes` its
     * size, so a second document's citations in the same list would be
     * compared against a state whose header says the run was about a different
     * text. The two documents have separate lifetimes -- the spec is rewritten
     * by other lots during a wave, the completion document far more rarely --
     * and one state per document identity is what keeps the comparison
     * meaningful for both. The second document's citations are still judged
     * every run; what they are not is in the notebook. */
    if (ref_which[q] != 0) continue;
    DriftCit *c;
    int g = target_of(ref_target[q], strlen(ref_target[q]));
    if (drift_cur.n >= DRIFT_CIT_MAX) continue;   /* refusal is the reader's */
    c = &drift_cur.cit[drift_cur.n++];
    c->line = ref_line[q];
    c->lo = ref_lo[q];
    c->hi = ref_hi[q];
    snprintf(c->name, NAME_MAX, "%s", ref_target[q]);
    c->flags[0] = (ref_verdict_flags[q] & V_STALE) ? 'S' : '.';
    c->flags[1] = (ref_verdict_flags[q] & V_UNRESOLVED) ? 'U' : '.';
    c->flags[2] = (ref_verdict_flags[q] & V_SPAN_BLANK) ? 'B' : '.';
    c->flags[3] = (ref_verdict_flags[q] & V_SPAN_COMMENT) ? 'C' : '.';
    c->flags[4] = (ref_verdict_flags[q] & V_IDENT_MISSING) ? 'M' : '.';
    c->flags[5] = (ref_verdict_flags[q] & V_BUDGET) ? 'T' : '.';
    c->flags[6] = (ref_verdict_flags[q] & V_IDENT_COVERED) ? '+' : '.';
    c->flags[7] = 0;
    if (g >= 0 && tgt_nmatch[g])
      snprintf(c->pick, REF_PATH, "%s", tgt_match[g][tgt_pick[g]]);
    else
      snprintf(c->pick, REF_PATH, "-");
  }
  drift_cur.run_start = drift_run_start;
  drift_cur.pid = drift_pid;
  drift_cur.doc_bytes = drift_doc_bytes;
  drift_cur.doc_hash = drift_doc_hash;
  drift_cur.have_run = 1;
}

/* ONE KEY PER LINE, which the first version of this writer did not do: it
 * wrote `run_start=... pid=... doc_bytes=... doc_hash=...` on a single line,
 * and the reader -- which is strict, and matches a key at the START of a line
 * so that an unknown line cannot be half a key -- therefore read the pid, the
 * size and the identity of the document as absent. The round-trip case caught
 * it on its first execution, and the consequence was not a crash: `doc_hash`
 * came back as zero on every read, so `doc=` in the summary would have said
 * `changed` on every run of an unchanging document, and the one clause that
 * decides whether a drift belongs to the prose or to the tree would have been
 * permanently, silently wrong. */
/* SIXTEEN DIGITS, and the second half of a bug the first half of this writer
 * had. It wrote `%08lx` of a value masked to 32 bits while the comparison used
 * all 64, so the two sides of `doc=` were different numbers BY CONSTRUCTION on
 * every run: `doc=changed` was a constant, printed over and over, and the
 * clause that decides whether a drift belongs to the prose or to the tree was
 * permanently, silently wrong. The banner now prints both identities, which is
 * what made it visible in one run: `doc=changed:e98c2553->8110914de98c2553` is
 * a reader being shown two numbers that were never going to be equal. */
static size_t drift_render(const DriftState *s, char *out, size_t cap) {
  int k = snprintf(out, cap, "%s\nrun_start=%ld\npid=%u\ndoc_bytes=%lu\ndoc_hash=%016lx\n",
                   DRIFT_MAGIC, s->run_start, s->pid, s->doc_bytes, s->doc_hash);
  size_t at = (k > 0 && (size_t)k < cap) ? (size_t)k : cap;
  for (unsigned i = 0; i < s->n && at + 1 < cap; i++) {
    const DriftCit *c = &s->cit[i];
    k = snprintf(out + at, cap - at, "cit %u %u %u %s %s %s\n", c->line, c->lo, c->hi,
                 c->flags, c->name, c->pick);
    if (k < 0 || (size_t)k >= cap - at) { at = cap - 1; break; }
    at += (size_t)k;
  }
  return at;
}

/* STRICT, and the strictness is the point. Every line must be one of the five
 * shapes this writer emits, a citation must carry seven flags and a plausible
 * range, and a text that runs past DRIFT_CIT_MAX is REFUSED rather than
 * truncated: a state that parsed as a shorter document would report the
 * citations past the cut as `dropped` and the ones before it as untouched,
 * which is a complete-looking verdict over a partial read. A state this gate
 * cannot read is a defect HERE and is failed; a state written by something
 * that is not this gate is not a defect, it is a baseline we do not have. */
static int drift_parse(const char *text, size_t n, DriftState *s, const char **why) {
  size_t i = 0;
  int seen_magic = 0;
  memset(s, 0, sizeof *s);
  while (i < n) {
    const char *b = text + i;
    size_t l = 0, consumed = 0, rest;
    const char *nm, *sp;
    unsigned line, lo, hi;
    char flags[16], linebuf[1024];
    while (i + l < n && text[i + l] != '\n') l++;
    i += l + 1;
    if (l == 0) continue;
    /* The line is copied out before it is parsed, and that is a correctness
     * requirement rather than tidiness: sscanf on a pointer into the middle of
     * the file reads to the next NUL, not to the end of the LINE, so a short
     * citation line would take its numbers from the line below it. */
    if (l >= sizeof linebuf) { *why = "a line longer than any this gate writes"; return DRIFT_CORRUPT; }
    memcpy(linebuf, b, l);
    linebuf[l] = 0;
    b = linebuf;
    if (!seen_magic) {
      if (l != strlen(DRIFT_MAGIC) || memcmp(b, DRIFT_MAGIC, l) != 0) {
        *why = "first_line_is_not_this_gates_magic";
        return DRIFT_FOREIGN;
      }
      seen_magic = 1;
      continue;
    }
    if (l > 10 && !memcmp(b, "run_start=", 10)) { s->run_start = strtol(b + 10, 0, 10); s->have_run |= 1; continue; }
    if (l > 4 && !memcmp(b, "pid=", 4)) { s->pid = (unsigned)strtoul(b + 4, 0, 10); s->have_run |= 2; continue; }
    if (l > 10 && !memcmp(b, "doc_bytes=", 10)) { s->doc_bytes = strtoul(b + 10, 0, 10); continue; }
    if (l > 9 && !memcmp(b, "doc_hash=", 9)) { s->doc_hash = strtoul(b + 9, 0, 16); continue; }
    if (!(l > 4 && !memcmp(b, "cit ", 4))) { *why = "a line this gate did not write"; return DRIFT_CORRUPT; }
    if (sscanf(b, "cit %u %u %u %15s %n", &line, &lo, &hi, flags, (int *)&consumed) != 4) {
      *why = "a citation line that does not parse";
      return DRIFT_CORRUPT;
    }
    if (strlen(flags) != 7) { *why = "a citation whose flag field is not seven slots"; return DRIFT_CORRUPT; }
    if (lo < 1 || hi < lo) { *why = "a citation with an impossible range"; return DRIFT_CORRUPT; }
    if (s->n >= DRIFT_CIT_MAX) { *why = "more citations than the state can hold"; return DRIFT_TOOMANY; }
    rest = l - consumed;
    nm = b + consumed;
    sp = memchr(nm, ' ', rest);
    if (!sp || (size_t)(sp - nm) == 0 || (size_t)(sp - nm) >= NAME_MAX) {
      *why = "a citation line with no name";
      return DRIFT_CORRUPT;
    }
    {
      DriftCit *c = &s->cit[s->n++];
      const char *pk;
      size_t nl = (size_t)(sp - nm);
      c->line = line;
      c->lo = lo;
      c->hi = hi;
      memcpy(c->name, nm, nl);
      c->name[nl] = 0;
      memcpy(c->flags, flags, 8);
      pk = sp + 1;
      while (pk < b + l && *pk == ' ') pk++;
      if (pk >= b + l) snprintf(c->pick, REF_PATH, "-");
      else snprintf(c->pick, REF_PATH, "%.*s", (int)(b + l - pk), pk);
    }
  }
  if (!seen_magic) { *why = "an empty state"; return DRIFT_FOREIGN; }
  if (s->have_run != 3) { *why = "a state with no run stamp"; return DRIFT_CORRUPT; }
  return DRIFT_OK;
}

static int drift_read_previous(void) {
  size_t n = 0;
  char *t = loadf(DRIFT_STATE_PATH, &n);
  int rc;
  if (!t) { drift_prev_outcome = DRIFT_ABSENT; drift_prev_why = "no_state_file"; return 0; }
  rc = drift_parse(t, n, &drift_prev, &drift_prev_why);
  free(t);
  drift_prev_outcome = rc;
  return rc == DRIFT_OK;
}

/* The file is written through a temporary name and renamed, so a run killed
 * mid-write leaves the PREVIOUS state in place rather than half a state that
 * parses. A gate that can lose the baseline can also lose the comparison, and
 * a comparison over a truncated file is the silent kind. */
static int drift_write_current(void) {
  static char text[DRIFT_TEXT_MAX];
  char tmp[512];
  FILE *f;
  size_t n = drift_render(&drift_cur, text, sizeof text);
  mkdir("out", 0777);
  mkdir("out/c-bootstrap", 0777);
  mkdir(DRIFT_STATE_DIR, 0777);
  snprintf(tmp, sizeof tmp, "%s.tmp.%u", DRIFT_STATE_PATH, drift_pid);
  f = fopen(tmp, "wb");
  if (!f) return 0;
  if (fwrite(text, 1, n, f) != n || fclose(f) != 0) { remove(tmp); return 0; }
  if (rename(tmp, DRIFT_STATE_PATH) != 0) { remove(tmp); return 0; }
  return 1;
}

typedef struct {
  unsigned added, dropped, shifted, moved, verdict, repointed;
  int doc_changed;
  int refused_self;
} DriftDiff;

/* The comparison. Announce is off only where a case asks for silence; the run
 * announces. The five passes are ordered from the strongest identity to the
 * weakest, and each pass consumes what it matched, so a pair is never
 * counted twice: a citation whose line numbers moved is `moved`, not
 * `dropped` plus `added`, which is the difference between a report a reader
 * can act on and a diff.
 *
 * THE MATCH ARRAYS ARE CLEARED HERE, and that line is the fix of a defect this
 * function's own case runner found on its first execution. They were `static`,
 * which is the shape this project has spent three waves removing: the bits a
 * call consumed stayed consumed, so the first case to run was the only case
 * that could see anything, and every later case reported zero movement -- a
 * comparison that had been proven quiet by its own memory. Four of the eight
 * cases in check_drift() failed the day this was written, which is the whole
 * argument for running them at all. They are ordinary locals now, zeroed on
 * entry, and nothing in this function survives a call. */
static void drift_compare(const DriftState *prev, const DriftState *cur, DriftDiff *d,
 int announce) {
  unsigned char used_p[DRIFT_CIT_MAX], used_c[DRIFT_CIT_MAX];
  unsigned np = prev->n, nc = cur->n;
  memset(d, 0, sizeof *d);
  memset(used_p, 0, sizeof used_p);
  memset(used_c, 0, sizeof used_c);
  d->doc_changed = prev->doc_hash != cur->doc_hash;
  /* THE SELF-COMPARISON REFUSAL, in the words of the corpus self-host check
   * that already does this: comparing a producer with itself would pass
   * whatever it emits, so this run proves nothing. A state stamped with this
   * process's own pid and start is that state, whatever route it arrived by. */
  if (prev->pid == cur->pid && prev->run_start == cur->run_start) {
    d->refused_self = 1;
    if (announce)
      fprintf(stderr, "REF-DRIFT self : the state being compared carries this very process's pid=%u "
                      "and start=%ld, so it is this run's own output. Comparing a run with itself "
                      "would pass whatever it emits, so this comparison proves nothing and is "
                      "REFUSED rather than reported as no drift.\n", cur->pid, cur->run_start);
    return;
  }
  /* 1. the same sentence, the same range. */
  for (unsigned i = 0; i < nc; i++) {
    for (unsigned j = 0; j < np; j++) {
      if (used_p[j]) continue;
      if (cur->cit[i].line != prev->cit[j].line || cur->cit[i].lo != prev->cit[j].lo ||
          cur->cit[i].hi != prev->cit[j].hi || strcmp(cur->cit[i].name, prev->cit[j].name)) continue;
      used_p[j] = used_c[i] = 1;
      if (strcmp(cur->cit[i].pick, prev->cit[j].pick)) {
        d->repointed++;
        if (announce)
          fprintf(stderr, "REF-DRIFT repointed spec/ntasm/ntasm.md:%u cites %s:%u-%u, which resolved to "
                          "%s in the previous run and to %s in this one: the name now answers to a "
                          "different file of the tree\n",
                  cur->cit[i].line, cur->cit[i].name, cur->cit[i].lo, cur->cit[i].hi,
                  prev->cit[j].pick, cur->cit[i].pick);
      } else if (memcmp(cur->cit[i].flags, prev->cit[j].flags, 7)) {
        d->verdict++;
        if (announce)
          fprintf(stderr, "REF-DRIFT verdict spec/ntasm/ntasm.md:%u cites %s:%u-%u and its verdict moved "
                          "from %s to %s while the citation itself is byte-identical: the TREE moved "
                          "under a sentence that did not\n",
                  cur->cit[i].line, cur->cit[i].name, cur->cit[i].lo, cur->cit[i].hi,
                  prev->cit[j].flags, cur->cit[i].flags);
      }
      break;
    }
  }
  /* 2. the same citation, a different line of the document. */
  for (unsigned i = 0; i < nc; i++) {
    if (used_c[i]) continue;
    for (unsigned j = 0; j < np; j++) {
      if (used_p[j]) continue;
      if (cur->cit[i].lo != prev->cit[j].lo || cur->cit[i].hi != prev->cit[j].hi ||
          strcmp(cur->cit[i].name, prev->cit[j].name)) continue;
      used_p[j] = used_c[i] = 1;
      d->shifted++;
      if (announce)
        fprintf(stderr, "REF-DRIFT shifted spec/ntasm/ntasm.md:%u -> %u : the sentence citing %s:%u-%u "
                        "moved down the document and the citation itself is unchanged\n",
                prev->cit[j].line, cur->cit[i].line, cur->cit[i].name, cur->cit[i].lo, cur->cit[i].hi);
      break;
    }
  }
  /* 3. the same sentence, a different range. THIS is the wave-12 event. */
  for (unsigned i = 0; i < nc; i++) {
    if (used_c[i]) continue;
    for (unsigned j = 0; j < np; j++) {
      if (used_p[j]) continue;
      if (cur->cit[i].line != prev->cit[j].line || strcmp(cur->cit[i].name, prev->cit[j].name))
        continue;
      used_p[j] = used_c[i] = 1;
      d->moved++;
      if (announce)
        fprintf(stderr, "REF-DRIFT moved spec/ntasm/ntasm.md:%u cited %s:%u-%u in the previous run and "
                        "cites %s:%u-%u in this one: those are the citations to re-anchor\n",
                cur->cit[i].line, prev->cit[j].name, prev->cit[j].lo, prev->cit[j].hi,
                cur->cit[i].name, cur->cit[i].lo, cur->cit[i].hi);
      break;
    }
  }
  /* 4. what is left is a citation that appeared or one that is gone. */
  for (unsigned i = 0; i < nc; i++) {
    if (used_c[i]) continue;
    d->added++;
    if (announce)
      fprintf(stderr, "REF-DRIFT added spec/ntasm/ntasm.md:%u cites %s:%u-%u and the previous run had no "
                      "such citation at that line\n",
              cur->cit[i].line, cur->cit[i].name, cur->cit[i].lo, cur->cit[i].hi);
  }
  for (unsigned j = 0; j < np; j++) {
    if (used_p[j]) continue;
    d->dropped++;
    if (announce)
      fprintf(stderr, "REF-DRIFT dropped spec/ntasm/ntasm.md:%u cited %s:%u-%u and this run does not\n",
              prev->cit[j].line, prev->cit[j].name, prev->cit[j].lo, prev->cit[j].hi);
  }
  if (announce && d->verdict && !d->doc_changed)
    fprintf(stderr, "REF-DRIFT verdict-under-a-still-document n=%u : the document is byte-identical "
                    "to the previous run and %u citation verdict%s moved, so this drift belongs to "
                    "the TREE and not to the prose. It is reported, not failed: a line number moving "
                    "when a file moves is counted, not failed, everywhere else in this file, and a "
                    "second gate that failed here would be inventing a refusal.\n",
            d->verdict, d->verdict, d->verdict == 1 ? "" : "s");
}

/* The summary line, and the sentence that says what it does not cover. It is
 * longer than the other limits clauses on purpose: this is the line a reader of
 * `ident_missing=0` lands on, and it must not read like a health bulletin.
 *
 * The word after `drift=` is the load-bearing part, and it is never a bare
 * zero. `drift=verdict:0,moved:0,...` is a comparison that ran; `drift=baseline`
 * is a run that compared itself to nothing and says so; `drift=refused:...` is
 * a comparison that could not be trusted. A banner reading `drift=0` would say
 * the same thing about all three, which is the whole defect this section is
 * about, so the case runner below asserts that the string cannot be produced. */
static char drift_banner[768];
static char drift_state_word[96];

/* DRIFT_LIMITS, spelled once so that the banner and the case runner cannot
 * drift apart -- a limit asserted in a test and worded differently in the
 * banner is a limit nobody reads. */
#define DRIFT_LIMITS \
  "two_runs_speak_only_of_the_interval_between_them_and_nothing_of_the_next_one; " \
  "a_run_with_no_previous_state_compares_nothing_and_says_so; " \
  "a_second_registry_run_at_the_same_time_may_rewrite_the_state_under_this_comparison"

static void drift_report(int outcome, const char *why, const DriftDiff *d) {
  int k;
  if (outcome == DRIFT_OK) {
    k = snprintf(drift_state_word, sizeof drift_state_word,
                 "verdict:%u,moved:%u,shifted:%u,repointed:%u,added:%u,dropped:%u",
                 d->verdict, d->moved, d->shifted, d->repointed, d->added, d->dropped);
    if (k < 0 || (size_t)k >= sizeof drift_state_word)
      snprintf(drift_state_word, sizeof drift_state_word, "counters_truncated");
  } else if (outcome == DRIFT_ABSENT) {
    snprintf(drift_state_word, sizeof drift_state_word, "baseline");
  } else if (outcome == DRIFT_FOREIGN) {
    snprintf(drift_state_word, sizeof drift_state_word, "baseline_foreign(%s)", why);
  } else {
    snprintf(drift_state_word, sizeof drift_state_word, "refused(%s)", why);
  }
  /* BOTH IDENTITIES, and the reason is the one the whole file argues: a banner
   * that says `doc=changed` from a number the reader cannot see is a claim the
   * reader has to take on trust. The first version of this line said exactly
   * that, and said `changed` on two runs over a document whose bytes had not
   * moved -- which sent the search for a reader bug that was in fact a writer
   * ordering three functions away. Printing `prev->now` makes the claim
   * falsifiable from the log: a reader who doubts it compares two numbers
   * instead of believing a word. */
  k = snprintf(drift_banner, sizeof drift_banner,
               "REF-DRIFT-SUMMARY drift=%s refs=%u doc=%s:%016lx->%016lx prev_run=%ld prev_pid=%u "
               "now_run=%ld now_pid=%u limits=%s\n",
               drift_state_word, refs_n, d ? (d->doc_changed ? "changed" : "unchanged") : "unknown",
               outcome == DRIFT_OK ? drift_prev.doc_hash : 0UL, drift_doc_hash,
               outcome == DRIFT_OK ? drift_prev.run_start : -1L,
               outcome == DRIFT_OK ? drift_prev.pid : 0u,
               drift_run_start, drift_pid, DRIFT_LIMITS);
  if (k < 0 || (size_t)k >= sizeof drift_banner) {
    checks++;
    failures++;
    fprintf(stderr, "FAIL the drift summary did not fit in %zu bytes, so the line a reader of "
                    "ident_missing=0 lands on is the one that was cut\n", sizeof drift_banner);
  }
}


/* ================================================================== both
 * instruments, PROVEN ABLE TO FIRE -- and able to stay quiet.
 *
 * The rule this file keeps to is that a check exercised in one state has not
 * been tested against the state it exists to detect, and these two have a
 * second problem on top of it: on a correct document today BOTH are silent
 * (missing=0, and the first run after this lands has no previous state), so
 * without these cases they would ship as two code paths nothing has ever
 * entered. The cases drive the same functions the run drives, on states the
 * tree does not currently hold, and each asserts what must NOT be said as well
 * as what must.
 */
static unsigned class_cases, class_proven, class_quiet;
static unsigned drift_cases, drift_proven, drift_quiet, drift_parse_proven;

static unsigned count_text(const char *t, size_t n, const char *p) {
  size_t l = strlen(p);
  unsigned c = 0;
  for (size_t i = 0; i + l <= n; i++)
    if (!memcmp(t + i, p, l)) c++;
  return c;
}

static void unres_put(UnresRef *u, unsigned *n, const char *name, unsigned line,
                      unsigned lo, unsigned hi) {
  UnresRef *r = &u[(*n)++];
  memset(r, 0, sizeof *r);
  snprintf(r->name, NAME_MAX, "%s", name);
  r->line = line;
  r->lo = lo;
  r->hi = hi;
  r->doc = 0;
  r->copied = 0;
}

/* The same entry, resolved to a COPY rather than to nothing. The two are
 * distinguished by exactly one byte and the report branches on it, so the case
 * runner has to be able to build the second one or the new branch is untested
 * and the suite is green about a report nobody has ever seen fire. */
static void unres_put_copy(UnresRef *u, unsigned *n, const char *name, unsigned line,
                           unsigned lo, unsigned hi, unsigned doc, const char *at) {
  unres_put(u, n, name, line, lo, hi);
  u[*n - 1].copied = 1;
  u[*n - 1].doc = doc;
  snprintf(u[*n - 1].at, REF_PATH, "%s", at);
}

static void probe_hit(OutProbe *p, unsigned pi, unsigned u, const char *where) {
  if (p[pi].nfound >= UNRES_MAX) return;
  snprintf(p[pi].path[p[pi].nfound], REF_PATH, "%s", where);
  p[pi].nfound++;
  p[pi].hit[u] = 1;
}

/* ONE case per state the report has a word for. `want_out` and `want_absent`
 * are the number of class headers that must appear -- the out-of-scope ones and
 * the absent-or-unknown ones, counted separately because the difference between
 * them IS the instrument: a name that is nowhere and a name the probe was not
 * allowed to look for are the same shape on a log and opposite facts. */
static void unres_case(const char *label, const UnresRef *u, unsigned un,
                       const OutProbe *p, unsigned pn, int truncated,
                       unsigned want_out, unsigned want_absent,
                       const char *named, const char *forbidden) {
  char out[8192];
  unsigned got_out, got_other;
  err_capture_begin();
  ref_report_unresolved(u, un, p, pn, truncated);
  size_t len = err_capture_end(out, sizeof out);
  cases++;
  checks++;
  got_out = count_text(out, len, "REF-CLASS out-of-scope");
  got_other = count_text(out, len, "REF-CLASS absent") + count_text(out, len, "REF-CLASS unknown");
  if (got_out != want_out || got_other != want_absent) {
    failures++;
    fprintf(stderr, "FAIL class %s: the report named %u out-of-scope and %u absent/unknown classes "
                    "and this state holds %u and %u, so the state this report exists to name is one "
                    "it does not name. It said: %.300s\n",
            label, got_out, got_other, want_out, want_absent, out);
    return;
  }
  if (forbidden && has_text(out, len, forbidden)) {
    failures++;
    fprintf(stderr, "FAIL class %s: the report said %s, which is a claim about the tree it did not "
                    "look at. It said: %.300s\n", label, forbidden, out);
    return;
  }
  if (named && !has_text(out, len, named)) {
    failures++;
    fprintf(stderr, "FAIL class %s: the report did not name %s, and a report that does not name the "
                    "thing to fix is the count this section was opened against. It said: %.300s\n",
            label, named, out);
    return;
  }
  if (!want_out && !want_absent) {
    /* Nothing unresolved is the state every green run is in, so the report's
     * quiet path is the one the suite depends on and it is a case, not a
     * formality. */
    if (len != 0) {
      failures++;
      fprintf(stderr, "FAIL class %s: nothing is unresolved and the report still spoke: %.300s\n",
              label, out);
      return;
    }
    class_quiet++;
  }
  class_proven++;
  class_cases++;
}

static void check_unresolved_classes(void) {
  UnresRef u[4];
  OutProbe p[2];
  unsigned n = 0;
  memset(u, 0, sizeof u);
  memset(p, 0, sizeof p);

  /* THE wave-11 shape: seven citations into one directory the scope does not
   * search, reduced to two here. The class header must appear ONCE, name the
   * directory, and say it is one decision -- three assertions, because each of
   * them is a way the fix can be half-built. */
  n = 0;
  unres_put(u, &n, "scripts/ntbuild.sh", 2575, 12, 12);
  unres_put(u, &n, "scripts/ntselfhost.sh", 2578, 44, 44);
  p[0].dir[0] = 's';
  snprintf(p[0].dir, REF_PATH, "scripts");
  probe_hit(p, 0, 0, "scripts/ntbuild.sh");
  probe_hit(p, 0, 1, "scripts/ntselfhost.sh");
  unres_case("TWO-IN-ONE-ROOT", u, n, p, 1, 0, 1, 0, "ONE decision", NULL);
  unres_case("TWO-IN-ONE-ROOT-NAMES-THE-FILE", u, n, p, 1, 0, 1, 0, "scripts/ntbuild.sh", NULL);

  /* The split: one of the pair is in the scope's blind spot and one is nowhere.
   * Lumping them is the failure the document owner described -- seven things to
   * fix -- so the two classes must be reported separately. */
  n = 0;
  unres_put(u, &n, "scripts/ntbuild.sh", 2575, 12, 12);
  unres_put(u, &n, "no_such_file_anywhere.c", 2577, 7, 7);
  memset(p, 0, sizeof p);
  snprintf(p[0].dir, REF_PATH, "scripts");
  probe_hit(p, 0, 0, "scripts/ntbuild.sh");
  unres_case("SPLIT", u, n, p, 1, 0, 1, 1, NULL, NULL);

  /* Two directories, one class each: the scope is a set of roots, and a
   * document that strays into two of them has made two of the same decision. */
  n = 0;
  unres_put(u, &n, "scripts/ntbuild.sh", 2575, 12, 12);
  unres_put(u, &n, "verifieur/verifieur.md", 2576, 3, 3);
  memset(p, 0, sizeof p);
  snprintf(p[0].dir, REF_PATH, "scripts");
  snprintf(p[1].dir, REF_PATH, "verifieur");
  probe_hit(p, 0, 0, "scripts/ntbuild.sh");
  probe_hit(p, 1, 1, "verifieur/verifieur.md");
  unres_case("TWO-ROOTS", u, n, p, 2, 0, 2, 0, "verifieur", NULL);

  /* A name that is nowhere, said as a fact about the scope and not about the
   * tree -- the wording is the difference between a true sentence and a false
   * one, since a file under the unsearched part of out/ would make it false. */
  n = 0;
  unres_put(u, &n, "no_such_file_anywhere.c", 2577, 7, 7);
  memset(p, 0, sizeof p);
  unres_case("ALL-ABSENT", u, n, p, 2, 0, 0, 1, "no directory the scope excludes", NULL);

  /* The probe stopped on its budget. The claim it cannot support is not made:
   * this case asserts the ABSENCE of the absent-class, which is the only way to
   * show that the unknown branch is a different branch. */
  n = 0;
  unres_put(u, &n, "no_such_file_anywhere.c", 2577, 7, 7);
  memset(p, 0, sizeof p);
  unres_case("TRUNCATED", u, n, p, 2, 1, 0, 1, "NO name is claimed absent",
             "REF-CLASS absent");

  /* Nothing unresolved: the state of every green run, and the report must be
   * silent in it. */
  n = 0;
  unres_case("EMPTY", u, n, p, 2, 0, 0, 0, NULL, NULL);

  /* THE THIRD CLASS, and the one this section did not have until a citation was
   * found resolving into a lot's evidence directory: the citation RESOLVED, so
   * nothing above was red, and it was judged against
   * `out/c-bootstrap/.../snapshot-a1-a7-a10/scripts/ntbuild.sh` rather than
   * against `scripts/ntbuild.sh`. Two things must be true of the report and
   * neither is the count: it must SAY the word copy, and it must name the copy
   * it answered with -- a report that says "some citations are weaker" and does
   * not print the path leaves the reader to re-derive the finding by hand,
   * which is the whole cost this class was opened against. The probe is given
   * the hit too, so the report can add where the real file is, and doc=1 puts
   * the citation in the SECOND document: a report that printed
   * `spec/ntasm/ntasm.md:62` for a line of `docs/status/ntasm-completion.md` sends the
   * reader to a line that has nothing to do with the ticket. */
  n = 0;
  unres_put_copy(u, &n, "scripts/ntbuild.sh", 62, 108, 108, 1,
                 "out/c-bootstrap/nova/evidence/W19CriteriaGaps/snapshot-a1-a7-a10/scripts/ntbuild.sh");
  memset(p, 0, sizeof p);
  snprintf(p[0].dir, REF_PATH, "scripts");
  probe_hit(p, 0, 0, "scripts/ntbuild.sh");
  unres_case("COPIED", u, n, p, 1, 0, 1, 0, "REF-CLASS copied", NULL);
  unres_case("COPIED-NAMES-THE-COPY", u, n, p, 1, 0, 1, 0,
             "snapshot-a1-a7-a10/scripts/ntbuild.sh", NULL);
  unres_case("COPIED-NAMES-THE-SOURCE", u, n, p, 1, 0, 1, 0, "scripts/ntbuild.sh", NULL);
  unres_case("COPIED-NAMES-ITS-DOCUMENT", u, n, p, 1, 0, 1, 0,
             ref_doc[1] ? ref_doc[1] : "docs/status/ntasm-completion.md", NULL);
  /* And the sentence a reader must not be able to draw: a copy is NOT a
   * missing file. If this report ever says "resolve to nothing" about a
   * citation that resolved, it is describing a state the tree is not in. */
  unres_case("COPIED-IS-NOT-UNRESOLVED", u, n, p, 1, 0, 1, 0, NULL, "REF-CLASS absent");
  unres_case("COPIED-IS-NOT-UNRESOLVED-2", u, n, p, 1, 0, 1, 0, NULL, "REF-CLASS unknown");

  if (class_quiet < 1) {
    failf("the class report ran %u quiet cases, and a report that speaks when there is nothing to "
          "report is a report the log teaches readers to skip", class_quiet);
  } else good();
  printf("CLASS-PROVEN %2u/%2u states named, %u quiet\n", class_proven, class_cases, class_quiet);
}

static void check_resolver_rank(void);
static void drift_put(DriftState *s, unsigned line, const char *name, unsigned lo, unsigned hi,
                      const char *flags, const char *pick) {
  DriftCit *c;
  if (s->n >= DRIFT_CIT_MAX) return;
  c = &s->cit[s->n++];
  c->line = line;
  c->lo = lo;
  c->hi = hi;
  snprintf(c->name, NAME_MAX, "%s", name);
  snprintf(c->flags, sizeof c->flags, "%s", flags);
  snprintf(c->pick, REF_PATH, "%s", pick);
}

static void drift_stamp(DriftState *s, long start, unsigned pid, unsigned long hash) {
  memset(s, 0, sizeof *s);
  s->run_start = start;
  s->pid = pid;
  s->have_run = 1;
  s->doc_bytes = 4242;
  s->doc_hash = hash;
}

/* One comparison. `want` is the number of citations that must be reported as
 * moved in any of the five ways, and `forbidden` a phrase that must NOT appear
 * -- which is how the quiet case is proved to be quiet by assertion rather
 * than by the return value being zero. */
static void drift_case(const char *label, const DriftState *prev, const DriftState *cur,
                       unsigned want, const char *named, const char *forbidden) {
  char out[8192];
  DriftDiff d;
  unsigned total;
  err_capture_begin();
  drift_compare(prev, cur, &d, 1);
  size_t len = err_capture_end(out, sizeof out);
  cases++;
  checks++;
  total = d.verdict + d.moved + d.shifted + d.repointed + d.added + d.dropped;
  if (total != want) {
    failures++;
    fprintf(stderr, "FAIL drift %s: the comparison reported %u moved citations and this state holds "
                    "%u, so a state this check exists to detect is one it does not detect. It said: "
                    "%.300s\n", label, total, want, out);
    return;
  }
  if (forbidden && has_text(out, len, forbidden)) {
    failures++;
    fprintf(stderr, "FAIL drift %s: the comparison said %s, which this state does not contain. It "
                    "said: %.300s\n", label, forbidden, out);
    return;
  }
  if (named && !has_text(out, len, named)) {
    failures++;
    fprintf(stderr, "FAIL drift %s: the comparison did not name %s, and a drift report that does not "
                    "name the citation that moved is a count. It said: %.300s\n", label, named, out);
    return;
  }
  if (!want && !d.refused_self) {
    if (len != 0) {
      failures++;
      fprintf(stderr, "FAIL drift %s: nothing moved and the comparison still spoke: %.300s\n",
              label, out);
      return;
    }
    drift_quiet++;
  }
  drift_proven++;
  drift_cases++;
}

static void drift_parse_case(const char *label, const char *text, int want,
                             const char *why_want) {
  static DriftState s;
  const char *why = "";
  int rc = drift_parse(text, strlen(text), &s, &why);
  cases++;
  checks++;
  if (rc != want) {
    failures++;
    fprintf(stderr, "FAIL drift-state %s: the reader returned %d where this state is %d, so a state "
                    "it cannot read is one it does not notice (%s)\n", label, rc, want, why);
    return;
  }
  if (why_want && strcmp(why, why_want)) {
    failures++;
    fprintf(stderr, "FAIL drift-state %s: the reader said %s where this state is %s, and a reader "
                    "that names the wrong cause sends the reader to the wrong file\n",
            label, why, why_want);
    return;
  }
  drift_parse_proven++;
}

/* The round trip is the case that matters most and is the one a hand test
 * cannot reach: the writer and the reader are two halves of one instrument,
 * and a disagreement between them is invisible in every other case -- the
 * comparison would report the document as wholly rewritten, or as wholly
 * still, and both readings look like findings. */
static void drift_round_trip(void) {
  static char text[DRIFT_TEXT_MAX];
  static DriftState a, b;
  const char *why = "";
  size_t n;
  /* The identity a real run of this gate produces, high bits and all. The first
   * version of this case used 0xdeadbeef, which is why the round trip did not
   * catch the 32-bit truncation the writer was doing: a value with nothing
   * above bit 31 survives being cut in half. A round trip over a test value
   * the production path would never produce is a test of the test. */
  drift_stamp(&a, 1759050000L, 4242u, 0x8110914de98c2553UL);
  drift_put(&a, 10, "control_flow.nova", 800, 848, "......+", "compiler/nova/analysis/control_flow.nova");
  drift_put(&a, 20, "scripts/ntbuild.sh", 12, 12, "..U....", "-");
  drift_put(&a, 30, "tests_ntasm_diagnostics.c", 264, 264, "...C...", "tests/c/nova/tests_ntasm_diagnostics.c");
  n = drift_render(&a, text, sizeof text);
  cases++;
  checks++;
  if (drift_parse(text, n, &b, &why) != DRIFT_OK) {
    failures++;
    fprintf(stderr, "FAIL drift-state ROUND-TRIP: the gate wrote a state it cannot read back (%s)\n",
            why);
    return;
  }
  if (b.n != a.n) {
    failures++;
    fprintf(stderr, "FAIL drift-state ROUND-TRIP: %u citations went in and %u came out, so a "
                    "document that gained citations would read as one that lost them\n", a.n, b.n);
    return;
  }
  for (unsigned i = 0; i < a.n; i++)
    if (b.cit[i].line != a.cit[i].line || b.cit[i].lo != a.cit[i].lo || b.cit[i].hi != a.cit[i].hi ||
        strcmp(b.cit[i].name, a.cit[i].name) || strcmp(b.cit[i].flags, a.cit[i].flags) ||
        strcmp(b.cit[i].pick, a.cit[i].pick)) {
      failures++;
      fprintf(stderr, "FAIL drift-state ROUND-TRIP: citation %u differs after a write and a read\n", i);
      return;
    }
  if (b.run_start != a.run_start || b.pid != a.pid || b.doc_hash != a.doc_hash) {
    failures++;
    fprintf(stderr, "FAIL drift-state ROUND-TRIP: the run stamp did not survive, and a state that "
                    "cannot say which run wrote it cannot refuse a self-comparison\n");
    return;
  }
  drift_parse_proven++;
  good();
}

static void check_drift(void) {
  static DriftState prev, cur;
  DriftDiff d;
  char text[4096];
  /* STILL. Same run on both sides, byte for byte. Must be silent: the quiet
   * direction is the one every green in this repository depends on. */
  drift_stamp(&prev, 1759050000L, 100u, 0xabcUL);
  drift_put(&prev, 10, "control_flow.nova", 800, 848, "......+", "compiler/nova/analysis/control_flow.nova");
  drift_put(&prev, 20, "stub_table.nova", 31, 31, "......+", "compiler/nova/frontend/stub_table.nova");
  cur = prev;
  cur.run_start = 1759050600L;
  cur.pid = 101u;
  drift_case("STILL", &prev, &cur, 0, NULL, NULL);

  /* MOVED: the wave-12 event, a script grew 45 lines and three citations with
   * it. The sentence is the same and the range is not, so this is a citation to
   * re-anchor -- NOT a dropped plus an added, which is the difference between
   * a report and a diff. */
  drift_stamp(&prev, 1759050000L, 100u, 0xabcUL);
  drift_put(&prev, 42, "ntbuild.sh", 866, 866, "......+", "scripts/ntbuild.sh");
  drift_stamp(&cur, 1759050600L, 101u, 0xabcUL);
  drift_put(&cur, 42, "ntbuild.sh", 911, 911, "......+", "scripts/ntbuild.sh");
  drift_case("MOVED", &prev, &cur, 1, "REF-DRIFT moved", NULL);
  /* The same comparison a second time, asserting the word it must NOT use: a
   * citation whose range moved is one re-anchoring, not one deletion plus one
   * creation, and a report that said otherwise would send the reader to two
   * places instead of the one sentence that needs editing. */
  drift_case("MOVED-NOT-A-DIFF", &prev, &cur, 1, "REF-DRIFT moved", "REF-DRIFT dropped");

  /* SHIFTED: the document grew above the citation. Nothing is wrong and the
   * log has to say that rather than leave the reader to work it out. */
  drift_stamp(&prev, 1759050000L, 100u, 0xabcUL);
  drift_put(&prev, 100, "stub_table.nova", 31, 31, "......+", "compiler/nova/frontend/stub_table.nova");
  drift_stamp(&cur, 1759050600L, 101u, 0xdefUL);
  drift_put(&cur, 140, "stub_table.nova", 31, 31, "......+", "compiler/nova/frontend/stub_table.nova");
  drift_case("SHIFTED", &prev, &cur, 1, "REF-DRIFT shifted", NULL);

  /* VERDICT under a still document: this is U28's own event, the tree moving
   * under a sentence that did not. It is the case the whole instrument exists
   * for and the one whose banner line must not read like a health bulletin. */
  drift_stamp(&prev, 1759050000L, 100u, 0xabcUL);
  drift_put(&prev, 7, "frontend.c", 304, 304, "......+", "compiler/c/ntasm/frontend/frontend.c");
  drift_stamp(&cur, 1759050600L, 101u, 0xabcUL);
  drift_put(&cur, 7, "frontend.c", 304, 304, "S....+", "compiler/c/ntasm/frontend/frontend.c");
  drift_case("VERDICT-UNDER-A-STILL-DOCUMENT", &prev, &cur, 1,
             "the TREE moved under a sentence that did not", NULL);

  /* REPOINTED: the same name now answers to another file, which is what
   * happens when a shallower copy of it appears in the tree. */
  drift_stamp(&prev, 1759050000L, 100u, 0xabcUL);
  drift_put(&prev, 7, "control_flow.nova", 800, 800, "......+", "out/c-bootstrap/20260901/control_flow.nova");
  drift_stamp(&cur, 1759050600L, 101u, 0xabcUL);
  drift_put(&cur, 7, "control_flow.nova", 800, 800, "......+", "compiler/nova/analysis/control_flow.nova");
  drift_case("REPOINTED", &prev, &cur, 1, "REF-DRIFT repointed", NULL);

  /* ADDED and DROPPED: the citation set itself changed. */
  drift_stamp(&prev, 1759050000L, 100u, 0xabcUL);
  drift_put(&prev, 7, "control_flow.nova", 800, 800, "......+", "compiler/nova/analysis/control_flow.nova");
  drift_stamp(&cur, 1759050600L, 101u, 0xdefUL);
  drift_put(&cur, 7, "control_flow.nova", 800, 800, "......+", "compiler/nova/analysis/control_flow.nova");
  drift_put(&cur, 9, "splice.nova", 12, 12, "......+", "compiler/nova/splice.nova");
  drift_case("ADDED", &prev, &cur, 1, "REF-DRIFT added", NULL);
  drift_stamp(&cur, 1759050600L, 101u, 0xdefUL);
  /* The two names, the other way round: the citation is on the PREVIOUS side
   * and absent from this one, which is a citation the document stopped making
   * rather than one it started making. */
  drift_case("DROPPED", &prev, &cur, 1, "REF-DRIFT dropped", "REF-DRIFT added");

  /* THE SELF-COMPARISON, in the words of the corpus self-host check that
   * already refuses its own: comparing a run with itself would pass whatever
   * it emits, so this comparison proves nothing. The refusal is the negative
   * proof of the whole instrument -- a drift check that could compare a run to
   * itself would be `stale_lines=0` again under a new name. */
  drift_stamp(&prev, 1759050000L, 100u, 0xabcUL);
  drift_put(&prev, 7, "control_flow.nova", 800, 800, "......+", "compiler/nova/analysis/control_flow.nova");
  cur = prev;
  drift_case("SELF", &prev, &cur, 0, "REFUSED rather than reported as no drift", NULL);
  err_capture_begin();
  drift_compare(&prev, &cur, &d, 1);
  checks++;
  if (!d.refused_self) {
    failures++;
    fprintf(stderr, "FAIL drift SELF: the comparison of a state with itself was not refused\n");
  } else good();
  err_capture_end(text, sizeof text);

  /* THE READER, on the states a state file can be in that are not the one it
   * should be. A reader that answers "no drift" to a state it cannot read is
   * the most dangerous failure this instrument could have, so every one of these
   * is a distinct outcome rather than a quiet zero. The first one is the shape
   * this writer produces, asserted as a case rather than assumed: the round
   * trip below proves the two halves agree about CITATIONS, and this proves
   * they agree about the run stamp a state without cannot be trusted. */
  snprintf(text, sizeof text, "%s\nrun_start=1\npid=2\ndoc_bytes=3\ndoc_hash=4\n", DRIFT_MAGIC);
  drift_parse_case("OK", text, DRIFT_OK, NULL);
  drift_parse_case("ABSENT-MAGIC", "run_start=1\npid=2\n", DRIFT_FOREIGN,
                   "first_line_is_not_this_gates_magic");
  drift_parse_case("TRUNCATED-CIT", DRIFT_MAGIC "\nrun_start=1 pid=2\ncit 7 304 ......+\n",
                   DRIFT_CORRUPT, "a citation line that does not parse");
  drift_parse_case("SHORT-FLAGS", DRIFT_MAGIC "\nrun_start=1 pid=2\ncit 7 304 304 ... control_flow.nova\n",
                   DRIFT_CORRUPT, "a citation whose flag field is not seven slots");
  drift_parse_case("NO-NAME", DRIFT_MAGIC "\nrun_start=1 pid=2\ncit 7 304 304 ......+\n",
                   DRIFT_CORRUPT, "a citation line with no name");
  drift_parse_case("IMPOSSIBLE-RANGE", DRIFT_MAGIC "\nrun_start=1 pid=2\ncit 7 0 900 ......+ control_flow.nova\n",
                   DRIFT_CORRUPT, "a citation with an impossible range");
  drift_parse_case("NO-RUN-STAMP", DRIFT_MAGIC "\ndoc_bytes=3\n", DRIFT_CORRUPT,
                   "a state with no run stamp");
  drift_parse_case("FOREIGN-LINE", DRIFT_MAGIC "\nrun_start=1 pid=2\nthis gate never wrote this\n",
                   DRIFT_CORRUPT, "a line this gate did not write");
  /* And the one that would have been invisible: a document with more citations
   * than the state can hold. Truncating it would report the tail as dropped
   * and the head as untouched, which is a complete-looking verdict over a
   * partial read. */
  {
    static char big[1u << 17];
    int m = snprintf(big, sizeof big, "%s\nrun_start=1 pid=2 doc_bytes=3 doc_hash=4\n", DRIFT_MAGIC);
    for (unsigned i = 0; i <= DRIFT_CIT_MAX; i++)
      m += snprintf(big + m, sizeof big - (size_t)m, "cit %u 1 1 ......+ control_flow.nova -\n", i + 1);
    drift_parse_case("TOO-MANY", big, DRIFT_TOOMANY, "more citations than the state can hold");
  }
  drift_round_trip();

  /* AND THE BANNER, which is what a reader actually sees. The case that
   * matters is the negative one: whatever the comparison found, the summary
   * must not be able to print a bare `drift=0`, because that word would read
   * the same for a comparison that ran, a run with no baseline, and a state
   * that could not be trusted. */
  {
    static const struct { int outcome; const char *why; const char *forbidden; } words[] = {
      {DRIFT_OK, "", "drift=0"},
      {DRIFT_OK, "", "baseline"},
      {DRIFT_ABSENT, "no_state_file", "drift=0"},
      {DRIFT_FOREIGN, "first_line_is_not_this_gates_magic", "drift=0"},
      {DRIFT_CORRUPT, "a state with no run stamp", "drift=0"},
    };
    for (unsigned i = 0; i < sizeof words / sizeof *words; i++) {
      DriftDiff empty;
      memset(&empty, 0, sizeof empty);
      drift_report(words[i].outcome, words[i].why, &empty);
      cases++;
      checks++;
      if (!has_text(drift_banner, strlen(drift_banner), "REF-DRIFT-SUMMARY")) {
        failures++;
        fprintf(stderr, "FAIL drift-banner %u: the summary did not print its own name\n", i);
      } else if (has_text(drift_banner, strlen(drift_banner), words[i].forbidden)) {
        failures++;
        fprintf(stderr, "FAIL drift-banner %u: the summary printed %s, which is the reading this "
                        "section exists to refuse: %.200s\n", i, words[i].forbidden, drift_banner);
      } else if (!has_text(drift_banner, strlen(drift_banner), "nothing_of_the_next_one")) {
        failures++;
        fprintf(stderr, "FAIL drift-banner %u: the summary dropped the clause that says what two "
                        "runs cannot say, and a banner that reads better and says less is a "
                        "regression\n", i);
      } else good();
    }
    /* The baseline word, asserted rather than hoped for: this is the state the
     * very first run after this lands is in, and it is the state in which a
     * naive instrument would print a reassuring zero. */
    {
      DriftDiff empty;
      memset(&empty, 0, sizeof empty);
      drift_report(DRIFT_ABSENT, "no_state_file", &empty);
      cases++;
      checks++;
      if (!has_text(drift_banner, strlen(drift_banner), "drift=baseline"))
        failf("a run with no previous state does not say so in its banner, and a first run that "
              "reads as a comparison is the defect U28 names");
      else good();
    }
  }

  if (drift_quiet < 1)
    failf("the drift comparison ran %u quiet cases, and a comparison that cannot stay quiet on a "
          "still tree is a comparison nobody reads", drift_quiet);
  else good();
  printf("DRIFT-PROVEN %2u/%2u states named, %u quiet, %u states read\n", drift_proven, drift_cases,
         drift_quiet, drift_parse_proven);
}

/* Section 8. It writes into the same counters as everything else, and it is a
 * function so that main() can re-judge it on a fresher copy of the document;
 * see the note there. The banner of the last judgement is kept so that a
 * re-judge reprints it only when the verdict actually moved: printing it twice
 * when nothing changed would make the log say section 8 ran twice, which it did
 * not, because the counters are restored before the second judgement. */
/* 2048 and not 1024: the banner grew a THIRD line, the per-document breakdown,
 * and the `limits=` clause below grew with it -- a second time, for the same
 * reason as the first. A banner that truncates itself is a banner whose LAST
 * words are the ones that went, and the last words of this one are the clauses
 * that say what the check does NOT cover, which is the part a hurried reader
 * most needs and the part most likely to be cut. The truncation is CHECKED
 * rather than trusted: snprintf that filled the buffer is a failure below, so
 * this size cannot become a lie by the next edit, and the size is deliberately
 * generous so that the NEXT growth does not land on the edge. */
static char ref_banner[2048];

/* The `limits=` clause of REFERENCES-CONTENT, spelled once and CHECKED against
 * the string it replaced rather than trusted: the first two clauses are the
 * ones that were there before this section grew, verbatim, and the case runner
 * below fails if either of them ever disappears. A limits clause that can be
 * shortened by an edit is a limits clause that will be.
 *
 * The fourth clause is the document owner's own sentence, in the place a reader
 * of `ident_missing=0` actually looks. It is there because every instrument in
 * this file certifies the TEXT and not the person who wrote it, and a banner
 * that reads like a health bulletin is what makes that difference invisible. */
#define REF_LIMITS \
  "span:well_formedness_only_not_which_line; " \
  "ident:only_where_the_prose_names_something; " \
  "unresolved:the_class_is_named_but_the_probe_covers_only_the_top_level_dirs_the_scope_excludes_" \
  "entirely_and_out_is_searched_as_out/c-bootstrap_only; " \
  "copied:artefact_cited_counts_citations_that_resolved_to_build_output_and_is_REPORTED_not_" \
  "failed_because_a_citation_into_out_may_be_legitimate_and_a_resolver_that_refuses_one_is_a_" \
  "new_class_of_wrong; the_number_is_citations_and_artefact_only_is_names_so_they_do_not_sum; " \
  "a_check_that_certifies_this_document_cannot_certify_its_author; " \
  "multi_and_ambiguous:multi_names_are_names_that_answer_in_more_than_one_place; ambiguous_names_"\
  "is_the_subset_a_source_over_artefact_then_shallowest_CANNOT_separate_on_this_tree_out/c-bootstrap_"\
  "is_a_declared_root_so_build_artefacts_and_mutation_batteries_are_reachable_ON_PURPOSE_not_excluded;"\
  " a_stale_line_is_NOT_counted_for_an_ambiguous_citation_because_the_REMEDIES_differ; " \
  "the_interval_since_the_previous_run_is_on_the_REF-DRIFT-SUMMARY_line_not_here; " \
  "the_drift_comparison_covers_spec/ntasm.md_alone_and_says_so_rather_than_implying_two_" \
  "documents_were_compared; " \
  "file:line_resolution_is_the_ONLY_part_of_the_link_class_and_the_table_geometry_and_" \
  "anchor_checks_are_on_the_DOC-*_lines_of_the_same_banner"

/* Per-document citation counts, so the banner can say WHICH document `refs=`
 * counted. One number over two documents is a number nobody can act on: the
 * whole point of adding the second document is that a reader can SEE it being
 * read at all, and `refs=249` on its own does not say that -- a check that
 * stopped reading the second document would print a smaller total and nothing
 * else would move. */
static unsigned doc_refs[REF_DOCS], doc_resolved[REF_DOCS], doc_missing[REF_DOCS],
    doc_stale[REF_DOCS];

static void check_references(const char *spec, size_t n, int announce) {
  /* BOUND HERE, at the top of every judgement, and not in main(): the re-judge
   * path hands this function a fresher copy of the spec, and the identifier
   * check reads its windows through ref_text[0]. A binding made once in main()
   * would have left the second judgement reading windows out of the FIRST copy
   * under the SECOND copy's line numbers -- the stale read this file has
   * already paid for once, in the content cache. */
  ref_text[0] = spec;
  ref_docn[0] = n;
  ref_text[1] = doc2_text;
  ref_docn[1] = doc2_text ? strlen(doc2_text) : 0;

  unsigned resolved = 0, missing = 0, stale = 0, nearest = 0, copied = 0, artefact_only = 0;
  /* CITATIONS, not targets: one name cited three times is three citations and
   * three chances to be pointing at a copy. `artefact_only` counts NAMES whose
   * every match is build output; this counts the citations, which is the
   * number a reader of `resolved=` is actually reasoning about. */
  unsigned artefact_copied = 0;
  /* THE FAMILY: names/citations answering in more than one place, and the inseparable subset. */
  unsigned multi = 0, multi_cit = 0, ambiguous = 0, ambiguous_cit = 0;
  int have_nearest = 0;
  memset(doc_refs, 0, sizeof doc_refs);
  memset(doc_resolved, 0, sizeof doc_resolved);
  memset(doc_missing, 0, sizeof doc_missing);
  memset(doc_stale, 0, sizeof doc_stale);
  refs_n = refs_overflow = refs_over_name = 0;
  tgts_n = tgts_overflow = 0;
  ref_dirs = ref_files = 0;
  ref_truncated = 0;
  unres_n = unres_overflow = 0;
  memset(ref_verdict_flags, 0, sizeof ref_verdict_flags);
  memset(tgt_nmatch, 0, sizeof tgt_nmatch);
  memset(tgt_pick, 0, sizeof tgt_pick); memset(tgt_ambiguous, 0, sizeof tgt_ambiguous);
  memset(tgt_match_artefact, 0, sizeof tgt_match_artefact);
  memset(tgt_truncated, 0, sizeof tgt_truncated);
  memset(tgt_lines, 0, sizeof tgt_lines);
  /* The content cache is keyed by target INDEX, and the target table is reset
   * just above, so a cache kept across two judgements of this function would
   * hand the second one the first one's file contents under the second one's
   * line numbers. That is a stale read wearing a fresh verdict, and the
   * re-judge path in main() takes it on every run where the document moved
   * under the gate. Freed here, before the new judgement reads anything. */
  for (unsigned g = 0; g < TGT_MAX; g++) {
    free(ref_file_cache[g].text);
    free(ref_file_cache[g].off);
    free(ref_file_cache[g].blank);
    free(ref_file_cache[g].comment);
    memset(&ref_file_cache[g], 0, sizeof ref_file_cache[g]);
  }
  ref_file_cached = 0;
  collect_references(spec, n, 0);
  /* The second document, through the same resolver and the same single walk
   * below. main() loads it into a global; if the file is absent the check says
   * so rather than quietly reporting the spec alone, because a coverage number
   * that shrinks when a file goes missing reads as though nothing changed. */
  if (ref_text[1] && ref_docn[1]) collect_references(ref_text[1], ref_docn[1], 1);
  cases++;
  CHECK(refs_n > 0, "the documents carry at least one file:line reference to resolve");
  if (refs_overflow && refs_over_name)
    failf("a cited file name is NAME_MAX or longer (%d bytes) so the reference was "
          "not stored. Do NOT read this as too MANY references: one long path and no "
          "others produces it, and the count printed below is under REF_MAX (%u). "
          "Either cite a shorter path or raise NAME_MAX against the tree, not against "
          "a round number", (int)NAME_MAX, (unsigned)REF_MAX);
  if (refs_overflow)
    failf("the documents carry more file:line references than this harness can hold, "
          "which is %u. This one really is the count", REF_MAX);
  if (tgts_overflow)
    failf("the documents name more distinct referenced files than this harness can hold, which is %u",
          TGT_MAX);

  for (unsigned r = 0; r < REF_ROOTS_N; r++) {
    ref_in_artefact = REF_ROOTS[r].artefact;
    ref_walk(REF_ROOTS[r].path, 0, REF_ROOTS[r].recurse);
  }

  for (unsigned g = 0; g < tgts_n; g++) {
    if (tgt_nmatch[g] == 0) continue;
    resolved += tgt_nrefs[g];
    for (unsigned m = 0; m < tgt_nmatch[g] && m < REF_MATCH; m++)
      tgt_lines[g][m] = count_lines(tgt_match[g][m]);
    /* THE PICK: source over artefact, then the shallowest, then path order -- a TOTAL order. The
     * HEAD is the pick because tgt_add keeps the BEST REF_MATCH candidates and not the first: the
     * old first-N table could not hold the file this rule wants, which is how a correct citation
     * of ngbuild.sh:760 came to be judged against a nine-line mutation battery. Argument, and
     * what a rival on BOTH axes means, is under RANK AND RETENTION at the foot of this file. */
    for (unsigned m = 1; m < tgt_nmatch[g] && m < REF_MATCH; m++)
      if (tgt_depth(tgt_match[g][m]) == tgt_depth(tgt_match[g][0]) &&
          tgt_match_artefact[g][m] == tgt_match_artefact[g][0])
        { tgt_ambiguous[g] = 1; break; }
    tgt_pick[g] = 0;
    if (tgt_nmatch[g] > 1) { multi++; multi_cit += tgt_nrefs[g]; }
    if (tgt_ambiguous[g]) { ambiguous++; ambiguous_cit += tgt_nrefs[g]; ref_report_ambiguous(g); }
    /* A name with more copies than REF_MATCH is a fact about out/, not about
     * the document, so it is counted once in the banner instead of being named
     * once per target: the first version printed 90 such lines on a clean tree,
     * and a log line a reader learns to skip is worse than no log line. */
    if (tgt_nmatch[g] > REF_MATCH) copied++;
    /* Resolved, but only by build output. The reference is not wrong -- the
     * file is named, and a document may legitimately cite a build artefact --
     * but no SOURCE in the declared scope answers to that name, so the verdict
     * is weaker than the word `resolved` suggests, and the reader is told which
     * ones are weak instead of being left to assume. Shrinking REF_ROOTS is the
     * way to make this number move, which is the point: the scope is then
     * falsifiable from the banner rather than from a reading of this comment. */
    { int from_source = 0;
      for (unsigned m = 0; m < tgt_nmatch[g] && m < REF_MATCH; m++)
        if (!tgt_match_artefact[g][m]) from_source = 1;
      if (!from_source) {
        artefact_only++;
        fprintf(stderr, "ARTEFACT-ONLY %s : every file of the declared scope that answers to that "
                        "name is build output under out/c-bootstrap, not a source; the reference is "
                        "not falsified, but no source in scope backs it\n", tgt_name[g]);
      } }
  }

  for (unsigned q = 0; q < refs_n; q++) {
    /* Which document this citation is counted against. The four arrays are
     * filled here, at the point where the verdict is decided, and nowhere
     * else: a counter assembled a second time from the verdict bits would be a
     * second reading of the same judgement, and this file keeps refusing those
     * for exactly the reason the class report below needs one reader. */
    if (ref_which[q] < REF_DOCS) doc_refs[ref_which[q]]++;
    int g = target_of(ref_target[q], strlen(ref_target[q]));
    unsigned long best = 0;
    int long_enough = 0;
    cases++;
    if (g < 0) { good(); continue; }
    if (tgt_nmatch[g] == 0) {
      /* A search that stopped on its budget cannot say a file is absent. */
      if (ref_truncated) {
        fprintf(stderr, "UNRESOLVED %s:%u-%u (%s:%u) : the search stopped on its budget "
                        "of %u directories, so this reference is counted, not failed\n",
                tgt_name[g], ref_lo[q], ref_hi[q], rdoc(q), ref_line[q], REF_MAX_DIRS);
        /* No verdict is claimed when the search stopped, and saying so is what
         * keeps the drift comparison honest: a run whose search was cut short
         * must not be allowed to look like a run in which every citation
         * resolved. */
        ref_verdict_flags[q] |= (unsigned char)V_BUDGET;
        missing++;
        if (ref_which[q] < REF_DOCS) doc_missing[ref_which[q]]++;
        good();
        continue;
      }
      if (unres_n < UNRES_MAX) {
        UnresRef *r = &unres[unres_n++];
        snprintf(r->name, NAME_MAX, "%s", tgt_name[g]);
        r->lo = ref_lo[q];
        r->hi = ref_hi[q];
        r->line = ref_line[q];
        r->doc = ref_which[q] < REF_DOCS ? ref_which[q] : 0;
        r->copied = 0;
        r->at[0] = '\0';
      } else unres_overflow = 1;
      ref_verdict_flags[q] |= (unsigned char)V_UNRESOLVED;
      checks++; failures++;
      fprintf(stderr, "FAIL %s:%u cites %s:%u-%u and no file of the tree has that name; "
                      "the search covered", rdoc(q), ref_line[q], tgt_name[g], ref_lo[q], ref_hi[q]);
      for (unsigned r = 0; r < REF_ROOTS_N; r++)
        fprintf(stderr, " %s%s", *REF_ROOTS[r].path ? REF_ROOTS[r].path : ".",
                REF_ROOTS[r].recurse ? "/" : "");
      fprintf(stderr, "\n");
      missing++;
      continue;
    }
    {
      unsigned pick = tgt_pick[g];
      best = tgt_lines[g][pick];
      long_enough = best >= (unsigned long)ref_hi[q];
    }
    /* RESOLVED TO A COPY. The citation is not missing -- a file of that name
     * was found and read, and the range was judged against its bytes -- but
     * the file is build output under out/c-bootstrap and no source in the
     * declared scope answers to the name, so the verdict is about a copy of
     * the file the sentence means. It is counted separately from `missing`
     * and separately from `copied=` (which counts targets with more than
     * REF_MATCH matches, i.e. copies of DIFFERENT names), because the two
     * numbers answer different questions and adding them would produce a
     * number that answers neither. Kept in the same table as the unresolved
     * citations on purpose: the out-of-scope probe below is the instrument
     * that turns "resolved to a copy" into "the real file is at
     * scripts/ntbuild.sh and the declared scope does not search it", and it
     * was reachable only from the failing branch until now. */
    if (tgt_match_artefact[g][tgt_pick[g]]) {
      if (unres_n < UNRES_MAX) {
        UnresRef *r = &unres[unres_n++];
        snprintf(r->name, NAME_MAX, "%s", tgt_name[g]);
        r->lo = ref_lo[q];
        r->hi = ref_hi[q];
        r->line = ref_line[q];
        r->doc = ref_which[q] < REF_DOCS ? ref_which[q] : 0;
        r->copied = 1;
        snprintf(r->at, REF_PATH, "%s", tgt_match[g][tgt_pick[g]]);
        artefact_copied++;
      } else { unres_overflow = 1; artefact_copied++; }
    }
    good();
    if (ref_which[q] < REF_DOCS) doc_resolved[ref_which[q]]++;
    /* THE RECLASSIFICATION: a stale line's repair is the citation; an unseparated one's is the RESOLVER. */
    if (!long_enough && tgt_ambiguous[g])
      ref_report_unseparated(q, tgt_name[g], ref_lo[q], ref_hi[q], best);
    else if (!long_enough) {
      ref_verdict_flags[q] |= (unsigned char)V_STALE;
      stale++;
      if (ref_which[q] < REF_DOCS) doc_stale[ref_which[q]]++;
      fprintf(stderr, "STALE-LINE %s:%u cites %s:%u-%u and the file it resolves to, %s, "
                      "has %lu lines; counted, not failed, because a line number moves when the "
                      "file does\n", rdoc(q), ref_line[q], tgt_name[g], ref_lo[q], ref_hi[q],
              tgt_match[g][tgt_pick[g]], best);
    } else if (!have_nearest || best - (unsigned long)ref_hi[q] < (unsigned long)nearest) {
      nearest = (unsigned)(best - (unsigned long)ref_hi[q]);
      have_nearest = 1;
    }
  }
  /* THE CLASS, over the set rather than over the items, and the trigger is no
   * longer "something failed to resolve". It is "the table has an entry",
   * because the table now holds a citation that RESOLVED -- to a copy -- and
   * that is the entry most worth reading and the one that used to be
   * unreachable from here. The cost is the out-of-scope probe, a walk of the
   * top-level directories the declared scope never enters; it is paid on any
   * run that has a copy to explain, and skipped on a run that has none. */
  if (unres_n) {
    if (unres_overflow)
      fprintf(stderr, "REF-CLASS truncated : this harness holds %u citations to classify and the "
                      "document produced more, so the classes below are a lower bound\n", UNRES_MAX);
    scope_probe();
    ref_report_unresolved(unres, unres_n, outprobe, outprobe_n, probe_truncated);
  }
  /* The state is built at the END of this function, not here, and the first
   * version of this line stood here. That put it before check_spans() and
   * check_identifiers(), which are the two loops that fill in four of the seven
   * verdict slots -- so the state carried a document whose citations had no
   * span verdict and no identifier verdict yet, and a tree moving under a
   * still document produced `verdict:0`. The end-to-end run over a document
   * copy is what found it: the self-test could not, because it compares two
   * hand-built states and neither of them is built by the three loops. A
   * place where a state is assembled is a place where its order matters, and
   * nothing but a run of the whole thing would have said so. */
  /* The two CONTENT checks, and the counters that say how much of the
   * document each one actually reached. `span_covered` and `ident_covered`
   * are printed because a content check that cannot say its own coverage is
   * the shape this whole section is about: a reader who sees only
   * `ident_missing=0` cannot tell whether the check looked at 219 citations or
   * at none, and those two banners mean opposite things. */
  span_covered = span_blank = span_comment = 0;
  ident_covered = ident_missing = ident_tokens = ident_failed = ident_reported = 0;
  check_spans();
  cases++;
  CHECK(span_covered > 0, "the span check reached at least one resolved reference");
  check_identifiers();
  cases++;
  /* The floor, and only the floor. ident_covered is NOT pinned to a number: a
   * sentence reworded so that it no longer names anything is a legitimate
   * change that must not demand an edit to a C constant here. What is refused
   * is the section being emptied around the check, the same floor
   * MODULE_FLOOR and the per-gate claims pin are. */
  CHECK(ident_covered > 0, "the identifier check reached at least one citation that names something");
  if (ident_missing)
    fprintf(stderr, "IDENT-SCOPE covered=%u tokens=%u missing=%u : a citation that names nothing "
                    "beside it is not checked, and a range that is well formed but names the wrong "
                    "non-blank line is not checkable here at all\n",
            ident_covered, ident_tokens, ident_missing);
  /* The verdicts of this judgement, for the next run to compare against, and
   * built HERE because this is where the last of the three judging loops has
   * run. */
  drift_build_current(spec, n);
  cases++;
  CHECK(resolved > 0, "at least one file:line reference of the documents resolves in the tree");
  /* The per-document floor. It exists because the second document was read by
   * NO gate before this, and a total that includes it silently is a total that
   * would look identical if the file went back to being unread. The check is
   * a FLOOR, not a pin: a document may legitimately stop citing the tree, and
   * the only thing that must never happen again is the check forgetting that
   * the document exists. */
  cases++;
  if (!ref_doc[1] || !ref_docn[1])
    failf("docs/status/ntasm-completion.md does not load from the repository root, so the citations of "
          "the document that states the B2.1 acceptance criteria are not checked at all");
  else
    CHECK(doc_refs[1] > 0,
          "docs/status/ntasm-completion.md carries at least one file:line reference to resolve");
  if (ref_truncated)
    fprintf(stderr, "WALK-BUDGET dirs=%u files=%u : the search stopped early, so no reference is "
                    "failed on absence in this run\n", ref_dirs, ref_files);
  {
    int k = snprintf(ref_banner, sizeof ref_banner,
           "REFERENCES docs=%u refs=%u targets=%u resolved=%u missing=%u stale_lines=%u "
           "nearest_margin=%u walked_dirs=%u walked_files=%u copied=%u artefact_only=%u "
           "artefact_cited=%u roots=%u multi_names=%u multi_citations=%u ambiguous_names=%u ambiguous_citations=%u\n"
           "REFERENCES-PER-DOC %s refs=%u resolved=%u missing=%u stale_lines=%u | %s refs=%u "
           "resolved=%u missing=%u stale_lines=%u\n"
           "REFERENCES-CONTENT span_covered=%u span_blank=%u span_comment=%u ident_covered=%u "
           "ident_tokens=%u ident_missing=%u ident_failed=%u ident_reported=%u "
           "ident_failing_docs=%u "
           "classes_named=%u limits=%s\n",
           (unsigned)REF_DOCS, refs_n, tgts_n, resolved, missing, stale,
           have_nearest ? nearest : 0, ref_dirs, ref_files,
           copied, artefact_only, artefact_copied, REF_ROOTS_N, multi, multi_cit, ambiguous, ambiguous_cit,
           ref_doc[0] ? ref_doc[0] : "?", doc_refs[0], doc_resolved[0], doc_missing[0], doc_stale[0],
           ref_doc[1] ? ref_doc[1] : "?", doc_refs[1], doc_resolved[1], doc_missing[1], doc_stale[1],
           span_covered, span_blank, span_comment, ident_covered, ident_tokens, ident_missing,
           ident_failed, ident_reported, (unsigned)IDENT_FAILING_DOCS,
           unres_n, REF_LIMITS);
    /* A banner that cut itself off is a banner whose LAST words -- the limits --
     * are the ones that went, and a limit that did not fit is a limit nobody
     * reads. The size is therefore checked rather than trusted. */
    if (k < 0 || (size_t)k >= sizeof ref_banner) {
      checks++;
      failures++;
      fprintf(stderr, "FAIL the references banner did not fit in %zu bytes, so the clauses that "
                      "say what this check does not cover are the ones that were cut\n",
              sizeof ref_banner);
    }
  }
  if (announce) fputs(ref_banner, stdout);
}


/* The two documents, named once. Named rather than spelled at each use because
 * a check that says `docs/status/ntasm-completion.md` in one message and
 * `the completion document` in another is a check whose reader has to guess
 * which file a red is about -- and this is the second document, the one with
 * the least history of being checked at all. */
#define DOC0_PATH "spec/ntasm/ntasm.md"
#define DOC2_PATH "docs/status/ntasm-completion.md"
static size_t doc2n;
/* ================================================================== section 10.
 * THE STRUCTURE OF THE TWO DOCUMENTS, which is not what anything above reads.
 *
 * WHY IT EXISTS, in the shape the instance was found in. Every check in this
 * file and in the rest of the suite asks whether a document's CLAIMS are true:
 * does the cited line hold the cited symbol, does the identifier appear in the
 * range, does the code have a row. Not one of them asks whether the document
 * renders. The document owner found, while applying an ordinary edit, that the
 * A5 row had been split across nine physical lines by an earlier edit of its
 * own, that a row had lost a trailing delimiter, and that two literal pipes
 * inside a quoted `grep` alternation in A7 were reading as two extra columns.
 * All three were found by eye. None of them could turn a gate red, because no
 * gate looks at the table -- and a gate green and a document structurally
 * broken are not in tension, they are the same fact seen from two sides.
 *
 * So this section is the same defect class as the rest of this wave, applied to
 * the document's own shape instead of to its claims: an instrument that checks
 * one thing and reads as though it checked the thing. Three classes:
 *
 *   1. TABLE GEOMETRY -- a table is a header row, a delimiter row, and data
 *      rows, all with the same cell count, and a row cannot span two physical
 *      lines. A maximal run of row-shaped lines with no header above it is a
 *      block a reader reads as a table and a renderer reads as a paragraph.
 *   2. CELL ESCAPING -- a `|` inside a code span does NOT protect the cell from
 *      being split; only `\|` does. This is the A7 case, and it is silent in
 *      the worst way: the row renders with extra columns and nothing says so.
 *   3. LINK AND ANCHOR TARGETS -- a `§N` resolves to a heading that exists, a
 *      relative link resolves to a file that exists, and (in the banner above,
 *      not here) every `file:line` citation of either document resolves.
 *
 * WHAT IS RED AND WHAT IS ONLY COUNTED, decided by measurement and not by
 * preference, because that difference is the whole question. The rule applied
 * is the one the brief set: a check that fires many times on correct prose is a
 * report, and a check that never fires on correct prose is a failure. Measured
 * on the two documents as they stand, this section reads 13 tables, 190
 * well-formed data rows, 101 section references and 2 links, and it fires 18
 * times -- every one of them on a malformed row, a cell fragment, an unescaped
 * pipe or a section number that resolves to nothing, and none of them on a
 * well-formed row, a resolved reference or a live link. A false-fire rate of
 * zero out of 306 well-formed constructs is not a rate at which a rule is
 * tuned; it is a rule that is allowed to be red. So every class here FAILS.
 * The two things that do NOT fail upstream are the two that were measured on a
 * correct document and are about a file other lots are moving -- a stale line
 * number is counted, a range touching a comment is reported. Neither is true of
 * a broken table, and a table does not move under a writer.
 *
 * The cost of failing is stated rather than hidden: this section is red on the
 * tree as it stands, on eighteen findings, and the repair belongs to the owner
 * of the documents and not to this file. Every finding names its file and its
 * line, so the repair is a list.
 */
typedef struct {
  unsigned lines, fences;
  unsigned tables, header_rows, delim_rows, data_rows, runs;
  unsigned orphan_runs, orphan_rows;
  unsigned col_bad, delim_bad, tail_frag;
  unsigned esc_rows, esc_pipes, esc_fixed_rows;
  unsigned headings, anchor_refs, anchor_unresolved, links, link_missing;
} DocStat;

/* The two bytes of U+00A7, spelled as escapes because this file is ASCII. A
 * section sign written literally would make the encoding of the source file
 * load-bearing for a check that has nothing to do with encodings. */
#define DOC_SECT "\xc2\xa7"

/* A line is a TABLE ROW when it opens with a pipe and holds at least one more.
 * The trailing pipe is NOT required, because GFM does not require it either --
 * `| a | b | c` is three cells -- and a check that refused it would be red on
 * correct prose, which is the thing this section measures before it decides.
 * The row that lost its trailing delimiter is caught by its CELL COUNT below
 * rather than by its shape, which is where the defect actually lives. */
static int doc_is_row(const char *b, const char *l) {
  const char *k = skip_ws(b, l);
  return k < l && *k == '|' && memchr(k, '|', (size_t)(l - k)) != NULL;
}

/* The cells of a row: one more than the number of CELL DELIMITERS, less one
 * for each delimiter the line does not carry. Written as a count and not as a
 * split so that the empty first and last cells of `| a | b |` are counted by
 * the same rule that counts them in every other row.
 *
 * AN ESCAPED PIPE IS NOT A DELIMITER, and the first version counted it. That
 * is the same bug the escape check exists to catch, sitting inside the check
 * that catches it: the correct spelling `a\|b` was reported as a row with one
 * cell too many, so a document that had done the right thing would have been
 * red for having done it. It was found by the self-test, on the case written
 * to prove the escaped row is SILENT -- which is the whole argument for
 * having that case, since the failure it caught is one no reading of the
 * documents would have found. */
static unsigned doc_cells(const char *b, const char *l) {
  const char *k = skip_ws(b, l);
  unsigned pipes = 0, c;
  for (const char *p = k; p < l; p++) {
    if (*p != '|') continue;
    if (p > k && p[-1] == '\\') continue;
    pipes++;
  }
  c = pipes + 1;
  if (k < l && *k == '|') c--;
  if (l > k && l[-1] == '|') c--;
  return c;
}

/* A DELIMITER ROW: only pipes, dashes, colons and blanks, with at least one
 * dash. Without the dash rule a row of three empty cells would answer, and a
 * table would be found under every table. */
static int doc_is_delim(const char *b, const char *l) {
  int dash = 0;
  if (!memchr(b, '|', (size_t)(l - b))) return 0;
  for (const char *p = b; p < l; p++) {
    if (*p == '|' || *p == ' ' || *p == '\t' || *p == '\r') continue;
    if (*p == '-') { dash = 1; continue; }
    if (*p == ':') continue;
    return 0;
  }
  return dash;
}

/* The pipes of one row, and what the row does about them. `bad` counts pipes
 * inside a code span, which is the A7 defect: GFM splits a cell on an
 * unescaped pipe whether or not it is inside backticks, so `a|b` written as
 * code inside a cell becomes two cells, and the only correct spelling is
 * `a\|b`. `fixed` counts the pipes that ARE escaped, so the banner can say the
 * correct form is in use somewhere -- a check that could not tell an escaped
 * pipe from an unescaped one could not fail on anything real. */
static void doc_row_pipes(const char *b, const char *l, unsigned *bad, unsigned *fixed) {
  const char *k = skip_ws(b, l);
  int open = 0;
  *bad = 0;
  *fixed = 0;
  for (const char *p = k; p < l; p++) {
    if (*p == '`') {
      const char *q = p;
      unsigned run;
      while (q < l && *q == '`') q++;
      run = (unsigned)(q - p);
      if (open == 0) open = (int)run;
      else if (open == (int)run) open = 0;
      p = q - 1;
      continue;
    }
    if (*p != '|') continue;
    if (p > k && p[-1] == '\\') { (*fixed)++; continue; }
    if (open) (*bad)++;
  }
}

/* One finding, one check, one failure -- the shape the rest of this file uses
 * for a per-item verdict, and the reason `failures=` in the final banner counts
 * the defects rather than the classes.
 *
 * The self-test calls the scanners with `announce=0` and reads their counters,
 * so a case that stops detecting turns this file red rather than quietly
 * agreeing.
 *
 * `doc_synthetic` is a guard, not a fix, and it is honest to say so. Every call
 * site is `if (announce) { fprintf(...); doc_found(); }` -- the COUNT is inside
 * the guard -- so with `announce=0` the self-test neither prints nor counts, and
 * nothing was ever charged here. This flag changes no current behaviour. It
 * exists because that invariant is invisible: it is ten call sites' worth of
 * nesting, and the first one written outside the guard would charge the
 * self-test's own successes to this file, silently, with the message
 * suppressed by the same flag. That is a real defect and it is the same shape
 * as the drift and reference rows -- it would be reported against the wrong
 * party -- so it is closed here rather than left to a reader to notice.
 *
 * The "failures=1 with no FAIL line" that prompted this was NOT this. The log
 * held five FAIL lines, all one causal chain: a parity self-test case failing,
 * which voided the image, which zeroed a gate's counters, which made two
 * numbers in the spec wrong. The banner's `failures=1` was a cross-gate count,
 * and the conclusion drawn from it -- that a failure had printed nothing -- was
 * wrong. Recorded here because a guard whose comment names a symptom it did not
 * cause is the same defect in a different medium. */
static int doc_synthetic;

static void doc_found(void) {
  if (doc_synthetic) return;
  checks++;
  failures++;
}

/* TABLES AND ESCAPES over one document, in ONE pass over its lines, because two
 * passes over the same text is two chances to disagree about what a line is. */
static void doc_scan(const char *path, const char *t, size_t n, DocStat *st, int announce) {
  const char *e = t + n, *cur = t, *b, *l, *nb, *nl;
  unsigned lineno = 0, run_pos = 0, run_start = 0, hdr_cells = 0;
  int run_headed = 0, have_hdr = 0, in_fence = 0;

  while ((cur = next_line(cur, e, &b, &l))) {
    const char *k = skip_ws(b, l);
    size_t klen = (size_t)(l - k);
    lineno++;
    st->lines++;
    /* A fenced block is neither prose nor a table. Skipping it is not tidiness:
     * a grammar sample inside a fence may hold a line that opens with a pipe,
     * and a row predicate that read it would invent a table that is not there. */
    if (klen >= 3 && !memcmp(k, "```", 3)) {
      if (!in_fence) st->fences++;
      in_fence = !in_fence;
      continue;
    }
    if (in_fence) continue;

    if (doc_is_row(b, l)) {
      const char *np = next_line(cur, e, &nb, &nl);
      unsigned cells = doc_cells(b, l), bad = 0, fixed = 0;
      if (run_pos == 0) {
        st->runs++;
        run_start = lineno;
        run_headed = (np && doc_is_delim(nb, nl));
        if (run_headed) {
          hdr_cells = cells;
          have_hdr = 1;
          st->tables++;
          st->header_rows++;
          st->delim_rows++;
          if (cells == 0) {
            st->delim_bad++;
            if (announce) {
              fprintf(stderr, "FAIL DOC-TABLE-DELIM %s:%u : this line is the header of a table and holds "
                              "no cell at all, so the table it opens has no columns\n", path, lineno);
              doc_found();
            }
          } else if (doc_cells(nb, nl) != cells) {
            st->delim_bad++;
            if (announce) {
              fprintf(stderr, "FAIL DOC-TABLE-DELIM %s:%u : the header row above has %u cells and its "
                              "delimiter row has %u, so the two disagree about how many columns "
                              "the table has\n", path, lineno, cells, doc_cells(nb, nl));
              doc_found();
            }
          }
        }
      }
      run_pos++;
      /* On a headed table the first two lines ARE the header and the delimiter
       * and are counted above, so the comparison starts at the third line. On
       * an UNHEADED run every line is compared, against the nearest header
       * above it in the same document -- which is the only reference a broken
       * table has, and refusing to compare would mean the rows of a table whose
       * header was lost are the one thing never checked. */
      if (run_headed ? run_pos > 2u : have_hdr) {
        if (cells != hdr_cells) {
          st->col_bad++;
          if (announce) {
            /* TWO DIRECTIONS, because they lose different things. Too many
             * cells and the surplus is DROPPED, so a whole column of the table
             * is invisible. Too few and the shortfall is PADDED with empty
             * cells, so the row reads as though the missing columns were blank
             * -- which for an acceptance table is a claim, and a false one. The
             * first version subtracted in both directions and printed
             * 4294967295 cells for the row that was one short, which is the
             * kind of number a reader learns to skip. */
            if (cells > hdr_cells)
              fprintf(stderr, "FAIL DOC-TABLE-COLS %s:%u : this row has %u cells and the header of its "
                              "table has %u; a renderer keeps the first %u and drops the rest, so "
                              "%u cell(s) of this row are invisible\n",
                      path, lineno, cells, hdr_cells, hdr_cells, cells - hdr_cells);
            else
              fprintf(stderr, "FAIL DOC-TABLE-COLS %s:%u : this row has %u cells and the header of its "
                              "table has %u; a renderer pads the missing %u with empty cells, so "
                              "the last %u column(s) of this row read as blank\n",
                      path, lineno, cells, hdr_cells, hdr_cells - cells, hdr_cells - cells);
            doc_found();
          }
        } else if (run_headed) {
          st->data_rows++;
        }
      }
      doc_row_pipes(b, l, &bad, &fixed);
      if (bad) {
        st->esc_rows++;
        st->esc_pipes += bad;
        if (announce) {
          fprintf(stderr, "FAIL DOC-ESCAPE %s:%u : %u pipe(s) inside a code span of a table row; a code "
                          "span does not protect a cell from being split, and only \\| does\n",
                  path, lineno, bad);
          doc_found();
        }
      }
      if (fixed) st->esc_fixed_rows++;
      continue;
    }

    if (run_pos) {
      if (!run_headed) {
        st->orphan_runs++;
        st->orphan_rows += run_pos;
        if (announce) {
          fprintf(stderr, "FAIL DOC-TABLE-ORPHAN %s:%u : %u consecutive row-shaped lines with no header "
                          "and no delimiter row above them, so a reader sees a table and a "
                          "renderer sees one paragraph\n", path, run_start, run_pos);
          doc_found();
        }
      }
      run_pos = 0;
      run_headed = 0;
    }
    if (klen > 1 && k[klen - 1] == '|' && k[klen - 2] != '\\') {
      st->tail_frag++;
      if (announce) {
        fprintf(stderr, "FAIL DOC-TABLE-TAIL %s:%u : a line that opens no row and ends with a cell "
                        "delimiter; this is the shape a table cell leaves when its row was split "
                        "across physical lines\n", path, lineno);
        doc_found();
      }
    }
  }
  if (run_pos && !run_headed) {
    st->orphan_runs++;
    st->orphan_rows += run_pos;
    if (announce) {
      fprintf(stderr, "FAIL DOC-TABLE-ORPHAN %s:%u : %u consecutive row-shaped lines with no header and "
                      "no delimiter row above them, so a reader sees a table and a renderer sees "
                      "one paragraph\n", path, run_start, run_pos);
      doc_found();
    }
  }
}

/* ============================== the ANCHOR half of class 3.
 *
 * Headings are collected from BOTH documents, and a `§N` in either document is
 * looked up in the union. The union is the right set and not a convenience:
 * `docs/status/ntasm-completion.md` writes "spec/ntasm/ntasm.md §17" and names the other
 * document explicitly, and a rule that confined each document to its own
 * numbers would call that a defect. What the union cannot do is notice a
 * reference written against the WRONG document -- a `§5` in the spec that means
 * the other document's §5 and happens to exist in both is resolved, and the
 * limits clause says so rather than leaving it to be discovered. */
#define HEAD_MAX 192
static char head_num[HEAD_MAX][24];
static char head_slug[HEAD_MAX][96];
static unsigned head_n, head_slug_n, head_overflow;

static void head_add_num(const char *s, size_t len) {
  if (len == 0 || len >= sizeof head_num[0]) return;
  for (unsigned i = 0; i < head_n; i++)
    if (strlen(head_num[i]) == len && !memcmp(head_num[i], s, len)) return;
  if (head_n >= HEAD_MAX) { head_overflow = 1; return; }
  memcpy(head_num[head_n], s, len);
  head_num[head_n][len] = 0;
  head_n++;
}

/* A GFM anchor slug, computed the way a renderer computes it: lowercased, every
 * run of characters that is not a letter or a digit folded to one '-', and no
 * leading or trailing '-'. Written out rather than skipped because a `#` link
 * that resolves to nothing is as broken as a relative link that resolves to
 * nothing, and a check that covered one style and not the other would be a
 * check whose coverage depends on which style the author happened to use.
 *
 * Non-ASCII is folded to nothing rather than kept, which is where this departs
 * from a real renderer: GFM keeps unicode letters in a slug and this drops
 * them, so a link to a heading whose slug keeps a non-ASCII letter is NOT
 * verified here. That is a limit and not a defect -- it can only ever let a
 * broken `#` link through, never turn a sound one red, and the two documents
 * carry no `#` link between them, so the case is empty today and named. */
static void slug_of(const char *s, size_t len, char *out, size_t cap) {
  size_t o = 0;
  int dash = 0;
  for (size_t i = 0; i < len && o + 1 < cap; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c >= 0x80) {                    /* the whole sequence, one folded nothing */
      while (i + 1 < len && ((unsigned char)s[i + 1] & 0xC0) == 0x80) i++;
      if (!dash) { out[o++] = '-'; dash = 1; }
      continue;
    }
    if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
      out[o++] = (char)c;
      dash = 0;
    } else if (!dash) {
      out[o++] = '-';
      dash = 1;
    }
  }
  while (o > 0 && out[o - 1] == '-') o--;
  out[o] = 0;
}

static void head_collect(const char *t, size_t n, DocStat *st) {
  const char *e = t + n, *p = t, *b, *l;
  while ((p = next_line(p, e, &b, &l))) {
    const char *k = skip_ws(b, l), *q;
    size_t hash = 0, len;
    char slug[96];
    while (k + hash < l && k[hash] == '#') hash++;
    if (hash == 0 || hash > 6) continue;
    q = k + hash;
    while (q < l && (*q == ' ' || *q == '\t')) q++;
    if (q < l && *q >= '0' && *q <= '9') {
      const char *d = q;
      while (d < l && ((*d >= '0' && *d <= '9') || *d == '.')) d++;
      len = (size_t)(d - q);
      while (len > 0 && q[len - 1] == '.') len--;
      head_add_num(q, len);
    }
    slug_of(q, (size_t)(l - q), slug, sizeof slug);
    if (slug[0] && head_slug_n < HEAD_MAX) {
      snprintf(head_slug[head_slug_n], sizeof head_slug[0], "%s", slug);
      head_slug_n++;
    } else if (slug[0]) {
      head_overflow = 1;
    }
    st->headings++;
  }
}

static int head_has_num(const char *s, size_t len) {
  for (unsigned i = 0; i < head_n; i++)
    if (strlen(head_num[i]) == len && !memcmp(head_num[i], s, len)) return 1;
  return 0;
}

/* A relative link target, resolved against the document's own directory first
 * and against the repository root second, and called missing only when neither
 * answers. Two candidates rather than one because the two documents live at
 * different depths and each spells its links its own way -- the spec writes
 * `../docs/ntasm-completion.md` from spec/ and the completion document writes
 * none -- and a resolver that picked one would have been a red on a correct
 * document the first time either style changed. */
static int doc_link_exists(const char *path, const char *tgt, size_t len) {
  char buf[512];
  const char *slash = strrchr(path, '/');
  size_t dlen = slash ? (size_t)(slash - path) + 1 : 0;
  struct stat st;
  if (len == 0 || dlen + len + 2 >= sizeof buf) return 0;
  memcpy(buf, path, dlen);
  memcpy(buf + dlen, tgt, len);
  buf[dlen + len] = 0;
  if (stat(buf, &st) == 0 && S_ISREG(st.st_mode)) return 1;
  if (len + 2 < sizeof buf) {
    memcpy(buf, tgt, len);
    buf[len] = 0;
    if (stat(buf, &st) == 0 && S_ISREG(st.st_mode)) return 1;
  }
  return 0;
}

static void doc_anchors(const char *path, const char *t, size_t n, DocStat *st, int announce) {
  const char *e = t + n, *p = t, *b, *l;
  size_t seclen = strlen(DOC_SECT);
  unsigned lineno = 0;
  while ((p = next_line(p, e, &b, &l))) {
    lineno++;
    for (const char *i = b; i + seclen <= l; i++) {
      const char *d;
      size_t len;
      if (memcmp(i, DOC_SECT, seclen) != 0) continue;
      d = i + seclen;
      if (d >= l || *d < '0' || *d > '9') continue;
      while (d < l && ((*d >= '0' && *d <= '9') || *d == '.')) d++;
      len = (size_t)(d - (i + seclen));
      while (len > 0 && (i + seclen)[len - 1] == '.') len--;
      st->anchor_refs++;
      if (head_has_num(i + seclen, len)) continue;
      st->anchor_unresolved++;
      if (announce) {
        fprintf(stderr, "FAIL DOC-ANCHOR %s:%u : neither %s nor %s carries a heading numbered %.*s, so "
                        "this cross-reference resolves to nothing\n",
                path, lineno, DOC0_PATH, DOC2_PATH, (int)len, i + seclen);
        doc_found();
      }
    }
    /* every markdown link of the line, in one pass over it */
    for (const char *i = b; i < l; i++) {
      const char *rb, *tgt;
      size_t len;
      if (*i != ']' || i + 1 >= l || i[1] != '(') continue;
      rb = i + 2;
      tgt = rb;
      while (rb < l && *rb != ')') rb++;
      if (rb >= l) break;
      len = (size_t)(rb - tgt);
      st->links++;
      if (len && *tgt == '#') {
        char want[96];
        int ok = 0;
        slug_of(tgt + 1, len - 1, want, sizeof want);
        for (unsigned g = 0; g < head_slug_n; g++)
          if (!strcmp(head_slug[g], want)) { ok = 1; break; }
        if (ok) continue;
        st->link_missing++;
        if (announce) {
          fprintf(stderr, "FAIL DOC-LINK %s:%u : the link to #%s has no heading of that name in this "
                          "document\n", path, lineno, want);
          doc_found();
        }
        continue;
      }
      {
        const char *hash = memchr(tgt, '#', len);
        size_t flen = hash ? (size_t)(hash - tgt) : len;
        if (doc_link_exists(path, tgt, flen)) continue;
      }
      st->link_missing++;
      if (announce) {
        fprintf(stderr, "FAIL DOC-LINK %s:%u : the link target %.*s does not exist, relative to this "
                        "document's directory or to the repository root\n",
                path, lineno, (int)len, tgt);
        doc_found();
      }
      i = rb;
    }
  }
}

/* The `limits=` of the three structural checks, on every one of the three banner
 * lines, and CHECKED for fit like the one above: a limit that did not fit is a
 * limit nobody reads, and the limits are the last words of the line. */
#define DOC_LIMITS \
  "geometry:a_row_shaped_line_is_one_that_OPENS_with_a_pipe_and_the_trailing_pipe_is_optional_" \
  "because_GFM_makes_it_optional_so_the_row_that_lost_one_is_caught_by_its_CELL_COUNT_not_by_" \
  "its_shape; " \
  "fenced_blocks_are_skipped_entirely_so_a_table_written_INSIDE_one_is_not_checked_at_all; " \
  "an_unheaded_run_is_compared_against_the_nearest_header_above_it_which_is_a_guess_about_" \
  "which_table_it_belongs_to; " \
  "escape:only_pipes_inside_a_CODE_SPAN_are_refused_and_an_unescaped_pipe_in_plain_text_is_" \
  "caught_only_when_it_changes_the_cell_count; " \
  "tail_fragment:any_non_blank_line_outside_a_table_that_ends_in_an_unescaped_pipe_is_refused_" \
  "including_a_sentence_that_legitimately_ends_in_one_and_the_measured_count_is_two_both_of_" \
  "which_are_the_broken_cell_shape; " \
  "anchors:the_number_is_looked_up_in_BOTH_documents_together_so_a_reference_written_against_" \
  "the_wrong_document_that_happens_to_exist_in_the_other_is_resolved_and_not_caught_and_a_" \
  "slug_that_keeps_a_non_ASCII_letter_is_not_verified; " \
  "links:only_markdown_links_are_checked_and_a_bare_path_in_prose_is_a_file:line_citation_" \
  "checked_by_the_REFERENCES_lines_above_or_not_at_all; " \
  "structure_is_not_correctness_a_sound_table_can_state_a_false_thing_and_this_section_cannot_" \
  "read_a_word_of_it"

static char doc_banner[2048];

/* The driver, and the verdict. Every counter is printed, INCLUDING the ones
 * that stayed at zero, because a reader who sees only `unresolved=0` cannot
 * tell whether the check looked at 101 section references or at none -- and
 * those two banners mean opposite things. */
static void check_doc_structure(const char *t0, size_t n0, const char *t1, size_t n1) {
  DocStat a, b;
  unsigned findings;
  int k;
  memset(&a, 0, sizeof a);
  memset(&b, 0, sizeof b);
  head_n = head_slug_n = head_overflow = 0;
  memset(head_slug, 0, sizeof head_slug);
  doc_scan(DOC0_PATH, t0, n0, &a, 1);
  doc_scan(DOC2_PATH, t1, n1, &b, 1);
  head_collect(t0, n0, &a);
  head_collect(t1, n1, &b);
  doc_anchors(DOC0_PATH, t0, n0, &a, 1);
  doc_anchors(DOC2_PATH, t1, n1, &b, 1);

  cases++;
  /* Floors, and the reason they are floors and not pins: a document may
   * legitimately end with no table, no link and no section reference, and a pin
   * on any of those numbers is a sentence reworded into a red. What must never
   * happen again is this section being emptied around the check. */
  CHECK(a.tables + b.tables > 0,
        "the documents carry at least one table for the geometry check to read");
  CHECK(a.runs + b.runs > 0, "the documents carry at least one row-shaped line");
  CHECK(a.anchor_refs + b.anchor_refs > 0,
        "the documents carry at least one section cross-reference for the anchor check to read");
  if (head_overflow)
    failf("the documents carry more than %u headings, so the section numbers and the anchors below "
          "are a lower bound", HEAD_MAX);
  if (head_n == 0)
    failf("no heading of either document carries a section number, so every section cross-reference "
          "below would be unresolved for the wrong reason");

  findings = a.orphan_runs + b.orphan_runs + a.col_bad + b.col_bad +
             a.delim_bad + b.delim_bad + a.tail_frag + b.tail_frag +
             a.esc_rows + b.esc_rows + a.anchor_unresolved + b.anchor_unresolved +
             a.link_missing + b.link_missing;
  /* Not a check and not a failure: a pointer to the count the reader needs, in
   * one sentence, in the place the log is read. The findings themselves are
   * already in `failures=` and each one is named above with its file and line. */
  fprintf(stderr, "DOC-STRUCTURE defects=%u : every one is named above with its file and its "
                  "line. A row that renders with the wrong number of columns makes every number "
                  "in it unreadable, and a document whose table is broken is not a document a "
                  "reader can rely on. The repair belongs to the owner of the documents, not to "
                  "this harness.\n", findings);

  k = snprintf(doc_banner, sizeof doc_banner,
         "DOC-TABLE docs=2 tables=%u header_rows=%u delimiter_rows=%u data_rows=%u runs=%u "
         "orphan_runs=%u orphan_rows=%u col_mismatch=%u delimiter_mismatch=%u tail_fragments=%u "
         "fenced_blocks_skipped=%u\n"
         "DOC-ESCAPE rows_with_an_unescaped_pipe_in_a_code_span=%u such_pipes=%u "
         "rows_using_the_escape=%u\n"
         "DOC-ANCHOR section_numbers=%u section_refs=%u unresolved=%u links=%u missing=%u limits=%s\n",
         a.tables + b.tables, a.header_rows + b.header_rows, a.delim_rows + b.delim_rows,
         a.data_rows + b.data_rows, a.runs + b.runs,
         a.orphan_runs + b.orphan_runs, a.orphan_rows + b.orphan_rows,
         a.col_bad + b.col_bad, a.delim_bad + b.delim_bad, a.tail_frag + b.tail_frag,
         a.fences + b.fences,
         a.esc_rows + b.esc_rows, a.esc_pipes + b.esc_pipes, a.esc_fixed_rows + b.esc_fixed_rows,
         head_n, a.anchor_refs + b.anchor_refs, a.anchor_unresolved + b.anchor_unresolved,
         a.links + b.links, a.link_missing + b.link_missing, DOC_LIMITS);
  if (k < 0 || (size_t)k >= sizeof doc_banner) {
    checks++;
    failures++;
    fprintf(stderr, "FAIL the structural banner did not fit in %zu bytes, so the clauses that say "
                    "what these three checks do not cover are the ones that were cut\n",
            sizeof doc_banner);
  }
  fputs(doc_banner, stdout);
}

/* ============================== THE SELF-TEST, and it is not optional.
 *
 * A structural check that passes on the current documents might be passing
 * because the documents happen to be sound, or because the check cannot see the
 * defect. Those two look identical from the banner and the second is worse than
 * having no check, so every sub-check above is put to a document copy carrying a
 * known defect, through the SAME functions, on EVERY invocation -- not behind a
 * flag, because a self-test behind a flag is an instrument exercised in exactly
 * one state, which is the thing this project keeps paying for.
 *
 * The negative half matters as much as the positive half and is the half the
 * fail-versus-report decision rests on: each case is paired with a document that
 * is correct, and the check must be SILENT on it. A rule that cannot be quiet
 * has no verdict to give. The link cases are answered by the real filesystem
 * rather than by a stub, so a `link_missing` that fires here means a file really
 * is absent and not that a mock said so. */
static void doc_case(const char *what, const char *text,
                     unsigned want_orphan, unsigned want_col, unsigned want_esc,
                     unsigned want_delim, unsigned want_tail, unsigned want_anchor,
                     unsigned want_link) {
  DocStat st;
  size_t n = strlen(text);
  memset(&st, 0, sizeof st);
  head_n = head_slug_n = head_overflow = 0;
  memset(head_slug, 0, sizeof head_slug);
  /* A self-test's fixtures are synthetic: the scanners are expected to find
   things in them, and those findings must not be counted against this file. */
  doc_synthetic = 1;
  doc_scan(DOC2_PATH, text, n, &st, 0);
  head_collect(text, n, &st);
  doc_anchors(DOC2_PATH, text, n, &st, 0);
  doc_synthetic = 0;
  cases++;
  if (st.orphan_runs != want_orphan || st.col_bad != want_col || st.esc_rows != want_esc ||
      st.delim_bad != want_delim || st.tail_frag != want_tail ||
      st.anchor_unresolved != want_anchor || st.link_missing != want_link) {
    checks++;
    failures++;
    fprintf(stderr, "FAIL the structural self-test case `%s' did not read what it was built to "
                    "read: orphan=%u/%u col=%u/%u escape=%u/%u delim=%u/%u tail=%u/%u "
                    "anchor=%u/%u link=%u/%u. A self-test that stops detecting is worse than no "
                    "self-test, because it still says nothing is wrong.\n",
            what, st.orphan_runs, want_orphan, st.col_bad, want_col, st.esc_rows, want_esc,
            st.delim_bad, want_delim, st.tail_frag, want_tail, st.anchor_unresolved, want_anchor,
            st.link_missing, want_link);
  } else good();
}

static void check_doc_structure_selftest(void) {
  /* 1. A table that is right. Everything at zero: this is the case that says
   *    the check can be quiet, and the case the fail/report decision rests on. */
  doc_case("a well formed table",
           "| a | b | c |\n|---|---|---|\n| 1 | 2 | 3 |\n| 4 | 5 | 6 |\n",
           0, 0, 0, 0, 0, 0, 0);
  /* 2. A row split across physical lines: the cell keeps its closing delimiter
   *    and loses its row, and what is left below the table is the shape of a
   *    cell with no row. This is the A2 defect. */
  doc_case("a row split across physical lines",
           "| a | b | c |\n|---|---|---|\n| 1 | 2 | 3 |\n\nthe rest of the cell, over here. |\n",
           0, 0, 0, 0, 1, 0, 0);
  /* 3. A run of rows with no header above it: the A5 defect after the split has
   *    broken the table in two. The rows keep the header's cell count, which is
   *    the point -- the orphan finding is the only one that fires here, and a
   *    case that fired on everything would not be able to tell two defects apart
   *    in a document that has both. */
  doc_case("an unheaded run of rows",
           "| a | b | c |\n|---|---|---|\n| 1 | 2 | 3 |\n\n| 4 | 5 | 6 |\n| 7 | 8 | 9 |\n",
           1, 0, 0, 0, 0, 0, 0);
  /* 4. A row that gained a cell. A renderer keeps the header's count and drops
   *    the rest, so the extra cell is invisible. */
  doc_case("a row with more cells than its header",
           "| a | b | c |\n|---|---|---|\n| 1 | 2 | 3 | 4 |\n",
           0, 1, 0, 0, 0, 0, 0);
  /* 5. A header and a delimiter that disagree about the width. The data row
   *    matches the HEADER, so the delimiter row is the only thing wrong, and
   *    this is the only case that can catch a rule which read the delimiter
   *    where it should have read the header. */
  doc_case("a delimiter row of the wrong width",
           "| a | b | c |\n|---|---|\n| 1 | 2 | 3 |\n",
           0, 0, 0, 1, 0, 0, 0);
  /* 6. The A7 case as it was found: a pipe inside a code span, which splits the
   *    cell with nothing at all to show that it did. It fires TWICE and by two
   *    independent readings -- the escape rule, and the cell count -- because
   *    the cell count is the consequence and the escape is the cause, and a
   *    document can be broken by either without the other noticing. */
  doc_case("an unescaped pipe inside a code span",
           "| a | b |\n|---|---|\n| 1 | `x|y` |\n",
           0, 1, 1, 0, 0, 0, 0);
  /* 7. The same row with the escape. It must be SILENT on BOTH readings: a
   *    check that could not tell the correct spelling from the broken one would
   *    be a check that could not fail on anything real, and would be red on a
   *    correct row. This case is what caught doc_cells counting an escaped pipe
   *    as a delimiter -- the same bug, inside the check that catches it. */
  doc_case("the same row with the pipe escaped",
           "| a | b |\n|---|---|\n| 1 | `x\\|y` |\n",
           0, 0, 0, 0, 0, 0, 0);
  /* 8. A section reference to a heading that is not there. */
  doc_case("a section reference with no heading",
           "## 17.6 the table\n\nsee " DOC_SECT "17.2 for the other half\n",
           0, 0, 0, 0, 0, 1, 0);
  /* 9. The same reference to a heading that IS there. */
  doc_case("a section reference that resolves",
           "## 17.2 the table\n\nsee " DOC_SECT "17.2 for the other half\n",
           0, 0, 0, 0, 0, 0, 0);
  /* 10. A link to a file that does not exist. The name is derived from the file
   *     that does, so the negative is a real filesystem answer and not a stub:
   *     were the file ever created this case would go quiet and say so, which is
   *     the correct behaviour and the reason the name is not obviously fake. */
  doc_case("a link to a file that does not exist",
           "see [the doc](ntasm-completion-NO-SUCH-FILE.md)\n", 0, 0, 0, 0, 0, 0, 1);
  /* 11. A relative link that resolves, against the document's own directory. */
  doc_case("a link that resolves",
           "see [the doc](ntasm-completion.md)\n", 0, 0, 0, 0, 0, 0, 0);
  /* 12. A grammar sample inside a fence that opens with a pipe. It must be
   *     SILENT: a row predicate that read a fence would invent a table in a
   *     document that has none, which is the false fire this case keeps out. */
  doc_case("a fence that holds a row-shaped line",
           "```text\n| not | a | table |\n|---|---|---|\n```\n", 0, 0, 0, 0, 0, 0, 0);
}

/* ================================================================== the shape
 * of the 17.9 register, which is a different question from how MANY rows it
 * has, and the only one a count cannot answer.
 *
 * WHY SHAPE, and the reason is measured rather than preferred. That register's
 * numbering has drifted, or been one edit away from drifting, three times in
 * one evening: its row count went 32 -> 33 -> 34, a duplicate U33 was briefly
 * present, and a closing paragraph was written twice into a table body and
 * orphaned a row. A count of rows passes all three. `rows == 34` written down
 * passes the first two and turns the third into a C edit. What catches them is
 * a set of RELATIONS AMONG THE ROWS, each stated so that perturbing the tree
 * breaks it:
 *
 *   R1 NO HOLE. The labels are 1..N with nothing missing between them.
 *   R2 NO DUPLICATE. A repeated label is the count-neutral defect, and the
 *      count is the whole reason R2 exists: P2 appended a well-formed second
 *      U33 and nothing in the suite moved.
 *   R3 THE RUN ENDS AT THE HIGHEST ROW AND THE ROW COUNT IS IT. Ascending
 *      document order, a first label of 1, a last label equal to the maximum,
 *      and the number of rows equal to that same maximum.
 *   R4 THE INDEPENDENT ANCHOR. See the note on tautology below; this is the
 *      one arm whose expectation is NOT read out of the table.
 *
 * The table is READ, never transcribed: the section comes from doc_section,
 * the rows from doc_is_row, the first cell from u_row_label below, which uses
 * doc_cells' escaped-pipe rule rather than a second opinion about it. A
 * literal list of U-identifiers written into this file would be a second copy
 * of the register, and a second copy is what U29 and U30 are about.
 */

#define REG_U_MAX 4096   /* the label space; a citation outside it is named */
#define REG_ROWS_MAX 1024 /* a register longer than this is reported, not cut */

static unsigned char reg_seen[REG_U_MAX + 1];

/* ASCII alphanumerics and the underscore, spelled out rather than taken from
 * <ctype.h>: the token boundary of a citation must not depend on the locale,
 * and every byte of a multi-byte character in these documents is above 0x7f
 * and therefore a boundary, which is the correct reading of "not a letter of
 * this identifier". */
static int reg_token_char(int c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

/* THE LABEL OF A REGISTER ROW. The WHOLE of cell 0 must be `U` and at least
 * one decimal digit and nothing else, so a cell reading `U17 (clos)` is
 * refused here instead of counted as U17 -- a shape check that accepts a
 * decorated label is measuring the decoration. The row predicate is
 * doc_is_row and the escaped-pipe rule is doc_cells', for the reason the
 * comment on doc_cells gives: a row whose cells were counted two ways would be
 * two different rows to two different checks in this same run.
 *
 * Returns the END of cell 0, which is where the citations on this row begin,
 * or 0 when the line is not a row of the register. `*start` receives the
 * beginning, which the citation pass needs so that it never mistakes a label
 * for a citation of itself. */
static const char *u_row_label(const char *b, const char *l, unsigned *out, const char **start) {
  const char *k = skip_ws(b, l);
  if (!doc_is_row(b, l)) return 0;
  const char *s = k + 1, *e = l;
  for (const char *p = s; p < l; p++)
    if (*p == '|' && p[-1] != '\\') { e = p; break; }
  while (s < e && (*s == ' ' || *s == '\t' || *s == '\r')) s++;
  while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r')) e--;
  if (e - s < 2 || s[0] != 'U') return 0;
  unsigned v = 0;
  for (const char *p = s + 1; p < e; p++) {
    if (*p < '0' || *p > '9') return 0;
    v = v * 10u + (unsigned)(*p - '0');
    if (v > REG_U_MAX) return 0;
  }
  *out = v;
  *start = s;
  return e;
}

/* ONE CITATION of the register: `U` and at least one decimal digit with a
 * non-token character on BOTH sides, so `U17` and a backquoted `U17` are
 * citations while `SU17` and `U17a` are not tokens of this register at all.
 * `*out` is 0 for a number outside the label space, which is reported by the
 * caller rather than skipped: a check that silently drops what it cannot
 * classify is a check that can only ever look complete.
 * Returns the end of the number, or 0 when there is no citation here. */
static const char *u_citation(const char *p, const char *e, const char *line, unsigned *out) {
  if (p >= e || *p != 'U') return 0;
  if (p > line && reg_token_char((unsigned char)p[-1])) return 0;
  const char *q = p + 1;
  unsigned v = 0;
  while (q < e && *q >= '0' && *q <= '9') { v = v * 10u + (unsigned)(*q - '0'); q++; }
  if (q == p + 1) return 0;
  if (q < e && reg_token_char((unsigned char)*q)) return 0;
  *out = v > REG_U_MAX ? 0u : v;
  return q;
}

/* ---------------------------------------------------------------- THE ANCHOR,
 * and why this is not a tautology.
 *
 * R1, R2 and R3 compare the rows of the table AMONG THEMSELVES. Every quantity
 * they use -- the row count, the largest label, the first and the last -- is
 * read out of the very table being asserted on, and NOT ONE OF THEM IS WRITTEN
 * DOWN HERE. That is a choice, and the reason is this file's own: a constant
 * that says "exactly this much" is a maintenance trap, because a legitimate
 * new row would then be a C edit, and a gate whose red means "somebody was
 * right" is a gate whose red stops meaning that. So the register is free to
 * grow and this file never has to be told about it.
 *
 * The cost of that choice is stated here rather than left to be discovered:
 * a register that lost its LAST rows and renumbered nothing is a flawless
 * 1..N run, and R1, R2 and R3 all pass it. That is the failure mode this check
 * cannot catch by shape, and the cure for it is not a pin -- a pin cannot tell
 * a shortened register from a legitimate removal, because the register's own
 * closing rule says a line LEAVES the table when a gate covers it. The cure is
 * a CITATION.
 *
 * R4 is that cure and it is the INDEPENDENT ANCHOR. A `U17` written in the
 * prose of spec/ntasm/ntasm.md, or the `U28` of the other document, is a DEMAND on
 * the table made from a text the table does not occupy, and in one case from a
 * second file. The expectation is read from somewhere else, so it cannot be
 * satisfied by re-reading the table, and that is the whole of the difference
 * between an anchor and a tautology. Deleting the U17 row does not shorten the
 * run to 16 -- it leaves 1..16 and 18..34 -- and it strands a sentence that
 * still says "the U17 row of the 17.9 section". R1 catches the hole, R4
 * catches the sentence, and neither expectation is derived from the other.
 *
 * IN ONE PLACE, so a reader does not have to reconstruct it:
 *   DERIVED, every run, never written down: rows, max, first, last, the set.
 *   ANCHORED, and independent of the table: the set of labels cited in the
 *   prose of EITHER document -- the cross-document half of it is the only
 *   anchor in this check that this file cannot invalidate by editing the
 *   register -- together with the convention that the run starts at U1, which
 *   is a convention of the register's naming and not a measurement, and which
 *   a deliberate change would have to change here in the open. */
/* ONE VERDICT, and the reason it is a function rather than a repeated block.
 *
 * FIRST, so that a failure carries its own name and its own sentence: a count a
 * reader cannot turn into a line is a count they will conclude is wrong when
 * the count was right and the message was missing.
 *
 * SECOND, and this is the finding rather than the tidiness. A verdict that is
 * SKIPPED appears in no count at all, so an instrument that counts increments
 * cannot see it and it cannot be found by a sweep -- it has to be found by
 * reading. The overflow guard below was exactly such a branch, written as
 * `if (!overflow && cond) good(); else if (!overflow) FAIL`, which on overflow
 * neither passed nor failed. It is unreachable on this tree and unreachable is
 * not closed. So `overflow` does not suppress anything here: it makes every
 * verdict RUN and report that it did not get to judge. A branch that reports
 * itself is a property that can be tested; a branch believed to be unreachable
 * is not. */
static void shape_verdict(const char *name, int ok, int overflow, const char *fmt, ...) {
  checks++;
  if (ok && !overflow) return;
  failures++;
  if (overflow) {
    fprintf(stderr, "FAIL REGISTER-SHAPE-%s-NOTREACHED : this verdict judged nothing, because the 17.9 "
                    "register carries more U rows than this check records a line for (%d). It is named "
                    "here rather than passed over, because a verdict that does not run appears in no "
                    "count and no sweep can see it.\n", name, REG_ROWS_MAX);
    return;
  }
  fprintf(stderr, "FAIL REGISTER-SHAPE-%s : ", name);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

static void check_register_shape(const char *spec, size_t n, const char *doc2, size_t doc2n) {
  const char *sb, *se, *p, *b, *l;
  const char *label_at[REG_ROWS_MAX];
  unsigned label_line[REG_ROWS_MAX];
  unsigned label_val[REG_ROWS_MAX];
  unsigned rows = 0, first = 0, last = 0, max = 0, prev = 0;
  unsigned dup = 0, dup_of = 0, dup_line = 0, ooo = 0, ooo_of = 0, ooo_after = 0, ooo_line = 0;
  unsigned holes = 0, hole = 0, hole_line = 0;
  unsigned cited = 0, dangling = 0, dangling_of = 0, dangling_line = 0, dangling_doc = 0;
  unsigned outside = 0, outside_line = 0, overflow = 0, lineno = 0;
  /* The anchor's own evidence: how many DISTINCT labels the prose reaches, and
   * up to three of them with the place they were written. Distinct rather than
   * raw, because a label cited nine times is one anchor and nine mentions. */
  unsigned distinct_cited = 0, cited_shown = 0;
  unsigned shown_val[3], shown_line[3];
  unsigned shown_doc[3];
  int found = 0;

  memset(reg_seen, 0, sizeof reg_seen);
  memset(label_at, 0, sizeof label_at);
  memset(label_line, 0, sizeof label_line);
  memset(label_val, 0, sizeof label_val);

  if (!doc2) {
    shape_verdict("DOC2-ABSENT", 0, 0,
                  "%s does not load, so the half of the anchor that crosses the two documents is not "
                  "measured at all. A check that can only see one side of a cross-check must say so "
                  "rather than report the side it has.", DOC2_PATH);
    return;
  }
  found = doc_section(spec, spec + n, "17.9", &sb, &se);
  shape_verdict("NOSECTION", found, 0,
                "the 17.9 heading is not in %s, so the register of coverage gaps is not measured at "
                "all. A check whose subject it cannot find must say so rather than report a green "
                "about nothing.", DOC0_PATH);
  if (!found) return;

  /* R1 R2 R3 -- the rows themselves, in ONE pass. What a label IS is decided
   * here and nowhere else, and the offsets go into label_at so that the
   * citation pass below is TOLD which offsets are labels instead of asking a
   * second time and risking a second answer. */
  for (p = spec; p < sb; p++) if (*p == '\n') lineno++;
  for (p = sb; (p = next_line(p, se, &b, &l)); lineno++) {
    unsigned v = 0;
    const char *start = 0;
    if (!u_row_label(b, l, &v, &start)) continue;
    if (rows >= REG_ROWS_MAX) { overflow = 1; continue; }
    label_at[rows] = start;
    label_line[rows] = lineno + 1;
    label_val[rows] = v;
    if (reg_seen[v]) {
      dup++;
      if (!dup_of) { dup_of = v; dup_line = lineno + 1; }
    }
    reg_seen[v] = 1;
    rows++;
    if (rows == 1) first = v;
    if (rows > 1 && v <= prev) {
      ooo++;
      if (!ooo_of) { ooo_of = v; ooo_after = prev; ooo_line = lineno + 1; }
    }
    prev = v;
    last = v;
    if (v > max) max = v;
  }

  /* R4 -- the anchor, read from the prose of BOTH documents. The exclusion is
   * by OFFSET and not by re-parsing: a token that starts exactly where a label
   * was recorded is that label, not a citation of itself. */
  {
    const char *docs[2];
    size_t docn[2];
    docs[0] = spec; docn[0] = n;
    docs[1] = doc2;  docn[1] = doc2n;
    for (int d = 0; d < 2; d++) {
      for (p = docs[d], lineno = 0; (p = next_line(p, docs[d] + docn[d], &b, &l)); lineno++) {
        const char *t;
        for (t = b; t < l; t++) {
          unsigned v = 0;
          const char *q = u_citation(t, l, b, &v);
          int is_label = 0;
          if (!q) continue;
          for (unsigned i = 0; i < rows && !is_label; i++) is_label = label_at[i] == t;
          t = q - 1;
          if (is_label) continue;
          cited++;
          if (!v) { outside++; if (!outside_line) outside_line = lineno + 1; continue; }
          {
            /* A label cited from BOTH documents is the strongest form of the
             * anchor, so the two passes of this loop are allowed to meet here:
             * the first document claims the label, the second one corroborates
             * it, and no edit to the register can make either sentence stop
             * saying it. */
            static unsigned char claimed[REG_U_MAX + 1];
            int fresh = !claimed[v];
            if (fresh) { claimed[v] = 1; distinct_cited++; }
            if (cited_shown < 3 && (fresh || cited < 6)) {
              shown_val[cited_shown] = v;
              shown_line[cited_shown] = lineno + 1;
              shown_doc[cited_shown] = (unsigned)d;
              cited_shown++;
            }
          }
          if (!reg_seen[v]) {
            dangling++;
            if (!dangling_of) { dangling_of = v; dangling_line = lineno + 1; dangling_doc = d; }
          }
        }
      }
    }
  }

  /* A hole is reported at the line of the row that is PRESENT where the gap
   * opens, which is where the missing row used to be and where the fix goes --
   * a red that sends the reader to the place the gap is, not to the top of
   * the table. */
  if (rows && !overflow) for (unsigned v = 1; v <= max; v++)
    if (!reg_seen[v]) {
      holes++;
      if (!hole) {
        /* The line of the first row that comes AFTER the gap: that is where
         * the missing row used to sit and where the fix goes, so the red
         * sends the reader to the place the gap opens rather than to the top
         * of a table they then have to count through. */
        hole = v;
        for (unsigned i = 0; i < rows; i++)
          if (label_val[i] > hole) { hole_line = label_line[i]; break; }
        if (!hole_line) hole_line = label_line[rows - 1];
      }
    }

  cases++;
  shape_verdict("EMPTY", rows > 0, overflow,
                "the 17.9 register carries no U row at all, so nothing about its shape was measured.");
  shape_verdict("START", rows > 0 && first == 1, overflow,
                "%s:%u : the 17.9 register starts at U%u and not at U1, so it is a SUFFIX of a run and "
                "the row count is not the highest label. This is a convention of the register's naming "
                "and not a measurement: changing it is a deliberate edit here and in the document "
                "together, and not something a red should be answered by guessing at.",
                DOC0_PATH, rows ? label_line[0] : 0, first);
  cases++;
  shape_verdict("HOLE", holes == 0, overflow,
                "%s:%u : the 17.9 register runs to U%u with %u hole(s), the first at U%u. A row that is "
                "gone leaves a gap, and a gap is INVISIBLE TO A COUNT: the row count fell by one and the "
                "row count is not a thing anything asserted. If a row is mid-paste, finish it; if it is "
                "gone, restore it or renumber the rest -- but do not renumber silently, because a "
                "silent renumbering is the defect this whole check exists to catch.",
                DOC0_PATH, hole_line, max, holes, hole);
  cases++;
  shape_verdict("DUPLICATE", dup == 0, overflow,
                "%s:%u : U%u is a DUPLICATE label -- %u row(s) repeat it. A repeated row leaves every "
                "OTHER assertion here satisfied: the set of labels is unchanged and the row count went "
                "UP, so a count cannot see it at all, which is the whole reason this is a shape "
                "assertion and not a count. The line named is the REPEATING row, not the first "
                "occurrence -- delete this one and the register is whole again.",
                DOC0_PATH, dup_line, dup_of, dup);
  cases++;
  shape_verdict("ORDER", ooo == 0, overflow,
                "%s:%u : U%u follows U%u in the 17.9 register, and %u row(s) are out of order. The "
                "highest label is a SET property and the last row is a POSITION property, and a "
                "register that is a correct set in the wrong order satisfies the first and not the "
                "second.",
                DOC0_PATH, ooo_line, ooo_of, ooo_after, ooo);
  cases++;
  shape_verdict("COUNT", rows > 0 && rows == max, overflow,
                "%s : the 17.9 register carries %u U rows and its highest label is U%u. These are two "
                "DIFFERENT quantities read from the same table -- one is how many rows there are, the "
                "other is what the largest one is called -- and a duplicate moves the first without "
                "moving the second, which is what makes their agreement a measurement and their "
                "disagreement a fact.",
                DOC0_PATH, rows, max);
  cases++;
  shape_verdict("TAIL", rows > 0 && last == max, overflow,
                "%s:%u : the 17.9 register ends on U%u and its highest label is U%u, so the run does "
                "not end at the row that carries it. The tail is deliberately STRICT: a check that "
                "tolerates a half-finished paste is a check that goes red for reasons nobody can act "
                "on, and the moment it is disabled for that reason it is a check that LOOKS like "
                "coverage. Finish the row.",
                DOC0_PATH, rows ? label_line[rows - 1] : 0, last, max);
  cases++;
  shape_verdict("CITED-NONE", cited > 0, overflow,
                "no U label is cited in the prose of either document, so the independent anchor R4 has "
                "nothing to check and this run has measured the table's shape against ITSELF. An "
                "anchor that found no anchor is not an anchor, and a green here would be the one "
                "result this check must never produce.");
  cases++;
  shape_verdict("CITATION", dangling == 0, overflow,
                "%s:%u : U%u is cited in the prose and no row of the 17.9 register carries it (%u "
                "dangling citation(s), first U%u). This is the INDEPENDENT arm: the expectation comes "
                "from a sentence rather than from the table, so it cannot be satisfied by re-reading "
                "the table. Either the row is missing or the sentence cites a row that no longer "
                "exists.",
                dangling_doc ? DOC2_PATH : DOC0_PATH, dangling_line, dangling_of, dangling, dangling_of);
  cases++;
  shape_verdict("OUT-OF-SPACE", outside == 0, overflow,
                "%s:%u : %u U-prefixed number(s) in the prose lie outside the label space of 1..%d and "
                "were not classified. A token this check cannot read is reported here rather than "
                "dropped, because a check that drops what it cannot classify is a check that can only "
                "look complete.",
                DOC0_PATH, outside_line, outside, REG_U_MAX);

  /* WHAT IT COMPARED, and the order of it is the point. The EXAMPLES come
   * before the counts, because an instrument that prints only a count will
   * eventually report a number about a set it cannot see, and the number will
   * be entirely composed of things it happened to recognise. Three citations
   * with their file and line are the cheapest proof that the independent arm
   * read prose and not a table -- and this lot got that wrong first, with an
   * awk that counted the register's own labels as citations of themselves. */
  printf("REGISTER-17.9 anchor examples:");
  for (unsigned i = 0; i < cited_shown; i++)
    printf(" %s:%u->U%u", shown_doc[i] ? DOC2_PATH : DOC0_PATH, shown_line[i], shown_val[i]);
  if (!cited_shown) printf(" (none -- see REGISTER-SHAPE-CITED-NONE)");
  printf("\n");
  printf("REGISTER-17.9 rows=%u first=U%u last=U%u max=U%u dup=%u holes=%u order=%u cited=%u "
         "distinct_cited=%u dangling=%u outside=%u\n",
         rows, first, last, max, dup, holes, ooo, cited, distinct_cited, dangling, outside);
}
/* ================================================================== section 12,
 * the GATE-SHAPE census: a negative control on a JUDGEMENT this gate does not
 * make, computed from the build script's own ARRAYS and from nothing else.
 *
 * A census of the 124 gates of the suite classified each one by the SHAPE of
 * its evidence: 52 terminate in bytes, and 72 terminate in a status word and
 * therefore cannot demonstrate an end-to-end property about emitted bytes
 * whatever their check count says. That classification is written down in a
 * comment block of `legacy/tools/coldproof/ngbuild.sh` and in that lot's report, and
 * a classification in a comment is a classification nobody re-checks, which is
 * how a cited count goes stale while its subject is being repaired.
 *
 * WHAT THIS SECTION DOES NOT READ, and the reason is the design and not an
 * omission. It does not read the census COMMENT. An earlier version of this
 * section parsed the comment's anchored words -- `GATES +`, `NOVA_GATES +`,
 * `ROOT_GATES)` -- and compared what it found with what the arrays held, and
 * that was refused, for a reason worth keeping: it couples a gate to a
 * sentence. A person rewording a comment cannot know they have broken a check,
 * the check will not say which words it wanted, and the first response to a
 * red of that kind is to weaken the check. That is last-writer-wins wearing a
 * different hat, and the fix is not a better anchor.
 *
 * So: the ARRAYS are the truth, the arrays are CODE, a change to them breaks
 * loudly, and this section computes from them and prints what it computes. The
 * comment is a CLAIM. This section is a WITNESS. Where they disagree the
 * comment is wrong, and the sentence that says so belongs beside the claim
 * rather than inside the check -- otherwise the block becomes an authority and
 * a reader will treat it as maintained.
 *
 * WHY NOT TO RE-DERIVE THE SPLIT, which is the whole problem and the reason
 * this section is shaped the way it is. `52` is a JUDGEMENT: a reading of 124
 * gates by a rule no amount of C reproduces. An instrument that recomputed it
 * would be a second reading that could disagree with the first and would then
 * need a human to adjudicate -- which is the position the suite is already in.
 * So the split is not computed, not parsed, and not compared with anything.
 * THE WORDS `72` AND `52` ARE NOT READ BY THIS FILE. That is a rule, and a
 * rule that lives only in a reader's head is not a rule.
 *
 * WHAT IT ASSERTS -- claim one of two. The two are different claims and are
 * kept apart in the banner so that neither can be read as the other.
 *
 *   C1 THE POPULATION IS WHAT THE BUILD SCRIPT DECLARES, AND IT IS READABLE.
 *      The three arrays are parsed; every name in them is composed into the
 *      path the build script itself composes and is required to exist, be a
 *      regular file, and load. A gate that vanishes turns this red, and the red
 *      names the gate. Nothing here is a pin on how MANY there are: a hundred
 *      and twenty-five is printed, not failed, because an exact count written
 *      down here is a maintenance trap -- a legitimate new gate would then be a
 *      C edit, and a gate whose red means "somebody was right" is a gate whose
 *      red stops meaning that.
 *
 *   C2 THE D1 REFUTATION STILL HAS THE FACT UNDER IT. The census rejects the
 *      discriminator "which APIs does the gate call" by naming ONE gate, and
 *      naming it is what makes the rejection checkable: `nxo_link_pe` DOES
 *      compare bytes and a vocabulary scan missed the idiom. This asserts the
 *      fact the refutation rests on -- that harness declares a byte-typed
 *      member in a struct tagged `Run`. A refutation whose subject has been
 *      refactored away is a refutation that has rotted while still reading as
 *      one, and nothing else in the tree would notice.
 *
 *   C3 THE D2 REFUTATION STILL HAS THE FACT UNDER IT, IN BOTH DIRECTIONS, and
 *      it is the only arm whose subject is THIS FILE. The census rejects "memcmp
 *      is present" by naming `registry`: a document gate whose memcmps are all
 *      string compares over a markdown file. Both halves are asserted -- this
 *      gate still HAS memcmp sites, and this gate still has NO byte-typed member
 *      in a struct tagged `Run` -- because either half alone is a different
 *      claim. A gate that stopped comparing bytes would no longer refute D2; a
 *      gate that acquired a byte container would no longer be the document gate
 *      D2 mis-counts. Both are real changes and both silently invalidate a
 *      sentence in another file, so both are named here rather than discovered
 *      by the next reader of that sentence.
 *
 *   C4 THE DETECTOR CAN FIRE, on synthetic sources, on every invocation, and
 *      the self-test is INSIDE this section rather than beside it. A fence that
 *      prints ok when its own detector has silently stopped matching is the
 *      failure this project exists to remove, applied to the instrument instead
 *      of to the document -- and a classifier in this project has already
 *      regressed twice silently.
 *
 * WHAT IT CANNOT ASSERT -- claim two of two, and the honest half.
 *
 *   - That the classification is CORRECT. Nothing here reads 52 gates and forms
 *     an opinion about them. A gate the census calls byte-evidenced and that is
 *     not, or the reverse, is invisible here and stays invisible until someone
 *     reads that gate. This is a control on the PROCEDURE, never a verdict on
 *     its output.
 *   - The population digest `6fdb102703f969d9`. It is stated as a digest "over
 *     (gate name + bytes)" and the construction is not written down anywhere.
 *     264 candidate constructions were measured on this tree -- twelve hash
 *     functions over twelve serialisations of one gate entry, in two
 *     accumulation modes -- and none reproduced it. 264 attempts is what the
 *     absence of a written construction costs: the artefact has no interface,
 *     so it is quoted here as an OPEN QUESTION and compared with nothing.
 *   - The two tallies the driver block names: TÉMOIN D'OCTETS (46) and OCTETS
 *     SANS SECOND CÔTÉ (6). They are a per-gate reading that lives in that
 *     lot's report and in no file in this tree, so this section CANNOT compute
 *     them and does not print a substitute under another name. A number
 *     computed here and presented as one of those two would be a third number
 *     wearing their clothes, which is the exact failure the driver's own ruling
 *     about the two names exists to stop.
 *   - That the procedure used is the one the census used. C2 and C3 verify the
 *     two refutations the census NAMED. They say nothing about the other 122
 *     gates, and a future lot that discriminates differently can satisfy both
 *     arms and still be wrong.
 *   - The two signals it DOES print are not the census's classes. `runbyte` is
 *     the accepted discriminator's cheap half; `memcmp` is the REJECTED one,
 *     computed anyway and printed beside the other precisely because the two
 *     DISAGREE. They travel together in one line for that reason, and the
 *     banner says on every run that they are not the census's partition.
 *
 * AND THE PLACEMENT, which is a real question and not a formality. The
 * population is declared in the build script and the build script already has
 * a closure rail over it, so duplicating that here would be a second convention
 * that can drift: this section does NOT check inventory closure against the
 * directory, only that each DECLARED gate is readable. What it adds is what a
 * build script cannot do -- whether a claim ABOUT the gates still has the facts
 * under it. That is this file's subject, it is the only gate that already reads
 * both documents and already knows every gate's name, and it is the only one
 * that can be both the subject and the instrument of the same claim, which C3
 * requires. */

/* The file the census lives in. It is inside the resolver's declared scope
 * (`tools` is a REF_ROOT), so a future lot that cites a line of it gets that
 * line checked by section 8 without this section having to widen anything. */
#define CENSUS_PATH "legacy/tools/coldproof/ngbuild.sh"

/* One declared population and the path convention its names use. A name in
 * GATES is a STEM, a name in NOVA_GATES is a stem too, and a name in
 * ROOT_GATES already carries its extension -- which is not a guess, it is what
 * the build script does with the three arrays, and copying the convention
 * wrongly would produce 124 paths that resolve to nothing. */
#define CENSUS_POP_MAX 1024

typedef struct {
  const char *array;   /* the shell variable, as it is spelled in the script */
  int group;           /* 0 nova tests_ntasm_<g>.c, 1 nova/<g>.c, 2 c/<g> */
  char name[CENSUS_POP_MAX][64];
 unsigned n;
  /* `pre` is what a COMMENT-BLIND reader would have counted here: every
   * whitespace-separated word of the array, the ones inside `#` blocks
   * included. It is what makes the tolerance below sayable rather than silent
   * -- a reader that discards a comment and prints nothing moves staleness from
   * a wrong number, which is arguable, to an absent line, which is not. */
  unsigned pre;
 unsigned overflow;
} CensusArray;

static CensusArray census[3];

/* The harness a name of `group` is written in. Returns 0 when the composed
 * path does not fit, which the caller reports rather than truncating: a
 * truncated path is a path to a different file, and "it resolved" would then
 * be a claim about nothing. */
static int census_path(int group, const char *name, char *out, size_t cap) {
  int r;
  switch (group) {
    case 0: r = snprintf(out, cap, "compiler/c/nova/tests_ntasm_%s.c", name); break;
    case 1: r = snprintf(out, cap, "compiler/c/nova/%s.c", name); break;
    default: r = snprintf(out, cap, "compiler/c/%s", name); break;
  }
  return r > 0 && (size_t)r < cap;
}

/* ONE ARRAY of the build script, read as text.
 *
 * THE TERMINATOR IS A CHARACTER, NOT A LINE, and the first version of this
 * looked for a line whose first non-blank was `)` and therefore read two of
 * the three arrays as absent: `NOVA_GATES=(nova_corpus_convergence)` is a
 * single line, and `ROOT_GATES` ends `tests_x64.c)` on the same line as its
 * last name. The fence reported 95+0+27 where bash says 95+1+28, and the
 * two numbers disagreeing is how the bug was found rather than absorbed --
 * which is the whole argument for reading the population from CODE.
 *
 * `#` starts a comment to end of line, and any character that cannot appear in
 * a bare word is a REFUSAL rather than a skip: an array that grew a quoted
 * string containing a space would otherwise be read as two gates, and two
 * names that resolve to no file is a red here, which is the right direction in
 * which to be wrong. THAT REFUSAL IS KEPT: a reader that tolerates comments
 * must not also tolerate a malformed list, or it has stopped being able to say
 * no to anything.
 *
 * AND THE COMMENT ITSELF WAS A BUG, measured rather than argued. The first
 * version's `#` arm was
 *     if (c == '#') { while (i < n && t[i] != '\n') i++; if (i < n) i++; continue; }
 * which lands `i` on the character AFTER the newline and then lets the `for`
 * increment step over ONE MORE. It eats one character past every comment, and
 * when that character is the array's own closing `)` the array does not end --
 * it bleeds into the rest of the script. Measured on the shape of incident 3,
 * a comment block between the last stem and the closing delimiter:
 *     before   GATES REFUSED, population 128 -> 29, and `fi` -- the shell's own
 *              `fi`, three lines past the array -- was read as a gate and named
 *              by GATE-SHAPE-ABSENT-GATE.
 * The arm below stops AT the newline and leaves the stepping to the loop, and
 * the words the comment swallowed are counted into `pre` rather than discarded,
 * so the fence can print that count when it is non-zero. */
static int census_read_array(const char *t, size_t n, const char *name, CensusArray *a) {
  char open[64];
  size_t i = 0, ol;
  char tok[64];
  size_t k = 0;
  a->array = name;
  a->n = 0;
  a->pre = 0;
  a->overflow = 0;
  snprintf(open, sizeof open, "\n%s=(", name);
  ol = strlen(open);
  for (; i + ol <= n; i++)
    if (memcmp(t + i, open, ol) == 0) { i += ol; break; }
  if (i + ol > n) return 0;
  for (; i < n; i++) {
    char c = t[i];
    if (c == ')') {
      if (k) {
        tok[k] = 0;
        if (a->n < CENSUS_POP_MAX) { memcpy(a->name[a->n], tok, k + 1); a->n++; }
        else a->overflow = 1;
        a->pre++;
      }
      return 1;
    }
    if (c == '#') {
      /* A `#` INSIDE a bare word is a REFUSAL, not a comment: no gate name
       * contains one, and reading the rest of the line as prose would turn
       * `x#y` into `x`, which is a silent edit of the population. */
      if (k) return 0;
      {
        /* one pre-drop count per whitespace-delimited word of the comment,
         * charged at the word's FIRST character. The first version charged at
         * the LAST one and tested the following byte against " \t\r" only, so
         * the final word of every comment line -- the one whose successor is
         * the newline that ends the comment -- was never counted: measured 202
         * against the Python reader's 210 on the same file, a gap of exactly
         * the eight comment lines. Two readers of one file disagreeing by a
         * clean, explainable eight is the shape that finds this class of bug;
         * had they agreed, the count would have been wrong in both. */
        int at_start = 1;
        while (i < n && t[i] != '\n') {
          char d = t[i];
          if (d == ' ' || d == '\t' || d == '\r') at_start = 1;
          else if (at_start) { a->pre++; at_start = 0; }
          i++;
        }
      }
      continue;
    }
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      if (k) {
        tok[k] = 0;
        if (a->n < CENSUS_POP_MAX) { memcpy(a->name[a->n], tok, k + 1); a->n++; }
        else a->overflow = 1;
        a->pre++;
        k = 0;
      }
      continue;
    }
    if (!(ident_char((unsigned char)c) || c == '.' || c == '-')) return 0;
    if (k + 1 >= sizeof tok) return 0;
    tok[k++] = c;
  }
  return 0;
}


/* A byte-typed member. The two spellings are the ones this tree actually
 * uses, and that was measured rather than assumed: `NtBuffer` occurs in
 * pe_oracle.h and in eleven harnesses, and `NtSpan` occurs NOWHERE, so a
 * detector that listed it would be detecting a type this tree has never had.
 * The census's own wording is `uint8_t/NtBuffer` and this is that wording. */
static int census_byte_type(const char *t, size_t n) {
  return has_text(t, n, "uint8_t") || has_text(t, n, "NtBuffer") ||
         has_text(t, n, "unsigned char");
}

/* Whether a source declares a byte-typed member in a struct tagged `Run`.
 *
 * FOUR THINGS IN HERE ARE LOAD-BEARING, and three of them were a bug or a
 * crash before they were a line, which is why they are spelled:
 *
 *   1. The scan is bounded by `i + 14 <= n`, not by `i < n`. A 14-byte memcmp
 *      from the last byte of a source is a global-buffer-overflow, and
 *      AddressSanitizer named it with a line number on the first run of this
 *      section, on a synthetic source short enough to end inside the pattern.
 *      A detector whose only job is to read other people's files has no
 *      business reading past the end of one.
 *   2. The body is matched with a DEPTH COUNTER that starts AFTER the opening
 *      brace. It used to start on it, which counted the opening brace twice
 *      and made every struct in the tree read as unterminated. The self-test
 *      caught that on its very first case, in the first run, with a message
 *      naming the case -- which is the fence working, and worth more than the
 *      bug was.
 *   3. The tag is read AFTER the closing brace, and only the tag -- never
 *      "some struct". A detector answering "does this file declare a byte
 *      member anywhere" is the loose form of the census's own discriminator,
 *      and this very file refutes that form: its byte members live in RefFile,
 *      UnresRef and OutProbe, which is exactly why `registry` is the gate the
 *      census uses to refute D2.
 *   4. Only the tag at THIS closing brace is tested. An earlier version
 *      advanced to the next `typedef struct` and retried, which made the
 *      answer depend on a struct the reader cannot see from the line under
 *      test. The outer loop already visits every struct in the file, so the
 *      retry was a second opinion about one question and a chance to disagree
 *      with itself. */
static int census_run_byte_member(const char *t, size_t n) {
  for (size_t i = 0; i + 14 <= n; i++) {
    size_t open, close, p;
    int depth = 1;
    if (memcmp(t + i, "typedef struct", 14) != 0) continue;
    for (open = i; open < n && t[open] != '{'; open++) ;
    if (open >= n) return 0;
    for (close = open + 1; close < n; close++) {
      if (t[close] == '{') depth++;
      else if (t[close] == '}') { depth--; if (!depth) break; }
    }
    if (close >= n) return 0;
    if (!census_byte_type(t + open + 1, close - open - 1)) { i = close; continue; }
    for (p = close + 1; p < n; p++) {
      while (p < n && (t[p] == ' ' || t[p] == '\t' || t[p] == '\n')) p++;
      if (p < n && t[p] == '*') continue;
      break;
    }
    i = close;
    if (p + 3 <= n && memcmp(t + p, "Run", 3) == 0 &&
        !(p + 3 < n && ident_char((unsigned char)t[p + 3]))) return 1;
  }
  return 0;
}

/* The number of `memcmp(` sites in a source. Read over the RAW text, and that
 * is a choice with a cost: a `memcmp` named in a COMMENT of this file counts,
 * and the census's own figure of 23 for `registry` is a raw-text figure, so
 * stripping comments first would make this gate's own subject disagree with
 * the sentence that refutes D2 on its account. The cost is stated rather than
 * paid silently: the memcmp arm is a NEGATIVE control on a rejected
 * discriminator and never a classification, and a comment that raises this
 * gate's own count is a change to C3, which is where it should be noticed. */
static unsigned census_memcmp(const char *t, size_t n) {
  unsigned c = 0;
  for (size_t i = 0; i + 7 <= n; i++)
    if (memcmp(t + i, "memcmp(", 7) == 0 &&
        !(i && (ident_char((unsigned char)t[i - 1]) || t[i - 1] == '_'))) c++;
  return c;
}
/* THE CLASS OF ONE GATE, as this file computes it, and the two names it is
 * not allowed to be given. `runbyte` is the census's ACCEPTED discriminator's
 * cheap half -- a byte-typed member in a struct tagged `Run`. `memcmp` is the
 * census's REJECTED one, computed here anyway, and the reason to compute it is
 * that the two are printed side by side: they disagree, and the disagreement
 * is the finding. Neither is the census's class, and the banner says so on
 * every run, because a short class name in a log is read as a verdict by
 * somebody, and one that is not a verdict is how a number becomes a fact by
 * repetition. */
static const char *census_class(int runbyte, int memcmp) {
  if (runbyte && memcmp) return "runbyte+memcmp";
  if (runbyte)         return "runbyte";
  if (memcmp)          return "memcmp";
  return "neither";
}

/* THE SELF-TEST, and it is inside the fence rather than beside it, because a
 * fence that prints ok when its own detector has silently stopped matching is
 * the exact failure this project exists to remove, applied to the instrument
 * instead of to the document. Every case below is a source that MOVES the
 * answer, so a detector that has regressed to a constant turns one of them red
 * instead of quietly agreeing with the tree.
 *
 * Cases 2 and 6 carry the most weight, and they are here for a measured reason.
 * A substring match that stopped discriminating, and a filter that dropped 24
 * real gates, are two silent regressions this project has already had; case 2
 * is the first shape and case 6 is the second. A detector one substitution away
 * from answering "does this file mention a byte" passes every other case. */
static void check_shape_detector(void) {
  static const struct { const char *what; const char *src;
                        int runbyte; unsigned memcmp; } shapes[] = {
    {"a Run struct carrying a byte member is the shape the census describes",
     "typedef struct {\n  unsigned char text[64];\n} Run;\n", 1, 0},
    {"the SAME member under another tag is not that shape, and a detector that "
     "cannot tell the two apart is making the mistake D1 made",
     "typedef struct {\n  unsigned char text[64];\n} Buffer;\n", 0, 0},
    {"a Run struct with no byte member carries no byte evidence",
     "typedef struct {\n  int n;\n} Run;\n", 0, 0},
    {"memcmp with no byte container is exactly the shape that refutes D2",
     "int f(void){ return memcmp(a, b, 4); }\n", 0, 1},
    {"a byte member behind a nested struct is still a member, so the depth "
     "counter is load-bearing and not tidy",
     "typedef struct {\n  struct { int x; } inner;\n  unsigned char b[4];\n} Run;\n", 1, 0},
    {"a byte member in a NON-Run struct after a Run struct must not be answered "
     "from the first byte struct found anywhere in the file",
     "typedef struct { int n; } Run;\ntypedef struct { unsigned char b[4]; } Other;\n", 0, 0},
    {"two memcmps are two sites and neither is dropped",
     "memcmp(a,b,1); memcmp(c,d,2);\n", 0, 2},
    {"a name that merely ENDS in memcmp is not a call",
     "int my_memcmp(const char*,const char*,unsigned long);\n", 0, 0},
  };
  unsigned n = (unsigned)(sizeof shapes / sizeof *shapes), shown = 0, proven = 0;
  for (unsigned i = 0; i < n; i++) {
    size_t l = strlen(shapes[i].src);
    int rb = census_run_byte_member(shapes[i].src, l);
    unsigned mc = census_memcmp(shapes[i].src, l);
    cases++;
    checks++;
    if (rb != shapes[i].runbyte || mc != shapes[i].memcmp) {
      failures++;
      fprintf(stderr, "FAIL SHAPE-DETECTOR-CASE : %s -- the detector answered runbyte=%d memcmp=%u "
                      "where this source is built to give runbyte=%d memcmp=%u. The classifier that "
                      "just ran over the population has regressed, so every class and every digest "
                      "printed below is about a detector that no longer detects.\n",
              shapes[i].what, rb, mc, shapes[i].runbyte, shapes[i].memcmp);
      continue;
    }
    good();
    proven++;
    if (shown < 3) { printf("SHAPE-PROVEN %s\n", shapes[i].what); shown++; }
  }
  printf("SHAPE-PROVEN %u/%u states answered, %u shown\n", proven, n, shown);
}

/* THE READER'S OWN SELF-TEST, and it is here for the same reason the shape
 * detector's is: census_read_array now TOLERATES a comment, and the price of
 * tolerance is that it can no longer be trusted by inspection. Three things
 * have to hold at once and no two of them imply the third:
 *
 *   1 a comment inside the array changes nothing about the names
 *   2 a comment AFTER the last stem and before the closing `)` also changes
 *     nothing -- this is the shape of incident 3, and it is the case the
 *     off-by-one in the `#` arm broke: the reader ate one character past the
 *     comment, the closing paren was that character, and GATES bled into the
 *     rest of the script and read the shell's own `fi` as a gate
 *   3 a MALFORMED array is still REFUSED. Tolerance bought for comments must
 *     not extend to a quoted string, or the reader has stopped being able to
 *     say no -- and "it says the same thing as before" is not evidence for
 *     that, because a reader that refuses everything also says it.
 *
 * And the CLEAN case is a case too: a reader that dropped nothing must report
 * `pre == n`, because that is the precondition on the conditional line the
 * fence prints, and a fence whose silence cannot be distinguished from a
 * silence caused by a dropped 111-word note is not reporting. */
static void check_census_reader(void) {
  static const char *const clean_  = "\nGATES=(\n  abi parser x64_lea\n)\n";
  static const char *const inside_ = "\nGATES=(\n  abi\n"
    "  # a positional reader cannot tell a name from a sentence.\n  parser\n)\n";
  static const char *const after_  = "\nGATES=(\n  abi parser\n"
    "  # a positional reader cannot tell a name from a sentence.\n)\n";
  static const char *const paren_  = "\nGATES=(\n  abi\n"
    "  # prose ends a sentence with a bracket (see the note above).\n  parser\n)\n";
  static const char *const quoted_ = "\nGATES=(\n  abi \"two words\"\n)\n";
  static const char *const inline_hash = "\nGATES=(\n  abi x#y\n)\n";
  CensusArray a;
  const unsigned n_prose = 11; /* the two `#` and the nine words of the note */

#define READER_CASE(what, src, want_names, want_pre, want_ok) do {               \
    size_t l = strlen(src);                                                      \
    int ok = census_read_array(src, l, "GATES", &a);                             \
    cases++; checks++;                                                           \
    if (ok != (want_ok) || (want_ok && (a.n != (want_names) || a.pre != (want_pre)))) { \
      failures++;                                                                \
      fprintf(stderr, "FAIL GATE-READER-CASE : %s -- the reader answered parsed=%d n=%u pre=%u " \
                      "where this source is built to give parsed=%d n=%u pre=%u. A reader that " \
                      "cannot tell a comment from a name, or that tolerates a quoted string, is " \
                      "not reading the population it reports.\n",                 \
              what, ok, a.n, a.pre, (want_ok), (unsigned)(want_names), (unsigned)(want_pre)); \
      continue;                                                                   \
    }                                                                             \
    good(); proven++;                                                             \
  } while (0)

  unsigned proven = 0;
  READER_CASE("a clean array parses, and drops NOTHING at all", clean_, 3, 3, 1);
  READER_CASE("a comment INSIDE the array is dropped and COUNTED", inside_, 2, 2 + n_prose, 1);
  READER_CASE("a comment AFTER the last stem and before the `)` is dropped", after_, 2, 2 + n_prose, 1);
  READER_CASE("a comment carrying a `)` does not END the array", paren_, 2, 2 + 12, 1);
  READER_CASE("a MALFORMED array is REFUSED, not tolerated away", quoted_, 0, 0, 0);
  READER_CASE("a `#` inside a bare word is REFUSED, not read as a comment", inline_hash, 0, 0, 0);
#undef READER_CASE
  printf("READER-PROVEN %u/6 states answered\n", proven);
}

/* THE FENCE. Four arms, and the two claims are separated in the banner because
 * a reader who cannot tell which of two numbers is a claim and which is a
 * measurement will eventually quote the second as the first. */
static void check_gate_shape(void) {
  static const char *const arrays[3] = { "GATES", "NOVA_GATES", "ROOT_GATES" };
  static const int groups[3] = { 0, 1, 2 };
  size_t n = 0;
  char *t = loadf(CENSUS_PATH, &n);
  unsigned total = 0, read_ok = 0, runbyte_n = 0, memcmp_n = 0, agree = 0, disagree = 0;
  unsigned long long cls = 1469598103934665603ULL;

  /* The self-test runs FIRST and on every invocation, for the reason its own
   * comment gives: on a correct tree every arm below is silent, so a run that
   * only ever exercised the silent state would be an instrument that has only
   * ever been exercised in one state. */
  check_shape_detector();
  check_census_reader();

  if (!t) {
    checks++; failures++;
    fprintf(stderr, "FAIL GATE-SHAPE-ABSENT : %s does not load from the repository root, so the "
                    "population this gate classifies is not read at all. A fence whose subject it "
                    "cannot open says so rather than reporting the gates it did not see.\n", CENSUS_PATH);
    return;
  }

  for (unsigned k = 0; k < 3; k++) {
    census[k].group = groups[k];
    if (census_read_array(t, n, arrays[k], &census[k])) {
      total += census[k].n;
      /* AN ARRAY THAT PARSES AND IS EMPTY IS NOT A PASS, and this arm exists
       * because the shape of that failure was demonstrated on this tree rather
       * than imagined: a build script reduced to three empty array literals is
       * still shaped like a build script, its closure rails still run, and
       * every one of them passes over a population of zero. A fence that reads
       * `GATES=(` and finds it is a fence that can be satisfied by a file with
       * nothing in it, and a check that a deletion turns GREEN is worse than no
       * check at all.
       *
       * So the two failures are different and both are reported: `absent` is a
       * variable the file does not declare, and `empty` is a variable it
       * declares and fills with nothing. The first is a rename; the second is
       * a deletion wearing the first's syntax. */
      if (census[k].n == 0) {
        checks++; failures++;
        fprintf(stderr, "FAIL GATE-SHAPE-EMPTY-ARRAY : %s declares %s=( ) and it holds no names, so "
                        "the population this gate just counted is not the population any of this "
                        "suite's rails would build. An empty array passes every closure rail in that "
                        "file vacuously; this arm is here so that it cannot also pass this one.\n",
                CENSUS_PATH, arrays[k]);
      } else good();
    } else {
      checks++; failures++;
      fprintf(stderr, "FAIL GATE-SHAPE-ARRAY : %s declares no array named %s, so the population this "
                      "gate reads is not the one the census classified. This names the name it "
                      "looked for, because an array that silently read as empty is a fence over "
                      "nothing.\n", CENSUS_PATH, arrays[k]);
    }
  }
  /* WHAT THE COMMENT-DROPPING COST, printed CONDITIONALLY and computed from the
   * PRE-drop count -- the number a comment-blind reader would have printed here,
   * not the number the tolerant one printed after discarding. Both halves are
   * load-bearing. The count is a measurement rather than the reader's opinion
   * of itself; and the condition is the rule that an instrument with nothing to
   * say must print nothing AND say so. An unconditional `dropped=0` on every
   * run forever is the noise this project has already paid for once, and a
   * fence that says nothing when it dropped nothing and the same amount when it
   * dropped 111 words is not reporting anything at all. */
  for (unsigned k = 0; k < 3; k++)
    if (census[k].pre > census[k].n)
      printf("GATE_SHAPE-COMMENT_DROPPED array=%s pre_drop=%u survived=%u\n",
             arrays[k], census[k].pre, census[k].n);
  cases++;
  CHECK(total > 0, "the build script's three arrays hold a population at all");
  printf("GATE_SHAPE-POPULATION measured=%u arrays=%u+%u+%u stated_by_the_census_block=124 "
         "not_compared=the_count_is_printed_not_pinned\n",
         total, census[0].n, census[1].n, census[2].n);

  /* THE PER-GATE PASS, and it is the only place any of the population is read.
   * Each source is loaded once, measured, classified and released: the
   * reference resolver above has already walked this tree, and a check that
   * re-read it file by file would double the most expensive thing this gate
   * does. */
  for (unsigned k = 0; k < 3; k++) {
    if (census[k].overflow) {
      checks++; failures++;
      fprintf(stderr, "FAIL GATE-SHAPE-OVERFLOW : array %s holds more names than the %d this harness "
                      "can hold, so the population above is a floor and not a count.\n",
              census[k].array, CENSUS_POP_MAX);
      continue;
    }
    for (unsigned i = 0; i < census[k].n; i++) {
      char path[512];
      size_t gn = 0;
      char *src;
      int rb;
      unsigned mc;
      const char *cl;
      struct stat st;
      if (!census_path(census[k].group, census[k].name[i], path, sizeof path)) {
        checks++; failures++;
        fprintf(stderr, "FAIL GATE-SHAPE-PATH : the harness path of gate %s does not fit 512 bytes, "
                        "so the gate was not read. A truncated path is a path to a different file.\n",
                census[k].name[i]);
        continue;
      }
      if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        checks++; failures++;
        fprintf(stderr, "FAIL GATE-SHAPE-ABSENT-GATE : %s declares gate %s and %s does not exist, so "
                        "the population this gate just counted is not %u runnable harnesses.\n",
                CENSUS_PATH, census[k].name[i], path, total);
        continue;
      }
      src = loadf(path, &gn);
      if (!src) {
        checks++; failures++;
        fprintf(stderr, "FAIL GATE-SHAPE-UNREADABLE : the harness of gate %s exists at %s and does not "
                        "load.\n", census[k].name[i], path);
        continue;
      }
      read_ok++;
      rb = census_run_byte_member(src, gn);
      mc = census_memcmp(src, gn);
      if (rb) runbyte_n++;
      if (mc) memcmp_n++;
      if ((rb != 0) == (mc != 0)) agree++; else disagree++;
      cl = census_class(rb, mc != 0);
      printf("GATE_CLASS %s %s\n", census[k].name[i], cl);
      /* The digest is over CLASSES and never over bytes, and that is a decision
       * with a reason rather than a preference: a byte digest moves on every
       * comment, so it answers "has anybody edited" and not "has the
       * classification changed", and those are different questions. */
      for (const char *q = census[k].name[i]; *q; q++) { cls ^= (unsigned char)*q; cls *= 1099511628211ULL; }
      for (const char *q = cl; *q; q++) { cls ^= (unsigned char)*q; cls *= 1099511628211ULL; }
      free(src);
    }
  }

  /* C2 and C3, the two REFUTATIONS, each a fact about ONE gate that the census
   * named. They are that lot's most reusable result, and a reusable result that
   * cannot be re-checked is a story. */
  { char path[512], *src; size_t gn = 0; int rb = 0; unsigned mc = 0, have = 0;
    if (census_path(0, "nxo_link_pe", path, sizeof path) && (src = loadf(path, &gn)) != 0) {
      rb = census_run_byte_member(src, gn); mc = census_memcmp(src, gn); have = 1; free(src);
    }
    cases++;
    if (!have)
      failf("the harness of gate nxo_link_pe does not load, so the census's refutation of D1 -- that "
            "this gate compares Nova PE bytes against a C-oracle PE and a vocabulary scan missed the "
            "idiom -- cannot be checked against the tree at all");
    else if (!rb)
      failf("gate nxo_link_pe no longer declares a byte-typed member in a struct tagged Run (memcmp "
            "sites=%u). It was the census's refutation of the D1 discriminator; a refutation whose "
            "subject has been refactored away is one that has rotted while still reading as one", mc);
    else good();
  }
  { /* This file, measured on itself: the only gate in the suite that can be
     * both the subject and the instrument of the same claim, and that is the
     * whole reason C3 lives here and nowhere else. */
    size_t gn = 0;
    char *src = loadf("tests/c/nova/tests_ntasm_registry.c", &gn);
    int rb = 0;
    unsigned mc = 0;
    if (src) { rb = census_run_byte_member(src, gn); mc = census_memcmp(src, gn); free(src); }
    cases++;
    if (!src)
      failf("this gate's own source does not load, so the census's refutation of D2 -- that registry "
            "is a document gate whose memcmps are string compares over a markdown file -- cannot be "
            "checked");
    else if (mc == 0)
      failf("this gate no longer contains a single memcmp site, so it is no longer the document gate "
            "with memcmps that refutes the D2 discriminator, and the sentence in the census that "
            "refutes D2 is about a gate that does not exist");
    else if (rb)
      failf("this gate now declares a byte-typed member in a struct tagged Run (memcmp sites=%u), so "
            "it is no longer a document gate and the census's refutation of D2 names the wrong kind "
            "of gate. That may well be a real change; it is not a silent one", mc);
    else good();
    printf("GATE_SHAPE-SELF memcmp=%u runbyte=%d\n", mc, rb);
  }

  cases++;
  CHECK(read_ok == total, "every gate the build script declares was read by this run");

  printf("GATE_CLASS_DIGEST %016llx over=classes_not_bytes gates=%u read=%u runbyte=%u memcmp=%u "
         "signals_agree=%u signals_disagree=%u\n",
         cls, total, read_ok, runbyte_n, memcmp_n, agree, disagree);
  printf("GATE_SHAPE-LIMITS asserted=the_population_the_build_script_declares_is_all_readable_"
         "harnesses;the_D1_refutation_nxo_link_pe_still_declares_a_byte_member_in_a_struct_tagged_"
         "Run;the_D2_refutation_registry_still_has_memcmp_sites_and_still_has_no_byte_member_in_a_"
         "struct_tagged_Run;this_detector_answers_every_synthetic_case_it_is_given. "
         "not_asserted=that_the_classification_is_correct;the_population_digest_6fdb102703f969d9_"
         "whose_construction_is_written_down_nowhere_and_which_264_measured_constructions_failed_to_"
         "reproduce_so_it_is_quoted_and_compared_with_nothing;TE_MOIN_D_OCTETS_46_and_OCTETS_SANS_"
         "SECOND_COTE_6_which_are_a_per_gate_reading_living_in_no_file_in_this_tree_and_are_NOT_"
         "reproduced_here_under_any_other_name. "
         "runbyte_reaches_%u_of_%u_gates_and_that_is_its_measured_coverage_not_its_accuracy:_a_gate_"
         "declaring_no_Run_struct_at_all_is_runbyte=0_here_which_is_the_same_answer_as_a_gate_with_a_"
         "Run_struct_and_no_byte_member_and_this_check_cannot_tell_those_two_apart. A detector that "
         "is silent on most of the population is not a classifier and is not offered as one. "
         "runbyte_and_memcmp_are_two_signals_recomputed_here_and_they_are_not_the_census_classes;"
         "they_disagree_on_this_tree_by_design_and_are_printed_together_so_that_the_two_numbers_a_"
         "future_lot_is_likely_to_re_derive_travel_as_a_pair;and_a_digest_over_them_answers_did_the_"
         "classification_change_never_is_the_classification_right_\n",
         runbyte_n, total);
  free(t);
}


int main(void) {
  size_t n = 0;
  char *spec = loadf(DOC0_PATH, &n);
  /* THE SECOND DOCUMENT, loaded here and only here, into the globals the
   * citation resolver and the structural section read. It is loaded BEFORE the
   * first judgement and not freed until the end, for the reason the re-judge
   * path in section 8 needs: a pointer that main() owns and the checks borrow
   * cannot dangle across a second judgement, and a document re-read from disk
   * between the two would be two texts under one comparison. A load failure is
   * NOT fatal here -- the check that depends on it says so and fails with a
   * sentence naming the file, which is more use than a banner that never
   * printed. */
  char *doc2 = loadf(DOC2_PATH, &doc2n);
  doc2_text = doc2;
  ref_doc[0] = DOC0_PATH;
  ref_doc[1] = DOC2_PATH;
  /* The SIZE is set here and the TEXT is bound inside check_references, which
   * is the function that knows which copy of the spec this judgement is about.
   * Setting both here is what the first version did, and the first version
   * handed a 25-byte string literal to a scanner with a 2681-byte length. */
  ref_docn[1] = doc2 ? doc2n : 0;
  /* WHO THIS RUN IS, taken before anything else runs, because the two numbers
   * are what make a later comparison of two runs falsifiable rather than
   * merely performed: a state file that cannot say which process wrote it
   * cannot refuse to be compared with itself. */
  drift_run_start = (long)time(NULL);
  drift_pid = (unsigned)getpid();
  /* And the PREVIOUS run's state, read HERE, before this run has judged
   * anything and long before it writes. Reading it at the end instead would
   * read the file this run had just written on a machine where a previous run
   * of the same tree happened to be concurrent, and the check would be
   * comparing a run to itself while reporting that it compared two. */
  drift_read_previous();
  if (!spec) {
    checks++; failures++;
    fprintf(stderr, "FAIL spec/ntasm/ntasm.md does not load from the repository root\n");
    reg_banner();
    return 1;
  }

  /* ---- 1. the section, not the file: 17.6 runs until the next ### heading.
   * Through doc_section, the same walk the 17.9 register reader below uses. */
  const char *se = spec + n, *b, *l, *p = spec;
  const char *sec = 0, *sec_end = se;
  doc_section(spec, se, "17.6", &sec, &sec_end);
  checks++;
  if (!sec) {
    failures++;
    fprintf(stderr, "FAIL the 17.6 heading is not in spec/ntasm.md\n");
    reg_banner();
    return 1;
  }

  /* ---- 2. the family table: first cell of every row is the code, or a range. */
  int nums[NUM_MAX];
  unsigned published_n = 0, rows = 0;
  p = sec;
  while ((p = next_line(p, sec_end, &b, &l))) {
    const char *k = skip_ws(b, l);
    if (k >= l || *k != '|') continue;
    rows++;
    /* Cell 0 is the text between the leading pipe and the next one, so the walk
     * starts on a pipe and each step consumes the delimiter it found. */
    int cell = 0;
    const char *c = k;
    while (c + 1 < l) {
      const char *pipe = memchr(c + 1, '|', (size_t)(l - c - 1));
      if (!pipe) break;
      unsigned m = cell_numbers(c + 1, pipe, nums, NUM_MAX);
      if (cell == 0)
        for (unsigned i = 0; i < m; i++)
          if (nums[i] >= BAND_LO && nums[i] <= BAND_HI) {
            published[nums[i]] = 1;
            published_n++;
          }
      c = pipe;
      cell++;
    }
  }
  cases++;
  CHECK(ranges_n > 0 && ranges_n < NUM_MAX, "the 17.6 table states its bands as dash-joined ranges");
  cases++;
  CHECK(rows > 0, "the 17.6 section carries at least one table row");
  /* A floor on both sides, so an empty parse cannot agree with an empty scan
   * and call the registry exhaustive. */
  CHECK(published_n >= 40, "the 17.6 family table names at least 40 published codes");

  /* ---- 3. the unattributed enumeration, read from the same paragraph. */
  /* The anchor is the head of the enumeration, "`301`, `302`, `303`", which is
   * the only place the registry lists those three side by side: 1410-1411
   * splits them across the sentence that says the oracle owns 300-303, and
   * 1556 reads "`301`, `302` et `303`" to say the same thing again. The block
   * ends at the first following line with no backquoted span left in it. */
  int unattributed[NUM_MAX];
  unsigned unattributed_n = 0;
  p = sec;
  while ((p = next_line(p, sec_end, &b, &l))) {
    if (!has_text(b, (size_t)(l - b), "`301`, `302`, `303`")) continue;
    for (;;) {
      unsigned m = cell_numbers(b, l, nums, NUM_MAX);
      for (unsigned i = 0; i < m && unattributed_n < NUM_MAX; i++)
        unattributed[unattributed_n++] = nums[i];
      p = next_line(p, sec_end, &b, &l);
      if (!p) break;
      if (!memchr(b, '`', (size_t)(l - b))) break;
    }
    break;
  }
  cases++;
  CHECK(unattributed_n > 0, "the 17.6 unattributed enumeration is found");
  for (unsigned i = 0; i < unattributed_n; i++) {
    int v = unattributed[i];
    cases++;
    if (v < 0 || v >= CODE_MAX) {
      /* Dropping it quietly would turn an unparsable enumeration into a green
       * gate, which is the shape of the defect this file exists to close. */
      checks++; failures++;
      fprintf(stderr, "FAIL the unattributed enumeration names %d, outside the code space of this gate\n", v);
      continue;
    }
    if (published[v]) { bad("declared unattributed by the registry yet published in its table", v); }
    else good();
    cases++;
    if (emitted[v]) { bad("declared unattributed by the registry yet emitted by a module", v); }
    else good();
  }
  /* The list the audit fixed by name, so the check does not rest on the parse
   * of a sentence that a later lot is free to reword. */
  /* 366 and 367 left this list on 30 September 2026: both are now emitted, by
   * abi.obligations and abi.fact_validity, and each has a row in the 17.6
   * family table.  They stay QUERIES -- nothing in validate.nova calls either --
   * and a query with an owner is not an unattributed slot. */
  static const int named[] = {301, 302, 303, 304, 307, 308, 309, 312,
                              368, 369, 382, 383, 384, 385};
  for (unsigned i = 0; i < sizeof named / sizeof *named; i++) {
    cases++;
    if (published[named[i]]) bad("named unattributed but published in the 17.6 table", named[i]);
    else good();
  }

  /* ---- 4. the emissions, from the modules themselves, read from the tree. */
  DIR *d = opendir("compiler/nova");
  unsigned modules = 0, unloadable = 0;
  if (!d) {
    checks++; failures++;
    fprintf(stderr, "FAIL compiler/nova does not open from the repository root\n");
  } else {
    struct dirent *de;
    while ((de = readdir(d)) != 0) {
      const char *nm = de->d_name;
      size_t l = strlen(nm);
      if (l < 6 || memcmp(nm + l - 5, ".nova", 5) != 0) continue;
      char path[512];
      snprintf(path, sizeof path, "compiler/nova/%s", nm);
      /* d_type reads DT_UNKNOWN on the drvfs mount, and tests/ must not be
       * mistaken for a module, so ask the filesystem what this name is. */
      struct stat st;
      if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
      size_t mn = 0;
      char *text = loadf(path, &mn);
      if (!text) { unloadable++; fprintf(stderr, "FAIL module %s does not load\n", nm); continue; }
      scan_emissions(text, mn);
      free(text);
      modules++;
    }
    closedir(d);
  }
  cases++;
  CHECK(modules >= MODULE_FLOOR, "the tree offers at least 44 Nova modules to scan");
  checks++;
  if (unloadable) { failures++; fprintf(stderr, "FAIL %u modules of the tree do not load\n", unloadable); }

  /* ---- 5. equality in both directions, one check per code named by either. */
  unsigned emitted_n = 0, missing = 0, extra = 0, agreed = 0;
  for (int c = BAND_LO; c <= BAND_HI; c++) if (emitted[c]) emitted_n++;
  for (int c = BAND_LO; c <= BAND_HI; c++) {
    if (!published[c] && !emitted[c]) continue;
    cases++;
    checks++;
    if (published[c] == emitted[c]) { agreed++; continue; }
    failures++;
    if (emitted[c]) {
      extra++;
      fprintf(stderr, "FAIL code %d is emitted by a module and has no row in the 17.6 family table\n", c);
    } else {
      missing++;
      fprintf(stderr, "FAIL code %d has a row in the 17.6 family table and no module emits it\n", c);
    }
  }
  cases++;
  CHECK(agreed > 0, "at least one code is both published and emitted");

  /* ---- 6. the two bounds, as the schema table states them and as they hold.
   *
   * The structural bound is compared to STRUCT_HI, not to a literal. It was a
   * literal -- 844 -- while the code's own ceiling has been STRUCT_HI 899 since
   * the beginning, and nothing compared the two numbers. ir_image.nova then
   * allocated 850..860 in the gap, for a reason it wrote down and which was
   * correct against the table, and the two reds that followed named the MODULE
   * rather than the declaration. A bound that is not compared to its ceiling in
   * the code is a nominal bound, not a contract, and the check that closes the
   * gap is the one below that says so. */
  int sem_lo = 0, sem_hi = 0, st_lo = 0, st_hi = 0, st_band_hi = 0;
  for (unsigned i = 0; i < ranges_n; i++) {
    if (ranges_lo[i] == BAND_LO && ranges_hi[i] == 386) { sem_lo = 1; sem_hi = 1; }
    if (ranges_lo[i] == STRUCT_LO && ranges_hi[i] == STRUCT_HI) { st_lo = 1; st_hi = 1; }
    if (ranges_lo[i] == STRUCT_LO) st_band_hi = ranges_hi[i];
  }
  cases++;
  CHECK(sem_lo && sem_hi, "the schema table states the semantic band 300-386");
  cases++;
  CHECK(st_lo && st_hi, "the schema table states the structural band 800-899");
  cases++;
  CHECK(st_band_hi == STRUCT_HI,
        "the schema table's structural bound IS the code's STRUCT_HI. Two numbers "
        "naming the same limit, compared against nothing, is how ir_image.nova came "
        "to be named by two red checks for using a range the table did not declare");
  if (!sem_lo || !st_lo)
    fprintf(stderr, "SCHEMA-RANGE %u ranges read from the 17.6 table:", ranges_n);
  for (unsigned i = 0; i < ranges_n; i++)
    if ((!sem_lo || !st_lo) && (ranges_hi[i] - ranges_lo[i]) > 1)
      fprintf(stderr, " %d-%d", ranges_lo[i], ranges_hi[i]);
  if (!sem_lo || !st_lo) fprintf(stderr, "\n");
  int max_pub = 0, max_emit = 0, max_struct = 0;
  for (int c = BAND_LO; c <= BAND_HI; c++) {
    if (published[c]) max_pub = c;
    if (emitted[c]) max_emit = c;
  }
  for (int c = STRUCT_LO; c <= STRUCT_HI; c++) if (structural[c]) max_struct = c;
  cases++;
  CHECK(max_pub == 386, "386 is the highest published semantic code");
  cases++;
  CHECK(max_emit == 386, "386 is the highest emitted semantic code");
  cases++;
  CHECK(max_struct <= STRUCT_HI,
        "every emitted structural code is at or below the declared ceiling -- this "
        "asks the question, where the old check asked what the number happened to be");
  int above = 0;
  for (int c = 387; c <= BAND_HI; c++) if (emitted[c] || published[c]) above = 1;
  cases++;
  CHECK(!above, "no 3xx code at or above 387 is emitted or published");
  /* This check asked "is any structural code at or above 845" -- a literal
   * standing in for the ceiling, which is how the table and STRUCT_HI came to
   * disagree without anything noticing. The question worth asking is whether
   * anything is emitted ABOVE the declared band, and that has to be read from
   * the band the table states, not from a number typed here. STRUCT_HI is
   * checked against that band one screen above, so this arm now only has to
   * catch an emission past it. */
  int above8 = 0;
  for (int c = st_band_hi + 1; c <= STRUCT_HI + 1; c++)
    if (c <= STRUCT_HI && structural[c]) above8 = 1;
  cases++;
  CHECK(!above8, "no structural code is emitted above the band the schema table declares");

  /* ================================================================== 7.
   * The coverage counters the document asserts, each one measured.
   *
   * THERE IS NO ANCHOR LEFT, and this comment used to be the place that said
   * so. It said: the numbers in COVER are a TIME ANCHOR, five (checks, cases)
   * pairs a human read off five banners, not an oracle and not a derivation,
   * and a gate that grows still turned this gate red until a human re-anchored
   * a constant in this file. That was true of the file this wave inherited and
   * it is the residual the audit numbered 9. It is no longer true, and the
   * repair is the one the audit asked for: the expectation is not written down
   * anywhere in C. It is the DOCUMENT. The measurement is the twin, run above
   * in this process, from this compilation. The verdict is their difference.
   *
   * What that changes for the person who breaks a gate on purpose. Before: the
   * suite went red with "re-anchor it", and the cheapest repair was to edit a
   * number in this file, which is how a coverage claim stops being a claim
   * about the code. Now: the suite goes red with the measured pair and the
   * stated pair side by side, and the only repair is to correct the sentence
   * in spec/ntasm/ntasm.md, which is the only place the repair belongs.
   *
   * Five directions, all measured, none pinned:
   *
   *   1. every counter the document states is compared with what the gate
   *      really produces, so a gate that gains a check, or a document that
   *      lies about a gate, is red here -- and the two are now the same kind
   *      of object, one written by running code and one written by prose;
   *   2. the counters the scan READ are put in bijection with the sites that
   *      have the shape of a counter, so a counter reworded into a shape this
   *      parser cannot finish reading is a red rather than a silent loss. The
   *      rule that recognises such a site, and the one prose mention it has to
   *      spare, are spelled at collect_coverage;
   *   3. every counter the document states must name a gate that exists in the
   *      tree, so a counter cannot be attributed to nothing;
   *   4. every counter the document states must name a gate this file is
   *      responsible for, so a new column of numbers cannot appear unchecked;
   *   5. every one of those gates must still print, in its own harness source
 *      in the tree, the banner the comparison is about, and must still have a
   *      twin here. A COVER row whose twin went missing is a red: there is no
   *      longer a path that quietly compares a number with itself.
   *
   * And the floor that is deliberately NOT a pin: each of these gates must
   * still be described by at least one counter, so the section cannot be
   * emptied without this noticing. What it no longer does is insist on HOW
   * MANY counters each gate has -- a sentence may be reworded, a counter may
   * be added, and neither needs a human to edit this file. The cost of that
   * choice is that a counter DELETED from the document, with the rest of the
   * section intact, is not noticed here; the floor catches only an empty
   * section. That is the trade, and it is named rather than hidden.
   *
   * `diagnostics` is in this table now, and it is measured: residual 8 said a
   * change to tests_ntasm_diagnostics.c that moved its counters without
   * touching the shape of its banner would not turn this gate red, and that is
   * no longer true. The door is at the fifth include, where run_host.h is read
   * again through the same rename so the member and the function move
   * together. `anchored_only` is gone from the banner because there is no
   * anchor left for it to count. */
  {
    unsigned claimed = 0, measured_n = 0, verified = 0;

    collect_coverage(spec, n);
    cases++;
    CHECK(claims_n > 0, "spec/ntasm/ntasm.md states at least one coverage counter");
    if (claims_overflow)
      failf("spec/ntasm/ntasm.md states more coverage counters than this harness can hold, which is %u", CLAIM_MAX);

    /* The fence is placed BEFORE the first twin and read AFTER the last one, so
     * the window it measures is exactly the window in which the twins read the
     * tree. Placing it anywhere else would leave the same hole with a check in
     * front of it, which is the shape this file keeps refusing. */
    src_collect(src_before, &src_n, &src_truncated);
    /* The twins run before anything is compared, and in the order of the COVER
     * table so that a reader of a red log sees them in the order they are
     * discussed. Each prints its own banner: this log is then its own proof
     * that none of the seven numbers below was read out of a build directory. */
    h1_locals_main();
    h1_bindings_main();
    h1_stub_table_main();
    h1_call_contracts_main();
    h1_diag_main();
    h1_splice_main();
    h1_reg_width_binding_main();
    /* Read the fence immediately, before any comparison, so a moved tree is
     * named first in the log rather than after six derived verdicts the reader
     * has already started to explain. */
    src_collect(src_after, &src_n_after, &src_truncated_after);
    if (src_moved(src_before, src_n, src_after, src_n_after, src_truncated,
                  src_truncated_after)) {
      /* THE FENCE'S OWN COUNTER, and the reason it is not `failures` alone.
       *
       * `failures` is the number a reader reads to decide whether the CODE is
       * wrong, and a tree that moved under the gate is not a statement about
       * the code: it says the measurement is void. Folding the two together
       * is what made the fourth run of 30 September 2026 unreadable -- it
       * printed `failures=1` and the reader could not tell from the banner
       * whether one check had failed or the tree had simply moved, and the
       * two demand opposite responses (fix the code / wait for the writers).
       *
       * So the fence charges BOTH: `failures`, because the run must still be
       * red and the driver reads the exit code, and `fence_moved`, so the
       * banner can subtract one from the other. `failures=1 fence_moved=1` is
       * a void measurement; `failures=1 fence_moved=0` is a real red. The fence
       * is not weakened by this -- it is still a hard failure -- it is only
       * made legible, which is the same trade the whole file keeps making.
       *
       * `fence_moved` counts the CALL, not the files: src_moved has already
       * named every file on stderr, and a banner that reported a file count
       * next to a failure count would invite a reader to add them together and
       * get a number this gate never measured. */
      checks++;
      failures++;
      fence_moved++;
    } else good();

    /* The fence above is only worth reading once it is known to be able to
     * fire, and that is what this proves -- on tables it builds, through the
     * same function, after the real verdict so the real verdict is still the
     * first thing the log says. Placing it before the twins would put twelve
     * synthetic cases in front of seven measured ones and make the log read as
     * though the twins were the preamble. check_resolver_rank below proves the
     * RETENTION half of the resolver, the half no clean tree could exercise. */
    check_fence();

    for (unsigned g = 0; g < COVER_N; g++) {
      const Cover *cv = &COVER[g];
      unsigned mc = 0, mf = 0, mk = 0, seen = 0;
      if (!measured(cv, &mc, &mf, &mk))
        failf("gate %s is a row of COVER and this harness has no in-process twin of it, so its "
              "counters are not measured and its numbers in the document are unchecked", cv->gate);
      else {
        measured_n++;
        if (mf != 0) failf("gate %s is red while its counters were measured: failures=%u", cv->gate, mf);
        else good();
        good();
      }
      cases++;
      if (!prints_its_own_banner(cv))
        failf("the harness of gate %s does not print the banner NTASM_NOVA_%s checks=/failures=/"
              "cases= that its counters are compared against", cv->gate, cv->gate);
      else good();
      for (unsigned q = 0; q < claims_n; q++) {
        if (strcmp(claim_gate[q], cv->gate) != 0) continue;
        seen++;
        cases++;
        if (claim_a[q] != mc || claim_b[q] != mc || claim_cases[q] != mk)
          failf("spec/ntasm/ntasm.md states `%s` %u/%u, %u cas and gate %s really produces %u checks "
                "and %u cases", cv->gate, claim_a[q], claim_b[q], claim_cases[q], cv->gate, mc, mk);
        else good();
      }
      if (seen == 0)
        failf("spec/ntasm/ntasm.md states no coverage counter at all for gate %s, which this file is "
              "responsible for: the section has been emptied around it", cv->gate);
      else good();
      claimed += seen;
      verified++;
    }
    /* The fourth direction: no counter of the document may name a gate that
     * is not one, or one this file does not measure. */
    for (unsigned q = 0; q < claims_n; q++) {
      int known = 0;
      cases++;
      if (!is_gate(claim_gate[q])) {
        failf("spec/ntasm/ntasm.md states the coverage counter `%s` %u/%u, %u cas and no gate of the "
              "suite is named %s",
              claim_gate[q], claim_a[q], claim_b[q], claim_cases[q], claim_gate[q]);
        continue;
      }
      for (unsigned g = 0; g < COVER_N; g++)
        if (strcmp(COVER[g].gate, claim_gate[q]) == 0) known = 1;
      if (!known)
        failf("spec/ntasm/ntasm.md states the coverage counter of gate %s and this file measures no "
              "counter for it, so that number is unchecked", claim_gate[q]);
      else good();
    }
    cases++;
    CHECK(claimed == claims_n, "every coverage counter of the spec belongs to a measured gate");
    /* The bijection, and the whole of what replaced the per-gate `claims` pin:
     * the scan read exactly as many counters as there are sites shaped like
     * one. A site it could not finish reading is the difference. */
    cases++;
    if (claim_sites != claims_n)
      failf("spec/ntasm/ntasm.md has %u sites shaped like a coverage counter and this harness read %u "
            "of them: a counter was reworded into a shape the parser cannot finish",
            claim_sites, claims_n);
    else good();
    printf("COVERAGE claims=%u sites=%u gates=%u measured=%u verified_gates=%u\n",
           claims_n, claim_sites, COVER_N, measured_n, verified);
  }

  /* ---- 8. the file:line references, then the re-judge. */
  /* The counters section 8 contributes are saved, because a re-judge replaces
   * them instead of adding to them: a run that refreshed its copy of the
   * document must report the same totals as a run that did not, or the banner
   * would be a function of the editor's timing. */
  unsigned ref_checks = checks, ref_failures = failures, ref_cases = cases;
  struct stat spec_at_load;
  int have_stat = stat("spec/ntasm/ntasm.md", &spec_at_load) == 0;
  check_references(spec, n, 1);

  /* spec/ntasm/ntasm.md is being rewritten by another lot while this gate runs, and
   * a reference is re-judged here on whatever the file says NOW if the file
   * moved under the run. That is the whole of the tolerance for a document in
   * flight, and it is deliberately narrow: it never softens the verdict, it
   * only stops the verdict from being about a copy of the document that no
   * longer exists. A rename that completes between the load and this point
   * therefore produces the correct verdict, not a red against a text that is
   * gone. Sections 1 to 7 keep the snapshot they were given, and the log says
   * so rather than leaving the reader to assume otherwise. If the file is
   * moving faster than the gate can settle, the verdict is not established and
   * that is a failure naming itself: this gate will not be green on a verdict
   * it could not take. */
  if (have_stat) {
    struct stat now;
    if (stat("spec/ntasm/ntasm.md", &now) == 0 &&
        (now.st_size != spec_at_load.st_size || now.st_mtime != spec_at_load.st_mtime)) {
      size_t n2 = 0;
      char *spec2 = loadf("spec/ntasm/ntasm.md", &n2);
      if (spec2) {
        int settled;
        char first[sizeof ref_banner];
        fprintf(stderr, "SPEC-REFRESHED bytes=%ld->%ld : spec/ntasm/ntasm.md was rewritten while this gate "
                        "ran, so the reference verdict was taken again on the current text; sections "
                        "1 to 7 keep the copy this run started from\n",
                (long)spec_at_load.st_size, (long)n2);
        checks = ref_checks;
        failures = ref_failures;
        cases = ref_cases;
        snprintf(first, sizeof first, "%s", ref_banner);
        check_references(spec2, n2, 0);
        if (strcmp(first, ref_banner) != 0) {
          fprintf(stderr, "REFERENCES-CHANGED : the re-judgement on the current text differs from "
                          "the one taken on the copy this run started from\n");
          fputs(ref_banner, stdout);
        }
        settled = stat("spec/ntasm/ntasm.md", &now) == 0 && now.st_size == (off_t)n2;
        if (!settled) {
          checks++;
          failures++;
          fprintf(stderr, "FAIL SPEC-MIDFLIGHT : spec/ntasm/ntasm.md moved again while its reference "
                          "verdict was being taken, so the verdict is about no text that is still on "
                          "disk. This gate does not report green on a verdict it could not "
                          "establish; run it again once the writer has finished.\n");
        }
        free(spec2);
      } else {
        fprintf(stderr, "SPEC-REFRESH-FAILED : spec/ntasm/ntasm.md moved under this gate and the new copy "
                        "does not load, so the reference verdict stands on the copy this run started "
                        "from\n");
      }
    }
  }

  /* ---- 9. the interval, and the two self-tests that say these two instruments
   * can fire. They run on EVERY invocation and before the comparison, for the
   * reason the fence self-test gives: a check that has only ever been seen in
   * one state has not been tested against the state it exists to detect, and
   * on a correct document today both of these are silent.
   * check_resolver_rank also proves the RETENTION, which is the half that was
   * wrong on 30 September 2026 and which no clean tree could have shown. */
  check_unresolved_classes();
  check_resolver_rank();
  check_drift();
  {
    static DriftDiff diff;
    int ok = drift_prev_outcome == DRIFT_OK;
    memset(&diff, 0, sizeof diff);
    if (ok) {
      drift_compare(&drift_prev, &drift_cur, &diff, 1);
      if (diff.refused_self) {
        /* The refusal the corpus self-host check already makes, in its words.
         * A drift check that compared a run with itself would pass whatever it
         * emitted, so this one refuses rather than reporting no drift. */
        checks++;
        failures++;
        fprintf(stderr, "FAIL REF-DRIFT-SELF : the state this run was about to compare against "
                        "carries this process's own pid and start, so the comparison would be a run "
                        "against itself and proves nothing.\n");
      } else good();
    } else if (drift_prev_outcome == DRIFT_ABSENT || drift_prev_outcome == DRIFT_FOREIGN) {
      /* NOT a failure, and the distinction is the point. A machine that has
       * never run this gate, or one whose state was written by a version that
       * is not this one, has no baseline; that is a fact about the machine and
       * not a defect of the document, and failing it would make the suite red
       * on a fresh checkout. What is NOT optional is that the run say so. A
       * first run that printed `drift=0` would be a green that certifies the
       * interval it never observed. */
      fprintf(stderr, "REF-DRIFT baseline=%s (%s) : this run has no previous run to compare with, "
                      "so it certifies the state it ran against and nothing about the interval "
                      "before it. The next run of this gate on this tree will be able to say.\n",
              drift_prev_outcome == DRIFT_ABSENT ? "absent" : "foreign", drift_prev_why);
      good();
    } else {
      /* A state THIS gate wrote and cannot read is a defect here, not a
       * condition of the machine: the comparison is refused rather than
       * reported, because a reader that answers "no drift" to a state it could
       * not parse is the most dangerous failure this instrument could have. */
      checks++;
      failures++;
      fprintf(stderr, "FAIL REF-DRIFT-STATE : %s wrote %s and this run cannot read it (%s), so the "
                      "interval is unmeasured. The state is refused rather than compared, because a "
                      "comparison over a state nobody read is a verdict about nothing.\n",
              DRIFT_STATE_PATH, drift_prev_why, "this gate");
    }
    drift_report(drift_prev_outcome, drift_prev_why, ok ? &diff : 0);
    fputs(drift_banner, stdout);
    if (!drift_write_current()) {
      /* Reported and not failed, and the reason is that a gate refusing to run
       * because it cannot keep a notebook would be a gate whose verdict
       * depends on a directory nobody promised it. The cost is stated in the
       * banner instead: with no state written, the NEXT run has no baseline
       * and will say so. */
      fprintf(stderr, "REF-DRIFT-STATE-UNWRITTEN : %s could not be written, so the next run of this "
                      "gate will have no baseline to compare with and will say drift=baseline. The "
                      "comparison above is still a comparison of this run and the previous one.\n",
              DRIFT_STATE_PATH);
      good();
    } else good();
  }

  /* ---- 10. the STRUCTURE of the two documents, and the self-test that says
   * these three checks can see a defect at all. Last, so that a structural
   * failure cannot be confused with a content failure in the log above, and so
   * that nothing it does can disturb the drift state, which was already
   * written from the verdicts of the citations.
   *
   * The self-test runs FIRST and on every invocation, for the reason its own
   * comment gives and not for tidiness: on a correct document today every one
   * of these checks is silent, so a run that only ever exercised the silent
   * state would be an instrument that has only ever been exercised in one
   * state -- which is the defect this whole project exists to remove, applied
   * to the instrument rather than to the document. */
  check_doc_structure_selftest();
  if (!doc2) {
    checks++;
    failures++;
    fprintf(stderr, "FAIL DOC-STRUCTURE-ABSENT : %s does not load from the repository root, so the "
                    "structure of the document that states the B2.1 acceptance criteria is not "
                    "checked at all. A check that cannot open its subject must say so rather than "
                    "report the other one and look complete.\n", DOC2_PATH);
  } else {
    check_doc_structure(spec, n, doc2, doc2n);
  }

  /* ---- 11. the SHAPE of the 17.9 register, which is a different question
   * from its row count and the one a count cannot answer. It runs after the
   * structural pass so that a table which is malformed as a TABLE and a table
   * whose numbering is wrong are two different reds in two different places
   * in this log, rather than one failure that could be either. */
  check_register_shape(spec, n, doc2, doc2n);

  /* ---- 12. the SHAPE OF THE GATES, which is a claim about the tree and about
   * neither document, and it therefore runs last: a failure here is a failure
   * of the census, and the reader has already seen both documents' verdicts
   * above, so the two kinds of red are never confused in one log.
   *
   * It reads the build script's own ARRAYS and never its comment block, which
   * is the whole design and not a shortcut; the header on the section says why
   * a check anchored to a sentence is last-writer-wins wearing a different hat.
   * It runs after the drift state is written, deliberately: the state file
   * records the citation verdicts, and a section that reads 124 further sources
   * has no business invalidating a comparison the log has already made. */
  check_gate_shape();

  printf("REGISTRY modules=%u rows=%u published=%u emitted=%u agreed=%u missing=%u extra=%u unattributed=%u\n",
         modules, rows, published_n, emitted_n, agreed, missing, extra, unattributed_n);
  reg_banner();
  free(spec);
  free(doc2);
  return failures ? 1 : 0;
}

/* ==================================================================== RANK AND
 * RETENTION. Placed at the FOOT of this file, below the last line any document
 * cites in it, because a definition added at the top would shift
 * `tests_ntasm_registry.c:388-395`, `:5363-5371` and `:6007` in
 * docs/status/ntasm-completion.md and invalidate three correct citations silently.
 * That is the trap this very resolver walks into, so the repair pays it
 * explicitly rather than by luck.
 *
 * WHAT WENT WRONG ON 30 SEPTEMBER 2026, in the shape the reader needs.
 *
 *   STALE-LINE  docs/status/ntasm-completion.md:43 cites ngbuild.sh:760-760 and the
 *               file it resolves to,
 *               out/c-bootstrap/builds/w26reg2/neg/CLASS/tools/coldproof/ngbuild.sh,
 *               has 9 lines
 *
 * The citation is CORRECT -- legacy/tools/coldproof/ngbuild.sh:760 is `ROOT_GATES=(`,
 * the construct the A2 row's displacement_offset finding depends on -- and the
 * report says the line is stale. Those are two different defects with OPPOSITE
 * repairs: a stale line means the citation must be re-pointed, and a wrong
 * resolution means NO citation needs changing and the RESOLVER is wrong. A
 * check that reports the second as the first sends the next reader to edit a
 * correct citation, which is this project's recurring shape one level up.
 *
 * THE CAUSE, and it is not the preference. The resolver already ranked by
 * depth, and depth is right: `legacy/tools/coldproof/ngbuild.sh` is at depth 3 and
 * the four W26 mutation batteries at depth 9. The defect was the TABLE. The
 * candidate list kept the FIRST REF_MATCH (4) matches in WALK ORDER and
 * stamped its path only for those, while REF_ROOTS declares out/c-bootstrap
 * at index 7 and tools at index 9 -- so four dated snapshots of
 * legacy/tools/coldproof/ngbuild.sh were recorded first, the real file arrived fifth
 * and its path was never stored, the depth search ran over four mutants, and
 * its tie at depth 9 was broken by path order into CLASS. Five files share the
 * name; the preference was never given the one it wanted.
 *
 * WHY NOT EXCLUDE out/. Three shapes were open. (1) Dropping out/ from the walk
 * is the simplest and is incoherent: REF_ROOTS declares out/c-bootstrap as a
 * root because a document cites a driver.c that exists only there, and a
 * declared root the walk never enters is a contradiction, not a policy. Those
 * four mutants are a W26 regression battery recorded as evidence and are not
 * junk to be swept.
 *
 * WHAT WAS BUILT, and why it is (2) with the refusal of (3) kept for the part
 * (2) cannot cover.
 *
 * `tgt_add` inserts at RANK and evicts the worst, so the head of the table is
 * the best file the walk has ever seen however many copies arrive later. That
 * is (2)'s "prefer the canonical location": the preference is made to work on
 * the file it names rather than on whichever four the directory order
 * happened to yield, and today the instance resolves to
 * legacy/tools/coldproof/ngbuild.sh, 1107 lines, and stale_lines drops 1 -> 0
 * because the line was never stale.
 *
 * (3) -- refuse rather than resolve -- is KEPT for the case where the
 * preference runs out. Measured on this tree, 30 September 2026: 94 of the 101
 * distinct names the two documents cite answer in more than one place, 365 of
 * 384 citations, so refusing every ambiguity would refuse 95% of the
 * citations over copies of files the preference separates cleanly and
 * correctly. A refusal that fires on 365 correct citations teaches readers to
 * ignore it, which is the noise the TIE log was already deleted for. The
 * refusal therefore fires only where two candidates agree on BOTH axes --
 * same artefact class, same depth -- and nothing in the tree says which a
 * citation meant. Measured here: ZERO such names, which is why the counter is
 * in the banner rather than the failure list, and why the negative control
 * below BUILDS one: an instrument that has never refused anything is not known
 * to refuse. */
static int rank_cmp(int art_a, const char *pa, int art_b, const char *pb) {
  unsigned da, db;
  if (art_a != art_b) return art_a < art_b ? -1 : 1;
  da = tgt_depth(pa);
  db = tgt_depth(pb);
  if (da != db) return da < db ? -1 : 1;
  return strcmp(pa, pb);
}

static void tgt_add(unsigned g, const char *path, int artefact) {
  unsigned n = tgt_nmatch[g] < REF_MATCH ? tgt_nmatch[g] : REF_MATCH;
  unsigned at = n, count;
  for (unsigned i = 0; i < n; i++)
    if (rank_cmp(artefact, path, tgt_match_artefact[g][i], tgt_match[g][i]) < 0) { at = i; break; }
  /* COUNTED FIRST, and always. `tgt_nmatch` is how many files of the declared
   * scope answer to this name, which is what `copied=` and `multi_names=` are
   * read from, so incrementing it only on the insert path pins it at REF_MATCH
   * the moment the table fills and quietly understates every later arrival.
   * The first version of this line did exactly that and the self-test caught
   * it by counting five offered files and being told four. */
  tgt_nmatch[g]++;
  if (at >= REF_MATCH) { tgt_truncated[g] = 1; return; }
  count = n < REF_MATCH ? n + 1 : REF_MATCH;
  for (unsigned i = count; i-- > at + 1;) {
    memcpy(tgt_match[g][i], tgt_match[g][i - 1], REF_PATH);
    tgt_match_artefact[g][i] = tgt_match_artefact[g][i - 1];
  }
  snprintf(tgt_match[g][at], REF_PATH, "%s", path);
  tgt_match_artefact[g][at] = artefact;
}

/* THE TWO NEW MESSAGES, kept here for the same reason the rest of this section
 * is here. Both are the reader's first contact with a resolution this
 * instrument could not make, so both SAY which file was read and why the
 * other candidate is equally plausible -- a class name alone sends the next
 * reader looking for a stale citation, which is the error this class exists
 * to stop. */
static void ref_report_ambiguous(unsigned g) {
  fprintf(stderr, "AMBIGUOUS_REFERENCE %s : %u files of the declared scope answer to that name and "
                  "the preference -- a source over a build artefact, then the shallowest -- does not "
                  "separate them, so the one judged is the first in path order and nothing in the "
                  "tree says that is the one meant. This is NOT a stale line: a stale line says the "
                  "cited text is no longer at the cited position, and this is a finding about WHICH "
                  "FILE was read. The candidates are:\n", tgt_name[g],
          tgt_nmatch[g] < REF_MATCH ? tgt_nmatch[g] : REF_MATCH);
  for (unsigned m = 0; m < tgt_nmatch[g] && m < REF_MATCH; m++)
    fprintf(stderr, "    %8lu lines  %s\n", tgt_lines[g][m], tgt_match[g][m]);
}

static void ref_report_unseparated(unsigned q, const char *name, unsigned lo, unsigned hi,
                                    unsigned long head_lines) {
  fprintf(stderr, "NOT-STALE-BUT-UNRESOLVED %s:%u cites %s:%u-%u, the head of whose candidate list "
                  "has %lu lines, and at least one rival is at the same depth and the same artefact "
                  "class. The line may be exactly right against the other file; this is counted as "
                  "AMBIGUOUS_REFERENCE and not as a stale line, because the remedies are "
                  "different\n", rdoc(q), ref_line[q], name, lo, hi, head_lines);
}

/* The resolver's own rank and retention, proved rather than argued in a
 * comment, because the defect they replace was invisible on a clean tree: the
 * gate was GREEN with a citation resolved against a nine-line mutation battery.
 *
 * The shape under test is the one that produced it -- five files of one name,
 * four artefacts at depth 9 offered FIRST because REF_ROOTS declares
 * out/c-bootstrap at index 7 and tools at index 9, and the source at depth 3
 * offered last. A first-N table stops with four mutants; a best-N table keeps
 * the source at the head. */
static void check_resolver_rank(void) {
  /* A PRIVATE SLOT, appended past every target the run collected, and the run's
   * own target state restored on the way out. The first version borrowed the
   * real target of the same name, which made the count assertion depend on the
   * document's own citations: a test whose expected value comes from the thing
   * under test is a test that can be right for the wrong reason. */
  unsigned g = tgts_n < TGT_MAX - 1 ? tgts_n : TGT_MAX - 1, saved_n = tgts_n;
  memset(tgt_ambiguous, 0, sizeof tgt_ambiguous);
  memset(tgt_truncated, 0, sizeof tgt_truncated);
  memset(tgt_match_artefact, 0, sizeof tgt_match_artefact);
  memset(tgt_match, 0, sizeof tgt_match);
  memset(tgt_nmatch, 0, sizeof tgt_nmatch);
  snprintf(tgt_name[g], NAME_MAX, "%s", "ngbuild.sh");
  tgt_add(g, "out/c-bootstrap/builds/w26reg2/neg/CLASS/tools/coldproof/ngbuild.sh", 1);
  tgt_add(g, "out/c-bootstrap/builds/w26reg2/neg/D1-ROTT/tools/coldproof/ngbuild.sh", 1);
  tgt_add(g, "out/c-bootstrap/builds/w26reg2/neg/D2-ROTT/tools/coldproof/ngbuild.sh", 1);
  tgt_add(g, "out/c-bootstrap/builds/w26reg2/neg/QUIET/tools/coldproof/ngbuild.sh", 1);
  tgt_add(g, "legacy/tools/coldproof/ngbuild.sh", 0);
  CHECK(strcmp(tgt_match[g][0], "legacy/tools/coldproof/ngbuild.sh") == 0,
        "the HEAD of the candidate table is the SOURCE, not the first file the walk offered: a "
        "best-N retention keeps the file the preference wants even when it arrives last");
  CHECK(tgt_match_artefact[g][0] == 0,
        "the head carries the artefact flag of the root it was found under, so it reads as source");
  if (tgt_nmatch[g] != 5) {
    failf("the candidate table counted %u of the five candidates offered and keeps REF_MATCH=%u of "
          "them; a candidate that is counted but not kept is exactly the shape that lost "
          "legacy/tools/coldproof/ngbuild.sh on 30 September 2026", tgt_nmatch[g], REF_MATCH);
  } else good();
  /* POSITIVE, because rank_cmp answers "does A outrank B": the WORSE file
   * compares greater. These three signs were written as < 0 on the reasoning
   * that the preferred file compares less, which the opposite is; a standalone
   * probe of the same function settled it and the probe was right, so the
   * assertions were wrong and not the preference. A control asserting the
   * wrong sign proves nothing about the thing it is a control for. */
  CHECK(rank_cmp(1, "out/c-bootstrap/builds/w26reg2/neg/CLASS/tools/coldproof/ngbuild.sh",
                 0, "legacy/tools/coldproof/ngbuild.sh") > 0,
        "a build artefact ranks WORSE than a source whatever its depth, which is what the out/ "
        "root's artefact flag buys and what a depth-only rule would not decide");
  CHECK(rank_cmp(0, "a/b/c/d.nova", 0, "a/b/n.nova") > 0,
        "among sources the DEEPER file ranks worse, and the order is TOTAL (path order breaks the "
        "remainder) so two runs over one tree cannot disagree about what was read");

  /* And the irreducible case, built rather than waited for. Two SOURCES at the
   * same depth is exactly what source-over-artefact-then-shallowest cannot
   * separate, and this branch has never once run on this tree. */
  memset(tgt_nmatch, 0, sizeof tgt_nmatch);
  memset(tgt_ambiguous, 0, sizeof tgt_ambiguous);
  memset(tgt_truncated, 0, sizeof tgt_truncated);
  memset(tgt_match_artefact, 0, sizeof tgt_match_artefact);
  memset(tgt_match, 0, sizeof tgt_match);
  /* Two SOURCES at the SAME depth: same segment count, neither a prefix of the
   * other, so neither artefact flag nor depth separates them. The first pair
   * tried here was compiler/c/ntasm/cli/cli.c and .../nova/cli.c, which are
   * depth 4 against depth 5 -- the preference separates those cleanly and the
   * assertion below failed on its own bad data, which is the shape of a control
   * that proves the reader nothing. */
  tgt_add(g, "compiler/c/ntasm/cli/cli.c", 0);
  tgt_add(g, "compiler/c/nova/cli/cli.c", 0);
  CHECK(tgt_nmatch[g] == 2, "two sources of one name are both retained");
  /* NEGATIVE here, and the sign flips between this and the two above because the
   * arguments differ: both of those compare a WORSE file against a better one,
   * this one compares the BETTER file first. The probe in the scratch directory
   * is what settled both signs; reasoning about the convention got one of them
   * backwards and the run said so. */
  CHECK(rank_cmp(0, "compiler/c/ntasm/cli/cli.c", 0, "compiler/c/nova/cli/cli.c") < 0,
        "depth DOES separate two sources that sit at different depths, the shallower ranking "
        "better, so this pair is resolved and is NOT ambiguous");
  tgt_add(g, "bootstrap/quarantine/cx/cli.c", 0);
  {
    unsigned m, ties = 0;
    for (m = 1; m < tgt_nmatch[g] && m < REF_MATCH; m++)
      if (tgt_depth(tgt_match[g][m]) == tgt_depth(tgt_match[g][0]) &&
          tgt_match_artefact[g][m] == tgt_match_artefact[g][0]) ties = 1;
    CHECK(ties,
          "two sources at the SAME depth are indistinguishable by the preference, which is the "
          "condition AMBIGUOUS_REFERENCE exists to refuse rather than to resolve by path order");
  }
  /* The run's own target state is put back, so a self-test that borrowed a slot
   * cannot be the reason a later section reads a different tree than the banner
   * described. */
  memset(tgt_nmatch, 0, sizeof tgt_nmatch);
  memset(tgt_ambiguous, 0, sizeof tgt_ambiguous);
  memset(tgt_truncated, 0, sizeof tgt_truncated);
  memset(tgt_match_artefact, 0, sizeof tgt_match_artefact);
  memset(tgt_match, 0, sizeof tgt_match);
  tgt_name[g][0] = '\0';
  tgts_n = saved_n;
  printf("RESOLVER-RANK 9 cases: a source beats an artefact whatever the depth, then the shallower "
         "source, then path order; the table keeps the BEST %u candidates rather than the FIRST %u, "
         "and a pair no preference can separate is refused as AMBIGUOUS_REFERENCE\n",
         REF_MATCH, REF_MATCH);
}
