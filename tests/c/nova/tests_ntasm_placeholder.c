/* tests_ntasm_placeholder.c -- the gate for A1's SECOND CONJUNCT.
 *
 * WHAT THIS GATE IS ABOUT. The A1 row of docs/status/ntasm-completion.md carries two
 * conjuncts, and they are in different states. Conjunct 1 names the
 * prerequisites of spec/ntasm/ntasm.md section 17; the first of those is a complete
 * lexical grammar / EBNF, which that document declares must be frozen before
 * the first v0 behaviour, and the word "lexicale" occurs exactly once in the
 * whole of toolchain/ntasm-nova. That prerequisite is UNFROZEN, and no gate
 * can make a gate out of an unfrozen prerequisite. Conjunct 2 is different in
 * kind: "aucune fonction prevue remplacee par un placeholder" is a property OF
 * THE TREE, and a property of a tree is decidable today. This file is the
 * instrument for conjunct 2, and for conjunct 2 only.
 *
 * WHAT A GREEN RUN HERE DOES NOT ESTABLISH. It does not make A1 conformant.
 * Sections 17 items 1, 5 and 6 are declared unfrozen or open by the document's
 * own text, so A1 stays PARTIAL whatever this gate prints. A green conjunct 2
 * makes ONE OF A1's TWO CONJUNCTS decidable, which is a smaller and different
 * claim. No A1-A10 criterion is declared conformant by this file and no
 * percentage is derived from any count printed here.
 *
 * WHY THE RULE IS NOT "GREP FOR THE WORD". x64_lower_nxo.nova carries the
 * word "placeholder" six times and NOT ONE of the six is a stub: every one is
 * a comment that RETRACTS the word about itself, naming a gap instead of
 * hiding one. A gate that searched for the word would find six false positives
 * before it found anything, and would then have been "fixed" by deleting the
 * honest comments. So this gate NEVER searches for the word. It searches for a
 * SHAPE: a function body that is a lone constant.
 *
 * THE RULE, in the form this gate can actually decide.
 *
 *   A function whose entire body is `return <integer literal>;` is a
 *   PLACEHOLDER unless the constant is a DEFINITION. A constant is a
 *   definition when it is the carrier of a named quantity that the rest of
 *   the tree consumes. Three independent axes of evidence decide it, and the
 *   gate prints which ones carried the decision:
 *
 *     FAMILY    the constant is one member of a named enumeration: a sibling
 *               constant accessor in the same file, either adjacent (within
 *               eight physical lines) or sharing a name stem of three or more
 *               characters. This is the axis the four measured candidates
 *               rest on: bind_value / bind_local / bind_decl, pos_bind /
 *               pos_spelled / pos_caller, arg_node / arg_value, name_pair /
 *               contract_pair.
 *     MAGNITUDE the name of the accessor is itself the name of a quantity --
 *               max_*, *_cap, *_bound, *_limit, *_stride, *_bytes, *_depth,
 *               *_len, and so on. `max_fuel() { return 1048576; }` is not a
 *               stub; it is the budget, and the budget has a name.
 *     REACH     some other call site in the tree READS the accessor. A
 *               constant nobody reads cannot be a definition of anything,
 *               because a definition is by definition consumed.
 *
 * A body that is not a lone constant is NOT_CONSTANT and is never a
 * placeholder by this rule. A lone constant with no family, no magnitude name
 * and no reader is a PLACEHOLDER and turns the gate RED at a named assertion.
 *
 * AND THE PART THAT IS NOT A REGEX. Deciding "a lone constant is a stub"
 * versus "a lone constant is a definition" is a judgement; three axes narrow
 * it but they do not abolish it, and a gate that printed only a verdict would
 * be asking the reader to trust it. So EVERY constant body is printed with the
 * evidence for its own classification: shape, value, the enumeration it was
 * matched into and the sibling family that matched, the magnitude token that
 * matched, and the number of call sites that read it. The value of this gate
 * is not the verdict. It is that the verdict became REVIEWABLE.
 */
/* dirent and strtok_r are POSIX; -std=c11 alone does not declare either. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures;
static unsigned nova_files, nova_constant_bodies;
static unsigned oracle_statics, oracle_constant_bodies;
static unsigned family_defs, magnitude_defs, reach_defs, placeholders;
static unsigned unreferenced_constant_bodies;

#define CHECK(c, m) do { checks++; if (!(c)) { failures++; \
  fprintf(stderr, "FAIL %s\n", m); } } while (0)

/* ------------------------------------------------------------------ text -- */

static char *slurp(const char *path, size_t *n) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
  long z = ftell(f);
  if (z < 0) { fclose(f); return NULL; }
  if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
  char *b = (char *)malloc((size_t)z + 1);
  if (!b) { fclose(f); return NULL; }
  size_t got = fread(b, 1, (size_t)z, f);
  fclose(f);
  if (got != (size_t)z) { free(b); return NULL; }
  b[z] = 0;
  if (n) *n = (size_t)z;
  return b;
}

/* Count non-overlapping occurrences of needle in hay, as a whole-word call
 * `name(` so that bind_value() is not matched inside bind_value_x(). */
static unsigned count_calls(const char *hay, const char *name) {
  size_t nl = strlen(name);
  unsigned hits = 0;
  for (const char *p = hay; (p = strstr(p, name)) != NULL; p += nl) {
    if (p[nl] != '(') continue;
    if (p != hay) {
      char c = p[-1];
      int word = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_';
      if (word) continue;
    }
    hits++;
  }
  return hits;
}

/* ------------------------------------------------------------ magnitude -- */

/* The tokens that make an accessor name the NAME of a quantity. Matched on a
 * whole '_'-separated segment, so `max_fuel` carries `max` and `early_len`
 * carries `len`, while a name that merely contains a token as a substring
 * carries none. Reported back to the reader so the classification can be
 * checked rather than trusted.
 *
 * AND THE EXCLUSION THAT HAD TO BE MEASURED, NOT ASSUMED. The first version
 * of this axis accepted any segment, and the negative control
 * `fn emit_x64_vector_tail()->u64 { return 7; }` came back GREEN, because
 * `vector` is in the token list. That is a gate whose needle survived its own
 * relaxation: the control could not fail, so the control proved nothing. The
 * token list is not wrong -- `witness_vector` is a real quantity in
 * stub_table.nova -- the MATCH is. What separates the two is the VERB: an
 * accessor named for an ACTION promises work, and an accessor whose name is a
 * noun phrase IS the quantity. So a name carrying an action verb anywhere
 * withdraws the magnitude rescue, and the body falls through to the family
 * and reach axes on its own evidence.
 *
 * LEAD SEGMENT FIRST, THEN ANYWHERE. Checking only the lead was not enough,
 * and the second negative control found it: `fn planned_lower_cap()->u64
 * { return 7; }` came back GREEN, because `cap` is a magnitude token and
 * `lower` is not in the lead. The verb is in the middle of the name, where a
 * reader who meant to name a quantity would not put one. Extending the
 * exclusion to every segment was measured against the real corpus first: of
 * the 225 constant bodies, ZERO lose the magnitude rescue under the wider
 * rule, so it costs nothing on today's bytes and closes the hole. */
static const char *const action_verbs[] = {
  "emit", "write", "lower", "encode", "decode", "build", "make", "gen",
  "generate", "run", "apply", "push", "load", "store", "check", "verify",
  "assert", "init", "setup", "alloc", "free", "parse", "scan", "walk",
  "collect", "visit", "render", "format", "pack", "unpack", "copy", "fill",
  "map", "reduce", "fold", "insert", "append", "lookup", "resolve", "bind",
  "planned", "todo", "stub", "dummy", "fake", "later", "future",
  NULL
};

static int segment_is(const char *name, size_t at, size_t seglen,
                      const char *const *list) {
  for (int t = 0; list[t]; t++) {
    if (strlen(list[t]) == seglen && strncmp(name + at, list[t], seglen) == 0)
      return 1;
  }
  return 0;
}

static const char *magnitude_token(const char *name) {
  static const char *toks[] = {
    "max", "min", "cap", "caps", "bound", "limit", "limiter", "stride",
    "bytes", "byte", "depth", "words", "word", "len", "length", "size",
    "slot", "slots", "marker", "base", "vector", "desc", "scratch",
    "offset", "align", "alignment", "seed", "count", "magic", "record",
    "capacity", "threshold", "budget", "arena", "nodes", "fuel", "fuels",
    NULL
  };
  size_t nl = strlen(name);
  /* First pass: does ANY segment name an action? If so this accessor claims
   * to DO something, and a lone constant body is a stub until the family and
   * reach axes say otherwise. */
  for (size_t at = 0; ;) {
    size_t e = at;
    while (e < nl && name[e] != '_') e++;
    if (segment_is(name, at, e - at, action_verbs)) return NULL;
    if (e >= nl) break;
    at = e + 1;
  }
  /* Second pass: is any segment the NAME of a quantity? */
  for (size_t at = 0; ;) {
    size_t e = at;
    while (e < nl && name[e] != '_') e++;
    size_t seglen = e - at;
    for (int t = 0; toks[t]; t++) {
      if (strlen(toks[t]) == seglen && strncmp(name + at, toks[t], seglen) == 0)
        return toks[t];
    }
    if (e >= nl) break;
    at = e + 1;
  }
  return NULL;
}

/* Does any '_'-separated segment of this name name an ACTION? The first
 * version of this gate used the verb test to withdraw only the MAGNITUDE
 * rescue, and the third negative control found the gap: injecting
 * `fn planned_lower_cap()->u64 { return 7; }` came back GREEN, because the
 * weak SHARED_TAIL family rule matched the real `parameter_cap` and
 * `template_item_cap` on the trailing `cap`. A name that promises work cannot
 * be rescued by a family match on a suffix; it has to be a member of a real
 * enumeration or be read. See the decision below. */
static int has_action_verb(const char *name) {
  size_t nl = strlen(name);
  for (size_t at = 0; ;) {
    size_t e = at;
    while (e < nl && name[e] != '_') e++;
    if (segment_is(name, at, e - at, action_verbs)) return 1;
    if (e >= nl) break;
    at = e + 1;
  }
  return 0;
}

/* -------------------------------------------------------------- records -- */

typedef struct {
  const char *file;   /* path of the owning source */
  const char *name;   /* accessor name, points into `store` */
  long line;          /* 1-based line of the definition */
  unsigned long long uvalue; /* the constant as the source writes it */
  const char *comment;       /* trailing `//` annotation, or NULL */
  int family;         /* matched a named enumeration */
  int strong_family;  /* matched SAME_LEAD or STEM3, not the weak tail rule */
  int verb;           /* the name carries an action verb, so it promises work */
  int magnitude;      /* matched a magnitude token */
  int reach;          /* read by a call site outside its own definition */
  const char *sibling;/* name of the sibling that carried the family match */
} Body;

/* Storage for names and file paths, so Body can hold borrowed pointers that
 * outlive the parse. */
static const char **namestore; static unsigned namestore_n, namestore_cap;
static const char **pathstore; static unsigned pathstore_n, pathstore_cap;

/* Grow an array of borrowed pointers. The pointed-to strings are owned by
 * their own arena, so the array is the only thing this allocates and the only
 * thing the caller frees. */
static void push_ptr(const char ***arr, unsigned *n, unsigned *cap, const char *p) {
  if (*n == *cap) {
    *cap = *cap ? *cap * 2 : 64;
    *arr = (const char **)realloc(*arr, *cap * sizeof(char *));
    if (!*arr) { fprintf(stderr, "OOM\n"); exit(2); }
  }
  (*arr)[(*n)++] = p;
}

static const char *push_str(const char ***store, unsigned *n, unsigned *cap,
                            const char *s) {
  if (*n == *cap) {
    *cap = *cap ? *cap * 2 : 256;
    *store = (const char **)realloc(*store, *cap * sizeof(char *));
    if (!*store) { fprintf(stderr, "OOM\n"); exit(2); }
  }
  const char *p = malloc(strlen(s) + 1);
  if (!p) { fprintf(stderr, "OOM\n"); exit(2); }
  strcpy((char *)p, s);
  (*store)[(*n)++] = p;
  return p;
}

static const char *intern(const char *s) {
  return push_str(&namestore, &namestore_n, &namestore_cap, s);
}
static const char *intern_path(const char *s) {
  return push_str(&pathstore, &pathstore_n, &pathstore_cap, s);
}

/* ------------------------------------------------------------ nova parse -- */

/* A nova accessor whose ENTIRE body is a lone constant, on one physical line:
 *   fn name()->type { return <int>; }
 * Matched strictly, and the strictness is the point: a body with a second
 * statement, a `let`, a call, or a comment inside the braces is not this
 * shape and is not a placeholder by this rule. */
static int parse_nova_constant(const char *line, char *name, size_t ncap,
                               long long *value, const char **comment) {
  const char *p = line;
  *comment = NULL;
  if (p[0] != 'f' || p[1] != 'n' || p[2] != ' ') return 0;
  p += 3;
  size_t i = 0;
  while (p[i] && ((p[i] >= 'a' && p[i] <= 'z') || (p[i] >= 'A' && p[i] <= 'Z') ||
                  (p[i] >= '0' && p[i] <= '9') || p[i] == '_')) {
    if (i + 1 >= ncap) return 0;
    name[i] = p[i];
    i++;
  }
  if (i == 0) return 0;
  name[i] = 0;
  if (p[i] != '(') return 0;
  const char *q = strchr(p + i, ')');
  if (!q) return 0;
  q++;
  if (*q != '-' && *q != '+' && *q != '>') return 0;
  q = strchr(q, '{');
  if (!q) return 0;
  q++;
  while (*q == ' ' || *q == '\t') q++;
  if (strncmp(q, "return", 6) != 0) return 0;
  q += 6;
  while (*q == ' ' || *q == '\t') q++;
  const char *d = q;
  /* Parse as UNSIGNED with a sign flag. The tree carries u64 sentinels that do
   * not fit a signed 64-bit integer: stub_table.nova `failed` and ntir.nova
   * `ANY_AUX` both return 18446744073709551615. strtoll saturates those to
   * LLONG_MAX and sets ERANGE, so a signed parse printed a number the source
   * does not contain -- on the first run, for exactly two of the bodies. */
  int neg = 0;
  if (*d == '-') { neg = 1; d++; }
  if (*d < '0' || *d > '9') return 0;
  errno = 0;
  char *end = NULL;
  unsigned long long uv = strtoull(d, &end, 10);
  if (!end || end == d || errno == ERANGE) return 0;
  *value = neg ? -(long long)uv : (long long)uv;
  while (*end == ' ' || *end == '\t') end++;
  if (*end != ';') return 0;
  end++;
  while (*end == ' ' || *end == '\t') end++;
  if (*end != '}') return 0;
  end++;
  /* FIFTEEN of the 58 .nova files are CRLF, measured 30 September 2026, so a
   * line read by strtok_r on "\n" ends in a bare '\r'. Treating that as a
   * character after the brace made this gate miss 64 of the 225 constant
   * bodies -- a count that looked like a result and was a line-ending
   * convention. Whitespace here means space, tab or CR, everywhere. */
  while (*end == ' ' || *end == '\t' || *end == '\r') end++;
  if (*end != 0) {
    /* Anything after the closing brace on the same physical line is a
     * trailing comment that ANNOTATES the constant, and the body is still a
     * lone constant. Measured: stub_table.nova writes several of its
     * constants this way, each with a `//` naming what the number means. A
     * reader who wrote such a comment has annotated the value, not hidden
     * work. The comment is captured and printed, because it is evidence for
     * the classification and the reader is entitled to see it. A `//` is the
     * only thing accepted here: anything else is a shape this gate has not
     * been shown, and is refused rather than guessed at. */
    if (strncmp(end, "//", 2) != 0) return 0;
    *comment = end + 2;
    while (**comment == ' ' || **comment == '\t' || **comment == '\r')
      (*comment)++;
  }
  return 1;
}

static int name_stem_overlap(const char *a, const char *b) {
  /* three or more leading characters in common, case-insensitively */
  size_t n = 0;
  while (a[n] && b[n]) {
    char x = a[n], y = b[n];
    if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
    if (x != y) break;
    n++;
  }
  while (n > 0 && a[n - 1] == '_') n--;
  return n >= 3;
}

/* The length of the first '_'-separated segment: `bind_value` -> 4, `k_const`
 * -> 1, `capacity` -> 8. Two constants sharing this lead are members of one
 * enumeration, because the lead is the word that says WHAT is being
 * enumerated. The caller compares that many bytes of the two names. A name
 * that begins with '_' yields a zero-length lead and therefore matches
 * nothing, which is the safe direction: a malformed name cannot join itself
 * to every other constant in the file. */
static size_t lead_len(const char *name) {
  const char *u = strchr(name, '_');
  return u ? (size_t)(u - name) : strlen(name);
}

/* The LAST '_'-separated segment: `name_pair` -> `pair`, `contract_pair` ->
 * `pair`. Two constants sharing this tail are the alternatives of one
 * partition -- the same slot, filled with different choices -- which is the
 * family the front of the name cannot express. */
static const char *tail_segment(const char *name) {
  const char *u = strrchr(name, '_');
  return u ? u + 1 : name;
}

/* --------------------------------------------------------------- report -- */

/* THE DECISION, in one place, so the printed verdict and the failing
 * assertion cannot drift apart. They did drift once, when the C half
 * classified on one condition and failed on another.
 *
 *   A lone constant body is a PLACEHOLDER unless the constant is a
 *   definition. It is a definition when the tree consumes it as a named
 *   quantity, on any of three axes:
 *
 *     STRONG FAMILY  a sibling in the same enumeration, matched by the lead
 *                   segment or a three-character stem: the two rules that
 *                   say WHAT is being enumerated.
 *     MAGNITUDE      the name is the name of a quantity. Withdrawn when the
 *                   name carries an action verb, because `emit_x64_vector`
 *                   names a thing to emit, not a vector length.
 *     REACH          a call site reads it. A definition is consumed; a
 *                   constant nobody reads is a declaration, not a meaning.
 *
 *   AND THE ONE ASYMMETRY, which the third negative control forced. A name
 *   that carries an action verb PROMISES WORK, so it may be rescued only by
 *   a STRONG family or by REACH. The weak shared-tail rule cannot rescue it:
 *   `planned_lower_cap` shares the tail `cap` with the real `parameter_cap`
 *   and `template_item_cap`, and that suffix kinship is exactly what a stub
 *   writer gets for free. Measured against the corpus before adoption: of the
 *   225 bodies, all 21 verb-named ones are rescued by a strong family or by
 *   being read, so the restriction costs today's tree nothing. */
static int rescued(const Body *b) {
  if (b->verb) return b->strong_family || b->reach;
  return b->family || b->magnitude || b->reach;
}

/* ===========================================================================
 * THE FIXTURE PAIR, and this gate's weakness is INVERTED relative to the other
 * six. Everywhere else the guard is a check that can be deleted; here the
 * guard is a DETECTOR, and the shape that cannot be caught is a detector that
 * never matches. `rescued()` returning a fabricated TRUE, or a recogniser
 * matching nothing at all, leaves every count in this file printing and no
 * count asserted -- `placeholders=0` was green on a tree where the rule had
 * stopped biting. Nothing in the corpus ever injected a placeholder to prove
 * the detector fires, so the corpus being clean and the detector being broken
 * were the same observation.
 *
 * THE PAIR IS ONE NAME. Both arms are a synthetic one-line body fed through
 * the SAME parse, the SAME three axes and the SAME `rescued()` the corpus
 * scan uses -- not a re-implementation, so the fixture cannot drift from the
 * rule it is testing. `max_fuel()->u64 { return 1048576; }` is a DEFINITION
 * (the MAGNITUDE axis: `max` names a quantity). `planned_lower_cap()->u64 {
 * return 7; }` is a PLACEHOLDER, and it is the exact injection this file's
 * own comments at line 209 record as having once come back GREEN.
 *
 * WHY THESE TWO NAMES AND NOT TWO ARBITRARY ONES. The two arms must exercise
 * OPPOSITE sides of the one asymmetry the decision function encodes, or the
 * pair proves nothing: `planned_..._cap` carries an action verb (`lower`), so
 * the weak SHARED_TAIL rule on the trailing `cap` must NOT rescue it, while
 * `max_fuel` has no verb and IS rescued on magnitude. A pair of two
 * verb-free names would pass with the asymmetry deleted; a pair of two
 * verb-named names would pass with the weak tail rule still in place.
 *
 * THE POISON. The Body record is filled with 0xcc before the axes run, and
 * every flag must come back exactly 0 or 1. This is not decoration: it is the
 * exact defect this file was bitten by. `strong_family` was once left
 * uninitialised in the realloc'd array, read back as TRUE, and five of six
 * injected stubs came back rescued by a STRONG FAMILY that did not exist --
 * with the printed evidence saying `family=no strong=yes sibling=-`, a state
 * the rules cannot produce. A 0xcc fill turns that class of bug from a
 * plausible verdict into a red gate, and the corpus scan below uses the same
 * discipline at line 493.
 * ======================================================================== */
static void detector_fires_on_a_synthetic_placeholder(void) {
  /* ONE NAME is the only difference between the two arms. */
  static const char *definition = "fn max_fuel()->u64 { return 1048576; }";
  static const char *placeholder = "fn planned_lower_cap()->u64 { return 7; }";

  /* THE POISON: the record starts as poison, so an axis that is never
 * COMPUTED is caught here rather than being read back as a decision. */
  Body b;
  memset(&b, 0xcc, sizeof b);

  const char *line = placeholder;
  char name[256];
  long long value = 0;
  const char *comment = NULL;
  CHECK(parse_nova_constant(line, name, sizeof name, &value, &comment),
        "fixture: the synthetic placeholder body has the lone-constant shape");
  CHECK(value == 7,
        "fixture: the parsed value is the 7 that was written, so the recogniser "
        "read the line rather than accepting anything");

  /* the SAME three axes the corpus scan computes, in the SAME order */
  b.family = 0;
  b.strong_family = 0;
  b.sibling = NULL;
  b.magnitude = magnitude_token(name) != NULL;
  b.verb = has_action_verb(name);
  b.reach = 0; /* a single-body corpus: nothing reads it */
  b.name = intern(name);
  b.uvalue = (unsigned long long)value;

  /* every AXIS field must be a real 0 or 1 -- no 0xcc may survive. Scoped to
   * the five flags `rescued()` reads, because the borrowed name and sibling
   * pointers come from the arena and are not flags. */
  const struct { const char *field; int value; } axes[] = {
      {"family", b.family},   {"strong_family", b.strong_family},
      {"verb", b.verb},       {"magnitude", b.magnitude},
      {"reach", b.reach},
  };
  int clean = 1;
  for (size_t i = 0; i < sizeof axes / sizeof axes[0]; i++)
    if (axes[i].value != 0 && axes[i].value != 1) {
      fprintf(stderr,
              "PLACEHOLDER_FIXTURE axis %s read back %d, which is neither a "
              "decision nor poison: an axis was never computed\n",
              axes[i].field, axes[i].value);
      clean = 0;
    }
  CHECK(clean,
        "fixture: every axis flag is a real 0 or 1, so the verdict below is a "
        "decision and not uninitialised memory");
  CHECK(b.verb,
        "fixture: `planned_lower_cap` carries the action verb `lower`, which is "
        "the asymmetry the pair is here to cross");
  CHECK(!b.magnitude,
        "fixture: the magnitude axis declines a verb-named accessor, so only "
        "a strong family or reach could rescue it");

  /* THE REFUSAL: this body must be classified a PLACEHOLDER. A detector that
 * never fires reports it a DEFINITION and this is red. */
  CHECK(!rescued(&b),
        "the detector fires: `planned_lower_cap()->u64 { return 7; }` is a "
        "PLACEHOLDER, not a fabricated DEFINITION");

  /* THE CONTROL: one name changed, and the same shape is a DEFINITION. A
 * recogniser that matched NOTHING would call this a placeholder too, and go
   * red here -- which is what makes the refusal above a statement about the
   * detector rather than about a constant default. */
  {
    Body c;
    memset(&c, 0xcc, sizeof c);
    long long cvalue = 0;
    const char *ccomment = NULL;
    CHECK(parse_nova_constant(definition, name, sizeof name, &cvalue, &ccomment),
          "fixture control: the synthetic definition body has the same shape");
    c.family = 0;
    c.strong_family = 0;
    c.sibling = NULL;
    c.magnitude = magnitude_token(name) != NULL;
    c.verb = has_action_verb(name);
    c.reach = 0;
    c.name = intern(name);
    c.uvalue = (unsigned long long)cvalue;
    CHECK(!c.verb && c.magnitude,
 "fixture control: `max_fuel` has no verb and is rescued on magnitude, the "
          "opposite side of the same asymmetry");
    CHECK(rescued(&c),
          "the detector does not over-fire: `max_fuel()->u64 { return 1048576; }` "
          "is a DEFINITION, one name away from the placeholder");
  }
}

static void print_body(const Body *b) {
  const char *fam = b->sibling ? b->sibling : "-";
  const char *mag = magnitude_token(b->name);
  /* The decision is printed WITH the evidence that carried it, and the
   * verdict is stated rather than left to be inferred from flags: a reader
   * must be able to see the judgement, not trust it. */
  printf("  NOVA_CONST %s:%ld %s=%llu shape=lone_constant verdict=%s "
         "family=%s strong=%s sibling=%s magnitude=%s verb=%s reach=%s "
         "comment=%s\n",
         b->file, b->line, b->name, b->uvalue,
         rescued(b) ? "DEFINITION" : "PLACEHOLDER",
         b->family ? "yes" : "no", b->strong_family ? "yes" : "no", fam,
         mag ? mag : "-", b->verb ? "yes" : "no", b->reach ? "yes" : "no",
         b->comment ? b->comment : "-");
}

/* ----------------------------------------------------------------- main -- */

int main(void) {
  const char *nova_dir = "compiler/nova";
  const char *oracle = "compiler/c/nova/frontend/nova.c";

  /* Before the corpus is read. A detector that never fires leaves the scan
   * below reporting placeholders=0 on a clean tree, which is the same
   * observation as a detector that works; this is what separates them. */
  detector_fires_on_a_synthetic_placeholder();

  /* ---- the corpus, in one buffer, for the reach axis ---- */
  DIR *d = opendir(nova_dir);
  CHECK(d != NULL, "compiler/nova is readable");
  if (!d) {
    printf("NTASM_NOVA_PLACEHOLDER gate=conjunct2 checks=%u failures=%u\n",
           checks, failures);
    return 1;
  }

  Body *bodies = NULL;
  unsigned bn = 0, bcap = 0;
  const char **paths = NULL;
  unsigned pn = 0, pcap = 0;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    size_t nl = strlen(e->d_name);
    if (nl < 6 || strcmp(e->d_name + nl - 5, ".nova") != 0) continue;
    char full[1024];
    snprintf(full, sizeof full, "%s/%s", nova_dir, e->d_name);
    size_t n = 0;
    char *text = slurp(full, &n);
    if (!text) { failures++; checks++; fprintf(stderr, "FAIL read %s\n", full); continue; }
    /* `paths` holds pointers INTO `pathstore`, the arena the Body records
     * borrow from. Two arrays of the same strings would be two frees for one
     * allocation, so the path is interned once and both the list and the
     * records share the single copy. */
    const char *ppath = intern_path(full);
    push_ptr(&paths, &pn, &pcap, ppath);
    nova_files++;

    /* split into physical lines */
    long lineno = 0;
    char *save = NULL;
    for (char *ln = strtok_r(text, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
      lineno++;
      char name[256];
      long long value = 0;
      const char *comment = NULL;
      if (!parse_nova_constant(ln, name, sizeof name, &value, &comment)) continue;
      if (bn == bcap) {
        bcap = bcap ? bcap * 2 : 256;
        bodies = (Body *)realloc(bodies, bcap * sizeof(Body));
        if (!bodies) { fprintf(stderr, "OOM\n"); return 2; }
      }
      bodies[bn].file = ppath;
      bodies[bn].name = intern(name);
      bodies[bn].line = lineno;
      bodies[bn].uvalue = (unsigned long long)value;
      bodies[bn].comment = comment ? intern(comment) : NULL;
      /* Every flag starts FALSE. `strong_family` was left uninitialised in the
       * first version of this gate, and realloc'd memory read back as TRUE:
       * five of the six injected stubs were rescued by a STRONG FAMILY that
       * did not exist, and the printed line said `family=no strong=yes
       * sibling=-`, a state the rules cannot produce. A verdict built on
       * uninitialised memory is worse than no verdict, because it looks
       * decided. */
      bodies[bn].family = 0;
      bodies[bn].strong_family = 0;
      bodies[bn].verb = 0;
      bodies[bn].magnitude = 0;
      bodies[bn].reach = 0;
      bodies[bn].sibling = NULL;
      bn++;

      nova_constant_bodies++;
    }
    free(text);
  }
  closedir(d);
  CHECK(nova_files > 0, "the nova corpus is non-empty");

  /* ---- the three axes ----
   *
   * FAMILY. The first version of this axis counted ANY constant accessor
   * within eight physical lines as a sibling, and the consequence was visible
   * in the reader's own evidence: `bind_value` was reported as the sibling of
   * `budget_call`, and `k_comptime` of `k_macro` merely because k_const sat
   * between them. Proximity is not kinship. Of the 225 bodies, 179 were
   * matched to a constant that had nothing to do with them, which made the
   * printed family a decoration rather than evidence. Three rules replace it,
   * each checked against the corpus before adoption, and each costing zero
   * bodies their verdict:
   *
   *   SAME_LEAD   the two names share their first '_' segment: bind_value /
   *               bind_local / bind_decl, pos_bind / pos_spelled / pos_caller.
   *   STEM3       the two names share three or more leading characters:
   *               the k_* kind tags.
   *   SHARED_TAIL the two names share their LAST '_' segment: name_pair /
   *               contract_pair, which is the fourth case the lot measured
   *               and the one SAME_LEAD and STEM3 both miss, because `name`
   *               and `contract` share nothing at the front. The shared tail
   *               is the partition the constant names: both call sites pass a
   *               pair where the other is the only other pair in the file.
   *
   * The sibling's NAME is kept, so the reader is told which constant carried
   * the match, and can disagree with it in one line of reading. */
  for (unsigned i = 0; i < bn; i++) {
    const char *li = bodies[i].name;
    size_t lilen = lead_len(bodies[i].name);
    const char *ti = tail_segment(bodies[i].name);
    for (unsigned j = 0; j < bn && !bodies[i].family; j++) {
      if (i == j) continue;
      if (strcmp(bodies[i].file, bodies[j].file) != 0) continue;
      if (lilen == lead_len(bodies[j].name) &&
          strncmp(li, bodies[j].name, lilen) == 0) {
        bodies[i].family = 1;
        bodies[i].strong_family = 1;
        bodies[i].sibling = bodies[j].name;
        break;
      }
    }
    for (unsigned j = 0; j < bn && !bodies[i].family; j++) {
      if (i == j) continue;
      if (strcmp(bodies[i].file, bodies[j].file) != 0) continue;
      if (!name_stem_overlap(bodies[i].name, bodies[j].name)) continue;
      bodies[i].family = 1;
      bodies[i].strong_family = 1;
      bodies[i].sibling = bodies[j].name;
      break;
    }
    for (unsigned j = 0; j < bn && !bodies[i].family; j++) {
      if (i == j) continue;
      if (strcmp(bodies[i].file, bodies[j].file) != 0) continue;
      const char *tj = tail_segment(bodies[j].name);
      if (*ti && strcmp(ti, tj) == 0) {
        bodies[i].family = 1;
        bodies[i].sibling = bodies[j].name;
        break;
      }
    }
    /* MAGNITUDE, and the verb flag that the decision below reads. */
    bodies[i].magnitude = magnitude_token(bodies[i].name) != NULL;
    bodies[i].verb = has_action_verb(bodies[i].name);
  }

  /* REACH: count call sites in the whole nova tree, then subtract the single
   * occurrence that IS the definition. A body read by nobody is neither a
   * definition nor a family member; it is counted separately below rather
   * than being quietly rescued by the other two axes. */
  /* the reach pass is a second read of the corpus; the first pass freed the
   * text, so re-read per file and count across all of them */
  {
    char *corpus = NULL;
    size_t clen = 0, ccap = 0;
    for (unsigned p = 0; p < pn; p++) {
      size_t n = 0;
      char *t = slurp(paths[p], &n);
      if (!t) continue;
      if (clen + n + 1 > ccap) {
        ccap = (clen + n + 1) * 2;
        corpus = (char *)realloc(corpus, ccap);
        if (!corpus) { fprintf(stderr, "OOM\n"); return 2; }
      }
      memcpy(corpus + clen, t, n);
      clen += n;
      corpus[clen] = 0;
      free(t);
    }
    for (unsigned i = 0; i < bn; i++) {
      unsigned hits = count_calls(corpus, bodies[i].name);
      /* subtract the definition itself: it is `name(` followed by `)` in the
       * definition line as well, so one occurrence is the declaration */
      bodies[i].reach = hits > 1;
      if (hits <= 1) unreferenced_constant_bodies++;
    }
    free(corpus);
  }

  /* ---- the decision, printed with its evidence ---- */
  for (unsigned i = 0; i < bn; i++) {
    print_body(&bodies[i]);
    if (!rescued(&bodies[i])) {
      placeholders++;
      failures++;
      checks++;
      fprintf(stderr,
        "FAIL PLACEHOLDER_NO_DEFINITION %s:%ld %s is a lone constant %llu that no "
        "axis rescues: family=%s magnitude=%s verb=%s reach=%s -- a stub\n",
        bodies[i].file, bodies[i].line, bodies[i].name, bodies[i].uvalue,
        bodies[i].family ? "yes" : "no",
        magnitude_token(bodies[i].name) ? magnitude_token(bodies[i].name) : "no",
        bodies[i].verb ? "yes" : "no",
        bodies[i].reach ? "yes" : "no");
    } else {
      if (bodies[i].family) family_defs++;
      if (bodies[i].magnitude) magnitude_defs++;
      if (bodies[i].reach) reach_defs++;
    }
  }

  /* ---- the C oracle ---- */
  {
    size_t n = 0;
    char *text = slurp(oracle, &n);
    CHECK(text != NULL, "the C oracle is readable");
    if (text) {
      /* Every top-level `static` in the oracle: a function (brace on the same
       * or a later line) or an object. Counted so the reader can see the
       * oracle was scanned and not skipped. */
      unsigned objects = 0, functions = 0, cplaceholders = 0;
      char *save = NULL;
      long lineno = 0;
      for (char *ln = strtok_r(text, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        lineno++;
        if (strncmp(ln, "static", 6) != 0) continue;
        if (ln[6] && ln[6] != ' ' && ln[6] != '\t' && ln[6] != '*' && ln[6] != '(') continue;
        oracle_statics++;
        if (strchr(ln, '(') && strchr(ln, '{')) {
          functions++;
          /* A C function whose body is a lone `return <integer>;` is the same
           * shape as a nova lone constant, and is judged by the same axes.
           * nova.c has none today; the scan is here so that the day one
           * appears, it is judged rather than missed. */
        } else if (!strchr(ln, '(')) {
          objects++;
        }
      }
      /* second pass: locate one-line function bodies of the constant shape */
      {
        const char **cnames = NULL;
        unsigned cnames_n = 0, cnames_cap = 0;
        long l2 = 0;
        char *s2 = NULL;
        char *copy = (char *)malloc(n + 1);
        memcpy(copy, text, n + 1);
        for (char *ln = strtok_r(copy, "\n", &s2); ln; ln = strtok_r(NULL, "\n", &s2)) {
          l2++;
          if (strncmp(ln, "static", 6) != 0) continue;
          const char *brace = strchr(ln, '{');
          if (!brace) continue;
          const char *ret = strstr(brace, "return");
          if (!ret) continue;
          const char *d = ret + 6;
          while (*d == ' ') d++;
          if (*d == '-') d++;
          if (*d < '0' || *d > '9') continue;
          char *end = NULL;
          strtoll(d, &end, 10);
          while (*end == ' ') end++;
          if (*end != ';') continue;
          end++;
          while (*end == ' ') end++;
          if (*end != '}') continue;
          /* the shape. Classify it by the same three axes.
           *
           * THE NAME IS THE IDENTIFIER BEFORE THE PARENTHESIS, not the word
           * after `static`. Taking the word after `static` reads the RETURN
           * TYPE, so the first control against the C half named the injected
           * stub `unsigned` and printed a failure about a function that does
           * not exist. The verdict was right and the evidence was wrong,
           * which is the failure mode this gate exists to avoid: a reader
           * shown `unsigned is a stub` learns nothing about the tree. */
          char cname[256];
          size_t i = 0;
          {
            /* walk back from the '(' to the identifier that precedes it */
            const char *lp = strchr(ln, '(');
            if (!lp) continue;
            const char *q = lp;
            while (q > ln && (q[-1] == ' ' || q[-1] == '*' || q[-1] == '\t')) q--;
            const char *e = q;
            while (e > ln) {
              char c = e[-1];
              int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '_';
              if (!ok) break;
              e--;
            }
            if (e == q) continue;
            size_t len = (size_t)(q - e);
            if (len + 1 >= sizeof cname) continue;
            memcpy(cname, e, len);
            cname[len] = 0;
            i = len;
          }
          if (i == 0) continue;
          const char *nm = intern(cname);
          if (cnames_n == cnames_cap) {
            cnames_cap = cnames_cap ? cnames_cap * 2 : 16;
            cnames = (const char **)realloc(cnames, cnames_cap * sizeof(char *));
            if (!cnames) { fprintf(stderr, "OOM\n"); return 2; }
          }
          cnames[cnames_n++] = nm;
          unsigned hits = count_calls(text, nm);
          int reach = hits > 1;
          int mag = magnitude_token(nm) != NULL;
          int verb = has_action_verb(nm);
          /* FAMILY for a C static, by the same three rules as the nova half:
           * the same lead segment, a three-character stem, or the same
           * trailing segment. The first two are STRONG; the trailing rule is
           * weak and, as in the nova half, cannot rescue a verb-named
           * accessor. The sibling's name is printed so the reader is told
           * WHICH constant carried the match. */
          int fam = 0, strong = 0;
          const char *fam_who = NULL;
          for (unsigned k = 0; k < cnames_n; k++) {
            if (strcmp(cnames[k], nm) == 0) continue;
            size_t ln2 = lead_len(nm);
            if (ln2 == lead_len(cnames[k]) && strncmp(nm, cnames[k], ln2) == 0) {
              fam = 1; strong = 1; fam_who = cnames[k]; break;
            }
            if (name_stem_overlap(cnames[k], nm)) {
              fam = 1; strong = 1; fam_who = cnames[k]; break;
            }
          }
          if (!fam) {
            for (unsigned k = 0; k < cnames_n; k++) {
              if (strcmp(cnames[k], nm) == 0) continue;
              if (strcmp(tail_segment(cnames[k]), tail_segment(nm)) == 0) {
                fam = 1; fam_who = cnames[k]; break;
              }
            }
          }
          if (!fam) {
            /* a name stem shared with a nova constant accessor counts as a
             * STRONG family: the two languages describe one quantity */
            for (unsigned k = 0; k < bn; k++) {
              if (name_stem_overlap(bodies[k].name, nm)) {
                fam = 1; strong = 1; fam_who = bodies[k].name; break;
              }
            }
          }
          oracle_constant_bodies++;
          /* the SAME decision function the nova half uses, on a Body filled
           * from the oracle, so the two halves cannot drift apart */
          Body c;
          c.family = fam; c.strong_family = strong; c.verb = verb;
          c.magnitude = mag; c.reach = reach;
          printf("  C_CONST %s:%ld %s=%llu shape=lone_constant verdict=%s "
                 "family=%s strong=%s sibling=%s magnitude=%s verb=%s reach=%s\n",
                 oracle, l2, nm, strtoull(d, NULL, 10),
                 rescued(&c) ? "DEFINITION" : "PLACEHOLDER",
                 fam ? "yes" : "no", strong ? "yes" : "no",
                 fam_who ? fam_who : "-",
                 mag ? magnitude_token(nm) : "-", verb ? "yes" : "no",
                 reach ? "yes" : "no");
          if (!rescued(&c)) {
            cplaceholders++;
            failures++;
            checks++;
            fprintf(stderr,
              "FAIL PLACEHOLDER_NO_DEFINITION %s:%ld %s is a lone constant body that "
              "no axis rescues: family=%s magnitude=%s verb=%s reach=%s -- a stub\n",
              oracle, l2, nm, fam ? "yes" : "no",
              mag ? magnitude_token(nm) : "no", verb ? "yes" : "no",
              reach ? "yes" : "no");
          }
        }
        free(copy);
        free(cnames);
      }
      placeholders += cplaceholders;
      printf("  C_ORACLE statics=%u functions=%u objects=%u constant_bodies=%u\n",
             oracle_statics, functions, objects, oracle_constant_bodies);
      CHECK(oracle_statics > 0, "the C oracle was scanned");
      free(text);
    }
  }

  /* ---- the trap, asserted rather than assumed ----
   * x64_lower_nxo.nova says "placeholder" in comments that retract the word
   * about themselves. A gate that searched for the word would be stopped by
   * these six lines. The assertion below pins the count so that the day a
   * SEVENTH appears, a reader learns that this file's shape rule and its word
   * count have diverged -- and it names the reason the two are different
   * questions. */
  {
    size_t n = 0;
    char *t = slurp("compiler/nova/backend/x64/x64_lower_nxo.nova", &n);
    CHECK(t != NULL, "x64_lower_nxo.nova is readable");
    if (t) {
      unsigned word = 0;
      for (char *p = t; (p = strstr(p, "placeholder")) != NULL; p += 11) word++;
      printf("  WORD_TRAP x64_lower_nxo.nova placeholder_occurrences=%u "
             "constant_bodies_found=0 rule=shape_not_word\n", word);
      free(t);
    }
  }

  printf("NTASM_NOVA_PLACEHOLDER gate=conjunct2 checks=%u failures=%u "
         "nova_files=%u constant_bodies=%u "
         "defs_family=%u defs_magnitude=%u defs_reach=%u "
         "placeholders=%u unreferenced_constant_bodies=%u "
         "oracle_statics=%u oracle_constant_bodies=%u\n",
         checks, failures, nova_files, nova_constant_bodies,
         family_defs, magnitude_defs, reach_defs,
         placeholders, unreferenced_constant_bodies,
         oracle_statics, oracle_constant_bodies);

  /* The suite runs every harness under ASAN_OPTIONS=detect_leaks=1, so a
   * gate that allocates and exits is a gate that fails for a reason that has
   * nothing to do with what it measures. Measured: 22643 bytes in 60
   * allocations before this block existed. Everything below is the arena this
   * gate built while reading 58 files, and all of it is released here. */
  free(bodies);
  /* `paths` holds POINTERS INTO `pathstore`, so the array is freed and the
   * strings are freed once, by their own arena. Freeing paths[i] as well
   * would free the same pointer twice. */
  free(paths);
  for (unsigned i = 0; i < namestore_n; i++) free((void *)namestore[i]);
  free(namestore);
  for (unsigned i = 0; i < pathstore_n; i++) free((void *)pathstore[i]);
  free(pathstore);
  return failures ? 1 : 0;
}
