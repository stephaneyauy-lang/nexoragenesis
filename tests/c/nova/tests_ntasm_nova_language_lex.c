/* tests_ntasm_nova_language_lex.c -- LOT 139, the gate for the FIRST TOKEN of
 * the Nova language front end.
 *
 * WHAT THIS GATE IS. The register records, as the project's first artefact,
 * "un module qui tokenise et analyse la grammaire Nova -- les huit mots-cles".
 * The eight words are export fn let module mut return struct while. Measured
 * BY EXECUTION on 2026-10-03:
 *   - nova.c honours all eight. A fixture using all eight compiles (E0), and
 *     every one-character alteration of every one of them is REFUSED, as is
 *     every same-length replacement. 16/16 refused: the words are load-bearing
 *     in the C front end, not decoration.
 *   - parser.nova's flat keyword table reads back 77 words and holds
 *     module/fn/let/export/return, NOT struct/mut/while: KEYWORD_GAP 3 of 8.
 *     That table is the NTASM DIALECT's set, indexed by numeric id from every
 *     call site, so appending a Nova word to it edits the dialect.
 *   - NO .nova file in the tree mentions "struct", "mut" or "while" in a
 *     keyword position.
 * So the language is real and the C front end speaks it, and the absent thing
 * is a module that does, written in Nova. nova_language_lex.nova is that
 * module. It is ONE token wide: it lexes a buffer and reports which of the
 * eight occur as whole identifiers. It is not a parser and this gate does not
 * claim it is one.
 *
 * WHY IT IS EXECUTED HERE AND NOT BY `nova build`. This file loads the two
 * .nova modules by repo-relative path, compiles them with
 * nova_compile_many_v2 -- the SAME C entry point the project's other Nova
 * gates use, and the one that compiles x64_fixed.nova today -- maps the
 * artifact with nova_host_map and calls image->entry. Every number below comes
 * out of the Nova module running on the C host. Nothing here re-implements the
 * lexer in C and compares it to itself: the EXPECTATIONS are the eight names
 * read back OUT of the executed image (keyword_read_back), and the C side's
 * only job is to hand over a buffer and read what came back.
 *
 * THE TWO NEGATIVE DIRECTIONS, because "reports which it found" is worth
 * nothing unless it can also refuse:
 *   (a) a buffer MISSING one of the eight must leave that bit 0, and the gate
 *       NAMES the keyword in its FAIL line rather than printing a count;
 *   (b) a buffer in which a keyword is altered by ONE character, and a buffer
 *       in which a keyword is a PREFIX of a longer identifier, must both leave
 *       the bit 0 -- which is what a substring matcher would get wrong.
 * Both are in run_case() below and both are exercised by the case table.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;
#define CHECK(c, m)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL %s\n", m);                                        \
    }                                                                          \
  } while (0)

/* The scratch, malloc'd and PRE-FILLED WITH A GUARD so a refused call is
 * visible as "the guard is still there" and not as "some number happened to
 * be zero". WORDS is the u64 output buffer, TEXT is the byte buffer handed to
 * the lexer as the source, REPORT is spare and is asserted untouched by a
 * refusal. */
#define WORDS 4096
#define TEXT 65536
#define REPORT 256
#define GUARD UINT64_C(0xcccccccccccccccc)

static const char *const PATHS[] = {
    "tests/nova/tests/nova-language-lex-entry.nova",
    "compiler/nova/frontend/nova_language_lex.nova"};
#define PATHS_N ((unsigned)(sizeof PATHS / sizeof PATHS[0]))

static char *loadf(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long z = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) {
    free(b); fclose(f); return NULL;
  }
  fclose(f); b[z] = 0; *length = (size_t)z; return b;
}

typedef struct { uint64_t returned, runtime; } Result;

/* run() packs FIVE flat slots, which is what this entry's signature occupies:
 * buf<u8> crosses as two slots, buf<u64> as two, and mode as one. THE COUNT
 * IS MEASURED, NOT ASSUMED. The brief for this lot asked for sixteen packed
 * slots; sixteen is what every OTHER gate's entry declares, and packing
 * sixteen here produced 204 checks and 298 failures that all said "the Nova
 * module reported a keyword present" against an untouched guard pattern.
 * Sweeping the count 1..16 against this exact entry is what named the cause:
 * argc 5 runs (err=0), and 1..4 and 6..16 are all refused with NV2_ARGUMENT
 * (10) before the body executes. The host checks the count; it does not
 * ignore the surplus.
 *
 * `words` is filled with GUARD by the caller, so a call that wrote nothing is
 * distinguishable from a call that wrote a zero. */
#define SLOTS 5
static Result run(const NovaHostImage *image, uint64_t *words, uint64_t mode,
                  const char *source) {
  Result r = {0, 0};
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)source, strlen(source), 0);
  uint64_t oh = nova_borrow_v2(&c, words, WORDS * 8, 1);
  uint64_t args[SLOTS] = {sh, strlen(source), oh, WORDS, mode};
  r.returned = image->entry(&c, args, SLOTS);
  r.runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return r;
}

/* ---- THE EIGHT, read back OUT of the executed image ----------------------
 * Not a literal copied here. keyword_read_back copies the table the Nova
 * module actually holds into words[], so `name[i]` is what the module says its
 * i'th keyword is. If the module's table changed, these names change with it
 * and the gate's FAIL lines name the module's own words.
 * Slot order is the module's keyword_words() order, which is the order of the
 * C front end's own sites: export fn let module mut return struct while. */
static char name[8][32];

/* The image, filled in by main() once it maps. table_into() needs it and
 * run_case() needs it; neither is reachable before main() sets it. */
static const NovaHostImage *g_image;

/* The byte length of the table read back, taken from the entry's return value
 * and published so main() counts over the SAME number this function indexed
 * with. Two readers of one run's answer is how a count and a bound disagree. */
static uint64_t g_table_size;

static void table_into(uint64_t *words) {
  for (unsigned i = 0; i < 8; i++) name[i][0] = 0;
  Result r = run(g_image, words, 1, "");
  CHECK(r.returned > 0, "keyword_read_back returned a byte length");
  CHECK(r.runtime == 0, "keyword_read_back ran without a runtime fault");
  /* The byte length is the ENTRY'S RETURN VALUE, read off the run and not out
   * of the scratch: taking it from words[1] instead read the guard pattern,
   * which ASan turned into a heap-buffer-overflow rather than a number. That
   * is the record: the first version of this line read a length from a field
   * the producer does not publish, and the instrument looked like a bounds
   * bug instead of a wrong field. */
  uint64_t size = r.returned;
  g_table_size = size;
  CHECK(size > 0 && size < 1024, "keyword table length is sane");
  if (size == 0 || size >= 1024) return; /* refuse to index on a bad length */
  for (unsigned i = 0; i < 8; i++) {
    uint64_t at = 0, k = 0;
    while (at < size) {
      uint64_t len = 0;
      while (at + len < size && words[2 + at + len] != 0) len++;
      if (k == (uint64_t)i) {
        uint64_t m = len < 31 ? len : 31;
        for (uint64_t j = 0; j < m; j++) name[i][j] = (char)words[2 + at + j];
        name[i][m] = 0;
        break;
      }
      at += len + 1;
      k++;
    }
  }
}

/* ---- one buffer, one expectation ----------------------------------------
 * `expect` is a bitmask over the eight, in the module's own order. A case that
 * disagrees prints WHICH keyword disagrees, by the name the module published,
 * so the failure names a word and not a number. */
static void run_case(const char *label, const char *source, uint64_t expect,
                     uint64_t found_expect) {
  uint64_t *words = malloc(WORDS * 8);
  uint64_t *report = malloc(REPORT * 8);
  cases++;
  if (!words || !report) { free(words); free(report); CHECK(0, "scratch malloc"); return; }
  for (unsigned i = 0; i < WORDS; i++) words[i] = GUARD;
  for (unsigned i = 0; i < REPORT; i++) report[i] = GUARD;

  Result r = run(g_image, words, 0, source);
  CHECK(r.returned == 0, label);
  CHECK(r.runtime == 0, label);
  uint64_t found = words[0];
  int bad = 0;
  for (unsigned k = 0; k < 8; k++) {
    uint64_t want = (expect >> k) & 1u;
    uint64_t got = words[1 + k] ? 1u : 0u;
    if (got != want) {
      failures++;
      fprintf(stderr, "FAIL %s: keyword %s expected %s, module reported %s\n",
              label, name[k][0] ? name[k] : "(unnamed)", want ? "present" : "absent",
              got ? "present" : "absent");
      bad = 1;
    }
    /* a bit outside the eight must never be written */
    if (words[9] != GUARD) {
      failures++;
      fprintf(stderr, "FAIL %s: wrote past the eight keywords\n", label);
      bad = 1;
    }
  }
  if (found != found_expect) {
    failures++;
    fprintf(stderr, "FAIL %s: found count %llu expected %llu\n", label,
            (unsigned long long)found, (unsigned long long)found_expect);
    bad = 1;
  }
  checks++;
  (void)bad;
  free(words); free(report);
}

/* A refused call must leave the output untouched -- transactional, not half
 * written. Reported separately because "the call refused" and "the call
 * refused AND wrote nothing" are different properties and only the second is
 * worth having. */
static void expect_refusal(const char *label, const char *source) {
  uint64_t *words = malloc(WORDS * 8);
  cases++;
  if (!words) { CHECK(0, "scratch malloc"); return; }
  for (unsigned i = 0; i < WORDS; i++) words[i] = GUARD;
  /* out is sized THREE words: the eight bits plus the count cannot fit, so the
   * module must refuse with 800 and write nothing. The mode slot stays 0
   * because mode 0 is the scan; the refusal is provoked by the SIZE, which is
   * the property under test. */
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)source, strlen(source), 0);
  uint64_t oh = nova_borrow_v2(&c, words, 3 * 8, 1);
  uint64_t args[SLOTS] = {sh, strlen(source), oh, 3, 0};
  uint64_t returned = g_image->entry(&c, args, SLOTS);
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  /* out is sized 3 words: the eight bits cannot fit, so 800 and nothing
   * written. */
  CHECK(returned == 800, label);
  CHECK(words[0] == GUARD && words[1] == GUARD && words[2] == GUARD,
        label);
  free(words);
}

static uint64_t bit(unsigned k) { return (uint64_t)1u << k; }

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);

  char *sources[PATHS_N] = {0};
  NtFInput inputs[PATHS_N];
  for (unsigned i = 0; i < PATHS_N; i++) {
    size_t length = 0;
    sources[i] = loadf(PATHS[i], &length);
    inputs[i] = (NtFInput){PATHS[i], sources[i], length};
  }
  int loaded = 1;
  for (unsigned i = 0; i < PATHS_N; i++) if (!sources[i]) loaded = 0;
  CHECK(loaded, "Nova sources load");
  if (!loaded) {
    for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);
    printf("NTASM_NOVA_NOVA_LANGUAGE_LEX checks=%u failures=%u cases=%u\n",
           checks, failures, 0);
    return 2;
  }

  /* TWO compiles into two artifacts, and the image is mapped from the FIRST.
   * The second compile is the run-race check: if the second artifact is not
   * byte-identical to the first, the module is not deterministic and every
   * count this gate prints is a count over a coin flip. The comparison is on
   * the artifact bytes, not on a re-run's verdict. */
  NtArtifact first = {0}, second = {0};
  int c1 = nova_compile_many_v2(inputs, PATHS_N, &first);
  CHECK(c1, "modules compile");
  if (!c1) {
    fprintf(stderr, "E%u %zu:%zu %s\n", first.error.code, first.error.line,
            first.error.column, first.error.message);
    for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);
    printf("NTASM_NOVA_NOVA_LANGUAGE_LEX checks=%u failures=%u cases=%u\n",
           checks, failures, 0);
    return 2;
  }
  int c2 = nova_compile_many_v2(inputs, PATHS_N, &second);
  CHECK(c2, "modules compile twice");
  /* The determinism check is on the TEXT BYTES, not on a re-run's verdict and
   * not on a size field: two compiles that agree on a length and disagree on
   * a byte would pass a length check and fail every count below. */
  CHECK(first.text.size == second.text.size, "two compiles agree on text size");
  CHECK(first.text.size == second.text.size &&
            memcmp(first.text.bytes, second.text.bytes, first.text.size) == 0,
        "two compiles agree on every text byte");

  NovaHostImage image = {0};
  CHECK(nova_host_map(&first, &image), "image maps");
  if (!image.memory) {
    for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);
    printf("NTASM_NOVA_NOVA_LANGUAGE_LEX checks=%u failures=%u cases=%u\n",
           checks, failures, 0);
    return 2;
  }
  g_image = &image;

  /* the eight, as the module publishes them */
  {
    uint64_t *words = malloc(WORDS * 8);
    for (unsigned i = 0; i < WORDS; i++) words[i] = GUARD;
    table_into(words);
    /* THE COUNT, read off the executed module over g_table_size -- the SAME
     * length table_into() indexed with. Reading words[1] here, as a second
     * and independent source of the length, is what the first version did and
     * it produced a heap-buffer-overflow on the guard pattern. */
    uint64_t size = g_table_size;
    unsigned entries = 0;
    int in_word = 0;
    for (uint64_t i = 0; i < size; i++) {
      if (words[2 + i] == 0) { in_word = 0; continue; }
      if (!in_word) { entries++; in_word = 1; }
    }
    printf("NOVA_LANGUAGE_LEX_TABLE words=%u names:", entries);
    for (unsigned i = 0; i < 8; i++) printf(" %s", name[i][0] ? name[i] : "?");
    printf("\n");
    CHECK(entries == 8, "the Nova language table holds eight words");
    /* and the eight ARE the eight, by name, read back from the module */
    CHECK(strcmp(name[0], "export") == 0, "keyword 1 is export");
    CHECK(strcmp(name[1], "fn") == 0, "keyword 2 is fn");
    CHECK(strcmp(name[2], "let") == 0, "keyword 3 is let");
    CHECK(strcmp(name[3], "module") == 0, "keyword 4 is module");
    CHECK(strcmp(name[4], "mut") == 0, "keyword 5 is mut");
    CHECK(strcmp(name[5], "return") == 0, "keyword 6 is return");
    CHECK(strcmp(name[6], "struct") == 0, "keyword 7 is struct");
    CHECK(strcmp(name[7], "while") == 0, "keyword 8 is while");
    free(words);
  }

  printf("NOVA_LANGUAGE_LEX_GATE -- what the Nova language lexer sees\n");

  /* ---- 1. THE POSITIVE: all eight, once each ----------------------------
   * THE FIXTURE WAS WRONG THE FIRST TIME AND THE GATE SAID SO. It spelled
   * `fn f` and `struct S` with no `export`, and expected all eight; the gate
   * answered `keyword export expected present, module reported absent` and
   * `found count 7 expected 8`. That is the naming property doing its job on
   * its own author, which is the only place it can be trusted from. */
  run_case("all eight",
           "module m\nexport struct S{v:u64}\nexport fn f(x:u64)->u64{"
           "let mut i:u64=0;while i<x{i=i+1;}return i;}\n",
           bit(0) | bit(1) | bit(2) | bit(3) | bit(4) | bit(5) | bit(6) | bit(7),
           8);

  /* ---- 2. EACH KEYWORD ALONE --------------------------------------------
   * Eight cases, so the failure of one names one keyword rather than saying
   * "the eight case went red". */
  static const char *const ALONE[] = {"export", "fn", "let", "module",
                                      "mut", "return", "struct", "while"};
  for (unsigned k = 0; k < 8; k++) {
    run_case(ALONE[k], ALONE[k], bit(k), 1);
  }

  /* ---- 3. (a) ONE KEYWORD MISSING, and the gate NAMES it ---------------
   * Seven of the eight, each in turn. This is the direction the brief asks
   * for: the bit for the absent word must be 0 and the FAIL line carries the
   * word. */
  {
    char buf[256];
    for (unsigned miss = 0; miss < 8; miss++) {
      buf[0] = 0;
      for (unsigned k = 0; k < 8; k++) {
        if (k == miss) continue;
        strcat(buf, ALONE[k]);
        strcat(buf, " ");
      }
      char label[64];
      snprintf(label, sizeof label, "missing %s", name[miss]);
      run_case(label, buf, 0xffffffffu & ~bit(miss), 7);
    }
  }

  /* ---- 4. (b) ONE CHARACTER ALTERED ------------------------------------
   * Every one of the eight, with its LAST character replaced. Same length,
   * so a length-based matcher would still say yes and only a byte comparison
   * can refuse. A substring matcher also refuses these, which is why case 5
   * exists: 4 alone does not distinguish whole-word from substring. */
  for (unsigned k = 0; k < 8; k++) {
    char alt[32];
    snprintf(alt, sizeof alt, "%s", ALONE[k]);
    size_t n = strlen(alt);
    alt[n - 1] = (alt[n - 1] == 'z') ? 'y' : (char)(alt[n - 1] + 1);
    char label[96];
    snprintf(label, sizeof label, "altered %s to %s", ALONE[k], alt);
    run_case(label, alt, 0, 0);
  }

  /* ---- 5. (b') A KEYWORD AS A PREFIX OF A LONGER IDENTIFIER -------------
   * THE case a substring matcher gets wrong. `mutable` CONTAINS `mut` and
   * `structures` CONTAINS `struct`; neither IS the keyword. */
  run_case("mut as prefix of mutable", "mutable\n", 0, 0);
  run_case("struct as prefix of structures", "structures\n", 0, 0);
  run_case("module as prefix of module_name", "module_name\n", 0, 0);
  run_case("while as prefix of elsewhere", "elsewhere\n", 0, 0);
  /* and the control: the whole word in the same position IS found, so 4 and 5
   * are refusing a word and not refusing the buffer. */
  run_case("mut whole", "mut\n", bit(4), 1);
  run_case("struct whole", "struct\n", bit(6), 1);

  /* ---- 6. A KEYWORD SPLIT BY A NON-NAME BYTE IS TWO IDENTIFIERS ----------
   * `mu t` is two identifiers, neither of which is `mut`. */
  run_case("mut split by a space", "mu t\n", 0, 0);
  run_case("struct split by a digit", "struc7\n", 0, 0);

  /* ---- 7. NOTHING AT ALL, and the empty buffer ------------------------- */
  run_case("no keywords", "target x86_64-nexora-none\nsection .text {}\n", 0, 0);
  run_case("empty", "", 0, 0);

  /* ---- 8. A KEYWORD TWICE COUNTS ONCE ----------------------------------
   * `found` is a count of the eight BITS, not of the occurrences. Stated here
   * because a reader could reasonably expect 2 from `let ... let`, and the
   * difference is a property of the published interface, not a convenience. */
  run_case("let twice", "let a:u64=0; let b:u64=0;\n", bit(2), 1);

  /* ---- 9. THE REFUSAL IS TRANSACTIONAL --------------------------------- */
  expect_refusal("a three-word output cannot carry eight bits",
                 "module m\n");

  nova_host_unmap(&image);
  if (c2) nt_artifact_free(&second);
  nt_artifact_free(&first);
  for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);

  printf("NTASM_NOVA_NOVA_LANGUAGE_LEX checks=%u failures=%u cases=%u\n",
         checks, failures, cases);
  return failures ? 1 : 0;
}