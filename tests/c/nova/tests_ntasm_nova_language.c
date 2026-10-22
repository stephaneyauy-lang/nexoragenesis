/* Lot 122 -- THE RED THAT NAMES THE MISSING MODULE.
 *
 * WHAT THIS FILE IS. A gate over four Nova-language source fixtures. It
 * asserts, for each, exactly what a Nova FRONT END would do with it: accept
 * it. Today the only parser reachable from this bootstrap is the NTASM
 * dialect parser, compiler/nova/frontend/parser.nova, and it refuses all four.
 * That refusal is the deliverable. It is not a bug in this gate and it is not
 * a typo in a fixture: the C front end in compiler/c/nova/frontend/nova.c
 * compiles all four without complaint, so what parser.nova is refusing is the
 * LANGUAGE, not the spelling.
 *
 * WHY FOUR FIXTURES AND NOT ONE. Each isolates a different demand on a future
 * front end, so the day one of them goes green the diff names what landed:
 *   struct                     a record declaration, absent from NTASM wholly
 *   mut                        a writable binding, absent from NTASM wholly
 *   eight-keywords             all eight at once, so a one-word table edit
 *                              cannot turn this green
 *   struct-mut-typed-let       record type as a `let` annotation, a record
 *                              initializer and a field write
 *
 * WHY THE CONTROL AT THE BOTTOM IS NOT OPTIONAL. A gate that cannot go green
 * is not a gate, and a gate that goes green the moment somebody appends two
 * words to a table is worse than no gate. The control is an NTASM fixture
 * driven through the SAME image and the SAME assertion as the four Nova ones.
 * It passes today. So the green path of this harness is a real, walked path,
 * and the four reds are the language refusing them and nothing else.
 *
 * WHAT THIS FILE DELIBERATELY DOES NOT DO. It does not add `struct` or `mut`
 * to parser.nova's keyword table, and it does not widen a bound, relax an
 * assertion or special-case a fixture name to make the red go away. The red
 * is the artefact. A green here means a Nova front end exists.
 */
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;

typedef struct {
  uint64_t *words;
  size_t word_count;
  uint64_t returned, runtime_error;
} Parsed;

static char *load(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *data = size >= 0 ? (char *)malloc((size_t)size + 1) : NULL;
  if (!data || fread(data, 1, (size_t)size, f) != (size_t)size) {
    free(data);
    fclose(f);
    return NULL;
  }
  fclose(f);
  data[size] = 0;
  *length = (size_t)size;
  return data;
}

/* `floor` is the output-buffer the CALLER needs, in words. It exists because
 * the empty-source keyword read-back is not sized like a parse: it hands back
 * the whole NUL-separated table one byte per word and refuses anything under
 * 1024 (parser-entry.nova:10). Sizing that call from the source length, which
 * is zero, silently yields a 394-word buffer and a 902. */
static Parsed parse_floored(const NovaHostImage *image, const char *source,
                            size_t length, size_t floor) {
  Parsed result = {0};
  size_t needed = 10 + (length * 2 + 32) * 12;
  result.word_count = needed > floor ? needed : floor;
  result.words = (uint64_t *)calloc(result.word_count, sizeof(uint64_t));
  NovaContextV2 context;
  if (!result.words || !nova_context_init_v2(&context)) {
    result.runtime_error = UINT64_MAX;
    return result;
  }
  uint64_t source_handle =
      nova_borrow_v2(&context, (void *)source, (uint64_t)length, 0);
  uint64_t output_handle = nova_borrow_v2(
      &context, result.words,
      (uint64_t)(result.word_count * sizeof(*result.words)), 1);
  uint64_t args[] = {source_handle, length, output_handle, result.word_count};
  result.returned = image->entry(&context, args, 4);
  result.runtime_error = context.error;
  nova_context_destroy_v2(&context);
  return result;
}

/* An accept is not merely "no error": the entry returns 0, the tree says ok,
 * and every node's span lies inside the source it came from. A harness that
 * called "did not crash" an accept would be the tautology this gate must not
 * be. */
static int ast_well_formed(const Parsed *parsed, size_t source_length) {
  if (!parsed->words || !parsed->words[0] || parsed->words[9] == 0)
    return 0;
  uint64_t count = parsed->words[9];
  for (uint64_t id = 1; id <= count; id++) {
    const uint64_t *node = parsed->words + 10 + (id - 1) * 12;
    if (!node[0] || node[6] > node[7] || node[7] > source_length ||
        node[8] > count || node[9] > count || node[10] > count)
      return 0;
  }
  return parsed->words[10] == 1;
}

static int accepted(const Parsed *parsed, size_t source_length) {
  return !parsed->runtime_error && parsed->returned == 0 && parsed->words &&
         ast_well_formed(parsed, source_length);
}

/* The one assertion, applied identically to Nova fixtures and to the NTASM
 * control. The only difference between the two callers is the file. */
static void expect_accepted(const NovaHostImage *image, const char *label,
                            const char *path) {
  size_t length = 0;
  char *text = load(path, &length);
  if (!text) {
    failures++;
    checks++;
    cases++;
    fprintf(stderr, "FAIL %s: fixture does not load %s\n", label, path);
    return;
  }
  Parsed parsed = parse_floored(image, text, length, 0);

  int ok = accepted(&parsed, length);
  checks++;
  cases++;
  if (!ok) {
    failures++;
    /* stdout, not stderr, and in pass/fail order: this transcript IS the
     * artefact, and two interleaved streams reorder it into a lie. The
     * infrastructure failures below still go to stderr because they abort
     * before a verdict exists. */
    printf("  RED  %-34s REFUSED  return=%llu runtime=%llu E%llu reason=%llu "
           "at %llu:%llu nodes=%llu  %s\n",
           label, (unsigned long long)parsed.returned,
           (unsigned long long)parsed.runtime_error,
           (unsigned long long)(parsed.words ? parsed.words[1] : 0),
           (unsigned long long)(parsed.words ? parsed.words[2] : 0),
           (unsigned long long)(parsed.words ? parsed.words[4] : 0),
           (unsigned long long)(parsed.words ? parsed.words[5] : 0),
           (unsigned long long)(parsed.words ? parsed.words[9] : 0), path);
  } else {
    printf("  ok   %-34s ACCEPTED nodes=%llu  %s\n", label,
           (unsigned long long)parsed.words[9], path);
  }
  free(parsed.words);
  free(text);
}

/* The table is one flat NUL-separated run of bytes, one byte per u64 word of
 * the read-back. Two scans, both exact: a whole-word match and never a prefix
 * match, so `in` cannot be reported as known because `inout` is in the table;
 * and a scan over the `size` bytes rather than to the first NUL, because the
 * separator IS a NUL and stopping there reported a 77-word table as holding
 * one word the first time this ran. */
static unsigned count_words(const char *table, size_t size) {
  unsigned n = 0;
  int in_word = 0;
  for (size_t i = 0; i < size; i++) {
    if (table[i] == '\0') { in_word = 0; continue; }
    if (!in_word) { n++; in_word = 1; }
  }
  return n;
}

static int table_has(const char *table, const char *name) {
  size_t n = strlen(name);
  for (const char *p = table; *p; ) {
    size_t w = strlen(p);
    if (w == n && !memcmp(p, name, n))
      return 1;
    p += w + 1;
  }
  return 0;
}
/* The mechanical half of "names a missing module": read parser.nova's own
 * keyword table back out of the image and name, one by one, which of the
 * eight Nova keywords it does not contain. This is read-back, not a copy of
 * a literal written here, so it cannot drift from the table it reports on. */
static void report_keyword_gap(const NovaHostImage *image) {
  const char *nova[] = {"module", "export", "struct", "fn",
                        "let",   "mut",    "return", "while"};
  Parsed parsed = parse_floored(image, "", 0, 1024);
  if (!parsed.words || !parsed.words[0] || parsed.words[1] == 0 ||
      parsed.words[1] > 4096) {
    fprintf(stderr, "KEYWORD_TABLE unreadable\n");
    free(parsed.words);
    return;
  }
  uint64_t size = parsed.words[1];
  char table[4097];
  for (uint64_t i = 0; i < size; i++)
    table[i] = (char)parsed.words[2 + i];
  table[size] = 0;
  unsigned missing = 0;
  printf("KEYWORD_TABLE parser.nova holds %u words; of the eight Nova keywords:\n",
         (unsigned)count_words(table, (size_t)size));
  for (unsigned i = 0; i < 8; i++) {
    int present = table_has(table, nova[i]);
    if (!present)
      missing++;
    printf("  %-8s %s\n", nova[i], present ? "known" : "ABSENT");
  }
  printf("KEYWORD_GAP %u of 8 Nova keywords absent from the parser that is "
         "asked to read Nova\n", missing);
  free(parsed.words);
}

int main(void) {
  /* Unbuffered: this gate's output is the deliverable, and it must not depend
   * on how the C library chose to interleave it with an early abort. */
  setvbuf(stdout, NULL, _IONBF, 0);
  /* The same four modules tests_ntasm_parser.c builds. No import is added,
   * no closure is deepened: parser.nova was already reachable and this gate
   * only asks it a question it had never been asked. */
  const char *paths[] = {"tests/nova/tests/parser-entry.nova",
                         "compiler/nova/frontend/parser.nova",
                         "compiler/nova/frontend/ast.nova",
                         "compiler/nova/frontend/lexer.nova"};
  char *sources[4] = {0};
  NtFInput inputs[4];
  for (size_t i = 0; i < 4; i++) {
    size_t length = 0;
    sources[i] = load(paths[i], &length);
    inputs[i] = (NtFInput){paths[i], sources[i], length};
  }
  int loaded = sources[0] && sources[1] && sources[2] && sources[3];
  if (!loaded) {
    fprintf(stderr, "FAIL parser Nova sources load\n");
    for (size_t i = 0; i < 4; i++)
      free(sources[i]);
    return 2;
  }
  NtArtifact artifact;
  int compiled = nova_compile_many_v2(inputs, 4, &artifact);
  if (!compiled) {
    fprintf(stderr, "FAIL parser Nova modules compile E%u %zu:%zu %s\n",
            artifact.error.code, artifact.error.line, artifact.error.column,
            artifact.error.message);
    for (size_t i = 0; i < 4; i++)
      free(sources[i]);
    return 2;
  }
  NovaHostImage image = {0};
  if (!nova_host_map(&artifact, &image)) {
    fprintf(stderr, "FAIL parser image maps\n");
    nt_artifact_free(&artifact);
    for (size_t i = 0; i < 4; i++)
      free(sources[i]);
    return 2;
  }

  printf("NOVA_LANGUAGE_GATE -- what a Nova front end must accept\n");
  report_keyword_gap(&image);
  expect_accepted(&image, "nova/struct",
                  "tests/nova/tests/fixtures/"
                  "nova-language-struct.nova");
  expect_accepted(&image, "nova/mut",
                  "tests/nova/tests/fixtures/nova-language-mut.nova");
  expect_accepted(&image, "nova/eight-keywords",
                  "tests/nova/tests/fixtures/"
                  "nova-language-eight-keywords.nova");
  expect_accepted(&image, "nova/struct+mut+typed-let",
                  "tests/nova/tests/fixtures/"
                  "nova-language-struct-mut-typed-let.nova");
  /* THE CONTROL. Same image, same assertion, a file the parser does speak.
   * If this ever stops passing the four reds above stop meaning anything,
   * because the harness would have stopped being able to say yes. */
  expect_accepted(&image, "control/ntasm",
                  "tests/nova/tests/fixtures/positive-module.ntasm");

  nova_host_unmap(&image);
  nt_artifact_free(&artifact);
  for (size_t i = 0; i < 4; i++)
    free(sources[i]);
  printf("NOVA_LANGUAGE checks=%u failures=%u cases=%u %s\n", checks, failures,
         cases,
         failures ? "RED: no Nova front end" : "GREEN: Nova front end present");
  return failures ? 1 : 0;
}
