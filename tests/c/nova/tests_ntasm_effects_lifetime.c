#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* THE LIFETIME GATE FOR THE EFFECTS VOCABULARIES.
 *
 * THE QUESTION IS NOT "WHAT IS THE NAME WORTH" BUT "WHAT DOES THE ASKING
 * COST". A string literal in this dialect is not static: `let w:buf<u8>=
 * "..."` allocates a handle, and a handle nobody frees is a live handle for
 * the rest of the run. The allocation map of the full reconstruction named
 * three functions of `effects` as the largest single sources of live
 * handles -- atom_kind 15432, memory_kind 3215, space_bit 1286 -- because
 * each of them built its words out of fresh literals and returned before
 * freeing one of them.
 *
 * THE GATE ASKS THE THREE VOCABULARIES ABOUT A NAME THAT IS IN NONE OF THEM,
 * FOUR THOUSAND TIMES, IN ONE RUNTIME CONTEXT. The old code allocated
 * nineteen handles per iteration -- eleven atoms, two memory effects, six
 * spaces -- and freed none, so the loop exhausted the runtime's buffer table
 * (65536 live handles) after about three thousand four hundred iterations
 * and the program died with NV2_EXHAUSTED. The new code frees each word it
 * allocates, after the comparison that read it, and the loop answers every
 * time.
 *
 * ONE CONTEXT, NOT ONE PER ITERATION. A context per iteration would give
 * the leak a fresh table every time and the gate would pass on the old code
 * as well: the leak is only visible when the same table has to survive the
 * whole loop.
 *
 * THE SOURCE IS BORROWED, READ AND NOT WRITTEN, and the C checks its bytes
 * after the call: a program that wrote to the lent source would be caught
 * here and not by the vocabulary.
 *
 * THE C SEED COMPILES THE ENTRY AND ITS CLOSURE -- the Nova sources below --
 * and NOTHING ELSE. No fixture is translated: the source the entry reads is
 * the word list below, and the entry is the only Nova program that runs.
 */

static unsigned checks, failures, cases;
static const uint64_t guard = UINT64_C(0xcccccccccccccccc);
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s\n", m); } } while (0)

static char *load(const char *path, size_t *size) {
  FILE *file = fopen(path, "rb");
  if (!file) return NULL;
  fseek(file, 0, SEEK_END);
  long length = ftell(file);
  fseek(file, 0, SEEK_SET);
  char *bytes = length >= 0 ? malloc((size_t)length + 1) : NULL;
  if (!bytes || fread(bytes, 1, (size_t)length, file) != (size_t)length) {
    free(bytes); fclose(file); return NULL;
  }
  fclose(file); bytes[length] = 0; *size = (size_t)length; return bytes;
}

typedef struct { uint64_t returned, runtime, out[4]; } Run;

/* THE CALL. The flat argument list is the entry's own: the borrowed source
 * (a handle and its length in bytes) and the out buffer (a handle and its
 * length in words). The context is created ONCE for the call and destroyed
 * after it, so every allocation the entry makes belongs to the same table. */
static Run run(const NovaHostImage *image, const char *source, uint64_t words) {
  Run result = {.out = {guard, guard, guard, guard}};
  NovaContextV2 context = {0};
  CHECK(nova_context_init_v2(&context), "context init");
  uint64_t source_handle = nova_borrow_v2(&context, (void *)source, strlen(source), 0);
  uint64_t out_handle = nova_borrow_v2(&context, result.out, words * 8, 1);
  uint64_t args[] = {source_handle, strlen(source), out_handle, words};
  result.returned = image->entry(&context, args, 4);
  result.runtime = context.error;
  CHECK(nova_context_destroy_v2(&context), "context cleanup");
  return result;
}

int main(void) {
  /* THE MODULE LIST IS THE ONE OF THE EFFECTS GATE, with the entry replaced:
   * the same closure, the same compiler, the same ABI2 arguments. */
  const char *paths[] = {
    "tests/nova/tests/effects-lifetime-entry.nova",
    "compiler/nova/analysis/abi/effects.nova",
    "compiler/nova/analysis/calls/callable_names.nova",
    "compiler/nova/analysis/semantics.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova"
  };
  char *sources[7] = {0}; NtFInput inputs[7];
  for (unsigned i = 0; i < 7; i++) {
    size_t size = 0; sources[i] = load(paths[i], &size);
    inputs[i] = (NtFInput){paths[i], sources[i], size};
  }
  int all = 1;
  for (unsigned i = 0; i < 7; i++) if (!sources[i]) all = 0;
  CHECK(all, "sources load");
  NtArtifact artifact = {0};
  int compiled = all && nova_compile_many_v2(inputs, 7, &artifact);
  CHECK(compiled, "modules compile");
  if (!compiled) fprintf(stderr, "E%u %zu:%zu %s\n", artifact.error.code,
                         artifact.error.line, artifact.error.column,
                         artifact.error.message);
  NovaHostImage image = {0};
  CHECK(compiled && nova_host_map(&artifact, &image), "image maps");
  if (image.memory) {
    /* THE SOURCE THE ENTRY READS, AND ITS LAYOUT IS THE ONE THE ENTRY
     * CHECKS: an unknown name of TEN bytes, then the first atom, the first
     * memory effect and the first space. The spans are checked HERE, so a
     * drift between the C and the entry is caught instead of measuring
     * something else. */
    static const char *source = "telepathyz privileged reads_mem user";
    char before[64];
    size_t length = strlen(source);
    CHECK(length == 36, "the lent source has the length the entry expects");
    CHECK(memcmp(source + 0, "telepathyz", 10) == 0,
          "the span [0,10) is the unknown name");
    CHECK(memcmp(source + 11, "privileged", 10) == 0,
          "the span [11,21) is privileged");
    CHECK(memcmp(source + 22, "reads_mem", 9) == 0,
          "the span [22,31) is reads_mem");
    CHECK(memcmp(source + 32, "user", 4) == 0,
          "the span [32,36) is user");
    memcpy(before, source, length);
    Run result = run(&image, source, 4);
    cases++;
    if (result.runtime || result.returned)
      fprintf(stderr, "EFFECTS_LIFETIME returned=%llu runtime=%llu\n",
              (unsigned long long)result.returned,
              (unsigned long long)result.runtime);
    /* THE LOOP SURVIVED. With the old code this is where the runtime's
     * buffer table ran out and the context carried NV2_EXHAUSTED. */
    CHECK(result.returned == 0 && result.runtime == 0,
          "the three vocabularies were asked four thousand times in one context");
    /* THE KNOWN NAMES ANSWERED. */
    CHECK(result.out[0] == 4000, "the entry did the four thousand iterations");
    CHECK(result.out[1] == 1 && result.out[2] == 1 && result.out[3] == 1,
          "the known names answered the documented values");
    /* THE BORROWED SOURCE IS INTACT. */
    CHECK(memcmp(before, source, length) == 0,
          "the borrowed source is byte for byte what the C lent");
    nova_host_unmap(&image);
  }
  for (unsigned i = 0; i < 7; i++) free(sources[i]);
  nt_artifact_free(&artifact);
  printf("NTASM_NOVA_EFFECTS_LIFETIME checks=%u failures=%u cases=%u\n",
         checks, failures, cases);
  return failures ? 1 : 0;
}
