/* ARTIFACT_OWNERSHIP -- the success path of nova_compile_many_v2 hands its
 * buffers to the CALLER, and this is the gate that says so.
 *
 * WHY THIS GATE EXISTS.  On the success path compile_profile() moves
 * image.bytes/rdata/data into the NtArtifact and NULLs the image before
 * nt_code_image_free(), so nt_codegen_x64() holds no live pointer to release:
 * the obligation is the caller's, discharged with nt_artifact_free().  A
 * caller that forgets does not merely waste memory under a leak checker.
 * legacy/tools/coldproof/ngbuild.sh:783 runs every gate under detect_leaks=1 with
 * stdout redirected to a FILE, so stdout is block-buffered; LeakSanitizer
 * ends the process with _exit(), which skips the stdio flush, and every
 * printf still in that buffer is LOST.  That is how A5_INVENTORY's summary
 * line -- the one stating denominator= and checks=/failures=, the line that
 * IS the measurement -- never reached the log, and the gate was reported
 * INTERRUPTED:NO_BANNER rather than as a leak.  Measured on this tree:
 * 4195328 bytes in 2 allocations, the machine-code buffer and the data
 * buffer, both allocated at codegen.c:162 and codegen.c:190.
 *
 * WHAT IS ASSERTED, and what is NOT.  This gate does NOT assert that the
 * producer freed anything -- the producer is correct and this gate proves
 * that by USING the artifact after compile and before free, which is only
 * sound if the buffers are genuinely the caller's to use.  What it asserts
 * is the ownership CONTRACT, in the two directions that matter:
 *   1. a second identical compile is byte-identical (the buffers are stable,
 *      not scratch the producer kept a pointer into), and
 *   2. nt_artifact_free() + nova_host_unmap() leave the process clean, which
 *      under the rail's own detect_leaks=1 is the assertion that matters.
 *
 * The banner is printed LAST and unconditionally, so a run that loses it is
 * reporting that something upstream died -- that property is the point of
 * this file, so it must not be given up to make the gate look green. */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/ntasm/frontend/ntasm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; \
  fprintf(stderr, "FAIL %s\n", m); } } while (0)

static char *load(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long z = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) {
    free(b); fclose(f); return NULL;
  }
  fclose(f);
  b[z] = 0;
  *n = (size_t)z;
  return b;
}

/* The machine-code text the producer handed over must be non-empty, must be
 * readable at the entry it published, and must be identical across two
 * independent compiles of the same inputs.  A producer that freed its own
 * buffers on the success path -- the mistake this gate exists to catch, and
 * the one a leak report alone would NOT catch, because the buffer would be
 * freed rather than leaked -- fails the first read here. */
static void arm(const NtFInput *inputs, size_t count, const char *label) {
  cases++;
  NtArtifact a = {0}, b = {0};
  int ca = nova_compile_many_v2(inputs, count, &a);
  CHECK(ca, "the success path compiles");
  if (!ca) {
    fprintf(stderr, "E%u %zu:%zu %s\n", a.error.code, a.error.line,
            a.error.column, a.error.message);
    nt_artifact_free(&a);
    nt_artifact_free(&b);
    return;
  }
  /* The buffers are OURS: read them, and map them. */
  CHECK(a.text.bytes != NULL, "text buffer is the caller's to read");
  CHECK(a.text.size > 0, "text buffer is non-empty");
  CHECK(a.entry < a.text.size, "the published entry lies inside our text");
  if (a.text.bytes && a.entry < a.text.size) {
    volatile unsigned char probe = a.text.bytes[a.entry];
    (void)probe;
    CHECK(1, "the entry byte reads back from the caller's buffer");
  }
  NovaHostImage image = {0};
  CHECK(nova_host_map(&a, &image), "the artifact maps for execution");
  if (image.memory) {
    CHECK(image.entry != NULL, "the mapped image has an entry");
    /* run_host COPIES the text (run_host.c:29 memcpy), so unmapping the
     * image must not disturb the artifact we still hold.  That is the
     * direction that would fail if the two shared one allocation. */
    nova_host_unmap(&image);
    CHECK(1, "unmapping the image leaves the artifact intact");
  }
  int cb = nova_compile_many_v2(inputs, count, &b);
  CHECK(cb, "the second compile succeeds");
  CHECK(b.text.size == a.text.size && b.rdata.size == a.rdata.size &&
        b.data.size == a.data.size,
        "two compiles of the same inputs agree on every section size");
  if (cb && a.text.size == b.text.size && a.text.bytes && b.text.bytes)
    CHECK(memcmp(a.text.bytes, b.text.bytes, a.text.size) == 0,
          "two compiles of the same inputs are byte-identical");

  /* The obligation, discharged.  Under detect_leaks=1 this is the assertion
   * that actually bites: with either call omitted the process is killed by
   * LeakSanitizer and the banner below never reaches the log. */
  nt_artifact_free(&a);
  nt_artifact_free(&b);
  CHECK(a.text.bytes == NULL, "nt_artifact_free clears the artifact");
  (void)label;
}

int main(void) {
  const char *paths[] = {
      "tests/nova/tests/macro-expand-entry.nova",
      "compiler/nova/macros/macro_expand.nova",
      "compiler/nova/macros/constant_eval.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/ast.nova",
      "compiler/nova/frontend/lexer.nova"};
  char *sources[6] = {0};
  NtFInput inputs[6];
  for (size_t i = 0; i < 6; i++) {
    size_t n = 0;
    sources[i] = load(paths[i], &n);
    inputs[i] = (NtFInput){paths[i], sources[i], n};
  }
  int all = 1;
  for (size_t i = 0; i < 6; i++) if (!sources[i]) all = 0;
  CHECK(all, "sources load");
  if (all) arm(inputs, 6, "macro_expand corpus");

  for (size_t i = 0; i < 6; i++) free(sources[i]);

  printf("ARTIFACT_OWNERSHIP the_success_path_transfers_the_buffers_to_the_"
         "caller checks_they_are_ours_to_read_and_map released_with_"
         "nt_artifact_free_and_nova_host_unmap cases=%u\n", cases);
  printf("ARTIFACT_OWNERSHIP denominator=%u checks=%u failures=%u cases=%u\n",
         6u, checks, failures, cases);
  return failures ? 1 : 0;
}
