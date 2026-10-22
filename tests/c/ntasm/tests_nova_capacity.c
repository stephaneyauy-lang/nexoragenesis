#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks, failures;
#define CHECK(c, m)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL %s\n", m);                                         \
    }                                                                          \
  } while (0)

/* ===========================================================================
 * THE REFUSAL/CONTROL PAIR, and this is a CAPACITY gate whose every fixture
 * sat on the accepting side of every capacity. 513 functions against
 * MAX_FUNCS=32768; 64 scalar slots, which is exactly the allowed count and
 * never 65. Its only two substantive checks were `CHECK(ok, label)` and
 * `CHECK(result == want && !c.error, ...)` -- both acceptances, verified by
 * enumerating the file's failure surface. So nothing here could tell a limit
 * that fires from a limit that was deleted: a nova.c with both MAX_FUNCS and
 * the ABI slot check raised out of reach compiles both fixtures identically.
 *
 * TWO PAIRS, because this tree has two capacity walls on the accepting path
 * and the census named one of them with a fixture that measures the OTHER.
 *
 *   THE FUNCTION LIMIT. The census said "32769 functions, one past
 *   MAX_FUNCS=32768". MEASURED, it is not 32769 and the message is not the one
 *   predicted. MAX_TOKENS=393216 is hit FIRST by bodies of the shape the
 *   census described (`fn f00000(p:u64)->u64{return p+0;}`), so 32768, 32769
 *   and 32770 all answer "Nova token limit" and none of them is a
 *   one-past-the-bound on the FUNCTION wall at all -- they are three points
 *   past a different wall. The boundary was then located by shortening the
 *   body until the function wall is the one that bites: 32766 functions is
 *   the LAST accepted count and 32767 the FIRST refused, so the pair below is
 *   genuinely one count apart on the wall the census named. Both arms answer
 *   code 201; the refusal message names the function limit.
 *
 *   THE ABI SLOT LIMIT. The census itself named this one as the cheaper
 *   alternative already proven in tests_nova_boundary.c, and it is the better
 *   fixture here because it costs microseconds and is unambiguously one slot
 *   apart: 64 slots accepted, 65 refused with code 403. Kept as well, because
 *   a capacity gate that pins only the function wall still cannot tell a
 *   deleted SLOT check from a working one.
 *
 * THE POISON: the artifact is filled with 0xcc before the call and must come
 * back with no text and no relocations. nova_compile_v2 clears its own output
 * on failure, so the assertion is stated as absence -- what a refusal has to
 * guarantee. `ok == 0` alone would not catch a compiler that reported the
 * limit and still emitted an image.
 * ======================================================================== */
static void refusal_past_the_function_limit(void) {
  /* ONE COUNT, as the only variable: 32766 vs 32767. The body is the shortest
   * the grammar allows so that the token wall is not what is being measured. */
  struct { unsigned count; int accept; } pair[] = {{32766, 1}, {32767, 0}};
  for (unsigned i = 0; i < 2; i++) {
    size_t per = 40, cap = (size_t)pair[i].count * per + 256;
    char *source = malloc(cap);
    CHECK(source != NULL, "capacity pair: source allocated");
    if (!source)
      return;
    size_t n = 0;
    for (unsigned f = 0; f < pair[i].count; f++)
      n += (size_t)snprintf(source + n, cap - n,
                            "fn f%05u()->u64{return 1;}\n", f);
    n += (size_t)snprintf(source + n, cap - n, "fn main()->u64{return 1;}");
    NtArtifact a;
    memset(&a, 0xcc, sizeof a);
    int ok = nova_compile_v2(source, n, &a);
    if (pair[i].accept) {
      /* THE CONTROL. It must be accepted, and it must really emit text --
     * otherwise "no text on the refusal arm" would be a property of this
     * harness and not of the limit. */
      CHECK(ok, "capacity control: 32766 functions is the last accepted count");
      if (ok)
        CHECK(a.text.bytes && a.text.size > 0,
              "capacity control: a real code image is produced, so its absence "
              "on the refusal arm is a statement about the limit");
      else
        fprintf(stderr, "CAPACITY_CONTROL code=%u %s\n", a.error.code,
                a.error.message);
    } else {
      /* THE REFUSAL. The exact code, not merely nonzero. */
      CHECK(!ok, "capacity refusal: 32767 functions is one past the limit");
      if (!ok) {
        CHECK(a.error.code == 201,
              "capacity refusal: the exact failure code is 201");
        fprintf(stderr, "CAPACITY_PAIR_REFUSAL funcs=%u code=%u %s\n",
                pair[i].count, a.error.code, a.error.message);
 }
      CHECK(!a.text.bytes && !a.pe.bytes && !a.rdata.bytes && !a.data.bytes,
            "capacity refusal: no section carries bytes, so no image was "
      "fabricated behind the limit");
    }
    nt_artifact_free(&a);
    free(source);
  }
}

/* ONE SLOT, as the only variable: 64 vs 65. */
static void refusal_past_the_abi_slot_limit(void) {
  for (unsigned slots = 64; slots <= 65; slots++) {
    size_t cap = 1u << 20;
    char *source = malloc(cap);
    CHECK(source != NULL, "slot pair: source allocated");
    if (!source)
      return;
    size_t n = 0;
    n += (size_t)snprintf(source + n, cap - n, "fn total(");
    for (unsigned i = 0; i < slots; i++)
      n += (size_t)snprintf(source + n, cap - n, "%sa%u:u64", i ? "," : "", i);
    n += (size_t)snprintf(source + n, cap - n, ")->u64{return ");
    for (unsigned i = 0; i < slots; i++)
      n += (size_t)snprintf(source + n, cap - n, "%sa%u", i ? "+" : "", i);
    n += (size_t)snprintf(source + n, cap - n, ";}fn main()->u64{return total(");
    for (unsigned i = 0; i < slots; i++)
      n += (size_t)snprintf(source + n, cap - n, "%s%u", i ? "," : "", i);
    n += (size_t)snprintf(source + n, cap - n, ");}");
    NtArtifact a;
    memset(&a, 0xcc, sizeof a);
    int ok = nova_compile_v2(source, n, &a);
    if (slots == 64) {
      CHECK(ok, "slot control: 64 scalar slots is the allowed count");
      if (ok)
        CHECK(a.text.bytes && a.text.size > 0,
     "slot control: a real code image is produced on the accepted side of the "
              "one-slot difference");
    } else {
      CHECK(!ok, "slot refusal: 65 scalar slots is one past the ABI slot limit");
      if (!ok) {
        CHECK(a.error.code == 403,
              "slot refusal: the exact failure code is 403");
        fprintf(stderr, "SLOT_PAIR_REFUSAL slots=%u code=%u %s\n", slots,
                a.error.code, a.error.message);
      }
      CHECK(!a.text.bytes && !a.pe.bytes && !a.rdata.bytes && !a.data.bytes,
            "slot refusal: no section carries bytes, so no image was "
            "fabricated behind the limit");
    }
    nt_artifact_free(&a);
    free(source);
  }
}
static void execute(const char *source, size_t n, uint64_t want,
                    const char *label) {
  NtArtifact a;
  int ok = nova_compile_v2(source, n, &a);
  CHECK(ok, label);
  if (!ok) {
    fprintf(stderr, "E%u %zu:%zu %s\n", a.error.code, a.error.line,
            a.error.column, a.error.message);
    nt_artifact_free(&a);
    return;
  }
  NovaContextV2 c;
  NovaHostImage image;
  CHECK(nova_context_init_v2(&c) && nova_host_map(&a, &image),
        "capacity execution setup");
  uint64_t result = image.entry(&c, NULL, 0);
  CHECK(result == want && !c.error,
        "large compiled program executes expected result");
  printf("NOVA_CAPACITY_CASE label=%s source=%zu text=%zu result=%llu\n", label,
         n, a.text.size, (unsigned long long)result);
  nova_host_unmap(&image);
  nova_context_destroy_v2(&c);
  nt_artifact_free(&a);
}
int main(void) {
  char *source = malloc(1024 * 1024);
  if (!source)
    return 2;
  size_t n = 0;
  n += (size_t)sprintf(source + n, "fn total(");
  for (unsigned i = 0; i < 64; i++)
    n += (size_t)sprintf(source + n, "%sa%u:u64", i ? "," : "", i);
  n += (size_t)sprintf(source + n, ")->u64{return ");
  for (unsigned i = 0; i < 64; i++)
    n += (size_t)sprintf(source + n, "%sa%u", i ? "+" : "", i);
  n += (size_t)sprintf(source + n, ";}fn main()->u64{return total(");
  for (unsigned i = 0; i < 64; i++)
    n += (size_t)sprintf(source + n, "%s%u", i ? "," : "", i + 1);
  n += (size_t)sprintf(source + n, ");}");
  execute(source, n, 2080, "64-scalar-ABI");
  n = 0;
  for (unsigned f = 0; f < 512; f++) {
    n += (size_t)sprintf(source + n, "fn f%03u(p:u64)->u64{", f);
    for (unsigned i = 0; i < 8; i++)
      n += (size_t)sprintf(source + n, "let v%u:u64=p+%u;", i, i);
    n += (size_t)sprintf(source + n, "return v0+v1+v2+v3+v4+v5+v6+v7;}\n");
  }
  n += (size_t)sprintf(source + n, "fn main()->u64{return f511(1);}");
  execute(source, n, 36, "513-functions-4096-source-locals");
  refusal_past_the_abi_slot_limit();
  refusal_past_the_function_limit();
  free(source);
  printf("NOVA_CAPACITY_TESTS checks=%u failures=%u\n", checks, failures);
  return failures ? 1 : 0;
}
