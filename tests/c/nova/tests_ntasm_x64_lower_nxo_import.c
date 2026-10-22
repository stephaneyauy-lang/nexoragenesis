/* Gate for x64_lower_nxo.build_import_call, for
 * x64_lower_nxo.build_import_call_with_scalar_data and, above all, for the
 * cross producer link that was impossible until the contract text of
 * x64_lower_nxo matched the C reference byte for byte.
 *
 * THE NAMES ARE ASKED, NOT BUILT. The import symbol of this gate was, until
 * now, the one place in the tree where a C object writer's answer was
 * reconstructed by string surgery: c_importer_name compiled a probe source
 * with no import, took the prefix up to that probe's main's last dot, and
 * appended the bare alias. The result was "m." + alias BY CONSTRUCTION, and it
 * agreed with the producer because the producer did the same wrong thing --
 * x64_lower_nxo qualified the import with the ALIAS and the module of the
 * source that declared it. The reference does neither. frontend.c:2974 keeps
 * the dotted path in f->import_name and the alias in f->name; codegen.c:1586
 * -1599 splits that path at its LAST dot and gives the head to add_symbol as
 * the module and the tail as the name; object_build.c:305 joins head, dot and
 * tail. The name in the object is therefore the PATH, and neither the alias
 * nor the declaring module appears in it. Two sides agreeing on a wrong answer
 * is exactly what a gate built by construction cannot see, so this file now
 * compiles the importer's own declarations with nt_object_compile and compares
 * the reference's symbol table against the producer's, name against name,
 * whole string, in the reference's order.
 *
 * Every accepted link is compared three ways against the C pipeline, never
 * against an expectation written here: nt_object_link over the two read
 * objects, nt_object_write for the merged NXO, nt_object_materialize and
 * nt_make_pe for the PE, and nt_object_read for the contract text of the
 * producer own bytes. */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "../../../compiler/c/ntasm/backend/codegen.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL %s\n", m); } } while (0)
/* Reports the fixture name beside the expectation. */
#define CHECKL(c, m, l) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL %s [%s]\n", (l), (m)); } } while (0)
static char *loadf(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb"); if (!f) return NULL;
  fseek(f, 0, SEEK_END); long z = ftell(f); fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) { free(b); fclose(f); return NULL; }
  fclose(f); b[z] = 0; *n = (size_t)z; return b;
}
static char *dup_text(const char *s) {
  size_t n = s ? strlen(s) : 0;
  char *copy = malloc(n + 1);
  if (!copy) { CHECK(0, "text copy allocated"); return NULL; }
  if (n) memcpy(copy, s, n);
  copy[n] = 0;
  return copy;
}
/* Reports the first byte where a produced object and the C reference differ, so
 * a failure names the field instead of only its absence. */
static void report_object_diff(const uint8_t *got, uint64_t got_size,
                               const uint8_t *want, uint64_t want_size,
                               const char *label) {
  uint64_t j, n = got_size < want_size ? got_size : want_size;
  for (j = 0; j < n; j++)
    if (got[j] != want[j]) {
      fprintf(stderr, "OBJECT_DIFF %s at=%llu got=%02x want=%02x sizes=%llu/%llu\n",
              label, (unsigned long long)j, got[j], want[j],
              (unsigned long long)got_size, (unsigned long long)want_size);
      return;
    }
  fprintf(stderr, "OBJECT_DIFF %s tail got=%llu want=%llu\n", label,
          (unsigned long long)got_size, (unsigned long long)want_size);
}
static uint64_t r64(const uint8_t *b) {
  uint64_t v = 0;
  for (unsigned i = 0; i < 8; i++) v |= (uint64_t)b[i] << (i * 8);
  return v;
}
static size_t encode_(uint8_t *out, const char *name, NtX64Operand *op, size_t n) {
  NtX64Instruction encoded = {0};
  NtX64Context ctx = {1, 3};
  CHECK(nt_x64_encode(name, op, n, ctx, &encoded) == 0, "C x64 oracle");
  memcpy(out, encoded.bytes, encoded.length);
  return encoded.length;
}

#define OUTCAP 262144

/* The host ABI passes every buffer as a (handle, length) pair, so the eight
 * parameters of the gate entry need fifteen argument slots. The source is a
 * byte range and not a C string, because mode 3 reads a serialised NXO. */
static uint64_t run_bytes(const NovaHostImage *i, const void *source, size_t source_size,
                          const uint8_t *definition, size_t definition_size,
                          uint64_t mode, uint64_t index, uint8_t *out, size_t capacity) {
  static uint8_t empty[1];
  NovaContextV2 c = {0};
  uint64_t sh, dh, oh, args[8], code;
  const uint8_t *definition_bytes = definition_size ? definition : empty;
  CHECK(nova_context_init_v2(&c), "context init");
  sh = nova_borrow_v2(&c, (void *)source, source_size, 0);
  dh = nova_borrow_v2(&c, (void *)definition_bytes, definition_size, 0);
  oh = nova_borrow_v2(&c, out, capacity, 1);
  args[0] = sh; args[1] = source_size;
  args[2] = dh; args[3] = definition_size;
  args[4] = mode; args[5] = index;
  args[6] = oh; args[7] = capacity;
  code = i->entry(&c, args, 8);
  CHECK(c.error == 0, "runtime clean");
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  cases++;
  return code;
}
static uint64_t run(const NovaHostImage *i, const char *source, const uint8_t *definition,
                    size_t definition_size, uint64_t mode, uint64_t index,
                    uint8_t *out, size_t capacity) {
  return run_bytes(i, source, strlen(source), definition, definition_size, mode, index,
                   out, capacity);
}
static uint64_t run_producer(const NovaHostImage *i, const char *source, uint64_t mode,
                             uint8_t *out, size_t capacity) {
  return run(i, source, NULL, 0, mode, 0, out, capacity);
}
static void rejected(const NovaHostImage *i, const char *source, const char *label) {
  uint8_t out[1024];
  unsigned j;
  int intact;
  uint64_t code;
  memset(out, 0xcc, sizeof out);
  code = run_producer(i, source, 0, out, sizeof out);
  intact = (code == 800);
  for (j = 0; j < sizeof out; j++) intact &= out[j] == 0xcc;
  CHECK(intact, label);
}

/* The contract the C reference writes for the symbol whose name ends in
 * "." + name, read out of nt_object_compile. That is the exact byte string the
 * Nova producer has to match, taken from the reference and not retyped. */
static char *canonical_contract(const char *source, const char *name) {
  NtFInput input = {"d", (char *)source, strlen(source)};
  NtObject object;
  NtDiagnostic error;
  char *found = NULL;
  size_t k, nl = strlen(name);
  memset(&object, 0, sizeof object);
  memset(&error, 0, sizeof error);
  if (!nt_object_compile(&input, 1, &object, &error)) {
    fprintf(stderr, "CANONICAL_REFUSED code=%u %s\n", error.code, error.message);
    return NULL;
  }
  for (k = 0; k < object.symbol_count && !found; k++) {
    const char *written = object.symbols[k].name;
    size_t l = written ? strlen(written) : 0;
    if (l > nl && written[l - 1 - nl] == '.' && !memcmp(written + l - nl, name, nl))
      found = dup_text(object.symbols[k].contract);
  }
  if (!found) fprintf(stderr, "CANONICAL_MISSING name=%s\n", name);
  nt_object_free(&object);
  return found;
}

/* ------------------------------------------------------------------ */
/* The naming oracle: the C reference asked, not a second spelling of it.   */
/* ------------------------------------------------------------------ */

/* One symbol as the reference wrote it: the name it chose, and the section and
 * flag word it wrote the name under. */
typedef struct { char *name; uint32_t section, flags; } RefSymbol;

/* Every symbol of the object the C reference builds for `source`, in the order
 * the reference writes them -- which is the order object_build.c:213 sorts the
 * table into, and therefore the order the object is required to carry. This is
 * the whole naming oracle of this gate: no name below is typed here, none is
 * found by a suffix or a substring, and none is stitched together out of some
 * other source's answer. The reference is asked and its answer is compared.
 *
 * object mode, not the default, because a unit whose import is unresolved is
 * exactly the case codegen.c:1580-1583 refuses outside it. Caller frees each
 * name and the array. NULL when the reference refused the source. */
static RefSymbol *c_reference_symbols(const char *source, size_t *count) {
  NtObject object;
  NtDiagnostic error;
  RefSymbol *table;
  size_t k;
  *count = 0;
  memset(&object, 0, sizeof object);
  memset(&error, 0, sizeof error);
  if (!nt_object_compile(&(NtFInput){"naming", (char *)source, strlen(source)},
                         1, &object, &error)) {
    fprintf(stderr, "REFERENCE_REFUSED code=%u %s\n", error.code, error.message);
    nt_object_free(&object);
    return NULL;
  }
  table = calloc(object.symbol_count ? object.symbol_count : 1, sizeof *table);
  if (!table) { nt_object_free(&object); return NULL; }
  for (k = 0; k < object.symbol_count; k++) {
    table[k].name = dup_text(object.symbols[k].name);
    table[k].section = object.symbols[k].section;
    table[k].flags = object.symbols[k].flags;
    if (!table[k].name) {
      for (; k; k--) free(table[k - 1].name);
      free(table); nt_object_free(&object); return NULL;
    }
  }
  *count = object.symbol_count;
  nt_object_free(&object);
  return table;
}
static void c_reference_symbols_free(RefSymbol *table, size_t count) {
  size_t k;
  if (!table) return;
  for (k = 0; k < count; k++) free(table[k].name);
  free(table);
}

/* The name the reference wrote for the ONE symbol carrying `flags` in
 * `section`, or NULL when it wrote none or more than one. Selection is by the
 * reference's own metadata and never by recognising a name, so a producer that
 * wrote the wrong name cannot be found by searching for the right one, and two
 * symbols that happen to share a spelling cannot be told apart by it.
 *
 * This is the replacement for c_importer_name, which built the answer by
 * string surgery on another source's main: it took the prefix up to main's last
 * dot and appended the bare alias, so the result was "m." + alias BY
 * CONSTRUCTION. The reference names an unresolved import by its PATH
 * (codegen.c:1586-1599 splits f->import_name at its last dot and object_build.c
 * .305 rejoins the two halves), so that construction was the wrong answer
 * spelled correctly, and a producer agreeing with it could not be distinguished
 * from one agreeing with the reference. Caller frees. */
static char *c_reference_name(const char *source, uint32_t section, uint32_t flags) {
  RefSymbol *table;
  size_t count = 0, k, hits = 0, at = 0;
  char *found = NULL;
  table = c_reference_symbols(source, &count);
  if (!table) return NULL;
  for (k = 0; k < count; k++)
    if (table[k].section == section && table[k].flags == flags) { hits++; at = k; }
  if (hits == 1) found = dup_text(table[at].name);
  else fprintf(stderr, "REFERENCE_NAME_AMBIGUOUS section=%u flags=%u hits=%zu\n",
               section, flags, hits);
  c_reference_symbols_free(table, count);
  return found;
}

/* The contract text the C reference wrote for the one symbol carrying `flags`
 * in `section`. Same selection rule as c_reference_name and for the same
 * reason: the harness never spells a name to find a symbol. Caller frees. */
static char *c_reference_contract(const char *source, uint32_t section, uint32_t flags) {
  NtObject object;
  NtDiagnostic error;
  char *found = NULL;
  size_t k, hits = 0, at = 0;
  memset(&object, 0, sizeof object);
  memset(&error, 0, sizeof error);
  if (!nt_object_compile(&(NtFInput){"contract", (char *)source, strlen(source)},
                         1, &object, &error)) {
    fprintf(stderr, "CONTRACT_ORACLE_REFUSED code=%u %s\n", error.code, error.message);
    nt_object_free(&object);
    return NULL;
  }
  for (k = 0; k < object.symbol_count; k++)
    if (object.symbols[k].section == section && object.symbols[k].flags == flags) {
      hits++; at = k;
    }
  if (hits == 1) found = dup_text(object.symbols[at].contract);
  else fprintf(stderr, "CONTRACT_ORACLE_AMBIGUOUS section=%u flags=%u hits=%zu\n",
               section, flags, hits);
  nt_object_free(&object);
  return found;
}

/* The last occurrence of `marker` in `text`, or NULL. strrstr is a GNU
 * extension and this harness is compiled -std=c11 -Werror, so the search is
 * written out rather than reached for. */
static const char *last_occurrence(const char *text, const char *marker) {
  size_t m = strlen(marker), n = strlen(text), i, at = 0;
  int found = 0;
  for (i = 0; i + m <= n; i++)
    if (!memcmp(text + i, marker, m)) { at = i; found = 1; }
  return found ? text + at : NULL;
}

/* The source the naming oracle is asked about: the fixture's own bytes up to
 * and including the brace that opens the main body, then a body the reference
 * accepts. The substitution is forced by a measurement, not chosen: the
 * reference REFUSES the fixture's own `call` / `ret` body with 503 "ret
 * requires unavailable stack/frame balance proof", which reference_body_refused
 * below asserts on every run, so the reference cannot be asked to name the
 * symbols of that exact text at all.
 *
 * A body contributes no name. Every name in the table is the module of the
 * declaration plus a function or variable name, or the head and tail of an
 * import path, and the reference reads all three off the declaration lines --
 * which are the fixture's own bytes, copied here and not retyped. What the
 * substitution drops is the call site, and the call site is not a name: it is
 * the alias, and the reference discards the alias (frontend.c:2974 keeps it in
 * f->name, which codegen.c never reads for a name). */
static char *naming_source(const char *fixture, const char *call) {
  const char *marker = "clobbers {} {\n";
  const char *at = last_occurrence(fixture, marker);
  size_t keep, room;
  char *out;
  int n;
  if (!at) return NULL;
  keep = (size_t)(at - fixture) + strlen(marker);
  room = keep + strlen(call) + 32;
  out = malloc(room);
  if (!out) return NULL;
  n = snprintf(out, room, "%.*sreturn %s()\n}\n}\n", (int)keep, fixture, call);
  if (n < 0 || (size_t)n >= room) { free(out); return NULL; }
  return out;
}

/* That the substitution above is not quietly a whole different program. The
 * naming source and the fixture must agree on every byte up to the body's
 * opening brace, and the keep count is recomputed here from the fixture rather
 * than carried over from naming_source, so a change to either half that breaks
 * that agreement is a failure of this check and not a silent new oracle. */
static void naming_source_is_the_fixture(const char *fixture, const char *derived,
                                         const char *label) {
  const char *at = last_occurrence(fixture, "clobbers {} {\n");
  size_t keep;
  CHECKL(at != NULL, "the fixture's main body opens where the naming source assumes", label);
  if (!at) return;
  keep = (size_t)(at - fixture) + strlen("clobbers {} {\n");
  CHECKL(derived && strlen(derived) >= keep &&
             !memcmp(derived, fixture, keep),
         "the naming source is the fixture's own declarations, byte for byte", label);
}
/* ------------------------------------------------------------------ *
 * THE ENTRY ORACLE: asked, never stated.
 * ------------------------------------------------------------------ */

/* The entry_symbol the C reference wrote for `source`, or UINT32_MAX when the
 * reference refused the source. It is read out of the object the reference
 * itself built, and nothing here reconstructs it.
 *
 * WHY THIS IS NOT A LITERAL. This gate used to write `oracle.entry_symbol = 2`
 * twice, once per target, and to build the symbol table around a hardcoded
 * NT_OBJECT_EXPORT on main. Both halves stated the answer the producer gave
 * rather than the answer the reference gives, so a producer that disagreed
 * with the reference about the entry could not be distinguished from one that
 * agreed with it. That is the same defect as a stamped oracle in any other
 * form, and it is what let a producer mark a non-exported main as exported go
 * unnoticed: the two halves agreed with each other and neither asked.
 *
 * WHY IT IS THE REFERENCE'S ANSWER AND NOT OURS. object_build.c:337-351 sets
 * `o->entry_symbol` only for the symbol at image.entry whose function is
 * exported AND whose name is "main", and codegen.c:1557-1562 sets image.entry
 * only for a function that is exported and named main. So the reference's
 * answer is zero for a non-exported main, for a module with no main, and for
 * an exported function under any other name -- and a literal 2 asserts the
 * opposite in all three cases.
 *
 * `naming` must be a source the reference ACCEPTS (see naming_source: the
 * reference refuses a bare `ret` body with 503), but one whose DECLARATIONS
 * are the fixture's own bytes, so the export bit being asked about is the
 * fixture's own. naming_source_is_the_fixture asserts exactly that. */
static uint32_t c_reference_entry(const char *source) {
  NtObject object;
  NtDiagnostic error;
  uint32_t entry;
  memset(&object, 0, sizeof object);
  memset(&error, 0, sizeof error);
  if (!nt_object_compile(&(NtFInput){"entry", (char *)source, strlen(source)},
                         1, &object, &error)) {
    fprintf(stderr, "ENTRY_ORACLE_REFUSED code=%u %s\n", error.code, error.message);
    nt_object_free(&object);
    return UINT32_MAX;
  }
  entry = object.entry_symbol;
  nt_object_free(&object);
  return entry;
}

/* The whole expectation for one producer shape, every field of which is the
 * reference's own: the names from c_reference_name, the contracts from
 * canonical_contract, and the entry from c_reference_entry. A shape whose
 * reference is refused yields want_entry = UINT32_MAX and the caller CHECKs
 * that, rather than silently comparing against a default. */
typedef struct { char *import_name, *main_name; uint32_t entry; } EntryExpectation;

static void entry_expectation(const char *fixture, const char *call,
                              const char *label, EntryExpectation *want) {
  char *naming = naming_source(fixture, call);
  naming_source_is_the_fixture(fixture, naming, label);
  want->import_name = naming
      ? c_reference_name(naming, 0, NT_OBJECT_IMPORT | NT_OBJECT_FUNCTION) : NULL;
  want->main_name = naming
      ? c_reference_name(naming, 1, NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION) : NULL;
  want->entry = naming ? c_reference_entry(naming) : UINT32_MAX;
  free(naming);
}
static void entry_expectation_free(EntryExpectation *want) {
  free(want->import_name); free(want->main_name);
  want->import_name = want->main_name = NULL;
}


/* A definition object the C reference built for `name`, renamed to the name
 * the reference itself gives the IMPORTER's import. Sections, flags, offsets,
 * sizes, the .text payload and the contract all come from nt_object_compile plus
 * nt_object_write. The rename exists because the two sides are built from two
 * different sources under two different modules; the name it is renamed TO is
 * the one c_reference_name read out of the reference for the importer's own
 * declarations, so it is the reference's spelling and not a construction of one.
 *
 * `name` is passed in rather than derived here because a definition must be
 * named after the symbol the producer's object actually carries, and that
 * symbol is the thing the naming check below is about. A linker that resolved
 * it under any other spelling would be testing a different producer. */
static NtBuffer c_definition(const char *source, const char *name) {
  NtFInput input = {"d", (char *)source, strlen(source)};
  NtObject built, renamed;
  NtBuffer file = {0};
  NtDiagnostic error;
  NtObjectSymbol symbol;
  char *qualified = name ? dup_text(name) : NULL;
  memset(&built, 0, sizeof built);
  memset(&renamed, 0, sizeof renamed);
  memset(&symbol, 0, sizeof symbol);
  memset(&error, 0, sizeof error);
  if (!qualified) return file;
  if (!nt_object_compile(&input, 1, &built, &error)) {
    fprintf(stderr, "DEFINITION_REFUSED code=%u %s\n", error.code, error.message);
    free(qualified);
    return file;
  }
  if (built.symbol_count != 1) {
    fprintf(stderr, "DEFINITION_SHAPE symbols=%zu\n", built.symbol_count);
    nt_object_free(&built);
    free(qualified);
    return file;
  }
  symbol.name = qualified;
  symbol.contract = built.symbols[0].contract;
  symbol.section = built.symbols[0].section;
  symbol.flags = built.symbols[0].flags;
  symbol.offset = built.symbols[0].offset;
  symbol.size = built.symbols[0].size;
  renamed.target = built.target;
  renamed.entry_symbol = 0;
  renamed.sections[0] = built.sections[0];
  renamed.sections[1] = built.sections[1];
  renamed.sections[2] = built.sections[2];
  renamed.symbols = &symbol;
  renamed.symbol_count = 1;
  renamed.relocations = built.relocations;
  renamed.relocation_count = built.relocation_count;
  if (!nt_object_write(&renamed, &file, &error))
    fprintf(stderr, "DEFINITION_WRITE_REFUSED code=%u %s\n", error.code, error.message);
  nt_object_free(&built);
  free(qualified);
  return file;
}

/* The same C produced object with the contract replaced by `contract`, which
 * is how a one byte contract difference is staged without touching anything
 * the reference owns. */
static NtBuffer c_definition_with(const char *source, const char *name,
                                  const char *contract) {
  NtFInput input = {"d", (char *)source, strlen(source)};
  NtObject built, renamed;
  NtBuffer file = {0};
  NtDiagnostic error;
  NtObjectSymbol symbol;
  char *qualified = name ? dup_text(name) : NULL;
  memset(&built, 0, sizeof built);
  memset(&renamed, 0, sizeof renamed);
  memset(&symbol, 0, sizeof symbol);
  memset(&error, 0, sizeof error);
  if (!qualified) return file;
  if (!nt_object_compile(&input, 1, &built, &error)) { free(qualified); return file; }
  symbol.name = qualified;
  symbol.contract = (char *)contract;
  symbol.section = built.symbols[0].section;
  symbol.flags = built.symbols[0].flags;
  symbol.offset = built.symbols[0].offset;
  symbol.size = built.symbols[0].size;
  renamed.target = built.target;
  renamed.entry_symbol = 0;
  renamed.sections[0] = built.sections[0];
  renamed.symbols = &symbol;
  renamed.symbol_count = 1;
  if (!nt_object_write(&renamed, &file, &error))
    fprintf(stderr, "DEFINITION_WRITE_REFUSED code=%u %s\n", error.code, error.message);
  nt_object_free(&built);
  free(qualified);
  return file;
}

static uint8_t out_a[OUTCAP];
static uint8_t out_b[OUTCAP];

/* THE naming check, and the reason this lot exists. nt_object_read recovers the
 * names the producer wrote, in the order the object carries them;
 * c_reference_symbols returns the names the C reference writes for the same
 * declarations, in the order the reference writes them. The two lists are
 * compared entry by entry with strcmp on the whole string.
 *
 * There is no prefix, no suffix and no search anywhere in this comparison, and
 * that is the property that matters. A suffix match against "main" passes for a
 * producer that qualified the import with the WRONG module, and a prefix match
 * against "m." passes for a producer that never qualified it at all; only a
 * whole string comparison against the reference's own answer distinguishes the
 * three. It also covers the ORDER, because the reference's order is the order
 * object_build.c:213 sorts the table into, so a producer that got both names
 * right and put them in the wrong slots is red here too. */
static void expect_reference_names(const NovaHostImage *i, const char *fixture,
                                   const char *call, uint64_t mode,
                                   const char *label) {
  static NtObject got;
  NtDiagnostic error;
  RefSymbol *want;
  char *naming;
  size_t want_count = 0, k;
  naming = naming_source(fixture, call);
  naming_source_is_the_fixture(fixture, naming, label);
  want = naming ? c_reference_symbols(naming, &want_count) : NULL;
  CHECKL(naming && want, "the C reference answers for this fixture's own declarations", label);
  if (naming && want) {
    uint64_t code, size;
    memset(&got, 0, sizeof got);
    memset(&error, 0, sizeof error);
    memset(out_a, 0xcc, sizeof out_a);
    code = run_producer(i, fixture, mode, out_a, sizeof out_a);
    size = r64(out_a);
    if (code != 0 || size > sizeof out_a - 8 ||
        !nt_object_read(out_a + 8, (size_t)size, &got, &error)) {
      CHECKL(0, "C reads the producer object for the naming check", label);
    } else {
      CHECKL(got.symbol_count == want_count,
             "the producer writes exactly the symbols the reference writes", label);
      for (k = 0; k < got.symbol_count && k < want_count; k++) {
        int same = got.symbols[k].name && want[k].name &&
                   !strcmp(got.symbols[k].name, want[k].name);
        CHECKL(same, "every symbol is named exactly as the C reference names it", label);
        if (!same)
          fprintf(stderr, "NAME_DIFF %s index=%zu nova=[%s] C=[%s]\n", label, k,
                  got.symbols[k].name ? got.symbols[k].name : "(null)",
                  want[k].name ? want[k].name : "(null)");
      }
      nt_object_free(&got);
    }
  }
  c_reference_symbols_free(want, want_count);
  free(naming);
}

/* ------------------------------------------------------------------ */
/* The cross producer link: the case this whole lot exists for. */
/* ------------------------------------------------------------------ */
static void expect_link(const NovaHostImage *i, const char *importer,
                        const char *definition_source, const char *import_name,
                        const char *label) {
  static NtObject nova_read, def_read, linked;
  NtBuffer definition, expected = {0};
  NtArtifact executable = {0};
  NtDiagnostic error;
  uint64_t code, size, pe_size;

  definition = c_definition(definition_source, import_name);
  CHECKL(definition.bytes != NULL, "C produces the definition object", label);
  if (!definition.bytes) return;
  memset(&nova_read, 0, sizeof nova_read);
  memset(&def_read, 0, sizeof def_read);
  memset(&linked, 0, sizeof linked);
  memset(&error, 0, sizeof error);

  /* The C pipeline first, so the Nova answers have something to be compared to. */
  memset(out_a, 0xcc, sizeof out_a);
  code = run_producer(i, importer, 0, out_a, sizeof out_a);
  size = r64(out_a);
  CHECKL(code == 0 && size <= sizeof out_a - 8, "Nova import object is produced", label);
  if (code != 0 || size > sizeof out_a - 8) { free(definition.bytes); return; }
  if (!nt_object_read(out_a + 8, (size_t)size, &nova_read, &error)) {
    CHECKL(0, "C reads the Nova import object", label);
    free(definition.bytes);
    return;
  }
  if (!nt_object_read(definition.bytes, definition.size, &def_read, &error)) {
    CHECKL(0, "C reads its own definition object", label);
    nt_object_free(&nova_read); free(definition.bytes); return;
  }
  {
    NtObject pair[2];
    pair[0] = nova_read; pair[1] = def_read;
    if (!nt_object_link(pair, 2, &linked, &error)) {
      fprintf(stderr, "C_LINK_REFUSED code=%u %s [%s]\n", error.code, error.message, label);
      CHECKL(0, "C links the two objects", label);
    } else {
      CHECKL(nt_object_write(&linked, &expected, &error) != 0, "C writes the merged object", label);
      CHECKL(nt_object_materialize(&linked, &executable, &error) != 0, "C materializes the link", label);
      if (executable.pe.bytes)
        CHECKL(nt_make_pe(&executable) != 0, "C lays the merged object out as a PE", label);
    }
  }

  /* Now the Nova side, mode 1 the merged NXO and mode 2 the merged PE. */
  memset(out_b, 0xcc, sizeof out_b);
  code = run(i, importer, definition.bytes, definition.size, 1, 0, out_b, sizeof out_b);
  {
    uint64_t got = r64(out_b);
    CHECKL(code == 0, "Nova merge accepts the C definition", label);
    if (code != 0)
      fprintf(stderr, "NOVA_MERGE_REFUSED got=%llu [%s]\n",
              (unsigned long long)code, label);
    if (code == 0 && expected.bytes)
      CHECKL(got == expected.size && !memcmp(out_b + 8, expected.bytes, (size_t)got),
             "merged NXO is byte identical to nt_object_link plus nt_object_write", label);
  }
  memset(out_b, 0xcc, sizeof out_b);
  code = run(i, importer, definition.bytes, definition.size, 2, 0, out_b, sizeof out_b);
  pe_size = r64(out_b);
  CHECKL(code == 0, "Nova link_pe accepts the C definition", label);
  if (code != 0)
    fprintf(stderr, "NOVA_LINK_PE_REFUSED got=%llu [%s]\n",
            (unsigned long long)code, label);
  if (code == 0 && executable.pe.bytes)
    CHECKL(pe_size == executable.pe.size &&
           !memcmp(out_b + 8, executable.pe.bytes, executable.pe.size),
           "merged PE is byte identical to nt_object_link plus nt_make_pe", label);
  nt_artifact_free(&executable);
  if (expected.bytes) free(expected.bytes);
  nt_object_free(&linked);
  nt_object_free(&def_read);
  nt_object_free(&nova_read);
  free(definition.bytes);
}

/* The same link with a contract the Nova producer did not write, which the
 * merger must still refuse with 825, byte for byte and nothing softer. */
static void expect_link_refused(const NovaHostImage *i, const char *importer,
                                const char *definition_source, const char *import_name,
                                const char *contract, uint64_t want,
                                const char *label) {
  NtBuffer definition = c_definition_with(definition_source, import_name, contract);
  unsigned j;
  int intact;
  uint64_t code;
  CHECKL(definition.bytes != NULL, "C writes the mismatched definition", label);
  if (!definition.bytes) return;
  memset(out_b, 0xcc, sizeof out_b);
  code = run(i, importer, definition.bytes, definition.size, 1, 0, out_b, sizeof out_b);
  intact = (code == want);
  for (j = 0; j < sizeof out_b; j++) intact &= (out_b[j] == 0xcc);
  CHECKL(intact, "refused merge keeps the output buffer untouched", label);
  if (code != want)
    fprintf(stderr, "REFUSED_MISMATCH got=%llu want=%llu [%s]\n",
            (unsigned long long)code, (unsigned long long)want, label);
  free(definition.bytes);
}

/* The contract text the producer own bytes carry, read back by the frozen C
 * reader and by the Nova inspector, both against the C canonical text. */
static void expect_contract_round_trip(const NovaHostImage *i, const char *source,
                                       const char *definition_source, const char *alias,
                                       size_t expected_count, const char *label) {
  static NtObject object;
  NtDiagnostic error;
  uint64_t code, size;
  unsigned j;
  int intact;
  memset(&object, 0, sizeof object);
  memset(&error, 0, sizeof error);
  memset(out_a, 0xcc, sizeof out_a);
  code = run_producer(i, source, 0, out_a, sizeof out_a);
  size = r64(out_a);
  CHECKL(code == 0, "producer object for the round trip", label);
  if (code != 0) return;
  if (!nt_object_read(out_a + 8, (size_t)size, &object, &error)) {
    CHECKL(0, "C reads the producer object", label);
    return;
  }
  for (j = 0; j < object.symbol_count; j++) {
    char *canonical;
    char definition[512];
    int same;
    snprintf(definition, sizeof definition,
             "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
             "export fn %s()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
             alias);
    canonical = canonical_contract(definition_source && *definition_source
                                       ? definition_source : definition, alias);
    CHECKL(canonical != NULL, "C canonical contract available", label);
    same = canonical && !strcmp(object.symbols[j].contract, canonical);
    CHECKL(same, "nt_object_read recovers the canonical contract", label);
    if (!same && canonical)
      fprintf(stderr, "CONTRACT_MISMATCH symbol=%s nova=[%s] C=[%s]\n",
              object.symbols[j].name, object.symbols[j].contract, canonical);
    free(canonical);
    /* the Nova accessor reads the same bytes out of the same file */
    memset(out_b, 0xcc, sizeof out_b);
    code = run_bytes(i, out_a + 8, (size_t)size, NULL, 0, 3, j, out_b, sizeof out_b);
    CHECKL(code == 0, "Nova inspector returns the contract", label);
    if (code != 0)
      fprintf(stderr, "INSPECT code=%llu index=%u [%s]\n",
              (unsigned long long)code, j, label);
    intact = (code == 0);
    if (intact) {
      char *canonical2;
      char probe[512];
      snprintf(probe, sizeof probe,
               "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
               "export fn %s()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
               alias);
      canonical2 = canonical_contract(probe, alias);
      if (!canonical2 || strlen(canonical2) != expected_count)
        fprintf(stderr, "INSPECT length got=%zu want=%zu [%s]\n",
                canonical2 ? strlen(canonical2) : (size_t)0, expected_count, label);
      CHECKL(canonical2 != NULL && strlen(canonical2) == expected_count &&
                 !memcmp(out_b, canonical2, strlen(canonical2)),
             "the Nova inspector returns the canonical contract bytes", label);
      if (canonical2 && memcmp(out_b, canonical2, strlen(canonical2)))
        fprintf(stderr, "INSPECT_TEXT got=[%.*s] want=[%s]\n",
                (int)strlen(canonical2), (const char *)out_b, canonical2);
      free(canonical2);
    }
  }
  nt_object_free(&object);
}

int main(void) {
  const char *paths[] = {
      "tests/nova/tests/x64-lower-nxo-import-entry.nova",
      "compiler/nova/backend/x64/x64_lower_nxo.nova",
      "compiler/nova/backend/x64/x64_lower_control.nova",
      "compiler/nova/backend/x64/x64_lower_fixed.nova",
      "compiler/nova/backend/x64/x64_fixed.nova",
      "compiler/nova/analysis/types/register_widths.nova",
      "compiler/nova/formats/nxo/nxo.nova",
      "compiler/nova/formats/nxo/nxo_merge.nova",
      "compiler/nova/formats/nxo/nxo_link_pe.nova",
      "compiler/nova/formats/nxo/nxo_pe.nova",
      "compiler/nova/inspectors/nxo_inspect.nova",
      "compiler/nova/formats/pe/pe.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/ast.nova",
      "compiler/nova/frontend/lexer.nova",
        "compiler/nova/macros/macro_splice.nova",
        "compiler/nova/macros/macro_expand.nova",
        "compiler/nova/macros/constant_eval.nova"};
  char *sources[18] = {0};
  NtFInput inputs[18];
  unsigned i;
  int all = 1, compiled;
  NtArtifact compiler = {0};
  NovaHostImage image = {0};

  for (i = 0; i < 18; i++) {
    size_t n = 0;
    sources[i] = loadf(paths[i], &n);
    inputs[i] = (NtFInput){paths[i], sources[i], n};
    if (!sources[i]) all = 0;
  }
  CHECK(all, "sources load");
  compiled = all && nova_compile_many_v2(inputs, 18, &compiler);
  CHECK(compiled, "Nova modules compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", compiler.error.code, compiler.error.line,
            compiler.error.column, compiler.error.message);
  CHECK(compiled && nova_host_map(&compiler, &image), "host map");

  if (image.memory) {
    /* The caller's main is EXPORTED, and that is not decoration: the object
     * this gate compares against is the one the C reference builds for the
     * fixture's own declarations, and the reference sets NT_OBJECT_EXPORT from
     * `f->exported` (object_build.c:317) and names the entry only for an
     * exported main (object_build.c:343-347). A `fn main` with no export makes
     * the reference write entry_symbol = 0, and an entryless object is refused
     * 803 by the PE route -- which is the route this gate exercises. The two
     * spellings are not interchangeable, and a producer that hardcoded the
     * export bit made the difference invisible here. */
    static const char *IMPORTER =
        "module m\ntarget x86_64-nexora-uefi\nimport api.echo as ext: fn()->u64\n"
        "effects {}\nclobbers {}\nsection .text {\nexport fn main()->u64\n"
        "effects {}\nclobbers {} {\ncall ext()\nret\n}\n}\n";
    static const char *DEFINITION =
        "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
        "export fn ext()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    char *canonical = canonical_contract(DEFINITION, "ext");
    /* Every name AND the entry below are what the C reference writes for the
     * IMPORTER's own declarations: module line, import line and all, taken from
     * the fixture and asked about rather than retyped. The entry is asked too,
     * not stated -- see c_reference_entry for why a literal here was a rubber
     * stamp that could not see a producer disagreeing with the reference. */
    EntryExpectation want = {0};
    entry_expectation(IMPORTER, "ext", "import", &want);
    char *import_name = want.import_name;
    char *main_name = want.main_name;
    /* That the reference REFUSES the fixture's own body, which is the whole
     * reason naming_source exists. Measured, not assumed: without this the
     * substitution could one day become unnecessary and the gate would be
     * asking the reference about a different program than it claims to. The
     * code is 503, "ret requires unavailable stack/frame balance proof", and
     * it is a refusal of the REFERENCE's own, so pinning it is safe. */
    {
      NtObject refused;
      NtDiagnostic error;
      int code = 0;
      memset(&refused, 0, sizeof refused);
      memset(&error, 0, sizeof error);
      if (!nt_object_compile(&(NtFInput){"importer", (char *)IMPORTER, strlen(IMPORTER)},
                             1, &refused, &error))
        code = (int)error.code;
      nt_object_free(&refused);
      CHECKL(code == 503, "the reference refuses the importer's own call/ret body", "import");
    }
    CHECKL(import_name && main_name && want.entry != UINT32_MAX,
           "the C reference names the importer's own declarations and its entry", "import");
    /* The entry this gate compares against is the reference's, and so is the
     * export bit on the expectation's main. Writing the literal 2 here is what
     * let a producer that marked a NON-exported main as exported pass: the
     * oracle and the producer agreed with each other and neither was asking. */
    CHECKL(want.entry == 2, "the reference names an exported main as symbol two", "import");

    /* 0. THE naming check, over all three producer shapes. See
     *    expect_reference_names for why it is a whole string comparison and
     *    not a suffix: a suffix against "main" would pass for a producer that
     *    qualified the import with the wrong module, which is the exact defect
     *    this gate used to be unable to see. */
    expect_reference_names(&image, IMPORTER, "ext", 0, "import");

    /* 1. the object bytes, against the C reference with the canonical text */
    {
      uint8_t text[6] = {0};
      size_t text_size = 0;
      NtX64Operand call_target = {.kind = NT_X64_REL, .imm = 0, .is_signed = 1};
      text_size += encode_(text + text_size, "call", &call_target, 1);
      text_size += encode_(text + text_size, "ret", NULL, 0);
      CHECK(text_size == 6, "C call ret size");
      if (canonical && import_name && main_name) {
        /* Both names are the ones the C reference writes for the IMPORTER's
         * own declarations, so the oracle is the reference and not a pair of
         * bare literals. The reference writes them in name order, and it
         * writes "api.echo" before "m.main", so the import is symbol one and
         * the REL32 names symbol one. That order is not an assumption: check 0
         * above compares the producer's table against the reference's table
         * entry for entry, so a producer that ordered them the other way is
         * already red before this byte comparison runs. */
        NtObjectSymbol symbols[2];
        NtObjectReloc reloc = {1, NT_OBJECT_REL32, 1, 1, 0};
        NtObject oracle;
        NtBuffer expected = {0};
        NtDiagnostic error = {0};
        memset(symbols, 0, sizeof symbols);
        symbols[0].name = import_name;
        symbols[0].contract = canonical;
        symbols[0].section = 0; symbols[0].flags = NT_OBJECT_IMPORT | NT_OBJECT_FUNCTION;
        symbols[1].name = main_name;
        symbols[1].contract = canonical;
        symbols[1].section = 1; symbols[1].flags = NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION;
        symbols[1].size = 6;
        memset(&oracle, 0, sizeof oracle);
        oracle.target = 1; oracle.entry_symbol = want.entry;
        oracle.sections[0] = (NtBuffer){text, sizeof text, sizeof text};
        oracle.symbols = symbols; oracle.symbol_count = 2;
        oracle.relocations = &reloc; oracle.relocation_count = 1;
        CHECK(nt_object_write(&oracle, &expected, &error), "C NXO oracle write");
        memset(out_a, 0xcc, sizeof out_a);
        {
          uint64_t code = run_producer(&image, IMPORTER, 0, out_a, sizeof out_a);
          uint64_t size = r64(out_a);
          int same = code == 0 && size == expected.size &&
                     !memcmp(out_a + 8, expected.bytes, expected.size);
          CHECK(same, "NXO import byte parity against the canonical contract");
          if (!same && code == 0)
            report_object_diff(out_a + 8, size, expected.bytes, expected.size, "import");
        }
        free(expected.bytes);
      }
    }

    /* 2. the bare target variant, sorted symbol order and the canonical text */
    {
      static const char *BARE =
          "module m\ntarget x86_64-nexora-none\nimport api.echo as zeta: fn()->u64\n"
          "effects {}\nclobbers {}\nsection .text {\nexport fn main()->u64\n"
          "effects {}\nclobbers {} {\ncall zeta()\nret\n}\n}\n";
      char *bare_contract = canonical_contract(
          "module d\ntarget x86_64-nexora-none\nsection .text {\n"
          "export fn zeta()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "zeta");
      /* Names AND entry, all asked of the reference for this fixture's own
       * declarations. See c_reference_entry for why the entry is not a literal. */
      EntryExpectation bwant = {0};
      entry_expectation(BARE, "zeta", "bare", &bwant);
      char *bare_import = bwant.import_name;
      char *bare_main = bwant.main_name;
      CHECKL(bare_contract && bare_import && bare_main && bwant.entry != UINT32_MAX,
             "C canonical contract, names and entry for the bare target", "bare");
      /* The selector asks for the symbol the reference writes with BOTH bits.
       * A non-exported main is selected by NT_OBJECT_FUNCTION alone, so a
       * selector without the export bit would name a different shape than the
       * fixture declares -- and would find it in a source that has one. */
      CHECKL(bwant.entry == 2, "the reference names an exported main as symbol two", "bare");
      expect_reference_names(&image, BARE, "zeta", 0, "bare");
      if (bare_contract && bare_import && bare_main) {
        uint8_t text[6] = {0};
        size_t text_size = 0;
        NtX64Operand call_target = {.kind = NT_X64_REL, .imm = 0, .is_signed = 1};
        NtObjectSymbol symbols[2];
        /* section, kind, target, offset, addend: the reference names this
         * unit's import by its PATH, "api.echo", and that sorts before
         * "m.main", so the import is symbol one and the REL32 names symbol
         * one. The names are the reference's own answer for this fixture's own
         * declarations. The alias, "zeta", appears in neither of them: the
         * reference keeps it in f->name and never reads it back out. */
        NtObjectReloc reloc = {1, NT_OBJECT_REL32, 1, 1, 0};
        NtObject oracle;
        NtBuffer expected = {0};
        NtDiagnostic error = {0};
        text_size += encode_(text + text_size, "call", &call_target, 1);
        text_size += encode_(text + text_size, "ret", NULL, 0);
        memset(symbols, 0, sizeof symbols);
        symbols[0].name = bare_import;
        symbols[0].contract = bare_contract;
        symbols[0].section = 0; symbols[0].flags = NT_OBJECT_IMPORT | NT_OBJECT_FUNCTION;
        symbols[1].name = bare_main;
        symbols[1].contract = bare_contract;
        symbols[1].section = 1; symbols[1].flags = NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION;
        symbols[1].size = 6;
        memset(&oracle, 0, sizeof oracle);
        oracle.target = 2; oracle.entry_symbol = bwant.entry;
        oracle.sections[0] = (NtBuffer){text, sizeof text, sizeof text};
        oracle.symbols = symbols; oracle.symbol_count = 2;
        oracle.relocations = &reloc; oracle.relocation_count = 1;
        CHECK(nt_object_write(&oracle, &expected, &error), "C bare oracle write");
        memset(out_a, 0xcc, sizeof out_a);
        {
          uint64_t code = run_producer(&image, BARE, 0, out_a, sizeof out_a);
          uint64_t size = r64(out_a);
          int same = code == 0 && size == expected.size &&
                     !memcmp(out_a + 8, expected.bytes, expected.size);
          CHECK(same, "bare NXO sorted import parity against the canonical contract");
          if (!same && code == 0)
            report_object_diff(out_a + 8, size, expected.bytes, expected.size, "bare");
        }
        free(expected.bytes);
      }
      entry_expectation_free(&bwant); free(bare_contract);
    }

    /* 3. the decisive case: a Nova object linked against a C produced
     *    definition. Before the contract text of x64_lower_nxo existed this
     *    merge answered 825 and no C object could ever be linked. */
    expect_link(&image, IMPORTER, DEFINITION, import_name,
                "Nova import object linked against a C produced definition");

    /* 4. a contract that differs from the canonical text in one byte is still
     *    refused with 825, so the repair did not weaken the comparison. */
    if (canonical && import_name) {
      char perturbed[512];
      size_t n = strlen(canonical);
      CHECK(n + 1 < sizeof perturbed, "perturbed contract fits");
      memcpy(perturbed, canonical, n + 1);
      /* the last hex digit of the clobbers mask, a single byte */
      perturbed[n - 21] = (perturbed[n - 21] == '0') ? '1' : '0';
      expect_link_refused(&image, IMPORTER, DEFINITION, import_name, perturbed, 825,
                          "one perturbed contract byte still refuses 825");
      /* 5. and the historical two byte placeholder refuses too, which is the
       *    exact refusal this lot removed. */
      expect_link_refused(&image, IMPORTER, DEFINITION, import_name, "v0", 825,
                          "the v0 placeholder still refuses 825");
    }

    /* 6. the canonical text survives serialisation: the C reader and the Nova
     *    inspector both hand it back byte for byte. */
    if (canonical) expect_contract_round_trip(&image, IMPORTER, NULL, "ext",
                                              strlen(canonical),
                                              "contract round trip through nt_object_read and nxo_inspect");

    /* 7. a data symbol carries the data form of the contract, with the type
     *    and the section the reference prints. */
    {
      static const char *WITH_DATA =
          "module m\ntarget x86_64-nexora-uefi\nimport api.echo as ext: fn()->u64\n"
          "effects {}\nclobbers {}\n"
          "section .rdata {\ndata table: u8 = 5\n}\n"
          "section .data {\ndata counter: u64 = 9\n}\n"
          "section .text {\nexport fn main()->u64\n"
          "effects {}\nclobbers {} {\ncall ext()\nret\n}\n}\n";
      static const char *DATA_SOURCE =
          "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
          "export fn ext()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n"
          "section .rdata {\nexport data table: u8 = 5\n}\n"
          "section .data {\nexport data counter: u64 = 9\n}\n";
      static NtObject object;
      NtDiagnostic error;
      uint64_t code, size;
      char *rdata = NULL, *data = NULL;
      /* Both names are asked of the C reference and neither is typed. The
       * producer side is WITH_DATA, so its data symbols are the reference's
       * answer for WITH_DATA's own declarations; the contract text comes from
       * DATA_SOURCE, whose own module is `d`, selected by the reference's own
       * section and flag word rather than by a spelled out name. The contract
       * text mentions no module, so the two sides' names need not agree and
       * comparing the contracts across them is exactly the point. */
      char *data_naming = naming_source(WITH_DATA, "ext");
      char *table_name = data_naming
          ? c_reference_name(data_naming, 2, NT_OBJECT_VARIABLE) : NULL;
      char *counter_name = data_naming
          ? c_reference_name(data_naming, 3, NT_OBJECT_VARIABLE) : NULL;
      unsigned k;
      naming_source_is_the_fixture(WITH_DATA, data_naming, "import with data");
      expect_reference_names(&image, WITH_DATA, "ext", 4, "import with data");
      memset(&object, 0, sizeof object);
      memset(&error, 0, sizeof error);
      rdata = c_reference_contract(DATA_SOURCE, 2, NT_OBJECT_EXPORT | NT_OBJECT_VARIABLE);
      data = c_reference_contract(DATA_SOURCE, 3, NT_OBJECT_EXPORT | NT_OBJECT_VARIABLE);
      CHECK(table_name && counter_name, "C canonical names for the producer's data symbols");
      CHECK(rdata && data, "the C reference wrote both data contracts");
      memset(out_a, 0xcc, sizeof out_a);
      code = run_producer(&image, WITH_DATA, 4, out_a, sizeof out_a);
      size = r64(out_a);
      CHECK(code == 0 && size <= sizeof out_a - 8, "producer object with data symbols");
      if (code == 0 && nt_object_read(out_a + 8, (size_t)size, &object, &error)) {
        int saw_rdata = 0, saw_data = 0;
        CHECK(object.symbol_count == 4, "four symbols, two of them data");
        for (k = 0; k < object.symbol_count; k++) {
          if (table_name && !strcmp(object.symbols[k].name, table_name)) {
            saw_rdata = 1;
            CHECK(rdata && !strcmp(object.symbols[k].contract, rdata), "rdata contract text");
            if (rdata && strcmp(object.symbols[k].contract, rdata))
              fprintf(stderr, "DATA_CONTRACT nova=[%s] C=[%s]\n",
                      object.symbols[k].contract, rdata);
          }
          if (counter_name && !strcmp(object.symbols[k].name, counter_name)) {
            saw_data = 1;
            CHECK(data && !strcmp(object.symbols[k].contract, data), "data contract text");
            if (data && strcmp(object.symbols[k].contract, data))
              fprintf(stderr, "DATA_CONTRACT nova=[%s] C=[%s]\n",
                      object.symbols[k].contract, data);
          }
        }
        CHECK(saw_rdata && saw_data, "both data symbols are present");
        nt_object_free(&object);
      } else if (code == 0) {
        CHECK(0, "C reads the object carrying data symbols");
      }
      free(table_name);
      free(counter_name);
      free(data_naming);
      free(rdata);
      free(data);
    }

    /* 8. the historical refusals of the import producer are unchanged */
    {
      uint8_t short_out[128];
      unsigned j;
      int intact;
      uint64_t code;
      memset(short_out, 0xcc, sizeof short_out);
      code = run_producer(&image, IMPORTER, 0, short_out, sizeof short_out);
      intact = (code == 800);
      for (j = 0; j < sizeof short_out; j++) intact &= short_out[j] == 0xcc;
      CHECK(intact, "short output transactional");
    }
    rejected(&image,
             "module m\ntarget x86_64-nexora-uefi\nimport api.echo as ext: fn()->u64\n"
             "effects {}\nclobbers {}\nsection .text {\nfn main()->u64\n"
             "effects {}\nclobbers {} {\ncall bad()\nret\n}\n}\n",
             "unknown alias transactional");
    rejected(&image,
             "module m\ntarget x86_64-nexora-uefi\nimport api.echo as ext: fn()->u64\n"
             "effects {}\nclobbers {}\nsection .text {\nfn main()->u64\n"
             "effects {}\nclobbers {} {\ncall ext(1)\nret\n}\n}\n",
             "nonzero arity transactional");
    rejected(&image,
             "module m\ntarget x86_64-nexora-uefi\nimport api.echo as ext: fn()->u64\n"
             "effects {}\nclobbers {}\nsection .text {\nfn main()->u64\n"
             "effects {}\nclobbers {} {\ncall ext()\nud2\nret\n}\n}\n",
             "extra statement transactional");
    free(canonical);
    entry_expectation_free(&want);
  }
  if (image.memory) nova_host_unmap(&image);
  if (compiled) nt_artifact_free(&compiler);
  for (i = 0; i < 18; i++) free(sources[i]);
  printf("NTASM_NOVA_X64_LOWER_NXO_IMPORT checks=%u failures=%u cases=%u\n",
         checks, failures, cases);
  return failures ? 1 : 0;
}
