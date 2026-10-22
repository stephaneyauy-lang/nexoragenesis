#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Linker phase 1 for a variable length link unit: merge_list mirrors
 * compiler/c/ntasm/formats/object_link.c over 1..64 objects. The C reference is
 * the oracle for every accepted case; Nova keeps the 800/820/821/823/824/825/
 * 826 codes of the pairwise merge. */
static unsigned checks, failures, cases;
#define CHECK(c, m)                                                          \
  do {                                                                       \
    checks++;                                                                \
    if (!(c)) {                                                              \
      failures++;                                                            \
      fprintf(stderr, "FAIL %s\n", m);                                       \
    }                                                                        \
  } while (0)

#define OUT_CAPACITY 65536
#define WIDE 40000
static const uint8_t guard = 0xcc;

static char *load(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f)
    return NULL;
  fseek(f, 0, SEEK_END);
  long z = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) {
    free(b);
    fclose(f);
    return NULL;
  }
  fclose(f);
  b[z] = 0;
  *n = (size_t)z;
  return b;
}

static uint64_t r64(const uint8_t *p) {
  uint64_t v = 0;
  for (unsigned i = 0; i < 8; i++)
    v |= (uint64_t)p[i] << (i * 8);
  return v;
}

typedef struct {
  const char *name;
  const char *contract;
  uint32_t section, flags;
  uint64_t offset, size;
} Sym;

static NtBuffer build(uint32_t target, const uint8_t *t, size_t tn,
                      const uint8_t *r, size_t rn, const uint8_t *d, size_t dn,
                      const Sym *syms, size_t symn, const NtObjectReloc *rel,
                      size_t reln, uint32_t entry) {
  NtObject o = {0};
  NtObjectSymbol *table = NULL;
  NtBuffer file = {0};
  NtDiagnostic e = {0};
  o.target = target;
  o.sections[0] = (NtBuffer){(uint8_t *)t, tn, tn};
  o.sections[1] = (NtBuffer){(uint8_t *)r, rn, rn};
  o.sections[2] = (NtBuffer){(uint8_t *)d, dn, dn};
  if (symn) {
    table = calloc(symn, sizeof *table);
    if (!table) {
      CHECK(0, "symbol table allocation");
      return file;
    }
    for (size_t i = 0; i < symn; i++)
      table[i] = (NtObjectSymbol){(char *)syms[i].name, (char *)syms[i].contract,
                                  syms[i].section,    syms[i].flags,
                                  syms[i].offset,     syms[i].size};
    o.symbols = table;
    o.symbol_count = symn;
  }
  if (reln) {
    o.relocations = (NtObjectReloc *)rel;
    o.relocation_count = reln;
  }
  o.entry_symbol = entry;
  CHECK(nt_object_write(&o, &file, &e), "oracle writes NXO");
  if (!file.bytes)
    fprintf(stderr, "E write %s\n", e.message);
  free(table);
  return file;
}

/* One arena holds count 16-byte (offset,length) descriptors then the payloads:
 * the layout merge_list reads, because only buf<u8> crosses the boundary. */
static NtBuffer arena(NtBuffer *files, size_t count) {
  NtBuffer a = {0};
  size_t total = count * 16;
  for (size_t i = 0; i < count; i++)
    total += files[i].size;
  a.bytes = calloc(total ? total : 1, 1);
  a.size = a.capacity = total;
  if (!a.bytes) {
    CHECK(0, "arena allocation");
    return a;
  }
  size_t at = count * 16;
  for (size_t i = 0; i < count; i++) {
    uint8_t rec[16];
    for (unsigned b = 0; b < 8; b++) {
      rec[b] = (uint8_t)(at >> (b * 8));
      rec[8 + b] = (uint8_t)(files[i].size >> (b * 8));
    }
    memcpy(a.bytes + i * 16, rec, 16);
    if (files[i].size)
      memcpy(a.bytes + at, files[i].bytes, files[i].size);
    at += files[i].size;
  }
  return a;
}

typedef struct {
  uint64_t returned, runtime, source, offset;
  uint8_t out[OUT_CAPACITY];
} Run;

static Run run(const NovaHostImage *i, NtBuffer *a, uint64_t count,
               uint64_t outn, uint64_t mode) {
  Run x = {0};
  memset(x.out, guard, sizeof x.out);
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t ih = nova_borrow_v2(&c, a->bytes, a->size, 0);
  uint64_t oh = nova_borrow_v2(&c, x.out, outn, 1);
  uint64_t aux = nova_borrow_v2(&c, NULL, 0, 0);
  uint64_t args[] = {ih, a->size, count, oh, outn, mode, aux, 0};
  x.returned = i->entry(&c, args, 8);
  x.runtime = c.error;
  x.source = c.error_source;
  x.offset = c.error_offset;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return x;
}

/* mode 2: two independent borrows, so a limit above the single-buffer ceiling
 * is observable. */
static Run run_two(const NovaHostImage *i, NtBuffer *left, NtBuffer *right) {
  Run x = {0};
  memset(x.out, guard, sizeof x.out);
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t lh = nova_borrow_v2(&c, left->bytes, left->size, 0);
  uint64_t rh = nova_borrow_v2(&c, right->bytes, right->size, 0);
  uint64_t oh = nova_borrow_v2(&c, x.out, OUT_CAPACITY, 1);
  uint64_t args[] = {lh, left->size, 2, oh, OUT_CAPACITY, 2, rh, right->size};
  x.returned = i->entry(&c, args, 8);
  x.runtime = c.error;
  x.source = c.error_source;
  x.offset = c.error_offset;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return x;
}

static void report(const char *n, Run *x) {
  fprintf(stderr,
          "  %s ret=%llu runtime=%llu source=%llu offset=%llu\n", n,
          (unsigned long long)x->returned, (unsigned long long)x->runtime,
          (unsigned long long)x->source, (unsigned long long)x->offset);
}

static void expect_error(const NovaHostImage *i, const char *n, NtBuffer *files,
                         size_t count, uint64_t outn, uint64_t code) {
  NtBuffer a = arena(files, count);
  Run x = run(i, &a, (uint64_t)count, outn, 0);
  cases++;
  checks++;
  if (x.returned != code || x.runtime || x.out[0] != guard || x.out[1] != guard) {
    failures++;
    fprintf(stderr, "FAIL error %s ret=%llu runtime=%llu want=%llu\n", n,
            (unsigned long long)x.returned, (unsigned long long)x.runtime,
            (unsigned long long)code);
    report(n, &x);
  }
  free(a.bytes);
}

/* Links the same units with the C reference and reports byte parity. */
static void expect_oracle(const char *n, const uint8_t *got, uint64_t gotn,
                          NtBuffer *files, size_t count);

/* merge and merge_list must emit the same image for the same two units. */
static void expect_identity(const NovaHostImage *i, const char *n,
                            NtBuffer *files) {
  NtBuffer a = arena(files, 2);
  Run list = run(i, &a, 2, OUT_CAPACITY, 0);
  Run pair = run(i, &a, 2, OUT_CAPACITY, 1);
  cases++;
  CHECK(list.returned == 0 && list.runtime == 0, "merge_list two units");
  CHECK(pair.returned == 0 && pair.runtime == 0, "merge two units");
  if (list.returned == 0 && pair.returned == 0) {
    uint64_t ls = r64(list.out), ts = r64(pair.out);
    int same = ls == ts && !memcmp(list.out, pair.out, (size_t)ls + 8);
    if (!same)
      fprintf(stderr, "FAIL identity %s merge_list=%llu merge=%llu\n", n,
              (unsigned long long)ls, (unsigned long long)ts);
    CHECK(same, "merge_list byte identical to merge at count 2");
    expect_oracle(n, list.out + 8, ls, files, 2);
  } else {
    report(n, &list);
    report(n, &pair);
  }
  free(a.bytes);
}

/* Links the same units with the C reference and reports byte parity. */
static void expect_oracle(const char *n, const uint8_t *got, uint64_t gotn,
                          NtBuffer *files, size_t count) {
  NtObject *objs = calloc(count, sizeof *objs);
  NtObject linked = {0};
  NtBuffer oracle = {0};
  NtDiagnostic e = {0};
  int ok = 1;
  cases++;
  for (size_t i = 0; i < count; i++)
    if (!nt_object_read(files[i].bytes, files[i].size, &objs[i], &e)) {
      ok = 0;
      break;
    }
  if (ok && !nt_object_link(objs, count, &linked, &e))
    ok = 0;
  if (ok && !nt_object_write(&linked, &oracle, &e))
    ok = 0;
  CHECK(ok, "C oracle links");
  int parity = ok && gotn == oracle.size &&
               !memcmp(got, oracle.bytes, oracle.size);
  if (!parity) {
    size_t limit = gotn < oracle.size ? (size_t)gotn : oracle.size;
    size_t first = 0;
    while (first < limit && got[first] == oracle.bytes[first])
      first++;
    fprintf(stderr,
            "FAIL parity %s nova=%llu oracle=%zu first=%zu novaByte=%u "
            "oracleByte=%u oracleError=%s\n",
            n, (unsigned long long)gotn, oracle.size, first,
            first < gotn ? got[first] : 0,
            first < oracle.size ? oracle.bytes[first] : 0, e.message);
  }
  CHECK(parity, "C oracle byte parity");
  free(oracle.bytes);
  nt_object_free(&linked);
  for (size_t i = 0; i < count; i++)
    nt_object_free(&objs[i]);
  free(objs);
}

static void expect_structure(const char *n, const uint8_t *got, uint64_t gotn,
                             uint32_t target, uint32_t entry, size_t symbols,
                             size_t relocations) {
  NtObject merged = {0};
  NtDiagnostic e = {0};
  cases++;
  CHECK(gotn > 0 && nt_object_read(got, gotn, &merged, &e),
        "merged NXO reads");
  if (merged._owned) {
    CHECK(merged.target == target, "merged target");
    CHECK(merged.entry_symbol == entry, "merged entry");
    CHECK(merged.symbol_count == symbols, "merged symbol count");
    CHECK(merged.relocation_count == relocations, "merged relocation count");
    nt_object_free(&merged);
  }
  (void)n;
}

/* merge_list alone, oracle compared: no identity clause, so a three unit case can
 * isolate the layout a trailing empty section produces. */
static void expect_list_oracle(const NovaHostImage *i, const char *n,
                               NtBuffer *files, size_t count) {
  NtBuffer a = arena(files, count);
  Run x = run(i, &a, (uint64_t)count, OUT_CAPACITY, 0);
  cases++;
  CHECK(x.returned == 0 && x.runtime == 0, "merge_list accepts");
  if (x.returned == 0 && !x.runtime)
    expect_oracle(n, x.out + 8, r64(x.out), files, count);
  else
    report(n, &x);
  free(a.bytes);
}

/* One alignment shape at count 2: merge_list and the pairwise merge must agree
 * and the pair must match object_link.c byte for byte. The shapes are the ones
 * that separate the unconditional align16 of object_link.c:78 from an alignment
 * applied only to a non empty section, and from an 8 byte alignment. */
static void expect_shape(const NovaHostImage *i, const char *n, size_t lt,
                         size_t lr, size_t ld, size_t rt, size_t rr, size_t rd) {
  size_t lz[3] = {lt, lr, ld}, rz[3] = {rt, rr, rd};
  uint8_t *lp[3] = {0}, *rp[3] = {0};
  for (unsigned k = 0; k < 3; k++) {
    if (lz[k]) {
      lp[k] = calloc(lz[k], 1);
      CHECK(lp[k] != NULL, "shape left allocation");
      if (lp[k])
        memset(lp[k], (int)(0x11 * (k + 1)), lz[k]);
    }
    if (rz[k]) {
      rp[k] = calloc(rz[k], 1);
      CHECK(rp[k] != NULL, "shape right allocation");
      if (rp[k])
        memset(rp[k], (int)(0x11 * (k + 1)), rz[k]);
    }
  }
  NtBuffer L = build(1, lp[0], lt, lp[1], lr, lp[2], ld, NULL, 0, NULL, 0, 0);
  NtBuffer R = build(1, rp[0], rt, rp[1], rr, rp[2], rd, NULL, 0, NULL, 0, 0);
  NtBuffer two[2] = {L, R};
  expect_identity(i, n, two);
  for (unsigned k = 0; k < 3; k++) {
    free(lp[k]);
    free(rp[k]);
  }
  free(L.bytes);
  free(R.bytes);
}

/* Three units whose last two are empty in one section. object_link.c:79 aligns
 * the running total for an empty section too, so the merged size is the 16 byte
 * boundary and not the unaligned total the first unit left behind. */
static void expect_empty_tail(const NovaHostImage *i, const char *n,
                              unsigned section, size_t first) {
  uint8_t *head = calloc(first, 1);
  CHECK(head != NULL, "empty tail allocation");
  NtBuffer one = {0}, rest = {0}, trio[3];
  if (section == 1)
    one = build(1, head, first, NULL, 0, NULL, 0, NULL, 0, NULL, 0, 0);
  else if (section == 2)
    one = build(1, NULL, 0, head, first, NULL, 0, NULL, 0, NULL, 0, 0);
  else
    one = build(1, NULL, 0, NULL, 0, head, first, NULL, 0, NULL, 0, 0);
  rest = build(1, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, 0);
  trio[0] = one;
  trio[1] = rest;
  trio[2] = rest;
  expect_list_oracle(i, n, trio, 3);
  free(head);
  free(one.bytes);
  free(rest.bytes);
}

int main(void) {
  const char *paths[] = {"tests/nova/tests/nxo-merge-list-entry.nova",
                         "compiler/nova/formats/nxo/nxo_merge.nova",
                         "compiler/nova/formats/nxo/nxo.nova",
                         "compiler/nova/formats/pe/pe.nova"};
  char *sources[4] = {0};
  NtFInput inputs[4];
  for (unsigned i = 0; i < 4; i++) {
    size_t n = 0;
    sources[i] = load(paths[i], &n);
    inputs[i] = (NtFInput){paths[i], sources[i], n};
  }
  CHECK(sources[0] && sources[1] && sources[2] && sources[3], "sources load");
  NtArtifact a = {0};
  int compiled = sources[0] && sources[1] && sources[2] && sources[3] &&
                 nova_compile_many_v2(inputs, 4, &a);
  CHECK(compiled, "modules compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", a.error.code, a.error.line, a.error.column,
            a.error.message);
  NovaHostImage image = {0};
  CHECK(compiled && nova_host_map(&a, &image), "image maps");

  if (image.memory) {
    const uint8_t body[8] = {0xe8, 0, 0, 0, 0, 0xc3, 0x90, 0x90};
    const uint8_t ro[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t rw[8] = {9, 10, 11, 12, 13, 14, 15, 16};

    /* A exports m.f and carries the entry; B and C import it; C also exports
     * m.g and relocates against both of its own sections. */
    Sym sa[] = {{"m.f", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 8}};
    Sym sb[] = {{"m.f", "fn:u64", 0, NT_OBJECT_FUNCTION | NT_OBJECT_IMPORT, 0, 0}};
    Sym sc[] = {{"m.f", "fn:u64", 0, NT_OBJECT_FUNCTION | NT_OBJECT_IMPORT, 0, 0},
                {"m.g", "data:u8", 2, NT_OBJECT_VARIABLE | NT_OBJECT_EXPORT, 1, 2}};
    NtObjectReloc rb[] = {{1, NT_OBJECT_REL32, 1, 1, 0}};
    NtObjectReloc rc[] = {{1, NT_OBJECT_REL32, 1, 1, 0},
                          {2, NT_OBJECT_DIR64, 2, 0, 0},
                          {3, NT_OBJECT_REL32, 1, 0, 0}};
    NtBuffer A = build(1, body, 8, NULL, 0, NULL, 0, sa, 1, NULL, 0, 1);
    NtBuffer B = build(1, body, 8, NULL, 0, NULL, 0, sb, 1, rb, 1, 0);
    NtBuffer C = build(1, body, 8, ro, 8, rw, 8, sc, 2, rc, 3, 0);

    /* 1. three objects, one exported definition consumed twice. */
    NtBuffer three[3] = {A, B, C};
    NtBuffer a3 = arena(three, 3);
    Run r3 = run(&image, &a3, 3, OUT_CAPACITY, 0);
    cases++;
    CHECK(r3.returned == 0 && r3.runtime == 0, "three objects link");
    if (r3.returned || r3.runtime)
      report("three", &r3);
    if (r3.returned == 0) {
      uint64_t size = r64(r3.out);
      expect_oracle("three objects", r3.out + 8, size, three, 3);
      expect_structure("three objects", r3.out + 8, size, 1, 1, 2, 4);
      NtObject m = {0};
      NtDiagnostic e = {0};
      if (size && nt_object_read(r3.out + 8, size, &m, &e) && m._owned) {
        CHECK(m.symbol_count == 2 && !strcmp(m.symbols[0].name, "m.f") &&
                  !strcmp(m.symbols[1].name, "m.g"),
              "three object symbols sorted");
        CHECK(m.symbols[0].offset == 0 && m.symbols[0].size == 8 &&
                  (m.symbols[0].flags & NT_OBJECT_IMPORT) == 0,
              "import folded onto the definition");
        CHECK(m.symbols[1].offset == 1 && m.symbols[1].section == 2,
              "rightmost definition rebased");
        CHECK(m.sections[0].size == 40 && m.sections[1].size == 8 &&
                  m.sections[2].size == 8,
              "three object section totals");
        CHECK(m.relocation_count == 4 && m.relocations[0].offset == 17 &&
                  m.relocations[0].target == 1 && m.relocations[1].offset == 33 &&
                  m.relocations[2].section == 2 && m.relocations[2].target == 2 &&
                  m.relocations[3].section == 3 && m.relocations[3].target == 1,
              "three object relocation remap");
        nt_object_free(&m);
      }
      int guarded = 1;
      for (size_t i = 8 + size; i < OUT_CAPACITY; i++)
        if (r3.out[i] != guard)
          guarded = 0;
      CHECK(guarded, "three object output guards");
    }
    free(a3.bytes);

    /* 2. four objects chained c.a -> c.b -> c.c. */
    Sym s1[] = {{"c.a", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 8}};
    Sym s2[] = {{"c.a", "fn:u64", 0, NT_OBJECT_FUNCTION | NT_OBJECT_IMPORT, 0, 0},
                {"c.b", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 8}};
    Sym s3[] = {{"c.b", "fn:u64", 0, NT_OBJECT_FUNCTION | NT_OBJECT_IMPORT, 0, 0},
                {"c.c", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 8}};
    Sym s4[] = {{"c.c", "fn:u64", 0, NT_OBJECT_FUNCTION | NT_OBJECT_IMPORT, 0, 0}};
    NtBuffer P1 = build(1, body, 8, NULL, 0, NULL, 0, s1, 1, NULL, 0, 1);
    NtBuffer P2 = build(1, body, 8, NULL, 0, NULL, 0, s2, 2, rb, 1, 0);
    NtBuffer P3 = build(1, body, 8, NULL, 0, NULL, 0, s3, 2, rb, 1, 0);
    NtBuffer P4 = build(1, body, 8, NULL, 0, NULL, 0, s4, 1, rb, 1, 0);
    NtBuffer four[4] = {P1, P2, P3, P4};
    NtBuffer a4 = arena(four, 4);
    Run r4 = run(&image, &a4, 4, OUT_CAPACITY, 0);
    cases++;
    CHECK(r4.returned == 0 && r4.runtime == 0, "four objects link");
    if (r4.returned || r4.runtime)
      report("four", &r4);
    if (r4.returned == 0) {
      uint64_t size = r64(r4.out);
      expect_oracle("four objects", r4.out + 8, size, four, 4);
      expect_structure("four objects", r4.out + 8, size, 1, 1, 3, 3);
      NtObject m = {0};
      NtDiagnostic e = {0};
      if (size && nt_object_read(r4.out + 8, size, &m, &e) && m._owned) {
        CHECK(m.sections[0].size == 56, "chain text total");
        CHECK(m.symbols[0].offset == 0 && m.symbols[1].offset == 16 &&
                  m.symbols[2].offset == 32,
              "chain symbols rebased");
        CHECK(m.relocation_count == 3 && m.relocations[0].offset == 17 &&
                  m.relocations[0].target == 1 &&
                  m.relocations[1].offset == 33 &&
                  m.relocations[1].target == 2 &&
                  m.relocations[2].offset == 49 &&
                  m.relocations[2].target == 3,
              "chain relocation remap");
        nt_object_free(&m);
      }
    }
    free(a4.bytes);

    /* 3. degenerate single unit: already closed, so the link is a copy. */
    Sym solo_syms[] = {{"u.a", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 8},
                       {"u.b", "data:u8", 2, NT_OBJECT_VARIABLE | NT_OBJECT_EXPORT, 1, 2}};
    NtBuffer solo = build(1, body, 8, ro, 8, rw, 8, solo_syms, 2, NULL, 0, 1);
    NtBuffer one[1] = {solo};
    NtBuffer a1 = arena(one, 1);
    Run r1 = run(&image, &a1, 1, OUT_CAPACITY, 0);
    cases++;
    CHECK(r1.returned == 0 && r1.runtime == 0, "single unit links");
    if (r1.returned || r1.runtime)
      report("single", &r1);
    if (r1.returned == 0) {
      uint64_t size = r64(r1.out);
      expect_oracle("single unit", r1.out + 8, size, one, 1);
      expect_structure("single unit", r1.out + 8, size, 1, 1, 2, 0);
      int same = size == solo.size && !memcmp(r1.out + 8, solo.bytes, solo.size);
      CHECK(same, "single closed unit is byte identical");
    }
    free(a1.bytes);

    /* 4. two units, the second one a library: merge and merge_list agree.
     * Three orders cover an entry on the left, an entry on the right, and a
     * right unit that mixes an import with a definition of its own. */
    {
      NtBuffer ab[2] = {A, B};
      expect_identity(&image, "two units entry left", ab);
      NtBuffer a2 = arena(ab, 2);
      Run r2 = run(&image, &a2, 2, OUT_CAPACITY, 0);
      cases++;
      CHECK(r2.returned == 0 && r2.runtime == 0, "two units link");
      if (r2.returned == 0) {
        uint64_t size = r64(r2.out);
        expect_structure("two units", r2.out + 8, size, 1, 1, 1, 1);
        NtObject m = {0};
        NtDiagnostic e = {0};
        if (size && nt_object_read(r2.out + 8, size, &m, &e) && m._owned) {
          CHECK(m.symbol_count == 1 && !strcmp(m.symbols[0].name, "m.f") &&
                    (m.symbols[0].flags & NT_OBJECT_IMPORT) == 0,
                "definition kept, import dropped");
          CHECK(m.relocation_count == 1 && m.relocations[0].offset == 17 &&
                    m.relocations[0].target == 1,
                "right relocation rebased and resolved");
          nt_object_free(&m);
        }
      }
      free(a2.bytes);
    }
    {
      NtBuffer ba[2] = {B, A};
      expect_identity(&image, "two units entry right", ba);
    }
    {
      NtBuffer ac[2] = {A, C};
      expect_identity(&image, "two units mixed right", ac);
    }
    {
      NtBuffer ca[2] = {C, A};
      expect_identity(&image, "two units mixed left", ca);
    }

    /* 5. the documented ceiling: 64 units of the same target link at once. */
    {
      NtBuffer sixty_four[64];
      sixty_four[0] = A;
      for (size_t i = 1; i < 64; i++)
        sixty_four[i] = B;
      NtBuffer a64 = arena(sixty_four, 64);
      Run r64u = run(&image, &a64, 64, OUT_CAPACITY, 0);
      cases++;
      CHECK(r64u.returned == 0 && r64u.runtime == 0, "sixty four units link");
      if (r64u.returned == 0) {
        uint64_t size = r64(r64u.out);
        expect_oracle("sixty four units", r64u.out + 8, size, sixty_four, 64);
        expect_structure("sixty four units", r64u.out + 8, size, 1, 1, 1, 63);
        NtObject m = {0};
        NtDiagnostic e = {0};
        if (size && nt_object_read(r64u.out + 8, size, &m, &e) && m._owned) {
          CHECK(m.sections[0].size == 1016, "sixty four unit text total");
          CHECK(m.relocation_count == 63 && m.relocations[0].offset == 17 &&
                    m.relocations[0].target == 1 &&
                    m.relocations[62].offset == 1009 &&
                    m.relocations[62].target == 1,
                "sixty four unit relocations all resolved");
          nt_object_free(&m);
        }
      }
      free(a64.bytes);
    }

    /* 6. a unit with no symbol at all still takes a base of its own. */
    {
      NtBuffer empty = build(1, body, 8, NULL, 0, NULL, 0, NULL, 0, NULL, 0, 0);
      NtBuffer with_empty[3] = {A, empty, B};
      NtBuffer ae = arena(with_empty, 3);
      Run re = run(&image, &ae, 3, OUT_CAPACITY, 0);
      cases++;
      CHECK(re.returned == 0 && re.runtime == 0, "empty middle unit links");
      if (re.returned == 0) {
        uint64_t size = r64(re.out);
        expect_oracle("empty middle unit", re.out + 8, size, with_empty, 3);
        expect_structure("empty middle unit", re.out + 8, size, 1, 1, 1, 1);
        NtObject m = {0};
        NtDiagnostic e = {0};
        if (size && nt_object_read(re.out + 8, size, &m, &e) && m._owned) {
          CHECK(m.sections[0].size == 40, "empty unit base still reserved");
          CHECK(m.relocation_count == 1 && m.relocations[0].offset == 33,
                "later unit rebased past the empty one");
          nt_object_free(&m);
        }
      }
      free(ae.bytes);
      free(empty.bytes);
    }

    /* 7. refusals: unit count, arena shape, and the merge diagnostic codes. */
    NtBuffer none[1] = {A};
    expect_error(&image, "zero units", none, 0, OUT_CAPACITY, 800);
    NtBuffer many[65];
    for (size_t i = 0; i < 65; i++)
      many[i] = A;
    expect_error(&image, "too many units", many, 65, OUT_CAPACITY, 800);
    {
      NtBuffer bad[1] = {A};
      NtBuffer ab = arena(bad, 1);
      uint8_t *p = malloc(ab.size);
      CHECK(p != NULL, "arena copy allocation");
      memcpy(p, ab.bytes, ab.size);
      for (unsigned b = 0; b < 8; b++)
        p[b] = (uint8_t)((uint64_t)(ab.size + 64) >> (b * 8));
      Run x = {0};
      memset(x.out, guard, sizeof x.out);
      NovaContextV2 c = {0};
      CHECK(nova_context_init_v2(&c), "context init");
      uint64_t ih = nova_borrow_v2(&c, p, ab.size, 0);
      uint64_t oh = nova_borrow_v2(&c, x.out, OUT_CAPACITY, 1);
      uint64_t aux = nova_borrow_v2(&c, NULL, 0, 0);
      uint64_t args[] = {ih, ab.size, 1, oh, OUT_CAPACITY, 0, aux, 0};
      x.returned = image.entry(&c, args, 8);
      x.runtime = c.error;
      x.source = c.error_source;
      x.offset = c.error_offset;
      CHECK(nova_context_destroy_v2(&c), "context cleanup");
      cases++;
      checks++;
      if (x.returned != 800 || x.runtime || x.out[0] != guard) {
        failures++;
        fprintf(stderr, "FAIL error descriptor out of arena ret=%llu runtime=%llu\n",
                (unsigned long long)x.returned, (unsigned long long)x.runtime);
      }
      free(p);
      free(ab.bytes);
    }
    {
      NtBuffer shorty[1] = {A};
      NtBuffer ab = arena(shorty, 1);
      uint8_t *p = malloc(ab.size - 1);
      CHECK(p != NULL, "truncated copy allocation");
      memcpy(p, ab.bytes, ab.size - 1);
      Run x = {0};
      memset(x.out, guard, sizeof x.out);
      NovaContextV2 c = {0};
      CHECK(nova_context_init_v2(&c), "context init");
      uint64_t ih = nova_borrow_v2(&c, p, ab.size - 1, 0);
      uint64_t oh = nova_borrow_v2(&c, x.out, OUT_CAPACITY, 1);
      uint64_t aux = nova_borrow_v2(&c, NULL, 0, 0);
      uint64_t args[] = {ih, ab.size - 1, 1, oh, OUT_CAPACITY, 0, aux, 0};
      x.returned = image.entry(&c, args, 8);
      x.runtime = c.error;
      x.source = c.error_source;
      x.offset = c.error_offset;
      CHECK(nova_context_destroy_v2(&c), "context cleanup");
      cases++;
      checks++;
      if (x.returned != 800 || x.runtime || x.out[0] != guard) {
        failures++;
        fprintf(stderr, "FAIL error truncated unit ret=%llu runtime=%llu\n",
                (unsigned long long)x.returned, (unsigned long long)x.runtime);
      }
      free(p);
      free(ab.bytes);
    }
    {
      NtBuffer bad[1] = {A};
      NtBuffer ab = arena(bad, 1);
      Run x = run(&image, &ab, 1, 8, 0);
      cases++;
      checks++;
      if (x.returned != 822 || x.runtime || x.out[0] != guard) {
        failures++;
        fprintf(stderr, "FAIL error short output ret=%llu runtime=%llu\n",
                (unsigned long long)x.returned, (unsigned long long)x.runtime);
      }
      free(ab.bytes);
    }

    /* 820 mixed target: the third unit disagrees with the first. */
    {
      NtBuffer other = build(2, body, 8, NULL, 0, NULL, 0, sa, 1, NULL, 0, 0);
      NtBuffer mixed[3] = {A, B, other};
      expect_error(&image, "mixed target", mixed, 3, OUT_CAPACITY, 820);
      NtObject *objs = calloc(3, sizeof *objs);
      NtObject linked = {0};
      NtDiagnostic e = {0};
      int ok = 1;
      for (size_t i = 0; i < 3; i++)
        if (!nt_object_read(mixed[i].bytes, mixed[i].size, &objs[i], &e)) {
          ok = 0;
          break;
        }
      if (ok)
        ok = nt_object_link(objs, 3, &linked, &e);
      cases++;
      CHECK(!ok, "C oracle refuses mixed target");
      nt_object_free(&linked);
      for (size_t i = 0; i < 3; i++)
        nt_object_free(&objs[i]);
      free(objs);
      free(other.bytes);
    }

    /* 821 capacity: 40000 + 40000 symbols exceed the 65536 merged budget. */
    {
      char (*names)[8] = calloc(WIDE, 8);
      Sym *wide = calloc(WIDE, sizeof *wide);
      CHECK(names && wide, "wide fixture allocation");
      for (size_t i = 0; i < WIDE; i++) {
        snprintf(names[i], 8, "s%05zu", i);
        wide[i] = (Sym){names[i], "c", 3, NT_OBJECT_VARIABLE, 0, 1};
      }
      NtBuffer w1 = build(1, NULL, 0, NULL, 0, rw, 8, wide, WIDE, NULL, 0, 0);
      NtBuffer w2 = build(1, NULL, 0, NULL, 0, rw, 8, wide, WIDE, NULL, 0, 0);
      NtBuffer wide_pair[2] = {w1, w2};
      expect_error(&image, "symbol capacity", wide_pair, 2, OUT_CAPACITY, 821);
      NtObject *objs = calloc(2, sizeof *objs);
      NtObject linked = {0};
      NtDiagnostic e = {0};
      int ok = 1;
      for (size_t i = 0; i < 2; i++)
        if (!nt_object_read(wide_pair[i].bytes, wide_pair[i].size, &objs[i], &e)) {
          ok = 0;
          break;
        }
      if (ok)
        ok = nt_object_link(objs, 2, &linked, &e);
      cases++;
      CHECK(!ok, "C oracle refuses symbol capacity");
      nt_object_free(&linked);
      for (size_t i = 0; i < 2; i++)
        nt_object_free(&objs[i]);
      free(objs);
      free(w1.bytes);
      free(w2.bytes);
      free(names);
      free(wide);
    }

    /* 821 capacity, aggregate payload: three sections of 22MiB each, so every
     * merged section stays under 64MiB while their sum does not. One arena
     * cannot hold more than the 64MiB borrow limit, so this cap is only
     * reachable through the pairwise merge, whose two units are separate. */
    {
      const size_t big = 23068672;
      uint8_t *payload = calloc(big, 1);
      CHECK(payload != NULL, "aggregate payload allocation");
      NtBuffer left = build(1, payload, big, NULL, 0, NULL, 0, NULL, 0, NULL, 0, 0);
      NtBuffer right = build(1, NULL, 0, payload, big, payload, big, NULL, 0, NULL, 0, 0);
      NtBuffer both[2] = {left, right};
      Run x = run_two(&image, &left, &right);
      cases++;
      checks++;
      if (x.returned != 821 || x.runtime || x.out[0] != guard) {
        failures++;
        fprintf(stderr, "FAIL error aggregate payload ret=%llu runtime=%llu want=821\n",
                (unsigned long long)x.returned, (unsigned long long)x.runtime);
        report("aggregate", &x);
      }
      NtObject *objs = calloc(2, sizeof *objs);
      NtObject linked = {0};
      NtDiagnostic e = {0};
      int ok = 1;
      for (size_t i = 0; i < 2; i++)
        if (!nt_object_read(both[i].bytes, both[i].size, &objs[i], &e)) {
          ok = 0;
          break;
        }
      if (ok)
        ok = nt_object_link(objs, 2, &linked, &e);
      cases++;
      CHECK(!ok, "C oracle refuses aggregate payload");
      nt_object_free(&linked);
      for (size_t i = 0; i < 2; i++)
        nt_object_free(&objs[i]);
      free(objs);
      free(left.bytes);
      free(right.bytes);
      free(payload);
    }

    /* 823 duplicate definition across three units. */
    {
      Sym dup[] = {{"m.f", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 8}};
      NtBuffer dup2 = build(1, body, 8, NULL, 0, NULL, 0, dup, 1, NULL, 0, 0);
      Sym g[] = {{"m.g", "data:u8", 2, NT_OBJECT_VARIABLE | NT_OBJECT_EXPORT, 1, 2}};
      NtBuffer gonly = build(1, body, 8, ro, 8, NULL, 0, g, 1, NULL, 0, 0);
      NtBuffer three_dup[3] = {A, dup2, gonly};
      expect_error(&image, "duplicate definition", three_dup, 3, OUT_CAPACITY,
                   823);
      NtObject *objs = calloc(3, sizeof *objs);
      NtObject linked = {0};
      NtDiagnostic e = {0};
      int ok = 1;
      for (size_t i = 0; i < 3; i++)
        if (!nt_object_read(three_dup[i].bytes, three_dup[i].size, &objs[i], &e)) {
          ok = 0;
          break;
        }
      if (ok)
        ok = nt_object_link(objs, 3, &linked, &e);
      cases++;
      CHECK(!ok, "C oracle refuses duplicate definition");
      nt_object_free(&linked);
      for (size_t i = 0; i < 3; i++)
        nt_object_free(&objs[i]);
      free(objs);
      free(dup2.bytes);
      free(gonly.bytes);
    }

    /* 823 outranks 824: a duplicated name is refused before the imports of the
     * same group are resolved, which is the order object_link.c uses. */
    {
      Sym dup[] = {{"m.f", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 8}};
      NtBuffer dup2 = build(1, body, 8, NULL, 0, NULL, 0, dup, 1, NULL, 0, 0);
      NtBuffer dup_import[3] = {A, dup2, B};
      expect_error(&image, "duplicate before import", dup_import, 3, OUT_CAPACITY,
                   823);
      free(dup2.bytes);
    }

    /* 824 unresolved import in the third unit. */
    {
      Sym h[] = {{"m.h", "fn:u64", 0, NT_OBJECT_FUNCTION | NT_OBJECT_IMPORT, 0, 0}};
      NtBuffer missing = build(1, body, 8, NULL, 0, NULL, 0, h, 1, NULL, 0, 0);
      NtBuffer three_miss[3] = {A, B, missing};
      expect_error(&image, "unresolved import", three_miss, 3, OUT_CAPACITY, 824);
      free(missing.bytes);
    }

    /* 824 import against import, no definition anywhere. */
    {
      NtBuffer two_imp[2] = {B, B};
      expect_error(&image, "import against import", two_imp, 2, OUT_CAPACITY, 824);
    }

    /* 824 definition present but not exported. */
    {
      Sym priv[] = {{"m.f", "fn:u64", 1, NT_OBJECT_FUNCTION, 0, 8}};
      NtBuffer private = build(1, body, 8, NULL, 0, NULL, 0, priv, 1, NULL, 0, 0);
      NtBuffer three_priv[3] = {private, B, C};
      expect_error(&image, "definition not exported", three_priv, 3,
                   OUT_CAPACITY, 824);
      free(private.bytes);
    }

    /* 825 role mismatch against a middle unit. */
    {
      Sym role[] = {{"m.f", "data:u64", 0, NT_OBJECT_VARIABLE | NT_OBJECT_IMPORT, 0, 0}};
      NtBuffer wrong_role = build(1, body, 8, NULL, 0, NULL, 0, role, 1, NULL, 0, 0);
      NtBuffer three_role[3] = {A, wrong_role, C};
      expect_error(&image, "role mismatch", three_role, 3, OUT_CAPACITY, 825);
      free(wrong_role.bytes);
    }

    /* 825 contract mismatch against a middle unit. */
    {
      Sym contract[] = {{"m.f", "fn:u32", 0, NT_OBJECT_FUNCTION | NT_OBJECT_IMPORT, 0, 0}};
      NtBuffer wrong_contract =
          build(1, body, 8, NULL, 0, NULL, 0, contract, 1, NULL, 0, 0);
      NtBuffer three_contract[3] = {A, wrong_contract, C};
      expect_error(&image, "contract mismatch", three_contract, 3, OUT_CAPACITY,
                   825);
      free(wrong_contract.bytes);
    }

    /* 826 more than one entry across three units. */
    {
      NtBuffer entry2 = build(1, body, 8, NULL, 0, NULL, 0, sa, 1, NULL, 0, 1);
      NtBuffer three_entry[3] = {A, entry2, C};
      expect_error(&image, "two entries", three_entry, 3, OUT_CAPACITY, 826);
      free(entry2.bytes);
    }

    /* 6b. base alignment, oracle compared. object_link.c:78-84 aligns the
     * running total of every section to 16 for every unit, unconditionally, so
     * an empty section still rounds the total up. Each shape below is the count
     * 2 case where that differs from an alignment applied only to a non empty
     * section, or from an 8 byte alignment for .rdata and .data. */
    expect_shape(&image, "shape R.text empty", 1, 1, 1, 0, 0, 0);
    expect_shape(&image, "shape R.text empty L=8", 8, 1, 1, 0, 0, 0);
    expect_shape(&image, "shape R.rdata empty L=8", 1, 8, 1, 1, 0, 1);
    expect_shape(&image, "shape R.data empty L=3", 1, 1, 3, 1, 1, 0);
    expect_shape(&image, "shape R.rdata 8 not 16", 1, 8, 1, 1, 8, 1);
    expect_shape(&image, "shape R.rdata 24 not 16", 1, 8, 1, 1, 24, 1);
    expect_shape(&image, "shape L all empty", 0, 0, 0, 5, 7, 3);
    expect_shape(&image, "shape both all empty", 0, 0, 0, 0, 0, 0);

    /* 6c. the same rule at count 3, where the two trailing units are empty in
     * one section: the merged size is the 16 byte boundary, not the total the
     * first unit left behind. */
    expect_empty_tail(&image, "tail .text empty x2", 1, 3);
    expect_empty_tail(&image, "tail .rdata empty x2", 2, 8);
    expect_empty_tail(&image, "tail .data empty x2", 3, 5);
    expect_empty_tail(&image, "tail .text empty x2 aligned", 1, 16);

    free(A.bytes);
    free(B.bytes);
    free(C.bytes);
    free(P1.bytes);
    free(P2.bytes);
    free(P3.bytes);
    free(P4.bytes);
    free(solo.bytes);
  }
  if (image.memory)
    nova_host_unmap(&image);
  if (compiled)
    nt_artifact_free(&a);
  for (unsigned i = 0; i < 4; i++)
    free(sources[i]);
  printf("NTASM_NOVA_NXO_MERGE_LIST checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  return failures ? 1 : 0;
}
