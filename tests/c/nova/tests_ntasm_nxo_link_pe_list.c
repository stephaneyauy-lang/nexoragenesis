#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Linker phase 1 + phase 2 for a variable length link unit. link_pe_list
 * routes merge_list over 1..64 objects straight into ntasm_nxo_pe.convert, so
 * a multi-module program reaches a PE for the first time; the pairwise
 * link_pe only ever merged two objects.
 *
 * The oracle is the frozen C pipeline: nt_object_link(count) +
 * nt_object_materialize + nt_make_pe. Every accepted case is compared with that
 * image byte for byte, and every refusal is checked against the stage of the
 * same pipeline that refuses, so a Nova code is never trusted on its own. */
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
#define MIB (1024u * 1024u)
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

/* call rel32 ; ret */
static const uint8_t body[6] = {0xe8, 0, 0, 0, 0, 0xc3};
static const uint8_t ro[8] = {1, 2, 3, 4, 5, 6, 7, 8};
static const uint8_t rw[8] = {9, 10, 11, 12, 13, 14, 15, 16};

/* One link unit: it imports the definition the previous unit exported and
 * exports its own, so a whole arena chains into a single executable whose entry
 * is the first unit's function. rel32_addend exists so the 806 case can push a
 * displacement past INT32_MAX without disturbing the layout. */
typedef struct {
  const char *import_name; /* NULL when the unit imports nothing */
  const char *export_name;
  const char *contract; /* contract text carried by both records */
  uint32_t target;
  int with_entry;
  int relocate; /* REL32 in .text and DIR64 in .data against the import */
  int64_t rel32_addend;
} Unit;

static NtBuffer build_unit(const Unit *u) {
  Sym syms[2];
  size_t ns = 0;
  NtObjectReloc rel[2];
  size_t nr = 0;
  uint32_t entry = 0;
  if (u->import_name) {
    CHECK(strcmp(u->import_name, u->export_name) < 0,
          "unit records stay sorted by name");
    uint32_t at = (uint32_t)(ns + 1);
    syms[ns++] = (Sym){u->import_name, u->contract, 0,
                       NT_OBJECT_FUNCTION | NT_OBJECT_IMPORT, 0, 0};
    if (u->relocate) {
      rel[nr++] = (NtObjectReloc){1, NT_OBJECT_REL32, at, 1, u->rel32_addend};
      rel[nr++] = (NtObjectReloc){3, NT_OBJECT_DIR64, at, 0, 0};
    }
  }
  syms[ns++] = (Sym){u->export_name, u->contract, 1,
                     NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, sizeof body};
  if (u->with_entry)
    entry = (uint32_t)ns;
  return build(u->target, body, sizeof body, ro, sizeof ro, rw, sizeof rw, syms,
               ns, rel, nr, entry);
}

/* count units chained m.f00 -> m.f01 -> ... Names are zero padded so the per
 * unit order is also the global order object_link.c requires. */
static void chain(NtBuffer *out, size_t count, const char *contract,
                  uint32_t target) {
  for (size_t i = 0; i < count; i++) {
    char here[32], prev[32];
    Unit u;
    snprintf(here, sizeof here, "m.f%02zu", i);
    snprintf(prev, sizeof prev, "m.f%02zu", i ? i - 1 : 0);
    memset(&u, 0, sizeof u);
    u.import_name = i ? prev : NULL;
    u.export_name = here;
    u.contract = contract;
    u.target = target;
    u.with_entry = (i == 0);
    u.relocate = (i != 0);
    out[i] = build_unit(&u);
  }
}

static void free_units(NtBuffer *files, size_t count) {
  for (size_t i = 0; i < count; i++)
    free(files[i].bytes);
}

/* One arena holds count 16-byte (offset,length) descriptors then the payloads:
 * the layout merge_list and therefore link_pe_list read. */
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
  size_t cap;
  uint8_t *out;
} Run;

static Run run_raw(const NovaHostImage *i, const uint8_t *bytes, size_t size,
                   uint64_t count, uint64_t cap, uint64_t mode) {
  Run x = {0};
  x.cap = (size_t)cap;
  x.out = malloc((size_t)cap + 16);
  CHECK(x.out != NULL, "output allocation");
  if (!x.out)
    return x;
  memset(x.out, guard, (size_t)cap + 16);
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t ih = nova_borrow_v2(&c, (void *)bytes, (uint64_t)size, 0);
  uint64_t oh = nova_borrow_v2(&c, x.out, cap, 1);
  uint64_t args[] = {ih, (uint64_t)size, count, oh, cap, mode};
  x.returned = i->entry(&c, args, 6);
  x.runtime = c.error;
  x.source = c.error_source;
  x.offset = c.error_offset;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return x;
}

static Run run(const NovaHostImage *i, NtBuffer *a, uint64_t count, uint64_t cap,
               uint64_t mode) {
  return run_raw(i, a->bytes, a->size, count, cap, mode);
}

static void report(const char *n, Run *x) {
  fprintf(stderr, "  %s ret=%llu runtime=%llu source=%llu offset=%llu\n", n,
          (unsigned long long)x->returned, (unsigned long long)x->runtime,
          (unsigned long long)x->source, (unsigned long long)x->offset);
}

/* Stage of the frozen C pipeline that refuses. STAGE_NONE means the pipeline
 * accepted and produced an image. */
enum { STAGE_NONE = 0, STAGE_LINK = 1, STAGE_MATERIALIZE = 2, STAGE_PE = 3 };

static int oracle(NtBuffer *files, size_t count, int *refused_at, NtBuffer *pe) {
  NtObject *objs = calloc(count ? count : 1, sizeof *objs);
  NtObject linked = {0};
  NtArtifact artifact = {0};
  NtDiagnostic e = {0};
  int ok = 1;
  *refused_at = STAGE_NONE;
  if (!objs) {
    *refused_at = STAGE_LINK;
    return 0;
  }
  for (size_t i = 0; i < count; i++)
    if (!nt_object_read(files[i].bytes, files[i].size, &objs[i], &e)) {
      ok = 0;
      break;
    }
  if (ok && !nt_object_link(objs, count, &linked, &e)) {
    *refused_at = STAGE_LINK;
    ok = 0;
  }
  if (ok && !nt_object_materialize(&linked, &artifact, &e)) {
    *refused_at = STAGE_MATERIALIZE;
    ok = 0;
  }
  if (ok && !nt_make_pe(&artifact)) {
    *refused_at = STAGE_PE;
    ok = 0;
  }
  if (ok) {
    /* Detach only the image: zeroing the whole record would drop the cloned
     * sections on the floor. */
    *pe = artifact.pe;
    artifact.pe.bytes = NULL;
    artifact.pe.size = artifact.pe.capacity = 0;
  }
  nt_artifact_free(&artifact);
  nt_object_free(&linked);
  for (size_t i = 0; i < count; i++)
    nt_object_free(&objs[i]);
  free(objs);
  return ok;
}

/* Byte for byte against nt_object_link(count) + nt_object_materialize +
 * nt_make_pe. */
static void expect_pe_bytes(const char *n, const uint8_t *got, uint64_t gotn,
                            NtBuffer *files, size_t count) {
  int refused_at = STAGE_NONE;
  NtBuffer pe = {0};
  cases++;
  int linked_ok = oracle(files, count, &refused_at, &pe);
  CHECK(linked_ok, "C oracle links and materializes");
  if (!linked_ok) {
    fprintf(stderr, "FAIL oracle %s refused at stage %d\n", n, refused_at);
    return;
  }
  int parity = gotn == pe.size && !memcmp(got, pe.bytes, pe.size);
  if (!parity) {
    size_t limit = gotn < pe.size ? (size_t)gotn : pe.size;
    size_t first = 0;
    while (first < limit && got[first] == pe.bytes[first])
      first++;
    fprintf(stderr,
            "FAIL parity %s nova=%llu oracle=%zu first=%zu novaByte=%u "
            "oracleByte=%u\n",
            n, (unsigned long long)gotn, pe.size, first,
            first < gotn ? got[first] : 0, first < pe.size ? pe.bytes[first] : 0);
  }
  CHECK(parity, "PE byte parity with the C oracle");
  free(pe.bytes);
}

static void expect_pe(const NovaHostImage *i, const char *n, NtBuffer *files,
                      size_t count, size_t cap) {
  NtBuffer a = arena(files, count);
  Run x = run(i, &a, (uint64_t)count, (uint64_t)cap, 0);
  cases++;
  CHECK(x.returned == 0 && x.runtime == 0, "link_pe_list accepts");
  if (x.returned || x.runtime) {
    report(n, &x);
  } else {
    uint64_t size = r64(x.out);
    int guarded = 1;
    for (size_t i = 8 + size; i < cap; i++)
      if (x.out[i] != guard)
        guarded = 0;
    CHECK(guarded, "output guards intact past the image");
    expect_pe_bytes(n, x.out + 8, size, files, count);
  }
  free(x.out);
  free(a.bytes);
}

/* stage 0 skips the C check: used for the arena shape codes, where the C
 * pipeline is handed an object array and has no arena to disagree with. */
static void expect_error(const NovaHostImage *i, const char *n, NtBuffer *files,
                         size_t count, size_t cap, uint64_t code, int stage) {
  NtBuffer a = arena(files, count);
  Run x = run(i, &a, (uint64_t)count, (uint64_t)cap, 0);
  cases++;
  checks++;
  if (x.returned != code || x.runtime || x.out[0] != guard ||
      x.out[1] != guard) {
    failures++;
    fprintf(stderr, "FAIL error %s ret=%llu runtime=%llu want=%llu\n", n,
            (unsigned long long)x.returned, (unsigned long long)x.runtime,
            (unsigned long long)code);
    report(n, &x);
  }
  if (stage) {
    int refused_at = STAGE_NONE;
    NtBuffer pe = {0};
    int ok = oracle(files, count, &refused_at, &pe);
    cases++;
    checks++;
    if (ok || refused_at != stage) {
      failures++;
      fprintf(stderr, "FAIL oracle stage %s linked=%d refused_at=%d want=%d\n", n,
              ok, refused_at, stage);
    }
    free(pe.bytes);
  }
  free(x.out);
  free(a.bytes);
}

/* Runs the entry on a hand patched arena, so a descriptor that points outside
 * the buffer can be observed. */
static void expect_error_raw(const NovaHostImage *i, const char *n,
                             const uint8_t *bytes, size_t size, uint64_t count,
                             uint64_t code) {
  Run x = run_raw(i, bytes, size, count, OUT_CAPACITY, 0);
  cases++;
  checks++;
  if (x.returned != code || x.runtime || x.out[0] != guard ||
      x.out[1] != guard) {
    failures++;
    fprintf(stderr, "FAIL error %s ret=%llu runtime=%llu want=%llu\n", n,
            (unsigned long long)x.returned, (unsigned long long)x.runtime,
            (unsigned long long)code);
    report(n, &x);
  }
  free(x.out);
}

/* merge_list at count 2 and the pairwise link_pe are the same link, so the two
 * entry modes must emit the same image for the same two units, and that image
 * must be the one the C pipeline builds. */
static void expect_identity(const NovaHostImage *i, const char *n,
                            NtBuffer *files) {
  NtBuffer a = arena(files, 2);
  Run list = run(i, &a, 2, OUT_CAPACITY, 0);
  Run pair = run(i, &a, 2, OUT_CAPACITY, 1);
  cases++;
  CHECK(list.returned == 0 && list.runtime == 0, "link_pe_list two units");
  CHECK(pair.returned == 0 && pair.runtime == 0, "link_pe two units");
  if (list.returned || list.runtime || pair.returned || pair.runtime) {
    report(n, &list);
    report(n, &pair);
  } else {
    uint64_t ls = r64(list.out), ps = r64(pair.out);
    int same = ls == ps && !memcmp(list.out, pair.out, (size_t)ls + 8);
    if (!same)
      fprintf(stderr, "FAIL identity %s list=%llu pair=%llu\n", n,
              (unsigned long long)ls, (unsigned long long)ps);
    CHECK(same, "link_pe_list byte identical to link_pe at count 2");
    expect_pe_bytes(n, list.out + 8, ls, files, 2);
  }
  free(list.out);
  free(pair.out);
  free(a.bytes);
}

int main(void) {
  const char *paths[] = {
      "tests/nova/tests/nxo-link-pe-list-entry.nova",
      "compiler/nova/formats/nxo/nxo_link_pe.nova",
      "compiler/nova/formats/nxo/nxo_merge.nova",
      "compiler/nova/formats/nxo/nxo_pe.nova",
      "compiler/nova/formats/nxo/nxo.nova",
      "compiler/nova/formats/pe/pe.nova"};
  char *sources[6] = {0};
  NtFInput inputs[6];
  for (unsigned i = 0; i < 6; i++) {
    size_t n = 0;
    sources[i] = load(paths[i], &n);
    inputs[i] = (NtFInput){paths[i], sources[i], n};
  }
  CHECK(sources[0] && sources[1] && sources[2] && sources[3] && sources[4] &&
            sources[5],
        "sources load");
  NtArtifact compiler = {0};
  int compiled = sources[0] && sources[1] && sources[2] && sources[3] &&
                 sources[4] && sources[5] &&
                 nova_compile_many_v2(inputs, 6, &compiler);
  CHECK(compiled, "modules compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", compiler.error.code, compiler.error.line,
            compiler.error.column, compiler.error.message);
  NovaHostImage image = {0};
  CHECK(compiled && nova_host_map(&compiler, &image), "image maps");

  if (image.memory) {
    /* Canonical contract text: the shape the C frontend writes. Both sides of
     * every link below carry it, so the bytes compare. */
    const char *k = "fn:u64";

    /* 1. one object: the closed self-contained unit, the degenerate link. */
    {
      NtBuffer one[1];
      chain(one, 1, k, 1);
      expect_pe(&image, "single unit", one, 1, OUT_CAPACITY);
      free_units(one, 1);
    }

    /* 2. two objects, through both entry modes at once. */
    {
      NtBuffer two[2];
      chain(two, 2, k, 1);
      expect_identity(&image, "two units", two);
      free_units(two, 2);
    }

    /* 3. three, four, eight and thirty two objects. */
    {
      static const size_t widths[] = {3, 4, 8, 32};
      for (unsigned w = 0; w < sizeof widths / sizeof *widths; w++) {
        size_t n = widths[w];
        NtBuffer group[32];
        chain(group, n, k, 1);
        char label[32];
        snprintf(label, sizeof label, "%zu units", n);
        expect_pe(&image, label, group, n, OUT_CAPACITY);
        free_units(group, n);
      }
    }

    /* 4. the documented unit ceiling: 64 objects at once. */
    {
      NtBuffer group[64];
      chain(group, 64, k, 1);
      expect_pe(&image, "64 units", group, 64, OUT_CAPACITY);
      free_units(group, 64);
    }

    /* 5. a library object with no entry, between two executable units. The
     * middle unit exports m.lib, imports nothing, carries no relocation and no
     * entry, and the entry still resolves through it. */
    {
      Unit a = {"m.a00", "m.b00", k, 1, 1, 1, 0};
      Unit b = {NULL, "m.a00", k, 1, 0, 0, 0};
      Unit c = {"m.b00", "m.zz", k, 1, 0, 1, 0};
      NtBuffer trio[3] = {build_unit(&a), build_unit(&b), build_unit(&c)};
      expect_pe(&image, "library unit", trio, 3, OUT_CAPACITY);
      free_units(trio, 3);
    }

    /* 6. two units carrying the SAME contract text, whatever that text is. The
     * linker resolves a link when the contracts match byte for byte, and the
     * merge never inspects the bytes themselves, so this case is about the
     * comparison, not about any particular contract.
     *
     * WHAT THIS IS NOT. It is not a claim about what x64_lower_nxo writes. An
     * earlier version of this comment said the producer stores the two bytes
     * "v0" as the contract of every symbol it emits, and cited
     * x64_lower_nxo.nova:182-184 for it. Both halves were false. That line
     * range is a comment about the clobber mask above source_clobbers and says
     * nothing about contracts; the printer is declaration_contract, and it
     * writes the same canonical text the C reference writes, measured
     * character for character. What this case keeps is the property the merge
     * actually has: equal contracts resolve. */
    {
      NtBuffer pair_nova[2];
      chain(pair_nova, 2, "v0", 1);
      expect_identity(&image, "equal contract text", pair_nova);
      free_units(pair_nova, 2);
    }

    /* 7. the same property at a larger unit count, so it is the comparison and
     * not the size of the group that resolves the link.
     *
     * The literal "v0" in the chain() calls of cases 6 and 7, and in case 23
     * below, is a CONTRACT STRING THIS HARNESS CHOOSES, not a value any
     * producer emits and not a live defect. It is short on purpose: it keeps
     * the arena arithmetic in these cases legible. If you grep this file for
     * "v0" and find these three, this paragraph is why. */
    {
      NtBuffer group[8];
      chain(group, 8, "v0", 1);
      expect_pe(&image, "equal contract text 8 units", group, 8, OUT_CAPACITY);
      free_units(group, 8);
    }

    /* 8. 800, unit count and arena shape. */
    {
      NtBuffer one[1];
      chain(one, 1, k, 1);
      /* zero units: nt_object_link refuses count 0 as well. */
      {
        NtBuffer a = arena(one, 0);
        Run x = run(&image, &a, 0, OUT_CAPACITY, 0);
        cases++;
        checks++;
        if (x.returned != 800 || x.runtime || x.out[0] != guard) {
          failures++;
          fprintf(stderr, "FAIL error zero units ret=%llu runtime=%llu\n",
                  (unsigned long long)x.returned, (unsigned long long)x.runtime);
          report("zero units", &x);
        }
        free(x.out);
        free(a.bytes);
      }
      /* 65 units: nt_object_link refuses count > 64 as well. */
      {
        NtBuffer many[65];
        for (size_t i = 0; i < 65; i++)
          many[i] = one[0];
        expect_error(&image, "65 units", many, 65, OUT_CAPACITY, 800,
                     STAGE_LINK);
      }
      /* a descriptor that points past the end of the arena. */
      {
        NtBuffer a = arena(one, 1);
        uint8_t *p = malloc(a.size);
        CHECK(p != NULL, "patched arena allocation");
        memcpy(p, a.bytes, a.size);
        for (unsigned b = 0; b < 8; b++)
          p[b] = (uint8_t)((uint64_t)(a.size + 64) >> (b * 8));
        expect_error_raw(&image, "descriptor out of arena", p, a.size, 1, 800);
        free(p);
        free(a.bytes);
      }
      /* an arena one byte short of the payload it describes. */
      {
        NtBuffer a = arena(one, 1);
        uint8_t *p = malloc(a.size - 1);
        CHECK(p != NULL, "truncated arena allocation");
        memcpy(p, a.bytes, a.size - 1);
        expect_error_raw(&image, "truncated unit", p, a.size - 1, 1, 800);
        /* the C reader refuses the same bytes. */
        NtObject o = {0};
        NtDiagnostic e = {0};
        cases++;
        CHECK(!nt_object_read(p, a.size - 1, &o, &e),
              "C reader refuses the truncated unit");
        nt_object_free(&o);
        free(p);
        free(a.bytes);
      }
      free_units(one, 1);
    }

    /* 9. 827, a short output buffer. out holds exactly the 8 byte header, so
     * the image cannot fit and nothing may be written. */
    {
      NtBuffer two[2];
      chain(two, 2, k, 1);
      expect_error(&image, "short output", two, 2, 8, 827, 0);
      free_units(two, 2);
    }

    /* 10. 802, a link that succeeds but is not the UEFI target. Every unit
     * agrees, so the merge is legal and the conversion is what refuses. */
    {
      NtBuffer trio[3];
      chain(trio, 3, k, 2);
      expect_error(&image, "bare x64 target", trio, 3, OUT_CAPACITY, 802,
                   STAGE_MATERIALIZE);
      free_units(trio, 3);
    }

    /* 11. 803, a closed library: no unit carries the entry, so the merged
     * object is a library and the conversion refuses. */
    {
      Unit a = {NULL, "m.f00", k, 1, 0, 0, 0};
      Unit b = {"m.f00", "m.f01", k, 1, 0, 1, 0};
      NtBuffer pair_lib[2] = {build_unit(&a), build_unit(&b)};
      expect_error(&image, "closed library", pair_lib, 2, OUT_CAPACITY, 803,
                   STAGE_MATERIALIZE);
      free_units(pair_lib, 2);
    }

    /* 12. 805 on .text, the section the entry lives in. A .text of 16MiB + 1
     * is refused. The neighbouring text_size==0 half of the same convert test
     * is not reachable from here: 803 is checked first, and an entry symbol
     * must be a sized function of .text, so a linked object with no .text is
     * always a library and never reaches the size test. */
    {
      uint8_t *big_text = calloc(16 * MIB + 1, 1);
      CHECK(big_text != NULL, "text ceiling payload allocation");
      Sym s = {"m.f00", k, 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 1};
      NtBuffer one[1] = {build(1, big_text, 16 * MIB + 1, NULL, 0, NULL, 0, &s,
                               1, NULL, 0, 1)};
      expect_error(&image, "text over the 16MiB ceiling", one, 1, OUT_CAPACITY,
                   805, STAGE_MATERIALIZE);
      free_units(one, 1);
      free(big_text);
      Sym v = {"m.f00", k, 2, NT_OBJECT_VARIABLE | NT_OBJECT_EXPORT, 1, 2};
      NtBuffer bare[1] = {build(1, NULL, 0, ro, sizeof ro, rw, sizeof rw, &v, 1,
                                NULL, 0, 0)};
      expect_error(&image, "empty text is a library", bare, 1, OUT_CAPACITY, 803,
                   STAGE_MATERIALIZE);
      free_units(bare, 1);
    }

    /* 13. 805, the per section ceiling on .rdata. Two units of 8MiB each land
     * on exactly 16MiB of .rdata and convert; one more byte is refused. 16MiB
     * per merged section is the reachable ceiling of link_pe_list: 48MiB of
     * linked payload in total, which is below the 64MiB a single borrow
     * accepts, so the arena is never the binding limit. */
    {
      uint8_t *big = calloc(8 * MIB + 1, 1);
      CHECK(big != NULL, "ceiling payload allocation");
      for (size_t i = 0; i < 8 * MIB + 1; i++)
        big[i] = (uint8_t)(i * 7u);
      Sym s0 = {"m.f00", k, 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 6};
      Sym s1 = {"m.zz", k, 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 6};
      NtBuffer at[2] = {build(1, body, sizeof body, big, 8 * MIB, NULL, 0, &s0,
                              1, NULL, 0, 1),
                        build(1, body, sizeof body, big, 8 * MIB, NULL, 0, &s1,
                              1, NULL, 0, 0)};
      expect_pe(&image, "rdata at the 16MiB ceiling", at, 2, 18 * MIB);
      NtBuffer over[2] = {at[0],
                          build(1, body, sizeof body, big, 8 * MIB + 1, NULL, 0,
                                &s1, 1, NULL, 0, 0)};
      expect_error(&image, "rdata over the 16MiB ceiling", over, 2, OUT_CAPACITY,
                   805, STAGE_MATERIALIZE);
      free(at[1].bytes);
      free_units(over, 2);
      free(big);
    }

    /* 14. 806, a displacement past INT32_MAX. The link is legal, so the
     * arithmetic in the conversion is what refuses. */
    {
      Unit a = {NULL, "m.f00", k, 1, 1, 0, 0};
      Unit b = {"m.f00", "m.f01", k, 1, 0, 1, 4294967295LL};
      NtBuffer pair_big[2] = {build_unit(&a), build_unit(&b)};
      expect_error(&image, "rel32 displacement out of range", pair_big, 2,
                   OUT_CAPACITY, 806, STAGE_MATERIALIZE);
      free_units(pair_big, 2);
    }

    /* 15. 820, a middle unit that disagrees about the target. */
    {
      NtBuffer trio[3];
      chain(trio, 2, k, 1);
      trio[2] = build(2, body, sizeof body, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                      0);
      expect_error(&image, "mixed target", trio, 3, OUT_CAPACITY, 820,
                   STAGE_LINK);
      free_units(trio, 3);
    }

    /* 16. 821, the merged symbol budget: 40000 + 40000 records exceed the
     * 65536 a linked object may carry. */
    {
      char (*names)[8] = calloc(WIDE, 8);
      Sym *wide = calloc(WIDE, sizeof *wide);
      CHECK(names && wide, "wide fixture allocation");
      for (size_t i = 0; i < WIDE; i++) {
        snprintf(names[i], 8, "s%05zu", i);
        wide[i] = (Sym){names[i], k, 3, NT_OBJECT_VARIABLE, 0, 1};
      }
      NtBuffer wide_pair[2] = {
          build(1, NULL, 0, NULL, 0, rw, sizeof rw, wide, WIDE, NULL, 0, 0),
          build(1, NULL, 0, NULL, 0, rw, sizeof rw, wide, WIDE, NULL, 0, 0)};
      expect_error(&image, "symbol capacity", wide_pair, 2, OUT_CAPACITY, 821,
                   STAGE_LINK);
      free_units(wide_pair, 2);
      free(names);
      free(wide);
    }

    /* 17. 823, two units defining the same name. */
    {
      Unit a = {NULL, "m.f00", k, 1, 1, 0, 0};
      Unit b = {NULL, "m.f00", k, 1, 0, 0, 0};
      Unit c = {"m.f00", "m.zz", k, 1, 0, 1, 0};
      NtBuffer trio_dup[3] = {build_unit(&a), build_unit(&b), build_unit(&c)};
      expect_error(&image, "duplicate definition", trio_dup, 3, OUT_CAPACITY,
                   823, STAGE_LINK);
      free_units(trio_dup, 3);
    }

    /* 18. 823 outranks 824: a duplicated name is refused before the imports of
     * the same group are resolved, the order object_link.c uses. m.aa sorts
     * first, so its group is walked before m.bb and m.cc are ever looked at. */
    {
      Unit a = {NULL, "m.aa", k, 1, 1, 0, 0};
      Unit b = {NULL, "m.aa", k, 1, 0, 0, 0};
      Unit c = {"m.aa", "m.bb", k, 1, 0, 1, 0};
      Unit d = {"m.bb", "m.cc", k, 1, 0, 1, 0};
      NtBuffer quartet[4] = {build_unit(&a), build_unit(&b), build_unit(&c),
                             build_unit(&d)};
      expect_error(&image, "duplicate before import", quartet, 4, OUT_CAPACITY,
                   823, STAGE_LINK);
      free_units(quartet, 4);
    }

    /* 19. 824, an import no unit defines. m.aa sorts first and nothing
     * defines it. */
    {
      Unit a = {NULL, "m.bb", k, 1, 1, 0, 0};
      Unit missing = {"m.aa", "m.zz", k, 1, 0, 1, 0};
      Unit c = {"m.bb", "m.cc", k, 1, 0, 1, 0};
      NtBuffer trio[3] = {build_unit(&a), build_unit(&missing),
                          build_unit(&c)};
      expect_error(&image, "unresolved import", trio, 3, OUT_CAPACITY, 824,
                   STAGE_LINK);
      free_units(trio, 3);
    }

    /* 20. 824, a definition that is not exported. */
    {
      Sym priv = {"m.aa", k, 1, NT_OBJECT_FUNCTION, 0, 6};
      NtBuffer private = build(1, body, sizeof body, ro, sizeof ro, rw,
                               sizeof rw, &priv, 1, NULL, 0, 1);
      Unit b = {"m.aa", "m.bb", k, 1, 0, 1, 0};
      Unit c = {"m.bb", "m.cc", k, 1, 0, 1, 0};
      NtBuffer trio[3] = {private, build_unit(&b), build_unit(&c)};
      expect_error(&image, "definition not exported", trio, 3, OUT_CAPACITY,
                   824, STAGE_LINK);
      free_units(trio, 3);
    }

    /* 21. 825, a role mismatch against a middle unit. */
    {
      Sym role = {"m.f00", "data:u64", 0,
                  NT_OBJECT_VARIABLE | NT_OBJECT_IMPORT, 0, 0};
      NtBuffer wrong = build(1, body, sizeof body, NULL, 0, NULL, 0, &role, 1,
                             NULL, 0, 0);
      Unit a = {NULL, "m.f00", k, 1, 1, 0, 0};
      Unit c = {"m.f00", "m.zz", k, 1, 0, 1, 0};
      NtBuffer trio[3] = {build_unit(&a), wrong, build_unit(&c)};
      expect_error(&image, "role mismatch", trio, 3, OUT_CAPACITY, 825,
                   STAGE_LINK);
      free_units(trio, 3);
    }

    /* 22. 825, a contract mismatch. A hand built pair: the middle unit offers
     * the contract "fn:u32" for m.f00 where the two neighbours require the
     * contract text k, and the merge compares contracts byte for byte, so it
     * refuses here before a single instruction is looked at.
     *
     * WHAT THIS CASE IS NOT. It is not the shape the C frontend and a Nova
     * producer disagree on. An earlier version of this comment said so, and
     * named the cause: "x64_lower_nxo writes v0 where the frontend writes the
     * full canonical text". That was false and it is the prose that briefed a
     * whole lot onto a repair that had already been made. The producer writes
     * the canonical text, measured character for character, so the two sides
     * of a real cross producer link agree on this field today.
     *
     * What is left is a genuine 825 with a genuine cause, and that is the
     * reason the case stays: the refusal is exact, it is on the contract and
     * nothing else, and case 23 asks the same question from the other side. */
    {
      Sym contract = {"m.f00", "fn:u32", 0, NT_OBJECT_FUNCTION | NT_OBJECT_IMPORT,
                      0, 0};
      NtBuffer wrong = build(1, body, sizeof body, NULL, 0, NULL, 0, &contract,
                             1, NULL, 0, 0);
      Unit a = {NULL, "m.f00", k, 1, 1, 0, 0};
      Unit c = {"m.f00", "m.zz", k, 1, 0, 1, 0};
      NtBuffer trio[3] = {build_unit(&a), wrong, build_unit(&c)};
      expect_error(&image, "contract mismatch", trio, 3, OUT_CAPACITY, 825,
                   STAGE_LINK);
      free_units(trio, 3);
    }

    /* 23. 825, the same refusal with the two units the other way round. The
     * "v0" below is a contract string THIS HARNESS CHOOSES for the odd side
     * out, so the arena is easy to read; it is not a value any producer emits.
     * See the note on cases 6 and 7. Nothing about the layout differs from
     * case 22, and neither does the cause. */
    {
      Unit nova_side = {NULL, "m.f00", "v0", 1, 1, 0, 0};
      Unit c_side = {"m.f00", "m.zz", k, 1, 0, 1, 0};
      NtBuffer trio[2] = {build_unit(&nova_side), build_unit(&c_side)};
      expect_error(&image, "hand built contract mismatch", trio, 2,
                   OUT_CAPACITY, 825, STAGE_LINK);
      free_units(trio, 2);
    }

    /* 24. 826, two units carrying the entry. */
    {
      Unit a = {NULL, "m.f00", k, 1, 1, 0, 0};
      Unit b = {NULL, "m.aa", k, 1, 1, 0, 0};
      Unit c = {"m.aa", "m.zz", k, 1, 0, 1, 0};
      NtBuffer trio[3] = {build_unit(&a), build_unit(&b), build_unit(&c)};
      expect_error(&image, "two entries", trio, 3, OUT_CAPACITY, 826,
                   STAGE_LINK);
      free_units(trio, 3);
    }

    /* 25. 801, 804 and 807 are not reachable from this call site, and the three
     * probes below are the closest shapes that exist. They must succeed, which
     * is what makes the three codes unreachable rather than merely untested:
     *   801 needs a merged object ntasm_nxo.validate rejects, and
     *        ntasm_nxo.read already validates before convert sees anything
     *        (nxo.nova:158), so a bad object arrives as 800, never as 801;
     *   804 needs a surviving import, and merge_list folds every import onto
     *        its definition, so no import reaches the conversion;
     *   807 needs pe.emit to refuse, and every one of its refusals is already
     *        excluded by 805 and by nt_object_validate, so the tightest
     *        packing of DIR64 sites still lays out. */
    {
      /* 801 probe: a link with no symbol and no relocation at all. */
      NtBuffer one[1] = {build(1, body, sizeof body, ro, sizeof ro, rw,
                               sizeof rw, NULL, 0, NULL, 0, 0)};
      expect_error(&image, "801 probe needs an entry", one, 1, OUT_CAPACITY,
                   803, STAGE_MATERIALIZE);
      free_units(one, 1);
      /* 804 probe: an import satisfied by a later unit, so the merged object
       * holds the definition only. */
      {
        Unit a = {"m.aa", "m.f00", k, 1, 1, 1, 0};
        Unit b = {NULL, "m.aa", k, 1, 0, 0, 0};
        NtBuffer pair[2] = {build_unit(&a), build_unit(&b)};
        expect_pe(&image, "804 probe import folded", pair, 2, OUT_CAPACITY);
        free_units(pair, 2);
      }
      /* 807 probe: the tightest base relocation packing, a DIR64 at the last
       * eight bytes of .text and one at offset 0 of .rdata. */
      {
        uint8_t wide[16] = {0xe8, 0, 0, 0, 0, 0xc3, 0x90, 0x90,
                            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        Sym t = {"m.f00", k, 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 8};
        NtObjectReloc r[2] = {{1, NT_OBJECT_DIR64, 1, 0, 0},
                              {2, NT_OBJECT_DIR64, 1, 0, 0}};
        NtBuffer one[1] = {build(1, wide, sizeof wide, ro, sizeof ro, rw,
                                 sizeof rw, &t, 1, r, 2, 1)};
        expect_pe(&image, "807 probe tight base relocations", one, 1,
                  OUT_CAPACITY);
        free_units(one, 1);
      }
    }
  }
  if (image.memory)
    nova_host_unmap(&image);
  if (compiled)
    nt_artifact_free(&compiler);
  for (unsigned i = 0; i < 6; i++)
    free(sources[i]);
  printf("NTASM_NOVA_NXO_LINK_PE_LIST checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  return failures ? 1 : 0;
}
