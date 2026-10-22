/* BOOTSTRAP_C_TEST: PE inspector oracle harness for the read-only Nova
 * ntasm_pe_inspect validator.
 *
 * For every fixture the harness builds the PE twice: once with the frozen C
 * writer oracle (pe_oracle.c / nt_make_pe) and once with the Nova PE writer
 * (tests/nova/tests/pe-entry.nova + pe.nova) from the same inputs.
 * Both images must be byte identical. An independent C reader then extracts
 * the sixteen summary words straight from the oracle bytes and every word is
 * compared with what ntasm_pe_inspect.inspect produced. The image is fed
 * read-only, so the borrow is never writable.
 *
 * Negative coverage corrupts each critical header and section field, truncates
 * at every structural boundary, overlaps raw and virtual spans, moves the entry
 * outside .text and shrinks the output buffer. Every rejection must return the
 * documented stable code and must leave all twenty guard words untouched. */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/pe/pe_oracle.h"
#include "../../../compiler/c/nova/pe/pe_layout_oracle.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../compiler/c/ntasm/formats/pe.h"

 /* Stable error codes mirrored from compiler/nova/pe_inspect.nova. */
enum {
  ERR_SHORT_OUTPUT = 820,
  ERR_TRUNCATED_DOS = 821,
  ERR_NOT_DOS = 822,
  ERR_BAD_LFANEW = 823,
  ERR_TRUNCATED_HEADERS = 824,
  ERR_BAD_PE_SIGNATURE = 825,
  ERR_BAD_MACHINE = 826,
  ERR_BAD_SECTION_COUNT = 827,
  ERR_BAD_OPTIONAL_SIZE = 828,
  ERR_BAD_CHARACTERISTICS = 829,
  ERR_BAD_MAGIC = 830,
  ERR_BAD_SUBSYSTEM = 831,
  ERR_BAD_IMAGE_BASE = 832,
  ERR_BAD_ALIGNMENT = 833,
  ERR_BAD_SECTION_NAME = 834,
  ERR_BAD_SECTION_FLAGS = 835,
  ERR_BAD_VIRTUAL_SPAN = 836,
  ERR_BAD_RAW_LAYOUT = 837,
  ERR_RAW_OUT_OF_FILE = 838,
  ERR_SPAN_OVERLAP = 839,
  ERR_BAD_IMAGE_SIZE = 840,
  ERR_BAD_ENTRY = 841,
  ERR_BAD_RELOC_DIR = 842,
  ERR_BAD_RESERVED = 843,
  ERR_FILE_LENGTH = 844
};
#define WORDS 16
#define GUARDS 20
#define GUARD UINT64_C(0xcccccccccccccccc)
#define FAULT_BIT (UINT64_C(1) << 63)

static unsigned checks, failures, cases;

/* Counters behind the WRITER banner. They are printed on their own line so the
 * limit and the numbers that bound it are always read together, which is the
 * whole reason that banner exists. */
static unsigned wm_mutations, wm_pairs, wm_observable, wm_loader, wm_inspector,
    wm_noop, wm_unbuilt;

#define CHECK(c, m)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL %s\n", m);                                         \
    }                                                                          \
  } while (0)

static char *load(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;
  if (fseek(f, 0, SEEK_END)) {
    fclose(f);
    return NULL;
  }
  long n = ftell(f);
  if (n < 0 || fseek(f, 0, SEEK_SET)) {
    fclose(f);
    return NULL;
  }
  char *p = malloc((size_t)n + 1);
  if (!p) {
    fclose(f);
    return NULL;
  }
  size_t got = fread(p, 1, (size_t)n, f);
  fclose(f);
  if (got != (size_t)n) {
    free(p);
    return NULL;
  }
  p[got] = 0;
  *length = got;
  return p;
}

static uint16_t rd16(const uint8_t *p) {
  return (uint16_t)((uint32_t)p[0] | (uint32_t)p[1] << 8);
}
static uint32_t rd32(const uint8_t *p) {
  uint32_t v = 0;
  for (unsigned i = 0; i < 4; i++)
    v |= (uint32_t)p[i] << (8 * i);
  return v;
}
static uint64_t rd64(const uint8_t *p) {
  uint64_t v = 0;
  for (unsigned i = 0; i < 8; i++)
    v |= (uint64_t)p[i] << (8 * i);
  return v;
}
static void wr16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
}
static void wr32(uint8_t *p, uint32_t v) {
  for (unsigned i = 0; i < 4; i++)
    p[i] = (uint8_t)(v >> (8 * i));
}
static void wr64(uint8_t *p, uint64_t v) {
  for (unsigned i = 0; i < 8; i++)
    p[i] = (uint8_t)(v >> (8 * i));
}


typedef struct {
  const char *label;
  size_t text, rdata, data, entry;
  NovaOracleBaseReloc relocs[8];
  size_t count;
} Fixture;

/* Independent reader: extracts the summary straight from the oracle bytes. */
static void reference_summary(const uint8_t *pe, uint64_t *out) {
  uint64_t l = rd32(pe + 60), o = l + 24, table = l + 264;
  out[0] = rd16(pe + l + 4);
  out[1] = rd16(pe + o + 68);
  out[2] = rd64(pe + o + 24);
  out[3] = rd32(pe + o + 16);
  out[4] = rd32(pe + o + 56);
  out[5] = rd32(pe + o + 60);
  for (unsigned i = 0; i < 4; i++) {
    out[6 + i] = rd32(pe + table + i * 40 + 8);
    out[10 + i] = rd32(pe + table + i * 40 + 16);
  }
  out[14] = rd32(pe + o + 112 + 40);
  out[15] = rd32(pe + o + 112 + 44);
}

static uint8_t *pattern(size_t size, unsigned seed) {
  uint8_t *p = calloc(size ? size : 1, 1);
  if (!p)
    exit(2);
  for (size_t i = 0; i < size; i++)
    p[i] = (uint8_t)(i * seed + 3);
  return p;
}

static uint64_t *make_bases(const Fixture *f) {
  uint64_t *b = calloc(f->count ? f->count * 2 : 1, 8);
  if (!b)
    exit(2);
  for (size_t i = 0; i < f->count; i++) {
    b[i * 2] = f->relocs[i].section;
    b[i * 2 + 1] = f->relocs[i].offset;
  }
  return b;
}

/* Drives tests/pe-entry.nova: (text, rdata, data, bases, entry, error). */
static int writer_pe(const NovaHostImage *image, const Fixture *f,
                     uint8_t **bytes, size_t *size) {
  uint8_t *t = pattern(f->text, 17), *r = pattern(f->rdata, 7),
          *d = pattern(f->data, 11);
  uint64_t *bases = make_bases(f);
  *bytes = NULL;
  *size = 0;
  int ok = 0;
  NovaContextV2 c = {0};
  if (nova_context_init_v2(&c)) {
    uint64_t args[] = {nova_borrow_v2(&c, t, f->text, 0),
                       f->text,
                       nova_borrow_v2(&c, r, f->rdata, 0),
                       f->rdata,
                       nova_borrow_v2(&c, d, f->data, 0),
                       f->data,
                       nova_borrow_v2(&c, bases, f->count * 16, 0),
                       f->count * 2,
                       f->entry,
                       0};
    uint64_t handle = image->entry(&c, args, 10);
    uint8_t *record = c.error ? NULL
                              : (uint8_t *)(uintptr_t)c.runtime->calls[NV2_RESOLVE](
                                    &c, handle, 0, 16);
    if (record && !c.error && rd64(record) == 0) {
      uint64_t out = rd64(record + 8);
      uint64_t n = c.runtime->calls[NV2_LENGTH](&c, out, 0, 0);
      uint8_t *p = (uint8_t *)(uintptr_t)c.runtime->calls[NV2_RESOLVE](
          &c, out, 0, n);
      if (p && n && n < (UINT64_C(1) << 20) && (*bytes = malloc((size_t)n))) {
        memcpy(*bytes, p, (size_t)n);
        *size = (size_t)n;
        ok = 1;
      }
    }
    if (!nova_context_destroy_v2(&c))
      ok = 0;
  }
  free(t);
  free(r);
  free(d);
  free(bases);
  return ok;
}

static uint64_t inspect(const NovaHostImage *image, const uint8_t *pe,
                        size_t size, uint64_t *out, uint64_t out_words) {
  NovaContextV2 c = {0};
  uint64_t returned = UINT64_MAX;
  if (!nova_context_init_v2(&c))
    return UINT64_MAX;
  uint64_t args[] = {nova_borrow_v2(&c, (void *)pe, size, 0),
                     size,
                     nova_borrow_v2(&c, out, out_words * 8, 1),
                     out_words};
  returned = image->entry(&c, args, 4);
  if (c.error || !nova_context_destroy_v2(&c))
    returned = UINT64_MAX;
  return returned;
}


static int build_oracle(const Fixture *f, uint8_t **pe, size_t *size) {
  uint8_t *t = pattern(f->text, 17), *r = pattern(f->rdata, 7),
          *d = pattern(f->data, 11);
  *pe = NULL;
  *size = 0;
  NovaOraclePeImage image = {0};
  image.text = (NtBuffer){t, f->text, f->text};
  image.rdata = (NtBuffer){r, f->rdata, f->rdata};
  image.data = (NtBuffer){d, f->data, f->data};
  image.entry = f->entry;
  image.base_relocations = (NovaOracleBaseReloc *)f->relocs;
  image.base_relocation_count = f->count;
  int made = nova_oracle_make_pe(&image);
  if (made && image.pe.bytes) {
    *pe = image.pe.bytes;
    *size = image.pe.size;
  } else {
    free(image.pe.bytes);
  }
  free(t);
  free(r);
  free(d);
  return made;
}

static void expect_ok(const NovaHostImage *image, const uint8_t *pe,
                      size_t size, const uint64_t *expected, const char *label) {
  uint64_t out[WORDS + GUARDS];
  for (unsigned i = 0; i < WORDS + GUARDS; i++)
    out[i] = GUARD;
  cases++;
  uint64_t returned = inspect(image, pe, size, out, WORDS);
  int pass = returned == 0;
  for (unsigned i = 0; i < WORDS && pass; i++)
    if (out[i] != expected[i])
      pass = 0;
  for (unsigned i = WORDS; i < WORDS + GUARDS && pass; i++)
    if (out[i] != GUARD)
      pass = 0;
  if (!pass)
    fprintf(stderr,
            "FAIL summary %s returned=%" PRIu64 " words=%" PRIu64 ",%" PRIu64
            ",%" PRIu64 ",%" PRIu64 " expected=%" PRIu64 ",%" PRIu64
            ",%" PRIu64 ",%" PRIu64 "\n",
            label, returned, out[0], out[1], out[2], out[3], expected[0],
            expected[1], expected[2], expected[3]);
  CHECK(pass, label);
}

/* Returns 1 when the image was refused with `code` and every guard word is
 * intact. The writer cases below need the verdict and not only the failure, so
 * they can report how many mutated images the inspector actually rejected. */
static int expect_error(const NovaHostImage *image, const uint8_t *pe,
                        size_t size, uint64_t words, uint64_t code,
                        const char *label) {
  uint64_t out[WORDS + GUARDS];
  for (unsigned i = 0; i < WORDS + GUARDS; i++)
    out[i] = GUARD;
  cases++;
  uint64_t returned = inspect(image, pe, size, out, words);
  int intact = 1;
  for (unsigned i = 0; i < WORDS + GUARDS; i++)
    if (out[i] != GUARD)
      intact = 0;
  if (returned != FAULT_BIT + code || !intact)
    fprintf(stderr, "FAIL reject %s returned=%" PRIu64 " want=%" PRIu64
                    " intact=%d\n",
            label, returned, FAULT_BIT + code, intact);
  CHECK(returned == FAULT_BIT + code, label);
  CHECK(intact, "rejection leaves every output guard intact");
  return returned == FAULT_BIT + code && intact;
}

typedef struct {
  size_t at;
  unsigned width;
  uint64_t value;
  uint64_t code;
  const char *label;
} Corruption;

/* Header and section field corruption on the "entry-offset" fixture:
 * text 1024, rdata 17, data 23, entry 113, 3584 bytes, e_lfanew 128. */
static const Corruption corruptions[] = {
    {0, 2, 0x4141, ERR_NOT_DOS, "dos magic"},
    {2, 4, 1, ERR_BAD_RESERVED, "dos reserved"},
    {60, 4, 0, ERR_BAD_LFANEW, "e_lfanew zero"},
    {60, 4, 32, ERR_BAD_LFANEW, "e_lfanew inside dos header"},
    {60, 4, UINT32_C(0xfffffff0), ERR_TRUNCATED_HEADERS, "e_lfanew past file"},
    {60, 4, 3160, ERR_BAD_PE_SIGNATURE, "e_lfanew shifted header"},
    {64, 4, 1, ERR_BAD_RESERVED, "dos stub"},
    {128, 4, UINT32_C(0x4551), ERR_BAD_PE_SIGNATURE, "pe signature"},
    {132, 2, 0x014c, ERR_BAD_MACHINE, "machine i386"},
    {134, 2, 3, ERR_BAD_SECTION_COUNT, "three sections"},
    {136, 4, 1, ERR_BAD_RESERVED, "time date stamp"},
    {140, 4, 0x1000, ERR_BAD_RESERVED, "symbol table pointer"},
    {144, 4, 1, ERR_BAD_RESERVED, "symbol count"},
    {148, 2, 224, ERR_BAD_OPTIONAL_SIZE, "optional header size"},
    {150, 2, 0x0022, ERR_BAD_CHARACTERISTICS, "coff characteristics"},
    {152, 2, 0x010b, ERR_BAD_MAGIC, "pe32 magic"},
    {154, 2, 1, ERR_BAD_RESERVED, "linker version"},
    {156, 4, 512, ERR_BAD_IMAGE_SIZE, "size of code"},
    {160, 4, 1024, ERR_BAD_IMAGE_SIZE, "size of initialized data"},
    {164, 4, 8, ERR_BAD_RESERVED, "size of uninitialized data"},
    {168, 4, 5120, ERR_BAD_ENTRY, "entry past text"},
    {168, 4, 0, ERR_BAD_ENTRY, "entry below text"},
    {168, 4, 4095, ERR_BAD_ENTRY, "entry one byte before text"},
    {172, 4, 8192, ERR_BAD_RESERVED, "base of code"},
    {176, 8, UINT64_C(0x140001000), ERR_BAD_IMAGE_BASE, "image base"},
    {184, 4, 512, ERR_BAD_ALIGNMENT, "section alignment"},
    {188, 4, 4096, ERR_BAD_ALIGNMENT, "file alignment"},
    {192, 2, 5, ERR_BAD_RESERVED, "os version"},
    {194, 2, 1, ERR_BAD_RESERVED, "os minor version"},
    {200, 2, 5, ERR_BAD_RESERVED, "subsystem version"},
    {208, 4, 24576, ERR_BAD_IMAGE_SIZE, "size of image"},
    {212, 4, 512, ERR_BAD_IMAGE_SIZE, "size of headers"},
    {216, 4, 1, ERR_BAD_RESERVED, "checksum"},
    {220, 2, 11, ERR_BAD_SUBSYSTEM, "subsystem"},
    {222, 2, 0x0161, ERR_BAD_CHARACTERISTICS, "dll characteristics"},
    {224, 8, UINT64_C(0x200000), ERR_BAD_RESERVED, "stack reserve"},
    {232, 8, 0x2000, ERR_BAD_RESERVED, "stack commit"},
    {240, 8, UINT64_C(0x200000), ERR_BAD_RESERVED, "heap reserve"},
    {248, 8, 0x2000, ERR_BAD_RESERVED, "heap commit"},
    {256, 4, 1, ERR_BAD_RESERVED, "loader flags"},
    {260, 4, 15, ERR_BAD_RESERVED, "number of rva and sizes"},
    {264, 8, 4096, ERR_BAD_RESERVED, "export directory"},
    {304, 4, 20480, ERR_BAD_RELOC_DIR, "relocation directory rva"},
    {308, 4, 16, ERR_BAD_RELOC_DIR, "relocation directory size"},
    {312, 8, 1, ERR_BAD_RESERVED, "exception directory"},
    {392, 8, 0, ERR_BAD_SECTION_NAME, "text name"},
    {400, 4, 0, ERR_BAD_VIRTUAL_SPAN, "text virtual size zero"},
    {404, 4, 4160, ERR_BAD_VIRTUAL_SPAN, "text rva unaligned"},
    {408, 4, 1536, ERR_BAD_RAW_LAYOUT, "text raw size"},
    {412, 4, 1280, ERR_BAD_RAW_LAYOUT, "text raw pointer alignment"},
    {412, 4, 512, ERR_RAW_OUT_OF_FILE, "text raw inside headers"},
    {416, 4, 0x20, ERR_BAD_RESERVED, "section relocation pointer"},
    {428, 4, UINT32_C(0x60000040), ERR_BAD_SECTION_FLAGS, "text flags"},
    {432, 8, 0, ERR_BAD_SECTION_NAME, "rdata name"},
    {448, 4, 1024, ERR_BAD_RAW_LAYOUT, "rdata raw size"},
    {468, 4, UINT32_C(0x40000020), ERR_BAD_SECTION_FLAGS, "rdata flags"},
    {484, 4, 8192, ERR_SPAN_OVERLAP, "data rva overlaps rdata"},
    {492, 4, 2048, ERR_SPAN_OVERLAP, "data raw overlaps rdata"},
    {512, 8, 0, ERR_BAD_SECTION_NAME, "reloc name"},
    {520, 4, 0, ERR_BAD_VIRTUAL_SPAN, "reloc virtual size zero"},
    {532, 4, 2560, ERR_SPAN_OVERLAP, "reloc raw overlaps data"},
    {532, 4, 3584, ERR_RAW_OUT_OF_FILE, "reloc raw past file"},
    {548, 4, UINT32_C(0x42000020), ERR_BAD_SECTION_FLAGS, "reloc flags"},
    {3072, 4, 0x100000, ERR_BAD_RELOC_DIR, "relocation page unmapped"},
    {3076, 4, 8, ERR_BAD_RELOC_DIR, "relocation block without entries"},
    {3076, 4, 16, ERR_BAD_RELOC_DIR, "relocation block overruns directory"},
    {3080, 2, 0x2000, ERR_BAD_RELOC_DIR, "relocation type"},
    {3080, 2, 0xa001, ERR_BAD_RELOC_DIR, "relocation offset alignment"},
    {3080, 2, 0, ERR_BAD_RELOC_DIR, "relocation entry zeroed"}};

static const Fixture fixtures[] = {
    {"text-only", 11, 0, 0, 0, {{0, 0, 8}}, 0},
    {"entry-offset", 1024, 17, 23, 113, {{0, 0, 8}}, 0},
    {"cross-page-sections", 8193, 8197, 12001, 4113, {{0, 0, 8}}, 0},
    {"rdata-only", 64, 4096, 0, 16, {{2, 0, 8}}, 1},
    {"data-only", 64, 0, 64, 8, {{3, 0, 8}}, 1},
    {"unsorted-multipage-dir64",
     8200,
     8200,
     16384,
     17,
     {{3, 8192, 8}, {1, 4092, 8}, {2, 4088, 8}, {3, 0, 8}, {1, 64, 8}, {2, 8, 8}, {3, 4096, 8}},
     7}};

static int build_program(const char **paths, unsigned count,
                         NovaHostImage *image, char **owned) {
  NtFInput inputs[8];
  size_t sizes[8];
  int all = count <= 8;
  for (unsigned i = 0; i < count; i++) {
    owned[i] = load(paths[i], sizes + i);
    if (!owned[i])
      all = 0;
    inputs[i] = (NtFInput){paths[i], owned[i], sizes[i]};
  }
  NtArtifact artifact = {0};
  int compiled = all && nova_compile_many_v2(inputs, count, &artifact);
  CHECK(compiled, "Nova modules compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", artifact.error.code, artifact.error.line,
            artifact.error.column, artifact.error.message);
  if (compiled)
    CHECK(nova_host_map(&artifact, image), "map generated machine code");
  if (compiled)
    nt_artifact_free(&artifact);
  return compiled;
}

static void run_fixture(const NovaHostImage *writer,
                        const NovaHostImage *inspector, const Fixture *f) {
  uint8_t *oracle = NULL, *nova = NULL;
  size_t oracle_size = 0, nova_size = 0;
  int made = build_oracle(f, &oracle, &oracle_size);
  CHECK(made && oracle, f->label);
  if (!made || !oracle)
    return;
  uint64_t expected[WORDS];
  reference_summary(oracle, expected);
  int written = writer_pe(writer, f, &nova, &nova_size);
  CHECK(written, "Nova PE writer accepts the fixture inputs");
  if (written)
    CHECK(nova_size == oracle_size && !memcmp(nova, oracle, oracle_size),
          "Nova PE writer reproduces the C oracle image");
  expect_ok(inspector, oracle, oracle_size, expected, f->label);
  if (written)
    expect_ok(inspector, nova, nova_size, expected, "Nova writer image summary");
  /* The image is borrowed read-only: the inspector cannot corrupt its input. */
  uint8_t *copy = malloc(oracle_size);
  if (copy) {
    memcpy(copy, oracle, oracle_size);
    expect_ok(inspector, copy, oracle_size, expected, "summary is input stable");
    free(copy);
  }
  expect_error(inspector, oracle, oracle_size, WORDS - 1, ERR_SHORT_OUTPUT,
               "one word short output");
  expect_error(inspector, oracle, oracle_size, 0, ERR_SHORT_OUTPUT,
               "empty output");
  uint8_t *longer = malloc(oracle_size + 1);
  if (longer) {
    memcpy(longer, oracle, oracle_size);
    longer[oracle_size] = 0x5a;
    expect_error(inspector, longer, oracle_size + 1, WORDS, ERR_FILE_LENGTH,
                 "trailing byte after last raw span");
    free(longer);
  }
  free(nova);
  free(oracle);
}

static void run_corruptions(const NovaHostImage *inspector, const uint8_t *pe,
                            size_t size) {
  for (unsigned i = 0; i < sizeof corruptions / sizeof *corruptions; i++) {
    const Corruption *c = corruptions + i;
    if (c->at + c->width > size)
      continue;
    uint8_t *copy = malloc(size);
    if (!copy)
      exit(2);
    memcpy(copy, pe, size);
    if (c->width == 2)
      wr16(copy + c->at, (uint16_t)c->value);
    else if (c->width == 4)
      wr32(copy + c->at, (uint32_t)c->value);
    else
      wr64(copy + c->at, c->value);
    expect_error(inspector, copy, size, WORDS, c->code, c->label);
    free(copy);
  }
}

/* Multi-block relocation directory corruption on "unsorted-multipage-dir64". */
typedef struct {
  unsigned block;
  size_t field;
  unsigned width;
  uint64_t value;
  const char *label;
} BlockCorruption;

static const BlockCorruption block_cases[] = {
    {1, 0, 4, 0, "second block page repeats the first"},
    {1, 0, 4, UINT32_C(0x100000), "second block page unmapped"},
    {1, 4, 4, 0, "second block size zero"},
    {1, 4, 4, 4, "second block size underflow"},
    {2, 8, 2, 0xb000, "second block entry type"},
    {1, 8, 2, 0xa020, "second block entry not increasing"}};

/* Locates the first relocation block and returns its raw offset. */
static uint64_t relocation_block(const uint8_t *pe, unsigned index) {
  uint64_t l = rd32(pe + 60), table = l + 264;
  uint64_t at = rd32(pe + table + 3 * 40 + 20);
  for (unsigned i = 0; i < index; i++)
    at += rd32(pe + at + 4);
  return at;
}

static void run_blocks(const NovaHostImage *inspector, const uint8_t *pe,
                       size_t size) {
  for (unsigned i = 0; i < sizeof block_cases / sizeof *block_cases; i++) {
    const BlockCorruption *b = block_cases + i;
    uint64_t at = relocation_block(pe, b->block) + b->field;
    if (at + b->width > size)
      continue;
    uint8_t *copy = malloc(size);
    if (!copy)
      exit(2);
    memcpy(copy, pe, size);
    if (b->width == 2)
      wr16(copy + at, (uint16_t)b->value);
    else
      wr32(copy + at, (uint32_t)b->value);
    expect_error(inspector, copy, size, WORDS, ERR_BAD_RELOC_DIR, b->label);
    free(copy);
  }
}

static void run_truncations(const NovaHostImage *inspector, const uint8_t *pe,
                            size_t size) {
  static const size_t boundaries[] = {0,   1,   2,   59,  60,  63,  64,  65,
                                      127, 128, 129, 391, 392, 393, 551, 552,
                                      553, 1023, 1024, 1025, 2047, 2048, 2049,
                                      2559, 2560, 2561, 3071, 3072, 3073};
  for (unsigned i = 0; i < sizeof boundaries / sizeof *boundaries; i++) {
    size_t n = boundaries[i];
    if (n > size)
      continue;
    uint64_t code = n < 64 ? ERR_TRUNCATED_DOS
                           : (n < 552 ? ERR_TRUNCATED_HEADERS
                                      : ERR_RAW_OUT_OF_FILE);
    char label[64];
    snprintf(label, sizeof label, "truncated to %zu bytes", n);
    expect_error(inspector, pe, n, WORDS, code, label);
  }
  char label[64];
  snprintf(label, sizeof label, "truncated to %zu bytes", size - 1);
  expect_error(inspector, pe, size - 1, WORDS, ERR_RAW_OUT_OF_FILE, label);
}

/* ---------------------------------------------------------------------------
 * HAND-BUILT SHAPES, AND WHY THE VERDICT IS READ FROM THE C ORACLE.
 *
 * nt_pe_inspect is the loader and it is the authority on what may be loaded.
 * Every image below is built here rather than reached, and every verdict is
 * read from nt_pe_inspect at run time, so this gate confronts the real loader
 * instead of restating a belief about it. The stable code is the one the Nova
 * header documents for that defect; if the loader ever started accepting one
 * of these shapes, the loader-accepts branch stops running and the gate says
 * so instead of quietly passing.
 *
 * The first two shapes are contiguity holes: a later section is moved forward
 * and every field that depends on it is carried, so the image is internally
 * consistent and the only thing wrong with it is the gap. The third is not a
 * hole at all. See the comment on short_span for what it is and how it was
 * found.
 *
 * CORRECTION, and it is the reason this header was rewritten. This block used
 * to claim that ntasm_pe_inspect asks a weaker question than the loader --
 * overlap and per-section alignment instead of contiguity, which a hole
 * satisfies. That claim was STALE. It described a validator that no longer
 * exists: the contiguity clauses it claimed were missing are in
 * pe_inspect.nova and are exactly what the two hole cases test. A stale
 * comment that describes a stricter validator as weaker is the worst of the
 * two directions, because it reads as a known and accepted limit.
 *
 * A second sweep settled what the real weaker question was, and it is not
 * this one. It is the page-rounded virtual extent in the relocation-site
 * mapping, and it was unsound rather than merely permissive.
 * ------------------------------------------------------------------------- */
static int loader_accepts(const uint8_t *pe, size_t size) {
  NtPeInfo info;
  NtDiagnostic error = {0};
  return nt_pe_inspect(pe, size, &info, &error);
}

/* One 4096-byte hole between .rdata and .data. .data and .reloc move up a
 * page; SizeOfImage and the relocation directory RVA follow them. The
 * relocation block itself keeps naming the .rdata anchor page, so the
 * directory stays consistent and only the virtual chain is broken. */
static uint8_t *hole_virtual(const uint8_t *pe, size_t size, size_t *out) {
  uint8_t *m = malloc(size);
  if (!m)
    exit(2);
  memcpy(m, pe, size);
  uint64_t l = rd32(pe + 60), o = l + 24, table = l + 264;
  wr32(m + table + 2 * 40 + 12, rd32(pe + table + 2 * 40 + 12) + 4096);
  wr32(m + table + 3 * 40 + 12, rd32(pe + table + 3 * 40 + 12) + 4096);
  wr32(m + o + 56, rd32(pe + o + 56) + 4096);
  wr32(m + o + 112 + 40, rd32(pe + o + 112 + 40) + 4096);
  *out = size;
  return m;
}

/* One 512-byte hole in the file between .rdata's raw bytes and .data's. The
 * tail of the image is carried up by the hole, so the last raw span still ends
 * at the end of the file and only the raw chain is broken. */
static uint8_t *hole_raw(const uint8_t *pe, size_t size, size_t *out) {
  const uint32_t gap = 512;
  uint8_t *m = calloc(size + gap, 1);
  if (!m)
    exit(2);
  uint64_t table = rd32(pe + 60) + 264;
  uint32_t data_raw = rd32(pe + table + 2 * 40 + 20);
  memcpy(m, pe, data_raw);
  memcpy(m + data_raw + gap, pe + data_raw, size - data_raw);
  for (unsigned i = 2; i < 4; i++) {
    uint32_t at = table + i * 40 + 20;
    wr32(m + at, rd32(pe + at) + gap);
  }
  *out = size + gap;
  return m;
}

/* .rdata's VirtualSize is cut to ONE byte, and nothing else moves. This is
 * not a hole and it is not a contiguity defect; it is the other weaker
 * question, and it was found by measurement rather than by reading.
 *
 * align(1,512) is still this section's raw size, and align(8192+1,4096) is
 * still 12288, which is where .data already sits, so the section walk, both
 * chains and the rawsize clause all pass unchanged. What changes is where the
 * loader puts a relocation SITE: map() places an 8-byte DIR64 site with
 * `within(rva - s->va, 8, s->vs)` and the same against the raw size (pe.c:29),
 * and the anchor the writer always emits at the start of .rdata no longer has
 * eight bytes to land in.
 *
 * ntasm_pe_inspect used to ask only whether the PAGE was covered by the
 * section's page-ROUNDED extent, which is still true at one byte, and it
 * accepted the image. A 166513-image sweep of mutated writer images against
 * the loader found 42 in exactly this direction and none the other way for
 * this clause; every one of the 42 was a section with VirtualSize 1, 2 or 4
 * and the loader's reason was "invalid DIR64 relocation site". */
static uint8_t *short_span(const uint8_t *pe, size_t size, size_t *out) {
  uint8_t *m = malloc(size);
  if (!m)
    exit(2);
  memcpy(m, pe, size);
  uint64_t table = rd32(pe + 60) + 264;
  wr32(m + table + 1 * 40 + 8, 1);
  *out = size;
  return m;
}

typedef struct {
  const char *label;
  uint8_t *(*build)(const uint8_t *, size_t, size_t *);
  uint64_t code;
} Hole;

static const Hole holes[] = {
    {"hole between .rdata and .data in virtual space", hole_virtual,
     ERR_BAD_VIRTUAL_SPAN},
    {"hole between .rdata and .data in the file", hole_raw,
     ERR_BAD_RAW_LAYOUT},
    {"relocation site does not fit the section's exact virtual size",
     short_span, ERR_BAD_RELOC_DIR},
};

/* The base image is the control: the loader accepts it and so must Nova, or
 * the refusals below would prove nothing. */
static void expect_loader_baseline(const NovaHostImage *inspector,
                                   const uint8_t *pe, size_t size,
                                   const uint64_t *expected) {
  CHECK(loader_accepts(pe, size), "the C loader accepts the writer's image");
  expect_ok(inspector, pe, size, expected, "baseline agrees with the loader");
}

static void run_holes(const NovaHostImage *inspector, const uint8_t *pe,
                      size_t size) {
  for (unsigned i = 0; i < sizeof holes / sizeof *holes; i++) {
    const Hole *h = holes + i;
    size_t n = 0;
    uint8_t *m = h->build(pe, size, &n);
    int accepted = loader_accepts(m, n);
    if (accepted) {
      /* Counted here because this branch checks by hand; the other branch
       * counts itself inside expect_error. */
      cases++;
      /* Direction matters. The loader honours this layout, so refusing it
       * would be Nova inventing a restriction the loader does not have. */
      uint64_t out[WORDS + GUARDS];
      for (unsigned k = 0; k < WORDS + GUARDS; k++)
        out[k] = GUARD;
      uint64_t got = inspect(inspector, m, n, out, WORDS);
      CHECK(got == 0, h->label);
      if (got != 0)
        fprintf(stderr, "FAIL loader accepts a layout Nova refuses: %s "
                        "returned=%" PRIu64 "\n", h->label, got);
    } else {
      expect_error(inspector, m, n, WORDS, h->code, h->label);
    }
    free(m);
  }
}


/* ---------------------------------------------------------------------------
 * REACHABILITY: WHAT THE CONTINUITY CLAUSES CAN AND CANNOT BE RED BY.
 *
 * pe_inspect.nova:154-155 refuses any image where a section does not continue
 * the previous one exactly, in memory and in the file. pe.c:80 refuses the
 * same shapes. The question this block answers is not "does the code run" but
 * "is there any ntasm_pe.emit output it can refuse", because a check that no
 * reachable input can contradict is counted as coverage while measuring
 * nothing.
 *
 * The answer for the current writer is NO, and it is structural rather than
 * empirical. pe.nova:96-98 derives every rva as align(previous_rva+previous_
 * size,4096) and pe.nova:119-120 derives every raw pointer the same way with
 * 512, and pe_inspect.nova:128-157 threads its two chains over exactly those
 * expressions from the same two seeds. The chains are therefore equal by
 * construction: align(x,a) >= x, so a gap cannot be introduced without first
 * being written into the writer. A 7124-case sweep of writer output found zero
 * rejections, but the sweep only confirms the algebra; the algebra is the
 * reason, and the reason is in this comment.
 *
 * So the clauses are not dead code -- they are UNREACHABLE-FROM-THE-WRITER.
 * That is a different statement from "vacuous", and it is worth measuring
 * rather than asserting: below, pe.nova is recompiled in memory with one
 * expression replaced by a broken one, the mutant writer emits real images,
 * and the inspector is run on those. Nothing is written to the tree, so a case
 * that needs a broken writer cannot leave one behind.
 *
 * WHAT THIS IS NOT. These cases are a REACHABILITY PROBE, not writer
 * coverage. The images they inspect do not exist; ntasm_pe.emit cannot produce
 * them. A red here means the inspector lost the ability to see a defect class,
 * and it says nothing about any defect ntasm_pe.emit can actually commit. The
 * banner says so in those words, because the alternative is a green number
 * that reads as evidence of a writer property and is evidence of nothing.
 *
 * The two oracle-image cases above are the complementary half and they are NOT
 * vacuous: they pin the inspector against the real loader on a shape the
 * writer cannot emit, which is the loader contract and stays worth having.
 * ------------------------------------------------------------------------- */
typedef struct {
  const char *label;
  const char *from;
  const char *to;
  uint64_t code;
} WriterMutation;

/* Each anchor is a whole statement that occurs exactly once in pe.nova, and
 * each replacement is a defect a writer could plausibly commit: a page of
 * padding nobody asked for, a file gap, an alignment dropped. Every field that
 * follows the mutated expression is still DERIVED from it, so the emitted
 * image is internally consistent and the only thing wrong with it is the
 * defect named in the label. That is what makes the refusal attributable. */
static const WriterMutation writer_mutations[] = {
    {"writer leaves a 4096-byte hole between .rdata and .data in memory",
     "let data_rva:u64=align(ro_rva+ro_size,4096);",
     "let data_rva:u64=align(ro_rva+ro_size,4096)+4096;",
     ERR_BAD_VIRTUAL_SPAN},
    {"writer leaves a 512-byte hole between .rdata and .data in the file",
     "let data_raw:u64=ro_raw+ro_raw_size;",
     "let data_raw:u64=ro_raw+ro_raw_size+512;",
     ERR_BAD_RAW_LAYOUT},
    {"writer stops aligning .text raw to the 512-byte file alignment",
     "let text_raw:u64=align(text_size,512);",
     "let text_raw:u64=text_size;",
     ERR_BAD_RAW_LAYOUT}};

static const char *substr_find(const char *hay, size_t n, const char *needle,
                               size_t m) {
  if (m == 0 || n < m)
    return NULL;
  for (size_t i = 0; i + m <= n; i++)
    if (hay[i] == needle[0] && !memcmp(hay + i, needle, m))
      return hay + i;
  return NULL;
}

/* Returns NULL unless the anchor occurs EXACTLY ONCE and the replacement
 * actually changes the text. All three refusals matter, and all three are the
 * anti-vacuity guard: an anchor that vanished in an unrelated edit, an anchor
 * that became ambiguous, and a replacement equal to its own anchor would each
 * produce a "case" in which the mutant writer is the correct writer and the
 * assertion underneath it proves nothing. Such a run must be RED, not
 * skipped. */
static char *apply_writer_mutation(const char *src, size_t n,
                                   const WriterMutation *m, size_t *out_len) {
  size_t fl = strlen(m->from), tl = strlen(m->to);
  if (fl == 0 || fl == tl)
    return NULL;
  const char *at = substr_find(src, n, m->from, fl);
  if (!at)
    return NULL;
  size_t head = (size_t)(at - src);
  if (substr_find(at + fl, n - head - fl, m->from, fl))
    return NULL;
  char *r = malloc(n - fl + tl + 1);
  if (!r)
    exit(2);
  memcpy(r, src, head);
  memcpy(r + head, m->to, tl);
  memcpy(r + head + tl, at + fl, n - head - fl);
  r[n - fl + tl] = 0;
  *out_len = n - fl + tl;
  return r;
}

/* Compiles the writer entry point against a MUTATED pe.nova that exists only
 * in this process. The two source names are the real paths on purpose: the
 * module identity comes from the declared `module` line, not the file name,
 * and using the real paths keeps everything except the defect itself
 * identical between the two builds. */
static int build_mutant_writer(const char *entry_path, const char *writer_path,
                               const char *mutant, size_t mutant_len,
                               NovaHostImage *image) {
  size_t entry_len = 0;
  char *entry_src = load(entry_path, &entry_len);
  if (!entry_src)
    return 0;
  int ok = 0;
  NtFInput inputs[2] = {{entry_path, entry_src, entry_len},
                        {writer_path, mutant, mutant_len}};
  NtArtifact artifact = {0};
  if (nova_compile_many_v2(inputs, 2, &artifact)) {
    CHECK(nova_host_map(&artifact, image), "mutated PE writer maps");
    ok = image->memory != NULL;
    nt_artifact_free(&artifact);
  } else {
    fprintf(stderr, "MUTANT_COMPILE_FAIL E%u %zu:%zu %s\n", artifact.error.code,
            artifact.error.line, artifact.error.column, artifact.error.message);
  }
  free(entry_src);
  return ok;
}

/* The control. Without it a mutant that is not really broken would be read as
 * "the inspector caught it", because the two cases would be indistinguishable
 * on a gate that only counted checks. */
static void expect_writer_control(const NovaHostImage *inspector,
                                   const uint8_t *pe, size_t size,
                                   const uint64_t *expected) {
  CHECK(loader_accepts(pe, size), "the C loader accepts the unmutated writer");
  expect_ok(inspector, pe, size, expected, "the unmutated writer is accepted");
}

static void run_writer_mutations(const NovaHostImage *writer,
                                 const NovaHostImage *inspector) {
  static const char *entry_path = "tests/nova/tests/pe-entry.nova";
  static const char *writer_path = "compiler/nova/formats/pe/pe.nova";
  size_t n = 0;
  char *source = load(writer_path, &n);
  CHECK(source != NULL, "the PE writer source is readable for mutation");
  if (!source)
    return;
  for (unsigned i = 0; i < sizeof writer_mutations / sizeof *writer_mutations;
       i++) {
    const WriterMutation *m = writer_mutations + i;
    wm_mutations++;
    size_t len = 0;
    char *mutant = apply_writer_mutation(source, n, m, &len);
    if (!mutant) {
      wm_unbuilt++;
      cases++;
      CHECK(0, "the writer mutation anchor is present exactly once");
      fprintf(stderr,
              "FAIL writer mutation anchor is missing, ambiguous or a no-op: %s\n",
              m->label);
      continue;
    }
    NovaHostImage broken = {0};
    if (!build_mutant_writer(entry_path, writer_path, mutant, len, &broken)) {
      wm_unbuilt++;
      cases++;
      CHECK(0, "the mutated writer compiles");
      free(mutant);
      continue;
    }
    for (unsigned f = 0; f < sizeof fixtures / sizeof *fixtures; f++) {
      const Fixture *fx = fixtures + f;
      uint8_t *base = NULL, *image = NULL;
      size_t base_size = 0, image_size = 0;
      int made_base = writer_pe(writer, fx, &base, &base_size);
      int made = made_base && writer_pe(&broken, fx, &image, &image_size);
      wm_pairs++;
      if (!made) {
        cases++;
        CHECK(0, "the mutated writer emits an image");
        free(image);
        free(base);
        continue;
      }
      if (image_size == base_size && !memcmp(image, base, base_size)) {
        /* The defect is invisible on this input, and it is NOT a pass. For the
         * .text alignment mutation that is every fixture whose .text is
         * already a multiple of 512, where text_raw == text_size and the
         * mutant image is the good one byte for byte. Counted, never counted
         * as coverage, and printed so the number is re-derivable. */
        wm_noop++;
        free(image);
        free(base);
        continue;
      }
      wm_observable++;
      int refused = !loader_accepts(image, image_size);
      if (refused)
        wm_loader++;
      else
        fprintf(stderr,
                "FAIL the C loader accepts a mutated writer's image: %s [%s]\n",
                m->label, fx->label);
      CHECK(refused, "the C loader refuses the mutated writer's image");
      char label[160];
      snprintf(label, sizeof label, "%s [%s]", m->label, fx->label);
      if (expect_error(inspector, image, image_size, WORDS, m->code, label))
        wm_inspector++;
      free(image);
      free(base);
    }
    nova_host_unmap(&broken);
    free(mutant);
  }
  /* The floors. wm_observable==0 would mean the mutations never changed a
   * single byte and the entire block proved nothing while staying green. */
  cases++;
  CHECK(wm_mutations == sizeof writer_mutations / sizeof *writer_mutations,
        "every writer mutation was built");
  cases++;
  CHECK(wm_observable > 0, "at least one writer mutation changed an image");
  cases++;
  CHECK(wm_loader == wm_observable,
        "the C loader refuses every observable mutated writer image");
  cases++;
  CHECK(wm_inspector == wm_observable,
        "the inspector refuses every observable mutated writer image");
  free(source);
}



int main(void) {
  static const char *writer_paths[] = {"tests/nova/tests/pe-entry.nova",
                                       "compiler/nova/formats/pe/pe.nova"};
  static const char *inspector_paths[] = {
      "tests/nova/tests/pe-inspect-entry.nova",
      "compiler/nova/inspectors/pe_inspect.nova",
      "compiler/nova/formats/pe/pe.nova"};
  char *writer_owned[2] = {0}, *inspector_owned[3] = {0};
  NovaHostImage writer = {0}, inspector = {0};
  int writer_ok = build_program(writer_paths, 2, &writer, writer_owned);
  int inspector_ok =
      build_program(inspector_paths, 3, &inspector, inspector_owned);
  CHECK(writer_ok && inspector_ok, "PE writer and inspector both build");
  if (writer_ok && inspector_ok) {
    for (unsigned i = 0; i < sizeof fixtures / sizeof *fixtures; i++)
      run_fixture(&writer, &inspector, fixtures + i);
    uint8_t *pe = NULL;
    size_t size = 0;
    if (build_oracle(fixtures + 1, &pe, &size)) {
      uint64_t baseline[WORDS];
      reference_summary(pe, baseline);
      expect_loader_baseline(&inspector, pe, size, baseline);
      run_holes(&inspector, pe, size);
      run_corruptions(&inspector, pe, size);
      run_truncations(&inspector, pe, size);
      free(pe);
    } else {
      CHECK(0, "corruption base image");
    }
    if (build_oracle(fixtures + 5, &pe, &size)) {
      run_blocks(&inspector, pe, size);
      free(pe);
    } else {
      CHECK(0, "multi block base image");
    }
    /* Baseline from the WRITER, not from the oracle: the mutated cases below
     * are compared against it byte for byte, and comparing them against an
     * oracle image would be the mistake this gate was written to end. */
    {
      uint8_t *fresh = NULL;
      size_t fresh_size = 0;
      if (writer_pe(&writer, fixtures + 1, &fresh, &fresh_size)) {
        uint64_t expected[WORDS];
        reference_summary(fresh, expected);
        expect_writer_control(&inspector, fresh, fresh_size, expected);
        free(fresh);
      } else {
        CHECK(0, "the unmutated writer emits the control image");
      }
    }
    run_writer_mutations(&writer, &inspector);
  }
  if (writer.memory)
    nova_host_unmap(&writer);
  if (inspector.memory)
    nova_host_unmap(&inspector);
  for (unsigned i = 0; i < 2; i++)
    free(writer_owned[i]);
  for (unsigned i = 0; i < 3; i++)
    free(inspector_owned[i]);
  printf("NTASM_NOVA_PE_INSPECT checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  /* The banner states the limit, because a limit that lives only in a report
   * is a hidden coverage hole. Three clauses, and each one names what it does
   * NOT cover:
   *   continuity    the 836/837 clauses cannot be red by any ntasm_pe.emit
   *                 output; pe.nova derives both chains with align() and the
   *                 two sides are equal by construction
   *   writer_cases  the observable=N below are a reachability probe on images
   *                 ntasm_pe.emit cannot emit; they are not writer coverage
   *   shape_cases   the shapes above are hand-built mutations of an ORACLE
   *                 image: two contiguity holes and one relocation site that
   *                 does not fit its section's exact virtual size
   * and noop is printed so the number of mutation/fixture pairs where the
   * defect was invisible rather than undetected can be re-derived. */
  printf("NTASM_NOVA_PE_INSPECT_WRITER mutations=%u pairs=%u observable=%u "
         "loader_rejects=%u inspector_rejects=%u invisible=%u unbuilt=%u "
         "limits=continuity:unreachable_from_ntasm_pe_emit_output_by_"
         "construction; writer_cases:reachability_probe_not_writer_coverage; "
         "shape_cases:hand_built_mutations_of_an_ORACLE_image\n",
         wm_mutations, wm_pairs, wm_observable, wm_loader, wm_inspector,
         wm_noop, wm_unbuilt);
  return failures ? 1 : 0;
}
