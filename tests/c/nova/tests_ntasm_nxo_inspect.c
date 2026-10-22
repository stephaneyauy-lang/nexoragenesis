/* tests_ntasm_nxo_inspect.c -- OPENS THE SECOND DOOR.
 *
 * The door: tests/nova/tests/nxo-inspect-entry.nova, which until now
 * was written and loaded by nobody. It is five lines wide --
 *
 *     fn main(input,out) = inspect(input,out)          on success
 *                        = 2^63 + code                  on refusal
 *
 * -- and it is the ONLY caller-visible route to ntasm_nxo_inspect.inspect,
 * the seven-word summary every reproducible manifest is built from.
 *
 * WHAT IT PUBLISHES. Seven u64s, in this order, from the module's own header
 * sentence "Output order: target, entry, text, rdata, data, symbols,
 * relocations": the target id, the entry symbol index, the three section byte
 * lengths, and the two record counts. On refusal it returns 2^63 + the code
 * instead, which is this entry's own encoding and is asserted below.
 *
 * THE PROPERTY IS A THREE-HALF ROUND TRIP, NOT A COMPARISON WITH A TABLE.
 *   1. The C WRITER nt_object_write (object.c) turns an NtObject into bytes.
 *   2. THIS ENTRY reads those bytes with the Nova reader and publishes seven
 *      numbers.
 *   3. The C READER nt_object_read (object.c) reads the SAME bytes back.
 * All three are production code on this tree: nt_object_write is what the
 * compiler emits through, nt_object_read is what object_link and
 * object_materialize parse through, and neither of them knows this file
 * exists. A gate that compared the seven words with a literal row written
 * beside it would be asserting a table; this one asserts that the Nova header
 * offsets and the C header offsets agree, which is the only thing that could
 * have gone wrong and has.
 *
 * THE SUMMARY MUST MOVE. Seven words that never changed would prove nothing,
 * and a reader could not tell that from seven words that were always right.
 * So the fixture family varies ONE dimension at a time -- target, entry, each
 * section length, the symbol count, the relocation count -- and asserts that
 * the corresponding word moved to the new value and that no other word did.
 * That is what distinguishes a summary read out of the bytes from a summary
 * fabricated next to the reader, and it is asserted rather than assumed.
 *
 * THE REFUSALS ARE ASSERTED ON WHAT THEY LEAVE BEHIND. Every output word is
 * poisoned with a sentinel before the call and must still hold it afterwards:
 * a refused inspect that had written a partial summary would be read by a
 * caller that only checks the return code, and a caller that only checks the
 * return code is exactly the caller this door serves.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include <inttypes.h>
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

#define GUARD UINT64_C(0xcccccccccccccccc)
#define REFUSAL_BIT UINT64_C(0x8000000000000000)
#define SUMMARY_WORDS 7
#define SLOTS 12

static char *load(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *p = n >= 0 ? malloc((size_t)n + 1) : NULL;
  if (!p || fread(p, 1, (size_t)n, f) != (size_t)n) {
    free(p);
    fclose(f);
    return NULL;
  }
  fclose(f);
  p[n] = 0;
  *length = (size_t)n;
  return p;
}

/* One call. `words` is what the caller offers, so the "output too small"
 * refusal is reachable by the same path as every other one. */
static uint64_t invoke(const NovaHostImage *image, const uint8_t *bytes,
                       size_t size, uint64_t *out, uint64_t words,
                       uint64_t *runtime_error) {
  NovaContextV2 c = {0};
  *runtime_error = UINT64_MAX;
  if (!nova_context_init_v2(&c)) return UINT64_MAX;
  uint64_t args[4] = {nova_borrow_v2(&c, (void *)bytes, size, 0), size,
                      nova_borrow_v2(&c, out, words * 8, 1), words};
  uint64_t returned = image->entry(&c, args, 4);
  *runtime_error = c.error;
  if (!nova_context_destroy_v2(&c)) return UINT64_MAX;
  return returned;
}

typedef struct {
  uint32_t target, entry;
  size_t text, rdata, data;
  size_t symbols, relocations;
} Shape;

/* A shape turned into an NtObject, written, and handed back. The symbols are
 * FUNCTIONS in .text at 8-byte strides and the relocations point at them, so
 * the fixture satisfies nxo.nova's own validate() -- every one of its rules,
 * the name ordering and the contract length included -- rather than relying on
 * the writer to be lenient. */
static int make_object(const Shape *s, NtObject *object, NtBuffer *file,
                       NtDiagnostic *error) {
  memset(object, 0, sizeof *object);
  memset(file, 0, sizeof *file);
  memset(error, 0, sizeof *error);
  uint8_t *text = calloc(s->text ? s->text : 1, 1);
  uint8_t *rdata = calloc(s->rdata ? s->rdata : 1, 1);
  uint8_t *data = calloc(s->data ? s->data : 1, 1);
  NtObjectSymbol *syms =
      calloc(s->symbols ? s->symbols : 1, sizeof *syms);
  NtObjectReloc *relocs =
      calloc(s->relocations ? s->relocations : 1, sizeof *relocs);
  char (*names)[8] = calloc(s->symbols ? s->symbols : 1, sizeof *names);
  if (!text || !rdata || !data || !syms || !relocs || !names) {
    free(text); free(rdata); free(data); free(syms); free(relocs); free(names);
    return 0;
  }
  for (size_t i = 0; i < s->text; i++) text[i] = (uint8_t)(i * 31 + 7);
  for (size_t i = 0; i < s->data; i++) data[i] = (uint8_t)(i * 17 + 3);
  /* Names sort ascending by construction: f000, f001, ... A fixture whose
   * symbol names were out of order would be refused by the reader, and a
   * refusal would be indistinguishable here from a defect in the summary. */
  for (size_t i = 0; i < s->symbols; i++) {
    /* Spelled by hand rather than with a printf: the name buffer is four
     * bytes wide and -Werror=format-truncation is right that a size_t can be
     * twenty digits. Four characters and a bound are both explicit. */
    if (i > 999) {
      free(text); free(rdata); free(data); free(syms); free(relocs);
      free(names);
      return 0;
    }
    names[i][0] = 'f';
    names[i][1] = (char)('0' + (int)((i / 100) % 10));
    names[i][2] = (char)('0' + (int)((i / 10) % 10));
    names[i][3] = (char)('0' + (int)(i % 10));
    names[i][4] = 0;
    syms[i].name = names[i];
    syms[i].contract = "fn:u64";
    syms[i].section = NT_OBJECT_TEXT;
    syms[i].flags = NT_OBJECT_FUNCTION;
    syms[i].offset = i * 8;
    syms[i].size = 8;
  }
  for (size_t i = 0; i < s->relocations; i++) {
    relocs[i].section = NT_OBJECT_TEXT;
    relocs[i].kind = NT_OBJECT_REL32;
    relocs[i].offset = i * 8;
    relocs[i].target = (uint32_t)(i % (s->symbols ? s->symbols : 1)) + 1u;
    relocs[i].addend = 0;
  }
  object->target = s->target;
  object->entry_symbol = s->entry;
  object->sections[NT_OBJECT_TEXT - 1] = (NtBuffer){text, s->text, s->text};
  object->sections[NT_OBJECT_RDATA - 1] =
      (NtBuffer){rdata, s->rdata, s->rdata ? s->rdata : 1};
  object->sections[NT_OBJECT_DATA - 1] = (NtBuffer){data, s->data, s->data};
  object->symbols = syms;
  object->symbol_count = s->symbols;
  object->relocations = relocs;
  object->relocation_count = s->relocations;

  int wrote = nt_object_write(object, file, error);
  free(text);
  free(rdata);
  free(data);
  free(syms);
  free(relocs);
  free(names);
  if (!wrote) return 0;
  return 1;
}

static void expect(const NovaHostImage *image, const Shape *s,
                   const char *label, const uint64_t *baseline) {
  NtObject object = {0};
  NtBuffer file = {0};
  NtDiagnostic error = {0};
  cases++;
  if (!make_object(s, &object, &file, &error)) {
    failures++;
    fprintf(stderr, "FAIL the C writer refused the %s fixture: E%u %s\n", label,
            error.code, error.message);
    return;
  }

  /* Half three: the C reader, on the SAME bytes. */
  NtObject back = {0};
  NtDiagnostic read_error = {0};
  int read_ok = nt_object_read(file.bytes, file.size, &back, &read_error);
  if (!read_ok) {
    failures++;
    fprintf(stderr, "FAIL the C reader refused the %s fixture the C writer "
                    "produced: E%u %s\n",
            label, read_error.code, read_error.message);
    nt_object_free(&back);
    free(file.bytes);
    return;
  }

  uint64_t out[SLOTS];
  for (unsigned i = 0; i < SLOTS; i++) out[i] = GUARD;
  uint64_t error_code = 0;
  uint64_t returned =
      invoke(image, file.bytes, file.size, out, SUMMARY_WORDS, &error_code);

  CHECK(error_code == 0, "no runtime error");
  checks++;
  if (returned != 0) {
    failures++;
    fprintf(stderr, "FAIL %s returned %" PRIu64 " on a file the C writer and "
                    "the C reader both accept\n",
            label, returned);
  } else {
    const uint64_t want[SUMMARY_WORDS] = {back.target,
                                          back.entry_symbol,
                                          back.sections[NT_OBJECT_TEXT - 1].size,
                                          back.sections[NT_OBJECT_RDATA - 1].size,
                                          back.sections[NT_OBJECT_DATA - 1].size,
                                          (uint64_t)back.symbol_count,
                                          (uint64_t)back.relocation_count};
    static const char *const field[SUMMARY_WORDS] = {"target", "entry", "text",
                                                     "rdata", "data", "symbols",
                                                     "relocations"};
    for (unsigned i = 0; i < SUMMARY_WORDS; i++) {
      checks++;
      if (out[i] != want[i]) {
        failures++;
        fprintf(stderr,
                "FAIL %s summary word %u (%s) is %" PRIu64 ", the C reader of "
                "the same bytes says %" PRIu64 "\n",
                label, i, field[i], out[i], want[i]);
      }
      /* THE WORD MUST HAVE MOVED, and only where it should. A baseline of
       * all-sentinels means the first shape is exempt. */
      if (baseline && out[i] != baseline[i]) {
        checks++;
        if (want[i] == baseline[i]) {
          failures++;
          fprintf(stderr,
                  "FAIL %s summary word %u (%s) moved to %" PRIu64 " although "
                  "the shape did not change it; it should still read %" PRIu64
                  "\n",
                  label, i, field[i], out[i], baseline[i]);
        }
      }
    }
    /* The word that the varied dimension owns must equal the shape, not just
     * the reader. This is the check the seven words are really for. */
    const uint64_t declared[SUMMARY_WORDS] = {s->target,
                                              s->entry,
                                              s->text,
                                              s->rdata,
                                              s->data,
                                              (uint64_t)s->symbols,
                                              (uint64_t)s->relocations};
    for (unsigned i = 0; i < SUMMARY_WORDS; i++) {
      checks++;
      if (out[i] != declared[i]) {
        failures++;
        fprintf(stderr,
                "FAIL %s summary word %u (%s) is %" PRIu64 ", the shape the C "
                "writer was handed declares %" PRIu64 "\n",
                label, i, field[i], out[i], declared[i]);
      }
    }
    for (unsigned i = SUMMARY_WORDS; i < SLOTS; i++) CHECK(out[i] == GUARD,
                                                           "summary tail guard");
    fprintf(stderr,
            "NXO_INSPECT case=%s target=%" PRIu64 " entry=%" PRIu64
            " text=%" PRIu64 " rdata=%" PRIu64 " data=%" PRIu64 " syms=%" PRIu64
            " relocs=%" PRIu64 "\n",
            label, out[0], out[1], out[2], out[3], out[4], out[5], out[6]);
  }
  nt_object_free(&back);
  free(file.bytes);
}

/* A refusal: the return is 2^63 + code, the code is one the Nova reader
 * publishes, and not one of the seven words moved. */
static void expect_refusal(const NovaHostImage *image, const uint8_t *bytes,
                           size_t size, uint64_t words, uint64_t want_code,
                           const char *label) {
  uint64_t out[SLOTS];
  for (unsigned i = 0; i < SLOTS; i++) out[i] = GUARD;
  uint64_t error_code = 0;
  cases++;
  uint64_t returned = invoke(image, bytes, size, out, words, &error_code);
  CHECK(error_code == 0, "no runtime error on a refusal");
  checks++;
  if (returned != (REFUSAL_BIT + want_code)) {
    failures++;
    fprintf(stderr,
            "FAIL %s returned %" PRIu64 ", which is not 2^63 + %" PRIu64
            "\n",
            label, returned, want_code);
  }
  for (unsigned i = 0; i < SLOTS; i++) {
    checks++;
    if (out[i] != GUARD) {
      failures++;
      fprintf(stderr,
              "FAIL %s is a refusal and it wrote output word %u (%" PRIu64
              "), which a caller that only reads the return code would take\n",
              label, i, out[i]);
    }
  }
  fprintf(stderr, "NXO_INSPECT_REFUSED case=%s size=%zu words=%" PRIu64
                  " returned=%" PRIu64 " code=%" PRIu64 "\n",
          label, size, words, returned, returned & ~REFUSAL_BIT);
}

int main(void) {
  static const char *const paths[] = {
      "tests/nova/tests/nxo-inspect-entry.nova",
      "compiler/nova/inspectors/nxo_inspect.nova",
      "compiler/nova/formats/nxo/nxo.nova",
      "compiler/nova/formats/pe/pe.nova"};
  size_t sizes[4];
  char *sources[4];
  NtFInput inputs[4];
  int loaded = 1;
  for (unsigned i = 0; i < 4; i++) {
    sizes[i] = 0;
    sources[i] = load(paths[i], sizes + i);
    inputs[i] = (NtFInput){paths[i], sources[i], sizes[i]};
    if (!sources[i]) loaded = 0;
  }
  CHECK(loaded, "the inspect entry and its three modules load");
  NtArtifact artifact = {0};
  int compiled = loaded && nova_compile_many_v2(inputs, 4, &artifact);
  CHECK(compiled, "the inspect entry compiles with nxo_inspect, nxo and pe");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", artifact.error.code, artifact.error.line,
            artifact.error.column, artifact.error.message);

  NovaHostImage image = {0};
  CHECK(compiled && nova_host_map(&artifact, &image), "image maps");
  if (image.memory) {
    /* The base shape, then one dimension varied at a time. The baseline is the
     * seven words of the base shape, so a word that moves when it should not
     * is as loud as one that fails to move. */
    const Shape base = {1, 2, 64, 0, 32, 6, 3};
    expect(&image, &base, "base", NULL);

    uint64_t baseline[SUMMARY_WORDS];
    {
      /* Recover the base words for the movement check by running it once with
       * the same call the expect() above makes. */
      NtObject object = {0};
      NtBuffer file = {0};
      NtDiagnostic error = {0};
      if (make_object(&base, &object, &file, &error) && file.bytes) {
        uint64_t out[SLOTS];
        for (unsigned i = 0; i < SLOTS; i++) out[i] = GUARD;
        uint64_t rc = 0;
        invoke(&image, file.bytes, file.size, out, SUMMARY_WORDS, &rc);
        for (unsigned i = 0; i < SUMMARY_WORDS; i++) baseline[i] = out[i];
        free(file.bytes);
      } else {
        failures++;
        fprintf(stderr, "FAIL the base fixture could not be rebuilt for the "
                        "movement baseline\n");
        for (unsigned i = 0; i < SUMMARY_WORDS; i++) baseline[i] = GUARD;
      }
    }

    const Shape varied[] = {
        {2, 2, 64, 0, 32, 6, 3},         /* target    */
        {1, 5, 64, 0, 32, 6, 3},         /* entry     */
        {1, 2, 128, 0, 32, 6, 3},        /* text      */
        {1, 2, 64, 48, 32, 6, 3},        /* rdata     */
        {1, 2, 64, 0, 96, 6, 3},         /* data      */
        /* 8, not 9: a symbol sits at 8*i with a width of 8, so a .text of 64
         * admits exactly eight and a ninth falls outside its section.
         * MEASURED: the first version of this row asked for 9, the C writer
         * refused the FIXTURE, and a red that names neither the fixture nor
         * the summary is a red that teaches nothing. */
        {1, 2, 64, 0, 32, 8, 3},         /* symbols   */
        {1, 2, 64, 0, 32, 6, 7},         /* relocations */
        {2, 5, 128, 48, 96, 9, 7}};      /* all seven */
    static const char *const varied_label[] = {
        "target_moved", "entry_moved", "text_moved", "rdata_moved",
        "data_moved", "symbols_moved", "relocations_moved", "all_moved"};
    for (unsigned i = 0; i < sizeof varied / sizeof varied[0]; i++)
      expect(&image, &varied[i], varied_label[i], baseline);

    /* THE REFUSALS, and each one is a different published rule.
     *   800 -- the Nova reader does not recognise the bytes. Three ways: too
     *          short, a damaged tag, and a truncated body.
     *   809 -- the caller's output buffer cannot hold seven words, which is
     *          inspect's own first line, `if len(out)<7`.
     * 2^63 + code -- this entry's refusal encoding. */
    {
      NtObject object = {0};
      NtBuffer file = {0};
      NtDiagnostic error = {0};
      if (make_object(&base, &object, &file, &error) && file.bytes) {
        static const uint8_t empty[1] = {0};
        expect_refusal(&image, empty, 0, SUMMARY_WORDS, 800, "zero_bytes");
        expect_refusal(&image, file.bytes, 239, SUMMARY_WORDS, 800,
                       "one_byte_short_of_the_header");
        expect_refusal(&image, file.bytes, file.size - 1, SUMMARY_WORDS, 800,
                       "last_byte_removed");
        {
          uint8_t *tag = malloc(file.size);
          memcpy(tag, file.bytes, file.size);
          tag[2] = 'X'; /* the third byte of "NXOV" */
          expect_refusal(&image, tag, file.size, SUMMARY_WORDS, 800,
                         "tag_byte_damaged");
          free(tag);
        }
        /* A caller offering six words, on a file that is otherwise good. */
        expect_refusal(&image, file.bytes, file.size, SUMMARY_WORDS - 1, 809,
                       "six_word_output");
        expect_refusal(&image, file.bytes, file.size, 0, 809, "no_output");
        free(file.bytes);
      } else {
        failures++;
        fprintf(stderr, "FAIL the base fixture could not be written for the "
                        "refusal rows\n");
      }
    }
  }
  if (image.memory) nova_host_unmap(&image);
  if (compiled) nt_artifact_free(&artifact);
  for (unsigned i = 0; i < 4; i++) free(sources[i]);
  printf("NTASM_NOVA_NXO_INSPECT checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  return failures ? 1 : 0;
}
