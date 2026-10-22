/* BOOTSTRAP_C_TEST: THE JOIN GATE. machine_x64.build_object's object, into the
 * PE reader, with the sixteen summary words compared against the C.
 *
 * WHY THIS FILE EXISTS, and it is a structural fact, not a coverage complaint.
 * Two properties of B2.1 were proved by two harnesses that never met:
 *   tests_ntasm_machine_x64.c drives machine_x64.build_object and gets an
 *     object, and that gate is green;
 *   tests_ntasm_pe_inspect.c drives ntasm_pe_inspect.inspect and extracts
 *     SIXTEEN summary words out of a PE image, comparing them against a C
 *     reader, and that gate is green too.
 * No single harness named both halves, so the PATH BETWEEN THEM was verified at
 * its two ends and nowhere along it. This file names both halves in one place.
 *
 * WHAT THE JOIN MEASURED, and this is the finding, not a summary of a green:
 * `build_object` does not produce a PE. It produces an NXO relocatable
 * container -- the tag `NXOV0001` is at its offset 0, which this gate PRINTS
 * on every object row, and nxo.nova carries the sentence that says so ("The C
 * oracle writes the tag \"NXOV0001\" at offset 0") next to its own
 * FORMAT_VERSION. The reader's first structural check is the MZ magic, so the
 * object is refused with ERR_NOT_DOS. That refusal is CORRECT, and the file
 * says so rather than dressing it as a pass: an NXO object is not a PE image
 * and a reader that accepted one would be the defect. The NC-TAG control
 * below rewrites those two bytes to `MZ` and shows the verdict move, so the
 * refusal is attributable to the tag and not to the reader refusing anything.
 *
 * So the sixteen words are NOT extracted from the object, and this gate does
 * not pretend otherwise. The join is refused BEFORE the comparison, and the
 * refusal is a named, documented code rather than a divergence. THE COMPARISON
 * IS NOT REACHABLE THROUGH THIS PRODUCER, and that is what the banner states.
 *
 * WHY THE COMPARISON IS STILL EXERCISED, because a gate that compares nothing
 * is a gate that cannot fail and its `failures=0` is an absence. The sixteen
 * words are compared on the nearest reachable pair -- a PE the frozen C writer
 * oracle built, read by ntasm_pe_inspect.inspect and by an independent C reader
 * over the SAME bytes -- so the comparison machinery is live, and the four
 * NEGATIVE CONTROLS below then perturb values already known to make it fail.
 * Without them this file would print a green over sixteen words it never read.
 *
 * THE THREE REFUSALS THE JOIN MEETS, and each is asserted with its code, in
 * BOTH directions (an unlisted verdict is red, so the table cannot rot):
 *   ERR_NOT_DOS 822              the PE reader on the NXO object. Correct.
 *   800 "object library has no executable entry"
 *                                 the C materializer, and it is refused
 *                                 because machine_x64.build_object writes
 *                                 `entry: 0`. machine_x64.nova's own comment
 *                                 says that 0 is a FACT and not a default, and
 *                                 says the NXO-to-PE conversion refuses an
 *                                 entryless object. So this is the producer's
 *                                 documented consequence and not a defect
 *                                 found in it. It is MEASURED here because this
 *                                 header claims it.
 *   400 "return value required"   the C front end, on the SAME source. Within
 *                                 this corpus the intersection is empty: the
 *                                 three bodies build_object accepts are the
 *                                 three the C front end refuses, and the two
 *                                 the C accepts as objects build_object
 *                                 refuses. So "the C oracle's words for the
 *                                 same source" does not exist for any row here.
 *                                 THAT IS A STATEMENT ABOUT THESE EIGHT ROWS
 *                                 and not about every source either half could
 *                                 accept; the banner prints the population and
 *                                 names the larger question as NOT MEASURED.
 *
 * THE ROLES ARE LABELLED, because a label is not self-validating. The C
 * oracle's sixteen words come from nova_oracle_make_pe, the frozen C writer --
 * another implementation, not pe.nova's own expectation of itself. The
 * sixteen-word comparisons below are a ROUTE CHECK over two C-oracle images
 * (the reader against an independent C reader on the same bytes), and they are
 * named as such: one image read two ways is not a witness about the object,
 * which is why the object rows are reported as refusals and not as
 * comparisons. THE COMPARISONS THAT RUN ARE OVER C-ORACLE IMAGES BUILT BY THE
 * FROZEN C WRITER FROM SYNTHETIC PATTERNS -- they are not any producer's
 * output, and the banner says so in those words rather than letting
 * `sixteen_agree` be read as the compiler agreeing with the C.
 * ===========================================================================
 * W214 -- THE CONVERSION LEG. ADDED ON TOP OF W210's FILE, AND THE BLOCKS
 * NAMED CONVERT / ADAPTER / NC-ENTRY-OBJECT BELOW ARE MINE. Everything above
 * this block, and every other block, is W210's and is unchanged by me.
 *
 * WHAT W210 MEASURED AND STOPPED AT: the object goes into the PE reader and
 * the reader refuses it with ERR_NOT_DOS, and the file says so. It also
 * measured the C's own route from the same bytes -- nt_object_read then
 * nt_object_materialize -- and reported that materialize refuses. Between
 * those two facts sat an UNMEASURED STEP: nt_object_read's NtObject is not
 * an NXO byte string, and nt_object_materialize is a C function. Nothing in
 * W210's file ever put the producer's bytes through a NXO->PE ADAPTER, so the
 * question "is there an adapter, does it run, and what does IT answer" had no
 * site in this file at all.
 *
 * THE ADAPTER IS THE TREE'S OWN AND IS NOT REIMPLEMENTED HERE. The host
 * callable wrapper is tests/nova/tests/nxo-pe-entry.nova over
 * compiler/nova/formats/nxo/nxo_pe.nova's single export `convert`, and the four
 * modules are the same four tests_ntasm_nxo_pe.c loads. So the code this file
 * reports is the code the six named callers get, and a divergence between
 * this gate and the nxo_pe gate would be a divergence between two callers of
 * ONE function rather than two spellings of it.
 *
 * THE PAIR, AND IT IS THE FINDING: ntasm_nxo_pe.convert answers 803 and
 * nt_object_materialize answers 800 on the SAME producer bytes, and both
 * messages name the same fact -- no executable entry. Two languages, one
 * object, one agreement, and neither side can observe the other: the C reads
 * its own NtObject, the Nova reads its own. That is a witness about the
 * OBJECT. It is not a witness about any PE, because no PE was produced.
 *
 * WHY THE SIXTEEN WORDS ARE NOT OVER THE PRODUCER'S OBJECT, restated at the
 * point of use and not only here: convert refuses, so there are no bytes, so
 * there is nothing to summarise. W210's route check over two C writer oracle
 * images stays what it was. What is ADDED is a third image for it -- a PE
 * whose bytes came out of ntasm_nxo_pe.convert rather than out of
 * nova_oracle_make_pe -- so the sixteen words are compared over ADAPTER
 * OUTPUT as well as over oracle output, and the adapter's PE is compared BYTE
 * FOR BYTE against the C's own PE for the same NXO. Each of those two is
 * named in the banner with its role; neither is allowed to read as "the
 * compiler agreed with the C about the producer's object", because no PE of
 * the producer's object exists.
 * =========================================================================== */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/pe/pe_oracle.h"
#include "../../../compiler/c/ntasm/frontend/ntasm.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "../../../compiler/c/ntasm/formats/pe.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The codes this gate needs, mirrored from pe_inspect.nova's own published
 * list -- "820 ERR_SHORT_OUTPUT fewer than summary_words() output words",
 * "822 ERR_NOT_DOS missing MZ magic", "841 ERR_BAD_ENTRY entry RVA is outside
 * .text". Only the codes a site below can be reached by are carried; the
 * authority is the module, not this list. */
enum {
  ERR_NOT_DOS = 822,
  ERR_BAD_ENTRY = 841
};
/* W214: the ONE nxo_pe.nova refusal this gate asserts, carried with its
 * source line rather than only its number. nxo_pe.nova's convert opens with
 * three refusals in this order -- "if ntasm_nxo.validate(object)!=0 return
 * failed(801)", "if object.target!=1 ... failed(802)", "if object.entry==0 ...
 * failed(803)" -- so a reader who sees 803 knows the object's own validator
 * PASSED and its target was 1 before the entry was ever asked about. That
 * ordering is the reason one code names the blocker and three would not. */
enum { CONVERT_NO_ENTRY = 803 };
#define WORDS 16
#define GUARDS 20
#define GUARD UINT64_C(0xcccccccccccccccc)
#define FAULT_BIT (UINT64_C(1) << 63)

/* The object producer's own buffer ceilings, taken from
 * tests_ntasm_machine_x64.c so the two harnesses agree on what a stage may
 * write into. */
#define MX_WORDS 262144
#define MX_TEXT 1048576
#define MX_REPORT 256

static unsigned checks, failures, cases;

/* Counters behind the JOIN banner. Every one of them is a count of something
 * the run OBSERVED, so a reader can tell an exercised gate from an idle one
 * without reading a line of the source. */
static unsigned j_rows, j_objects, j_refused_dos, j_refused_other;
static unsigned j_c_refusals, j_c_objects, j_c_no_pe;
static unsigned j_sixteen_joins, j_sixteen_agree;
/* The object-row reachability counters. They are separate from
 * j_sixteen_joins on purpose: the sixteen-word comparisons that DID run are
 * route checks over C-oracle images, and conflating the two populations would
 * let a reader believe sixteen words were compared against the object. */
static unsigned object_row_sixteen_joins, object_row_sixteen_agree,
    object_row_sixteen_disagree;
static unsigned nc_run, nc_magic, nc_entry, nc_two_image, nc_two_differ;
static unsigned nc_tag, nc_tag_moved;
static unsigned j_c_read_objects, j_c_mat_refusals;
static unsigned noc_cases;
/* The first object the producer built, kept so the on-object negative control
 * can perturb the JOIN'S OWN INPUT rather than a stand-in image. */
static uint8_t *first_object;
static size_t first_object_size;
/* ---- W214's counters. Every one counts something this run OBSERVED on the
 * producer's OWN object, or on an image the adapter produced. `cv_refused` and
 * `cv_accepted` partition `cv_calls`, so a run that refused nothing cannot
 * print 0 for accepted and be read as "nothing refused". */
static unsigned cv_calls, cv_refused, cv_accepted;
static uint64_t cv_code;
/* The C's own answer on the SAME bytes, carried out of join_row so the pair
 * can be printed on one line. Two languages, one object. */
static uint64_t cv_c_materialize_code;
static unsigned cv_imports, cv_symbols, cv_entry_capable;
/* The ADAPTER's PE compared against the C's PE for the same NXO, and its
 * sixteen words compared against the independent C reader. */
static unsigned ad_converted, ad_reader_accepted, ad_bytes_equal, ad_bytes_differ;
static unsigned ad_sixteen_agree, ad_sixteen_disagree;
/* The on-object entry control: the refusal must turn on the ENTRY WORD. */
static unsigned nc_entry_object_run, nc_entry_object_moved, nc_entry_object_field;
/* Output capacity for the adapter. 16MiB per section is the adapter's own
 * ceiling, so this is generous for every image this file builds and small
 * enough that the 0xcc guard sweep below is cheap. */
#define CV_CAPACITY 262144

#define CHECK(c, m)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL %s\n", (m));                                       \
    }                                                                          \
  } while (0)

/* ---- byte readers, copied from tests_ntasm_pe_inspect.c ---- */
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
static void wr32(uint8_t *p, uint32_t v) {
  for (unsigned i = 0; i < 4; i++)
    p[i] = (uint8_t)(v >> (8 * i));
}

/* The INDEPENDENT C reader, copied verbatim from tests_ntasm_pe_inspect.c.
 * Not reimplemented and not re-derived: it is the harness's own sixteen-word
 * extractor and its whole value is that it was written without reading
 * pe_inspect.nova. */
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

/* The sixteen word names, from pe_inspect.nova's own published order:
 *   0 machine 1 subsystem 2 image base 3 entry RVA 4 SizeOfImage
 *   5 SizeOfHeaders 6..9 the four section virtuals 10..13 the four raw
 *   14 base relocation directory RVA 15 its size. */
static const char *const WORD_NAME[WORDS] = {
    "machine",  "subsystem",       "image_base", "entry_rva",
    "size_of_image", "size_of_headers", "text_virtual", "rdata_virtual",
    "data_virtual",  "reloc_virtual",  "text_raw",     "rdata_raw",
    "data_raw",      "reloc_raw",     "reldir_rva",   "reldir_size"};

static void print_words(const char *tag, const char *label, const uint64_t *w) {
  fprintf(stdout, "SUMMARY %s [%s]", tag, label);
  for (unsigned i = 0; i < WORDS; i++)
    fprintf(stdout, " %s=%" PRIu64, WORD_NAME[i], w[i]);
  fprintf(stdout, "\n");
}

/* ---- module loading, copied from tests_ntasm_pe_inspect.c ---- */
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

static int build_program(const char **paths, unsigned count,
                         NovaHostImage *image, char **owned) {
  NtFInput inputs[16];
  size_t sizes[16];
  int all = count <= 16;
  for (unsigned i = 0; i < count; i++) {
    owned[i] = load(paths[i], sizes + i);
    if (!owned[i])
      all = 0;
    inputs[i] = (NtFInput){paths[i], owned[i], sizes[i]};
  }
  NtArtifact artifact = {0};
  int compiled = all && nova_compile_many_v2(inputs, count, &artifact);
  CHECK(compiled, "the Nova modules compile");
  if (!compiled)
    fprintf(stderr, "E%u %zu:%zu %s\n", artifact.error.code, artifact.error.line,
            artifact.error.column, artifact.error.message);
  if (compiled)
    CHECK(nova_host_map(&artifact, image), "map generated machine code");
  if (compiled)
    nt_artifact_free(&artifact);
  return compiled;
}

/* The PE reader, one call. Copied from tests_ntasm_pe_inspect.c: the image is
 * BORROWED READ-ONLY and the output buffer is writable, and the returned word
 * is 0 on acceptance and FAULT_BIT+code on refusal. */
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

/* ---- W214: THE ADAPTER, one call. --------------------------------------
 * nxo-pe-entry.nova's main is `fn main(input:buf<u8>,out:buf<u8>,mode:u64)`
 * and it returns the PE size on success and 2^63+code on refusal, writing
 * NOTHING to `out` on a refusal. That contract is the wrapper's own published
 * one, so the guard sweep below is a check on the claim rather than an
 * assumption about it. Calling convention copied from tests_ntasm_nxo_pe.c,
 * which is the harness that already drives this same entry. */
static uint64_t convert_run(const NovaHostImage *adapter, const uint8_t *nxo,
                            size_t size, uint8_t *out, size_t capacity,
                            uint64_t mode) {
  NovaContextV2 c = {0};
  uint64_t returned = UINT64_MAX;
  if (!nova_context_init_v2(&c))
    return UINT64_MAX;
  uint64_t args[] = {nova_borrow_v2(&c, (void *)nxo, size, 0),
                     size,
                     nova_borrow_v2(&c, out, capacity, 1),
                     capacity,
                     mode};
  returned = adapter->entry(&c, args, 5);
  if (c.error || !nova_context_destroy_v2(&c))
    returned = UINT64_MAX;
  return returned;
}

/* 0xcc is GUARD's low byte, so a 0xcc sweep is the same guard value the rest
 * of this file uses, read on a byte buffer instead of a u64 one. */
static int sweep_intact(const uint8_t *p, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (p[i] != 0xcc)
      return 0;
  return 1;
}

/* ---- the object producer, one call ---- */
typedef struct {
  uint64_t *words, *image;
  uint64_t *report;
  uint8_t *text;
  uint64_t code, length;
} Producer;

static void producer_init(Producer *p) {
  p->words = (uint64_t *)malloc(MX_WORDS * sizeof(uint64_t));
  p->image = (uint64_t *)malloc(MX_WORDS * sizeof(uint64_t));
  p->report = (uint64_t *)malloc(MX_REPORT * sizeof(uint64_t));
  p->text = (uint8_t *)malloc(MX_TEXT);
  p->code = UINT64_MAX;
  p->length = 0;
}
/* Every buffer malloc'd here is freed here, once. ASan runs with
 * detect_leaks=1, and a missing nt_artifact_free/free is a non-zero exit on a
 * gate whose counters are all green -- which is the failure this project has
 * already paid for once. */
static void producer_free(Producer *p) {
  free(p->words);
  free(p->image);
  free(p->report);
  free(p->text);
}

/* THE THREE STAGES, by the entry's own mode number, with the precondition each
 * one names: mode 2 fills the NTIR buffer, mode 4 fills the Machine IR buffer,
 * and mode 8 reads the Machine IR buffer. Copied from
 * tests_ntasm_machine_x64.c's stage table, including the reason a stage run
 * without its precondition answers 946 and that 946 is the entry refusing a
 * damaged image rather than a verdict on the body. */
static const uint64_t STAGE_MODE[3] = {2, 4, 8};

static uint64_t producer_run(Producer *p, const NovaHostImage *image,
                             const char *source, size_t size) {
  uint64_t last = UINT64_MAX;
  for (unsigned s = 0; s < 3; s++) {
    uint64_t length[4];
    NovaContextV2 c = {0};
    for (unsigned i = 0; i < MX_REPORT; i++)
      p->report[i] = GUARD;
    for (unsigned i = 0; i < 4; i++)
      length[i] = GUARD;
    memset(p->text, 0xcc, MX_TEXT);
    CHECK(nova_context_init_v2(&c), "context init");
    uint64_t args[] = {
        nova_borrow_v2(&c, (void *)source, size, 0),
        size,
        STAGE_MODE[s],
        0,
        nova_borrow_v2(&c, p->words, MX_WORDS * sizeof(uint64_t), 1),
        MX_WORDS,
        MX_WORDS,
        nova_borrow_v2(&c, p->image, MX_WORDS * sizeof(uint64_t), 1),
        MX_WORDS,
        MX_WORDS,
        nova_borrow_v2(&c, p->text, MX_TEXT, 1),
        MX_TEXT,
        nova_borrow_v2(&c, length, 4 * sizeof(uint64_t), 1),
        4,
        nova_borrow_v2(&c, p->report, MX_REPORT * sizeof(uint64_t), 1),
        MX_REPORT};
    last = image->entry(&c, args, 16);
    if (s == 2)
      p->length = length[0];
    CHECK(nova_context_destroy_v2(&c), "context cleanup");
    if (s < 2 && last != 0)
      break;
  }
  p->code = last;
  return last;
}

/* ---- the C side ---- */
/* The reference materializer allocates five buffers and frees none of them.
 * tests_ntasm_corpus_e2e.c and nova_corpus_convergence.c each carry this same
 * copy, so this is a third copy of ONE convention and not a second way of
 * doing it. */
static void free_artifact(NtArtifact *a) {
  if (a->pe.bytes) { free(a->pe.bytes); a->pe.bytes = NULL; }
  if (a->text.bytes) { free(a->text.bytes); a->text.bytes = NULL; }
  if (a->rdata.bytes) { free(a->rdata.bytes); a->rdata.bytes = NULL; }
  if (a->data.bytes) { free(a->data.bytes); a->data.bytes = NULL; }
  free(a->base_relocations);
  memset(a, 0, sizeof *a);
}

/* THE CORPUS, copied byte for byte from tests_ntasm_machine_x64.c. These are
 * the object producer's OWN inputs and not descriptions of them, and using the
 * producer's corpus rather than a convenient one is what makes "the same
 * source" mean the same thing on both sides. */
#define PROLOGUE "module m\ntarget x86_64-nexora-none\nsection .text {\n" \
                 "fn main()->u64\neffects {}\nclobbers "
#define EPILOGUE "}\n}\n"
typedef struct {
  const char *name;
  const char *body;
} Body;
static const Body BODIES[] = {
    {"nop;return", PROLOGUE "{} {\nnop\nreturn\n" EPILOGUE},
    {"return", PROLOGUE "{} {\nreturn\n" EPILOGUE},
    {"nop;nop;return", PROLOGUE "{} {\nnop\nnop\nreturn\n" EPILOGUE},
    {"return 0", PROLOGUE "{rax} {\nnop\nreturn 0\n" EPILOGUE},
    {"add rax,1", PROLOGUE "{rax} {\nnop\nadd rax, 1\nreturn rax\n" EPILOGUE},
    {"add rax,rcx", PROLOGUE "{rax} {\nnop\nadd rax, rcx\nreturn rax\n" EPILOGUE},
    {"mov rax,1", PROLOGUE "{rax} {\nnop\nmov rax, 1\nreturn rax\n" EPILOGUE},
    {"sub rax,1", PROLOGUE "{rax} {\nnop\nsub rax, 1\nreturn rax\n" EPILOGUE},
};
#define BODIES_N ((unsigned)(sizeof BODIES / sizeof BODIES[0]))

/* THE MEASURED VERDICTS, one row per corpus member, and the table is the
 * EXPECTATION rather than a description: an unlisted verdict on a listed row
 * is red, and so is a listed verdict that moved. Every entry was measured on
 * this tree by driving these two harnesses' own entries; none is derived from
 * the source by reading it.
 *
 *   build_object   the machine_x64 entry's own verdict on this body.
 *   object_bytes   the NXO container it wrote, 0 when it refused.
 *   reader_code    what ntasm_pe_inspect answered on that container, 0 when
 *                   build_object refused and there was nothing to read.
 *   c_code         nt_object_compile's verdict on the SAME source.
 *   c_pe           1 when nt_make_pe produced a PE the C reader could summarise.
 *
 * The three shapes the producer ACCEPTS are the three the C front end REFUSES
 * with 400 "return value required", and the two the C accepts are the two the
 * producer refuses: the intersection is empty. That is the fact this gate
 * exists to publish, and it is why `c_pe` is 0 on every row. */
typedef struct {
  const char *name;
  uint64_t build_object;
  uint64_t object_bytes;
  uint64_t reader_code;
  uint64_t c_code;
  uint64_t c_pe;
  const char *why;
} Row;
/* MIR/1.0 register operations carry runtime-cell metadata. The constrained
 * legacy writer rejects it as E_FORM before opcode/register selection; these
 * are still negative cases. The production machine_emit path is tested by
 * machine_corpus and machine_producer_exec. The three positive legacy object
 * paths below remain byte-pinned and independently read/materialized. */
static const Row ROWS[] = {
    {"nop;return", 0, 256, ERR_NOT_DOS, 400, 0,
     "the producer takes it; the C front end refuses the same source"},
    {"return", 0, 256, ERR_NOT_DOS, 400, 0,
     "the producer takes it; the C front end refuses the same source"},
    {"nop;nop;return", 0, 256, ERR_NOT_DOS, 400, 0,
     "the producer takes it; the C front end refuses the same source"},
    {"return 0", 963, 0, 0, 0, 0,
     "the producer refuses E_REGISTER; the C builds an object it cannot "
     "materialise because the target is nexora-none"},
    {"add rax,1", 962, 0, 0, 501, 0,
     "legacy rejects runtime cells as E_FORM; C refuses missing effects as 501"},
    {"add rax,rcx", 962, 0, 0, 501, 0,
     "legacy rejects runtime cells as E_FORM; C refuses missing effects as 501"},
    {"mov rax,1", 962, 0, 0, 0, 0,
     "legacy refuses runtime cells as E_FORM; the C builds an object it cannot "
     "materialise because the target is nexora-none"},
    {"sub rax,1", 962, 0, 0, 501, 0,
     "legacy rejects runtime cells as E_FORM; C refuses missing effects as 501"},
};
#define ROWS_N ((unsigned)(sizeof ROWS / sizeof ROWS[0]))

/* One corpus row: the producer's object, into the reader, with the C front
 * end asked the same question on the same source. */
static void join_row(const NovaHostImage *producer, const NovaHostImage *reader,
                     const NovaHostImage *adapter, const Row *row,
                     const char *source) {
  j_rows++;
  Producer p;
  producer_init(&p);
  uint64_t code = producer_run(&p, producer, source, strlen(source));

  uint64_t object_bytes = (code == 0) ? p.length : 0;
  CHECK(code == row->build_object, "the producer's verdict is the measured one");
  CHECK(object_bytes == row->object_bytes,
        "the producer's object byte count is the measured one");

  uint64_t got[WORDS + GUARDS];
  uint64_t reader_code = 0;
  int guards_intact = 1;
  if (code == 0 && object_bytes > 0) {
    j_objects++;
    for (unsigned i = 0; i < WORDS + GUARDS; i++)
      got[i] = GUARD;
    cases++;
    uint64_t returned =
        inspect(reader, p.text, (size_t)object_bytes, got, WORDS);
    reader_code = (returned & FAULT_BIT) ? (returned & ~FAULT_BIT) : 0;
    if (returned != 0 && returned != FAULT_BIT + row->reader_code)
      fprintf(stderr,
              "FAIL reader refused %s with %" PRIu64 ", measured %" PRIu64 "\n",
              row->name, reader_code, (uint64_t)row->reader_code);
    CHECK(returned == FAULT_BIT + row->reader_code,
          "the reader refuses the object with the measured code");
    for (unsigned i = WORDS; i < WORDS + GUARDS; i++)
      if (got[i] != GUARD)
        guards_intact = 0;
    CHECK(guards_intact, "a refusal leaves every output guard intact");
    if (reader_code == ERR_NOT_DOS)
      j_refused_dos++;
    else
      j_refused_other++;
    fprintf(stdout, "JOIN %-14s object=%" PRIu64 "B tag=%.8s reader_code=%" PRIu64
                    " guards_intact=%d why=%s\n",
            row->name, object_bytes, (const char *)p.text, reader_code,
            guards_intact, row->why);
    /* The FIRST object the producer built is kept for the on-object negative
     * control below, which perturbs the join's OWN input rather than a
     * stand-in. A control run on some other image proves the reader can fail;
     * only a control run on THIS image proves the JOIN can fail. */
    if (!first_object) {
      first_object = (uint8_t *)malloc((size_t)object_bytes);
      if (first_object) {
        memcpy(first_object, p.text, (size_t)object_bytes);
        first_object_size = (size_t)object_bytes;
      }
    }
  } else {
    fprintf(stdout, "JOIN %-14s object=none build_object_code=%" PRIu64
                    " why=%s\n",
            row->name, code, row->why);
  }

  /* THE C REFERENCE'S OWN ROUTE FROM THE PRODUCER'S OBJECT TO A PE. This is
   * the step the join skips over and it is the second structural blocker:
   * nt_object_read is handed the producer's own bytes, and if it accepts them
   * then the object IS a legal member of the format, and then
   * nt_object_materialize is asked to turn it into an executable image. It
   * refuses, because build_object sets `entry: 0`. machine_x64.nova says that
   * zero is a FACT rather than a default and names the refusal that follows
   * from it, so the refusal here is the module's own documented consequence
   * and not a defect found in it. It is MEASURED here rather than asserted,
   * because the header above claims it. */
  uint64_t c_read_ok = 0, c_mat_ok = 0, c_mat_code = 0;
  if (code == 0 && object_bytes > 0) {
    NtObject back = {0};
    NtDiagnostic berr = {0};
    c_read_ok = (uint64_t)nt_object_read(p.text, (size_t)object_bytes, &back, &berr);
    if (!c_read_ok)
      fprintf(stdout, "JOIN_C_OBJECT %-14s read refused code=%u %s\n", row->name,
              berr.code, berr.message);
    else {
      /* W214: WHAT THE OBJECT ACTUALLY NAMES, and this is the measurement the
       * 803 rests on. `entry=0` alone reads as "point it at symbol 1 and the
       * conversion proceeds". What says otherwise is a count of symbols that
       * COULD be pointed at: object.c requires an entry to be a DEFINED
       * function in section 1, so `entry_capable` is the population the fix
       * would have to draw from.
       *
       * AND THE COUNT THAT MATTERS IS NOT THE ONE I FIRST WROTE. An earlier
       * version of this block printed "every symbol is an import" and asserted
       * it -- and the measurement says symbols=0, so the assertion was 0==0
       * and would have stayed green on an object that named a defined
       * function. A check that cannot go red is not a check. The assertion
       * below is on the ENTRY-CAPABLE count, which is 0 here for the real
       * reason and would go red the day a producer emitted one.
       *
       * The counts come from the C readback, so they are the object's own and
       * not a re-derivation of them. */
      {
        size_t imports = 0, defined = 0, entry_capable = 0;
        for (size_t j = 0; j < back.symbol_count; j++) {
          const NtObjectSymbol *s = back.symbols + j;
          if (s->flags & NT_OBJECT_IMPORT)
            imports++;
          else {
            defined++;
            if (s->section == NT_OBJECT_TEXT && (s->flags & NT_OBJECT_FUNCTION))
              entry_capable++;
          }
        }
        if (cv_calls == 0) {
          cv_symbols = (unsigned)back.symbol_count;
          cv_imports = (unsigned)imports;
          cv_entry_capable = (unsigned)entry_capable;
        }
        fprintf(stdout,
                "JOIN_C_OBJECT_SYMBOLS %-14s symbols=%zu imports=%zu "
                "defined=%zu entry_capable=%zu entry_symbol=%u\n",
                row->name, back.symbol_count, imports, defined, entry_capable,
                back.entry_symbol);
        CHECK(entry_capable == 0,
              "the object names no defined function in section 1, so there is "
              "no index in it that could serve as an executable entry -- the "
              "entry is absent because there is nothing to point at, not "
              "because a field was left unset");
      }
      j_c_read_objects++;
      NtArtifact art = {0};
      NtDiagnostic merr = {0};
      memset(&art, 0, sizeof art);
      c_mat_ok = (uint64_t)nt_object_materialize(&back, &art, &merr);
      fprintf(stdout,
              "JOIN_C_OBJECT %-14s read=ok target=%u entry_symbol=%u "
              "symbols=%zu relocs=%zu text=%zu materialize=%s",
              row->name, back.target, back.entry_symbol, back.symbol_count,
              back.relocation_count, back.sections[0].size,
              c_mat_ok ? "ok" : "REFUSED");
      if (!c_mat_ok) {
        j_c_mat_refusals++;
        if (cv_calls == 0)
          cv_c_materialize_code = (uint64_t)merr.code;
        c_mat_code = merr.code;
        fprintf(stdout, " code=%u %s\n", merr.code, merr.message);
      } else if (nt_make_pe(&art) && art.pe.size > 0) {
        fprintf(stdout, " pe=%zu\n", art.pe.size);
      } else {
        fprintf(stdout, " make_pe refused code=%u %s\n", merr.code, merr.message);
      }
      free_artifact(&art);
    }
    nt_object_free(&back);
  }

  /* ================= W214: CONVERT. THE PRODUCER'S OWN BYTES INTO THE
   * TREE'S OWN NXO->PE ADAPTER. =========================================
   *
   * This is the step W210's file had no site for. Its C route ends at
   * nt_object_materialize, which is a C function over a C struct; the missing
   * middle was the NXO->PE adapter in Nova, and nxo_pe.nova has exported
   * `convert` all along with six named callers.
   *
   * WHAT IS ASSERTED, AND WHY IT IS A CONSTANT HERE RATHER THAN A PRINT: the
   * code is one of the adapter's own published refusals, and the banner names
   * which. A control below shows the code MOVES when the entry word moves, so
   * this constant is a discrimination and not a blanket refusal wearing a
   * number. If the adapter ever starts accepting the producer's object, this
   * check goes red -- which is the correct behaviour, and the banner below
   * says what the reader would then have to be given.
   *
   * THE PAIR ON ONE LINE: `c_materialize_code` is the C's answer on the SAME
   * bytes, printed beside the adapter's. 800 and 803 are different numbers in
   * two languages for one fact, and neither implementation can observe the
   * other. `imports` and `symbols` are printed because they decide what a
   * NON-ZERO entry could even point at, and a reader who sees entry=0 alone
   * would conclude "set entry=1 and it converts", which the symbol counts
   * here refute. */
  /* offset 88 must be INSIDE the object before it is read. The bound is
   * checked at the place the read happens and not assumed from the format,
   * because a producer that emitted a short container would otherwise have
   * this gate read four bytes of whatever follows it in the buffer. */
  if (code == 0 && object_bytes >= 92) {
    uint8_t *out = (uint8_t *)malloc(CV_CAPACITY);
    CHECK(out != NULL, "the conversion output buffer allocates");
    if (out) {
      memset(out, 0xcc, CV_CAPACITY);
      cases++;
      uint64_t returned = convert_run(adapter, p.text, (size_t)object_bytes,
                                      out, CV_CAPACITY, 0);
      cv_calls++;
      int intact = sweep_intact(out, CV_CAPACITY);
      uint64_t refused = (returned & FAULT_BIT) ? (returned & ~FAULT_BIT) : 0;
      if (refused)
        cv_refused++;
      else
        cv_accepted++;
      if (cv_refused == 1)
        cv_code = refused;
      /* THE ENTRY WORD, READ FROM THE OBJECT'S OWN BYTES AND NOT FROM A
       * STRUCT. offset 88 is where object.c's writer puts entry_symbol and
       * where its reader gets it, so this is the place the value is read in
       * production. Reading it from the C struct instead would be reading a
       * copy of the same fact through a second derivation. */
      uint32_t entry_word = rd32(p.text + 88);
      if (cv_calls == 1)
        nc_entry_object_field = entry_word;
      fprintf(stdout,
              "CONVERT %-14s object=%" PRIu64 "B adapter_code=%" PRIu64
              " c_materialize_code=%" PRIu64 " entry_word=%u symbols=%u "
              "imports=%u out_intact=%d\n",
              row->name, object_bytes, refused, c_mat_code, entry_word,
              cv_symbols, cv_imports, intact);
      CHECK(refused == CONVERT_NO_ENTRY,
            "the tree's NXO->PE adapter refuses the producer's object with the "
            "no-executable-entry code");
      CHECK(refused != 0,
            "the adapter refuses rather than emitting an empty PE the reader "
            "would then have to be fed");
      CHECK(intact, "the adapter's refusal writes nothing into the output "
                    "buffer, so the transaction claim is not taken on faith");
      free(out);
    }
  }

  /* THE C FRONT END, on the same source. Its verdict is reported whether or
   * not this harness uses it, because a C refusal on a source the producer
   * accepted is a finding and dropping it would hide it. */
  NtFInput in = {"m.ntasm", (char *)source, strlen(source)};
  NtObject obj = {0};
  NtDiagnostic err = {0};
  int c_ok = nt_object_compile(&in, 1, &obj, &err);
  uint64_t c_code = c_ok ? 0 : err.code;
  if (c_ok)
    j_c_objects++;
  else
    j_c_refusals++;
  CHECK(c_code == row->c_code, "the C front end's verdict is the measured one");
  if (!c_ok)
    fprintf(stdout, "JOIN_C %-14s refused code=%u %s\n", row->name, err.code,
            err.message);

  uint64_t made_pe = 0;
  if (c_ok) {
    NtArtifact art = {0};
    NtDiagnostic merr = {0};
    memset(&art, 0, sizeof art);
    if (nt_object_materialize(&obj, &art, &merr) &&
        nt_make_pe(&art) && art.pe.size > 0) {
      uint64_t w[WORDS];
      reference_summary(art.pe.bytes, w);
      print_words("C_ORACLE", row->name, w);
      made_pe = 1;
    } else {
      j_c_no_pe++;
      fprintf(stdout, "JOIN_C %-14s object=yes pe=no code=%u %s\n", row->name,
              merr.code, merr.message);
    }
    free_artifact(&art);
  }
  CHECK(made_pe == row->c_pe, "whether the C produced a PE is the measured one");
  /* THE SIXTEEN-WORD JOIN over an OBJECT row, and its REACHABILITY is the
   * result rather than an absence. Reaching it needs four things at once -- an
   * object from the producer, a reader that ACCEPTS that object, and a PE the C
   * built from the SAME source -- and the first pair cannot both hold, because
   * build_object emits an NXO container and the reader's first check is the
   * MZ magic. The counter is incremented HERE, at the one site that could do
   * the comparison, so the banner's zero is a measurement and not a number
   * written to match a belief. A join that cannot be reached must say so
   * rather than print a green over a comparison it never performed. */
  if (made_pe && code == 0 && object_bytes > 0 && reader_code == 0) {
    object_row_sixteen_joins++;
    uint64_t want[WORDS];
    reference_summary(p.text, want);
    int same = 1;
    for (unsigned i = 0; i < WORDS; i++)
      if (got[i] != want[i])
        same = 0;
    if (same)
      object_row_sixteen_agree++;
    else
      object_row_sixteen_disagree++;
  }
  nt_object_free(&obj);
  producer_free(&p);
}

/* ---- the C writer oracle, and the two images the sixteen words come from ----
 * These are the fixture inputs tests_ntasm_pe_inspect.c already builds its
 * oracle images from, reused through nova_oracle_make_pe -- the frozen C
 * writer. Comparing the reader against this and not against pe.nova is the
 * whole point: pe.nova's own expectations would prove pe.nova agrees with
 * itself. */
typedef struct {
  const char *label;
  size_t text, rdata, data, entry;
  NovaOracleBaseReloc relocs[8];
  size_t count;
} Fixture;
static const Fixture FIXTURES[] = {
    {"small-text", 1024, 17, 23, 113, {{0}}, 0},
    {"large-text", 2048, 17, 23, 113, {{0}}, 0},
};
#define FIXTURES_N ((unsigned)(sizeof FIXTURES / sizeof FIXTURES[0]))

static uint8_t *pattern(size_t size, unsigned seed) {
  uint8_t *p = calloc(size ? size : 1, 1);
  if (!p)
    exit(2);
  for (size_t i = 0; i < size; i++)
    p[i] = (uint8_t)(i * seed + 3);
  return p;
}

static uint8_t *build_oracle(const Fixture *f, size_t *size) {
  uint8_t *t = pattern(f->text, 17), *r = pattern(f->rdata, 7),
          *d = pattern(f->data, 11);
  *size = 0;
  NovaOraclePeImage image = {0};
  image.text = (NtBuffer){t, f->text, f->text};
  image.rdata = (NtBuffer){r, f->rdata, f->rdata};
  image.data = (NtBuffer){d, f->data, f->data};
  image.entry = f->entry;
  image.base_relocations = (NovaOracleBaseReloc *)f->relocs;
  image.base_relocation_count = f->count;
  int made = nova_oracle_make_pe(&image);
  uint8_t *out = NULL;
  if (made && image.pe.bytes) {
    out = image.pe.bytes;
    *size = image.pe.size;
  } else {
    free(image.pe.bytes);
  }
  free(t);
  free(r);
  free(d);
  return out;
}

/* THE REACHABLE SIXTEEN-WORD COMPARISON. The reader over the C writer oracle's
 * image, against the independent C reader over the SAME bytes. This is a ROUTE
 * CHECK and not a witness -- one image, two readers -- and it is what makes
 * every verdict this gate reports about the OBJECT attributable: without it a
 * reader that refused every input would produce the same object rows.
 *
 * IT IS CALLED ONCE PER IMAGE. `j_sixteen_joins` counts IMAGES and the floors
 * pin it to FIXTURES_N, so it cannot become a count of calls: an earlier
 * version of this file was called three times over two images and printed 3,
 * which read as a population and was a call count. */
static int sixteen_join(const NovaHostImage *reader, const uint8_t *pe,
                        size_t size, const char *label, uint64_t *produced) {
  uint64_t want[WORDS], got[WORDS + GUARDS];
  reference_summary(pe, want);
  for (unsigned i = 0; i < WORDS + GUARDS; i++)
    got[i] = GUARD;
  cases++;
  uint64_t returned = inspect(reader, pe, size, got, WORDS);
  /* The reader's words are printed ONLY when the reader produced them. A
   * refusal prints the C reader's words under a refusal line instead, because
   * printing the oracle's numbers under the reader's name is the whitening
   * this project has already retracted a claim over: the values would be right
   * and the attribution inverted, which is the worst pair of ways to be
   * wrong. */
  if (returned == 0)
    print_words("READER", label, got);
  else
    fprintf(stdout, "READER %s refused code=%" PRIu64 "\n", label,
            returned & ~FAULT_BIT);
  print_words("C_READER", label, want);
  int same = returned == 0;
  for (unsigned i = 0; i < WORDS && same; i++)
    if (got[i] != want[i]) {
      fprintf(stderr,
              "FAIL sixteen words disagree %s [%s] word=%u(%s) reader=%" PRIu64
              " oracle=%" PRIu64 "\n",
              label, WORD_NAME[i], i, WORD_NAME[i], got[i], want[i]);
      same = 0;
    }
  for (unsigned i = WORDS; i < WORDS + GUARDS && same; i++)
    if (got[i] != GUARD)
      same = 0;
  CHECK(returned == 0, "the reader accepts the C writer oracle's image");
  CHECK(same, "the reader's sixteen words equal the C reader's, on the same image");
  j_sixteen_joins++;
  if (same)
    j_sixteen_agree++;
  /* The words handed back are the READER's on acceptance and the GUARD on
   * refusal. That is not a convenience: NC-TWO compares these against another
   * image's words, so if the base image were ever refused both sides would be
   * guards, `differ` would be 0, and its check would go RED. A refusal in the
   * control's base image therefore cannot pass as "the words did not move". */
  for (unsigned i = 0; i < WORDS; i++)
    produced[i] = (returned == 0) ? got[i] : GUARD;
  return same;
}

/* THE NEGATIVE CONTROLS. Four of them, and each perturbs a value this file has
 * already observed, because a join that cannot fail is not a join and a green
 * over an unexercised comparison is an absence.
 *
 *   NC-TAG     THE CONTROL THAT CONTRADICTS THIS JOIN ON ITS OWN INPUT. The
 *              first object the producer built is copied and its first two
 *              bytes -- `NX`, the NXO tag -- are rewritten to `MZ`, which is
 *              the only value this file knows that the reader's magic check
 *              accepts. The reader's verdict MUST MOVE OFF ERR_NOT_DOS. If it
 *              does not, the reader is refusing on something other than the
 *              tag, the object rows' 822 is not attributable to the tag, and
 *              this file's headline claim is wrong. The exact code it moves to
 *              is measured, printed, and NOT asserted to a constant, because
 *              the point is that it MOVED and not which refusal it became.
 *   NC-MAGIC   the DOS magic of a C oracle image this file already summarised
 *              successfully. The reader must then refuse with ERR_NOT_DOS and
 *              leave every guard intact -- the SAME code the NXO object row
 *              produced, reached from an input the reader otherwise accepts.
 *              That is what makes ERR_NOT_DOS a discrimination rather than a
 *              blanket refusal, and therefore what makes the object rows
 *              attributable to the object's tag and not to a broken reader.
 *   NC-ENTRY   the entry RVA, moved outside .text. The reader must refuse with
 *              ERR_BAD_ENTRY and write nothing.
 *   NC-TWO     two C oracle images differing ONLY in .text size. The reader must
 *              accept both and their sixteen words must DIFFER in the words
 *              that depend on .text. A reader that returned a constant, or that
 *              compared its own expectations, would pass the single-image
 *              comparison and fail this one. */
static void negative_controls(const NovaHostImage *reader, const uint8_t *pe,
                              size_t size, const uint64_t *small_words) {
  noc_cases++;

  /* NC-TAG. The join's own input, with the one field this file knows the
   * reader discriminates on. The two bytes written are `MZ`, the same value
   * NC-MAGIC destroys on the C oracle image, so the perturbation is a value
   * ALREADY OBSERVED in both directions rather than a guess. */
  if (first_object && first_object_size > 2) {
    uint8_t *copy = (uint8_t *)malloc(first_object_size);
    CHECK(copy != NULL, "the tag control allocates");
    if (copy) {
      memcpy(copy, first_object, first_object_size);
      uint64_t before[WORDS + GUARDS];
      for (unsigned i = 0; i < WORDS + GUARDS; i++)
        before[i] = GUARD;
      uint64_t base = inspect(reader, copy, first_object_size, before, WORDS);
      copy[0] = 'M';
      copy[1] = 'Z';
      uint64_t got[WORDS + GUARDS];
      for (unsigned i = 0; i < WORDS + GUARDS; i++)
        got[i] = GUARD;
      cases++;
      uint64_t after = inspect(reader, copy, first_object_size, got, WORDS);
      int intact = 1;
      for (unsigned i = 0; i < WORDS + GUARDS; i++)
        if (got[i] != GUARD)
          intact = 0;
      fprintf(stdout,
              "NC_TAG object=%zuB tag_before=%.2s code_before=%" PRIu64
            " tag_after=%.2s code_after=%" PRIu64 " guards_intact=%d\n",
            first_object_size, (const char *)first_object,
            base & ~FAULT_BIT, (const char *)copy, after & ~FAULT_BIT, intact);
      /* The control fires when the verdict MOVED OFF ERR_NOT_DOS. It is not
       * asserted to a particular successor code: this reader walks its checks
       * in a published order, so the code it lands on is a fact about
       * pe_inspect.nova and not a property of the join. What the join claims
       * is only that the tag is what the refusal turned on. */
      nc_tag++;
      if ((base & ~FAULT_BIT) != (after & ~FAULT_BIT) &&
          (base & ~FAULT_BIT) == ERR_NOT_DOS)
        nc_tag_moved++;
      CHECK((base & ~FAULT_BIT) == ERR_NOT_DOS,
            "the unperturbed object is refused as not-DOS, which is what the "
            "object rows measured");
      CHECK((base & ~FAULT_BIT) != (after & ~FAULT_BIT),
            "rewriting the object's tag to MZ moves the reader off ERR_NOT_DOS, "
            "so the object rows' refusal is attributable to the tag");
      free(copy);
    }
  }

  /* NC-MAGIC */
  {
    uint8_t *copy = (uint8_t *)malloc(size);
    CHECK(copy != NULL, "the magic control allocates");
    if (copy) {
      memcpy(copy, pe, size);
      copy[0] = 'Z';
      uint64_t got[WORDS + GUARDS];
      for (unsigned i = 0; i < WORDS + GUARDS; i++)
        got[i] = GUARD;
      cases++;
      uint64_t returned = inspect(reader, copy, size, got, WORDS);
      int intact = 1;
      for (unsigned i = 0; i < WORDS + GUARDS; i++)
        if (got[i] != GUARD)
          intact = 0;
      fprintf(stdout, "NC_MAGIC returned=%" PRIu64 " code=%" PRIu64
                      " guards_intact=%d\n",
              returned, (returned & FAULT_BIT) ? (returned & ~FAULT_BIT) : 0,
              intact);
      CHECK(returned == FAULT_BIT + ERR_NOT_DOS,
            "a corrupted MZ magic is refused with ERR_NOT_DOS");
      CHECK(intact, "the corrupted-magic refusal leaves every guard intact");
      if (returned == FAULT_BIT + ERR_NOT_DOS)
        nc_magic++;
      free(copy);
    }
    nc_run++;
  }

  /* NC-ENTRY. The optional header's AddressOfEntryPoint is at e_lfanew+24+16,
   * the same field the C reader reads for word 3. */
  {
    uint8_t *copy = (uint8_t *)malloc(size);
    CHECK(copy != NULL, "the entry control allocates");
    if (copy) {
      memcpy(copy, pe, size);
      uint32_t at = rd32(pe + 60) + 24 + 16;
      uint32_t was = rd32(copy + at);
      wr32(copy + at, 0x7f000000u);
      uint64_t got[WORDS + GUARDS];
      for (unsigned i = 0; i < WORDS + GUARDS; i++)
        got[i] = GUARD;
      cases++;
      uint64_t returned = inspect(reader, copy, size, got, WORDS);
      int intact = 1;
      for (unsigned i = 0; i < WORDS + GUARDS; i++)
        if (got[i] != GUARD)
          intact = 0;
      fprintf(stdout, "NC_ENTRY at=%u was=%u returned=%" PRIu64 " code=%" PRIu64
                      " guards_intact=%d\n",
              at, was, returned,
              (returned & FAULT_BIT) ? (returned & ~FAULT_BIT) : 0, intact);
      /* The entry must NOT be accepted wherever it moved to. Either it lands
       * outside .text and is refused with ERR_BAD_ENTRY, or the writer profile
       * puts it inside and the words then disagree with the C reader's. Both
       * are the control firing; what it may NOT do is agree silently. */
      int fired = (returned == FAULT_BIT + ERR_BAD_ENTRY);
      if (!fired && returned == 0) {
        uint64_t want[WORDS];
        reference_summary(copy, want);
        for (unsigned i = 0; i < WORDS; i++)
          if (got[i] != want[i])
            fired = 1;
      }
      CHECK(fired, "an entry RVA moved outside .text is not accepted silently");
      CHECK(intact, "the entry refusal leaves every guard intact");
      if (fired)
        nc_entry++;
      free(copy);
    }
  }

  /* NC-TWO */
  {
    size_t big_size = 0;
    uint8_t *big = build_oracle(FIXTURES + 1, &big_size);
    CHECK(big != NULL, "the second oracle image builds");
    if (big) {
      /* The small image's words are the ones main() ALREADY compared against
       * the C reader, so this control REUSES them instead of comparing the
       * same bytes a second time. An earlier version called sixteen_join on
       * both images here, and the counter then read 3 comparisons over 2
       * distinct images -- a count of COMPARISALS presented beside a banner
       * that reads as a count of OBJECTS. The two numbers are indiscernible on
       * one line and they mean different things. */
      uint64_t big_words[WORDS];
      sixteen_join(reader, big, big_size, FIXTURES[1].label, big_words);
      int differ = 0;
      for (unsigned i = 0; i < WORDS; i++)
        if (small_words[i] != big_words[i])
          differ = 1;
      fprintf(stdout, "NC_TWO small_text=%zu large_text=%zu words_differ=%d\n",
              FIXTURES[0].text, FIXTURES[1].text, differ);
      CHECK(differ,
            "two images differing in .text size give different sixteen words");
      if (differ)
        nc_two_differ++;
      nc_two_image++;
      free(big);
    }
  }

}

/* The two images the reader is proven against, kept alive for the controls. */
static uint8_t *small_pe;
static size_t small_size;

/* ======================= W214: THE ADAPTER'S OWN OUTPUT, AND THE ENTRY
 * CONTROL. =================================================================
 *
 * WHY BOTH ARE HERE AND NOT IN SOME OTHER GATE.
 *
 * THE ADAPTER BLOCK IS A CANARY, AND THE GATE NEEDS IT BECAUSE OF WHAT IT
 * CLAIMS. Everything above reports that ntasm_nxo_pe.convert refuses the
 * producer's object. A module that refused EVERYTHING would print exactly the
 * same lines. `refused == 803` is only evidence about the entry if the same
 * call site, same four modules, same buffer, returns 0 and a PE for an object
 * that HAS an entry. That is the canary rule in its shortest form: run the
 * input the producer under test is supposed to answer, first, or every other
 * number in the table is void. Without this block the CONVERT block above is a
 * green over an instrument nobody has seen succeed.
 *
 * IT IS NOT THE PRODUCER'S OBJECT AND THE BANNER SAYS SO. The canary object is
 * built by the C writer nt_object_write from a struct this file fills in, so
 * it is a FIXTURE and not machine_x64's output. It exists to make one
 * statement falsifiable -- "the adapter runs and converts when the object
 * carries an entry" -- and it says nothing about the producer's object.
 *
 * WHAT IT COMPARES, AND AGAINST WHAT, WITH THE ROLES NOT BLENDED:
 *   bytes    the adapter's PE against nt_object_materialize + nt_make_pe over
 *            the SAME NXO. That is a PRODUCER-AGAINST-C comparison: two
 *            implementations, neither able to observe the other's output.
 *   words    ntasm_pe_inspect over the adapter's PE, against reference_summary
 *            -- this file's independent C reader, written without reading
 *            pe_inspect.nova. That is a ROUTE CHECK: one image, two readers.
 * Neither is compared against pe.nova's own expectations of itself, which
 * would be a self-agreement and is the thing W210's header warned about.
 */
static void adapter_canary(const NovaHostImage *adapter,
                           const NovaHostImage *reader) {
  static uint8_t text[16];
  NtObjectSymbol symbols[1];
  NtObject authored = {0};
  NtBuffer file = {0};
  NtDiagnostic err = {0};
  for (unsigned j = 0; j < sizeof text; j++)
    text[j] = (uint8_t)(j * 11 + 5);
  symbols[0] = (NtObjectSymbol){"f", "fn:u64", NT_OBJECT_TEXT,
                                 NT_OBJECT_FUNCTION, 0, sizeof text};
  authored.target = 1;
  authored.entry_symbol = 1;
  authored.symbols = symbols;
  authored.symbol_count = 1;
  authored.sections[0] = (NtBuffer){text, sizeof text, sizeof text};
  CHECK(nt_object_write(&authored, &file, &err), "the canary object serialises");
  CHECK(file.bytes != NULL && file.size > 0, "the canary object has bytes");
  if (!file.bytes)
    return;

  uint8_t *out = (uint8_t *)malloc(CV_CAPACITY);
  CHECK(out != NULL, "the canary output buffer allocates");
  if (!out) {
    free(file.bytes);
    return;
  }
  memset(out, 0xcc, CV_CAPACITY);
  cases++;
  uint64_t returned = convert_run(adapter, file.bytes, file.size, out,
                                  CV_CAPACITY, 0);
  ad_converted = (returned != 0 && !(returned & FAULT_BIT));
  fprintf(stdout, "ADAPTER_CONVERT nxo=%zuB returned=%" PRIu64 " converted=%u\n",
          file.size, returned, ad_converted);
  CHECK(ad_converted, "the adapter converts an object that carries an entry, "
                      "so the refusals above are a discrimination and not a "
                      "module that refuses everything");

  if (ad_converted) {
    size_t n = (size_t)returned;
    uint64_t got[WORDS + GUARDS], want[WORDS];
    for (unsigned i = 0; i < WORDS + GUARDS; i++)
      got[i] = GUARD;
    cases++;
    uint64_t read_back = inspect(reader, out, n, got, WORDS);
    ad_reader_accepted = (read_back == 0);
    fprintf(stdout, "ADAPTER_READER pe=%zuB reader_returned=%" PRIu64 "\n", n,
            read_back);
    CHECK(ad_reader_accepted,
          "the PE reader accepts the image the adapter emitted, which is the "
          "step the producer's object cannot reach");
    reference_summary(out, want);
    if (read_back == 0)
      print_words("ADAPTER_READER", "canary", got);
    print_words("ADAPTER_C_READER", "canary", want);
    int same = (read_back == 0);
    for (unsigned i = 0; i < WORDS && same; i++)
      if (got[i] != want[i]) {
        fprintf(stderr,
                "FAIL adapter sixteen words disagree word=%u(%s) reader=%" PRIu64
                " c_reader=%" PRIu64 "\n",
                i, WORD_NAME[i], got[i], want[i]);
        same = 0;
      }
    for (unsigned i = WORDS; i < WORDS + GUARDS && same; i++)
      if (got[i] != GUARD)
        same = 0;
    if (same)
      ad_sixteen_agree++;
    else
      ad_sixteen_disagree++;
    CHECK(same, "the sixteen words the reader extracts from the ADAPTER's PE "
                "equal the independent C reader's on those same bytes");

    /* PRODUCER AGAINST C, byte for byte, over the same NXO. */
    NtObject back = {0};
    NtDiagnostic berr = {0};
    CHECK(nt_object_read(file.bytes, file.size, &back, &berr),
          "the C reads the canary NXO");
    if (back.symbol_count || back.sections[0].size) {
      NtArtifact art = {0};
      NtDiagnostic merr = {0};
      int made = nt_object_materialize(&back, &art, &merr) &&
                 nt_make_pe(&art) && art.pe.size > 0;
      CHECK(made, "the C materialises and lays out the canary NXO");
      if (made) {
        int equal = art.pe.size == n && !memcmp(art.pe.bytes, out, n);
        if (equal)
          ad_bytes_equal++;
        else
          ad_bytes_differ++;
        fprintf(stdout,
                "ADAPTER_PARITY adapter=%zuB c=%zuB bytes_equal=%d\n", n,
                art.pe.size, equal);
        CHECK(equal,
              "the adapter's PE is byte-for-byte the C's PE for the same NXO");
      }
      free_artifact(&art);
    }
    nt_object_free(&back);
  }
  free(out);
  free(file.bytes);
}

/* ======================= W214: NC-ENTRY-OBJECT. THE CONTROL THAT SAYS THE
 * 803 IS THE ENTRY AND NOT SOMETHING ELSE. =================================
 *
 * THE PERTURBATION, and its two properties this project requires of one. It is
 * SCOPED: four bytes at offset 88, the field object.c writes entry_symbol into
 * and reads it back from, and nothing else in the container is touched. It is
 * LENGTH-PRESERVING: the object is the same size before and after, so nothing
 * downstream can be disturbed by a size change -- which is the failure mode
 * that made a one-site opcode perturbation redden every gate.
 *
 * WHAT MUST HAPPEN: the adapter's answer MOVES OFF 803. Where it lands is
 * measured and printed and NOT asserted to a constant, because the successor
 * is a fact about nxo_pe.nova's own check order -- its validator runs before
 * the entry test -- and not a property of this join. The claim being defended
 * is only "the entry is what the refusal turned on", and that claim is
 * falsified by an UNMOVED answer, not by an unexpected destination.
 *
 * AND THIS CONTROL IS ALSO A NAMED WITNESS AGAINST MY OWN READING. If the
 * producer's object had a defined function in section 1, pointing entry at it
 * would produce a PE and the sixteen words would become reachable on the
 * producer's own bytes. The CONVERT block prints how many of its symbols are
 * imports for exactly this reason: the successor code is expected to be a
 * validation refusal, and a reader who saw a PE there would have found a fact
 * about the object that this file did not know. */
static void entry_object_control(const NovaHostImage *adapter) {
  if (!first_object || first_object_size < 92)
    return;
  nc_entry_object_run++;
  uint8_t *copy = (uint8_t *)malloc(first_object_size);
  CHECK(copy != NULL, "the entry control allocates");
  if (!copy)
    return;
  memcpy(copy, first_object, first_object_size);
  uint8_t *out = (uint8_t *)malloc(CV_CAPACITY);
  CHECK(out != NULL, "the entry control output buffer allocates");
  if (!out) {
    free(copy);
    return;
  }
  memset(out, 0xcc, CV_CAPACITY);
  cases++;
  uint64_t before = convert_run(adapter, copy, first_object_size, out,
                                CV_CAPACITY, 0);
  int intact_before = sweep_intact(out, CV_CAPACITY);
  memset(out, 0xcc, CV_CAPACITY);
  wr32(copy + 88, 1);
  cases++;
  uint64_t after = convert_run(adapter, copy, first_object_size, out,
                               CV_CAPACITY, 0);
  int intact_after = sweep_intact(out, CV_CAPACITY);
  uint64_t b = (before & FAULT_BIT) ? (before & ~FAULT_BIT) : 0;
  uint64_t a = (after & FAULT_BIT) ? (after & ~FAULT_BIT) : 0;
  if (b != a)
    nc_entry_object_moved++;
  fprintf(stdout,
          "NC_ENTRY_OBJECT object=%zuB entry_field=%u entry_rewritten_to=1 "
          "code_before=%" PRIu64 " code_after=%" PRIu64
          " intact_before=%d intact_after=%d\n",
          first_object_size, nc_entry_object_field, b, a, intact_before,
          intact_after);
  CHECK(before == FAULT_BIT + CONVERT_NO_ENTRY,
        "the unperturbed object is refused with the no-executable-entry code, "
        "which is what the CONVERT rows measured");
  CHECK(after != before,
        "rewriting the object's entry word moves the adapter off the "
        "no-executable-entry code, so that refusal is attributable to the "
        "entry and not to the adapter refusing this object for some other "
        "reason");
  CHECK(intact_before && intact_after,
        "both adapter refusals left the output buffer untouched");
  free(out);
  free(copy);
}

int main(void) {
  /* The object producer's import closure, copied from
   * tests_ntasm_machine_x64.c's PATHS so this gate loads the same modules and
   * not a second selection of them. */
  static const char *producer_paths[] = {
      "tests/nova/tests/machine-x64-entry.nova",
      "compiler/nova/backend/x64/machine_x64.nova",
      "compiler/nova/ir/machine_ir.nova",
      "compiler/nova/formats/ntir/ntir.nova",
      "compiler/nova/backend/x64/x64_fixed.nova",
      "compiler/nova/formats/nxo/nxo.nova",
      "compiler/nova/ir/ir_image.nova",
      "compiler/nova/formats/pe/pe.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/lexer.nova",
      "compiler/nova/frontend/ast.nova",
      "compiler/nova/analysis/types/register_widths.nova",
      "compiler/nova/analysis/types/pointer_spaces.nova",
      "compiler/nova/frontend/versions.nova"};
  /* The reader's closure, copied from tests_ntasm_pe_inspect.c. */
  static const char *reader_paths[] = {
      "tests/nova/tests/pe-inspect-entry.nova",
      "compiler/nova/inspectors/pe_inspect.nova",
      "compiler/nova/formats/pe/pe.nova"};
  /* W214: the ADAPTER's closure. These four are exactly the four
   * tests_ntasm_nxo_pe.c loads for the same entry, so this gate and that one
   * drive one function rather than two spellings of it. */
  static const char *adapter_paths[] = {
      "tests/nova/tests/nxo-pe-entry.nova",
      "compiler/nova/formats/nxo/nxo_pe.nova",
      "compiler/nova/formats/nxo/nxo.nova",
      "compiler/nova/formats/pe/pe.nova"};

  char *producer_owned[14] = {0}, *reader_owned[3] = {0}, *adapter_owned[4] = {0};
  NovaHostImage producer = {0}, reader = {0}, adapter = {0};
  int producer_ok =
      build_program(producer_paths, 14, &producer, producer_owned);
  int reader_ok = build_program(reader_paths, 3, &reader, reader_owned);
  int adapter_ok = build_program(adapter_paths, 4, &adapter, adapter_owned);
  CHECK(producer_ok && reader_ok, "both halves build");
  CHECK(adapter_ok, "the NXO->PE adapter closure builds");
  if (producer_ok && reader_ok && adapter_ok) {
    for (unsigned i = 0; i < BODIES_N; i++)
      join_row(&producer, &reader, &adapter, ROWS + i, BODIES[i].body);

    small_pe = build_oracle(FIXTURES + 0, &small_size);
    CHECK(small_pe != NULL, "the C writer oracle builds the control image");
    if (small_pe) {
      uint64_t produced[WORDS];
      uint64_t want[WORDS];
      reference_summary(small_pe, want);
      print_words("C_ORACLE", FIXTURES[0].label, want);
      sixteen_join(&reader, small_pe, small_size, FIXTURES[0].label, produced);
      negative_controls(&reader, small_pe, small_size, produced);
    }
    /* W214: the canary runs BEFORE the entry control on purpose. The entry
     * control's claim is "the refusal turns on the entry word", and that claim
     * is only worth making if the same call site is known to succeed at all. */
    adapter_canary(&adapter, &reader);
    entry_object_control(&adapter);
  }
  free(small_pe);
  free(first_object);
  if (producer.memory)
    nova_host_unmap(&producer);
  if (reader.memory)
    nova_host_unmap(&reader);
  if (adapter.memory)
    nova_host_unmap(&adapter);
  for (unsigned i = 0; i < 14; i++)
    free(producer_owned[i]);
  for (unsigned i = 0; i < 3; i++)
    free(reader_owned[i]);
  for (unsigned i = 0; i < 4; i++)
    free(adapter_owned[i]);

  /* THE FLOORS. Each of these says "the run actually did the thing", so a
   * green that exercised nothing is red rather than silent. */
  cases++;
  CHECK(j_rows == BODIES_N, "every corpus row ran");
  cases++;
  CHECK(j_rows == ROWS_N, "every corpus row has a measured expectation");
  cases++;
  CHECK(j_objects > 0, "the producer built at least one object");
  cases++;
  CHECK(j_refused_dos == j_objects,
        "every object the producer built was refused by the reader as not-DOS");
  cases++;
  CHECK(j_c_refusals > 0, "the C front end refused at least one source");
  cases++;
  CHECK(j_sixteen_joins > 0, "the sixteen-word comparison ran");
  cases++;
  CHECK(j_sixteen_agree == j_sixteen_joins,
        "every sixteen-word comparison agreed");
  /* THE FLOOR THAT MAKES THE BANNER'S ZERO A MEASUREMENT. Zero object-row
   * sixteen-word joins is the FINDING, and a finding that is asserted rather
   * than counted is a belief. This check requires the two populations to be
   * disjoint in the only direction that could hide a comparison: every object
   * row must have been refused by the reader, so no object row can have
   * reached the comparison. If a future producer emitted a PE, the reader
   * would stop refusing and this check would go red and the banner's zero
   * would have to be re-derived. */
  cases++;
  CHECK(object_row_sixteen_joins == 0,
        "no object row reached the sixteen-word comparison, because every "
        "object was refused before it could");
  cases++;
  CHECK(object_row_sixteen_disagree == 0,
        "no object row disagreed, because none was compared");
  cases++;
  /* The C readback floors. `j_c_read_objects` must EQUAL the number of objects
   * the producer built, or the C reader was never shown to accept them and
   * the "materialize refused" line below would be a refusal of nothing. This
   * is the check that makes the second blocker attributable to the object and
   * not to a harness that handed the wrong bytes over. */
  cases++;
  CHECK(j_c_read_objects == j_objects,
        "the C object reader accepted every object the producer built");
  cases++;
  CHECK(j_c_mat_refusals == j_objects,
        "the C materializer refused every one of them, because the object "
        "carries no entry symbol");
  CHECK(nc_run == 1 && nc_magic == 1, "the MZ magic control fired");
  cases++;
  CHECK(nc_entry == 1, "the entry RVA control fired");
  cases++;
  CHECK(nc_two_image == 1 && nc_two_differ == 1,
        "the two-image control fired and the words moved");
  cases++;
  CHECK(nc_tag == 1 && nc_tag_moved == 1,
        "the on-object tag control ran and moved the reader off ERR_NOT_DOS");
  /* THE DISTINCT-IMAGE FLOOR. `j_sixteen_joins` counts IMAGES, and an earlier
   * version of this file counted COMPARISALS over two images and printed 3.
   * A count of comparisons presented beside a banner that reads as a count of
   * artefacts is the same defect this project calls a number read in the wrong
   * field, so the population is pinned here and the banner names it. */
  cases++;
  CHECK(j_sixteen_joins == FIXTURES_N,
        "exactly one image per declared fixture was compared");
  /* ---- W214's floors. Each says the run actually reached the leg, so a zero
   * in the CONVERT banner is a measurement rather than an absence. ---- */
  cases++;
  CHECK(cv_calls == j_objects,
        "the adapter was called once on every object the producer built, so the "
        "refusal below is about every object and not about one of them");
  cases++;
  CHECK(cv_refused == cv_calls,
        "every object the producer built was refused by the adapter");
  cases++;
  CHECK(cv_code == CONVERT_NO_ENTRY,
        "the refusal the adapter gave is the no-executable-entry code");
  cases++;
  CHECK(cv_c_materialize_code == 800,
        "the C's own route refused the same bytes with 800, which is a "
        "different number in a different language for the same missing fact");
  /* The population clause for the entry. `cv_entry_capable` is COUNTED from
   * the objects, and this pins it, so the banner's zero is a measurement. A
   * banner that stated the zero as a literal would read identically here and
   * go stale the day the producer emitted a symbol. */
  cases++;
  CHECK(cv_entry_capable == 0,
        "no object the producer built names a defined function in section 1, "
        "so the missing entry has nothing to point at");
  cases++;
  CHECK(nc_entry_object_field == 0,
        "the entry word read at offset 88 of the producer's own object is 0, "
        "read where object.c writes and reads it rather than from a struct");
  cases++;
  CHECK(ad_converted,
        "the same adapter call converted an object that carries an entry");
  cases++;
  CHECK(ad_reader_accepted,
        "the reader accepted the PE the adapter emitted");
  cases++;
  CHECK(ad_bytes_equal == 1 && ad_bytes_differ == 0,
        "the adapter's PE is byte-identical to the C's PE for the same NXO");
  cases++;
  CHECK(ad_sixteen_agree == 1 && ad_sixteen_disagree == 0,
        "the sixteen words over the adapter's PE agreed with the C reader");
  cases++;
  CHECK(nc_entry_object_run == 1 && nc_entry_object_moved == 1,
        "the entry control ran on the producer's own object and its answer "
        "moved, so the 803 is attributable to the entry word");

  printf("NTASM_NOVA_OBJECT_PE_JOIN checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  /* THE BANNER STATES WHAT THE GATE DID NOT CLOSE, because a banner that only
   * says what it measured is a banner that lets a reader assume the rest.
   *   object_rows  the join itself, producer object -> PE reader. Every one was
   *                a REFUSAL with ERR_NOT_DOS, and that refusal is correct:
   *                build_object emits an NXO container (tag NXOV0001), not a
   *                PE image.
   *   sixteen_joins how many times sixteen words were compared AND agreed.
   *                NOT one of them is an object row: within this corpus no
   *                row is accepted by both halves, so "the C oracle's words
   *                for the same source" does not exist and the sixteen-word
   *                comparison is unreachable THROUGH THIS PRODUCER. The
   *                sixteen_joins above are the route checks over C-oracle
   *                images, and they are labelled a route check in the source
   *                because one image read two ways is not a witness.
   *   c_read_*     the C reference's own route from the PRODUCER'S object: the
   *                object read back with nt_object_read, then handed to
   *                nt_object_materialize. Read accepts; materialize refuses,
   *                because build_object writes `entry: 0`.
   *   neg_*        the negative controls. A run whose counters read zero here
   *                proved nothing about the comparison it names. */
  printf("NTASM_NOVA_OBJECT_PE_JOIN_ROWS object_rows=%u objects_built=%u "
         "reader_not_dos=%u reader_other=%u c_frontend_objects=%u "
         "c_frontend_refusals=%u c_no_pe=%u c_object_read_ok=%u "
         "c_object_materialize_refused=%u\n",
         j_rows, j_objects, j_refused_dos, j_refused_other, j_c_objects,
         j_c_refusals, j_c_no_pe, j_c_read_objects, j_c_mat_refusals);
  /* `object_row_sixteen_joins` is PRINTED, not written as the literal 0. A
   * banner that states a zero it computed and a banner that states a zero it
   * was written with read identically and mean different things, and the
   * second one goes stale silently the day the producer changes. */
  /* The population clause names WHAT WAS WALKED and does not say "no source"
   * about a source set this gate never drove. The eight rows of
   * tests_ntasm_machine_x64.c's corpus are the population, they are printed
   * by object_rows, and a claim about every source either producer could
   * accept is a question this run did not settle. */
  printf("NTASM_NOVA_OBJECT_PE_JOIN_WORDS sixteen_joins=%u sixteen_agree=%u "
         "role=route_check_not_witness "
         "compared_images=%u_C_writer_oracle_images_from_synthetic_patterns_"
         "not_any_producer_output "
         "object_row_sixteen_joins=%u "
         "object_row_sixteen_agree=%u object_row_sixteen_disagree=%u "
         "population=the_8_rows_of_the_machine_x64_corpus "
         "limits=build_object_emits_NXO_not_PE_so_the_comparison_is_unreachable_"
         "through_this_producer;within_that_population_no_row_is_accepted_by_"
         "both_halves;whether_any_source_outside_this_population_is_accepted_by_"
         "both_is_NOT_MEASURED\n",
         j_sixteen_joins, j_sixteen_agree, j_sixteen_joins,
         object_row_sixteen_joins, object_row_sixteen_agree,
         object_row_sixteen_disagree);
  /* THE DISTINCT-IMAGE FLOOR. `j_sixteen_joins` counts IMAGES, and an earlier
   * version of this file counted COMPARISALS over two images and printed 3.
   * A count of comparisons presented beside a banner that reads as a count of
   * artefacts is the same defect this project calls a number read in the wrong
   * field, so the floor below pins the population and the banner names it. */
  cases++;
  CHECK(j_sixteen_joins == 2,
        "exactly two distinct images were compared, one per declared fixture");
  printf("NTASM_NOVA_OBJECT_PE_JOIN_NEG controls=%u tag=%u tag_moved=%u "
         "magic=%u entry=%u two_image=%u two_image_differ=%u "
         "limits=tag_control_perturbs_the_JOIN_S_OWN_object_not_a_stand_in\n",
         noc_cases, nc_tag, nc_tag_moved, nc_magic, nc_entry, nc_two_image,
         nc_two_differ);
  /* THE CONVERT BANNER. Every field names which SIDE produced it, because the
   * whole point of adding this leg is that "the adapter refused" and "the C
   * refused" are two answers about one object and a reader who saw only one
   * of them would not know there were two.
   *   calls/refused/accepted   the adapter, over the producer's own objects.
   *   adapter_code             2^63+code from ntasm_nxo_pe.convert.
   *   c_materialize_code       the C's nt_object_materialize, same bytes.
   *   entry_word               read at offset 88 of the object's own bytes.
   *   symbols/imports          what the object NAMES. On this population both
   *                            are ZERO -- the objects carry no symbols at
   *                            all -- and that is why entry=0 is not a field
   *                            waiting to be filled in.
   *   canary_*                 the ADAPTER's own output, from a fixture this
   *                            file authored -- NOT the producer's object.
   *   parity_bytes_*           adapter PE vs nt_make_pe PE, same NXO: two
   *                            producers, a witness.
   *   sixteen_*                the reader over the adapter's PE against the
   *                            independent C reader on the same bytes: one
   *                            image two ways, a route check. NOT compared
   *                            against pe.nova's own writer, and NOT over
   *                            the producer's object, which has no PE. */
  printf("NTASM_NOVA_OBJECT_PE_JOIN_CONVERT calls=%u refused=%u accepted=%u "
         "adapter_code=%" PRIu64 " c_materialize_code=%" PRIu64
         " entry_word=%u symbols=%u imports=%u entry_capable=%u "
         "limits=the_producer_names_NO_symbols_at_all_on_this_population_so_no_"
         "index_in_the_object_could_be_an_entry;entry_0_is_a_fact_machine_x64_"
         "says_so;whether_the_Machine_IR_could_name_the_function_it_defines_is_"
         "NOT_MEASURED_here;the_reader_still_refuses_the_object_with_822_"
         "because_convert_produced_no_bytes_to_give_it\n",
         cv_calls, cv_refused, cv_accepted, cv_code, cv_c_materialize_code,
         nc_entry_object_field, cv_symbols, cv_imports, cv_entry_capable);
  printf("NTASM_NOVA_OBJECT_PE_JOIN_ADAPTER canary_converted=%u "
         "reader_accepted=%u parity_bytes_equal=%u parity_bytes_differ=%u "
         "sixteen_agree=%u sixteen_disagree=%u "
         "words_compared_against=the_independent_C_reader_reference_summary_"
         "NOT_pe_nova_s_own_writer "
         "canary_source=an_NXO_this_file_authored_via_nt_object_write_"
         "NOT_machine_x64_output "
         "limits=no_PE_of_the_producers_own_object_exists_so_no_sixteen_words_"
         "were_compared_over_it\n",
         ad_converted, ad_reader_accepted, ad_bytes_equal, ad_bytes_differ,
         ad_sixteen_agree, ad_sixteen_disagree);
  return failures ? 1 : 0;
}
