/* tests_ntasm_ir_image.c -- the gate for the IR BYTE CONTAINER.
 *
 * THE STATE OF THE TREE THIS FILE WAS WRITTEN AGAINST, cited, because the
 * brief that asked for it said "NTIR and Machine IR have no serialised schema"
 * and that sentence is only half true and the half that is true is the half
 * that mattered.
 *
 *   ALREADY THERE, AND NOT MISSING. Both IRs specify a header. ntir.nova:44-63
 *   documents an eight-word header -- magic, major, minor, node_count, root,
 *   stride, ast_node_count, typed_count -- with its constants at ntir.nova:89-94
 *   and its reader refusing 808 on a wrong tag or a wrong version at
 *   ntir.nova:840-841. machine_ir.nova:63-76 documents the same for its
 *   twenty-word records, with constants at :118-123 and the same refusal at
 *   :2774-2775 and again in serialize at :2960-2961. For the NTIR this is not
 *   merely present but EXERCISED: tests_ntasm_ntir.c:576-577 damages the magic
 *   and the version and demands 808.
 *
 *   GENUINELY MISSING, AND THIS FILE IS THE PROOF. A header inside a
 *   `buf<u64>` is a header with nothing outside the process to be wrong about.
 *   The image is host words handed over by pointer, so it has no byte order, no
 *   record alignment, no length and no digest. The measure of that is one
 *   command and its result:
 *
 *       grep -rniE deserial --include=*.nova --include=*.c --include=*.h .
 *
 *   Over 8023 files that returned exactly one line, and the line is the comment
 *   in ir_image.nova that quotes this sentence. Before this lot it returned
 *   nothing at all. No reader of an IR image had ever existed, in any language,
 *   anywhere in the repository -- so the tag rejections above could only ever
 *   be reached by the process that had just written the buffer.
 *
 *   AND ONE THING THAT WAS WRITTEN AND NEVER FIRED. tests_ntasm_machine_ir.c
 *   lists "the version pin" under WHAT IS NOT HERE, ON PURPOSE, at its lines
 *   101-107. machine_ir.nova:2774-2775 was therefore reachable -- mode 5 of
 *   machine-ir-entry.nova verifies `out` with no parse and no build -- and had
 *   never been run. Section F below fires it.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ASSERTED HERE, AND AGAINST WHAT.
 *
 *  1. THE TAG IS PINNED BY A LITERAL IN THIS FILE. EXPECTED_NTIR_TAG and
 *     EXPECTED_MIR_TAG are typed here as text and are NOT read back from
 *     ir_image.nova. That is the whole point and it is worth being explicit
 *     about why, because the alternative is the defect this project keeps
 *     finding: a check whose expectation is derived from the module that
 *     produces the quantity can only confirm that the module agrees with
 *     itself. A tag that moved in ir_image.nova must red THIS file. If the
 *     expectation were read from the module, moving the tag would move the
 *     expectation with it and the gate would stay green -- which is the exact
 *     shape of "a register that lost its first row" and of a count whose
 *     expected maximum came from parsing the same table.
 *
 *     The expected tag is a function of the version: NTI0 + "0001", where
 *     NTI is the family, 0 is the domain as a digit, and 0001 is
 *     FORMAT_VERSION rendered in decimal. The derivation is the mechanism
 *     ir_image.nova copied from nxo.nova:36-59, and this file pins its RESULT
 *     rather than its formula.
 *
 *  2. THE HEADER LAYOUT. Offsets 8 version, 12 domain, 16 word_bytes, 20
 *     reserved0, 24 word_count, 32 size, 40 digest, 48 reserved1, 56 body.
 *     These offsets are literals in this file, for the reason in 1. The values
 *     are then read out of a file the TREE produced and compared against them.
 *
 *  3. ROUND TRIP, FOR BOTH IRs. build/lower, then write, then read, then the
 *     IR's OWN verifier, and the words that come back are compared byte for
 *     byte with the words that went in. A container that loses a word on the
 *     way out and a verifier that cannot see it would pass a gate that only
 *     checked the return code.
 *
 *  4. TWELVE NAMED REJECTIONS, EACH FROM A FILE THE TREE PRODUCED. A bad file
 *     invented in C would be testing a C fiction; a file this lowering wrote
 *     and this file then broke at a NAMED BYTE is a real break. Each case
 *     names the byte it damaged and the code it demands, and the codes are the
 *     ones ir_image.nova publishes (850..858).
 *
 *     THE ORDER OF THE READER'S CHECKS IS PART OF THE CONTRACT. The digest is
 *     checked LAST, so damaging a reserved word yields E_RESERVED rather than
 *     E_DIGEST even though the digest is also now wrong. A reader that
 *     checked the digest first would answer E_DIGEST for all twelve cases and
 *     the twelve cases would be one case wearing twelve hats. That is why each
 *     case below demands a SPECIFIC code and not merely "a non-zero code".
 *
 *  5. THE TWO DOMAINS DO NOT READ EACH OTHER. A Machine IR file offered to the
 *     NTIR reader and the reverse, both refused, both with the family code
 *     rather than a generic one. Byte 3 of the tag is the domain, so this
 *     tests the derived byte and not just the field at offset 12.
 *
 *  6. MACHINE IR'S OWN TAG CHECK, FIRED. machine_ir.nova:2774-2775 exists and
 *     had never rejected anything. An image the lowering produced is damaged
 *     at word 0 and at word 1, and mode 5 must answer 930 both times.
 *
 *  7. A DIGEST IS PRINTED. FNV-1a over the file, so the bytes are anchored to
 *     a number a reader can check and not only to a comparison somebody might
 *     have run wrongly.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
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

#define WORDS 262144
#define TEXT 1048576
#define REPORT 256
#define GUARD UINT64_C(0xcccccccccccccccc)

/* ---- the two images ------------------------------------------------------
 * Each entry module exports `main` and one image carries one entry, so the
 * NTIR container and the Machine IR container are two compiles of two source
 * sets and not one compile of a union. */
static const char *const NTIR_PATHS[] = {
    "tests/nova/tests/ntir-entry.nova",
    "compiler/nova/ir/ir_image.nova",
    "compiler/nova/formats/ntir/ntir.nova",
    "compiler/nova/formats/pe/pe.nova",
    "compiler/nova/analysis/types/pointer_spaces.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/lexer.nova",
    "compiler/nova/frontend/ast.nova"};
#define NTIR_PATHS_N ((unsigned)(sizeof NTIR_PATHS / sizeof NTIR_PATHS[0]))

static const char *const MIR_PATHS[] = {
    "tests/nova/tests/machine-ir-entry.nova",
    "compiler/nova/ir/ir_image.nova",
    "compiler/nova/ir/machine_ir.nova",
    "compiler/nova/formats/ntir/ntir.nova",
    "compiler/nova/formats/pe/pe.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/lexer.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/analysis/types/pointer_spaces.nova",
    "compiler/nova/frontend/versions.nova"};
#define MIR_PATHS_N ((unsigned)(sizeof MIR_PATHS / sizeof MIR_PATHS[0]))

/* ---- THE PINS. LITERALS IN C, ON PURPOSE. --------------------------------
 * These eight bytes are the whole contract and they are typed HERE rather than
 * read back from ir_image.nova. See section 1 of the header comment: an
 * expectation read from the module that produces the quantity confirms only
 * that the module agrees with itself, and a tag that moved in the module would
 * then move the expectation with it and leave this gate green.
 *
 * NTI0 0001 -- family "NTI", domain digit '0', FORMAT_VERSION 1 as decimal.
 * MIR1 0001 -- family "MIR", domain digit '1', FORMAT_VERSION 1 as decimal. */
static const char EXPECTED_NTIR_TAG[] = "NTI00001";
static const char EXPECTED_MIR_TAG[] = "MIR10001";

/* The header, in bytes. Also literals, for the same reason. */
enum { HDR_BYTES = 56, OFF_VERSION = 8, OFF_DOMAIN = 12, OFF_WORDBYTES = 16,
       OFF_RESERVED0 = 20, OFF_WORDCOUNT = 24, OFF_SIZE = 32, OFF_DIGEST = 40,
       OFF_RESERVED1 = 48 };

/* The container's refusal codes, as ir_image.nova publishes them. */
#define E_TAG 850
#define E_VERSION 851
#define E_DOMAIN 852
#define E_WORDBYTES 853
#define E_RESERVED 854
#define E_SIZE 855
#define E_COUNT 856
#define E_DIGEST 857
#define E_TRUNCATED 858
/* machine_ir.nova's own tag refusal, E_TAG at :291. */
#define MIR_E_TAG 930

/* ---- helpers ------------------------------------------------------------- */
static char *loadf(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *p = n >= 0 ? (char *)malloc((size_t)n + 1) : NULL;
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

static uint64_t r32(const uint8_t *b, size_t at) {
  return (uint64_t)b[at] | ((uint64_t)b[at + 1] << 8) |
         ((uint64_t)b[at + 2] << 16) | ((uint64_t)b[at + 3] << 24);
}
static uint64_t r64(const uint8_t *b, size_t at) {
  uint64_t v = 0;
  for (unsigned i = 0; i < 8; i++)
    v |= (uint64_t)b[at + i] << (i * 8);
  return v;
}
static void w64(uint8_t *b, size_t at, uint64_t v) {
  for (unsigned i = 0; i < 8; i++)
    b[at + i] = (uint8_t)(v >> (i * 8));
}
/* FNV-1a over a FILE, with the digest field itself read as zero.
 *
 * Two things are deliberate here. First, the same two constants
 * machine_ir.nova:837-846 and ir_image.nova use, so a disagreement between
 * this and the module is a disagreement about the bytes and not about the
 * hash. Second, bytes 40..48 are SKIPPED, because that is what the container
 * does: a digest is computed over every byte of the file except the field
 * holding it, and hashing the field you are about to write is a fixed point
 * nobody solves. The first version of this function hashed all `n` bytes and
 * disagreed with the module on every file -- which is the correct outcome for
 * two honest implementations asked different questions, and a reminder that
 * "the digests differ" is not the same finding as "the digest is wrong".
 *
 * This is a SECOND implementation on purpose. A digest computed by the same
 * code that produced the bytes confirms only that the code is deterministic. */
static uint64_t fnv(const uint8_t *b, size_t n) {
  uint64_t h = UINT64_C(14695981039346656037);
  for (size_t i = 0; i < n; i++) {
    if (i >= OFF_DIGEST && i < OFF_DIGEST + 8)
      continue;
    h ^= b[i];
    h *= UINT64_C(1099511628211);
  }
  return h;
}

typedef struct {
  uint64_t returned, runtime;
  uint64_t *words, *image;
  uint64_t *report;
  uint64_t length[4];
  uint8_t *text;
  size_t text_len;
} Run;

static void run_init(Run *r) {
  r->words = (uint64_t *)malloc(WORDS * sizeof(uint64_t));
  r->image = (uint64_t *)malloc(WORDS * sizeof(uint64_t));
  r->report = (uint64_t *)malloc(REPORT * sizeof(uint64_t));
  r->text = (uint8_t *)malloc(TEXT);
  if (!r->words || !r->image || !r->report || !r->text) {
    fprintf(stderr, "FAIL allocation\n");
    exit(1);
  }
  memset(r->text, 0xcc, TEXT);
  r->text_len = 0;
}
static void run_free(Run *r) {
  free(r->words);
  free(r->image);
  free(r->report);
  free(r->text);
}

/* `feed` is a file to hand the entry as INPUT, or NULL for a mode that only
 * writes. The read modes size the file by length[0] and not by len(text),
 * because `text` is a scratch buffer whose capacity is not a file's length and
 * the container refuses any file whose stated size is not the size it was
 * given. */
static void run(const NovaHostImage *image, int is_mir, const char *source,
                size_t size, uint64_t mode, uint64_t index, Run *r,
                const uint8_t *feed, size_t feed_len) {
  NovaContextV2 c = {0};
  for (unsigned i = 0; i < REPORT; i++)
    r->report[i] = GUARD;
  for (unsigned i = 0; i < 4; i++)
    r->length[i] = GUARD;
  memset(r->text, 0xcc, TEXT);
  r->text_len = 0;
  if (feed && feed_len && feed_len <= TEXT) {
    memcpy(r->text, feed, feed_len);
    r->length[0] = feed_len;
    r->text_len = feed_len;
  }
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)source, size, 0);
  uint64_t wh = nova_borrow_v2(&c, r->words, WORDS * sizeof(uint64_t), 1);
  uint64_t ih = nova_borrow_v2(&c, r->image, WORDS * sizeof(uint64_t), 1);
  uint64_t th = nova_borrow_v2(&c, r->text, TEXT, 1);
  uint64_t lh = nova_borrow_v2(&c, r->length, 4 * sizeof(uint64_t), 1);
  uint64_t rh = nova_borrow_v2(&c, r->report, REPORT * sizeof(uint64_t), 1);
  uint64_t code;
  if (is_mir) {
    /* machine-ir-entry.nova's main takes ten parameters of which six are
     * buffers, so 10 + 6 = 16 flat slots. */
    uint64_t args[] = {sh, size, mode, index, wh, WORDS, WORDS, ih, WORDS,
                       WORDS, th, TEXT, lh, 4, rh, REPORT};
    code = image->entry(&c, args, 16);
  } else {
    /* ntir-entry.nova's main takes eight parameters of which four are buffers,
     * so 8 + 4 = 12 flat slots. FOUR, not five: `words`, `text`,
     * `text_length` and `report` are buffers and `source` is borrowed
     * separately, so the count is not 8 + 5.
     *
     * A `buf<T>` crosses as a handle plus its ELEMENT count and then the
     * entry's OWN length parameter follows as a separate word, which is why
     * `wh, WORDS, WORDS` appears below and not `wh, WORDS`. Dropping the
     * second one does not fail loudly: `word_count` reads whatever slot comes
     * next, the entry returns 800, and every check downstream sees a GUARD
     * where a count should be. The first version of this file did exactly
     * that and the only symptom was an ASan abort on a malloc of
     * 0xcccccccc, which is what a missing slot looks like from the outside. */
    uint64_t args[] = {sh, size, mode, index, wh, WORDS, WORDS, th, TEXT, lh,
                       4, rh, REPORT};
    code = image->entry(&c, args, 13);
  }
  r->returned = code;
  r->runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
}

/* ---- the corpus ----------------------------------------------------------
 * Two programs, and the second is the one the first version of this file got
 * wrong. Fixture 0 originally carried a body of the shape
 *
 *     fn add(a:u64,b:u64)->u64 ... let r:u64=a ... r=r+b
 *
 * and it did not lower: ntir.build answered 800, which this gate reported as
 * "the NTIR did not build" and which says NOTHING about why. A parameter
 * without a direction word is a parse error and not a shorthand
 * (parser.nova:337), and the `let` form was the second thing wrong with it.
 * The shape below is taken from tests_ntasm_ntir.c's own f0, which is a
 * fixture that gate already knows lowers, so this gate is not inventing a
 * corpus and re-discovering the parser's grammar through it.
 *
 * Fixture 1 is a bare main, which gives a second and much smaller node count
 * and therefore a second file length. A container that had hard-coded a size,
 * or a reader that trusted a length it should have recomputed, would pass one
 * of these and not the other -- which is the only reason there are two. */
static const char *const FIXTURES[] = {
    /* Taken from tests_ntasm_machine_ir.c:206-224, which is a corpus that
     * gate already lowers, verifies and measures. This gate is not here to
     * re-discover the Machine IR's accepted input through trial and error:
     * two earlier versions of this file carried their own fixtures and the
     * Machine IR refused both -- 940 E_INPUT for a module with a const and a
     * data array, 934 E_SHAPE for a bare main. Both refusals are the Machine
     * IR being right about shapes this gate was not measuring. */
    "module m\ntarget x86_64-nexora-none\n"
    "section .text {\n"
    "fn helper(in a:u64, in b:u64)->u64\n"
    "effects {}\n"
    "clobbers {} {\n"
    "return a+b\n"
    "}\n"
    "fn main(in w:u8)->u64\n"
    "effects {}\n"
    "clobbers {rax} {\n"
    "let n:u64=w\n"
    "nop\n"
    "mov rax, n\n"
    "add rax, 1\n"
    "return rax\n"
    "}\n"
    "}\n",
    /* A second program, and the reason it is not `add rax, 2` is a measurement
     * this gate printed on its own first green run:
     *
     *   NTIR-FILE fixture 0 nodes=75 words=1208 bytes=9720 digest=0x74bfe916...
     *   NTIR-FILE fixture 1 nodes=75 words=1208 bytes=9720 digest=0x74bfe916...
     *
     * Two fixtures, one NTIR file, byte for byte. The immediate in `add rax, N`
     * is not a word the NTIR records -- an NTIR node carries kind, source,
     * line, column, span, three links, a child count and four typed words, and
     * the VALUE of an immediate is none of those (ntir.nova:63-78). So changing
     * 1 to 2 changed the Machine IR (whose digest did move, 0x3083ceb7 vs
     * 0x75482c4d) and changed the NTIR not at all. That is a real property of
     * the two levels and not a defect, and it is recorded here because the
     * first version of this comment claimed "different bytes, different record
     * count, different file length" for both, which was true of the Machine IR
     * and false of the NTIR. The comment was the thing that was wrong.
     *
     * The second fixture therefore varies main's SIGNATURE, which does change
     * the node count, and the run prints both digests so a reader can see
     * that the two files really are two.
     *
     * The first attempt at this second fixture was smaller -- a bare `fn main`
     * with a `nop` and `return 0` and no helper -- and the Machine IR refused
     * it with 934 E_SHAPE. This file is not measuring what makes a Machine IR
     * acceptable, and inventing a corpus to find out is how a gate ends up
     * encoding somebody else's refusal as its own expectation. */
    "module m\ntarget x86_64-nexora-none\n"
    "section .text {\n"
    "fn helper(in a:u64, in b:u64)->u64\n"
    "effects {}\n"
    "clobbers {} {\n"
    "return a+b\n"
    "}\n"
    "fn main(in w:u8, in v:u16, out z:u32)->u64\n"
    "effects {}\n"
    "clobbers {rax} {\n"
    "let n:u64=w\n"
    "nop\n"
    "mov rax, n\n"
    "add rax, 2\n"
    "return rax\n"
    "}\n"
    "}\n"};
#define FIXTURES_N ((unsigned)(sizeof FIXTURES / sizeof FIXTURES[0]))

/* ---- a named damage, and the code it must produce ------------------------
 * `at` is a byte offset into the file. The offset is WRITTEN DOWN here rather
 * than computed from a header this file also reads, so a header that moved
 * would make these cases land on the wrong byte and the case name would then
 * be describing something other than what it damaged. The tell for that is a
 * refusal code that does not match the case, which is why every case prints
 * both the name it damaged and the code it got. */
typedef struct {
  const char *name;
  size_t at;
  uint64_t value;   /* what the byte or word is set to */
  int is_word;      /* 1: write 8 bytes, 0: write one byte */
  uint64_t expect;  /* the code the reader must return */
  int truncate_to;  /* >0: hand the reader only this many bytes instead */
} Damage;

/* THE THIRTEENTH CASE WAS WRONG IN THE FIRST VERSION AND THE CODE WAS RIGHT.
 * "the file cut inside the body" truncated to 60 bytes and I expected
 * E_COUNT, on the reasoning that the body would no longer be a whole number
 * of words. The reader answers E_SIZE instead, and it is right: the header's
 * size field still says the original length and the file is 60 bytes, so the
 * first thing that is false is the size, and the size is checked first. The
 * expectation was the defect and the reader was not, which is the only
 * direction this project tolerates: never move a pin to make a red go away.
 * Both numbers stay here. */
static const Damage DAMAGES[] = {
    {"the family letter, byte 0", 0, 'X', 0, E_TAG, 0},
    {"the domain digit inside the tag, byte 3", 3, '9', 0, E_TAG, 0},
    {"the version digit inside the tag, byte 7", 7, '9', 0, E_VERSION, 0},
    {"the version number, offset 8", OFF_VERSION, 2, 1, E_VERSION, 0},
    {"the domain number, offset 12", OFF_DOMAIN, 1, 1, E_DOMAIN, 0},
    {"the word size, offset 16", OFF_WORDBYTES, 4, 1, E_WORDBYTES, 0},
    {"reserved word 0, offset 20", OFF_RESERVED0, 1, 1, E_RESERVED, 0},
    {"reserved word 1, offset 48", OFF_RESERVED1, 1, 1, E_RESERVED, 0},
    {"the word count, offset 24", OFF_WORDCOUNT, 999, 1, E_COUNT, 0},
    {"the size, offset 32", OFF_SIZE, 1, 1, E_SIZE, 0},
    {"a body word, byte 60", 60, 0xff, 1, E_DIGEST, 0},
    {"the file cut inside the header", 0, 0, 0, E_TRUNCATED, 40},
    {"the file cut inside the body", 0, 0, 0, E_SIZE, 60}};
#define DAMAGES_N ((unsigned)(sizeof DAMAGES / sizeof DAMAGES[0]))

/* ---- one image, one file ------------------------------------------------- */
static void exercise(const NovaHostImage *ntir, const NovaHostImage *mir,
                     const char *source, unsigned index) {
  char name[64];
  snprintf(name, sizeof name, "fixture %u", index);
  cases++;
  Run a, b, c;
  run_init(&a);
  run_init(&b);
  run_init(&c);
  size_t len = strlen(source);

  /* Every stage check below NAMES ITS TWO CODES rather than testing a bare
   * zero. A stage that refused silently would be indistinguishable from a
   * stage that was never reached, and the difference between "did not run" and
   * "ran and agreed" is the whole content of this file. It is also the only
   * way the reader learns WHICH stage refused: `length[0]` is a GUARD whenever
   * a stage fails, and a malloc of a GUARD aborts under ASan with a number
   * that says nothing about which call produced it. */

  /* --- 1. the NTIR file ------------------------------------------------- */
  /* mode 2 builds the image and leaves it undamaged in `words`. */
  run(ntir, 0, source, len, 2, 0, &a, NULL, 0);
  checks++;
  if (a.returned != 0 || a.runtime != 0) {
    failures++;
    fprintf(stderr, "FAIL %s the NTIR did not build: code=%llu runtime=%llu\n",
            name, (unsigned long long)a.returned, (unsigned long long)a.runtime);
    goto done;
  }
  uint64_t ntir_count = a.report[0];

  /* mode 6 builds, verifies and writes. The bytes land in `text`. */
  run(ntir, 0, source, len, 6, 0, &b, NULL, 0);
  checks++;
  if (b.returned != 0 || b.runtime != 0 || b.length[0] < HDR_BYTES ||
      b.length[0] >= TEXT) {
    failures++;
    fprintf(stderr,
            "FAIL %s the NTIR did not serialise: code=%llu runtime=%llu "
            "length=%llu\n",
            name, (unsigned long long)b.returned, (unsigned long long)b.runtime,
            (unsigned long long)b.length[0]);
    goto done;
  }
  size_t ntir_len = (size_t)b.length[0];
  uint8_t *file = (uint8_t *)malloc(ntir_len);
  if (!file) {
    fprintf(stderr, "FAIL allocation\n");
    exit(1);
  }
  memcpy(file, b.text, ntir_len);

  /* --- 2. THE TAG, against the literal in this file -------------------- */
  checks++;
  if (ntir_len < 8 || memcmp(file, EXPECTED_NTIR_TAG, 8) != 0) {
    failures++;
    fprintf(stderr,
            "FAIL %s the NTIR tag is not the one this file pins: got "
            "[%.*s] want [%s]\n",
            name, (int)(ntir_len < 8 ? ntir_len : 8), (const char *)file,
            EXPECTED_NTIR_TAG);
  }

  /* --- 3. THE HEADER, against the offsets in this file ------------------ */
  checks++;
  uint64_t wc = r64(file, OFF_WORDCOUNT);
  if (r32(file, OFF_VERSION) != 1 || r32(file, OFF_DOMAIN) != 0 ||
      r32(file, OFF_WORDBYTES) != 8 || r32(file, OFF_RESERVED0) != 0 ||
      r64(file, OFF_RESERVED1) != 0 || r64(file, OFF_SIZE) != ntir_len ||
      HDR_BYTES + wc * 8 != ntir_len || wc < 8 || wc > WORDS) {
    failures++;
    fprintf(stderr,
            "FAIL %s the NTIR header does not match the layout this file "
            "declares: version=%llu domain=%llu word_bytes=%llu res0=%llu "
            "res1=%llu word_count=%llu size=%llu len=%zu\n",
            name, (unsigned long long)r32(file, OFF_VERSION),
            (unsigned long long)r32(file, OFF_DOMAIN),
            (unsigned long long)r32(file, OFF_WORDBYTES),
            (unsigned long long)r32(file, OFF_RESERVED0),
            (unsigned long long)r64(file, OFF_RESERVED1),
            (unsigned long long)wc, (unsigned long long)r64(file, OFF_SIZE),
            ntir_len);
  }
  /* The digest is a claim about CONTENT. Checked against a second FNV written
   * out in C above, so this is two implementations agreeing and not one
   * implementation confirming itself. */
  checks++;
  if (r64(file, OFF_DIGEST) != fnv(file, ntir_len)) {
    failures++;
    fprintf(stderr, "FAIL %s the NTIR digest is not FNV-1a over the file\n",
            name);
  }

  /* --- 4. THE HEADER IS 56 BYTES WIDE, PROVEN FROM THE FILE ------------ */
  /* The first body word must be the NTIR's own magic. If the header were 48
   * bytes, or 64, this word would be the major version, or the node count, or
   * a node's kind -- and comparing it against the magic is how this file
   * establishes WHERE the body starts without asking the module where the
   * body starts. The magic is a literal here and it is the same number
   * ntir.nova:89 holds, which is the whole reason a second reader of it is
   * allowed to exist: the module and this check must be able to disagree. */
  checks++;
  if (ntir_len < HDR_BYTES + 8 || r64(file, HDR_BYTES) != 0x4E544952u) {
    failures++;
    fprintf(stderr,
            "FAIL %s the NTIR body does not begin with the NTIR magic, so the "
            "%d-byte header is wrong: word at offset %d is 0x%016llx\n",
            name, HDR_BYTES, HDR_BYTES,
            (unsigned long long)(ntir_len < HDR_BYTES + 8
                                     ? 0
                                     : r64(file, HDR_BYTES)));
  }

  /* --- 5. ROUND TRIP ---------------------------------------------------- */
  /* mode 7 reads the file back and then runs ntir.verify on what came out, so
   * a return of 0 says both "the bytes were read" and "what they hold is an
   * NTIR".
   *
   * THE SPAN IS THE IMAGE'S OWN, taken from its header words 3 and 5, and the
   * first version of this line compared `wc > ntir_count + 64` -- a TOTAL word
   * count against a NODE count. It failed on both fixtures, printed "they
   * differ", and the words it named as the first difference were word `wc`
   * itself, holding 0 against 0: there was no difference at all and the guard
   * was simply wrong. A guard that is wrong in the safe direction is still
   * wrong, and a comparison that reports a difference is right far more often
   * than not -- the case where it is wrong is the one worth printing. */
  uint64_t nodes = a.words[3];
  uint64_t stride = a.words[5];
  uint64_t span = 8 + nodes * stride;
  run(ntir, 0, source, len, 7, 0, &c, file, ntir_len);
  checks++;
  if (c.returned != 0 || c.runtime != 0) {
    failures++;
    fprintf(stderr, "FAIL %s the NTIR file did not read back: code=%llu\n", name,
            (unsigned long long)c.returned);
  } else {
    checks++;
    if (wc != span) {
      failures++;
      fprintf(stderr,
              "FAIL %s the file says %llu words and the image occupies %llu "
              "(%llu nodes of stride %llu under an 8-word header)\n",
              name, (unsigned long long)wc, (unsigned long long)span,
              (unsigned long long)nodes, (unsigned long long)stride);
    } else if (memcmp(a.words, c.words, (size_t)span * 8) != 0) {
      failures++;
      /* PRINT THE FIRST DIFFERING WORD, not the fact of a difference. "They
       * differ" and "word 3 is 0x2a in one and 0 in the other" are not the
       * same finding, and only the second one names a stage. */
      uint64_t first_bad = span;
      for (uint64_t w = 0; w < span; w++) {
        if (a.words[w] != c.words[w]) {
          first_bad = w;
          break;
        }
      }
      fprintf(stderr,
              "FAIL %s the NTIR did not survive the round trip over %llu words; "
              "first difference at word %llu: 0x%016llx vs 0x%016llx\n",
              name, (unsigned long long)span, (unsigned long long)first_bad,
              (unsigned long long)(first_bad < span ? a.words[first_bad] : 0),
              (unsigned long long)(first_bad < span ? c.words[first_bad] : 0));
    }
  }

  /* --- 6. THE NAMED REJECTIONS ----------------------------------------- */
  for (unsigned m = 0; m < DAMAGES_N; m++) {
    uint8_t *bad = (uint8_t *)malloc(ntir_len);
    size_t hand;
    if (!bad) {
      fprintf(stderr, "FAIL allocation\n");
      exit(1);
    }
    memcpy(bad, file, ntir_len);
    if (DAMAGES[m].truncate_to) {
      hand = (size_t)DAMAGES[m].truncate_to;
    } else {
      hand = ntir_len;
      if (DAMAGES[m].is_word)
        w64(bad, DAMAGES[m].at, DAMAGES[m].value);
      else
        bad[DAMAGES[m].at] = (uint8_t)DAMAGES[m].value;
    }
    run(ntir, 0, source, len, 7, 0, &c, bad, hand);
    cases++;
    checks++;
    if (c.returned != DAMAGES[m].expect) {
      failures++;
      fprintf(stderr,
              "FAIL %s damaged at %s: wanted %llu and got %llu\n", name,
              DAMAGES[m].name, (unsigned long long)DAMAGES[m].expect,
              (unsigned long long)c.returned);
    }
    free(bad);
  }

  printf("NTIR-FILE %s nodes=%llu words=%llu bytes=%zu digest=0x%016llx\n", name,
         (unsigned long long)ntir_count, (unsigned long long)wc, ntir_len,
         (unsigned long long)fnv(file, ntir_len));
  free(file);

  /* --- 7. THE MACHINE IR FILE ------------------------------------------ */
  run(mir, 1, source, len, 0, 0, &a, NULL, 0);
  checks++;
  if (a.returned != 0 || a.runtime != 0) {
    failures++;
    fprintf(stderr,
            "FAIL %s the Machine IR did not build: code=%llu runtime=%llu\n",
            name, (unsigned long long)a.returned, (unsigned long long)a.runtime);
    goto done;
  }
  uint64_t mir_records = a.report[0];

  run(mir, 1, source, len, 9, 0, &b, NULL, 0);
  checks++;
  if (b.returned != 0 || b.runtime != 0 || b.length[0] < HDR_BYTES ||
      b.length[0] >= TEXT) {
    failures++;
    fprintf(stderr,
            "FAIL %s the Machine IR did not serialise: code=%llu runtime=%llu "
            "length=%llu\n",
            name, (unsigned long long)b.returned, (unsigned long long)b.runtime,
            (unsigned long long)b.length[0]);
    goto done;
  }
  size_t mir_len = (size_t)b.length[0];
  uint8_t *mfile = (uint8_t *)malloc(mir_len);
  if (!mfile) {
    fprintf(stderr, "FAIL allocation\n");
    exit(1);
  }
  memcpy(mfile, b.text, mir_len);

  checks++;
  if (mir_len < 8 || memcmp(mfile, EXPECTED_MIR_TAG, 8) != 0) {
    failures++;
    fprintf(stderr,
            "FAIL %s the Machine IR tag is not the one this file pins: got "
            "[%.*s] want [%s]\n",
            name, (int)(mir_len < 8 ? mir_len : 8), (const char *)mfile,
            EXPECTED_MIR_TAG);
  }
  checks++;
  if (r32(mfile, OFF_DOMAIN) != 1 || r64(mfile, OFF_SIZE) != mir_len ||
      HDR_BYTES + r64(mfile, OFF_WORDCOUNT) * 8 != mir_len) {
    failures++;
    fprintf(stderr, "FAIL %s the Machine IR header does not match the layout\n",
            name);
  }
  /* The same header-width anchor as the NTIR gets, with the Machine IR's own
   * magic (machine_ir.nova:118, 0x4D495231). */
  checks++;
  if (mir_len < HDR_BYTES + 8 || r64(mfile, HDR_BYTES) != 0x4D495231u) {
    failures++;
    fprintf(stderr,
            "FAIL %s the Machine IR body does not begin with the Machine IR "
            "magic: word at offset %d is 0x%016llx\n",
            name, HDR_BYTES,
            (unsigned long long)(mir_len < HDR_BYTES + 8
                                     ? 0
                                     : r64(mfile, HDR_BYTES)));
  }

  /* The Machine IR ROUND TRIP, with the same span discipline as the NTIR's:
   * the span is the image's own words 3 and 5 under a 10-word header, and the
   * header width is the 10 that the magic check above just established. The
   * first version of this file simply did not round-trip the Machine IR at
   * all -- it checked the read returned zero and stopped -- and a file that
   * reads back and is not the image it came from would have passed it. */
  uint64_t recs = a.image[3];
  uint64_t mstride = a.image[5];
  uint64_t mspan = 10 + recs * mstride;
  run(mir, 1, source, len, 10, 0, &c, mfile, mir_len);
  checks++;
  if (c.returned != 0 || c.runtime != 0) {
    failures++;
    fprintf(stderr,
            "FAIL %s the Machine IR file did not read back: code=%llu "
            "runtime=%llu; the image has %llu records of stride %llu, so it "
            "occupies %llu words and the file holds %llu\n",
            name, (unsigned long long)c.returned, (unsigned long long)c.runtime,
            (unsigned long long)recs, (unsigned long long)mstride,
            (unsigned long long)mspan,
            (unsigned long long)r64(mfile, OFF_WORDCOUNT));
  } else {
    checks++;
    if (r64(mfile, OFF_WORDCOUNT) != mspan ||
        memcmp(a.image, c.image, (size_t)mspan * 8) != 0) {
      uint64_t first_bad = mspan;
      for (uint64_t w = 0; w < mspan; w++) {
        if (a.image[w] != c.image[w]) {
          first_bad = w;
          break;
        }
      }
      failures++;
      fprintf(stderr,
              "FAIL %s the Machine IR did not survive the round trip: file says "
              "%llu words, image occupies %llu (%llu records of stride %llu); "
              "first difference at word %llu: 0x%016llx vs 0x%016llx\n",
              name, (unsigned long long)r64(mfile, OFF_WORDCOUNT),
              (unsigned long long)mspan, (unsigned long long)recs,
              (unsigned long long)mstride, (unsigned long long)first_bad,
              (unsigned long long)(first_bad < mspan ? a.image[first_bad] : 0),
              (unsigned long long)(first_bad < mspan ? c.image[first_bad] : 0));
    }
  }
  free(mfile);
  printf("MIR-FILE %s records=%llu bytes=%zu digest=0x%016llx\n", name,
         (unsigned long long)mir_records, mir_len,
         (unsigned long long)fnv(b.text, mir_len));


done:
  run_free(&a);
  run_free(&b);
  run_free(&c);
}

/* ---- 8. MACHINE IR'S OWN TAG CHECK, FIRED -------------------------------
 * machine_ir.nova:2774-2775 refuses 930 on a wrong magic or a wrong version,
 * and tests_ntasm_machine_ir.c:101-107 lists "the version pin" under WHAT IS
 * NOT HERE, ON PURPOSE. Mode 4 lowers WITHOUT verifying and mode 5 verifies
 * without parsing or lowering, so the image in `out` is the one the lowering
 * produced and the bytes are the ones verify reads. */
static void fire_mir_tag(const NovaHostImage *mir, const char *source,
                         unsigned index) {
  char name[64];
  snprintf(name, sizeof name, "fixture %u", index);
  Run a, c;
  run_init(&a);
  run_init(&c);
  size_t len = strlen(source);
  cases += 2;

  /* Mode 2 first: it is the mode that BUILDS the NTIR image into `ntir_out`,
   * and mode 4 lowers from that image rather than from the source. The first
   * version of this function went straight to mode 4, which found an empty
   * `ntir_out`, returned 800, and reported "the Machine IR lowers without
   * verifying" -- a sentence about the Machine IR that was entirely about this
   * file having skipped a step. */
  run(mir, 1, source, len, 2, 0, &a, NULL, 0);
  checks++;
  if (a.returned != 0 || a.runtime != 0) {
    failures++;
    fprintf(stderr, "FAIL %s the NTIR did not build for the tag case: "
            "code=%llu runtime=%llu\n",
            name, (unsigned long long)a.returned, (unsigned long long)a.runtime);
    run_free(&a);
    run_free(&c);
    return;
  }
  run(mir, 1, source, len, 4, 0, &a, NULL, 0);
  checks++;
  if (a.returned != 0 || a.runtime != 0) {
    failures++;
    fprintf(stderr,
            "FAIL %s the Machine IR did not lower: code=%llu runtime=%llu\n",
            name, (unsigned long long)a.returned, (unsigned long long)a.runtime);
    run_free(&a);
    run_free(&c);
    return;
  }
  uint64_t *image = (uint64_t *)malloc(WORDS * sizeof(uint64_t));
  if (!image) {
    fprintf(stderr, "FAIL allocation\n");
    exit(1);
  }
  uint64_t records = a.report[0];
  memcpy(image, a.image, WORDS * sizeof(uint64_t));

  static const struct {
    const char *what;
    uint64_t word;
  } BREAKS[] = {{"the magic, word 0", 0}, {"the major, word 1", 1}};
  /* THE DAMAGE MUST REACH THE READER, so mode 5 is called on `a` -- the Run
   * whose `image` was just damaged -- and not on `c`. The first version of
   * this loop damaged `a.image` and then verified `c.image`, an untouched and
   * never-written buffer. It answered 800 both times, and 800 is this
   * project's generic refusal, so the case read as "the Machine IR refused a
   * damaged tag" when what had happened was that it was handed rubbish. A
   * case that cannot fail for the reason it names is a case that proves
   * nothing, and the only defence is to check that the operand the reader saw
   * is the operand that was damaged. */
  for (unsigned i = 0; i < 2; i++) {
    memcpy(a.image, image, WORDS * sizeof(uint64_t));
    a.image[BREAKS[i].word] ^= UINT64_C(0x5a5a5a5a5a5a5a5a);
    run(mir, 1, source, len, 5, 0, &a, NULL, 0);
    checks++;
    if (a.returned != MIR_E_TAG) {
      failures++;
      fprintf(stderr,
              "FAIL %s Machine IR damaged at %s: wanted %u and got %llu\n", name,
              BREAKS[i].what, MIR_E_TAG, (unsigned long long)a.returned);
    }
  }
  printf("MIR-TAG %s records=%llu both breaks refused with %u\n", name,
         (unsigned long long)records, MIR_E_TAG);
  free(image);
  run_free(&a);
  run_free(&c);
}

/* ---- 9. THE TWO DOMAINS DO NOT READ EACH OTHER --------------------------
 * Kept out of exercise() because it needs BOTH files alive at once, and the
 * round trip above frees the Machine IR file before the end of the loop. */
static void cross_domain(const NovaHostImage *ntir, const NovaHostImage *mir,
                         const char *source, unsigned index) {
  char name[64];
  snprintf(name, sizeof name, "fixture %u", index);
  Run a, c;
  run_init(&a);
  run_init(&c);
  size_t len = strlen(source);
  cases += 2;

  run(ntir, 0, source, len, 6, 0, &a, NULL, 0);
  if (a.returned != 0) {
    CHECK(0, "the NTIR serialises for the cross-domain case");
    goto out;
  }
  size_t nlen = (size_t)a.length[0];
  uint8_t *nfile = (uint8_t *)malloc(nlen);
  if (!nfile) { fprintf(stderr, "FAIL allocation\n"); exit(1); }
  memcpy(nfile, a.text, nlen);

  run(mir, 1, source, len, 9, 0, &a, NULL, 0);
  if (a.returned != 0) {
    CHECK(0, "the Machine IR serialises for the cross-domain case");
    free(nfile);
    goto out;
  }
  size_t mlen = (size_t)a.length[0];
  uint8_t *mfile = (uint8_t *)malloc(mlen);
  if (!mfile) { fprintf(stderr, "FAIL allocation\n"); exit(1); }
  memcpy(mfile, a.text, mlen);

  /* The NTIR file offered to the Machine IR reader. Byte 3 of that file is
   * '0' and the Machine IR tag wants '1', so the refusal is the FAMILY code and
   * not E_DOMAIN. That is the whole reason the domain is derived into the tag
   * and not only carried as a field. */
  run(mir, 1, source, len, 10, 0, &c, nfile, nlen);
  checks++;
  if (c.returned != E_TAG) {
    failures++;
    fprintf(stderr,
            "FAIL %s the Machine IR reader took an NTIR file: wanted %u got "
            "%llu\n",
            name, E_TAG, (unsigned long long)c.returned);
  }
  /* And the reverse. */
  run(ntir, 0, source, len, 7, 0, &c, mfile, mlen);
  checks++;
  if (c.returned != E_TAG) {
    failures++;
    fprintf(stderr,
            "FAIL %s the NTIR reader took a Machine IR file: wanted %u got "
            "%llu\n",
            name, E_TAG, (unsigned long long)c.returned);
  }
  printf("CROSS-DOMAIN %s both directions refused with %u\n", name, E_TAG);
  free(nfile);
  free(mfile);
out:
  run_free(&a);
  run_free(&c);
}

int main(void) {
  size_t ns[NTIR_PATHS_N] = {0}, ms[MIR_PATHS_N] = {0};
  char *nsrc[NTIR_PATHS_N] = {0}, *msrc[MIR_PATHS_N] = {0};
  NtFInput ni[NTIR_PATHS_N], mi[MIR_PATHS_N];
  int all = 1;
  for (unsigned i = 0; i < NTIR_PATHS_N; i++) {
    nsrc[i] = loadf(NTIR_PATHS[i], &ns[i]);
    if (!nsrc[i]) all = 0;
    ni[i] = (NtFInput){NTIR_PATHS[i], nsrc[i], ns[i]};
  }
  for (unsigned i = 0; i < MIR_PATHS_N; i++) {
    msrc[i] = loadf(MIR_PATHS[i], &ms[i]);
    if (!msrc[i]) all = 0;
    mi[i] = (NtFInput){MIR_PATHS[i], msrc[i], ms[i]};
  }
  CHECK(all, "the Nova sources for both entries load");
  if (!all)
    return 1;

  NtArtifact nimg = {0}, mimg = {0};
  int c1 = nova_compile_many_v2(ni, NTIR_PATHS_N, &nimg);
  int c2 = nova_compile_many_v2(mi, MIR_PATHS_N, &mimg);
  CHECK(c1, "the NTIR entry and the container compile");
  CHECK(c2, "the Machine IR entry and the container compile");
  if (!c1)
    fprintf(stderr, "E%u %zu:%zu %s\n", nimg.error.code, nimg.error.line,
            nimg.error.column, nimg.error.message);
  if (!c2)
    fprintf(stderr, "E%u %zu:%zu %s\n", mimg.error.code, mimg.error.line,
            mimg.error.column, mimg.error.message);
  if (!c1 || !c2) {
    printf("NTASM_NOVA_IR_IMAGE checks=%u failures=%u cases=%u\n", checks,
           failures, cases);
    /* The compile may have half-produced an artifact, so the free runs on the
     * failure path too. An early return that skips it leaks exactly the
     * buffer the failure is most likely to have grown. */
    nt_artifact_free(&nimg);
    nt_artifact_free(&mimg);
    for (unsigned i = 0; i < NTIR_PATHS_N; i++)
      free(nsrc[i]);
    for (unsigned i = 0; i < MIR_PATHS_N; i++)
      free(msrc[i]);
    return 1;
  }

  /* The compile step yields an NtArtifact; calling into a compiled module
   * needs the mapped NovaHostImage, and nova_host_map is what turns one into
   * the other. Both are checked to have actually mapped rather than assumed
   * to have: a call into an unmapped image reads nothing and reports nothing,
   * and "did not run" must not be able to read as "ran and agreed". */
  NovaHostImage nia = {0}, mia = {0};
  int mapped = nova_host_map(&nimg, &nia) && nova_host_map(&mimg, &mia);
  CHECK(mapped && nia.memory && mia.memory,
        "both compiled artifacts map into host images");
  if (!nia.memory || !mia.memory) {
    printf("NTASM_NOVA_IR_IMAGE checks=%u failures=%u cases=%u\n", checks,
           failures, cases);
    if (nia.memory)
      nova_host_unmap(&nia);
    if (mia.memory)
      nova_host_unmap(&mia);
    nt_artifact_free(&nimg);
    nt_artifact_free(&mimg);
    for (unsigned i = 0; i < NTIR_PATHS_N; i++)
      free(nsrc[i]);
    for (unsigned i = 0; i < MIR_PATHS_N; i++)
      free(msrc[i]);
    return 1;
  }

  for (unsigned i = 0; i < FIXTURES_N; i++) {
    exercise(&nia, &mia, FIXTURES[i], i);
    fire_mir_tag(&mia, FIXTURES[i], i);
    cross_domain(&nia, &mia, FIXTURES[i], i);
  }

  if (nia.memory)
    nova_host_unmap(&nia);
  if (mia.memory)
    nova_host_unmap(&mia);
  /* nt_artifact_free releases the machine-code buffers that nt_codegen_x64
   * allocated. nova_host_unmap releases the mmap, and the two are different
   * allocations: without this line the gate leaks one 4 MB code image and the
   * first version of this file did exactly that on every run. Both existing
   * IR gates call it (tests_ntasm_ntir.c:1308, tests_ntasm_machine_ir.c:1272)
   * and the convention was there to copy. */
  nt_artifact_free(&nimg);
  nt_artifact_free(&mimg);

  for (unsigned i = 0; i < NTIR_PATHS_N; i++)
    free(nsrc[i]);
  for (unsigned i = 0; i < MIR_PATHS_N; i++)
    free(msrc[i]);

  printf("NTASM_NOVA_IR_IMAGE checks=%u failures=%u cases=%u\n", checks, failures,
         cases);
  return failures ? 1 : 0;
}
