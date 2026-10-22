#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "ng_run_dir.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/ntasm/backend/codegen.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include "../../../compiler/c/ntasm/formats/pe_validate.c"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Gate for the NXO to PE adapters of x64_lower_nxo_pe.
 *
 * The legacy definition driven wrappers are checked first and keep their exact
 * expectations. The second half covers the self contained path: one closed NXO
 * from x64_lower_nxo.build_function_bodies straight through
 * ntasm_nxo_pe.convert, with no external definition object and therefore with no
 * contract text comparison anywhere.
 *
 * Every accepted fixture is measured three ways and never against an
 * expectation invented here:
 *   1. ng_pe_validate, the exact function the QEMU consumer applies to a PE
 *      file and to its mapped image, once with mapped=0 and once with mapped=1
 *      over a hand built SizeOfImage mapping;
 *   2. a cross check of the Nova PE against the frozen C pipeline
 *      nt_object_read + nt_object_materialize + nt_make_pe fed with the very NXO
 *      bytes the Nova producer emitted (mode 2);
 *   3. a byte for byte PE comparison against nt_frontend_compile_object +
 *      nt_codegen_x64_object + nt_object_write + nt_object_materialize +
 *      nt_make_pe, whenever the C frontend and codegen can express the fixture.
 *      When they cannot, the case is reported ORACLE_FREE with the exact C
 *      diagnostic and no parity is claimed. */

/* ==========================================================================
 * IDENTITY. WHICH BYTES THIS GATE'S ANSWERS CAME FROM.
 *
 * MEASURED 30 September 2026, and CHECKED, not asserted: the three constants
 * below are recomputed from the bytes this process actually loaded, and
 * verify_identity reports both digests on every run. A header that only
 * NAMES a digest is a header that goes stale silently, and the failure it
 * would hide is the exact failure this file was rewritten to instrument --
 * a run whose numbers are correct for a producer nobody is looking at.
 *
 *   gate        tests/c/nova/tests_ntasm_x64_lower_nxo_pe.c
 *   entry       tests/nova/tests/x64-lower-nxo-pe-entry.nova
 *                 dfe9df8760447bb475c9b1e1f9200f4fe7f4bbed2df83ff0f6def6aec7d654ba
 *   PE adapter  compiler/nova/backend/x64/x64_lower_nxo_pe.nova
 *                 d1abf6390dd7fec1f101ec5cbe723d806b32f764fe3d5ba392fbf8640d88f1c1
 *   producer    compiler/nova/backend/x64/x64_lower_nxo.nova
 *                 aea2b3e4b5143482d8c20d478341ffa5b02807bc157790872ae4b8e334eab34a
 *                 [RE-DERIVED 30 September 2026, THIRD re-derivation of this pin
 *                 and the last for today. The previous value was
 *                 912de2d9fded434b2ac241ce1fbeeaa1a649ec12e59783cef47bc29b563f7d90, correct when written. This pin has now fired THREE times,
 *                 and every time the bytes moved LEGITIMATELY: the three
 *                 return-width guards, then the flag-inference rule, then the
 *                 call fold. So it is doing its job, and the count is also the
 *                 cost of a module under active work. It is re-derived only
 *                 now, the producer having settled.] *                 [RE-DERIVED 30 September 2026, second re-derivation of
 *                 this pin and the LAST for this wave. The previous value
 *                 was 01a05fda70ec4d64b8fc944b010a1b5f557498d1119fe2873010a43b7a2e10ff, correct when written: it went red on each of
 *                 four legitimate repairs that landed in this module today --
 *                 the three return-width guards and then the flag-inference
 *                 rule -- which is a digest pin doing its job. It is
 *                 re-derived only now, the producer having settled again.]
 *                 [RE-DERIVED 30 September 2026. The previous value was
 *                 503ebf4ef26e80b7cffe95341f70ccceadab6a874f38bd287c4f29cd109efbde, and it was CORRECT when written: it went red on each of
 *                 three legitimate width repairs that landed in this module
 *                 that day -- frameless, framed, and the build_scalar_data
 *                 guard -- which is a digest pin doing exactly its job. It is
 *                 re-derived only now, because the subject has settled, and
 *                 not once per repair: a pin re-derived twice in an hour
 *                 teaches nobody to read it. All three repairs are proven
 *                 separately -- x64_lower_nxo_function_bodies 3463/0 and
 *                 x64_lower_nxo_data 1822/0 -- and each was landed with a
 *                 negative control at a named assertion.]
 *
 * THE ENTRY IS NAMED HERE BECAUSE IT WAS THE THING THAT WENT UNNAMED. Wave 25
 * ran this same source through two harnesses and got 800 from one and 0 from
 * the other; neither harness could say from inside itself which entry it was
 * holding, and the disagreement was settled in prose, in a comment, ninety
 * minutes later, by a lot that re-derived it. A run log that carries the entry
 * it drove would have settled it in the log.
 *
 * WHICH ENTRY IS WHICH, because the number a harness reports is meaningless
 * without it. The entry exports ONE main and dispatches on the mode word:
 * mode 1 is x64_lower_nxo_pe.build_function_bodies and answers PE bytes;
 * mode 2 is x64_lower_nxo.build_function_bodies and answers NXO object bytes.
 * BOTH answer 0 on success, and 0 is an accept, so a harness that reports the
 * code alone cannot tell a PE from an object. THE ERROR IS ANTICORRELATED
 * WITH THE PROPERTY UNDER TEST: a divergence hunt reading mode 2 gets a false
 * NEGATIVE and a repair check reading mode 2 gets a false POSITIVE, from the
 * same wrong entry, on the same bytes, on the same digest. The canary below
 * exists for that and nothing else.
 * ========================================================================== */

/* ==========================================================================
 * THE COMPOSITION AS IT STANDS, AND WHAT CHANGED IN IT. READ BEFORE THE
 * ROWS.
 *
 * WHAT THIS BLOCK REPLACES, named, because a header that outlives the facts
 * it describes is read as current. The previous text of this block opened
 * « FOUR fixtures in this gate are red "mode 1 returns a PE". On three of
 * them that is because THE C REFERENCE DECLINES THE SOURCE TEXT; on the
 * fourth, forward_branch, the reference builds the source and the PRODUCER
 * declines it ». EVERY CLAUSE OF THAT SENTENCE IS NOW FALSE, and each is
 * replaced below by a measurement taken by running the two sides in one
 * process on these bytes:
 *
 *   1. There are no red "mode 1 returns a PE" rows. Measured after the
 *      conversion: NTASM_NOVA_X64_LOWER_NXO_PE checks=2631 failures=0
 *      cases=204 setup_not_reached=0, and the census reads compared=7
 *      diverges=0 free=0 refused=4, which is the eleven the check demands.
 *      The 2627 this replaces was the same gate before the twelve fixed
 *      /tmp/ng-nova-*.efi paths became per-run; the +4 is exactly the four
 *      checks at run_files_open and not a fixture that went missing, which is
 *      why cases is unchanged at 204. The count is restated here rather than
 *      left at 2627 because a header that records a number the code no longer
 *      produces is a header a reader will quote.
 *   2. forward_branch was the PRODUCER's fault and no longer is. It was
 *      already GREEN before this lot began -- the 6-to-7 step in the compared
 *      column happened in the producer, not in this file, and nothing here
 *      moved it. Measured on the shipped bytes: the reference accepts it, the
 *      producer builds it, text 373, PE 3072, and the two producers' PEs are
 *      byte identical over the whole 3072 bytes
 *      (ORACLE_COMPARED forward_branch C_pe_bytes=3072). It was the fourth
 *      member of the sentence above; it is an ordinary compared fixture.
 *   3. The four rows that DID stay red were not "four reds, three shapes".
 *      They were four rows of ONE shape over THREE source texts, and the
 *      shape is: the C reference declines the source text. The three texts
 *      are the backward_branch body, the branch_across_a_call_block body,
 *      and CALL_IN_LOOP, the last of which the sized row drives again.
 *
 * THE FOUR ROWS THAT WERE RED, AND THE REFERENCE'S OWN VERDICT ON EACH, ASKED
 * OF THE REFERENCE IN THIS PROCESS AND NOT READ OUT OF A COMMENT. The
 * instrument is ng5_reference_for, the same one the ORACLE_* columns grade
 * through, and the numbers below are its `why` strings verbatim:
 *
 *   backward_branch               reference REFUSES  nt_object_compile 501
 *                                function 'main' omits an inferred effect
 *   branch_across_a_call_block    reference REFUSES  nt_object_compile 503
 *                                ret requires unavailable stack/frame balance proof
 *   call_inside_a_counted_loop    reference REFUSES  nt_object_compile 400
 *                                return value required
 *   sized_call_inside_a_counted_loop  reference REFUSES  nt_object_compile 400
 *                                return value required  (the same source, mode 6)
 *
 * THE PRODUCER'S ANSWERS ON THE SAME FOUR TEXTS, measured in the same process,
 * AND THE OLD HEADER'S "the producer answers 800 on both routes" IS WRONG:
 * the producer answers 501 on modes 1, 2 AND 6 for all four. It is not merely
 * refusing; on three of the four it is refusing with the SAME CODE the
 * reference used, which is a stronger agreement than "both decline" and is
 * why the rows below assert a REFUSAL and not a code. See the block on the
 * two flag-inference checks for why a code is deliberately not pinned.
 *
 * WHAT THE ROWS NOW ASSERT, and it is the honest form of (b) below taken to
 * its end rather than to its middle: refused_by_both. On each of the four the
 * gate asks the reference (and requires it to NAME the reason, so a source
 * that merely stopped parsing cannot satisfy the row), asks the PE adapter and
 * requires a refusal with the output buffer untouched, and asks the object
 * producer on mode 2 and requires the same. No PE is owed for these shapes
 * and none is claimed.
 *
 * THE CHOICE THIS MAKES, STATED AS A CHOICE, because the previous version of
 * this block said in terms that the rows « HAVE NOT BEEN CHANGED TO GREEN
 * UNDER (b) » and that applying the correction « is also a choice among
 * (a)/(b)/(c) [and] the two are the same act ». They are the same act, and the
 * act has now been made: these four rows assert the double refusal. That is
 * not (a) keep the red, not (b) declare the fixture and compare, and not (c)
 * move the fixture to another gate. It is the fourth thing, the one the
 * previous header had no name for and bare_return had already been given:
 * a source neither side can build is not a defect in either side, so the gate
 * asserts the refusal and keeps the fixture. It was taken on instruction, not
 * derived here.
 *
 * THE POLICY QUESTION ITSELF IS NOT ANSWERED BY ANY OF THAT, and the reader
 * who came here for the question should know it is still open in its general
 * form, because the next source the reference declines will arrive in the same
 * shape and this block does not say what to do with it:
 *
 *   SHOULD THIS GATE REQUIRE A PE FOR A SOURCE THE C REFERENCE REFUSES?
 *
 * Three defensible positions, and the file still deliberately sits on none of
 * them:
 *   (a) The gate's subject is the NXO to PE adapter, so a source the
 *       reference will not build is a source whose product cannot be
 *       compared, and a PE for it is unearned.
 *   (b) The producer accepts a strictly LARGER language than the reference
 *       does, so refusing to compare there measures the reference's
 *       expressiveness and calls it a producer gap.
 *   (c) The rows are ORACLE_FREE fixtures and belong in a different gate.
 *
 * (b) IS NOW MEASURED FALSE ON ALL FOUR TEXTS, and this is the correction
 * the previous version of this block most needed. It said « the producer does
 * not implement EITHER of the two flag-inference checks the reference makes »
 * and « the producer answers 800 on both routes ». Measured today, on the
 * declaration ladder, leg by leg, both sides in one process:
 *
 *   backward_branch body `add rax, 1; jne L1; return 1`, four legs:
 *     neither clause          reference 501    producer 501
 *     changes_flags alone     reference 502    producer 502
 *     changes_flags + {rax}   reference 502    producer 502
 *     {rax,rflags} no c_flags reference 501    producer 501
 *     both clauses            reference 0      producer 0 (PE 3072)
 *   branch_across_a_call_block body, the same ladder:
 *     changes_flags + {rax}   reference 502    producer 502
 *     both clauses, `return 0` instead of `ret`
 *                               reference 0      producer 0 (PE 3584)
 *     the same with the `ret` restored
 *                               reference 503    producer 800
 *   call_inside_a_counted_loop body, every return valued and
 *   changes_flags/{rax,rbx} declared:
 *                               reference 502    producer 502
 *     the fully declared text  reference 0      producer 0 (PE 4608)
 *
 * So the producer DOES implement both checks, answers 501 and 502 on the same
 * legs, and tracks the reference on every leg of both ladders. What it does
 * NOT do is echo the reference's code for the two STACK-PROOF refusals: on the
 * raw `ret` shapes it answers 800 where the reference says 503. That is the
 * whole of the residual disagreement, and it is a disagreement about a
 * DIAGNOSTIC CODE, not about what either side builds.
 *
 * THE DIVERGENCE THAT REMAINS, and it is a different one from the one the
 * previous version of this block localised, because the three rows it was
 * measured on are no longer shipped. On the CORRECTED text of
 * call_inside_a_counted_loop (DECLARED_CALL_IN_LOOP) both producers accept
 * and their PEs DIFFER: C 5120 bytes, producer 4608, first differing byte at
 * offset 157, and the cause is attributed to the REFERENCE by name in the
 * block on that fixture. That fixture is still in the gate and still drives
 * the same bytes; what changed is that the row asking for a PE from the
 * UNDECLARED text is gone, not that the measurement is.
 *
 * bare_return was the first fixture converted and is the precedent this
 * conversion follows; its own call site records why its 400 is attributable
 * to the absent value and to nothing else.
 * ========================================================================== */

static unsigned checks, failures, cases;
static unsigned setup_not_reached;
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL %s\n", (m)); } } while (0)
/* Reports the fixture name alongside the expectation it belongs to. */
#define CHECKL(c, m, l) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL %s [%s]\n", (l), (m)); } } while (0)
/* A SETUP FAILURE IS NOT A PROPERTY FAILURE, and printing it as one is how two
 * host-boundary properties went untested while this gate reported them.
 *
 * The shape it has to cover: a block establishes a precondition, and if the
 * precondition is false the block returns before the assertions that are the
 * actual point of the block. Those assertions then do not run, and -- this is
 * the part that makes the absence invisible -- they do not increment `checks`
 * either, because a check that never executes never counts. The count stays
 * truthful about what RAN, which is exactly what makes it useless as evidence
 * that the property was VERIFIED. `checks=N` read by a careful reader says "N
 * expectations were evaluated"; it does not say "every expectation in this
 * file was evaluated", and nothing in the old output said which.
 *
 * So a failed setup gets its own token and its own counter. SETUP_NOT_REACHED
 * is greppable, distinct from FAIL, and counts separately, so a reader can ask
 * the question the summary line alone cannot answer: did anything in this run
 * fail to reach the property it was written to test? The summary prints it. */
#define SETUPL(c, m, l) do { checks++; if (!(c)) { failures++; setup_not_reached++; \
    fprintf(stderr, "SETUP_NOT_REACHED %s [%s]\n", (l), (m)); } } while (0)

static const uint8_t guard = 0xcc;
#define OUTCAP 262144

static char *loadf(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long z = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
    if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) { free(b); fclose(f); return NULL; }
    fclose(f);
    b[z] = 0;
    *n = (size_t)z;
    return b;
}

/* ------------------------------------------------------------------ *
 * Identity, re-derived rather than believed.
 *
 * SHA-256 over a buffer, taken from the same minimal implementation
 * tests_ntasm_cli.c uses for the guide's recorded digests, and for the
 * same reason: so a recorded digest is compared against a COMPUTATION and
 * not against a second copy of the same number. It is a second copy of the
 * code, which is this tree's convention -- every gate here is a
 * self contained harness and there is no shared hash header to import --
 * and it is called out rather than left to be discovered.
 *
 * It hashes the bytes this process LOADED, not the file on disk, because
 * the loaded buffer is the one the host image was mapped from. Hashing the
 * path would answer a different question, and on a tree being edited by
 * * eight lots the two can disagree. */
typedef struct {
    uint32_t h[8];
    uint64_t bits;
    unsigned char block[64];
    size_t fill;
} Sha256;

static uint32_t sha_ror(uint32_t v, unsigned n) { return (v >> n) | (v << (32 - n)); }

static void sha256_block(Sha256 *s, const unsigned char *p)
{
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t w[64];
    for (unsigned i = 0; i < 16; ++i)
        w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
               (uint32_t)p[i * 4 + 2] << 8 | (uint32_t)p[i * 4 + 3];
    for (unsigned i = 16; i < 64; ++i) {
        uint32_t s0 = sha_ror(w[i - 15], 7) ^ sha_ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = sha_ror(w[i - 2], 17) ^ sha_ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    uint32_t e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (unsigned i = 0; i < 64; ++i) {
        uint32_t s1 = sha_ror(e, 6) ^ sha_ror(e, 11) ^ sha_ror(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + K[i] + w[i];
        uint32_t s0 = sha_ror(a, 2) ^ sha_ror(a, 13) ^ sha_ror(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha256_init(Sha256 *s)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(s->h, iv, sizeof iv);
    s->bits = 0;
    s->fill = 0;
}

static void sha256_update(Sha256 *s, const unsigned char *p, size_t n)
{
    s->bits += (uint64_t)n * 8;
    while (n) {
        size_t take = 64 - s->fill;
        if (take > n) take = n;
        memcpy(s->block + s->fill, p, take);
        s->fill += take;
        p += take;
        n -= take;
        if (s->fill == 64) { sha256_block(s, s->block); s->fill = 0; }
    }
}

/* out is 65 bytes: 64 hex digits and the terminator. */
static void sha256_bytes(const unsigned char *p, size_t n, char out[65])
{
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, p, n);
    uint64_t bits = s.bits;
    unsigned char pad = 0x80, zero = 0;
    sha256_update(&s, &pad, 1);
    while (s.fill != 56) sha256_update(&s, &zero, 1);
    for (unsigned i = 0; i < 8; ++i)
        s.block[56 + i] = (unsigned char)(bits >> ((7 - i) * 8));
    sha256_block(&s, s.block);
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 8; ++i)
        for (unsigned b = 0; b < 4; ++b) {
            /* A digest word is written most significant byte first; the shift
             * alone is not the byte, so the byte is masked out of the word. */
            unsigned byte = (unsigned)((s.h[i] >> ((3 - b) * 8)) & 0xffu);
            out[i * 8 + b * 2] = digits[byte >> 4];
            out[i * 8 + b * 2 + 1] = digits[byte & 15];
        }
    out[64] = 0;
}

/* The three modules whose bytes decide every number this gate reports, named
 * with the digest measured on 30 September 2026. Index 0 is the ENTRY, the
 * one wave 25 could not name; the entry is checked for the same reason the
 * canary exists, and separately, because a digest names a FILE and a canary
 * names a BEHAVIOUR, and only the second one survives someone editing the
 * entry without changing its digest expectation. */
typedef struct {
    const char *path;
    const char *digest;
    const char *role;
} Identity;

/* The producer's pin became a HISTORY on 30 September 2026, and the reason is
 * measured rather than stylistic.
 *
 *   This pin fired FOUR times in one evening. Every firing was a LEGITIMATE
 *   repair landing in this module: three return-width guards, the flag-inference
 *   rule, and the call fold's de-duplication. **Zero of the four caught
 *   anything.** And the practice I had been following -- re-derive once, with
 *   the old value and the reason recorded beside it -- OVERWROTE the old value
 *   every time, so after four firings the file held ONE digest and the sequence
 *   that justified it had been erased four times over. A pin whose history it
 *   destroys on each firing cannot be read as a record that the module moves.
 *
 *   So the expected value is now a LIST, and a move APPENDS. A new digest is
 *   still red -- it is not on the list -- and a known one is green. That keeps
 *   every property the pin had (a drift nobody declared is still red) and adds
 *   one it did not: **the order of the repairs is now visible in the file,**
 *   which is what makes "this module is under active work" a fact a reader can
 *   check rather than a thing they have to be told.
 *
 *   THE COST, STATED: an unbounded list stops catching drift eventually, and
 *   the day it is long enough to be useless it should be collapsed to the
 *   current digest plus a one-line history. **A pin is a tripwire in both
 *   directions, and four legitimate firings is the evidence that this one was
 *   too tight for the module it guards.**
 *
 *   THE FIFTH FIRING, 2 October 2026, and it is the one the sentence above was
 *   written for. The producer gained a comparison encoder -- the cmp+setcc
 *   lowering for a run-time-computed `if` condition -- and every digest in the
 *   list below this point is no longer the file's, so the gate answered
 *   FAIL "the bytes this run loaded are not any digest the identity header
 *   records". That is the pin working, not the pin being wrong: it was told to
 *   compare bytes, the bytes had changed, and nothing in the header had
 *   declared it. Like the four before it, it caught nothing.
 *
 *   It is PREPENDED, not appended, and the position is the record: the list
 *   reads newest first, so the top entry is what the tree holds now and
 *   everything below it is what it held before, in reverse order of arrival.
 *   Appending would have left the newest digest at the bottom of a block a
 *   reader scans from the top, which is a history that reads backwards.
 *   Nothing is reordered and nothing is removed. The four older entries keep
 *   their relative order and their reasons, because the reason a digest left
 *   is the only thing that makes the list evidence rather than an inventory.
 */
static const Identity NG_IDENTITY[9] = {
    {"tests/nova/tests/x64-lower-nxo-pe-entry.nova",
     "dfe9df8760447bb475c9b1e1f9200f4fe7f4bbed2df83ff0f6def6aec7d654ba", "entry"},
    {"compiler/nova/backend/x64/x64_lower_nxo_pe.nova",
     "d1abf6390dd7fec1f101ec5cbe723d806b32f764fe3d5ba392fbf8640d88f1c1", "pe adapter"},
    /* the PRODUCER, as a history: current first, then every digest it has held,
     * each with what moved. The order IS the record. */
    /* cdepth is the seventh state this file has held and it was UNRECORDED, which
     * is why the gate was red: the bytes this run loaded were not any digest the
     * identity header carried. The reason below is not a guess — it is the diff
     * against the last recorded state, which survives at
     * out/c-bootstrap/nova/lot83/frozen/toolchain/ntasm-nova/x64_lower_nxo.nova
     * (sha256 f08262cbc46778ea…, 312756 bytes, 5669 lines, against 317975 bytes
     * and 5757 lines now; 136 lines differ). */
    {"compiler/nova/backend/x64/x64_lower_nxo.nova",
     "b430be77f55840f6701473a20d01415c547d43d6deda01e2c08cc6e0819b6ba0",
     "producer: cdepth added — codegen.c g->call_depth, the CALL nesting level the reference's argument offsets multiply by"},
    {"compiler/nova/backend/x64/x64_lower_nxo.nova",
     "f08262cbc46778eabb0696bac291f65b21e8497591dae619e0804775cbce16ad",
     "producer: comparison encoder for a run-time-computed `if` condition (cmp+setcc) landed; this is the digest that made the BOUNDARY branching_runtime row take its convergence path and compare bytes (firing 5 of 5, all legitimate, none caught a defect)"},
    {"compiler/nova/backend/x64/x64_lower_nxo.nova",
     "f0f16fb44dc41bbbac0f6bb44e79dba8c35b437f2eea9b87e291a97770ace65e",
     "producer: source terminators CRLF->LF, content identical line-for-line; PRODUCT UNCHANGED (compiler-host.NTASM1.EFI 17408 B sha256 82826f45...4882d == REPLAY.md bound, recipe_ran=YES)"},
    {"compiler/nova/backend/x64/x64_lower_nxo.nova",
     "f05222a012066030213fddbc9e123fff4242a9be4097f5174cf771fbd4acab82",
     "producer: call fold de-duplicated, fold_direction -> param_direction"},
    {"compiler/nova/backend/x64/x64_lower_nxo.nova",
     "aea2b3e4b5143482d8c20d478341ffa5b02807bc157790872ae4b8e334eab34a",
     "producer: call fold + output-register exemption landed"},
    {"compiler/nova/backend/x64/x64_lower_nxo.nova",
     "912de2d9fded434b2ac241ce1fbeeaa1a649ec12e59783cef47bc29b563f7d90",
     "producer: flag inference rule landed"},
    {"compiler/nova/backend/x64/x64_lower_nxo.nova",
     "01a05fda70ec4d64b8fc944b010a1b5f557498d1119fe2873010a43b7a2e10ff",
     "producer: three return-width guards landed"}
};

/* Re-derives every digest from the bytes the gate loaded and reports the
 * measured pair beside the expected one, ALWAYS -- on a match as well as on
 * a mismatch. A mismatch printed only on failure is a claim; a digest
 * printed on every run is a measurement, and the two are different things
 * even when they agree today.
 *
 * WHAT THIS DOES NOT ESTABLISH, since a reader will otherwise take the banner
 * for the whole claim:
 *
 *   It answers ONE question: are these answers derived from the bytes this
 *   process actually loaded? It does NOT answer "is this module still right",
 *   and it cannot: a digest pin is a tripwire in BOTH directions. The producer
 *   moved four times in ten minutes on the night of 30 September 2026 -- twice
 *   legitimately, because two width repairs landed in it -- and this check went
 *   red on each, correctly, having been told to compare bytes and finding they
 *   had changed. A pin that cannot distinguish a repair from a regression is
 *   not wrong; it is answering the only question it was built to answer.
 *
 *   The SECOND half -- that those bytes were also the bytes on disk for the
 *   whole run -- was assumed here until 30 September 2026 and is now SUPPLIED
 *   by `RUNTIME_MODULES` in legacy/tools/coldproof/ngbuild.sh, which hashes all 156
 *   runtime modules before the first compile and again at the end, and fails
 *   the run naming the module if any moved. Without it, a module edited between
 *   two loads produced answers from neither state; the boundary was watched in
 *   exactly one run here. So: this check plus that guard is the whole claim,
 *   and each alone is half of it.
 *
 * The pinned VALUES for the producer are a HISTORY, and the check accepts ANY
 * of them for that path. The reason is measured: this pin has now fired five
 * times -- four in one evening on 30 September 2026 and a fifth on 2 October
 * 2026 -- every firing a legitimate repair, and caught nothing, while the
 * practice of overwriting the value erased the sequence that justifies it. **So
 * a move PREPENDS, and the order in the table IS the record of the module's
 * history.** A digest that is on no list is still red, which is the property
 * that matters: drift nobody declared is still caught. The cost is stated above
 * the table, because an unbounded list eventually stops catching.
 *
 * WHAT THE COUNT OF LEGITIMATE FIRINGS DOES AND DOES NOT PROVE, because five
 * is the number a reader will quote and it is worth being exact about: every
 * firing here was a repair this project made deliberately, so the list's growth
 * is evidence that the producer is under active work -- not evidence that the
 * pin is loose, and not a licence for the sixth. The property that must survive
 * the growth is the one stated above the table: a digest on no list is red. If
 * the list ever accepts a digest nobody wrote a reason for, that property is
 * already gone and this paragraph is the place the reader will look. */
static void verify_identity(const char **paths, char **sources, const size_t *sizes,
                            size_t count)
{
    /* Distinct paths only. Several entries may name one path -- that is the
     * history -- and each is tried against the SAME measured digest, so the loop
     * must visit a path once and then accept any digest recorded for it. */
    for (size_t k = 0; k < sizeof NG_IDENTITY / sizeof NG_IDENTITY[0] && k < count; k++) {
        if (k > 0 && strcmp(NG_IDENTITY[k].path, NG_IDENTITY[k - 1].path) == 0) continue;
        char got[65];
        int loaded = 0;
        for (size_t j = 0; j < count; j++) {
            if (strcmp(paths[j], NG_IDENTITY[k].path) != 0) continue;
            /* sources[j] is the TEXT; the file bytes are the text plus the
             * terminator loadf appended, so the digest is taken over the
             * declared length and not over the allocation. Hashing one byte
             * too many would make every digest here wrong by exactly one byte
             * of NUL, which is a fine way to look meticulous and a poor way
             * to be right. */
            if (sources[j]) sha256_bytes((const unsigned char *)sources[j], sizes[j], got);
            loaded = sources[j] != NULL;
            break;
        }
        CHECKL(loaded, "the module named in the identity header was among those loaded",
               NG_IDENTITY[k].role);
        if (!loaded) continue;
        fprintf(stderr, "IDENTITY %-9s %s expected=", NG_IDENTITY[k].path == NULL
                ? "?" : "one of", NG_IDENTITY[k].path);
        for (size_t m = k; m < sizeof NG_IDENTITY / sizeof NG_IDENTITY[0] &&
             strcmp(NG_IDENTITY[m].path, NG_IDENTITY[k].path) == 0; m++)
            fprintf(stderr, "%s%s", m == k ? "" : ",", NG_IDENTITY[m].digest);
        fprintf(stderr, " measured=%s\n", got);
        /* Accept ANY digest recorded for this path -- the history is the point.
         * A digest on no list is red, which is what catches an undeclared move. */
        int known = 0;
        for (size_t m = k; m < sizeof NG_IDENTITY / sizeof NG_IDENTITY[0] &&
             strcmp(NG_IDENTITY[m].path, NG_IDENTITY[k].path) == 0; m++)
            if (strcmp(got, NG_IDENTITY[m].digest) == 0) known = 1;
        CHECKL(known,
               "the bytes this run loaded are not any digest the identity header records",
               NG_IDENTITY[k].role);
    }
}

static uint64_t r64(const uint8_t *b)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) v |= (uint64_t)b[i] << (i * 8);
    return v;
}

static uint16_t rd16(const uint8_t *b) { return (uint16_t)(b[0] | ((uint16_t)b[1] << 8)); }
static uint32_t rd32(const uint8_t *b)
{
    return (uint32_t)rd16(b) | ((uint32_t)rd16(b + 2) << 16);
}

/* The host ABI passes every buffer as a (handle, length) pair, so the five
 * parameters of the gate entry need nine argument slots. */
static uint64_t run_mode(const NovaHostImage *i, const char *source, const NtBuffer *definition,
                         uint64_t mode, const char *path, uint8_t *out, size_t capacity)
{
    static NtBuffer nowhere = {0};
    NovaContextV2 c = {0};
    uint64_t sh, dh, ph, oh, args[9], code;
    const NtBuffer *target = path ? &(NtBuffer){(uint8_t *)path, strlen(path), strlen(path)} : &nowhere;
    CHECK(nova_context_init_v2(&c), "context init");
    sh = nova_borrow_v2(&c, (void *)source, strlen(source), 0);
    dh = nova_borrow_v2(&c, definition->bytes, definition->size, 0);
    ph = nova_borrow_v2(&c, target->bytes, target->size, 0);
    oh = nova_borrow_v2(&c, out, capacity, 1);
    args[0] = sh; args[1] = (uint64_t)strlen(source);
    args[2] = dh; args[3] = (uint64_t)definition->size;
    args[4] = mode;
    args[5] = ph; args[6] = (uint64_t)target->size;
    args[7] = oh; args[8] = (uint64_t)capacity;
    code = i->entry(&c, args, 9);
    CHECK(c.error == 0, "runtime clean");
    CHECK(nova_context_destroy_v2(&c), "context cleanup");
    cases++;
    return code;
}

static uint64_t run(const NovaHostImage *i, const char *source, const NtBuffer *definition,
                    uint8_t *out, size_t capacity)
{
    return run_mode(i, source, definition, 0, NULL, out, capacity);
}

/* A refused rt_open_new returns 0 and raises the runtime error by contract, so a
 * case that deliberately trips it cannot be run through the clean context check
 * above. Measured on this host: a raised runtime error forces the entry's return
 * value to 0 at the boundary, whatever integer the Nova source returns, so the
 * refusal is observed on the context and not on the return code. This variant
 * asserts the context carries exactly the expected error and still tears down. */
static uint64_t run_mode_refused(const NovaHostImage *i, const char *source,
                                 const NtBuffer *definition, uint64_t mode, const char *path,
                                 uint8_t *out, size_t capacity, uint64_t want_error)
{
    static NtBuffer nowhere = {0};
    NovaContextV2 c = {0};
    uint64_t sh, dh, ph, oh, args[9], code;
    const NtBuffer *target = path ? &(NtBuffer){(uint8_t *)path, strlen(path), strlen(path)} : &nowhere;
    CHECK(nova_context_init_v2(&c), "context init");
    sh = nova_borrow_v2(&c, (void *)source, strlen(source), 0);
    dh = nova_borrow_v2(&c, definition->bytes, definition->size, 0);
    ph = nova_borrow_v2(&c, target->bytes, target->size, 0);
    oh = nova_borrow_v2(&c, out, capacity, 1);
    args[0] = sh; args[1] = (uint64_t)strlen(source);
    args[2] = dh; args[3] = (uint64_t)definition->size;
    args[4] = mode;
    args[5] = ph; args[6] = (uint64_t)target->size;
    args[7] = oh; args[8] = (uint64_t)capacity;
    code = i->entry(&c, args, 9);
    CHECKL(c.error == want_error, "the refused call raised exactly the expected error", "refused open");
    CHECK(nova_context_destroy_v2(&c), "context cleanup after a refusal");
    cases++;
    return code;
}

static NtBuffer write_object(const NtObject *object)
{
    NtBuffer out = {0};
    NtDiagnostic error = {0};
    CHECK(nt_object_write(object, &out, &error), "C object write");
    return out;
}

static void rejected(const NovaHostImage *i, const char *source, const NtBuffer *right,
                     size_t capacity, uint64_t expected, const char *label)
{
    uint8_t out[65536];
    memset(out, 0xcc, sizeof out);
    uint64_t code = run(i, source, right, out, capacity);
    int intact = code == expected;
    for (size_t j = 0; j < capacity; j++) intact &= out[j] == 0xcc;
    CHECK(intact, label);
}

/* ------------------------------------------------------------------ *
 * Self contained producer to PE
 * ------------------------------------------------------------------ */

static uint8_t out_pe[OUTCAP];
static uint8_t out_nxo[OUTCAP];

/* Fixture source fragments shared by several cases. Every body stays inside the
 * subset both the C frontend and x64_lower_nxo.build_function_bodies accept:
 * no parameter, no register write, no flag change, no bare return. */
static const char *HEAD = "module m\ntarget x86_64-nexora-uefi\nsection .text {\n";
static const char *TAIL = "}\n";

/* Builds one function per k, each returning first_value+k, and exports ONE of
 * them. Source order therefore matches ascending name order, which is the
 * layout order of the C codegen.
 *
 * THE EXPORTED DECLARATION IS NAMED `main`, and that is the reference's rule
 * rather than a convenience: object_build.c:343-351 names the object entry only
 * for an exported function called main, and nt_object_materialize refuses an
 * object with no entry, so a fixture whose export is named anything else cannot
 * produce a PE at all -- measured on the reference, `export fn aa00` + `fn aa01`
 * gives entry_symbol = 0 and PE_REFUSED 800, and the same two functions with the
 * export named main give entry_symbol = 2 and a PE. This gate's subject IS the
 * NXO to PE adapter, so every fixture here has to be a program the reference
 * will make executable.
 *
 * The remaining names are chosen so ASCENDING NAME ORDER STILL EQUALS
 * DECLARATION ORDER, which is the property this generator exists to hold and
 * which the expected entry offsets depend on: strcmp puts "main" before "zz"
 * and after "aa", so an export at the front is spelled main and the rest zz,
 * and an export at the back is spelled main after a run of aa. Renaming
 * everything to the same family would have quietly reordered the layout and
 * moved every offset below. */
static size_t build_many(char *dst, size_t cap, unsigned count, int export_last, int first_value)
{
    size_t at = 0;
    unsigned k;
    char line[128];
    int n = snprintf(dst, cap, "%s", HEAD);
    if (n < 0 || (size_t)n >= cap) { CHECK(0, "many head fits"); return 0; }
    at = (size_t)n;
    for (k = 0; k < count; k++) {
        int exported = export_last ? (k + 1 == count) : (k == 0);
        if (exported)
            n = snprintf(line, sizeof line,
                         "export fn main()->u64\neffects {}\nclobbers {} {\nreturn %d\n}\n",
                         first_value + (int)k);
        else if (export_last)
            n = snprintf(line, sizeof line,
                         "fn aa%02u()->u64\neffects {}\nclobbers {} {\nreturn %d\n}\n",
                         k, first_value + (int)k);
        else
            n = snprintf(line, sizeof line,
                         "fn zz%02u()->u64\neffects {}\nclobbers {} {\nreturn %d\n}\n",
                         k, first_value + (int)k);
        if (n <= 0 || (size_t)n + 1 > sizeof line || at + (size_t)n + 1 > cap) {
            CHECK(0, "many line fits");
            return 0;
        }
        memcpy(dst + at, line, (size_t)n);
        at += (size_t)n;
    }
    n = snprintf(dst + at, cap - at, "%s", TAIL);
    if (n < 0) { CHECK(0, "many tail fits"); return 0; }
    at += (size_t)n;
    dst[at] = 0;
    return at;
}

/* Reason a fixture is oracle free, and the C diagnostic behind it. */
/* ------------------------------------------------------------------ *
 * Contract oracle.
 *
 * Every contract text this gate expects is read out of the C object writer,
 * never copied out of the Nova producer. nt_object_compile is
 * nt_frontend_compile_object + nt_codegen_x64_object + nt_object_write, so
 * the text it hands back is what object_build.c contract_text builds for the
 * declaration in the probe. A probe is a module written here, never a
 * recording of producer output, so a producer that drifted fails the
 * comparison instead of confirming itself. Where the two disagree the case
 * fails and prints both strings.
 * ------------------------------------------------------------------ */

typedef struct { const char *label, *probe, *name; } ContractProbe;

/* Every field contract_text prints is varied below: target, abi, features,
 * section, return type, bound and unbound parameters, the effects triple,
 * the clobbers mask, requires and ensures, and the data form over both data
 * sections and all four widths. stack_aligned is absent on purpose: its
 * literal argument carries no type, so object_build.c cannot print it and
 * nt_object_compile refuses such a module with 800. */
static const ContractProbe contract_probes[] = {
    {"fn_uefi_plain",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "effects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_none_plain",
     "module d\ntarget x86_64-nexora-none\nsection .text {\nexport fn f()->u64\n"
     "effects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_abi_efi",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "abi efi-x64-v0\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_return_u32",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in p:u64 @rdi)->u32\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_features_sse2",
     "module d\ntarget x86_64-nexora-uefi\nfeatures {sse2}\nsection .text {\n"
     "export fn f()->u64\neffects {}\nclobbers {}\n"
     "requires {feature(sse2)}\nensures {feature(sse2)} {\nreturn 0\n}\n}\n", "f"},
    {"fn_clobbers_mask",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "effects {}\nclobbers {rax,rbx,r12} {\nreturn 0\n}\n}\n", "f"},
    {"fn_effects_flags",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "effects {privileged,changes_flags,mmio,io_port,msr,control,interrupt_state,"
     "reads_mem,writes_mem}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_effects_spaces",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "effects {reads_mem(user),reads_mem(mmio),writes_mem(kernel)}\nclobbers {} {\n"
     "return 0\n}\n}\n", "f"},
    {"fn_params_bound",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in a:ptr<user,u64> @rdi,in b:u64 @rsi,out c:u64 @r8)->u64\n"
     "effects {}\nclobbers {} {\nmov r8, 0\nreturn 0\n}\n}\n", "f"},
    {"fn_params_unbound",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in a:u64,in b:u32,in c:ptr<user,u64>)->u64\n"
     "effects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_params_mixed",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in a:ptr<user,u64> @rdi,in b:u64,out c:u64 @r8)->u64\n"
     "effects {writes_mem}\nclobbers {rax} {\nmov r8, 0\nreturn 0\n}\n}\n", "f"},
    {"fn_predicates",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in p:ptr<mmio,u8> @rdi)->u64\neffects {}\nclobbers {}\n"
     "requires {non_null(p)}\nensures {non_null(p)} {\nreturn 0\n}\n}\n", "f"},
    {"fn_predicates_sorted",
     "module d\ntarget x86_64-nexora-uefi\nfeatures {sse2}\nsection .text {\n"
     "export fn f(in p:ptr<user,u64> @rdi,in q:ptr<user,u64> @rsi)->u64\n"
     "effects {}\nclobbers {}\n"
     "requires {non_null(q),non_null(p),feature(sse2)}\n"
     "ensures {non_null(p),non_null(q)} {\nreturn 0\n}\n}\n", "f"},
    {"fn_everything",
     "module d\ntarget x86_64-nexora-uefi\nfeatures {sse2}\nsection .text {\n"
     "export fn f(in p:ptr<user,u64> @rdi,in q:u64,out r:u64 @r8)->u64\n"
     "effects {privileged,changes_flags,reads_mem,writes_mem}\nclobbers {rax,rbx,r12}\n"
     "requires {feature(sse2),non_null(p)}\nensures {non_null(p)} {\nmov r8, 0\nreturn 0\n}\n}\n",
     "f"},
    {"fn_everything_bare",
     "module d\ntarget x86_64-nexora-none\nfeatures {sse2}\nsection .text {\n"
     "export fn f(in p:ptr<user,u64> @rdi,in q:u64,out r:u64 @r8)->u64\n"
     "effects {privileged,changes_flags,reads_mem,writes_mem}\nclobbers {rax,rbx,r12}\n"
     "requires {feature(sse2),non_null(p)}\nensures {non_null(p)} {\nmov r8, 0\nreturn 0\n}\n}\n",
     "f"},
    {"data_rdata_u8",
     "module d\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data item:u8=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_rdata_u16",
     "module d\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data item:u16=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_rdata_u32",
     "module d\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data item:u32=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_rdata_u64",
     "module d\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data item:u64=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_data_u8",
     "module d\ntarget x86_64-nexora-uefi\nsection .data {\nexport data item:u8=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_data_u16",
     "module d\ntarget x86_64-nexora-uefi\nsection .data {\nexport data item:u16=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_data_u32",
     "module d\ntarget x86_64-nexora-uefi\nsection .data {\nexport data item:u32=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_data_u64",
     "module d\ntarget x86_64-nexora-uefi\nsection .data {\nexport data item:u64=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {NULL, NULL, NULL}};
#define CONTRACT_PROBE_COUNT ((unsigned)(sizeof contract_probes / sizeof contract_probes[0] - 1))

/* The bare source name inside a module qualified C symbol name. */
static const char *contract_tail(const char *qualified)
{
    const char *dot = strrchr(qualified, '.');
    return dot ? dot + 1 : qualified;
}

static char *contract_dup(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    char *copy = malloc(n + 1);
    if (!copy) { CHECK(0, "contract text copy allocated"); return NULL; }
    if (n) memcpy(copy, s, n);
    copy[n] = 0;
    return copy;
}

/* The contract the C object writer built for the symbol whose qualified name
 * ends in "." + name, searched inside a C built object. */
static const char *c_symbol_contract(const NtObject *o, const char *name)
{
    size_t k, nl = strlen(name);
    for (k = 0; k < o->symbol_count; k++) {
        const char *written = o->symbols[k].name;
        size_t l = written ? strlen(written) : 0;
        if (l > nl && written[l - 1 - nl] == '.' && !memcmp(written + l - nl, name, nl))
            return o->symbols[k].contract;
    }
    return NULL;
}

/* A private copy of that text, for an object the C pipeline already built. */
static char *c_contract_of(const NtObject *o, const char *name)
{
    const char *written = o->symbol_count ? c_symbol_contract(o, name) : NULL;
    if (!written)
        fprintf(stderr, "C_CONTRACT_MISSING name=%s symbols=%zu\n", name, o->symbol_count);
    return written ? contract_dup(written) : NULL;
}

/* The same text from a fresh nt_object_compile of `probe`. */
static char *c_contract(const char *probe, const char *name)
{
    NtFInput input = {"d", probe, strlen(probe)};
    NtObject object;
    NtDiagnostic error;
    char *found = NULL;
    memset(&object, 0, sizeof object);
    memset(&error, 0, sizeof error);
    if (!nt_object_compile(&input, 1, &object, &error)) {
        fprintf(stderr, "C_CONTRACT_REFUSED name=%s code=%u %s\n", name, error.code,
                error.message);
        return NULL;
    }
    found = c_contract_of(&object, name);
    nt_object_free(&object);
    return found;
}

/* A second image holding only the Nova NXO text accessors, so the contract
 * texts the C writer produced can be read back by a Nova producer without
 * disturbing the entry this gate drives. */
static int contract_image(NovaHostImage *image, NtArtifact *artifact)
{
    const char *paths[] = {"tests/nova/tests/nxo-inspect-text-entry.nova",
                           "compiler/nova/inspectors/nxo_inspect.nova",
                           "compiler/nova/formats/nxo/nxo.nova",
                           "compiler/nova/formats/pe/pe.nova"};
    char *sources[4] = {0};
    NtFInput inputs[4];
    unsigned i;
    int all = 1, compiled;
    for (i = 0; i < 4; i++) {
        size_t n = 0;
        sources[i] = loadf(paths[i], &n);
        inputs[i] = (NtFInput){paths[i], sources[i], n};
        if (!sources[i]) all = 0;
    }
    CHECK(all, "contract accessor sources load");
    compiled = all && nova_compile_many_v2(inputs, 4, artifact);
    CHECK(compiled, "contract accessor modules compile");
    if (!compiled) {
        fprintf(stderr, "E%u %zu:%zu %s\n", artifact->error.code, artifact->error.line,
                artifact->error.column, artifact->error.message);
        for (i = 0; i < 4; i++) free(sources[i]);
        return 0;
    }
    if (!nova_host_map(artifact, image)) {
        CHECK(0, "contract accessor image maps");
        for (i = 0; i < 4; i++) free(sources[i]);
        return 0;
    }
    for (i = 0; i < 4; i++) free(sources[i]);
    CHECK(image->memory != NULL, "contract accessor image is mapped");
    return image->memory != NULL;
}

#define CONTRACT_OUT_CAPACITY 2048

/* One probe: the C object writer builds it, nt_object_write serialises it,
 * nt_object_read reads it back, and the Nova text accessor reads the same
 * bytes out of the same file. All of them must return the same string, and
 * that string must be longer than the two byte placeholder the producer used
 * to write, so a regression to the placeholder cannot pass here. */
static void contract_round_trip(const NovaHostImage *ci, const ContractProbe *p)
{
    static uint8_t text[CONTRACT_OUT_CAPACITY];
    uint64_t length[1];
    NtObject canon = {0}, read = {0};
    NtBuffer file = {0};
    NtDiagnostic error = {0};
    NtFInput input = {"d", p->probe, strlen(p->probe)};
    char *expected = NULL;
    size_t want = 0, index = 0, k;
    int found = 0;

    cases++;
    if (!nt_object_compile(&input, 1, &canon, &error)) {
        CHECK(0, "contract probe: the C object writer builds the probe");
        fprintf(stderr, "CONTRACT_ORACLE_REFUSED %s code=%u %s\n", p->label, error.code,
                error.message);
        return;
    }
    CHECK(1, "contract probe: the C object writer builds the probe");
    expected = c_contract_of(&canon, p->name);
    CHECK(expected != NULL, "contract probe: the C object writer wrote the contract");
    if (!expected) { nt_object_free(&canon); return; }
    want = strlen(expected);
    CHECK(want > 2, "contract probe: the C contract is longer than the v0 placeholder");
    CHECK(nt_object_write(&canon, &file, &error), "contract probe: nt_object_write serialises it");
    CHECK(file.bytes && nt_object_read(file.bytes, file.size, &read, &error),
          "contract probe: nt_object_read reads it back");
    for (k = 0; read.symbols && k < read.symbol_count; k++)
        if (!strcmp(contract_tail(read.symbols[k].name), p->name)) { index = k; found = 1; break; }
    CHECK(found, "contract probe: nt_object_read kept the probed symbol");
    if (found)
        CHECK(!strcmp(read.symbols[index].contract, expected),
              "contract probe: nt_object_read recovers the C contract byte for byte");
    if (file.bytes && found) {
        NovaContextV2 c = {0};
        uint64_t args[8], code = UINT64_C(0xffffffffffffffff);
        memset(text, 0xcc, sizeof text);
        length[0] = UINT64_C(0xcccccccccccccccc);
        CHECK(nova_context_init_v2(&c), "contract probe: accessor context init");
        args[0] = nova_borrow_v2(&c, file.bytes, file.size, 0);
        args[1] = file.size;
        args[2] = (uint64_t)index;
        args[3] = nova_borrow_v2(&c, text, sizeof text, 1);
        args[4] = (uint64_t)sizeof text;
        args[5] = nova_borrow_v2(&c, length, sizeof length, 1);
        args[6] = 1; /* the flat slot carries the element count of a buf<u64> */
        args[7] = 1; /* mode 1 copies the contract, mode 0 the name */
        code = ci->entry(&c, args, 8);
        CHECK(c.error == 0, "contract probe: accessor runtime clean");
        CHECK(nova_context_destroy_v2(&c), "contract probe: accessor context cleanup");
        CHECK(code == 0, "contract probe: the Nova accessor returns the contract");
        if (code == 0) {
            CHECK(length[0] == want, "contract probe: the accessor reports the C length");
            CHECK(length[0] == want && !memcmp(text, expected, want),
                  "contract probe: the Nova accessor returns the C contract byte for byte");
        }
    }
    if (read.symbols) nt_object_free(&read);
    free(file.bytes);
    nt_object_free(&canon);
    free(expected);
}

/* Two probes whose declarations differ must not collapse onto one contract
 * string, so the table is variation and not decoration. */
static void contract_distinct(void)
{
    char *texts[64];
    unsigned k, j;
    unsigned collisions = 0, refusals = 0;
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) texts[k] = NULL;
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) {
        NtFInput input = {"d", (char *)contract_probes[k].probe,
                          strlen(contract_probes[k].probe)};
        NtObject canon = {0};
        NtDiagnostic error = {0};
        if (!nt_object_compile(&input, 1, &canon, &error)) { refusals++; continue; }
        texts[k] = c_contract_of(&canon, contract_probes[k].name);
        nt_object_free(&canon);
    }
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++)
        for (j = k + 1; j < CONTRACT_PROBE_COUNT; j++)
            if (texts[k] && texts[j] && !strcmp(texts[k], texts[j])) {
                collisions++;
                fprintf(stderr, "CONTRACT_COLLISION %s == %s [%s]\n",
                        contract_probes[k].label, contract_probes[j].label, texts[k]);
            }
    CHECK(refusals == 0, "contract probes: the C object writer builds every probe");
    CHECK(collisions == 0, "contract probes: distinct declarations give distinct texts");
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) free(texts[k]);
}

/* The whole table, then the distinctness sweep. */
static void contract_suite(const NovaHostImage *ci)
{
    unsigned k;
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) contract_round_trip(ci, contract_probes + k);
    contract_distinct();
    cases++;
}
static char oracle_free_reason[256];
static unsigned oracle_compared_total, oracle_free_total, oracle_diverged_total;
/* Fixtures the PRODUCER refused, counted apart from the three oracle columns.
 *
 * WHY THIS COLUMN EXISTS, and it is a gap that had been invisible. accept()
 * returns early when mode 1 does not produce a PE, which is the correct thing
 * to do, but it returned BEFORE the oracle block, so a refused fixture reached
 * none of compared / diverges / free. The closing census then compared the
 * surviving fixtures against a constant that counted the refused ones too, and
 * it was unsatisfiable by construction: measured compared=6 diverges=0
 * free=0 against an expected 11, with the five missing ones refused rather
 * than lost. A check that cannot be satisfied and does not say so is worse
 * than no check, because the reader sees a number and cannot tell it is
 * standing in for a different question.
 *
 * This column makes the refusal an ACCOUNTED outcome rather than an absence.
 * The constant is NOT lowered to the number that happens to survive: the
 * census still expects every accepted fixture to be in exactly one column,
 * and a fixture that lands in none of the four is still a failure. */
static unsigned oracle_refused_total;
/* Fixtures driven entirely through the C reference, with no producer invocation
 * behind them, so they are counted apart from cases and never confused with it. */
static unsigned oracle_cases;
/* .text size of the last PE the C pipeline produced, for the divergence report. */
static size_t oracle_last_text_size;

static void free_artifact(NtArtifact *a)
{
    if (a->pe.bytes) { free(a->pe.bytes); a->pe.bytes = NULL; }
    if (a->text.bytes) { free(a->text.bytes); a->text.bytes = NULL; }
    if (a->rdata.bytes) { free(a->rdata.bytes); a->rdata.bytes = NULL; }
    if (a->data.bytes) { free(a->data.bytes); a->data.bytes = NULL; }
    free(a->base_relocations);
    memset(a, 0, sizeof *a);
}

/* A codegen image carries two parallel tables, and the contract is that a count
 * is only ever raised after its table exists: codegen.c:150 appends a symbol
 * after the realloc at codegen.c:120, and codegen.c:169 appends a relocation
 * after the realloc at codegen.c:163. So relocation_count == 0 legitimately
 * comes with relocations == NULL, and a non zero count with a NULL table is a
 * contract violation, not a state to walk. nt_object_validate states the same
 * rule for a written object ("missing object tables", object.c) and pe_oracle.c
 * refuses on exactly it (pe_oracle.c:46-47), so the harness checks it up front
 * and reports one named failure. Walking the table on trust instead costs the
 * whole gate: every link twin in this file is the zero relocation shape, so the
 * first unguarded r->target_function ends the process and takes the other 154
 * cases with it. */
static int image_tables_present(const NtCodeImage *image, char *why, size_t room)
{
    if (image->symbol_count && !image->symbols) {
        snprintf(why, room, "codegen image: symbol_count=%zu with a NULL symbol table",
                 image->symbol_count);
        return 0;
    }
    if (image->relocation_count && !image->relocations) {
        snprintf(why, room, "codegen image: relocation_count=%zu with a NULL relocation table",
                 image->relocation_count);
        return 0;
    }
    return 1;
}

/* Assembles an NtObject from a C codegen image and names it like
 * object_build.c does. The contract string is the one the C object writer built
 * for the same declaration, read out of `canon`: nt_object_write and
 * nt_object_read only carry the contract, so a placeholder here would make
 * every byte comparison below compare placeholders and detect nothing.
 * names_out receives the single allocation the symbol names point into; the
 * caller frees it with the symbol table. */
static int assemble(const NtCodeImage *image, const NtObject *canon, NtObject *o,
                    uint32_t *entry_symbol, void **names_out, char *why, size_t room)
{
    NtObjectSymbol *symbols;
    NtObjectReloc *relocs;
    size_t j, exported = 0;
    char (*names)[512];
    *names_out = NULL;
    if (!image_tables_present(image, why, room)) return 0;
    symbols = calloc(image->symbol_count ? image->symbol_count : 1, sizeof *symbols);
    relocs = calloc(image->relocation_count ? image->relocation_count : 1, sizeof *relocs);
    names = calloc(image->symbol_count ? image->symbol_count : 1, sizeof *names);
    if (!symbols || !relocs || !names) { free(symbols); free(relocs); free(names); return 0; }
    for (j = 0; j < image->symbol_count; j++) {
        const NtCodeSymbol *s = image->symbols + j;
        int n = snprintf(names[j], sizeof names[j], "%s.%s", s->module, s->name);
        if (n <= 0 || (size_t)n >= sizeof names[j]) {
            free(symbols); free(relocs); free(names);
            return 0;
        }
        symbols[j].name = names[j];
        symbols[j].contract = (char *)c_symbol_contract(canon, contract_tail(s->name));
        if (!symbols[j].contract) {
            free(symbols); free(relocs); free(names);
            snprintf(why, room, "assembly: the C object writer has no contract for %s",
                     s->name);
            return 0;
        }
        symbols[j].section = s->section;
        symbols[j].offset = s->offset;
        symbols[j].size = s->size;
        symbols[j].flags = NT_OBJECT_FUNCTION | ((s->flags & 1u) ? NT_OBJECT_EXPORT : 0);
        if (s->function_id && (s->flags & 1u) && s->section == NT_CODE_SECTION_TEXT) {
            *entry_symbol = (uint32_t)j + 1;
            exported++;
        }
    }
    if (exported != 1) { free(symbols); free(relocs); free(names); return 0; }
    /* bounded by the relocation count and never by the symbol count, and the
     * table pointer is tested as well so no future edit to the bound can turn a
     * zero relocation image into a NULL dereference */
    for (j = 0; image->relocations && j < image->relocation_count; j++) {
        const NtCodeReloc *r = image->relocations + j;
        uint32_t target = 0;
        size_t k;
        for (k = 0; k < image->symbol_count; k++) {
            if (r->target_function && image->symbols[k].function_id == r->target_function) {
                target = (uint32_t)k + 1;
                break;
            }
        }
        if (!target) { free(symbols); free(relocs); free(names); return 0; }
        relocs[j].section = r->source_section;
        relocs[j].kind = r->kind;
        relocs[j].offset = r->offset;
        relocs[j].target = target;
        relocs[j].addend = r->addend;
    }
    memset(o, 0, sizeof *o);
    o->target = 1;
    o->entry_symbol = *entry_symbol;
    o->sections[0] = (NtBuffer){image->bytes, image->size, image->capacity};
    o->sections[1] = (NtBuffer){image->rdata.bytes, image->rdata.size, image->rdata.capacity};
    o->sections[2] = (NtBuffer){image->data.bytes, image->data.size, image->data.capacity};
    o->symbols = symbols;
    o->symbol_count = image->symbol_count;
    o->relocations = relocs;
    o->relocation_count = image->relocation_count;
    *names_out = names;
    return 1;
}

/* Runs nt_object_write, nt_object_read, nt_object_materialize and nt_make_pe on
 * a borrowed object and hands back the PE bytes. */
static int oracle_pe_from(const NtObject *object, uint8_t **pe, size_t *pe_size,
                          uint64_t *entry_offset, char *why, size_t cap)
{
    NtBuffer file = {0};
    NtObject readback;
    NtArtifact artifact;
    NtDiagnostic error;
    uint32_t entry_symbol = object->entry_symbol;
    memset(&readback, 0, sizeof readback);
    memset(&artifact, 0, sizeof artifact);
    memset(&error, 0, sizeof error);
    if (!nt_object_validate(object, &error)) {
        snprintf(why, cap, "nt_object_validate %u %s", error.code, error.message);
        return 0;
    }
    if (!nt_object_write(object, &file, &error)) {
        snprintf(why, cap, "nt_object_write %u %s", error.code, error.message);
        return 0;
    }
    if (!nt_object_read(file.bytes, file.size, &readback, &error)) {
        snprintf(why, cap, "nt_object_read %u %s", error.code, error.message);
        free(file.bytes);
        return 0;
    }
    free(file.bytes);
    if (!nt_object_materialize(&readback, &artifact, &error)) {
        snprintf(why, cap, "nt_object_materialize %u %s", error.code, error.message);
        nt_object_free(&readback);
        return 0;
    }
    if (!nt_make_pe(&artifact)) {
        snprintf(why, cap, "nt_make_pe %u %s", artifact.error.code, artifact.error.message);
        free_artifact(&artifact);
        nt_object_free(&readback);
        return 0;
    }
    *entry_offset = (uint64_t)artifact.entry;
    *pe_size = artifact.pe.size;
    oracle_last_text_size = artifact.text.size;
    *pe = artifact.pe.bytes;
    artifact.pe.bytes = NULL;
    free_artifact(&artifact);
    nt_object_free(&readback);
    (void)entry_symbol;
    return 1;
}

/* Reference PE for a fixture, through the frozen C pipeline. Returns 0 and a
 * reason when the C frontend or the C codegen cannot express the fixture. */
static int oracle_pe(const char *source, uint8_t **pe, size_t *pe_size, uint64_t *entry_offset)
{
    NtFInput input = {"m", source, strlen(source)};
    NtFInput again = {"m", source, strlen(source)};
    NtFProgram program;
    NtCodeImage image;
    NtCodeDiagnostic cd;
    NtObject hand;
    NtObject canon = {0};
    NtDiagnostic canonical_error;
    uint32_t entry_symbol = 0;
    void *names = NULL;
    int ok = 0;
    oracle_free_reason[0] = 0;
    oracle_last_text_size = 0;
    memset(&program, 0, sizeof program);
    memset(&image, 0, sizeof image);
    memset(&cd, 0, sizeof cd);
    memset(&hand, 0, sizeof hand);
    memset(&canonical_error, 0, sizeof canonical_error);
    /* the canonical builder runs first: its contracts are what the hand
     * assembly below has to carry */
    if (!nt_object_compile(&again, 1, &canon, &canonical_error)) {
        snprintf(oracle_free_reason, sizeof oracle_free_reason, "nt_object_compile %u %s",
                 canonical_error.code, canonical_error.message);
        return 0;
    }
    if (!nt_frontend_compile_object(&input, 1, &program)) {
        nt_object_free(&canon);
        snprintf(oracle_free_reason, sizeof oracle_free_reason, "frontend %u %s",
                 program.diagnostic_count ? program.diagnostics[0].code : 0u,
                 program.diagnostic_count ? program.diagnostics[0].message : "no diagnostic");
        nt_frontend_free(&program);
        nt_object_free(&canon);
        return 0;
    }
    if (!nt_codegen_x64_object(&program, &image, &cd)) {
        snprintf(oracle_free_reason, sizeof oracle_free_reason, "codegen %u %s", cd.code, cd.message);
        nt_code_image_free(&image);
        nt_frontend_free(&program);
        nt_object_free(&canon);
        return 0;
    }
    if (!assemble(&image, &canon, &hand, &entry_symbol, &names, oracle_free_reason,
                  sizeof oracle_free_reason)) {
        if (!oracle_free_reason[0])
            snprintf(oracle_free_reason, sizeof oracle_free_reason,
                     "assembly: no single exported text function");
        nt_code_image_free(&image);
        nt_frontend_free(&program);
        nt_object_free(&canon);
        return 0;
    }
    ok = oracle_pe_from(&hand, pe, pe_size, entry_offset, oracle_free_reason,
                        sizeof oracle_free_reason);
    free(hand.symbols);
    free(hand.relocations);
    free(names);
    /* the canonical object has served its purpose: the hand assembly above
     * copied its contract texts, so it is released here */
    nt_object_free(&canon);
    /* Second reference: the canonical builder of the same C frontend, so the
     * hand assembly above is proven to be the reference assembly. */
    if (ok) {
        NtObject canonical;
        NtDiagnostic error;
        uint32_t found = 0;
        size_t k;
        uint8_t *pe3 = NULL;
        size_t pe3_size = 0;
        uint64_t entry3 = 0;
        memset(&canonical, 0, sizeof canonical);
        memset(&error, 0, sizeof error);
        if (!nt_object_compile(&input, 1, &canonical, &error)) {
            snprintf(oracle_free_reason, sizeof oracle_free_reason, "nt_object_compile %u %s",
                     error.code, error.message);
            ok = 0;
        } else {
            for (k = 0; k < canonical.symbol_count; k++) {
                if ((canonical.symbols[k].flags & (NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION)) ==
                        (NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION) &&
                    canonical.symbols[k].section == NT_OBJECT_TEXT) {
                    if (found) { found = 0; break; }
                    found = (uint32_t)k + 1;
                }
            }
            if (!found) {
                snprintf(oracle_free_reason, sizeof oracle_free_reason,
                         "nt_object_compile: no single exported text function");
                ok = 0;
            } else {
                canonical.entry_symbol = found;
                if (!oracle_pe_from(&canonical, &pe3, &pe3_size, &entry3, oracle_free_reason,
                                    sizeof oracle_free_reason)) {
                    ok = 0;
                } else {
                    CHECKL(pe3_size == *pe_size && !memcmp(pe3, *pe, pe3_size),
                           "canonical builder agrees with the hand assembly", "oracle");
                    free(pe3);
                }
            }
            nt_object_free(&canonical);
        }
        if (!ok && pe) { free(*pe); *pe = NULL; *pe_size = 0; }
    }
    nt_code_image_free(&image);
    nt_frontend_free(&program);
    return ok;
}

/* ------------------------------------------------------------------------ *
 * The exported .text offset, DERIVED FROM THE REFERENCE.
 *
 * WHY THIS EXISTS. A multi function fixture whose exported function is not
 * first in name order puts the exported .text offset at a value that is not
 * zero, and that value used to be written into the accept() call as a
 * literal. It was wrong, and it had been wrong since codegen.c began emitting
 * in name order: two_distinct_call_targets exports beta and declares alpha
 * before it, backward_branch exports spin and declares quiet before it. A
 * literal 0 encoded the OLD declaration order as if it were a law, which is
 * the same defect as a model transcribed from the producer: both take one
 * sample of the answer and freeze it.
 *
 * WHY IT IS NOT SIMPLY "11". Writing 11 would replace a stale pin with a fresh
 * one. The number has to be COMPUTED, from the reference, by a rule that would
 * give a different answer if the layout changed.
 *
 * THE RULE, and where the reference decides it. codegen.c function_before
 * (codegen.c:1359) orders functions by module name, then function name, then
 * declaration index, and the object carries .text in that order. So the
 * exported function's offset is the sum of the .text sizes of every function
 * preceding it in that order. The SIZES are not assumed: each is measured by
 * running the frozen C pipeline, nt_frontend_compile_object followed by
 * nt_codegen_x64_object, through oracle_pe, over a module holding that one
 * function and nothing else, and reading back the .text size the reference
 * itself produced.
 *
 * So nothing here reads the Nova producer. Lay the functions out in
 * declaration order instead of name order and this returns 0 for beta and the
 * fixture goes red. Change a body so it encodes to a different size and this
 * moves. That is what makes this an instrument rather than a restatement.
 *
 * The caller passes the preceding functions ALREADY IN REFERENCE NAME ORDER,
 * so the ordering decision is visible at the call site instead of hidden in
 * here. Where the C can express the whole fixture, accept() also checks this
 * derived value against the C's own answer, the "C oracle entry text offset"
 * check, which is the reference graded against itself. */

/* The .text size the C reference gives one function standing alone. */
static uint64_t reference_text_size(const char *fn_text, const char *label)
{
    char src[4096];
    uint8_t *pe = NULL;
    size_t pe_size = 0;
    uint64_t entry = 0;
    int n = snprintf(src, sizeof src, "%sexport %s}\n", HEAD, fn_text);
    if (n < 0 || (size_t)n >= sizeof src) {
        CHECKL(0, "the isolated function fits its buffer", label);
        return UINT64_MAX;
    }
    if (!oracle_pe(src, &pe, &pe_size, &entry)) {
        fprintf(stderr, "REF %s the C cannot express an isolated function: %s\n",
                label, oracle_free_reason);
        return UINT64_MAX;
    }
    free(pe);
    return (uint64_t)oracle_last_text_size;
}

/* The functions that precede the export in REFERENCE NAME ORDER, for the two
 * fixtures whose exported function is not declared first. codegen.c
 * function_before sorts ascending by name, so the list is written in the order
 * the reference lays the .text out, and the entry offset is the sum of their
 * .text sizes.
 *
 * BOTH LISTS CHANGED WITH THE RENAME, and in OPPOSITE directions, which is
 * exactly the part a mechanical rename gets wrong:
 *
 *   two_distinct_call_targets declared alpha, beta, gamma and exported beta.
 *   Exported as `main` the order is alpha, gamma, main -- "main" sorts after
 *   "gamma" -- so BOTH alpha and gamma precede the export and the list holds
 *   two entries. Measured on the reference for the renamed source: alpha@0,
 *   gamma@11, main@22, entry_symbol 3, entry offset 22. The old list held one
 *   entry and would have produced 11, which is the size of alpha and is wrong.
 *
 *   backward_branch declared quiet and spin and exported spin. Exported as
 *   `main` the order is main, quiet -- "main" sorts before "quiet" -- so
 *   NOTHING precedes the export, the list is empty, and the entry offset is 0
 *   where it used to be the size of quiet.
 *
 * Writing the lists out is what makes the ORDER auditable: a reader can check
 * it against function_before without reading the derivation. */
static const char *const TWO_TARGETS_PRECEDING[] = {
    "fn alpha()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n",
    "fn gamma()->u64\neffects {}\nclobbers {} {\nreturn 2\n}\n", NULL };
static const char *const BACKWARD_PRECEDING[] = { NULL };

/* The exported .text offset for a fixture, derived as described above.
 * UINT64_MAX means the reference could not be asked, and the caller must treat
 * that as a failure rather than as "no expectation".
 *
 * The count is COUNTED FROM THE NULL TERMINATOR rather than passed in, because
 * the two can disagree and nothing catches it. A caller handing a literal 1
 * alongside a list it had just emptied reads past the terminator and sums
 * whatever is in memory, which is not a wrong answer the gate can see -- it is
 * an answer to a question nobody asked. Measured: the linked fixture with its
 * list emptied and the count still written as 1 did not report a mismatched
 * offset, it reported that the reference could not be asked, which is a
 * different failure and would have been easy to read as the check working. */
static uint64_t reference_entry_offset(const char *label,
                                       const char *const *preceding)
{
    uint64_t total = 0;
    size_t k;
    for (k = 0; preceding[k] != NULL; k++) {
        uint64_t one = reference_text_size(preceding[k], label);
        if (one == UINT64_MAX) return UINT64_MAX;
        total += one;
    }
    return total;
}
/* The functions that precede LINK_FIXTURE's export in reference name order.
 * "helper" sorts before "main", so exactly one function precedes it and the
 * entry offset is that function's own .text size. Re-derived from the
 * reference, not carried over from the pre-rename 0. Declared here rather than
 * beside LINK_FIXTURE because the self-test below, which is what proves the
 * derivation is not a constant, is the first thing to read it. */
static const char *const LINK_PRECEDING[] = {
    "fn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n", NULL };

/* The instrument, exercised against the state it exists to detect.
 *
 * reference_entry_offset is a sum over a caller supplied list, so an
 * implementation returning a constant would satisfy every fixture wanting the
 * same number. This asks it for four different lists and requires four
 * different answers, so a constant cannot pass. None of the four is written
 * here: each is the size the C reference gives one aaNN function, asked
 * through the same oracle_pe the fixtures use. */
static void reference_entry_self_test(void)
{
    static const char *AA =
        "fn aa00()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n";
    static const char *AA1 =
        "fn aa01()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n";
    static const char *AA2 =
        "fn aa02()->u64\neffects {}\nclobbers {} {\nreturn 2\n}\n";
    const char *none[] = { NULL };
    const char *one[] = { AA, NULL };
    const char *two[] = { AA, AA1, NULL };
    const char *three[] = { AA, AA1, AA2, NULL };
    uint64_t z, a, b, c, unit, unit_helper, linked;

    unit_helper = reference_text_size(
        "fn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n", "self-test helper");
    linked = reference_entry_offset("self-test linked", LINK_PRECEDING);
    z = reference_entry_offset("self-test empty", none);
    unit = reference_text_size(AA, "self-test unit");
    a = reference_entry_offset("self-test one", one);
    b = reference_entry_offset("self-test two", two);
    c = reference_entry_offset("self-test three", three);
    CHECKL(z == 0, "a fixture with nothing before the export sits at 0", "self-test");
    CHECKL(unit != UINT64_MAX && unit > 0,
           "the reference gives a real size for one function", "self-test");
    CHECKL(a == unit, "one preceding function sums to its own size", "self-test");
    CHECKL(b == 2 * unit, "two equal preceding functions sum to twice one", "self-test");
    CHECKL(c == 3 * unit, "three equal preceding functions sum to three times one", "self-test");
    /* BACKWARD_PRECEDING is the EMPTY list, and it is asked here because
     * backward_branch no longer asks it for a PE offset: that row is now a
     * refused_by_both row and the derivation it fed has no caller. The list is
     * not deleted, because the paragraph above it records why the rename
     * emptied it, and deleting a documented fact because its row changed shape
     * loses the reason the row changed. What replaces the call is this check,
     * which asks the same instrument the same question the call did. */
    CHECKL(reference_entry_offset("backward_branch", BACKWARD_PRECEDING) == 0,
           "a fixture whose export sorts first needs no derivation and still reads 0",
           "self-test");
    CHECKL(z != a && a != b && b != c,
           "the derivation is not a constant", "self-test");
    /* The state linked_accept used to be untested in: an export that is NOT
     * first in name order, which is the case its old hardcoded 4096 could not
     * have survived. "helper" sorts before "main", so the linked fixture's
     * expected offset is the size of helper, not zero, and the derivation below
     * is what produces that number. If this ever equals z, the derivation has
     * acquired a constant of its own and the linked check is pinned again. */
    CHECKL(unit_helper != UINT64_MAX && linked == unit_helper,
           "the linked fixture's entry offset is the size of the one function preceding it",
           "self-test");
    CHECKL(linked != 0 && linked != z,
           "the linked fixture does not sit at offset 0", "self-test");
    fprintf(stderr, "ENTRY_SELFTEST empty=%llu one=%llu two=%llu three=%llu unit=%llu linked=%llu\n",
            (unsigned long long)z, (unsigned long long)a, (unsigned long long)b,
            (unsigned long long)c, (unsigned long long)unit,
            (unsigned long long)linked);
}

/* Reports the entry RVA of a PE, its anchor and its section table. */
static void report_pe(const char *label, const uint8_t *pe, size_t size, uint32_t entry_rva)
{
    uint32_t nt = rd32(pe + 60);
    uint16_t count = rd16(pe + nt + 6), opt = rd16(pe + nt + 20);
    size_t table = (size_t)nt + 24 + opt;
    uint64_t anchor = 0;
    uint32_t ro_raw = 0;
    fprintf(stderr, "PE %s size=%zu entry_rva=0x%08lx sections=%u machine=0x%04x magic=0x%03x "
                    "subsystem=%u\n", label, size, (unsigned long)entry_rva, count,
            rd16(pe + nt + 4), rd16(pe + nt + 24), rd16(pe + nt + 24 + 68));
    for (unsigned s = 0; s < count; s++) {
        const uint8_t *h = pe + table + (size_t)s * 40;
        char name[9];
        memcpy(name, h, 8);
        name[8] = 0;
        fprintf(stderr, "   section %-8s va=0x%08lx vs=0x%08lx raw=0x%08lx rawsz=0x%08lx flags=0x%08lx%s\n",
                name, (unsigned long)rd32(h + 12), (unsigned long)rd32(h + 8),
                (unsigned long)rd32(h + 20), (unsigned long)rd32(h + 16),
                (unsigned long)rd32(h + 36),
                (rd32(h + 12) <= entry_rva && entry_rva < rd32(h + 12) + rd32(h + 8)) ? " <-entry" : "");
        if (!strcmp(name, ".rdata")) ro_raw = rd32(h + 20);
    }
    if (ro_raw && ro_raw + 8 <= size) {
        for (unsigned k = 0; k < 8; k++) anchor |= (uint64_t)pe[ro_raw + k] << (k * 8);
        fprintf(stderr, "   .rdata anchor=0x%016llx\n", (unsigned long long)anchor);
    }
}

/* Every accepted fixture: run mode 1 for the PE and mode 2 for the NXO, then
 * validate the PE with the QEMU structural contract, cross check it against the
 * frozen C pipeline fed with the producer own NXO, and compare it byte for byte
 * against the C frontend and codegen whenever they can express the fixture. */
static void accept(const NovaHostImage *i, const char *source, const char *label,
                   uint64_t expected_entry, int expect_identical)
{
    static NtBuffer empty = {0};
    uint64_t pe_code, nxo_code, pe_size, nxo_size, declared_entry = 0, nova_text_size = 0;
    uint32_t entry_rva = 0, mapped_entry = 0;
    int mapped_result, file_result;
    NtObject readback;
    NtDiagnostic error;
    uint8_t *cross = NULL;
    size_t cross_size = 0;
    uint64_t cross_entry = 0;
    char why[256];

    memset(out_pe, guard, sizeof out_pe);
    pe_code = run_mode(i, source, &empty, 1, NULL, out_pe, OUTCAP);
    CHECKL(pe_code == 0, "mode 1 returns a PE", label);
    if (pe_code != 0) {
        /* Accounted as a refusal, with the code that named it. The code is
         * reported rather than counted alone because 800 is ambiguous on its
         * own: the gate entry answers 800 both when ntasm_parser.parse fails
         * and when the producer refuses, so the number says which stage bailed
         * only once that stage has been measured apart. */
        oracle_refused_total++;
        fprintf(stderr, "ORACLE_REFUSED %s producer_code=%llu\n", label,
                (unsigned long long)pe_code);
        return;
    }
    pe_size = r64(out_pe);
    CHECKL(pe_size > 0 && pe_size + 8 <= OUTCAP, "PE size fits", label);

    memset(out_nxo, guard, sizeof out_nxo);
    nxo_code = run_mode(i, source, &empty, 2, NULL, out_nxo, OUTCAP);
    CHECKL(nxo_code == 0, "mode 2 returns the NXO", label);
    if (nxo_code != 0) return;
    nxo_size = r64(out_nxo);
    CHECKL(nxo_size > 0 && nxo_size + 8 <= OUTCAP, "NXO size fits", label);
    if (pe_size + 8 > OUTCAP || nxo_size + 8 > OUTCAP) return;

    /* 1. the exact structural contract the QEMU consumer enforces */
    file_result = ng_pe_validate(out_pe + 8, (size_t)pe_size, 0, &entry_rva);
    CHECKL(file_result == NG_PE_OK, "ng_pe_validate file image", label);
    if (file_result != NG_PE_OK) {
        fprintf(stderr, "PE %s rejected with %d\n", label, file_result);
        return;
    }
    {
        uint32_t nt = rd32(out_pe + 8 + 60);
        uint16_t count = rd16(out_pe + 8 + nt + 6), opt = rd16(out_pe + 8 + nt + 20);
        size_t table = (size_t)nt + 24 + opt;
        uint32_t image = rd32(out_pe + 8 + nt + 24 + 56);
        uint8_t *mapped = calloc(image ? image : 1, 1);
        CHECKL(mapped != NULL, "mapped image allocated", label);
        if (mapped) {
            uint32_t headers = rd32(out_pe + 8 + nt + 24 + 60);
            if (headers > image) headers = image;
            memcpy(mapped, out_pe + 8, headers);
            for (unsigned s = 0; s < count; s++) {
                const uint8_t *h = out_pe + 8 + table + (size_t)s * 40;
                uint32_t va = rd32(h + 12), raw = rd32(h + 20), rawsz = rd32(h + 16);
                if (va > image || rawsz > image - va) continue;
                if (raw > pe_size || rawsz > pe_size - raw) continue;
                memcpy(mapped + va, out_pe + 8 + raw, rawsz);
            }
            mapped_result = ng_pe_validate(mapped, image, 1, &mapped_entry);
            CHECKL(mapped_result == NG_PE_OK, "ng_pe_validate mapped image", label);
            CHECKL(mapped_entry == entry_rva, "entry rva survives mapping", label);
            free(mapped);
        }
    }
    /* explicit restatement of the fields the harness names */
    {
        uint32_t nt = rd32(out_pe + 8 + 60);
        uint16_t count = rd16(out_pe + 8 + nt + 6), opt = rd16(out_pe + 8 + nt + 20);
        size_t table = (size_t)nt + 24 + opt;
        uint64_t anchor = 0;
        uint32_t ro_raw = 0;
        int overlap = 0, entry_in_exec = 0;
        CHECKL(rd16(out_pe + 8) == 0x5a4d, "MZ signature", label);
        CHECKL(rd32(out_pe + 8 + nt) == 0x4550, "PE signature", label);
        CHECKL(rd16(out_pe + 8 + nt + 4) == 0x8664, "machine 0x8664", label);
        CHECKL(rd16(out_pe + 8 + nt + 24) == 0x20b, "optional magic 0x20b", label);
        CHECKL(rd16(out_pe + 8 + nt + 24 + 68) == 10, "subsystem EFI application", label);
        for (unsigned a = 0; a < count && !overlap; a++) {
            const uint8_t *x = out_pe + 8 + table + (size_t)a * 40;
            uint32_t xv = rd32(x + 12), xs = rd32(x + 8) > rd32(x + 16) ? rd32(x + 8) : rd32(x + 16);
            for (unsigned b = 0; b < a; b++) {
                const uint8_t *y = out_pe + 8 + table + (size_t)b * 40;
                uint32_t yv = rd32(y + 12), ys = rd32(y + 8) > rd32(y + 16) ? rd32(y + 8) : rd32(y + 16);
                if (xs && ys && xv < yv + ys && yv < xv + xs) overlap = 1;
            }
        }
        CHECKL(!overlap, "sections do not overlap", label);
        for (unsigned s = 0; s < count; s++) {
            const uint8_t *h = out_pe + 8 + table + (size_t)s * 40;
            uint32_t va = rd32(h + 12), vs = rd32(h + 8), rawsz = rd32(h + 16);
            uint32_t flags = rd32(h + 36);
            char name[9];
            memcpy(name, h, 8);
            name[8] = 0;
            if ((flags & 0xe0000000u) == 0x60000000u && entry_rva >= va &&
                entry_rva - va < vs && entry_rva - va < rawsz) entry_in_exec = 1;
            if (!strcmp(name, ".rdata")) ro_raw = rd32(h + 20);
        }
        CHECKL(entry_in_exec, "entry inside an executable section", label);
        if (ro_raw && ro_raw + 8 <= pe_size) {
            for (unsigned k = 0; k < 8; k++) anchor |= (uint64_t)out_pe[8 + ro_raw + k] << (k * 8);
            CHECKL(anchor == 0x140000000ull + (uint64_t)entry_rva,
                   ".rdata anchor holds the preferred entry address", label);
        } else {
            CHECKL(0, ".rdata anchor present", label);
        }
    }

    /* 2. the entry RVA must be 4096 plus the .text offset the object declares
     *    for its single exported function */
    memset(&readback, 0, sizeof readback);
    memset(&error, 0, sizeof error);
    if (!nt_object_read(out_nxo + 8, (size_t)nxo_size, &readback, &error)) {
        CHECKL(0, "C NXO read of the producer bytes", label);
    } else {
        uint32_t exported = 0;
        size_t k;
        CHECKL(nt_object_validate(&readback, &error) != 0, "C NXO validate", label);
        CHECKL(readback.target == 1, "NXO target is UEFI", label);
        for (k = 0; k < readback.symbol_count; k++) {
            if ((readback.symbols[k].flags & (NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION)) ==
                    (NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION) && readback.symbols[k].section == NT_OBJECT_TEXT)
                exported++;
        }
        CHECKL(exported == 1, "exactly one exported text function", label);
        declared_entry = readback.entry_symbol
            ? readback.symbols[readback.entry_symbol - 1].offset : UINT64_MAX;
        CHECKL(declared_entry != UINT64_MAX && (uint64_t)entry_rva == 4096 + declared_entry,
               "entry RVA equals 4096 plus the exported .text offset", label);
        if (expected_entry != UINT64_MAX)
            CHECKL(declared_entry == expected_entry, "exported .text offset", label);
        fprintf(stderr, "ENTRY %s entry_rva=0x%08lx exported_text_offset=%llu text_size=%zu\n",
                label, (unsigned long)entry_rva, (unsigned long long)declared_entry,
                readback.sections[0].size);
        nova_text_size = readback.sections[0].size;

        /* 3. the frozen C materializer and PE writer fed with the producer own
         *    NXO bytes must produce exactly the Nova PE */
        why[0] = 0;
        if (oracle_pe_from(&readback, &cross, &cross_size, &cross_entry, why, sizeof why)) {
            CHECKL(cross_size == pe_size && !memcmp(cross, out_pe + 8, cross_size),
                   "PE byte parity with the C materializer on the same NXO", label);
            CHECKL(cross_entry == declared_entry, "C materializer entry offset", label);
            free(cross);
        } else {
            CHECKL(0, "C materializer on the same NXO", label);
            fprintf(stderr, "  reason %s\n", why);
        }
        nt_object_free(&readback);
    }

    report_pe(label, out_pe + 8, (size_t)pe_size, entry_rva);

    /* 4. byte for byte against the C frontend and codegen, when expressible.
     *    expect_identical marks the fixtures whose lowering the two producers
     *    are meant to share: there the C pipeline must reproduce the Nova PE
     *    exactly, and any difference is a failure. For the other fixtures the
     *    C pipeline may accept the same source and still emit a different code
     *    sequence, because it lowers a full nx64-abi-v0 frame where the Nova
     *    producer emits the bare statement stream. That outcome is measured and
     *    reported, never counted as parity. */
    {
        uint8_t *reference = NULL;
        size_t reference_size = 0;
        uint64_t reference_entry = 0;
        if (oracle_pe(source, &reference, &reference_size, &reference_entry)) {
            int identical = reference_size == pe_size &&
                            !memcmp(reference, out_pe + 8, reference_size);
            if (identical) {
                oracle_compared_total++;
                fprintf(stderr,
                        "ORACLE_COMPARED %s C_entry_text_offset=%llu C_pe_bytes=%zu\n", label,
                        (unsigned long long)reference_entry, reference_size);
                CHECKL(reference_entry == expected_entry, "C oracle entry text offset", label);
            } else {
                oracle_diverged_total++;
                fprintf(stderr,
                        "ORACLE_DIVERGES %s nova_text=%llu C_text=%llu nova_pe=%zu C_pe=%zu "
                        "nova_entry_rva=0x%08lx C_entry_text_offset=%llu\n",
                        label, (unsigned long long)nova_text_size,
                        (unsigned long long)oracle_last_text_size,
                        (size_t)pe_size, reference_size, (unsigned long)entry_rva,
                        (unsigned long long)reference_entry);
                CHECKL(!expect_identical, "declared parity fixture must not diverge", label);
            }
            free(reference);
        } else {
            oracle_free_total++;
            fprintf(stderr, "ORACLE_FREE %s reason=%s\n", label, oracle_free_reason);
            CHECKL(!expect_identical, "declared parity fixture must stay expressible", label);
        }
    }
}

static void refuse(const NovaHostImage *i, const char *source, const char *label, uint64_t want)
{
    static NtBuffer empty = {0};
    size_t j;
    int intact;
    uint64_t code;
    memset(out_pe, guard, sizeof out_pe);
    code = run_mode(i, source, &empty, 1, NULL, out_pe, OUTCAP);
    intact = code == want;
    for (j = 0; j < OUTCAP; j++) intact &= out_pe[j] == guard;
    CHECKL(intact, label, "refusal");
    if (intact) fprintf(stderr, "REFUSED %s code=%llu\n", label, (unsigned long long)code);
}

/* ---------------------------------------------------------------------------
 * THE TWO FLAG-INFERENCE CHECKS, AND THE PRODUCER'S ANSWER TO EACH.
 *
 * The C reference makes two SEPARATE obligations of a body that writes a flag,
 * and it discharges each with its own clause. Read at frontend.c by PHRASE,
 * not by line, because a repair anywhere above shifts every line number:
 *
 *   "f->inferred_effects.flags & ~f->effects.flags"  -> NTF_E_EFFECT, 501,
 *       "function '%s' omits an inferred effect". The obligation is on the
 *       EFFECTS set. A flag-writing instruction contributes
 *       NT_X64_EFFECT_CHANGES_FLAGS (x64.c sets it beside registers_written
 *       bit 17), folded in at "f->inferred_effects.flags |= facts.effects".
 *       The clause that pays it is the atom `changes_flags` in `effects`, and
 *       NO OTHER CLAUSE PAYS IT: `clobbers` is not consulted here.
 *
 *   "f->inferred_clobbers & ~(f->clobbers | output_registers)" ->
 *       NTF_E_CLOBBER, 502, "function '%s' omits an inferred clobber". The
 *       obligation is on the CLOBBERS set, modulo the return value registers
 *       nt_conformance_output_registers excuses. The same flag write
 *       contributes registers_written bit 17, folded in beside the effect
 *       fold. Bit 17 is RFLAGS: nt_frontend_register("rflags").family == 17,
 *       so the clause that pays it is the NAME `rflags` in `clobbers`, and
 *       `effects` is not consulted here.
 *
 * SO THE FOUR LEGS BELOW ARE THE ATTRIBUTION, and they are four TEXTS over
 * ONE body so that a change to any clause is a change of one token:
 *
 *   neither clause            -> the EFFECT check fires first: 501
 *   changes_flags alone       -> the EFFECT check is paid, the CLOBBER one
 *                                 is not: 502
 *   rflags alone              -> the CLOBBER check is not what fired and the
 *                                 EFFECT one still is: 501, NOT 502
 *   both clauses              -> accepted
 *
 * The third leg is the one that keeps the two checks apart: `rflags` is the
 * answer to 502 and it is not the answer to 501, so a repair that discharges
 * only one of the two obligations cannot make all four legs agree. A single
 * "require changes_flags on arithmetic" repair turns legs 1 and 3 green and
 * leaves leg 2 red, which is the shape that made the width work hard.
 *
 * WHY THIS BLOCK EXISTS AT ALL, since the header already records the finding:
 * a finding recorded in a comment is not a check, and nothing in the tree
 * fails if the producer keeps building what the reference declines. The four
 * ORACLE_REFUSED rows above were NOT that check and could not become it:
 * accept() returns as soon as mode 1 refuses, so on those rows the reference
 * was never asked, and the label "ORACLE_REFUSED" is printed by the PRODUCER's
 * refusal, not by the reference's. That inversion is the reason the gap
 * survived.
 *
 * WHAT CHANGED HERE, 30 September 2026, and it changes the reason this block
 * exists rather than removing it. The four rows ARE that check now: each is a
 * refused_by_both row, so the reference is asked first and must name its own
 * reason, and the producer is asked on both routes afterwards. The block
 * below is no longer the only place the producer is asked about the flag
 * checks, and it is still the only place the four LEGS are asked, which is a
 * different and unweaker claim: a row pins one text, this pins the ladder, and
 * a repair that discharges one obligation and not the other cannot satisfy it.
 *
 * The producer-side assertions below are GREEN, and they were red when this
 * paragraph was written: the producer answers 501 on leg 1, 502 on legs 2 and
 * 3, and 0 on leg 4, which is the reference's own answer on every leg. The
 * gap this block was built to catch is closed, and the block is kept because
 * the CLOSURE is the thing that can regress, and a block deleted with its
 * finding cannot report that.
 * ------------------------------------------------------------------------- */

/* The reference's own diagnostic code for one source, 0 when it accepts. The
 * call is nt_object_compile rather than nt_frontend_compile_object because
 * that is the entry the other oracle columns in this file grade through, and a
 * second route would answer a question about a different pipeline. */
static uint32_t reference_refusal_code(const char *source)
{
    NtFInput again = {"m", source, strlen(source)};
    NtObject canon;
    NtDiagnostic err;
    uint32_t code;
    memset(&canon, 0, sizeof canon);
    memset(&err, 0, sizeof err);
    if (nt_object_compile(&again, 1, &canon, &err)) { nt_object_free(&canon); return 0; }
    code = err.code;
    nt_object_free(&canon);
    return code;
}

/* Mode 1 for one source, with the produced byte count when it produced any. */
static uint64_t producer_mode1(const NovaHostImage *i, const char *source, uint64_t *bytes)
{
    static NtBuffer empty = {0};
    uint64_t code;
    *bytes = 0;
    memset(out_pe, guard, sizeof out_pe);
    code = run_mode(i, source, &empty, 1, NULL, out_pe, OUTCAP);
    if (code == 0) *bytes = r64(out_pe);
    return code;
}

/* Two counters, one per producer, so the attribution (what the C answers) and
 * the gap (what the producer answers with) are counted apart. A single column
 * would let a red producer read as a broken attribution, and the two are the
 * two things this block exists to say separately. */
static unsigned reference_disagreements, producer_disagreements;

static void flag_inference_pair(const NovaHostImage *i)
{
    /* The four texts differ ONLY in the two declaration clauses. The body is
     * `add rax, 1; return 1`, which is the smallest body that writes a flag,
     * so a leg cannot move for a reason the arithmetic did not cause. */
    static const char *const BODY = "add rax, 1\nreturn 1\n";
    static const char *const CALM = "mov rax, 1\nreturn 1\n"; /* the same body with no flag write */
    struct { const char *label; const char *effects; const char *clobbers;
             uint32_t want_reference; int want_producer_build; } leg[4] = {
        {"flag_neither_clause",        "effects {}\n",                 "clobbers {rax}\n",
         501u, 0},
        {"flag_changes_flags_alone",   "effects {changes_flags}\n",     "clobbers {rax}\n",
         502u, 0},
        {"flag_rflags_alone",          "effects {}\n",                 "clobbers {rax,rflags}\n",
         501u, 0},
        {"flag_both_clauses",          "effects {changes_flags}\n",     "clobbers {rax,rflags}\n",
         0u, 1}
    };
    unsigned k;
    char src[1024];

    /* THE CALM ROW, and it is the anchor for the other four rather than a fifth
     * case: a body that writes no flag is accepted by the reference with
     * `effects {}` and `clobbers {rax}` alone, so the 501 on the first leg is
     * attributable to `add` and to nothing else in the text. */
    snprintf(src, sizeof src,
             "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
             "export fn main()->u64\n%sclobbers {rax} {\n%s}\n}\n",
             "effects {}\n", CALM);
    cases++;
    CHECKL(reference_refusal_code(src) == 0,
           "flag: a body that writes no flag needs neither clause", "flag_calm_no_flag_write");
    {
        uint64_t bytes = 0;
        uint64_t code = producer_mode1(i, src, &bytes);
        CHECKL(code == 0 && bytes > 0, "producer builds the flag-free body",
               "flag_calm_no_flag_write");
    }

    for (k = 0; k < 4; k++) {
        uint32_t ref_code;
        uint64_t prod_code, bytes = 0;
        snprintf(src, sizeof src,
                 "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
                 "export fn main()->u64\n%s%s {\n%s}\n}\n",
                 leg[k].effects, leg[k].clobbers, BODY);
        ref_code = reference_refusal_code(src);
        cases++;
        if (ref_code != leg[k].want_reference) {
            failures++;
            reference_disagreements++;
            fprintf(stderr, "FAIL flag reference %s answered %u, want %u [%s]\n",
                    leg[k].label, ref_code, leg[k].want_reference,
                    leg[k].label);
        } else {
            fprintf(stderr, "FLAG_REFERENCE %-26s code=%u\n", leg[k].label, ref_code);
        }
        prod_code = producer_mode1(i, src, &bytes);
        if (leg[k].want_producer_build) {
            CHECKL(prod_code == 0 && bytes > 0,
                   "producer builds the text both clauses discharge", leg[k].label);
        } else {
            /* The producer-side half, and it was the half that was red when
             * this block was written; it is green now. It is stated as a
             * REFUSAL and not as a code, and that choice is now load bearing
             * rather than merely cautious: measured today the producer answers
             * 501 and 502 here, the same codes the reference uses, and it
             * answers 800 on the two STACK-PROOF refusals where the reference
             * says 503. Pinning any one of those numbers would turn a real
             * diagnostic-code change into a red row, and the thing this leg
             * asserts -- the producer declines what the reference declines --
             * survives all of them. */
            CHECKL(prod_code != 0, "producer refuses what the reference refuses", leg[k].label);
            if (prod_code == 0) {
                producer_disagreements++;
                fprintf(stderr, "FLAG_PRODUCER_BUILDS %-22s pe_bytes=%llu reference_code=%u\n",
                        leg[k].label, (unsigned long long)bytes, ref_code);
            }
        }
    }
    /* Two columns, because one would be a claim this block cannot support: the
     * REFERENCE legs are the attribution and they are answered by the C, and
     * the PRODUCER legs are the gap. Printing a single verdict would let a
     * red producer read as a broken attribution. */
    fprintf(stderr, "FLAG_SUMMARY legs=4 reference_disagreements=%u producer_disagreements=%u\n",
            reference_disagreements, producer_disagreements);
}

static void refuse_short(const NovaHostImage *i, const char *source, size_t cap, const char *label)
{
    static NtBuffer empty = {0};
    static uint8_t small[128];
    size_t j;
    int intact;
    uint64_t code;
    if (cap > sizeof small) { CHECK(0, "short cap fits"); return; }
    memset(small, guard, sizeof small);
    code = run_mode(i, source, &empty, 1, NULL, small, cap);
    intact = code == 827;
    for (j = 0; j < cap; j++) intact &= small[j] == guard;
    CHECK(intact, label);
}

/* ==========================================================================
 * THE TWELVE TEMPORARY FILES OF THIS GATE, AND THE ONE DIRECTORY THEY LIVE IN.
 *
 * WHAT WAS HERE, verbatim, and it is quoted because the defect is easier to
 * recognise than to describe: twelve string literals, /tmp/ng-nova-*.efi,
 * identical in every run on every machine, remove()d and rewritten by every
 * run. Two of the twelve are the load-bearing ones. write_refused's whole
 * property is that a REFUSAL CREATES NO FILE, and it measured that by
 * remove(path); fopen(path); CHECK(f == NULL) -- so on a shared path a second
 * run's file made the first run's refusal look like a write, and the gate went
 * red for a reason that was not the producer. write_sized_no_overwrite is the
 * same shape from the other side. The checks were never wrong. The paths they
 * were measured on belonged to every run at once.
 *
 * WHY A TABLE AND NOT TWELVE ng_run_file CALLS AT TWELVE CALL SITES: the
 * census below has to be about the paths the fixtures ACTUALLY use, and a
 * census of a second list beside the real one is a census of nothing. The
 * names live here, the resolved paths live here, and the fixtures read
 * run_file[RF_...]. There is one list and it is the one that is checked.
 *
 * NAMES ARE BARE, and ng_run_name_is_bare refuses anything else, which is the
 * guard that stops this defect coming back through the new door: an absolute
 * path here would build a directory, print a path, and write the file outside
 * it -- the shared path again, one indirection deeper and looking tidier.
 */
enum { RF_WRITTEN_SINGLE, RF_WRITTEN_CALL, RF_REFUSED, RF_REFUSED2,
       RF_SIZED_LOOP, RF_SIZED_DECLARED, RF_SIZED_REFUSED, RF_SIZED_SHORT,
       RF_SIZED_TWICE, RF_LINKED_825, RF_LINKED_800, RF_PROBE_830, RF_COUNT };

static const char *const RUN_FILE_NAMES[RF_COUNT] = {
    "written-single.efi", "written-call.efi", "refused.efi", "refused2.efi",
    "sized-loop.efi", "sized-declared.efi", "sized-refused.efi",
    "sized-short.efi", "sized-twice.efi", "linked-825.efi",
    "linked-800.efi", "830-probe.efi"
};
static char run_file[RF_COUNT][NG_RUN_DIR_MAX];
/* 1 only when every one of the twelve resolved. A fixture that is handed a
 * path this gate does not own is SKIPPED, not run against an empty string:
 * write_refused against "" would pass its "creates no file" expectation for
 * the wrong reason, and a check that passes for the wrong reason is the exact
 * shape this project has spent the night removing. The run is already red --
 * run_files_open says so on stderr by name -- and it stays red here rather
 * than going quietly green on an empty path. */
static int run_files_ready;

/* Opens the run's own directory, resolves the twelve names inside it, and
 * asserts the four properties that make the isolation a MEASUREMENT rather
 * than a promise. Four checks, and the count of them is stated in the report
 * because a reader comparing this gate's checks= against yesterday's needs to
 * know that the difference is exactly these and not a lost fixture.
 *
 *   1. the run owns a private temporary directory   -- the mkdir succeeded
 *   2. every name is bare                            -- no absolute path can be
 *                                                      reintroduced through
 *                                                      this table
 *   3. every resolved path is inside that directory -- the twelve are where
 *                                                      this run's directory
 *                                                      says they are
 *   4. the twelve paths are pairwise distinct         -- two fixtures naming
 *                                                      the same file would
 *                                                      collide WITHIN a run,
 *                                                      which no amount of
 *                                                      per-run isolation
 *                                                      would prevent
 *
 * 2, 3 and 4 are stated about the table and not about a run of the fixtures,
 * which is deliberate: they are properties of the NAMES, they hold whether or
 * not the fixtures that use them are reached, and they would still be true of
 * a future thirteenth row added to RUN_FILE_NAMES without a thought about
 * isolation. */
static void run_files_open(void)
{
    char why[NG_RUN_DIR_MAX];
    const char *d = ng_run_dir(why, sizeof why);
    unsigned i, j;
    int bare = 1, inside = 1, distinct = 1, built = 1;
    size_t dlen;

    CHECK(d != NULL, "the run owns a private temporary directory");
    if (!d) {
        fprintf(stderr, "FAIL TEMP-ISOLATION no run directory: %s\n", why);
        return;
    }
    dlen = strlen(d);
    fprintf(stderr, "RUN_DIR %s\n", d);
    for (i = 0; i < (unsigned)RF_COUNT; i++) {
        char w[NG_RUN_DIR_MAX];
        run_file[i][0] = 0;
        /* BEFORE the call, and that order is the only reason this check is
         * worth having. ng_run_file REFUSES a name that is not bare, so a test
         * written after it could never fail: every non-bare name would already
         * have taken the `continue` below and left `bare` at 1. A check that
         * cannot fail is not a check, and a green read off one is the exact
         * mistake this project has paid for four times tonight. Asked FIRST,
         * the question has an answer either way -- and if the guard in the
         * header is ever weakened, this is the line that says so.
         *
         * PERTURBATION, run once, by hand: a name of "/tmp/ng-nova-back.efi"
         * in the table turns this red AND leaves run_files_ready at 0, so the
         * twelve file fixtures are skipped rather than run against a path
         * outside the run directory. Without the reorder the same perturbation
         * leaves the banner green on a file written to /tmp. */
        if (!ng_run_name_is_bare(RUN_FILE_NAMES[i])) bare = 0;
        if (!ng_run_file(RUN_FILE_NAMES[i], run_file[i], sizeof run_file[i], w,
                         sizeof w)) {
            fprintf(stderr, "FAIL TEMP-ISOLATION %.64s %s\n", RUN_FILE_NAMES[i], w);
            built = 0;
            continue;
        }
        if (strncmp(run_file[i], d, dlen) != 0 || run_file[i][dlen] != '/') inside = 0;
        for (j = 0; j < i; j++)
            if (run_file[j][0] && strcmp(run_file[i], run_file[j]) == 0) distinct = 0;
    }
    CHECK(bare, "every temporary name in this gate is a bare file name");
    CHECK(inside, "every temporary file this gate writes is inside the run's own directory");
    CHECK(distinct, "the twelve temporary files have twelve different paths");
    run_files_ready = built;
}

/* Writes a PE to a file with no C driver in the middle, then reads it back and
 * puts it through the QEMU structural contract and the byte comparison against
 * the in memory PE of the same fixture. The file lives in THIS RUN's own
 * directory -- the one named at run_files_open, under NG_BUILD when the driver
 * supplied one -- and the runtime opens it exclusively. The sentence this
 * replaces said "the build directory", which was never true of the code: the
 * path was the fixed literal /tmp/ng-nova-*.efi. The intent was right and the
 * code did not implement it, and a comment describing the intent while the
 * code does the opposite is worse than no comment. */
static void write_and_check(const NovaHostImage *i, const char *source, const char *label,
                            const char *path)
{
    static NtBuffer empty = {0};
    static uint8_t memory_pe[OUTCAP];
    static uint8_t file_pe[OUTCAP];
    uint64_t code, memory_size, file_size;
    size_t got;
    FILE *f;
    uint32_t entry_rva = 0;
    int validated;

    remove(path);
    code = run_mode(i, source, &empty, 3, path, memory_pe, OUTCAP);
    CHECKL(code == 0, "mode 3 writes the PE", label);
    if (code != 0) return;
    fprintf(stderr, "WROTE %s %s\n", label, path);

    memset(memory_pe, guard, sizeof memory_pe);
    code = run_mode(i, source, &empty, 1, NULL, memory_pe, OUTCAP);
    CHECKL(code == 0, "mode 1 still returns the PE", label);
    if (code != 0) return;
    memory_size = r64(memory_pe);

    memset(file_pe, guard, sizeof file_pe);
    f = fopen(path, "rb");
    CHECKL(f != NULL, "written file is readable", label);
    if (!f) return;
    got = fread(file_pe, 1, sizeof file_pe, f);
    fclose(f);
    file_size = (uint64_t)got;
    CHECKL(file_size == memory_size && !memcmp(file_pe, memory_pe + 8, (size_t)memory_size),
           "file bytes equal the in memory PE", label);
    validated = ng_pe_validate(file_pe, (size_t)file_size, 0, &entry_rva);
    CHECKL(validated == NG_PE_OK, "written file passes ng_pe_validate", label);
    fprintf(stderr, "WROTE %s bytes=%llu entry_rva=0x%08lx validate=%d\n", label,
            (unsigned long long)file_size, (unsigned long)entry_rva, validated);
    remove(path);
}

/* A rejected source must not create the file it was pointed at. */
static void write_refused(const NovaHostImage *i, const char *source, const char *label,
                          const char *path, uint64_t want)
{
    static NtBuffer empty = {0};
    static uint8_t out[64];
    uint64_t code;
    FILE *f;
    memset(out, guard, sizeof out);
    remove(path);
    code = run_mode(i, source, &empty, 3, path, out, sizeof out);
    CHECK(code == want, label);
    f = fopen(path, "rb");
    CHECK(f == NULL, "refused write created no file");
    if (f) { fclose(f); remove(path); }
    fprintf(stderr, "WRITE_REFUSED %s code=%llu\n", label, (unsigned long long)code);
}

/* ------------------------------------------------------------------ *
 * The cross producer link, and the named blocker behind it
 * ------------------------------------------------------------------ */

/* The program this lot adds to the covered set: four functions, a call inside a
 * counted backward loop, and a nested call chain inside that loop. The loop
 * counter lives in rbx, a non volatile ms_abi register, because the call inside
 * the loop would destroy a volatile one. The C frontend REFUSES this fixture
 * rather than being unable to parse it: measured, 400 "return value required"
 * on this exact text, and 502 "omits an inferred clobber" once every bare
 * return is given a value and `changes_flags`/`{rax,rbx}` are declared on
 * every function. Removing both `call` statements does not change that
 * answer, so the call is not what it objects to: it objects to the two flag
 * obligations of the `add` and the `sub`, which is `changes_flags` AND
 * `rflags` on every function containing one, plus a value on every return.
 * No parity is claimed. The declaration it accepts is MEASURED, not
 * unidentified, and the measurements are at the accept() call site for
 * call_inside_a_counted_loop.
 */
static const char *CALL_IN_LOOP =
    "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
    "export fn main()->u64\neffects {}\nclobbers {} {\n"
    "call seed()\nmov rbx, 6\njmp body\ndead:\nmov rax, 99\nbody:\ntop:\n"
    "call step()\nadd rax, 1\nsub rbx, 1\njne top\njmp done\ndone:\nreturn\n}\n"
    "fn seed()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n"
    "fn step()->u64\neffects {}\nclobbers {} {\ncall twice()\nadd rax, 1\nreturn\n}\n"
    "fn twice()->u64\neffects {}\nclobbers {} {\nmov rax, 4\nadd rax, 1\nreturn\n}\n}\n";

/* THE SOURCE THE TWO FILE-BOUNDARY PROPERTIES RUN ON, and the reason it is not
 * CALL_IN_LOOP is the whole finding this constant records.
 *
 * A refused exclusive open is a property of the HOST BOUNDARY, not of one
 * program. rt_open_new opens with "wbx" (runtime_v2.c:253) whatever the source
 * is, so the refusal is available to EVERY source the producer accepts. These
 * two blocks used to hand it CALL_IN_LOOP, which the producer refuses (with
 * 501 as of the re-measurement below; it was recorded as 800 when this was
 * written, and the shape of the finding -- the setup line fails, the function
 * returns, the properties never run -- is the same either way),
 * so the setup line failed, the function returned before its own assertions,
 * and BOTH properties were reported by a check that never ran -- at a count
 * that stayed honest, because a check that never executes never increments.
 *
 * MEASURED, not assumed, and measured over the whole accepted corpus rather
 * than over one convenient source: this exact text is the two_functions_one_call
 * fixture the gate already compares byte for byte against the C oracle
 * (ORACLE_COMPARED, 3584 bytes), so the source is known-accepted on independent
 * evidence rather than on the say-so of the block that uses it. */
static const char *ACCEPTED_ONE_CALL =
    "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
    "export fn main()->u64\neffects {}\nclobbers {} {\ncall target()\nreturn 0\n}\n"
    "fn target()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\n}\n";

/* A module declaring nothing but the one exported function whose contract is
 * measured, so nt_object_compile can name that function without the rest of the
 * program.
 *
 * The export is `main`, in lockstep with LINK_FIXTURE below. The check that the
 * two fixtures qualify to the SAME name is what couples them, so renaming one
 * and not the other would leave the gate comparing two different symbols and
 * would go red for the right reason. */
static const char *ENTRY_ONLY =
    "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
    "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";

/* The cross producer fixture: one exported function and one local callee. An
 * import can only be resolved by an exported definition, so the measured symbol
 * is the exported one, not a local helper.
 *
 * The export is `main` because a PE cannot exist without an entry, for the
 * reason given at the refuse_short calls below. AND THE RENAME MOVES THE
 * ENTRY, which is the part a mechanical rename gets wrong: as `entry` the
 * reference ordered entry@0, helper@658, so the export sat first and the entry
 * text offset was 0. As `main`, "main" sorts AFTER "helper", so the reference
 * orders helper@0, main@11 -- entry_symbol 2, entry text offset 11, PE 3584
 * bytes, all measured on the reference for this exact source. linked_accept's
 * expected RVA is derived from that through the same reference_entry_offset
 * machinery the other fixtures use, so it is re-derived rather than typed. */
static const char *LINK_FIXTURE =
    "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
    "export fn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n"
    "fn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n}\n";


static char *dup_text(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    char *copy = malloc(n + 1);
    if (!copy) { CHECK(0, "text copy allocated"); return NULL; }
    if (n) memcpy(copy, s, n);
    copy[n] = 0;
    return copy;
}

/* An import only definition object for `name`, carrying `contract` verbatim as
 * that symbol's contract. nt_object_write is the C reference writer, so the
 * bytes handed to Nova are bytes a C producer would emit. object.c requires an
 * import symbol to carry no section, no offset and no size, which is also why
 * such a definition contributes no code of its own to the merged object. */
static NtBuffer import_definition(const char *name, const char *contract)
{
    NtObjectSymbol symbol;
    NtObject object;
    NtBuffer file = {0};
    NtDiagnostic error = {0};
    memset(&symbol, 0, sizeof symbol);
    symbol.name = (char *)name;
    symbol.contract = (char *)contract;
    symbol.section = 0;
    symbol.flags = NT_OBJECT_IMPORT | NT_OBJECT_FUNCTION;
    memset(&object, 0, sizeof object);
    object.target = 1;
    object.symbols = &symbol;
    object.symbol_count = 1;
    CHECK(nt_object_write(&object, &file, &error), "C write of the import only definition");
    if (!file.bytes)
        fprintf(stderr, "DEFINITION_REFUSED name=%s code=%u %s\n", name, error.code,
                error.message);
    return file;
}

/* The module a fixture source declares, read back out of the SOURCE TEXT.
 *
 * The reference forms a qualified name in exactly one place, object_build.c:305
 * inside nt_object_compile:
 *
 *     snprintf(order[j].symbol.name, mn + sn + 2, "%s.%s", s->module, s->name);
 *
 * and object_build.c:213 sorts on that same string while object.c:65 refuses a
 * non ascending table, so the qualified name is the object's IDENTITY rather
 * than a decoration. s->module is the source's own `module` declaration, not
 * the unit name the caller hands nt_frontend_compile_object, so the module is
 * a property of the fixture and is read back out of it. */
static int fixture_module(const char *source, char *out, size_t room)
{
    size_t i = 0, start;
    while (source[i] == ' ' || source[i] == '\t') i++;
    if (strncmp(source + i, "module", 6) != 0) return 0;
    i += 6;
    if (source[i] != ' ' && source[i] != '\t') return 0;
    while (source[i] == ' ' || source[i] == '\t') i++;
    start = i;
    while (source[i] && source[i] != '\n' && source[i] != ' ' && source[i] != '\t') i++;
    if (i == start || i - start + 1 > room) return 0;
    memcpy(out, source + start, i - start);
    out[i - start] = 0;
    return 1;
}

/* The name the reference would actually emit for `name` in `source`: the
 * reference's own rule applied to the fixture's own declaration.
 *
 * This is deliberately NOT a literal such as "m.entry", which would be the
 * same class of staleness as the bare "entry" this replaced: rename the
 * fixture's module and the expectation moves with it. It is also deliberately
 * not a substring, suffix or wildcard search: those would find the symbol
 * whether the module is right or wrong, and the point of the comparison is the
 * module. Name against name is strictly stronger -- under a tail match a
 * producer that qualified with the WRONG module still passes, and here it
 * does not, because a wrong module is not this name. */
static int qualified_symbol(const char *source, const char *name, char *out, size_t room)
{
    char module[64];
    int n;
    if (!fixture_module(source, module, sizeof module)) return 0;
    n = snprintf(out, room, "%s.%s", module, name);
    return n > 0 && (size_t)n < room;
}

/* The two byte placeholder the producer used to write, kept as a named value
 * so the refusal it earns is a measurement and not a forgotten string. */
static const char placeholder[] = "v0";

/* The contract string the C reference builder writes for the qualified `name`,
 * read out of nt_object_compile. The match is the whole name the reference
 * wrote, not its tail, so it cannot be satisfied by a different module. */

static char *canonical_contract(const char *source, const char *name)
{
    NtFInput input = {"m", source, strlen(source)};
    NtObject object;
    NtDiagnostic error;
    char *found = NULL;
    size_t k;
    memset(&object, 0, sizeof object);
    memset(&error, 0, sizeof error);
    if (!nt_object_compile(&input, 1, &object, &error)) {
        fprintf(stderr, "CANONICAL_REFUSED code=%u %s\n", error.code, error.message);
        return NULL;
    }
    for (k = 0; k < object.symbol_count && !found; k++)
        if (object.symbols[k].name && !strcmp(object.symbols[k].name, name))
            found = dup_text(object.symbols[k].contract);
    if (!found) fprintf(stderr, "CANONICAL_MISSING name=%s\n", name);
    nt_object_free(&object);
    return found;
}

/* The contract string the producer itself writes for `name`, read back out of
 * its own NXO bytes through the frozen C reader. The short form is measured
 * here, not assumed, so the two definitions compared below differ in nothing
 * but the one field under test. */
static char *producer_contract(const NovaHostImage *i, const char *source, const char *name)
{
    static NtBuffer empty = {0};
    static uint8_t nxo[OUTCAP];
    NtObject object;
    NtDiagnostic error;
    char *found = NULL;
    size_t k;
    uint64_t code, size;
    memset(nxo, guard, sizeof nxo);
    code = run_mode(i, source, &empty, 2, NULL, nxo, OUTCAP);
    if (code != 0) {
        fprintf(stderr, "PRODUCER_NXO_REFUSED code=%llu\n", (unsigned long long)code);
        return NULL;
    }
    size = r64(nxo);
    memset(&object, 0, sizeof object);
    memset(&error, 0, sizeof error);
    if (!nt_object_read(nxo + 8, (size_t)size, &object, &error)) {
        fprintf(stderr, "PRODUCER_NXO_UNREADABLE code=%u %s\n", error.code, error.message);
        return NULL;
    }
    for (k = 0; k < object.symbol_count && !found; k++)
        if (object.symbols[k].name && !strcmp(object.symbols[k].name, name))
            found = dup_text(object.symbols[k].contract);
    if (!found) fprintf(stderr, "PRODUCER_SYMBOL_MISSING name=%s\n", name);
    nt_object_free(&object);
    return found;
}

/* Mode 4 with a definition the merge accepts: the link resolves and the result
 * is a PE the QEMU structural contract accepts.
 *
 * `preceding` is the list of functions that sort before the export, in
 * reference name order, and the expected RVA is DERIVED from it the same way
 * accept() derives one. It used to be the literal 4096 with a comment spelling
 * out "the exported .text offset 0", which is a frozen copy of a derived value
 * that happened to be zero because the one fixture reaching here sorted its
 * export first. That made the check an instrument exercised in exactly one
 * state: it could not tell the reference's answer from a typed zero. */
static void linked_accept(const NovaHostImage *i, const char *source, const NtBuffer *definition,
                          const char *label, const char *const *preceding)
{
    static uint8_t pe[OUTCAP];
    uint64_t code, size, expected_offset;
    uint32_t entry_rva = 0;
    int validated;
    memset(pe, guard, sizeof pe);
    code = run_mode(i, source, definition, 4, NULL, pe, OUTCAP);
    CHECKL(code == 0, "mode 4 resolves the cross producer link", label);
    if (code != 0) {
        fprintf(stderr, "LINKED_REFUSED %s code=%llu\n", label, (unsigned long long)code);
        return;
    }
    size = r64(pe);
    CHECKL(size > 0 && size + 8 <= OUTCAP, "linked PE size fits", label);
    validated = ng_pe_validate(pe + 8, (size_t)size, 0, &entry_rva);
    CHECKL(validated == NG_PE_OK, "linked PE passes ng_pe_validate", label);
    expected_offset = reference_entry_offset(label, preceding);
    if (expected_offset == UINT64_MAX) {
        CHECKL(0, "the reference gives the linked entry an offset", label);
        return;
    }
    CHECKL((uint64_t)entry_rva == 4096 + expected_offset,
           "linked entry RVA is 4096 plus the reference's exported .text offset", label);
    fprintf(stderr, "LINKED %s code=%llu bytes=%llu entry_rva=0x%08lx offset=%llu validate=%d\n",
            label, (unsigned long long)code, (unsigned long long)size, (unsigned long)entry_rva,
            (unsigned long long)expected_offset, validated);
}

/* Mode 4 with a definition the merge refuses: the code is the refusal and no
 * byte of the output buffer moves. */
static void linked_refuse(const NovaHostImage *i, const char *source, const NtBuffer *definition,
                          const char *label, uint64_t want)
{
    static uint8_t pe[OUTCAP];
    uint64_t code;
    size_t j;
    int intact;
    memset(pe, guard, sizeof pe);
    code = run_mode(i, source, definition, 4, NULL, pe, OUTCAP);
    intact = code == want;
    for (j = 0; j < OUTCAP; j++) intact &= pe[j] == guard;
    CHECKL(intact, label, "linked refusal");
    if (intact)
        fprintf(stderr, "LINKED_REFUSED %s code=%llu\n", label, (unsigned long long)code);
}

/* Mode 5: the cross producer link, straight to a file. The merge has already
 * refused by the time a path could be opened, so nothing appears on disk. */
static void write_linked_refused(const NovaHostImage *i, const char *source,
                                 const NtBuffer *definition, const char *label,
                                 const char *path, uint64_t want)
{
    static uint8_t out[64];
    uint64_t code;
    FILE *f;
    memset(out, guard, sizeof out);
    remove(path);
    code = run_mode(i, source, definition, 5, path, out, sizeof out);
    CHECK(code == want, label);
    f = fopen(path, "rb");
    CHECK(f == NULL, "refused linked write created no file");
    if (f) { fclose(f); remove(path); }
    fprintf(stderr, "WRITE_LINKED_REFUSED %s code=%llu\n", label, (unsigned long long)code);
}

/* Mode 6: the self contained route to a file, plus the byte count Nova itself
 * computed. That count is compared with the length of the file on disk and with
 * the in memory PE of mode 1, so a producer reporting a size it did not write
 * could not pass here. */
static void write_sized(const NovaHostImage *i, const char *source, const char *label,
                        const char *path)
{
    static NtBuffer empty = {0};
    static uint8_t reported[64];
    static uint8_t memory_pe[OUTCAP];
    static uint8_t file_pe[OUTCAP];
    uint64_t code, claimed, memory_size, file_size;
    size_t got;
    uint32_t entry_rva = 0;
    FILE *f;

    memset(reported, guard, sizeof reported);
    memset(memory_pe, guard, sizeof memory_pe);
    remove(path);
    code = run_mode(i, source, &empty, 6, path, reported, sizeof reported);
    CHECKL(code == 0, "mode 6 writes the PE", label);
    if (code != 0) return;
    claimed = r64(reported);
    CHECKL(reported[8] == guard, "mode 6 wrote only the eight size bytes", label);

    code = run_mode(i, source, &empty, 1, NULL, memory_pe, OUTCAP);
    CHECKL(code == 0, "mode 1 still returns the PE", label);
    if (code != 0) return;
    memory_size = r64(memory_pe);

    f = fopen(path, "rb");
    CHECKL(f != NULL, "written file is readable", label);
    if (!f) return;
    got = fread(file_pe, 1, sizeof file_pe, f);
    fclose(f);
    file_size = (uint64_t)got;
    CHECKL(claimed == file_size, "producer byte count equals the file length", label);
    CHECKL(claimed == memory_size && !memcmp(file_pe, memory_pe + 8, (size_t)memory_size),
           "file bytes equal the in memory PE", label);
    CHECKL(ng_pe_validate(file_pe, (size_t)file_size, 0, &entry_rva) == NG_PE_OK,
           "written file passes ng_pe_validate", label);
    fprintf(stderr, "WROTE_SIZED %s bytes=%llu entry_rva=0x%08lx\n", label,
            (unsigned long long)file_size, (unsigned long)entry_rva);
    remove(path);
}

/* Mode 6 with a source the producer refuses: the report buffer keeps its
 * previous content and no file appears. */
static void write_sized_refused(const NovaHostImage *i, const char *source, const char *label,
                                const char *path, uint64_t want)
{
    static NtBuffer empty = {0};
    static uint8_t reported[64];
    uint64_t code;
    size_t j;
    int intact;
    FILE *f;
    memset(reported, guard, sizeof reported);
    remove(path);
    code = run_mode(i, source, &empty, 6, path, reported, sizeof reported);
    intact = code == want;
    for (j = 0; j < sizeof reported; j++) intact &= reported[j] == guard;
    CHECK(intact, label);
    f = fopen(path, "rb");
    CHECK(f == NULL, "refused sized write created no file");
    if (f) { fclose(f); remove(path); }
    fprintf(stderr, "WRITE_SIZED_REFUSED %s code=%llu\n", label, (unsigned long long)code);
}

/* A report buffer shorter than the eight size bytes is refused before the
 * producer runs, so no file is created either. */
static void write_sized_short(const NovaHostImage *i, const char *source, const char *label,
                              const char *path)
{
    static NtBuffer empty = {0};
    static uint8_t reported[4];
    uint64_t code;
    FILE *f;
    memset(reported, guard, sizeof reported);
    remove(path);
    code = run_mode(i, source, &empty, 6, path, reported, sizeof reported);
    CHECK(code == 827, label);
    f = fopen(path, "rb");
    CHECK(f == NULL, "short report write created no file");
    if (f) { fclose(f); remove(path); }
    fprintf(stderr, "WRITE_SIZED_SHORT %s code=%llu\n", label, (unsigned long long)code);
}

/* The runtime opens a path exclusively and refuses to overwrite, so a second
 * write of the same PE is refused and must leave the first file byte for byte as
 * it was. The refusal is observed as NV2_IO on the context: a raised runtime
 * error forces the entry's return value to 0 at the host boundary, so the code
 * this call returns is reported and not asserted. What is asserted is that the
 * refusal happened, that no report byte was written and that not one byte of the
 * file moved. */
static void write_sized_no_overwrite(const NovaHostImage *i, const char *source, const char *label,
                                     const char *path)
{
    static NtBuffer empty = {0};
    static uint8_t first[64];
    static uint8_t second[64];
    static uint8_t file_pe[OUTCAP];
    static uint8_t again[OUTCAP];
    uint64_t code;
    size_t got, got2, j;
    int unchanged = 1;
    FILE *f;
    memset(first, guard, sizeof first);
    memset(second, guard, sizeof second);
    remove(path);
    code = run_mode(i, source, &empty, 6, path, first, sizeof first);
    /* SETUPL, not CHECKL: if this is false the function returns on the next line
     * and the two assertions that are the entire point of this block -- that the
     * refused overwrite wrote no report byte, and that it moved no byte of the
     * file -- never execute. A FAIL here used to stand for all three. */
    SETUPL(code == 0, "first sized write succeeds", label);
    if (code != 0) return;
    f = fopen(path, "rb");
    if (!f) { CHECK(0, "first file is readable"); return; }
    got = fread(file_pe, 1, sizeof file_pe, f);
    fclose(f);
    CHECKL((uint64_t)got == r64(first), "reported count equals the first file length", label);
    code = run_mode_refused(i, source, &empty, 6, path, second, sizeof second, NV2_IO);
    for (j = 0; j < sizeof second; j++) unchanged &= second[j] == guard;
    CHECKL(unchanged, "the refused overwrite wrote no report byte", label);
    memset(again, guard, sizeof again);
    f = fopen(path, "rb");
    if (!f) { CHECK(0, "file readable after the refused write"); return; }
    got2 = fread(again, 1, sizeof again, f);
    fclose(f);
    CHECKL(got2 == got && !memcmp(again, file_pe, got),
           "the refused overwrite changed no byte of the file", label);
    fprintf(stderr, "WROTE_NO_OVERWRITE %s bytes=%zu second_code=%llu second_error=NV2_IO\n",
            label, got, (unsigned long long)code);
    remove(path);
}

/* ------------------------------------------------------------------ *
 * Canonical data layout oracle for the link fixture
 *
 * The left hand object of the link fixture used to be hand built, with .rdata
 * written as the three bytes 34 12 2a and alpha at offset 2. That is the
 * pre-spec layout, items packed back to back in declaration order, and
 * nt_object_write is a pure serialiser: it copies the section bytes the caller
 * hands it, so the fixture could never observe a layout divergence and simply
 * confirmed whatever the producer emitted. The data half of the object is now
 * taken from the C frontend and codegen, nt_frontend_compile_object +
 * nt_codegen_x64_object + nt_object_write, which lays items out by ascending
 * byte-wise unsigned name and aligns each one to min(width,8) exactly as
 * spec/formats/nxo-v0.md requires. The .text half stays the producer's own documented
 * instruction stream, encoded by nt_x64_encode, the C x64 oracle: the C frontend
 * cannot express a call to an unresolved import followed by a bare ret, so no C
 * parity is claimed for it. The assembled object is cross checked field by field
 * against the data half of nt_object_compile, the canonical builder of the same
 * C frontend, so the expectation is proven to carry the canonical layout rather
 * than asserted to.
 *
 * One row per fixture, verbatim:
 *   DATA <label> scope=data pe_rdata=<n> pe_data=<n> C_rdata=<n> C_data=<n>
 *        C_off=<name@off,...> verdict=IDENTICAL|DIVERGES first=<n> <detail>
 * The entry under test emits a PE, so the producer's own layout is read back out
 * of the produced image: the .rdata and .data section payloads. A symbol offset
 * is a function of exactly that layout, so a payload matching the canonical
 * payload carries the canonical offsets. pe_layout.h is the authority for the
 * two offsets used to find them: nt_pe_logical_rva puts section 2 at rdata+8, so
 * .rdata carries an eight byte anchor, and nt_pe_layout reserves eight bytes for
 * .data when the payload is empty.
 * ------------------------------------------------------------------ */

typedef struct { const char *name; size_t index; } Ng5NameOrder;
static int ng5_name_compare(const void *x, const void *y)
{
    int order = strcmp(((const Ng5NameOrder *)x)->name, ((const Ng5NameOrder *)y)->name);
    if (order) return order;
    return ((const Ng5NameOrder *)x)->index < ((const Ng5NameOrder *)y)->index ? -1 : 1;
}
static const char *ng5_tail_of(const char *name)
{
    const char *dot = strrchr(name, '.');
    return dot ? dot + 1 : name;
}
static int ng5_is_data(const NtObjectSymbol *s)
{
    return s->section == NT_OBJECT_RDATA || s->section == NT_OBJECT_DATA;
}
static void ng5_offsets_of(const NtObject *o, char *dst, size_t room)
{
    size_t used = 0, j;
    dst[0] = 0;
    for (j = 0; j < o->symbol_count; j++) {
        int n;
        if (!ng5_is_data(o->symbols + j)) continue;
        n = snprintf(dst + used, room - used, "%s%s@%llu", used ? "," : "", o->symbols[j].name,
                     (unsigned long long)o->symbols[j].offset);
        if (n < 0 || (size_t)n >= room - used) break;
        used += (size_t)n;
    }
}
/* Field by field equality of the data half, names matched on their unqualified
 * tail so a module qualified canonical table and bare source names can be
 * walked independently. */
static int ng5_data_half_match(const NtObject *a, const NtObject *b, char *detail, size_t room)
{
    size_t j, k, da = 0, db = 0;
    detail[0] = 0;
    if (a->sections[1].size != b->sections[1].size ||
        a->sections[2].size != b->sections[2].size) {
        snprintf(detail, room, "payload size %zu/%zu and %zu/%zu",
                 a->sections[1].size, b->sections[1].size,
                 a->sections[2].size, b->sections[2].size);
        return 0;
    }
    if ((a->sections[1].size && memcmp(a->sections[1].bytes, b->sections[1].bytes, a->sections[1].size)) ||
        (a->sections[2].size && memcmp(a->sections[2].bytes, b->sections[2].bytes, a->sections[2].size))) {
        snprintf(detail, room, "payload bytes differ");
        return 0;
    }
    for (j = 0; j < a->symbol_count; j++) if (ng5_is_data(a->symbols + j)) da++;
    for (j = 0; j < b->symbol_count; j++) if (ng5_is_data(b->symbols + j)) db++;
    if (da != db) { snprintf(detail, room, "data symbol count %zu vs %zu", da, db); return 0; }
    for (j = 0; j < a->symbol_count; j++) {
        if (!ng5_is_data(a->symbols + j)) continue;
        for (k = 0; k < b->symbol_count; k++) {
            if (!ng5_is_data(b->symbols + k)) continue;
            if (strcmp(ng5_tail_of(a->symbols[j].name), ng5_tail_of(b->symbols[k].name))) continue;
            if (a->symbols[j].section != b->symbols[k].section ||
                a->symbols[j].offset != b->symbols[k].offset ||
                a->symbols[j].size != b->symbols[k].size ||
                a->symbols[j].flags != b->symbols[k].flags) {
                snprintf(detail, room, "%s sec=%u/%u off=%llu/%llu size=%llu/%llu flags=%u/%u",
                         a->symbols[j].name, a->symbols[j].section, b->symbols[k].section,
                         (unsigned long long)a->symbols[j].offset,
                         (unsigned long long)b->symbols[k].offset,
                         (unsigned long long)a->symbols[j].size,
                         (unsigned long long)b->symbols[k].size,
                         a->symbols[j].flags, b->symbols[k].flags);
                return 0;
            }
            break;
        }
        if (k == b->symbol_count) {
            snprintf(detail, room, "%s absent from the C table", a->symbols[j].name);
            return 0;
        }
    }
    return 1;
}

/* The canonical C object of a source: nt_frontend_compile_object +
 * nt_codegen_x64_object + nt_object_write, assembled with bare source names the
 * way the Nova producer writes them, and cross checked against nt_object_compile
 * on every layout field before it is handed back. */
typedef struct { int ok; NtObject canonical; char *alias_contract; char why[256]; } Ng5Reference;
static void ng5_reference_free(Ng5Reference *r)
{
    if (r->canonical.symbols) nt_object_free(&r->canonical);
    free(r->alias_contract);
    r->alias_contract = NULL;
    r->ok = 0;
}
/* The definition the cross producer link resolves against: one exported
 * function named `alias` in the same target, carrying the contract the C object
 * writer builds for that declaration. The Nova producer writes the bare alias
 * as the import name, so the C object is renamed to it and nothing else
 * changes, which isolates the contract field as the only variable. */
static char *ng5_alias_contract(const char *target, const char *alias)
{
    static char storage[512];
    int n = snprintf(storage, sizeof storage,
                     "module d\ntarget x86_64-nexora-%s\nsection .text {\n"
                     "export fn %s()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
                     target, alias);
    if (n <= 0 || (size_t)n >= sizeof storage) return NULL;
    return c_contract(storage, alias);
}
static int ng5_reference_for(const char *source, Ng5Reference *ref)
{
    NtFInput input = {"m", source, strlen(source)};
    NtFInput again = {"m", source, strlen(source)};
    NtFProgram program;
    NtCodeImage image;
    NtCodeDiagnostic cd;
    NtDiagnostic error;
    size_t j, exported = 0, total;
    NtObjectSymbol *symbols, *sorted;
    NtObjectReloc *relocs;
    Ng5NameOrder *order;
    char (*names)[512];
    uint32_t entry = 0;

    memset(ref, 0, sizeof *ref);
    memset(&program, 0, sizeof program);
    memset(&image, 0, sizeof image);
    memset(&cd, 0, sizeof cd);
    memset(&error, 0, sizeof error);
    /* the canonical builder runs first: its contracts are what the hand
     * assembly below has to carry */
    if (!nt_object_compile(&again, 1, &ref->canonical, &error)) {
        snprintf(ref->why, sizeof ref->why, "nt_object_compile %u %s", error.code,
                 error.message);
        return 0;
    }
    if (!nt_frontend_compile_object(&input, 1, &program)) {
        snprintf(ref->why, sizeof ref->why, "frontend %u %s",
                 program.diagnostic_count ? program.diagnostics[0].code : 0u,
                 program.diagnostic_count ? program.diagnostics[0].message : "no diagnostic");
        nt_frontend_free(&program);
        nt_object_free(&ref->canonical);
        return 0;
    }
    if (!nt_codegen_x64_object(&program, &image, &cd)) {
        snprintf(ref->why, sizeof ref->why, "codegen %u %s", cd.code, cd.message);
        nt_code_image_free(&image);
        nt_frontend_free(&program);
        nt_object_free(&ref->canonical);
        return 0;
    }
    total = image.symbol_count ? image.symbol_count : 1;
    if (!image_tables_present(&image, ref->why, sizeof ref->why)) {
        nt_code_image_free(&image);
        nt_frontend_free(&program);
        nt_object_free(&ref->canonical);
        return 0;
    }
    symbols = calloc(total, sizeof *symbols);
    sorted = calloc(total, sizeof *sorted);
    relocs = calloc(image.relocation_count ? image.relocation_count : 1, sizeof *relocs);
    names = calloc(total, sizeof *names);
    order = calloc(total, sizeof *order);
    if (!symbols || !sorted || !relocs || !names || !order) {
        free(symbols); free(sorted); free(relocs); free(names); free(order);
        nt_code_image_free(&image); nt_frontend_free(&program);
        snprintf(ref->why, sizeof ref->why, "assembly allocation failed");
        return 0;
    }
    for (j = 0; j < image.symbol_count; j++) {
        const NtCodeSymbol *s = image.symbols + j;
        int n = snprintf(names[j], sizeof names[j], "%s", s->name);
        if (n <= 0 || (size_t)n >= sizeof names[j]) {
            free(symbols); free(sorted); free(relocs); free(names); free(order);
            nt_code_image_free(&image); nt_frontend_free(&program);
            snprintf(ref->why, sizeof ref->why, "assembly name overflow");
            return 0;
        }
        symbols[j].name = names[j];
        symbols[j].contract = (char *)c_symbol_contract(&ref->canonical, s->name);
        if (!symbols[j].contract) {
            free(symbols); free(sorted); free(relocs); free(names); free(order);
            nt_code_image_free(&image);
            nt_frontend_free(&program);
            snprintf(ref->why, sizeof ref->why,
                     "assembly: the C object writer has no contract for %s", s->name);
            nt_object_free(&ref->canonical);
            return 0;
        }
        symbols[j].section = s->section;
        symbols[j].offset = s->offset;
        symbols[j].size = s->size;
        symbols[j].flags = (s->function_id ? NT_OBJECT_FUNCTION : NT_OBJECT_VARIABLE) |
                           ((s->flags & 1u) ? NT_OBJECT_EXPORT : 0u);
        order[j].name = names[j];
        order[j].index = j;
        if (s->function_id && (s->flags & 1u) && s->section == NT_CODE_SECTION_TEXT) exported++;
    }
    if (exported != 1) {
        free(symbols); free(sorted); free(relocs); free(names); free(order);
        nt_code_image_free(&image); nt_frontend_free(&program);
        snprintf(ref->why, sizeof ref->why, "assembly: %zu exported .text functions", exported);
        nt_object_free(&ref->canonical);
        return 0;
    }
    qsort(order, image.symbol_count, sizeof *order, ng5_name_compare);
    for (j = 0; j < image.symbol_count; j++) {
        sorted[j] = symbols[order[j].index];
        if (sorted[j].section == NT_OBJECT_TEXT &&
            (sorted[j].flags & NT_OBJECT_EXPORT) && (sorted[j].flags & NT_OBJECT_FUNCTION))
            entry = (uint32_t)j + 1;
    }
    /* Bounded by the relocation count, never by the symbol count, and the table
     * pointer is tested too. A codegen image with symbols and no relocations has
     * relocations == NULL, which is the shape of every twin this gate hands to
     * this function, so a symbol_count bound here reads NULL and the reported
     * member access within null pointer of type 'const struct NtCodeReloc' is
     * what the harness would die of. */
    for (j = 0; image.relocations && j < image.relocation_count; j++) {
        const NtCodeReloc *r = image.relocations + j;
        size_t k, at = image.symbol_count;
        uint32_t target = 0;
        /* The one based index the object format uses is an index into the SORTED
         * table, because hand.symbols is sorted below. nt_codegen_x64_object
         * emits image.symbols grouped by section and sorted inside each section,
         * so an image index is not a sorted index: a .rdata item named zzz and a
         * .text helper named aaa give the image order "zzz aaa main" and the
         * global name order "aaa main zzz", and the image index of aaa is 1 while
         * its sorted index is 0. order[] is the permutation that carries one to
         * the other, sorted[j] being symbols[order[j].index], so the image index
         * has to be pushed through it before it can name a target. nt_object_
         * compile is the oracle for the answer: for that fixture it writes
         * target=1, the aaa row. */
        for (k = 0; k < image.symbol_count; k++)
            if (r->target_function && image.symbols[k].function_id == r->target_function) {
                at = k; break;
            }
        for (k = 0; at != image.symbol_count && k < image.symbol_count; k++)
            if (order[k].index == at) { target = (uint32_t)k + 1; break; }
        if (!target) {
            free(symbols); free(sorted); free(relocs); free(names); free(order);
            nt_code_image_free(&image); nt_frontend_free(&program);
            snprintf(ref->why, sizeof ref->why, "assembly: relocation has no target");
            return 0;
        }
        /* Named fields, never a positional initialiser: NtObjectReloc declares
         * {section, kind, target, offset, addend} (object.h:17-21) and the
         * positional form that passes r->offset third puts the REL32 site in
         * target and the one based symbol index in offset. nt_object_validate
         * then refuses the table with "invalid relocation kind, site or target",
         * and it stayed invisible because the loop above had no case. */
        relocs[j].section = r->source_section;
        relocs[j].kind = r->kind;
        relocs[j].target = target;
        relocs[j].offset = r->offset;
        relocs[j].addend = r->addend;
    }
    /* the hand assembly must carry the canonical C data half, proven here and
     * not asserted: the same payload bytes and the same symbol fields as the
     * nt_object_compile object, names matched on their unqualified tail */
    {
        NtObject hand = {0};
        char detail[128];
        detail[0] = 0;
        /* ref->canonical was built at the top of this function, before the hand
         * assembly, because the hand assembly copies its contract texts */
        hand.target = 1;
        hand.entry_symbol = entry;
        hand.sections[0] = (NtBuffer){image.bytes, image.size, image.capacity};
        hand.sections[1] = (NtBuffer){image.rdata.bytes, image.rdata.size, image.rdata.capacity};
        hand.sections[2] = (NtBuffer){image.data.bytes, image.data.size, image.data.capacity};
        hand.symbols = sorted; hand.symbol_count = image.symbol_count;
        hand.relocations = relocs; hand.relocation_count = image.relocation_count;
        if (!ng5_data_half_match(&hand, &ref->canonical, detail, sizeof detail) || detail[0]) {
            snprintf(ref->why, sizeof ref->why,
                     "hand assembly differs from the canonical C builder: %s", detail);
            ng5_reference_free(ref);
            free(symbols); free(sorted); free(relocs); free(names); free(order);
            nt_code_image_free(&image); nt_frontend_free(&program);
            return 0;
        }
        /* The same proof for the relocation half, which the data half comparison
         * above never looked at. Field by field against nt_object_compile for the
         * same source, with the target compared by unqualified name because the
         * hand table carries bare names and the canonical table module qualified
         * ones. This is the check the whole relocation loop above was missing: a
         * transposed site and target, or a target taken from the wrong index
         * space, is a difference the canonical table states outright. */
        if (hand.relocation_count != ref->canonical.relocation_count) {
            snprintf(ref->why, sizeof ref->why,
                     "hand assembly has %zu relocations, the canonical C builder has %zu",
                     hand.relocation_count, ref->canonical.relocation_count);
            ng5_reference_free(ref);
            free(symbols); free(sorted); free(relocs); free(names); free(order);
            nt_code_image_free(&image); nt_frontend_free(&program);
            return 0;
        }
        for (j = 0; j < hand.relocation_count; j++) {
            const NtObjectReloc *a = hand.relocations + j, *b = ref->canonical.relocations + j;
            const char *an, *bn;
            if (a->section != b->section || a->kind != b->kind || a->offset != b->offset ||
                a->addend != b->addend) {
                snprintf(ref->why, sizeof ref->why,
                         "hand relocation %zu is sec=%u kind=%u off=%zu addend=%lld, "
                         "canonical is sec=%u kind=%u off=%zu addend=%lld", j,
                         a->section, a->kind, (size_t)a->offset, (long long)a->addend,
                         b->section, b->kind, (size_t)b->offset, (long long)b->addend);
                ng5_reference_free(ref);
                free(symbols); free(sorted); free(relocs); free(names); free(order);
                nt_code_image_free(&image); nt_frontend_free(&program);
                return 0;
            }
            if (!a->target || (size_t)a->target > hand.symbol_count ||
                !b->target || (size_t)b->target > ref->canonical.symbol_count) {
                snprintf(ref->why, sizeof ref->why,
                         "hand relocation %zu names symbol %u of %zu, canonical names %u of %zu",
                         j, a->target, (size_t)hand.symbol_count,
                         b->target, (size_t)ref->canonical.symbol_count);
                ng5_reference_free(ref);
                free(symbols); free(sorted); free(relocs); free(names); free(order);
                nt_code_image_free(&image); nt_frontend_free(&program);
                return 0;
            }
            an = hand.symbols[a->target - 1].name;
            bn = ref->canonical.symbols[b->target - 1].name;
            if (strcmp(ng5_tail_of(an), ng5_tail_of(bn))) {
                snprintf(ref->why, sizeof ref->why,
                         "hand relocation %zu targets %s, the canonical C builder targets %s",
                         j, an, bn);
                ng5_reference_free(ref);
                free(symbols); free(sorted); free(relocs); free(names); free(order);
                nt_code_image_free(&image); nt_frontend_free(&program);
                return 0;
            }
        }
    }
    ref->ok = 1;
    free(symbols); free(sorted); free(relocs); free(names); free(order);
    nt_code_image_free(&image);
    nt_frontend_free(&program);
    return 1;
}

/* ------------------------------------------------------------------------ *
 * A FIXTURE THAT NO CLAUSE CAN SATISFY, asserted as the refusal it is.
 *
 * WHY THIS SHAPE EXISTS. accept() asks for a PE, and there are fixtures whose
 * source text no declaration can make acceptable to the C reference, so for
 * those the expectation is a number that can never arrive: the row is red for
 * a reason that is not a defect in anything and cannot be repaired by fixing
 * anything. A permanently red row is the worst shape a gate has, because it
 * trains the reader to ignore red, and a row that asserts its own refusal is
 * green while carrying the same fact.
 *
 * WHAT IT ASSERTS, three things and no more, each on its own CHECK so a
 * failure names which of the three moved:
 *   1. the frozen C reference refuses this exact text, and says why in the
 *      words the caller expects -- the reason is part of the claim, because
 *      "refused" alone would also be true of a source that stopped parsing;
 *   2. the PE adapter refuses it and leaves the output buffer untouched, the
 *      transactional property refuse() checks, on this fixture rather than on
 *      a synthetic one;
 *   3. the object producer refuses the same text. This leg is the reason the
 *      row can be called a PERMANENT refusal rather than a producer gap: one
 *      route answering 800 is what wave 25 mistook for a working entry, so a
 *      refusal measured on one route only is the shape of the original
 *      incident. Both routes are asked, in this process, on these bytes.
 *
 * THE CENSUS IS UNAFFECTED, and that is a property of the arithmetic rather
 * than a coincidence: this shape increments oracle_refused_total exactly as
 * accept() did for the same fixture, so the fixture still lands in exactly one
 * of the four columns and the closing sum over eleven fixtures is unmoved. The
 * column comment above should be read as "no comparison is available", not as
 * "the producer said no", and that reading is now the only one it supports:
 * every fixture in the refused column is refused by BOTH sides, so nothing in
 * it is a producer-only refusal. The previous sentence here said the column
 * held « one fixture whose refusal is the reference's rule and one whose
 * refusal is the producer's ». That was true when forward_branch was the
 * second, and it stopped being true when forward_branch went green; it is
 * replaced rather than left.
 *
 * WHAT IT DOES NOT CLAIM. No PE, no parity, no entry offset: a fixture the
 * reference will not build has no product to compare, and this shape says so
 * by asserting the absence rather than by carrying an expectation for it.
 *
 * WHERE THE NUMBERS IN THE NOTES AT THE FIXTURE ROWS CAME FROM, with the
 * digests of the bytes they were read from, because a count that does not
 * travel with its input is a number in somebody's head. Three throwaway
 * probes, all under out/c-bootstrap/w27pefix, all reading this tree and
 * nothing else:
 *
 *   refprobe.c  4679dc737c6e35bea9faf849d63b4700c1f164674b342fcfc9f6f6008c257317
 *     asks the C reference only: nt_object_compile, then the frontend, the
 *     codegen and the materializer, and prints REFUSE with the code and the
 *     diagnostic, or ACCEPT with the .text size, symbol count and relocation
 *     count. Batch files, one source per record:
 *       batch1.txt            6f0c87efdc7ba00c08f14a107b2364b1f8156320324e7da4e6fec659e0f99962
 *       batch2.txt            a466c13f172f8acb585b03ee599c7a91edcdf332f9dbf4b6c09779ec8490bf8b
 *       batch3.txt            ebb68236f349260c0ea01ded868cbbda3fba02a79407cf51fea5546d6a567b3a
 *   prodprobe.c f4a4ba623da460b882b8aa610643a86db264403f497e1ad275857e26055dab91
 *     asks the PRODUCER on both routes, over the same 18 modules this gate
 *     loads, naming the entry it loaded on every run.
 *   cmpprobe.c  01886a2e4f7721eb7e5a12bf1aa3aacfaff7e3fed4e91ed551166faf5d9bdd84
 *     asks BOTH and compares the two PEs byte for byte, printing the offset
 *     of the first difference. Neither side can observe the other's answer.
 *
 * THE NEGATIVE CONTROL, because an instrument that answers REFUSE for
 * everything would produce every number above unchanged. Two controls, both
 * measured: the reference probe reaches nine distinct diagnostic families on
 * purpose-built records -- 200 syntax, 300 duplicate, 301 unknown name, 400
 * return value, 401 range, 402 register, 500 never, 501 effect, 502 clobber,
 * 503 stack proof -- so it is reading the reference's diagnostics and not
 * echoing a default; and the comparison probe returns IDENTICAL on 26 records
 * and DIVERGES on 3, so neither verdict is a constant. The controls are in
 * batch4-controls.txt, d939d8a8befa06903f41c78063c7f656a0bbc9214a82654dd190e7de3b32f378.
 *
 * WHAT THE INSTRUMENTS DID NOT ESTABLISH, so no reader has to guess: the
 * producer's reason for its own 800. These routes report a code and not a
 * diagnostic, so every "the producer refuses" below is a measurement of the
 * refusal and NOT of its cause, on either route. */
/* The three legs, shared by refused_by_both and refused_by_both_sized so the
 * two shapes cannot drift apart on the parts they have in common.
 *
 * `census` says whether this call is a MEMBER of the eleven-fixture oracle
 * census. It is a parameter and not a separate copy of the three legs because
 * sized_call_inside_a_counted_loop drives CALL_IN_LOOP, the SAME source
 * call_inside_a_counted_loop already counts, and the census counts a fixture
 * once. Passing 1 twice would make the closing sum read 12 against an
 * expected 11 and fail a check that is otherwise correct -- a red census
 * standing for nothing. That is the one thing this parameter prevents, so it
 * is a parameter. */
static void refusal_legs(const NovaHostImage *i, const char *source, const char *label,
                         const char *want_why, int census)
{
    static NtBuffer empty = {0};
    /* OUTCAP, AND NOT A SMALL BUFFER, and the reason is a red proof rather
     * than a preference. The legs below assert "mode N refuses and writes no
     * output", and with a 64 byte buffer that assertion cannot fail for the
     * interesting reason: a successful mode 1 needs 8 + 3072 bytes, so the
     * producer answers 827 (buffer too short) on a source it would otherwise
     * build, writes nothing, and the leg stays green. Perturbing
     * backward_branch to the text the reference BUILDS therefore turned the
     * reference leg red and left the other two green -- measured, and the
     * measurement is the reason this line is not `out[64]`. At OUTCAP a build
     * lands in the buffer, the guard scan sees it, and the leg goes red on the
     * same perturbation. The property is unchanged for a source both sides
     * refuse, which is every fixture that uses this shape today. */
    static uint8_t out[OUTCAP];
    Ng5Reference ref;
    uint64_t pe_code, nxo_code;
    size_t j;
    int intact, reference_refused;

    memset(out, guard, sizeof out);
    reference_refused = !ng5_reference_for(source, &ref);
    if (!reference_refused) ng5_reference_free(&ref);
    CHECKL(reference_refused && strstr(ref.why, want_why) != NULL,
           "the C reference refuses this text and names that reason", label);

    pe_code = run_mode(i, source, &empty, 1, NULL, out, sizeof out);
    intact = pe_code != 0;
    for (j = 0; j < sizeof out; j++) intact &= out[j] == guard;
    CHECKL(intact, "mode 1 refuses it and writes no output", label);

    memset(out, guard, sizeof out);
    nxo_code = run_mode(i, source, &empty, 2, NULL, out, sizeof out);
    intact = nxo_code != 0;
    for (j = 0; j < sizeof out; j++) intact &= out[j] == guard;
    CHECKL(intact, "mode 2 refuses the same text and writes no output", label);

    if (census) oracle_refused_total++;
    fprintf(stderr, "REFUSED_BY_BOTH %s reference=\"%s\" producer_mode1=%llu producer_mode2=%llu\n",
            label, ref.why, (unsigned long long)pe_code, (unsigned long long)nxo_code);
}

static void refused_by_both(const NovaHostImage *i, const char *source, const char *label,
                            const char *want_why)
{
    refusal_legs(i, source, label, want_why, 1);
}

/* The same three legs plus the SELF-CONTAINED ROUTE, mode 6, which is the one
 * that writes a file: it must refuse, leave every byte of the report buffer
 * alone, and leave no file behind. The old row for this fixture was a
 * write_sized() call, i.e. five properties of a successful mode 6 write of a
 * PE that neither producer will build; what replaces it asserts the refusal on
 * all three routes and the transactional property on the route that owns the
 * file, which is the same property refuse() checks on the others.
 *
 * WHAT THIS SHAPE DOES NOT CARRY ACROSS, stated rather than left for a reader
 * to notice: the old row also asked the producer's REPORTED BYTE COUNT to
 * equal the length of the file on disk, the file bytes to equal the in-memory
 * PE of mode 1, and the file to pass ng_pe_validate. None of those is
 * assertable here, because there is no file. All three survive on an accepted
 * source: write_and_check("written_two_functions_one_call") compares the file
 * bytes with the in-memory PE and validates it, and write_sized_no_overwrite()
 * compares mode 6's reported count with the first file's length. What does NOT
 * survive on any accepted source is the mode 6 route on CALL_IN_LOOP, so that
 * one measurement is narrower than it was, and the honest reading is "the
 * mode 6 route is exercised on an accepted source and on two refused ones",
 * not "on every source". */
static void refused_by_both_sized(const NovaHostImage *i, const char *source, const char *label,
                                  const char *want_why, const char *path)
{
    static NtBuffer empty = {0};
    static uint8_t reported[64];
    uint64_t code;
    size_t j;
    int intact;
    FILE *f;

    refusal_legs(i, source, label, want_why, 0);

    memset(reported, guard, sizeof reported);
    remove(path);
    code = run_mode(i, source, &empty, 6, path, reported, sizeof reported);
    intact = code != 0;
    for (j = 0; j < sizeof reported; j++) intact &= reported[j] == guard;
    CHECKL(intact, "mode 6 refuses the same text and writes no size report", label);
    f = fopen(path, "rb");
    CHECKL(f == NULL, "the refused sized write created no file", label);
    if (f) { fclose(f); remove(path); }
    fprintf(stderr, "WRITE_SIZED_REFUSED %s code=%llu\n", label, (unsigned long long)code);
}

/* The left hand object of one link fixture: the canonical C data half, the
 * producer's documented call/ret text stream encoded by the x64 oracle, one
 * unresolved import of helper, the exported main, and the REL32 at the call
 * immediate pointing at the import. */
typedef struct {
    NtObject object;
    uint8_t *text;
    uint8_t *rdata, *data;
    NtObjectSymbol *symbols, *sorted;
    NtObjectReloc *reloc;
    /* The reference's own per symbol name bound: object_build.c:305 refuses
     * "object symbol name too long" above 512 bytes, and ng5_reference_for
     * sizes its own name table the same way. A 64 byte record was a bare name
     * bound, and the module qualified names this struct now carries do not fit
     * it -- the compiler was right to say so, and truncating a symbol name
     * would have made the left object a different object from the one the
     * reference builds. */
    char (*names)[512];
    Ng5NameOrder *order;
} Ng5Left;
static void ng5_left_free(Ng5Left *l)
{
    free(l->text); free(l->rdata); free(l->data);
    free(l->symbols); free(l->sorted); free(l->reloc); free(l->names); free(l->order);
    memset(l, 0, sizeof *l);
}
static int ng5_left_build(const NtObject *canon, const char *import_name,
                          const char *main_name, const char *alias_contract,
                          const char *main_contract, Ng5Left *l)
{
    size_t data_symbols = 0, j, used = 0;
    NtX64Operand forward = {0};
    NtX64Instruction call_encoded = {0}, ret_encoded = {0};
    NtX64Context ctx = {1, 3};
    char detail[256];

    memset(l, 0, sizeof *l);
    forward.kind = NT_X64_REL; forward.imm = 0; forward.is_signed = 1;
    for (j = 0; j < canon->symbol_count; j++) if (ng5_is_data(canon->symbols + j)) data_symbols++;
    l->text = calloc(8, 1);
    l->reloc = calloc(1, sizeof *l->reloc);
    l->symbols = calloc(data_symbols + 2, sizeof *l->symbols);
    l->sorted = calloc(data_symbols + 2, sizeof *l->sorted);
    l->names = calloc(data_symbols + 2, sizeof *l->names);
    l->order = calloc(data_symbols + 2, sizeof *l->order);
    l->rdata = calloc(canon->sections[1].size ? canon->sections[1].size : 1, 1);
    l->data = calloc(canon->sections[2].size ? canon->sections[2].size : 1, 1);
    if (!l->text || !l->reloc || !l->symbols || !l->sorted || !l->names || !l->order ||
        !l->rdata || !l->data) {
        fprintf(stderr, "ng5_left_build reason allocation\n"); ng5_left_free(l); return 0; }
    {
        /* nt_x64_encode returns an NtX64Error, so zero is success */
        NtX64Error rc_call = nt_x64_encode("call", &forward, 1, ctx, &call_encoded);
        NtX64Error rc_ret = nt_x64_encode("ret", NULL, 0, ctx, &ret_encoded);
        if (rc_call != 0 || rc_ret != 0) {
            fprintf(stderr, "ng5_left_build reason x64 oracle call=%u ret=%u\n",
                    (unsigned)rc_call, (unsigned)rc_ret);
            ng5_left_free(l); return 0; }
    }
    memcpy(l->text, call_encoded.bytes, call_encoded.length);
    memcpy(l->text + call_encoded.length, ret_encoded.bytes, ret_encoded.length);
    if (canon->sections[1].size) memcpy(l->rdata, canon->sections[1].bytes, canon->sections[1].size);
    if (canon->sections[2].size) memcpy(l->data, canon->sections[2].bytes, canon->sections[2].size);
    for (j = 0; j < canon->symbol_count; j++) {
        const NtObjectSymbol *c = canon->symbols + j;
        if (!ng5_is_data(c)) continue;
        /* The canonical object's OWN names, already module qualified by the C
         * object writer (object_build.c:305, snprintf "%s.%s"). Writing the
         * tail here built a left object whose identity was not the
         * reference's, so the C link measured a different object from the one
         * the producer is compared against. */
        snprintf(l->names[used], sizeof l->names[used], "%s", c->name);
        l->symbols[used] = (NtObjectSymbol){l->names[used], (char *)c->contract, c->section, c->flags, c->offset, c->size};
        l->order[used].name = l->names[used]; l->order[used].index = used;
        used++;
    }
    snprintf(l->names[used], sizeof l->names[used], "%s", import_name);
    l->symbols[used] = (NtObjectSymbol){l->names[used], (char *)alias_contract, 0, NT_OBJECT_FUNCTION | NT_OBJECT_IMPORT, 0, 0};
    l->order[used].name = l->names[used]; l->order[used].index = used; used++;
    snprintf(l->names[used], sizeof l->names[used], "%s", main_name);
    l->symbols[used] = (NtObjectSymbol){l->names[used], (char *)main_contract, NT_OBJECT_TEXT,
                                        NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0,
                                        call_encoded.length + ret_encoded.length};
    l->order[used].name = l->names[used]; l->order[used].index = used; used++;
    qsort(l->order, used, sizeof *l->order, ng5_name_compare);
    for (j = 0; j < used; j++) {
        l->sorted[j] = l->symbols[l->order[j].index];
        if (!strcmp(l->sorted[j].name, main_name)) l->object.entry_symbol = (uint32_t)j + 1;
        if (!strcmp(l->sorted[j].name, import_name)) l->reloc[0].target = (uint32_t)j + 1;
    }
    if (!l->object.entry_symbol || !l->reloc[0].target) {
        fprintf(stderr, "ng5_left_build reason entry=%u target=%u used=%zu import=%s\n",
                l->object.entry_symbol, l->reloc[0].target, used, import_name);
        ng5_left_free(l); return 0; }
    l->reloc[0].section = NT_OBJECT_TEXT;
    l->reloc[0].kind = NT_OBJECT_REL32;
    l->reloc[0].offset = 1;
    l->reloc[0].addend = 0;
    l->object.target = 1;
    l->object.symbols = l->sorted;
    l->object.symbol_count = used;
    l->object.relocations = l->reloc;
    l->object.relocation_count = 1;
    l->object.sections[0] = (NtBuffer){l->text, call_encoded.length + ret_encoded.length,
                                      call_encoded.length + ret_encoded.length};
    l->object.sections[1] = (NtBuffer){l->rdata, canon->sections[1].size, canon->sections[1].size};
    l->object.sections[2] = (NtBuffer){l->data, canon->sections[2].size, canon->sections[2].size};
    detail[0] = 0;
    if (!ng5_data_half_match(&l->object, canon, detail, sizeof detail)) {
        fprintf(stderr, "ng5_left_build reason %s\n", detail);
        ng5_left_free(l);
        return 0;
    }
    return 1;
}

/* The .rdata and .data payload of a produced PE, located with the two offsets
 * pe_layout.h defines, plus the bytes the linker left after the payload. The
 * linker starts every input section on a sixteen byte boundary, so a linked data
 * section is padded up to that boundary; those trailing zeros belong to the
 * link, not to the data layout, so they are reported separately and required to
 * be zero rather than compared against the C payload. */
static int ng5_pe_payload(const uint8_t *pe, size_t size, const char *want, size_t skip,
                          size_t canonical, const uint8_t **bytes, size_t *avail,
                          char *detail, size_t room)
{
    uint32_t nt; uint16_t count, opt; size_t table; unsigned s;
    if (size < 64) { snprintf(detail, room, "PE too small"); return 0; }
    nt = rd32(pe + 60);
    if ((size_t)nt + 24 > size) { snprintf(detail, room, "PE header out of range"); return 0; }
    count = rd16(pe + nt + 6); opt = rd16(pe + nt + 20);
    table = (size_t)nt + 24 + opt;
    if (table + (size_t)count * 40 > size) { snprintf(detail, room, "PE section table out of range"); return 0; }
    for (s = 0; s < count; s++) {
        const uint8_t *h = pe + table + (size_t)s * 40;
        uint32_t vs = rd32(h + 8), raw = rd32(h + 20);
        if (strncmp((const char *)h, want, strlen(want))) continue;
        if ((size_t)raw + vs > size || vs < skip) { snprintf(detail, room, "%s out of range", want); return 0; }
        if (vs < skip + canonical) {
            snprintf(detail, room, "%s virtual size %u, expected at least %zu", want, vs, skip + canonical);
            return 0;
        }
        *bytes = pe + raw + skip;
        *avail = vs - skip;
        return 1;
    }
    snprintf(detail, room, "PE has no %s section", want);
    return 0;
}

/* The canonical payload followed only by zeros. */
static int payload_is(const uint8_t *bytes, size_t avail, const uint8_t *want, size_t size)
{
    if (avail < size) return 0;
    if (size && memcmp(bytes, want, size)) return 0;
    for (size_t i = size; i < avail; i++) if (bytes[i]) return 0;
    return 1;
}

typedef struct { const char *name; unsigned width; uint64_t value; unsigned section; } Ng5Item;
static size_t ng5_emit_items(char *dst, size_t room, const Ng5Item *items, size_t count)
{
    size_t used = 0, i;
    for (i = 0; i < count; i++) {
        int n = snprintf(dst + used, room - used, "export data %s:u%u=%llu\n", items[i].name,
                         items[i].width * 8, (unsigned long long)items[i].value);
        if (n < 0 || (size_t)n >= room - used) return room + 1;
        used += (size_t)n;
    }
    return used;
}
/* WHY THE PRODUCER FORM SAYS `export fn main` AND THE TWIN ALREADY DID. The
 * reference sets NT_OBJECT_EXPORT from the declaration's own `exported` bit
 * (object_build.c:317) and names the entry only for an EXPORTED main
 * (object_build.c:343-347, codegen.c:1557-1562), so a main without the modifier
 * is a legal object with entry_symbol = 0 and flags = NT_OBJECT_FUNCTION alone.
 * The C reference REFUSES the producer's call+ret body (a bare ret has no
 * available stack/frame balance proof: 503), so the reference is asked about the
 * with_import = 0 twin below, which already says export fn main, and the two
 * must declare the SAME program. The producer used to hardcode the export bit on
 * main, which made producer and twin agree in the output even though they
 * declared different programs; that was hiding the difference, not proving
 * parity. */
/* The producer source and its C expressible twin: identical data declarations and
 * target, the producer form carrying the import and the bare call/ret body. */
static size_t ng5_build_source(char *dst, size_t room, const Ng5Item *items, size_t count,
                               const char *target, const char *alias, int with_import,
                               const char *call_text)
{
    size_t used = (size_t)snprintf(dst, room, "module m\ntarget x86_64-nexora-%s\n", target);
    unsigned sec; size_t i, k; int n;
    if (used >= room) return room + 1;
    if (with_import) {
        n = snprintf(dst + used, room - used,
                     "import api.echo as %s: fn()->u64\neffects {}\nclobbers {}\n", alias);
        if (n < 0 || (size_t)n >= room - used) return room + 1;
        used += (size_t)n;
    }
    for (sec = 0; sec < 3; sec++) {
        n = snprintf(dst + used, room - used, "section %s {\n", sec == 0 ? ".rdata" : sec == 1 ? ".data" : ".text");
        if (n < 0 || (size_t)n >= room - used) return room + 1;
        used += (size_t)n;
        if (sec == 2) {
            n = with_import
                ? snprintf(dst + used, room - used,
                           "export fn main()->u64\neffects {}\nclobbers {} {\n%s\nret\n}\n", call_text)
                : snprintf(dst + used, room - used,
                           "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n");
            if (n < 0 || (size_t)n >= room - used) return room + 1;
            used += (size_t)n;
        } else {
            for (i = 0; i < count; i++) if (items[i].section == (sec == 0 ? 2u : 3u)) {
                k = ng5_emit_items(dst + used, room - used, &items[i], 1);
                if (k >= room - used) return room + 1;
                used += k;
            }
        }
        n = snprintf(dst + used, room - used, "}\n");
        if (n < 0 || (size_t)n >= room - used) return room + 1;
        used += (size_t)n;
    }
    if (used >= room) return room + 1;
    dst[used] = 0;
    return used;
}

/* The module a fixture source declares, read back out of the SOURCE TEXT.
 *
 * The reference forms a qualified name in exactly one place, object_build.c:305
 * inside nt_object_compile:
 *
 *     snprintf(order[j].symbol.name, mn + sn + 2, "%s.%s", s->module, s->name);
 *
 * and s->module is the source's own `module` declaration -- not the name the
 * caller hands nt_frontend_compile_object, which is only a unit label. So the
 * module a link fixture is measured under is a property of the fixture, and
 * reading it back out of the fixture is a derivation that can fail: a source
 * with no readable module declaration has no qualified name to build, and the
 * case is refused rather than linked under a bare name. */
static int ng5_source_module(const char *source, char *out, size_t room)
{
    size_t i = 0, start;
    while (source[i] == ' ' || source[i] == '\t') i++;
    if (strncmp(source + i, "module", 6) != 0) return 0;
    i += 6;
    if (source[i] != ' ' && source[i] != '\t') return 0;
    while (source[i] == ' ' || source[i] == '\t') i++;
    start = i;
    while (source[i] && source[i] != '\n' && source[i] != ' ' && source[i] != '\t') i++;
    if (i == start || i - start + 1 > room) return 0;
    memcpy(out, source + start, i - start);
    out[i - start] = 0;
    return 1;
}

/* The last occurrence of `marker` in `text`, or NULL. strrstr is a GNU
 * extension and this harness is compiled -std=c11 -Werror, so the search is
 * written out rather than reached for. */
static const char *ng5_last_occurrence(const char *text, const char *marker)
{
    size_t m = strlen(marker), n = strlen(text), i, at = 0;
    int found = 0;
    for (i = 0; i + m <= n; i++)
        if (!memcmp(text + i, marker, m)) { at = i; found = 1; }
    return found ? text + at : NULL;
}

/* The source the naming oracle is asked about: the producer source's own bytes
 * up to and including the brace that opens the main body, then a body the
 * reference accepts. The substitution is forced by a measurement, not chosen:
 * the reference REFUSES the bare `call` / `ret` body with 503 "ret requires
 * unavailable stack/frame balance proof", so it cannot be asked to name the
 * symbols of that exact text. A body contributes no name -- every name is the
 * module of the declaration plus a function or variable name, or the head and
 * tail of an import path -- so every declaration byte here is the fixture's
 * own, and what the substitution drops is the call site, which is the alias,
 * and the reference discards the alias. */
static int ng5_naming_source(const char *fixture, const char *call, char *out, size_t room)
{
    const char *at = ng5_last_occurrence(fixture, "clobbers {} {\n");
    size_t keep;
    int n;
    if (!at) return 0;
    keep = (size_t)(at - fixture) + strlen("clobbers {} {\n");
    n = snprintf(out, room, "%.*sreturn %s()\n}\n}\n", (int)keep, fixture, call);
    return n > 0 && (size_t)n < room;
}

/* The name the C reference writes for the one symbol carrying `flags` in
 * `section` of the object it builds for `source`. Selection is by the
 * reference's own metadata and never by recognising a name, so the harness
 * never has to spell a name to find a symbol. */
static int ng5_reference_name(const char *source, uint32_t section, uint32_t flags,
                              char *out, size_t room)
{
    NtObject object;
    NtDiagnostic error;
    size_t k, hits = 0, at = 0;
    memset(&object, 0, sizeof object);
    memset(&error, 0, sizeof error);
    if (!nt_object_compile(&(NtFInput){"naming", (char *)source, strlen(source)},
                           1, &object, &error)) {
        fprintf(stderr, "REFERENCE_REFUSED %u %s\n", error.code, error.message);
        nt_object_free(&object);
        return 0;
    }
    for (k = 0; k < object.symbol_count; k++)
        if (object.symbols[k].section == section && object.symbols[k].flags == flags) {
            hits++; at = k;
        }
    if (hits == 1) {
        const char *name = object.symbols[at].name;
        int n = snprintf(out, room, "%s", name ? name : "");
        hits = n > 0 && (size_t)n < room;
    } else {
        fprintf(stderr, "REFERENCE_NAME_AMBIGUOUS section=%u flags=%u hits=%zu\n",
                section, flags, hits);
    }
    nt_object_free(&object);
    return (int)hits;
}

/* The name the C reference gives THIS SOURCE's unresolved import. A definition
 * object has to export exactly this string or object_link.c's find() cannot
 * resolve the import, and the producer's own nxo_merge ladder refuses it the
 * same way.
 *
 * This replaces a construction, not a value. The previous ng5_import_name
 * printed "%s.%s" of the twin's module and the alias, and it was wrong about
 * the reference in a way two agreeing halves could not see: the reference names
 * an unresolved import by its PATH. frontend.c:2974 keeps the dotted path in
 * f->import_name and the alias in f->name; codegen.c:1586-1599 splits the path
 * at its last dot and gives the head to add_symbol as the module and the tail
 * as the name; object_build.c:305 joins head, dot and tail. The declared module
 * and the alias are both discarded. The name is therefore asked of the
 * reference here, from the producer source's own import declaration. */
static int ng5_reference_import_name(const char *source, char *out, size_t room)
{
    const char *call = strstr(source, "call ");
    char naming[8192];
    char alias[64];
    const char *at;
    size_t n;
    int ok;
    if (!call) return 0;
    at = strchr(call + 5, '(');
    if (!at) return 0;
    n = (size_t)(at - (call + 5));
    if (n == 0 || n + 1 > sizeof alias) return 0;
    memcpy(alias, call + 5, n);
    alias[n] = 0;
    if (!ng5_naming_source(source, alias, naming, sizeof naming)) return 0;
    ok = ng5_reference_name(naming, 0, NT_OBJECT_IMPORT | NT_OBJECT_FUNCTION, out, room);
    return ok;
}

/* Every symbol of a canonical object carries the module and a dot. Used to
 * refuse rather than proceed if the reference ever stopped qualifying, which
 * is the one change that would make every name below compare the wrong
 * identity while still looking like a name. */
static int ng5_all_qualified_with(const NtObject *canon, const char *module)
{
    size_t k, ml = strlen(module);
    if (!canon->symbol_count) return 0;
    for (k = 0; k < canon->symbol_count; k++) {
        const char *name = canon->symbols[k].name;
        if (!name || strncmp(name, module, ml) || name[ml] != '.') return 0;
    }
    return 1;
}

/* The reference's own name for the entry of a canonical object, which is how
 * the left object's exported function is named. Not a literal: a module rename
 * in the fixture moves it with the reference instead of stranding the left
 * object under a name the producer does not emit. */
static int ng5_entry_name(const NtObject *canon, char *out, size_t room)
{
    uint32_t at = canon->entry_symbol;
    const char *name;
    int n;
    if (at < 1 || (size_t)at > canon->symbol_count) return 0;
    name = canon->symbols[at - 1].name;
    if (!name) return 0;
    n = snprintf(out, room, "%s", name);
    return n > 0 && (size_t)n < room;
}

/* One link fixture: the producer builds a PE against the supplied definition, the
 * expectation is the canonical C data half joined to the x64 oracle code stream
 * by the same C link, materialize and PE writer.
 *
 * `import_name` is the name the reference gives the unresolved import: the
 * module every symbol of the unit is qualified with, then the dot, then the
 * alias the import binds. The caller derives it from the twin source and hands
 * it in, and the check below refuses if the reference disagrees, so the two
 * objects that meet in this link carry the same identity by construction and
 * not by a name somebody typed. */
static void ng5_link_case(const NovaHostImage *image, const char *label, const char *source,
                          const char *twin, const char *alias, const char *import_name,
                          const NtBuffer *right_file)
{
    uint8_t out[65536];
    Ng5Reference ref;
    Ng5Left left;
    char alias_text[1024], module[64], main_name[128];
    NtObject right = {0}, pair[2], linked = {0};
    NtObjectSymbol helper = {(char *)import_name, alias_text, 1, NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION, 0, 6};
    static uint8_t callee[6];
    NtArtifact artifact = {0};
    NtDiagnostic error = {0};
    char detail[512];

    memset(out, 0xcc, sizeof out);
    {
        uint64_t code = run(image, source, right_file, out, sizeof out), size = r64(out);
        CHECKL(code == 0 && size > 0 && size <= sizeof out - 8, "producer returns a PE", label);
        if (code != 0 || size == 0 || size > sizeof out - 8) return;
        if (!ng5_reference_for(twin, &ref)) {
            CHECKL(0, "C reference for the twin", label);
            fprintf(stderr, "DATA %s reference reason=%s\n", label, ref.why);
            ng5_reference_free(&ref);
            return;
        }
        /* the definition object the linker is handed carries the contract the C
         * object writer builds for that declaration, which is the text the Nova
         * import names; a placeholder here would refuse every link and the byte
         * comparison below would compare placeholders */
        {
            char *text = ng5_alias_contract("uefi", alias);
            if (!text || strlen(text) + 1 > sizeof alias_text) {
                CHECKL(0, "the C object writer wrote the alias contract", label);
                free(text);
                ng5_reference_free(&ref);
                return;
            }
            memcpy(alias_text, text, strlen(text) + 1);
            free(text);
        }
        /* the producer's own layout, read back out of the produced image and
         * compared against the C canonical payload */
        detail[0] = 0;
        {
            const uint8_t *rdata = 0, *data = 0;
            size_t rdata_avail = 0, data_avail = 0;
            size_t rdata_size = ref.canonical.sections[1].size;
            size_t data_size = ref.canonical.sections[2].size;
            long first = -1;
            char c_offsets[2048];
            int same;
            if (ng5_pe_payload(out + 8, (size_t)size, ".rdata", 8, rdata_size, &rdata, &rdata_avail, detail, sizeof detail) &&
                ng5_pe_payload(out + 8, (size_t)size, ".data", 0, data_size, &data, &data_avail, detail, sizeof detail)) {
                for (size_t i = 0; i < rdata_size; i++)
                    if (rdata[i] != ref.canonical.sections[1].bytes[i]) { first = (long)i; break; }
                if (first < 0)
                    for (size_t i = 0; i < data_size; i++)
                        if (data[i] != ref.canonical.sections[2].bytes[i]) { first = (long)(rdata_size + i); break; }
                if (first < 0)
                    for (size_t i = rdata_size; i < rdata_avail; i++)
                        if (rdata[i]) { first = (long)i; snprintf(detail, sizeof detail, "rdata padding is not zero"); break; }
                if (first < 0)
                    for (size_t i = data_size; i < data_avail; i++)
                        if (data[i]) { first = (long)(rdata_size + i); snprintf(detail, sizeof detail, "data padding is not zero"); break; }
                same = first < 0;
            } else same = 0;
            if (!same && !detail[0]) snprintf(detail, sizeof detail, "payload differs from the C canonical payload");
            ng5_offsets_of(&ref.canonical, c_offsets, sizeof c_offsets);
            fprintf(stderr, "DATA %s scope=data pe_rdata=%zu pe_data=%zu C_rdata=%zu C_data=%zu "
                            "C_off=%s verdict=%s first=%ld %s\n",
                    label, rdata_size, data_size, rdata_size, data_size, c_offsets,
                    same ? "IDENTICAL" : "DIVERGES", first, same ? "" : detail);
            CHECKL(same, "data layout parity with the C frontend pipeline", label);
        }
        memset(&left, 0, sizeof left);
        /* Two independent cross-checks, and both of them can fail.
         *
         * The first is about the TWIN: the reference must qualify every one of
         * its symbols with the module the twin's own source declares, or the
         * left object below is built on a different identity than the one the
         * reference used.
         *
         * The second is about the import name, and it is here per case rather
         * than once at the call site on purpose. The caller hands in a name, and
         * the old check only asked that it START with the twin's module and a
         * dot -- a check the wrong answer passes, because "m.ext" is exactly
         * the wrong answer and it is a module qualified name. Re-deriving it
         * here from the reference and comparing with strcmp means a caller
         * that handed in a constructed name cannot get a link out of this
         * case, and the string that gets compared is the reference's. */
        {
            int agree = 0, named = 0;
            char asked[128];
            if (ng5_source_module(twin, module, sizeof module))
                agree = ng5_all_qualified_with(&ref.canonical, module);
            CHECKL(agree, "the reference qualifies the twin with the module its source declares",
                   label);
            if (!agree) { ng5_reference_free(&ref); return; }
            if (ng5_reference_import_name(source, asked, sizeof asked))
                named = !strcmp(asked, import_name);
            CHECKL(named, "the import name is the one the C reference gives this source's import",
                   label);
            if (!named) {
                fprintf(stderr, "IMPORT_NAME %s given=[%s] reference=[%s]\n",
                        label, import_name, asked);
                ng5_reference_free(&ref);
                return;
            }
        }
        if (!ng5_entry_name(&ref.canonical, main_name, sizeof main_name)) {
            CHECKL(0, "the C reference names its entry symbol", label);
            ng5_reference_free(&ref);
            return;
        }
        if (!ng5_left_build(&ref.canonical, import_name, main_name, alias_text,
                            c_symbol_contract(&ref.canonical, "main"), &left)) {
            CHECKL(0, "left object carries the canonical C data half", label);
            ng5_reference_free(&ref);
            return;
        }
        CHECKL(1, "left object carries the canonical C data half", label);
        callee[0] = 0xb8; callee[1] = 42; callee[2] = 0; callee[3] = 0; callee[4] = 0; callee[5] = 0xc3;
        right.target = 1;
        right.sections[0] = (NtBuffer){callee, sizeof callee, sizeof callee};
        right.symbols = &helper; right.symbol_count = 1;
        pair[0] = left.object; pair[1] = right;
        {
            int linked_ok = nt_object_link(pair, 2, &linked, &error);
            CHECKL(linked_ok, "C object link", label);
            if (!linked_ok) { ng5_left_free(&left); ng5_reference_free(&ref); return; }
        }
        {
            int materialized = nt_object_materialize(&linked, &artifact, &error);
            CHECKL(materialized, "C materialize", label);
            CHECKL(materialized && nt_make_pe(&artifact), "C make PE", label);
        }
        if (artifact.pe.bytes) {
            int parity = size == artifact.pe.size && !memcmp(out + 8, artifact.pe.bytes, artifact.pe.size);
            if (!parity) {
                size_t lim = size < artifact.pe.size ? (size_t)size : artifact.pe.size, off = 0;
                while (off < lim && out[8 + off] == artifact.pe.bytes[off]) off++;
                fprintf(stderr, "PE mismatch code=0 nova=%llu C=%zu first=%zu novaByte=%u CByte=%u\n",
                        (unsigned long long)size, artifact.pe.size, off,
                        off < size ? out[8 + off] : 0, off < artifact.pe.size ? artifact.pe.bytes[off] : 0);
            }
            CHECKL(parity, "Nova PE byte parity", label);
            /* the materialized payloads are the canonical payload; the linker
             * pads each data section up to its sixteen byte boundary and those
             * zeros belong to the link, so they are required to be zero */
            CHECKL(payload_is(artifact.rdata.bytes, artifact.rdata.size,
                              ref.canonical.sections[1].bytes, ref.canonical.sections[1].size),
                   "materialized .rdata is the canonical payload", label);
            CHECKL(payload_is(artifact.data.bytes, artifact.data.size,
                              ref.canonical.sections[2].bytes, ref.canonical.sections[2].size),
                   "materialized .data is the canonical payload", label);
            CHECKL(artifact.text.size >= 6 && artifact.text.bytes[0] == 0xe8 &&
                   artifact.text.bytes[1] != 0 && artifact.text.bytes[5] == 0xc3,
                   "REL32 call patched", label);
            CHECKL(artifact.entry == 0, "main entry offset", label);
        }
        free_artifact(&artifact);
        nt_object_free(&linked);
        ng5_left_free(&left);
        ng5_reference_free(&ref);
    }
}

/* ------------------------------------------------------------------ *
 * The codegen image table contract, and the relocation loop it feeds
 * ------------------------------------------------------------------ */

/* The shape one source leaves behind in the codegen, so "the relocation table is
 * absent" is a measured fixture and not an assumption. A twin whose body ends in
 * "return 0" emits no relocation at all, and codegen.c never allocates the table
 * for a count that stays zero, so that shape is symbols > 0 with relocations
 * NULL. It is the shape of all 97 link twins this gate built, and it is the
 * image the reported crash walked symbol_count entries into. */
typedef struct {
    int compiled;
    size_t symbol_count, relocation_count;
    int symbols_present, relocations_present;
    char why[256];
} Ng5ImageShape;
static void ng5_image_shape(const char *source, Ng5ImageShape *shape)
{
    NtFInput input = {"m", source, strlen(source)};
    NtFProgram program;
    NtCodeImage image;
    NtCodeDiagnostic cd;
    memset(shape, 0, sizeof *shape);
    memset(&program, 0, sizeof program);
    memset(&image, 0, sizeof image);
    memset(&cd, 0, sizeof cd);
    if (!nt_frontend_compile_object(&input, 1, &program)) {
        snprintf(shape->why, sizeof shape->why, "frontend %u %s",
                 program.diagnostic_count ? program.diagnostics[0].code : 0u,
                 program.diagnostic_count ? program.diagnostics[0].message : "no diagnostic");
        nt_frontend_free(&program);
        return;
    }
    if (!nt_codegen_x64_object(&program, &image, &cd)) {
        snprintf(shape->why, sizeof shape->why, "codegen %u %s", cd.code, cd.message);
        nt_code_image_free(&image);
        nt_frontend_free(&program);
        return;
    }
    shape->compiled = 1;
    shape->symbol_count = image.symbol_count;
    shape->relocation_count = image.relocation_count;
    shape->symbols_present = image.symbols != NULL;
    shape->relocations_present = image.relocations != NULL;
    nt_code_image_free(&image);
    nt_frontend_free(&program);
}

/* A C expressible twin whose body calls locally defined functions, so the C
 * codegen emits a REL32 and the reference's relocation loop has rows to map.
 * The data half is the only part a link fixture compares and ng5_left_build
 * discards the canonical text, so a local call changes no existing expectation;
 * it only makes a dead loop live. The data item names are chosen to sort late
 * and the helper names to sort early, because the codegen groups image.symbols
 * by section while the object format wants one global name order, and that is
 * exactly the gap the index mapping has to bridge. */
static size_t ng5_build_calling_twin(char *dst, size_t room, const Ng5Item *items,
                                     size_t count, unsigned helpers, unsigned calls)
{
    size_t used = (size_t)snprintf(dst, room, "module m\ntarget x86_64-nexora-uefi\n");
    unsigned sec, h; size_t i; int n;
    if (used >= room) return room + 1;
    for (sec = 0; sec < 3; sec++) {
        n = snprintf(dst + used, room - used, "section %s {\n",
                     sec == 0 ? ".rdata" : sec == 1 ? ".data" : ".text");
        if (n < 0 || (size_t)n >= room - used) return room + 1;
        used += (size_t)n;
        if (sec == 2) {
            n = snprintf(dst + used, room - used,
                         "export fn main()->u64\neffects {}\nclobbers {} {\n");
            if (n < 0 || (size_t)n >= room - used) return room + 1;
            used += (size_t)n;
            for (h = 0; h < calls; h++) {
                n = snprintf(dst + used, room - used, "call lh%u()\n", h % helpers);
                if (n < 0 || (size_t)n >= room - used) return room + 1;
                used += (size_t)n;
            }
            n = snprintf(dst + used, room - used, "return 0\n}\n");
            if (n < 0 || (size_t)n >= room - used) return room + 1;
            used += (size_t)n;
            for (h = 0; h < helpers; h++) {
                n = snprintf(dst + used, room - used,
                             "fn lh%u()->u64\neffects {}\nclobbers {} {\nreturn %u\n}\n",
                             h, h + 1);
                if (n < 0 || (size_t)n >= room - used) return room + 1;
                used += (size_t)n;
            }
        } else {
            for (i = 0; i < count; i++) {
                if (items[i].section != (sec == 0 ? 2u : 3u)) continue;
                {
                    size_t k = ng5_emit_items(dst + used, room - used, &items[i], 1);
                    if (k >= room - used) return room + 1;
                    used += k;
                }
            }
        }
        n = snprintf(dst + used, room - used, "}\n");
        if (n < 0 || (size_t)n >= room - used) return room + 1;
        used += (size_t)n;
    }
    if (used >= room) return room + 1;
    dst[used] = 0;
    return used;
}

/* One relocation half case: the C reference of a twin that does have
 * relocations. ng5_reference_for now compares its hand relocation table against
 * nt_object_compile row by row and refuses a difference, so reaching this
 * function with a nonzero canonical count already means the loop mapped every
 * row and the two tables agree. The expectations here add what the internal
 * comparison cannot state on its own: that the fixture really did drive the
 * loop, that every target is a defined function inside the symbol table, and
 * that each REL32 site lies inside the .text payload it claims. */
static void ng5_reloc_reference_case(const char *label, const char *twin, size_t want_relocs)
{
    Ng5Reference ref;
    size_t j;
    int shaped_ok = 1, in_text = 1, defined = 1;
    Ng5ImageShape shape;

    if (!ng5_reference_for(twin, &ref)) {
        CHECKL(0, "C reference for a twin that carries relocations", label);
        fprintf(stderr, "RELOC %s reference reason=%s\n", label, ref.why);
        ng5_reference_free(&ref);
        oracle_cases++;
        return;
    }
    ng5_image_shape(twin, &shape);
    /* the fixture must have produced relocations, or the loop stayed unentered
     * and everything below would be asserting nothing */
    CHECKL(shape.compiled && shape.relocation_count == want_relocs,
           "the twin drives exactly the expected number of relocations", label);
    CHECKL(shape.relocations_present, "a nonzero relocation count carries a table", label);
    CHECKL(ref.canonical.relocation_count == want_relocs,
           "the canonical C object carries the same relocations", label);
    CHECKL(ref.canonical.relocations != NULL || want_relocs == 0,
           "the canonical relocation table is present when the count is nonzero", label);
    for (j = 0; j < want_relocs; j++) {
        const NtObjectReloc *r = ref.canonical.relocations + j;
        const NtObjectSymbol *s;
        if (!r->target || (size_t)r->target > ref.canonical.symbol_count) { defined = 0; break; }
        s = ref.canonical.symbols + r->target - 1;
        if (!(s->flags & NT_OBJECT_FUNCTION) || (s->flags & NT_OBJECT_IMPORT)) { defined = 0; break; }
        if (r->kind != NT_OBJECT_REL32 || r->section != NT_OBJECT_TEXT) { in_text = 0; break; }
        if (r->offset + 4 > ref.canonical.sections[0].size) { in_text = 0; break; }
    }
    CHECKL(defined, "every relocation targets a defined function symbol", label);
    CHECKL(in_text, "every REL32 site lies inside the .text payload", label);
    CHECKL(shape.symbol_count > 0, "the twin carries symbols to index", label);
    shaped_ok = shape.compiled;
    CHECKL(shaped_ok, "the twin compiles through the C frontend and codegen", label);
    fprintf(stderr, "RELOC %s symbols=%zu relocs=%zu loop_body_rows=%zu\n", label,
            ref.canonical.symbol_count, ref.canonical.relocation_count, want_relocs);
    oracle_cases++;
    ng5_reference_free(&ref);
}

/* ------------------------------------------------------------------ *
 * THE CANARY. One row, run first, and the whole table is void without it.
 *
 * WHAT WENT WRONG IN WAVE 25, because this is the instrument for it and an
 * instrument with no incident behind it is decoration. One lot drove this
 * source through the PE adapter and read 800; another drove the SAME bytes
 * through the OBJECT producer and read 0, and reported the producer tracking
 * the reference on twelve cells. Both numbers were printed by a program that
 * could not tell you which module it held. The reason a wrong entry is not
 * self-announcing is that BOTH entries answer 0 on success, and 0 IS AN
 * ACCEPT -- so a harness that reports the code alone cannot distinguish "a PE
 * was built" from "an object was built", and the error runs ANTICORRELATED
 * with the property under test: a divergence hunt gets a false NEGATIVE from
 * it, a repair check gets a false POSITIVE, and neither can tell from inside
 * itself which it just did.
 *
 * WHAT THE CANARY ASSERTS, and why each leg is here. The source is the
 * smallest one the producer accepts: one exported main, an empty effects set,
 * an empty clobber set, a valued return. It is asked twice, once per route,
 * and the two answers must DIFFER, because the whole failure was one answer
 * standing in for the other:
 *   mode 1, x64_lower_nxo_pe.build_function_bodies, must answer 0 and 3072
 *          bytes whose first two are 'M' and 'Z'. The MZ is the discriminator
 *          no object producer can forge, and the 3072 is pinned so a change in
 *          the PE writer shows up here rather than as a diff in a later row.
 *   mode 2, x64_lower_nxo.build_function_bodies, must answer 0 and 480 bytes
 *          whose first two are NOT 'M' and 'Z'. Pinning the OBJECT size is
 *          what makes the pair a lock: a harness that swapped the two routes
 *          gets 480 where 3072 is expected, and the canary is red on the size
 *          before any fixture has run.
 *   the two sizes must differ, asserted rather than assumed. If they ever
 *          converge, the canary has stopped discriminating and its silence
 *          would be worthless -- which is a failure mode that looks exactly
 *          like success, so it gets its own check.
 *
 * IT ALSO ASSERTS THAT IT RAN FIRST, through `cases == 0`. "Run first" is a
 * property of the program, not of this comment, and a canary that has been
 * moved below the table is a canary that has been removed. A fixture that
 * has already run has already written the shared out_pe / out_nxo buffers,
 * and the canary memsets them, so this is one cheap check against the one
 * refactoring that would quietly gut the instrument.
 *
 * MEASURED on entry dfe9df87 / producer 503ebf4e, 30 September 2026: mode 1
 * answers 0 with 3072 bytes, mode 2 answers 0 with 480 bytes. These are the
 * numbers, not the expectation, and the constants below are checked against
 * both the value and the header bytes. */
#define CANARY_PE_BYTES 3072u
#define CANARY_NXO_BYTES 480u

static const char *CANARY_SOURCE =
    "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
    "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";

static void entry_canary(const NovaHostImage *i)
{
    static NtBuffer empty = {0};
    uint64_t pe_code, nxo_code, pe_size = 0, nxo_size = 0;
    int pe_shape, nxo_shape;

    /* 0. it ran first. See the comment: this is the check that makes "run
     *    first" a property of the run rather than a claim about the file. */
    CHECKL(cases == 0, "the canary runs before any other fixture has touched the tables",
           "entry_canary");

    memset(out_pe, guard, sizeof out_pe);
    pe_code = run_mode(i, CANARY_SOURCE, &empty, 1, NULL, out_pe, OUTCAP);
    if (pe_code == 0) {
        pe_size = r64(out_pe);
        pe_shape = pe_size + 8 <= OUTCAP && out_pe[8] == 'M' && out_pe[9] == 'Z';
    } else {
        pe_shape = 0;
    }
    CHECKL(pe_code == 0, "the PE adapter answers the canary source with its own success code",
           "entry_canary");
    CHECKL(pe_shape, "the PE adapter answers the canary with PE bytes, MZ at the front",
           "entry_canary");
    CHECKL(pe_size == CANARY_PE_BYTES,
           "the PE adapter answers the canary with the measured byte count", "entry_canary");

    memset(out_nxo, guard, sizeof out_nxo);
    nxo_code = run_mode(i, CANARY_SOURCE, &empty, 2, NULL, out_nxo, OUTCAP);
    if (nxo_code == 0) {
        nxo_size = r64(out_nxo);
        nxo_shape = nxo_size + 8 <= OUTCAP && !(out_nxo[8] == 'M' && out_nxo[9] == 'Z');
    } else {
        nxo_shape = 0;
    }
    CHECKL(nxo_code == 0, "the object producer answers the canary source with its own success code",
           "entry_canary");
    CHECKL(nxo_shape, "the object producer answers the canary with bytes that are not a PE",
           "entry_canary");
    CHECKL(nxo_size == CANARY_NXO_BYTES,
           "the object producer answers the canary with the measured byte count", "entry_canary");

    /* 6. THE LOCK. The whole instrument is the claim that these two routes
     *    are distinguishable, and a claim about distinguishability that is
     *    not itself checked is exactly the kind of thing that stops being
     *    true without anyone noticing. */
    CHECKL(CANARY_PE_BYTES != CANARY_NXO_BYTES,
           "the two routes answer the canary with different byte counts, so the canary discriminates",
           "entry_canary");
    fprintf(stderr, "CANARY pe_code=%llu pe_bytes=%llu nxo_code=%llu nxo_bytes=%llu\n",
            (unsigned long long)pe_code, (unsigned long long)pe_size,
            (unsigned long long)nxo_code, (unsigned long long)nxo_size);
}

/* ==========================================================================
 * A DOCUMENTED ORACLE-SIDE DIVERGENCE. NOT A PRODUCT DEFECT, NOT AN OVERSIGHT.
 *
 * READ THIS LINE FIRST: on DECLARED_CALL_IN_LOOP the two producers BOTH accept
 * the source and emit PE files that DIFFER, and the difference is a property of
 * the C REFERENCE, not of the Nova producer. This block is the fixture that
 * says so with a measurement instead of leaving it as a size gap a reader has
 * to explain. There is NO parity assertion here and there must never be one:
 * byte parity is unmeetable here while the reference emits the surplus below,
 * so a parity check would be red forever for a reason that is not the
 * producer's. What is asserted instead is (1) both sides accept, (2) the two
 * PEs are the same program once the reference's inert surplus is removed, and
 * (3) the size difference is exactly that surplus crossing one FileAlign
 * quantum. The producer is not asked to change.
 *
 * WHAT WAS ALREADY THERE, and why this block is not a duplicate. The gate had
 * no DECLARED fixture at all: `grep -c DECLARED tests_ntasm_x64_lower_nxo_pe.c`
 * answered 0. The gate drove only the SHIPPED CALL_IN_LOOP text, and on the
 * shipped text BOTH sides refuse -- which the harness already records correctly
 * as refused_by_both. What the harness did not have was a shape where both
 * accept and the two outputs differ.
 *
 * MEASURED, by this block, on the bytes named in the header:
 *   producer PE 4608 bytes, .text VirtualSize 2045
 *   reference PE 5120 bytes, .text VirtualSize 2059
 *   difference 14 bytes = 2 x 7, and 2059 crosses the 0x800 FileAlign quantum
 *   where 2045 does not, which is the whole of the 512 byte file difference.
 *
 * THE SURPLUS IS LOCATED AND MEASURED HERE, NOT IMPORTED. The byte sequence
 * 9c 8f 85 f0 fe ff ff (pushf ; pop [rbp-0x110]) occurs 6 times in the producer
 * .text and 8 times in the reference .text, and the two extra ones account for
 * exactly the 14 byte VirtualSize difference.
 *
 * "THE SAME PROGRAM" IS ASSERTED AT THE REACH THIS GATE HAS, AND NOT BEYOND.
 * The two .text are NOT byte identical after the surplus is deleted -- that is
 * false, and no such claim is made. What is measured and asserted is:
 *   1. delete every surplus pair from each .text: both streams are 2003 bytes;
 *   2. exactly FOUR bytes then differ, and every one of them lies inside the 32
 *      bit displacement of a relative branch (e8 call, or 0f 8x jcc) -- no
 *      opcode and no immediate differs anywhere in either program;
 *   3. each of those four branches lands on the SAME stripped offset when its
 *      target is resolved in each side's own raw .text and mapped back through
 *      the strip.
 * (3) is what makes this a semantic statement: a rel32 whose target is the same
 * instruction is the same branch. So the two PEs are the same program, and the
 * difference between them is where the reference's surplus sits -- which moves
 * every later branch by one pair.
 *
 * WHAT IS ASSERTED HERE VS REPORTED ELSEWHERE -- kept apart on purpose, because
 * merging an inference into a measurement is how a claim stops being checkable:
 *   MEASURED HERE: the 6/8 occurrence counts, the four differing branch
 *   displacements and their common targets, the 14 byte difference, both
 *   VirtualSizes, both FileAlignments, the align-up arithmetic, the section
 *   shift, that the spill slot [rbp-0x110] is written by these pops and read by
 *   NO instruction in either .text, and that both extra pairs are followed by a
 *   general-register restore (48 8b) rather than by anything that consumes the
 *   flags.
 *   REPORTED, NOT MEASURED HERE: that there are ZERO flag-writing opcodes
 *   between the second save and the restore -- the sibling investigation's
 *   argument about inertness. This block runs no decoder and does not re-prove
 *   it. What it measures instead is the slot's arity, which is countable, and
 *   the two are not merged.
 *
 * THE THREE NEGATIVE CONTROLS, in the tree, each aimed at one clause:
 *   1. flip one byte of the producer .text -> the agreement test must go red,
 *      so it is not a test that passes on anything;
 *   2. flip one byte INSIDE a call displacement -> the branch-target clause
 *      must go red, so a program that branched elsewhere cannot read as
 *      equivalent;
 *   3. delete ONE surplus occurrence from a copy of the reference .text -> the
 *      count difference must read 1 instead of 2, so "two extra pairs" is a
 *      measurement and not a literal.
 *
 * THE GATE'S OWN COUNTS DO NOT MOVE. This block increments none of
 * oracle_compared_total, oracle_diverged_total, oracle_free_total,
 * oracle_refused_total or oracle_cases, so the census check (== 11) and the
 * relocation/image/runtime case check (== 30) are provably unmoved by it. It
 * adds only to `checks`, `cases` and `failures`.
 * ========================================================================== */

/* The seven byte sequence the reference emits and the producer does not:
 * 9c pushf, then 8f 85 f0 fe ff ff pop qword [rbp-0x110]. */
static const uint8_t NG6_SURPLUS[7] = {0x9c, 0x8f, 0x85, 0xf0, 0xfe, 0xff, 0xff};

/* CALL_IN_LOOP with the two flag clauses the reference requires and a value on
 * every return -- the LADDER's accepted text, verbatim from the measurement at
 * the call_inside_a_counted_loop row. `rflags` is in step's and twice's
 * clobbers because both bodies contain `add`. */
static const char *DECLARED_CALL_IN_LOOP =
    "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
    "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rbx,rflags} {\n"
    "call seed()\nmov rbx, 6\njmp body\ndead:\nmov rax, 99\nbody:\ntop:\n"
    "call step()\nadd rax, 1\nsub rbx, 1\njne top\njmp done\ndone:\nreturn 0\n}\n"
    "fn seed()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n"
    "fn step()->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\n"
    "call twice()\nadd rax, 1\nreturn 0\n}\n"
    "fn twice()->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\n"
    "mov rax, 4\nadd rax, 1\nreturn 5\n}\n}\n";

/* The same shape with the callees' `add` deleted, so NEITHER callee writes a
 * flag, so `rflags` is no longer owed by either. main keeps its own arithmetic
 * and its own clauses, and the counted loop and both calls stay. Used to ask
 * whether the divergence survives the removal of rflags from the CALLEE, which
 * is the question the gate header's wording and the measured trigger disagree
 * about. */
static const char *DECLARED_NO_CALLEE_RFLAGS =
    "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
    "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rbx,rflags} {\n"
    "call seed()\nmov rbx, 6\njmp body\ndead:\nmov rax, 99\nbody:\ntop:\n"
    "call step()\nadd rax, 1\nsub rbx, 1\njne top\njmp done\ndone:\nreturn 0\n}\n"
    "fn seed()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n"
    "fn step()->u64\neffects {changes_flags}\nclobbers {rax} {\n"
    "call twice()\nreturn 0\n}\n"
    "fn twice()->u64\neffects {changes_flags}\nclobbers {rax} {\n"
    "mov rax, 4\nreturn 5\n}\n}\n";

/* The rflags callee with the LOOP deleted: a straight line main that still
 * calls step, so step still owes rflags. The other half of the trigger
 * question -- is the counted loop needed once rflags is in the callee? */
static const char *DECLARED_NO_LOOP =
    "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
    "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\n"
    "call seed()\ncall step()\nadd rax, 1\nreturn 0\n}\n"
    "fn seed()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n"
    "fn step()->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\n"
    "call twice()\nadd rax, 1\nreturn 0\n}\n"
    "fn twice()->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\n"
    "mov rax, 4\nadd rax, 1\nreturn 5\n}\n}\n";

/* One section header of a PE, read from the PE's OWN section table. Nothing
 * here is computed by the producer or transcribed from the other side: the
 * point of a comparison between two PEs is that each one says where its own
 * .text is. */
typedef struct { uint32_t va, vsize, raw, rawsz; int found; } Ng6Section;

static Ng6Section ng6_section(const uint8_t *pe, const char *name)
{
    Ng6Section s;
    uint32_t nt;
    uint16_t count, opt;
    size_t table;
    memset(&s, 0, sizeof s);
    nt = rd32(pe + 60);
    count = rd16(pe + nt + 6);
    opt = rd16(pe + nt + 20);
    table = (size_t)nt + 24 + opt;
    for (unsigned i = 0; i < count; i++) {
        const uint8_t *h = pe + table + (size_t)i * 40;
        char got[9];
        memcpy(got, h, 8);
        got[8] = 0;
        if (!strcmp(got, name)) {
            s.va = rd32(h + 12);
            s.vsize = rd32(h + 8);
            s.raw = rd32(h + 20);
            s.rawsz = rd32(h + 16);
            s.found = 1;
            return s;
        }
    }
    return s;
}

static uint32_t ng6_file_align(const uint8_t *pe)
{
    uint32_t nt = rd32(pe + 60);
    return rd32(pe + nt + 24 + 36); /* PE32+ optional header, FileAlignment */
}

static uint32_t ng6_align_up(uint32_t v, uint32_t a)
{
    return a ? (v + a - 1u) / a * a : v;
}


/* Builds the stripped stream AND, for every stripped offset, the RAW offset it
 * came from. The map is what lets a branch target be compared in raw
 * coordinates on one side and in raw on the other and still name the same
 * instruction -- which is the whole point of the equivalence test below. */
static size_t ng6_strip_map(const uint8_t *in, size_t n, uint8_t *out, size_t *map,
                            unsigned *deleted)
{
    size_t i = 0, o = 0;
    *deleted = 0;
    while (i < n) {
        if (n - i >= sizeof NG6_SURPLUS && !memcmp(in + i, NG6_SURPLUS, sizeof NG6_SURPLUS)) {
            i += sizeof NG6_SURPLUS;
            (*deleted)++;
            continue;
        }
        if (out) out[o] = in[i];
        if (map) map[o] = i;
        o++;
        i++;
    }
    return o;
}

static int32_t ng6_s32(const uint8_t *p)
{
    uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
                 ((uint32_t)p[3] << 24);
    return (int32_t)v;
}

/* The raw .text offset a stripped offset stands for, given the counts. */
static size_t ng6_to_raw(size_t raw_guess, unsigned pairs)
{
    return raw_guess - (size_t)pairs * sizeof NG6_SURPLUS;
}

/* THE INSTRUCTION-LEVEL EQUIVALENCE TEST, stated at the reach this gate
 * actually has. It is NOT "the two .text are byte identical" -- that is false
 * here and is NOT claimed anywhere in this block. What is claimed, and checked:
 *
 *   1. delete every surplus pair from each .text: the two streams then have the
 *      SAME LENGTH;
 *   2. EVERY differing byte lies inside the 32 bit displacement of a relative
 *      branch (e8 call, or 0f 8x jcc). A differing opcode or immediate is a
 *      difference in the program and fails here;
 *   3. for every such branch, the branch TARGET -- taken in each side's own raw
 *      .text, then mapped back through the strip to a stripped offset -- is the
 *      SAME offset on both sides.
 *
 * (3) is what turns (1) and (2) into a semantic claim rather than a shrug: a
 * rel32 whose target lands on the same instruction is the same branch, so the
 * two streams are the same program that differ only in where the surplus sits.
 * Measured on this fixture: 2003 stripped bytes on both sides, four differing
 * bytes, all four inside call/jcc displacements, all four resolving to the
 * same stripped target. Each leg has a control below, so none can pass
 * vacuously. */
static int ng6_same_program(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
                            uint8_t *sa, size_t *map_a, uint8_t *sb, size_t *map_b,
                            unsigned *pairs_a, unsigned *pairs_b,
                            unsigned *sites, unsigned *unexplained)
{
    size_t na = ng6_strip_map(a, a_len, sa, map_a, pairs_a);
    size_t nb = ng6_strip_map(b, b_len, sb, map_b, pairs_b);
    unsigned counted = 0;
    *sites = 0;
    *unexplained = 0;
    if (na != nb) return 0;
    for (size_t k = 0; k < na; k++) {
        size_t op, doff, len, ta, tb;
        unsigned pa = 0, pb = 0;
        if (sa[k] == sb[k]) continue;
        if (k >= 1 && sa[k - 1] == 0xe8) { op = k - 1; doff = 1; len = 5; }
        else if (k >= 2 && sa[k - 2] == 0x0f && (sa[k - 1] & 0xf0) == 0x80) {
            op = k - 2; doff = 2; len = 6;
        } else { (*unexplained)++; continue; }
        counted++;
        ta = map_a[op] + len + (size_t)((int64_t)ng6_s32(sa + op + doff));
        tb = map_b[op] + len + (size_t)((int64_t)ng6_s32(sb + op + doff));
        /* how many surplus pairs precede each raw target, then compare the two
         * targets as stripped offsets */
        /* A target outside its own .text is not a branch to the same
         * instruction on either side, so it fails the comparison. The bound is
         * checked here rather than inside ng6_strip_map because a control below
         * deliberately perturbs a displacement, and a control must fail by
         * ASSERTING rather than by reading past a buffer. */
        if (ta > a_len || tb > b_len) return 0;
        ng6_strip_map(a, ta, NULL, NULL, &pa);
        ng6_strip_map(b, tb, NULL, NULL, &pb);
        if (ng6_to_raw(ta, pa) != ng6_to_raw(tb, pb)) return 0;
    }
    *sites = counted;
    return *unexplained == 0;
}

/* One measured row: both sides accept, the two PEs are compared, and the
 * verdict is a three-state the caller asserts on. Returns the verdict:
 *   0 setup failed (setup_not_reached already counted by the caller)
 *   1 byte identical
 *   2 both accept and differ
 * The producer PE is written into `producer_pe`, the reference PE into
 * `reference_pe`; both are borrowed, never freed here. */
static int ng6_compare(const NovaHostImage *i, const char *source, const char *label,
                       uint8_t *producer_pe, uint64_t *producer_size,
                       uint8_t **reference_pe, size_t *reference_size)
{
    static NtBuffer empty = {0};
    uint64_t entry = 0;
    *reference_pe = NULL;
    *reference_size = 0;
    memset(producer_pe, guard, OUTCAP);
    SETUPL(run_mode(i, source, &empty, 1, NULL, producer_pe, OUTCAP) == 0 &&
           r64(producer_pe) + 8 <= OUTCAP,
           "the PRODUCER accepts this shape and answers a PE", label);
    if (r64(producer_pe) == 0 || r64(producer_pe) + 8 > OUTCAP) return 0;
    *producer_size = r64(producer_pe);
    SETUPL(reference_refusal_code(source) == 0,
           "the C REFERENCE accepts this shape too", label);
    if (reference_refusal_code(source) != 0) return 0;
    SETUPL(oracle_pe(source, reference_pe, reference_size, &entry),
           "the C reference emits a PE for it", label);
    if (!*reference_pe) return 0;
    if (*producer_size == *reference_size && !memcmp(producer_pe + 8, *reference_pe, *producer_size))
        return 1;
    return 2;
}

static void declared_loop_divergence(const NovaHostImage *i)
{
    static uint8_t producer_pe[OUTCAP];
    static uint8_t text_a[OUTCAP], text_b[OUTCAP], perturbed[OUTCAP];
    static size_t map_a[OUTCAP], map_b[OUTCAP];
    uint8_t *reference_pe = NULL;
    size_t reference_size = 0, prod_len, ref_len;
    uint64_t producer_size = 0;
    Ng6Section pt, rt;
    unsigned pairs_prod = 0, pairs_ref = 0;
    int verdict, no_rflags, no_loop, shifted_sections;

    /* ---- the documented divergence itself ---- */
    cases++;
    verdict = ng6_compare(i, DECLARED_CALL_IN_LOOP, "declared_call_in_loop",
                          producer_pe, &producer_size, &reference_pe, &reference_size);
    /* NO PARITY CHECK HERE AND NOWHERE IN THIS BLOCK. See the header above: the
 * producer is correct, the surplus is the reference's, and a parity assertion
 * would be red forever for a reason that is not the producer's. What is
 * asserted instead is that the two are the SAME PROGRAM once the reference's
 * inert surplus is removed, which is the strongest true statement available. */
    SETUPL(verdict == 2, "both producers accept DECLARED_CALL_IN_LOOP and their PEs differ",
           "declared_call_in_loop");
    if (verdict == 2) {
        /* each side's .text, located in that side's own section table */
        pt = ng6_section(producer_pe + 8, ".text");
        rt = ng6_section(reference_pe, ".text");
        CHECKL(pt.found && rt.found,
               "both PEs carry a .text section, located from their own headers",
               "declared_call_in_loop");
        CHECKL(pt.vsize == 2045u && rt.vsize == 2059u,
               "the .text VirtualSizes are the measured 2045 (producer) and 2059 (reference)",
               "declared_call_in_loop");
        CHECKL(rt.vsize - pt.vsize == 14u,
               "the whole VirtualSize difference is 14 bytes, the size of two surplus pairs",
               "declared_call_in_loop");

        /* THE ALIGNMENT CLIFF, asserted as arithmetic so a reader can redo it
         * with a calculator: same FileAlignment on both PEs, and the quantum
         * crossing is the entire file-size difference. */
        {
            uint32_t fa_p = ng6_file_align(producer_pe + 8), fa_r = ng6_file_align(reference_pe);
            uint32_t up_p = ng6_align_up(pt.vsize, fa_p), up_r = ng6_align_up(rt.vsize, fa_r);
            fprintf(stderr,
                    "ALIGNMENT declared label=declared_call_in_loop file_align=0x%lx producer_vsize=%lu->0x%lx "
                    "reference_vsize=%lu->0x%lx file_producer=%llu file_reference=%zu\n",
                    (unsigned long)fa_p, (unsigned long)pt.vsize, (unsigned long)up_p,
                    (unsigned long)rt.vsize, (unsigned long)up_r,
                    (unsigned long long)producer_size, reference_size);
            CHECKL(fa_p == 512u && fa_r == fa_p,
                   "both PEs declare FileAlignment 0x200, so the quantum is the same on both sides",
                   "declared_call_in_loop");
            CHECKL(up_p == 0x800u && up_r == 0xa00u,
                   "2045 rounds to 0x800 and 2059 crosses to 0xa00: one FileAlign quantum apart",
                   "declared_call_in_loop");
            CHECKL(pt.rawsz == up_p && rt.rawsz == up_r,
                   "each .text SizeOfRawData is its own VirtualSize rounded up to FileAlignment",
                   "declared_call_in_loop");
            CHECKL(reference_size == producer_size + 0x200u,
                   "the 512 byte file difference is exactly the one quantum the cliff costs",
                   "declared_call_in_loop");
            /* the shift every later section pays for it, measured from the two
             * section tables and not asserted as a list of offsets */
            shifted_sections = 0;
            {
                uint32_t nt = rd32(reference_pe + 60);
                uint16_t count = rd16(reference_pe + nt + 6);
                uint16_t opt = rd16(reference_pe + nt + 20);
                size_t tref = (size_t)nt + 24 + opt;
                uint32_t ntp = rd32(producer_pe + 8 + 60);
                uint16_t countp = rd16(producer_pe + 8 + ntp + 6);
                uint16_t optp = rd16(producer_pe + 8 + ntp + 20);
                size_t tprod = (size_t)ntp + 24 + optp;
                CHECKL(count == countp, "both PEs carry the same number of sections",
                       "declared_call_in_loop");
                for (unsigned k = 0; k < count && k < countp; k++) {
                    const uint8_t *hr = reference_pe + tref + (size_t)k * 40;
                    const uint8_t *hp = producer_pe + 8 + tprod + (size_t)k * 40;
                    char nr[9], np[9];
                    memcpy(nr, hr, 8); nr[8] = 0;
                    memcpy(np, hp, 8); np[8] = 0;
                    if (strcmp(nr, np)) continue;
                    if (strcmp(nr, ".text")) {
                        /* every section after .text is displaced by exactly one
                         * quantum on the reference side */
                        shifted_sections +=
                            (int)(rd32(hr + 20) == rd32(hp + 20) + 0x200u);
                    }
                }
            }
            CHECKL(shifted_sections >= 2,
                   "every section after .text sits one FileAlign quantum later in the reference",
                   "declared_call_in_loop");
        }

        /* THE SURPLUS, LOCATED IN BOTH .text AND COUNTED IN BOTH. The counts
         * are the ones the divergence decomposes into: six saves on the
         * producer side, eight on the reference side. */
        prod_len = pt.raw < producer_size ? pt.vsize : 0;
        ref_len = rt.raw < reference_size ? rt.vsize : 0;
        SETUPL(prod_len > 0 && ref_len > 0 &&
               (size_t)pt.raw + prod_len <= producer_size &&
               (size_t)rt.raw + ref_len <= reference_size,
               "both .text payloads lie inside their own PE files", "declared_call_in_loop");
        if (prod_len && ref_len && (size_t)pt.raw + prod_len <= producer_size &&
            (size_t)rt.raw + ref_len <= reference_size) {
            const uint8_t *pa = producer_pe + 8 + pt.raw;
            const uint8_t *ra = reference_pe + rt.raw;
            {
                unsigned sites = 0, unexplained = 0;
                int same = ng6_same_program(pa, prod_len, ra, ref_len, text_a, map_a,
                                            text_b, map_b, &pairs_prod, &pairs_ref,
                                            &sites, &unexplained);
                CHECKL(same,
                       "the two .text payloads are the SAME PROGRAM: equal length once the "
                       "surplus pairs are deleted, every differing byte inside a rel32 "
                       "displacement, and every one of those branches landing on the same "
                       "instruction on both sides", "declared_call_in_loop");
                CHECKL(unexplained == 0u,
                       "no differing byte lies outside a branch displacement, so no opcode or "
                       "immediate differs between the two programs", "declared_call_in_loop");
                CHECKL(sites == 4u,
                       "exactly four bytes differ after the strip, all four branch displacements "
                       "-- the measured shape of this divergence, not a bound", "declared_call_in_loop");
                fprintf(stderr,
                        "EQUIV declared stripped_producer=%zu stripped_reference=%zu "
 "differing_branch_displacements=%u unexplained=%u\n",
                        (size_t)(prod_len - pairs_prod * sizeof NG6_SURPLUS),
                        (size_t)(ref_len - pairs_ref * sizeof NG6_SURPLUS), sites, unexplained);
            }
            CHECKL(pairs_prod == 6u && pairs_ref == 8u,
                   "the surplus sequence occurs 6 times in the producer .text and 8 in the "
                   "reference .text, so the reference carries exactly two extra", "declared_call_in_loop");
            CHECKL(pairs_ref - pairs_prod == 2u &&
                   (pairs_ref - pairs_prod) * sizeof NG6_SURPLUS == rt.vsize - pt.vsize,
                   "the two extra pairs ARE the whole 14 byte VirtualSize difference",
                   "declared_call_in_loop");
            /* WHERE THE TWO EXTRA PAIRS SIT, measured here rather than asserted:
             * both are immediately followed by a spill restore of a GENERAL
             * register (48 8b 8d 70 ff ff ff, mov rcx,[rbp-0x90]) and neither is
             * followed by anything that consumes [rbp-0x110]. The spill slot
             * [rbp-0x110] is WRITTEN by these eight pops and READ by no
             * instruction in either .text (0 reads of 8b85 f0feffff and of
             * 488b85 f0feffff, measured below), so the pair stores flags to a
             * slot no instruction ever loads back.
             *
             * THE ZERO FLAG-WRITING OPCODES BETWEEN THE SECOND SAVE AND THE
             * RESTORE is the sibling investigation's argument and is NOT
             * re-measured here: this block runs no decoder and does not claim
             * it. What it does measure is the slot's arity, which is the part
             * that can be counted. */
            {
                unsigned slot_reads = 0, j;
                size_t extra[2];
                unsigned found = 0;
                /* the reads of [rbp-0x110] in BOTH .text */
                for (j = 0; j + 6 <= ref_len; j++)
                    if (ra[j] == 0x8b && ra[j + 1] == 0x85 &&
                        !memcmp(ra + j + 2, "\xf0\xfe\xff\xff", 4))
                        slot_reads++;
                for (j = 0; j + 6 <= prod_len; j++)
                    if (pa[j] == 0x8b && pa[j + 1] == 0x85 &&
                        !memcmp(pa + j + 2, "\xf0\xfe\xff\xff", 4))
                        slot_reads++;
                CHECKL(slot_reads == 0u,
                       "no instruction in either .text reads the [rbp-0x110] slot the surplus "
                       "pairs write, measured by scanning both payloads for 8b85 f0feffff",
                       "declared_call_in_loop");
                /* THE TWO EXTRA PAIRS, located by STRIPPED POSITION rather than by raw
                 * offset. Raw offsets do not line up past the first extra pair -- one
                 * extra pair shifts every later pair by seven bytes on the reference
                 * side only -- so a raw-offset comparison names the wrong pairs. The
                 * stripped position is what identifies "the same save in the same
                 * place in the program", which is the question being asked. */
                for (j = 0; j + sizeof NG6_SURPLUS <= ref_len; j++) {
                    size_t k, stripped = j;
                    int shared = 0;
                    if (memcmp(ra + j, NG6_SURPLUS, sizeof NG6_SURPLUS)) continue;
                    for (k = 0; k < j; k++)
                        if (!memcmp(ra + k, NG6_SURPLUS, sizeof NG6_SURPLUS)) stripped -= 7;
                    for (k = 0; k + sizeof NG6_SURPLUS <= prod_len && !shared; k++) {
                        size_t other = k;
                        size_t m;
                        if (memcmp(pa + k, NG6_SURPLUS, sizeof NG6_SURPLUS)) continue;
                        for (m = 0; m < k; m++)
                            if (!memcmp(pa + m, NG6_SURPLUS, sizeof NG6_SURPLUS)) other -= 7;
                        if (other == stripped) shared = 1;
                    }
                    if (!shared && found < 2) extra[found++] = j;
                }
                CHECKL(found == 2u,
                       "exactly two reference surplus pairs have no counterpart at the same "
                       "STRIPPED position in the producer .text", "declared_call_in_loop");
                if (found == 2) {
                    CHECKL(ra[extra[0] + 7] == 0x48 && ra[extra[0] + 8] == 0x8b &&
                           ra[extra[1] + 7] == 0x48 && ra[extra[1] + 8] == 0x8b,
                           "both surplus pairs are followed by a general-register restore "
                           "(48 8b), not by anything that consumes the flags they wrote",
                           "declared_call_in_loop");
                    fprintf(stderr,
                            "SURPLUS declared extra_pair_raw_offsets=%zu,%zu followed_by=488b "
 "spill_slot_reads=%u\n", extra[0], extra[1], slot_reads);
                }
            }
            /* NEGATIVE CONTROL 1, in the tree. One flipped byte of the producer
             * .text must make the agreement test fail. Without this, "the two
             * are the same program" would also read true of a test that passes
             * on anything. */
            memcpy(perturbed, pa, prod_len);
            perturbed[prod_len / 2] ^= 0x01;
            {
                unsigned cp = 0, cr = 0, cs = 0, cu = 0;
                CHECKL(!ng6_same_program(perturbed, prod_len, ra, ref_len, text_a, map_a,
                                         text_b, map_b, &cp, &cr, &cs, &cu),
                       "CONTROL: one flipped byte of the producer .text makes the agreement "
                       "test go red, so the test is not vacuous", "declared_call_in_loop");
            }
            /* NEGATIVE CONTROL 1b, aimed at the clause that could hide a
             * difference: flip a byte of a branch DISPLACEMENT, which leg (2)
             * permits and leg (3) must still catch. Without it, a program that
             * branched elsewhere would read as equivalent. */
            {
                unsigned cp = 0, cr = 0, cs = 0, cu = 0;
                size_t at = 0;
                /* Bounds are checked because a read one byte past a global is
                 * exactly what ASan is here to refuse: this control has to fail
                 * by ASSERTING, not by trapping. */
                memcpy(perturbed, pa, prod_len);
                while (at + 5 < prod_len && perturbed[at] != 0xe8) at++;
                CHECKL(at + 5 < prod_len,
                       "CONTROL: the producer .text holds a call whose displacement can be "
                       "perturbed", "declared_call_in_loop");
                if (at + 5 < prod_len) perturbed[at + 1] ^= 0x10;
                CHECKL(!ng6_same_program(perturbed, prod_len, ra, ref_len, text_a, map_a,
                                         text_b, map_b, &cp, &cr, &cs, &cu),
                       "CONTROL: flipping a byte inside a call displacement makes the agreement "
                       "test go red, so the branch-target leg is not vacuous either",
                       "declared_call_in_loop");
            }
            /* NEGATIVE CONTROL 2, in the tree. Delete ONE surplus occurrence
             * from a copy of the reference .text: the count difference must
             * read 1, not 2. So "two extra pairs" is a measurement. */
            {
                size_t first = (size_t)-1;
                unsigned cp = 0, cr = 0;
                for (size_t k = 0; k + sizeof NG6_SURPLUS <= ref_len; k++)
                    if (!memcmp(ra + k, NG6_SURPLUS, sizeof NG6_SURPLUS)) { first = k; break; }
                if (first != (size_t)-1) {
                    size_t o = 0;
                    for (size_t k = 0; k < ref_len; k++) {
                        if (k >= first && k < first + sizeof NG6_SURPLUS) continue;
                        perturbed[o++] = ra[k];
                    }
                    (void)ng6_strip_map(perturbed, o, NULL, NULL, &cr);
                    (void)ng6_strip_map(pa, prod_len, NULL, NULL, &cp);
                    CHECKL(cr - cp == 1u,
                           "CONTROL: deleting one surplus pair from the reference drops the "
                           "count difference to 1, so the 2 is measured", "declared_call_in_loop");
                } else {
                    CHECKL(0, "CONTROL: the surplus sequence was found in the reference .text",
                           "declared_call_in_loop");
                }
            }
            fprintf(stderr,
                    "ORACLE_SIDE attribute=reference cause=CALLEE_RFLAGS_SAVE_AND_RESTORE "
 "surplus=9c8f85f0feffff producer_pairs=%u reference_pairs=%u producer_text=%u "
 "reference_text=%u file_producer=%llu file_reference=%zu both_accept=1 parity_asserted=0\n",
                    pairs_prod, pairs_ref, (unsigned)pt.vsize, (unsigned)rt.vsize,
                    (unsigned long long)producer_size, reference_size);
        }
    } else if (verdict == 1) {
        /* If the reference ever stops emitting the surplus this block's whole
         * subject is gone, and saying so is the honest outcome. Named, not
         * silent. */
        fprintf(stderr,
                "ORACLE_SIDE attribute=none reason=the two PEs are now byte identical on this "
 "shape; the documented reference-side divergence no longer reproduces [declared_call_in_loop]\n");
        CHECKL(0, "the reference's surplus is still present, or this block's subject is void",
               "declared_call_in_loop");
    }
    free(reference_pe);

    /* ---- THE TRIGGER, CORRECTED, AND MEASURED HERE RATHER THAN BELIEVED.
     *
     * The header at the top of this file says the divergence « is a function of
     * a call inside the loop and not of the loop alone ». Two rows, each of which
     * BOTH sides accept, each compared with the SAME code path as the row above,
     * separate that into its two candidate causes:
     *
     *   no_callee_rflags -- the counted loop and BOTH calls are still there; the
     *     only change is that neither callee writes a flag any more, so `rflags`
     *     is no longer owed by step or twice. MEASURED: byte IDENTICAL, 4608 on
     *     both sides. The loop alone does not diverge.
     *
     *   no_loop -- the loop is gone, main is straight line, but step and twice
     *     still owe and declare `rflags`, and the call to step is still there.
     *     MEASURED: DIVERGES, 4608 against 5120. A loop is not needed.
     *
     * So the trigger is `rflags` in a CALLEE's clobbers set. The header's
     * narrower sentence is not wrong on its own field -- there IS a call -- but
     * it names the loop, and the loop is not what the divergence is a function
     * of. The header is NOT edited by this block; the correction is recorded
     * here and the header's own claim stays as written, so a reader can see
     * both. */
    {
        static uint8_t prod2[OUTCAP];
        uint8_t *ref2 = NULL;
        size_t ref2_size = 0;
        uint64_t prod2_size = 0;
        cases++;
        no_rflags = ng6_compare(i, DECLARED_NO_CALLEE_RFLAGS, "declared_no_callee_rflags",
                                prod2, &prod2_size, &ref2, &ref2_size);
        fprintf(stderr, "TRIGGER shape=no_callee_rflags producer_bytes=%llu reference_bytes=%zu "
 "verdict=%s\n", (unsigned long long)prod2_size, ref2_size,
                no_rflags == 1 ? "IDENTICAL" : no_rflags == 2 ? "DIVERGES" : "SETUP_FAILED");
        free(ref2);
        cases++;
        no_loop = ng6_compare(i, DECLARED_NO_LOOP, "declared_no_loop", prod2, &prod2_size,
                              &ref2, &ref2_size);
        fprintf(stderr, "TRIGGER shape=no_loop producer_bytes=%llu reference_bytes=%zu "
 "verdict=%s\n", (unsigned long long)prod2_size, ref2_size,
                no_loop == 1 ? "IDENTICAL" : no_loop == 2 ? "DIVERGES" : "SETUP_FAILED");
        free(ref2);
        CHECKL(no_rflags == 1,
               "MEASURED: with the callees' rflags removed -- same counted loop, same two "
               "calls -- the two PEs are byte identical, so the LOOP ALONE does not diverge",
               "declared_trigger");
        CHECKL(no_loop == 2,
               "MEASURED: with the loop removed -- same callees, same rflags, call still "
               "present -- the two PEs still diverge, so the loop is not the trigger either; "
               "the trigger is rflags in the CALLEE's clobbers set", "declared_trigger");
    }
}

int main(void)
{
    const char *paths[] = {
        "tests/nova/tests/x64-lower-nxo-pe-entry.nova",
        "compiler/nova/backend/x64/x64_lower_nxo_pe.nova",
        "compiler/nova/backend/x64/x64_lower_nxo.nova",
        "compiler/nova/backend/x64/x64_lower_control.nova",
        "compiler/nova/backend/x64/x64_lower_fixed.nova",
        "compiler/nova/backend/x64/x64_fixed.nova",
        "compiler/nova/analysis/types/register_widths.nova",
        "compiler/nova/formats/nxo/nxo_link_pe.nova",
        "compiler/nova/formats/nxo/nxo_merge.nova",
        "compiler/nova/formats/nxo/nxo_pe.nova",
        "compiler/nova/formats/nxo/nxo.nova",
        "compiler/nova/formats/pe/pe.nova",
        "compiler/nova/frontend/parser.nova",
        "compiler/nova/frontend/ast.nova",
        "compiler/nova/frontend/lexer.nova"
    ,
        "compiler/nova/macros/macro_splice.nova",
        "compiler/nova/macros/macro_expand.nova",
        "compiler/nova/macros/constant_eval.nova",
        "compiler/nova/macros/constant_eval.nova"};
    char *sources[18] = {0};
    size_t sizes[18] = {0};
    NtFInput inputs[18];
    char many[8192];
    for (unsigned i = 0; i < 18; i++) {
        size_t n = 0;
        sources[i] = loadf(paths[i], &n);
        sizes[i] = n;
        inputs[i] = (NtFInput){paths[i], sources[i], n};
    }
    int all = 1;
    for (unsigned i = 0; i < 18; i++) if (!sources[i]) all = 0;
    CHECK(all, "sources load");
    /* The identity check runs before the host image exists and before a
     * single fixture, so a run whose bytes are not the bytes the header names
     * says so on the way in rather than in a comment somebody reads later. */
    verify_identity(paths, sources, sizes, 18);
    NtArtifact compiler = {0};
    int compiled = all && nova_compile_many_v2(inputs, 18, &compiler);
    CHECK(compiled, "Nova modules compile");
    if (!compiled) fprintf(stderr, "E%u %zu:%zu %s\n", compiler.error.code, compiler.error.line,
                           compiler.error.column, compiler.error.message);
    NovaHostImage image = {0};
    CHECK(compiled && nova_host_map(&compiler, &image), "host map");
    /* The run's own temporary directory, opened HERE, before the first fixture
     * and BEFORE entry_canary, for two reasons. It must precede the fixtures
     * because the twelve paths below are resolved from it. It must precede
     * entry_canary because that canary asserts cases == 0 on entry and exists
     * precisely to notice a second thing being run before it; putting the open
     * inside the image block would have been that second thing. It is a
     * filesystem mkdir and it touches no counter, so `cases` is untouched. */
    run_files_open();
    if (image.memory) {
        /* THE CANARY RUNS FIRST, before the contract suite and before every
         * fixture below. Not as a convention: entry_canary asserts cases == 0
         * on entry, so if anything is ever moved above this line the canary
         * says so instead of quietly ceasing to be a canary. */
        entry_canary(&image);
        /* The two flag-inference legs, run before the fixture list so their
         * answer is on the record before any row whose comment cites them. */
        flag_inference_pair(&image);
        char *ng5_helper_text = ng5_alias_contract("uefi", "helper");
        CHECK(ng5_helper_text != NULL, "the C object writer wrote the helper contract");
        if (ng5_helper_text) {
        /* The producer source, its C expressible twin, and the definition object
         * the linker is handed. The data half of the expectation comes from the C
         * frontend and codegen; only the call/ret text stream and the import stay
         * the producer's own documented form, which the C frontend cannot
         * express. See the oracle block above. */
        char source[8192], twin[8192];
        /* The name the reference gives this unit's import of `helper`, asked of
         * the reference from the PRODUCER source's own import declaration. It
         * is not built from the twin's module and the alias: the reference
         * names an unresolved import by its path and discards both of those,
         * so a constructed name here would agree with a wrong producer. Every
         * link fixture below shares one alias and one import path, so this is
         * derived once, and the per-case check in ng5_link_case re-derives it
         * again and compares, so this value cannot be the only thing standing
         * between a wrong name and a green run. */
        char import_name[128];
        static uint8_t callee[6] = {0xb8, 42, 0, 0, 0, 0xc3};
        static const Ng5Item classic[] = {
            {"zeta", 2, 4660, 2}, {"alpha", 1, 42, 2}, {"beta", 4, 2018915346u, 3}
        };
        if (ng5_build_source(source, sizeof source, classic, 3, "uefi", "helper", 1, "call helper()") > sizeof source ||
            ng5_build_source(twin, sizeof twin, classic, 3, "uefi", "helper", 0, NULL) > sizeof twin) {
            CHECK(0, "link fixture bounded");
        } else if (!ng5_reference_import_name(source, import_name, sizeof import_name)) {
            CHECK(0, "the C reference names the producer source's import");
        } else {
            /* the definition carries the contract the C object writer builds for
             * that declaration, which is the text the Nova import names */
            NtObjectSymbol helper = {import_name, ng5_helper_text, 1, NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION, 0, 6};
            NtObject right = {0};
            NtBuffer right_file = {0};
            right.target = 1;
            right.sections[0] = (NtBuffer){callee, sizeof callee, sizeof callee};
            right.symbols = &helper; right.symbol_count = 1;
            right_file = write_object(&right);
            ng5_link_case(&image, "link_classic", source, twin, "helper", import_name, &right_file);
            /* the retained refusals, against the same definition object */
            {
                static const Ng5Item out_of_range[] = {
                    {"zeta", 2, 4660, 2}, {"alpha", 1, 256, 2}, {"beta", 4, 2018915346u, 3}
                };
                char missing[8192], arity[8192], range[8192];
                if (ng5_build_source(missing, sizeof missing, classic, 3, "uefi", "helper", 1, "call bad()") > sizeof missing ||
                    ng5_build_source(arity, sizeof arity, classic, 3, "uefi", "helper", 1, "call helper(1)") > sizeof arity ||
                    ng5_build_source(range, sizeof range, out_of_range, 3, "uefi", "helper", 1, "call helper()") > sizeof range) {
                    CHECK(0, "retained refusal copies bounded");
                } else {
                    CHECK(strstr(missing, "call bad()") && strstr(arity, "call helper(1)") &&
                          strstr(range, "export data alpha:u8=256"), "retained refusal sources edited");
                    rejected(&image, missing, &right_file, 65536, 800, "missing alias transactional");
                    rejected(&image, arity, &right_file, 65536, 800, "arity transactional");
                    rejected(&image, range, &right_file, 65536, 800, "data range transactional");
                }
            }
            {
                /* one perturbed byte of the canonical text, the historical
                 * placeholder, and the real text, so the comparison is shown
                 * to be exact and not merely permissive */
                char perturbed[1024];
                size_t pn = strlen(ng5_helper_text);
                NtObjectSymbol bad_contract = {import_name, perturbed, 1, NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION, 0, 6};
                if (pn + 1 < sizeof perturbed) {
                    memcpy(perturbed, ng5_helper_text, pn + 1);
                    /* the last hex digit of the clobbers mask, a single byte */
                    perturbed[pn - 21] = perturbed[pn - 21] == '0' ? '1' : '0';
                }
                right.symbols = &bad_contract;
                NtBuffer wrong = write_object(&right);
                rejected(&image, source, &wrong, 65536, 825, "perturbed contract transactional");
                {
                    NtObjectSymbol old = {import_name, (char *)placeholder, 1,
                                          NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION, 0, 6};
                    right.symbols = &old;
                    NtBuffer stale = write_object(&right);
                    rejected(&image, source, &stale, 65536, 825,
                             "the v0 placeholder is still refused with 825");
                    free(stale.bytes);
                }
                right.symbols = &helper;
                right.symbols = &helper; right.target = 2;
                NtBuffer wrong_target = write_object(&right);
                rejected(&image, source, &wrong_target, 65536, 820, "target mismatch transactional");
                right.target = 1;
                NtObjectSymbol other = {"other", ng5_helper_text, 1, NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION, 0, 6};
                right.symbols = &other;
                NtBuffer missing_helper = write_object(&right);
                rejected(&image, source, &missing_helper, 65536, 824, "missing helper transactional");
                rejected(&image, source, &right_file, 8, 827, "short output transactional");
                free(wrong.bytes); free(wrong_target.bytes); free(missing_helper.bytes);
            }
            /* ---- the canonical layout, one fixture at a time ---- */
            {
                static const Ng5Item singles[] = {
                    {"only", 1, 42, 2}, {"only", 2, 4660, 2},
                    {"only", 4, 2018915346u, 2}, {"only", 8, 0x1122334455667788ull, 2}
                };
                static const Ng5Item pairs[] = {
                    {"aa", 1, 0x11, 2}, {"bb", 8, 0x2233445566778899ull, 2},
                    {"aa", 8, 0x2233445566778899ull, 2}, {"bb", 1, 0x11, 2},
                    {"aa", 2, 0x1122, 2}, {"bb", 4, 0x33445566u, 2},
                    {"aa", 4, 0x33445566u, 2}, {"bb", 2, 0x1122, 2},
                    {"yn", 1, 0x11, 2}, {"aa", 8, 0x2233445566778899ull, 2},
                    {"yn", 8, 0x2233445566778899ull, 2}, {"aa", 1, 0x11, 2},
                    {"yn", 2, 0x1122, 2}, {"aa", 4, 0x33445566u, 2},
                    {"yn", 4, 0x33445566u, 2}, {"aa", 2, 0x1122, 2}
                };
                static const char *pair_labels[] = {
                    "u8_then_u64", "u64_then_u8", "u16_then_u32", "u32_then_u16",
                    "reversed_u8_u64", "reversed_u64_u8", "reversed_u16_u32", "reversed_u32_u16"
                };
                static const Ng5Item four_up[] = {{"a", 1, 1, 2}, {"b", 2, 2, 2}, {"c", 4, 3, 2}, {"d", 8, 4, 2}};
                static const Ng5Item four_down[] = {{"d", 8, 4, 2}, {"c", 4, 3, 2}, {"b", 2, 2, 2}, {"a", 1, 1, 2}};
                static const Ng5Item four_swap[] = {{"d", 8, 4, 2}, {"b", 2, 2, 2}, {"c", 4, 3, 2}, {"a", 1, 1, 2}};
                static const Ng5Item pad1[] = {{"a", 1, 1, 2}, {"z", 2, 2, 2}};
                static const Ng5Item pad2[] = {{"a", 1, 1, 2}, {"b", 1, 2, 2}, {"z", 4, 3, 2}};
                static const Ng5Item pad3[] = {{"a", 1, 1, 2}, {"b", 1, 2, 2}, {"c", 1, 3, 2}, {"z", 8, 4, 2}};
                static const Ng5Item pad4[] = {{"a", 1, 1, 2}, {"b", 1, 2, 2}, {"c", 1, 3, 2}, {"d", 1, 4, 2},
                                               {"z", 8, 5, 2}};
                static const Ng5Item pad5[] = {{"a", 1, 1, 2}, {"b", 1, 2, 2}, {"c", 1, 3, 2}, {"d", 1, 4, 2},
                                               {"e", 1, 5, 2}, {"z", 8, 6, 2}};
                static const Ng5Item pad7[] = {{"a", 1, 1, 2}, {"b", 1, 2, 2}, {"c", 1, 3, 2}, {"d", 1, 4, 2},
                                               {"e", 1, 5, 2}, {"f", 1, 6, 2}, {"g", 1, 7, 2}, {"z", 8, 8, 2}};
                static const Ng5Item pad8[] = {{"a", 1, 1, 2}, {"b", 1, 2, 2}, {"c", 1, 3, 2}, {"d", 1, 4, 2},
                                               {"e", 1, 5, 2}, {"f", 1, 6, 2}, {"g", 1, 7, 2}, {"h", 1, 8, 2},
                                               {"z", 8, 9, 2}};
                static const Ng5Item u16x3[] = {{"a", 2, 1, 2}, {"b", 2, 2, 2}, {"c", 2, 3, 2}, {"z", 8, 4, 2}};
                static const Ng5Item u16x5[] = {{"a", 2, 1, 2}, {"b", 2, 2, 2}, {"c", 2, 3, 2}, {"d", 2, 4, 2},
                                                {"e", 2, 5, 2}, {"z", 8, 6, 2}};
                static const Ng5Item u32x1[] = {{"a", 4, 1, 2}, {"z", 8, 2, 2}};
                static const Ng5Item u32x3[] = {{"a", 4, 1, 2}, {"b", 4, 2, 2}, {"c", 4, 3, 2}, {"z", 8, 4, 2}};
                static const Ng5Item u32u8[] = {{"a", 4, 1, 2}, {"b", 1, 2, 2}, {"c", 1, 3, 2}, {"d", 1, 4, 2},
                                                {"z", 8, 5, 2}};
                static const Ng5Item u16u8[] = {{"a", 2, 1, 2}, {"b", 1, 2, 2}, {"z", 8, 3, 2}};
                static const Ng5Item ascii[] = {{"Z", 1, 1, 2}, {"_x", 4, 2, 2}, {"abc", 2, 3, 2}, {"a", 8, 4, 2}};
                static const Ng5Item digits[] = {{"e0", 1, 1, 2}, {"d0", 8, 2, 2}, {"d00", 2, 3, 2}, {"a0", 4, 4, 2}};
                static const Ng5Item prefix[] = {{"ab", 8, 1, 2}, {"a", 1, 2, 2}, {"abc", 2, 3, 2}, {"b", 4, 4, 2}};
                static const Ng5Item mixedcase[] = {{"aB", 1, 1, 2}, {"Ab", 2, 2, 2}, {"AB", 4, 3, 2}, {"a", 8, 4, 2}};
                static const Ng5Item split[] = {{"zeta", 8, 4660, 2}, {"alpha", 1, 42, 3}, {"beta", 2, 7, 3}};
                static const Ng5Item interleave[] = {{"m1", 1, 1, 2}, {"m2", 8, 2, 3}, {"m3", 2, 3, 2}, {"m4", 4, 4, 3}};
                struct { const char *label; const Ng5Item *items; size_t count; } cases[] = {
                    {"single_u8", &singles[0], 1}, {"single_u16", &singles[1], 1},
                    {"single_u32", &singles[2], 1}, {"single_u64", &singles[3], 1},
                    {"u8_then_u64", &pairs[0], 2}, {"u64_then_u8", &pairs[2], 2},
                    {"u16_then_u32", &pairs[4], 2}, {"u32_then_u16", &pairs[6], 2},
                    {"reversed_u8_u64", &pairs[8], 2}, {"reversed_u64_u8", &pairs[10], 2},
                    {"reversed_u16_u32", &pairs[12], 2}, {"reversed_u32_u16", &pairs[14], 2},
                    {"four_widths_ascending", four_up, 4}, {"four_widths_descending", four_down, 4},
                    {"four_widths_mid_swap", four_swap, 4},
                    {"align2_after_1_u8", pad1, 2}, {"align4_after_2_u8", pad2, 3},
                    {"align8_after_3_u8", pad3, 4}, {"align8_after_4_u8", pad4, 5},
                    {"align8_after_5_u8", pad5, 6}, {"align8_after_7_u8", pad7, 8},
                    {"align8_at_8_u8", pad8, 9}, {"align8_after_3_u16", u16x3, 4},
                    {"align8_after_5_u16", u16x5, 6}, {"align8_after_1_u32", u32x1, 2},
                    {"align8_after_3_u32", u32x3, 4}, {"align8_after_u32_3_u8", u32u8, 5},
                    {"align8_after_u16_u8", u16u8, 3},
                    {"byte_order_mixed", ascii, 4}, {"byte_order_digits", digits, 4},
                    {"byte_order_prefix", prefix, 4}, {"byte_order_case", mixedcase, 4},
                    {"two_sections_split", split, 3}, {"two_sections_interleaved", interleave, 4}
                };
                for (unsigned k = 0; k < sizeof cases / sizeof cases[0]; k++) {
                    char label[64];
                    snprintf(label, sizeof label, "link_%s", cases[k].label);
                    if (ng5_build_source(source, sizeof source, cases[k].items, cases[k].count,
                                         "uefi", "helper", 1, "call helper()") > sizeof source ||
                        ng5_build_source(twin, sizeof twin, cases[k].items, cases[k].count,
                                         "uefi", "helper", 0, NULL) > sizeof twin) {
                        CHECKL(0, "link fixture bounded", label);
                        continue;
                    }
                    ng5_link_case(&image, label, source, twin, "helper", import_name, &right_file);
                }
                (void)pair_labels;
            }
            /* ---- the 1..64 item sweep, mixed widths, ascending names ---- */
            {
                static Ng5Item sweep[64];
                char names[64][8];
                for (size_t k = 0; k < 64; k++) {
                    static const unsigned widths[4] = {1, 2, 4, 8};
                    snprintf(names[k], sizeof names[k], "d%02zu", k);
                    sweep[k] = (Ng5Item){names[k], widths[k % 4], (uint64_t)(k * 3 + 1), 2};
                }
                for (size_t k = 1; k <= 64; k++) {
                    char label[32];
                    snprintf(label, sizeof label, "link_sweep_%zu", k);
                    if (ng5_build_source(source, sizeof source, sweep, k, "uefi", "helper", 1, "call helper()") > sizeof source ||
                        ng5_build_source(twin, sizeof twin, sweep, k, "uefi", "helper", 0, NULL) > sizeof twin) {
                        CHECKL(0, "sweep fixture bounded", label);
                        break;
                    }
                    ng5_link_case(&image, label, source, twin, "helper", import_name, &right_file);
                }
            }
            /* ---- the declaration index tiebreak of the name order is
             *      unreachable: both producers refuse two data items of one
             *      name, so no equal name reaches the comparator. Asserted. */
            {
                const char *twin_dup = "module m\ntarget x86_64-nexora-uefi\nsection .rdata {\n"
                                       "export data aa:u8=1\nexport data aa:u8=2\n}\n"
                                       "section .text {\nexport fn main()->u64\neffects {}\n"
                                       "clobbers {} {\nreturn 0\n}\n}\n";
                Ng5Reference dup;
                int refused = !ng5_reference_for(twin_dup, &dup);
                if (!refused) ng5_reference_free(&dup);
                CHECKL(refused, "C frontend refuses two data items of one name", "tie_break_unreachable");
                CHECKL(refused && strstr(dup.why, "duplicate") != NULL,
                       "C frontend names the duplicate diagnostic", "tie_break_unreachable");
                {
                    char dup_source[8192];
                    if (ng5_build_source(dup_source, sizeof dup_source, classic, 3, "uefi", "helper", 1, "call helper()")
                        > sizeof dup_source) {
                        CHECKL(0, "duplicate fixture bounded", "tie_break_unreachable");
                    } else {
                        char *at = strstr(dup_source, "export data alpha:u8=42");
                        if (at) memcpy(at, "export data zeta:u16=4660", 26);
                        CHECKL(strstr(dup_source, "export data zeta:u16=4660") != NULL,
                               "duplicate fixture edited", "tie_break_unreachable");
                        rejected(&image, dup_source, &right_file, 65536, 800,
                                 "producer refuses two data items of one name");
                    }
                }
            }
            free(right_file.bytes);
        }
    }
    if (image.memory) {
        /* ---- self contained producer to PE ---- */

        /* The entry offset derivation, exercised before anything relies on it.
         * A helper that cannot be shown to compute a different answer for a
         * different input cannot be used to unpin a literal. */
        reference_entry_self_test();

        /* 1. one exported function, one literal return: the C oracle lays out
         *    the same eleven bytes at the same entry offset. The export is named
         *    main because that is the only name the reference gives an entry to
         *    (object_build.c:343-351), and nt_object_materialize refuses an
         *    object with no entry, so a fixture exported under any other name
         *    cannot produce a PE at all. */
        accept(&image,
               "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
               "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 5\n}\n}\n",
               "single_literal_return", 0, 1);

        /* 2. two functions, source order equal to ascending name order.
         *    build_many spells the export main and the other zz01, and strcmp
         *    puts "main" before "zz", so main is still first and the entry
         *    offset is still 0: the layout property this fixture exists to hold
         *    is preserved by the rename rather than disturbed by it. */
        if (build_many(many, sizeof many, 2, 0, 1)) accept(&image, many, "two_sorted_functions", 0, 1);

        /* 3. the exported entry is the last of three, at a non zero text offset.
         *    build_many spells the two before it aa00 and aa01 and the export
         *    main; strcmp puts "main" after "aa", so main is still last and its
         *    offset is still the sum of the two preceding sizes, 11 + 11 = 22,
         *    each measured by the C reference rather than typed here. */
        if (build_many(many, sizeof many, 3, 1, 1)) accept(&image, many, "entry_is_last_of_three", 22, 1);

        /* 4. sixty four functions in one text section */
        if (build_many(many, sizeof many, 64, 0, 0)) accept(&image, many, "sixty_four_functions", 0, 1);

        /* 5. a bare return. THE ONE ROW HERE WITH NO ACCEPTED SOURCE, and now
         *    asserted as the refusal it is instead of asking for a PE that no
         *    declaration can make the reference build.
         *
         *    THE PROOF, and it is an exhaustion rather than a ladder, because
         *    a ladder can always be continued. Both axes the reference offers
         *    were walked to their ends on this exact body, every variant asked
         *    of the frozen C pipeline in one process:
         *
         *      the clause axis, five shapes, all 400 "return value required"
         *        with the message unchanged: `clobbers {}`; `{rax}`;
         *        `{rax,rflags}`; `changes_flags` with `{rax,rflags}`; and
         *        `changes_flags` with all sixteen GPRs plus rflags. The
         *        rflags name is here because it is the answer to every OTHER
         *        red row in this table, so this row is the control that shows
         *        the name changes nothing HERE.
         *      the type axis, both return types the type table has (frontend.c
         *        590-591): `->u64` gives 400, and `->never` gives 500 "never
         *        function cannot return", so there is no third spelling in which
         *        a value is optional.
         *      the body axis: the same bare return with the `mov` deleted is
         *        still 400, so the answer does not come from the statement
         *        before it.
         *
         *    THE MINIMAL PAIR, one token, and the leg that does not flip. With
         *    `clobbers {rax}` held fixed, changing `return` to `return 1` takes
         *    the reference from 400 to ACCEPTED (text 368, 1 symbol); adding a
         *    further declaration to the bare form changes nothing at all. So the
         *    400 is attributable to the absent value and to nothing else, and
         *    it is not an inability to parse: the same text with the value is
         *    built, by BOTH producers, to byte identical PEs.
         *
         *    WHY IT IS NOT A PRODUCER GAP, measured on both routes in the same
         *    process on these bytes: the producer refuses the bare form
         *    (mode 1 = 800, mode 2 = 800) and builds the valued one (mode 1 = 0
         *    with a 3072 byte PE, mode 2 = 0 with an 832 byte NXO, identical to
         *    the C's PE). The producer's reason for its 800 is NOT established
         *    here -- these routes report a code and not a diagnostic -- so that
         *    is an open question rather than a residual.
         *
         *    WHAT THE ROW NOW ASSERTS is refused_by_both: the reference names
         *    400, mode 1 refuses and writes nothing, mode 2 refuses and writes
         *    nothing, and the fixture is counted in the same census column it
         *    was counted in before. No PE is owed for this shape and none is
         *    claimed. */
        refused_by_both(&image,
                        "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
                        "export fn main()->u64\neffects {}\nclobbers {} {\nmov rax, 1\nreturn\n}\n}\n",
                        "bare_return", "400 return value required");

        /* 6. two functions and one call: the C codegen emits a full nx64-abi-v0
        *    frame, so the case is oracle free, but the REL32 site must be
        *    patched and the entry RVA must still be the exported offset. "main"
        *    sorts before "target", so the export is still the first function
        *    and the entry offset is still 0. */
        accept(&image,
               "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
               "export fn main()->u64\neffects {}\nclobbers {} {\ncall target()\nreturn 0\n}\n"
               "fn target()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\n}\n",
               "two_functions_one_call", 0, 0);

        /* 7. two calls with two distinct targets.
         *
         *    The preceding list is TWO functions, not one, and that is a
         *    consequence of the rename rather than an error in it. Exported
         *    under the name `beta`, the reference ordered the three as alpha,
         *    beta, gamma, so alpha alone preceded the export. Exported as
         *    `main`, the reference orders them alpha, gamma, main -- "main"
         *    sorts after both "gamma" and nothing else moves -- so BOTH alpha
         *    and gamma precede it. Measured on the reference for the renamed
         *    source: alpha@0, gamma@11, main@22, entry_symbol 3, entry offset
         *    22. The list below is written in that name order, and the
         *    derivation sums the C's own .text size for each, so the value is
         *    the reference's and not 11 carried over from the old name. */
        accept(&image,
               "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
               "export fn main()->u64\neffects {}\nclobbers {} {\ncall alpha()\ncall gamma()\nreturn 0\n}\n"
               "fn alpha()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n"
               "fn gamma()->u64\neffects {}\nclobbers {} {\nreturn 2\n}\n}\n",
               "two_distinct_call_targets",
               reference_entry_offset("two_distinct_call_targets", TWO_TARGETS_PRECEDING), 0);

        /* 8. forward and backward branches in the exported body.
         *
         *    THE CLAUSE BELOW IS A CORRECTION, and it is the reason this
         *    fixture now reads `clobbers {rax}`. It read `clobbers {}` while
         *    writing rax, and the C reference refused that exact text with 502
         *    "omits an inferred clobber". So the fixture was not testing a
         *    forward branch: it was testing whether the producer refuses an
         *    under-declared source, which is a different question and one the
         *    reference already answers. Declaring the clobber, and changing
         *    nothing else, makes the reference BUILD this source: measured,
         *    text=373 bytes, 1 symbol, 0 relocations. So the corrected fixture
         *    reaches the shape it names, which is what the correction is for.
         *
         *    THE WAVE 25 DISPUTE IS RESOLVED, AND IT RESOLVED THE OTHER WAY
         *    FROM THE WAY THE PARAGRAPHS ABOVE IT RECORDED. Two harnesses read
         *    this same text on this same digest and disagreed: one read 800 on
         *    both routes, the other read 0 on the object route and reported
         *    the producer tracking the reference on twelve cells. The
         *    resolution is to ask the disputed source of BOTH entries in ONE
         *    process and compare, which is what was missing, because each
         *    harness could only ever see the entry it held and both entries
         *    answer 0 on success -- 0 is an accept, so a wrong entry looks like
         *    a working one.
         *
         *    WHAT THAT INSTRUMENT ANSWERS NOW, re-measured 30 September 2026
         *    on the shipped bytes, one process, all three routes. The two
         *    paragraphs this one replaces said « mode 1 answers 800, mode 2
         *    answers 800. The producer refuses this text », and then that the
         *    800 « is about the spelling, not about the branch ». NEITHER
         *    HOLDS. On the text below, exactly as written:
         *
         *      mode 1 = 0, PE 3072     mode 2 = 0     mode 6 = 0
         *
         *    and the C reference builds it, text 373, and the two producers'
         *    PEs are byte identical over the whole 3072 bytes
         *    (ORACLE_COMPARED forward_branch C_pe_bytes=3072). The row is
         *    GREEN and it is an ordinary compared fixture. The producer-side
         *    defect this block recorded is closed, and it is closed in the
         *    producer, not here: nothing in this fixture was re-spaced.
         *
         *    THE SPELLING NEIGHBOURHOOD, MEASURED AGAIN, because the previous
         *    claim about it was the load bearing one and it was wrong. SIX
         *    spellings over the same body, both sides asked, one process; the
         *    first five declare a clobber covering the `mov rax, 2`, the sixth
         *    declares nothing at all:
         *
         *      `effects {} clobbers {rax} {` on one line  (SHIPPED)
         *          reference 0    producer mode 1/2/6 = 0
         *      the two clauses on separate lines
         *          reference 0    producer mode 1/2/6 = 0
         *      `effects {changes_flags} clobbers {rax,rflags} {` on one line
         *          reference 0    producer mode 1/2/6 = 0
         *      `effects {}clobbers {rax} {`, no space, one line
         *          reference 0    producer mode 1/2/6 = 0
         *      `effects {}  clobbers {rax} {`, two spaces, one line
         *          reference 0    producer mode 1/2/6 = 0
         *      `effects {} clobbers {} {`, no clobber at all
         *          reference 502  producer 800
         *
         *    So the producer is NOT sensitive to where the clause break falls.
         *    The previous text said `effects {}clobbers {rax}` and the
         *    two-space form « refuse », and the one spelling that still refuses
         *    is the one that declares nothing at all -- which is the reference's
         *    own objection, since `mov rax, 2` infers a clobber. Every
         *    SPELLING is accepted, and the previous sentence's « either clause
         *    on its own line accepts, indented or not » is kept only because it
         *    is still true, not because it is now the interesting half.
         *
         *    WHY THE CLAUSE `clobbers {rax}` IS STILL THE RIGHT ONE, which the
         *    last row of that table is the evidence for: without it BOTH sides
         *    decline, so a fixture that was written to test a forward branch
         *    would be testing an under-declared source instead. The
         *    correction at the top of this comment is what makes the fixture
         *    reach the shape it names, and it was right for the reason given
         *    there.
         *
         *    The entry offset is unchanged by the clause: "main" sorts before
         *    nothing else in this one-function source, so it is still first.
         *
         *    THE BACKWARD FIXTURE BELOW HAS A MEASURED ANSWER, and it is
         *    not the one this comment used to say was unknown. The 502 is
         *    reachable, by a name this file had not tried: the reference
         *    requires bit 17 in f->clobbers, and bit 17 is RFLAGS, spelled
         *    `rflags`. See the note on that fixture. That fixture is a
         *    REFUSAL row for a different reason than this one was: the
         *    reference declines its text at 501, whereas this fixture is
         *    built by both sides. */
        accept(&image,
               "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
               "export fn main()->u64\neffects {} clobbers {rax} {\njmp end\nend:\nmov rax, 2\nreturn 2\n}\n}\n",
               "forward_branch", 0, 0);
        /*    backward_branch: MEASURED, AND THE ROW IS A REFUSAL ROW. The
         *    reference refuses this exact text with 501 "omits an inferred
         *    effect".
         *    Declaring `changes_flags` moves it to 502 "omits an inferred
         *    clobber". The old comment stopped there and called the clause
         *    unidentified, and that was a true statement about the LADDER
         *    THAT WAS RUN, read as a false statement about the reference.
         *
         *    WHY THE LADDER STALLED, MEASURED IN THE REFERENCE ITSELF, and
         *    this is the reusable part rather than the fixture's answer.
         *    x64.c:1071-1072 -- for any instruction that writes or undefines
         *    a flag, nt_x64_effects sets bit 17 of registers_written, RFLAGS
         *    among the sixteen GPRs. frontend.c:5511 folds that into
         *    f->inferred_clobbers, and frontend.c:5847 refuses the function
         *    while any inferred bit is outside f->clobbers | output
         *    registers. A body with an arithmetic or conditional branch
         *    therefore infers bit 17, and the clause has to name it.
         *    nt_frontend_register DOES name it: `rflags` is family 17. So the
         *    502 was never a dead end, it was a name this file has not
         *    tried -- `clobbers {rax}` can never satisfy a body that does
         *    `add`, and no amount of additional GPRs can either.
         *
         *    THE ANSWER IS TWO CLAUSES, NOT ONE NAME, and the second half of
         *    that was the part the old note asserted without measuring. Re-run
         *    against the reference, one token at a time, all four legs in one
         *    process on these bytes:
         *
         *      as written                                    501 main
         *      `changes_flags` only                          502 main
         *      `changes_flags` + `clobbers {rax}`            502 main
         *      `clobbers {rax,rflags}` and NO changes_flags  501 main
         *      `changes_flags` + `clobbers {rax,rflags}`    ACCEPTED
         *
         *    The third and the fourth legs are the pair: they differ from the
         *    accepted one by a single token, `rflags`, and the leg that adds it
         *    WITHOUT `changes_flags` does not flip. So `rflags` alone is not
         *    the answer, the answer is the two clauses together, and each of
         *    the two checks in frontend.c:5841-5849 has to be satisfied by its
         *    own clause. Accepted geometry: text 377, 2 symbols, entry_symbol
         *    1; adding `rsp` to the clobber set changes nothing (still 377).
         *
         *    THE PRODUCER, ON ALL THREE ROUTES, RE-MEASURED 30 September 2026,
         *    and the previous version of this paragraph is withdrawn: it said
         *    the producer « refuses the text as written (mode 1 = 800, mode 2
         *    = 800), it BUILDS the `changes_flags` + `{rax}` variant that the
         *    reference refuses with 502 (mode 1 = 0, PE 3072) » and concluded
         *    that the producer « does not implement either of the two
         *    flag-inference checks at all ». None of that holds now. Asked of
         *    both sides in one process on these bytes:
         *
         *      neither clause          reference 501   producer 501
         *      changes_flags alone     reference 502   producer 502
         *      changes_flags + {rax}   reference 502   producer 502
         *      {rax,rflags}, no c_flag reference 501   producer 501
         *      both clauses            reference 0     producer 0, PE 3072
         *
         *    So the producer implements BOTH checks and answers 501 and 502 on
         *    exactly the legs the reference does, including the third leg that
         *    keeps the two checks apart. The finding this paragraph used to
         *    record is closed, and the ladder above is what records it now.
         *
         *    WHY THE ROW ASKS FOR NO PE, restated because the shape of the row
         *    is the thing a reader is most likely to doubt. The reference
         *    declines this text, so it has no product to compare, and the gate
         *    asserting a PE for it would be asserting a comparison that cannot
         *    be made. The row is refused_by_both: the reference must refuse
         *    AND name 501 "function 'main' omits an inferred effect" (the
         *    reason is part of the claim, so a text that merely stopped
         *    parsing cannot satisfy it), the PE adapter must refuse on mode 1
         *    and leave the output buffer untouched, and the object producer
         *    must refuse on mode 2 the same way. That is THREE checks where
         *    the old row had one, and the one it had was false.
         *
         *    WHAT THE CONVERSION DOES NOT COST, checked rather than asserted.
         *    The old row's other two arguments were an entry offset and an
         *    `expect_identical` flag, and NEITHER WAS EVER COMPARED: accept()
         *    runs mode 1, fails the first CHECKL, and returns, so the parity
         *    block and the "C oracle entry text offset" check below it were
         *    unreachable on this fixture. The offset ARGUMENT was evaluated --
         *    C evaluates arguments before the call -- but BACKWARD_PRECEDING is
         *    the empty list, so the derivation returned 0 without asking the
         *    reference anything, and the value was then discarded. So no
         *    property is lost, and the derivation is not deleted with the call:
         *    BACKWARD_PRECEDING is now asked in reference_entry_self_test,
         *    which is where an empty list is worth a check.
         *
         *    THE FIXTURE TEXT IS STILL THE TEXT THE REFERENCE REFUSES, and it
         *    is not edited. The accepted source remains one edit away and is
         *    named here so nobody has to reconstruct it: `effects
         *    {changes_flags}` and `clobbers {rax,rflags}` on the export, and
         *    nothing else changed. Applying it would make this row a parity
         *    row instead of a refusal row, and which of those this gate wants
         *    is the open question in the file header. */
        refused_by_both(&image,
                        "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
                        "export fn main()->u64\neffects {}\nclobbers {} {\nL1:\nadd rax, 1\njne L1\nreturn 1\n}\n"
                        "fn quiet()->u64\neffects {}\nclobbers {} {\nreturn 4\n}\n}\n",
                        "backward_branch", "501 function 'main' omits an inferred effect");

        /* 9. a backward branch whose displacement crosses an emitted call block.
         *    "main" sorts before "other", so the export is still first.
         *
         *    The reference refuses this exact text with 503 "ret requires
         *    unavailable stack/frame balance proof", and the `ret` is the
         *    whole of that: a raw `ret` moves the stack pointer through
         *    nt_x64_effects and frontend.c:5493-5498 refuses it.
         *
         *    THE `ret` IS A SECOND, INDEPENDENT OBJECTION, and this is the
         *    pair that establishes it rather than the ladder that suggested it.
         *    Take the fully corrected text -- `changes_flags` +
         *    `clobbers {rax,rflags}`, a valued `return 0` -- and change exactly
         *    one thing back: the reference answers ACCEPTED, text 682, 2
         *    symbols, entry_symbol 1. Restore the `ret` with every declaration
         *    left in place and it answers 503 again, with the message
         *    unchanged. So the 503 is not a stage the declaration ladder had
         *    not yet climbed: it survives every clause, and no clause reaches
         *    it, for the same reason bare_return has none -- the construct under
         *    test is the thing the clause would have to describe. A body whose
         *    only statement is `ret` is refused the same way, and so is one
         *    whose `push rbp` is followed by a matching `pop rbp`, which is the
         *    clearest form of the rule: the reference cannot prove a stack
         *    balance across a body it is refusing to describe.
         *
         *    THE FLAG HALF IS THE SAME TWO CLAUSES as backward_branch above,
         *    and the minimal pair is the same shape: `changes_flags` +
         *    `{rax}` gives 502, and adding the one token `,rflags` gives
         *    ACCEPTED. Accepted geometry text 682, 2 symbols, one relocation.
         *    On that accepted text both producers build it and their PEs are
         *    BYTE IDENTICAL over the whole 3584 bytes.
         *
         *    THE PRODUCER, ON ALL THREE ROUTES, RE-MEASURED 30 September 2026.
         *    The previous version of this paragraph said the producer « refuses
         *    the text as written (mode 1 = 800, mode 2 = 800) », that it
         *    « builds the `changes_flags` + `{rax}` variant the reference
         *    refuses with 502 (mode 1 = 0, PE 3584) », and that it therefore
         *    « agrees with the reference about the `ret` and disagrees with it
         *    about the flags ». Both halves of the last sentence are now false.
         *    Measured, both sides in one process:
         *
         *      as written (raw `ret`)          reference 503   producer 501
         *      changes_flags + {rax}           reference 502   producer 502
         *      both clauses, `return 0`        reference 0     producer 0, PE 3584
         *      both clauses, `ret` restored    reference 503   producer 800
         *
         *    So the producer does NOT disagree about the flags -- it answers
         *    502 on the same leg the reference does, and builds the same
         *    accepted text to the same 3584 byte PE. It agrees about the `ret`
         *    too, in the only sense that matters: both decline. The one place
         *    the two codes differ is the stack-proof refusal, where the
         *    reference names 503 and the producer answers 800, the gate
         *    entry's catch-all. That is a disagreement about a DIAGNOSTIC CODE
         *    on a source neither side builds, and it is the whole of the
         *    residual between them on this fixture. The producer's reason for
         *    its 800 is not established here and is not claimed.
         *
         *    The `ret`-only body and the `push rbp`/`pop rbp` body are the
         *    same shape and are re-measured on the same run: the reference
         *    answers 503 "ret requires unavailable stack/frame balance proof"
         *    and 503 "push requires unavailable stack/frame balance proof", and
         *    the producer answers 800 on both. The two stack refusals survive
         *    every clause, which is what makes them the construct under test
         *    rather than a rung of the declaration ladder.
         *
         *    WHY THIS ROW ASKS FOR NO PE. The reference declines this text, so
         *    there is no reference product to compare a PE against, and the
         *    row is refused_by_both instead: the reference must refuse AND name
         *    503 "ret requires unavailable stack/frame balance proof", the PE
         *    adapter must refuse on mode 1 leaving the output buffer
         *    untouched, and the object producer must refuse on mode 2. THREE
         *    checks where the old row had one false one, and the old row's two
         *    other arguments (entry offset 0, expect_identical 0) never ran,
         *    because accept() returns on its first failing check.
         *
         *    THE FIXTURE TEXT IS NOT EDITED. The accepted source is this
         *    fixture with the trailing `ret` written `return 0`, `effects
         *    {changes_flags}` and `clobbers {rax,rflags}` on the export, and
         *    nothing else changed. Note the `ret` is incidental to what this
         *    fixture is FOR -- a backward branch crossing a call block -- so
         *    if the header question is ever settled in favour of comparing,
         *    this is the first row to revisit. */
        refused_by_both(&image,
                        "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
                        "export fn main()->u64\neffects {}\nclobbers {} {\n"
                        "again:\nadd rax, 1\ncall other()\njne again\njmp end\nend:\nret\n}\n"
                        "fn other()->u64\neffects {}\nclobbers {} {\nreturn 9\n}\n}\n",
                        "branch_across_a_call_block",
                        "503 ret requires unavailable stack/frame balance proof");

        /* 10. four functions, a call inside a counted backward loop and a
         *     nested call chain inside that loop, so one backward branch
         *     displacement has to cross an inserted call block while a
         *     non volatile register carries the counter. ORACLE FREE: the
         *     reference declines this text, so there is no product to compare,
         *     and the row says so by asserting the refusal.
         *
         *     The old comment said "the C frontend refuses the fixture, its
         *     return needs a value". Measured: it refuses with 400 "return
         *     value required", and that 400 IS the bare return, which is only
         *     part of what this fixture contains. With every bare return given
         *     a value and `changes_flags`/`{rax,rbx}` declared on every
         *     function, the reference still refuses, with 502 "omits an
         *     inferred clobber"; and removing the two `call` statements
         *     altogether does not change that answer either, so the call is
         *     not what it is objecting to.
         *
         *     WHAT IT IS OBJECTING TO, NAMED, which is the whole answer and was
         *     the thing four attempts at a declaration had not reached: the two
         *     flag obligations of the ARITHMETIC, per function. `add` and `sub`
         *     write flags, so every function containing one owes BOTH
         *     `changes_flags` in `effects` (the 501 check, frontend.c:5841) and
         *     `rflags` in `clobbers` (the 502 check, frontend.c:5848, bit 17).
         *     Nothing about a call appears in that sentence, which is why
         *     deleting the calls changed nothing.
         *
         *     THE LADDER, ONE TOKEN AT A TIME, and it is the pair the old note
         *     asked for. Every leg asked of the reference in one process:
         *
         *       all returns valued, changes_flags everywhere,
         *         {rax,rbx} on main, {rax} on step and twice   502 'main'
         *       the same text with both `call` statements deleted     502 'main'
         *       + rflags on main only                          502 'step'
         *       + rflags on step only                          502 'twice'
         *       + rflags on twice                              ACCEPTED
         *
         *     The first two legs are the measurement that killed the call
         *     theory: one statement deleted from each of two functions, and
         *     the answer is the same code naming the same function. The middle
         *     three legs are why a partial fix that looks complete is the
         *     expensive mistake here: the diagnostic names the FIRST function
         *     that fails and says nothing about the ones after it, so "main is
         *     fixed" is invisible in the message. Accepted geometry: text 2059,
         *     4 symbols, entry_symbol 1, 3 relocations.
         *
         *     TWO MORE BOUNDARIES, so the answer is not overclaimed. `rbx` is
         *     owed in its own right -- the accepted text with `rbx` dropped
         *     from main's clobbers answers 502 naming 'main' -- and
         *     `changes_flags` on a function that writes no flags is accepted
         *     (giving it to `seed` changes nothing: still 2059), so the clause
         *     set above is SUFFICIENT, not minimal.
         *
         *     THE CALL IS CONFIRMED INERT AT BOTH ENDS: deleting both calls
         *     from the ACCEPTED text still builds, at text 1145 instead of
         *     2059. So the calls are not the obstacle and are not what the
         *     declarations are for; they are what the fixture exists to
         *     exercise.
         *
         *     THE PRODUCER, ON ALL THREE ROUTES, RE-MEASURED 30 September 2026.
         *     The previous version of this paragraph said the producer « builds
         *     every under-declared variant the reference refuses » and that
         *     « [the] producer does not implement the 501 or the 502 check ».
         *     It does not build them. On the `{rax,rbx}` leg, both sides in one
         *     process, the reference answers 502 and the producer answers 502;
         *     on the fully declared text both answer 0, producer PE 4608. So
         *     the producer implements both checks here as well, and the finding
         *     this paragraph used to record is closed for the third time over,
         *     on this fixture.
         *
         *     AND ON THE ACCEPTED TEXT THE TWO PRODUCERS DO NOT AGREE, which
         *     is the first byte level divergence this table has reached on a
         *     source both of them accept: the C pipeline emits a 5120 byte PE
         *     and the producer a 4608 byte one, first differing byte at offset
         *     157 of the file. The same disagreement appears with ONE call
         *     restored and the same 4608 byte size on both sides, first
         *     difference at offset 400, and DISAPPEARS when both calls are
         *     deleted, where the two PEs are byte identical at 4096.
         *
         *     [CORRECTED 30 September 2026, MEASURED, and the sentence this
         *     replaces named the wrong thing.] The old text said the
         *     disagreement « is a function of a call inside the loop and not of
         *     the loop alone ». Two extra shapes settle it, both sides accepting
         *     and both through the same comparator:
         *       no_callee_rflags  loop and BOTH calls intact, neither callee
         *                        writing a flag  ->  IDENTICAL, 4608/4608.
         *                        The loop alone does not diverge.
         *       no_loop          loop gone, `rflags` still declared on both
         *                        callees, call still present  ->  DIVERGES,
         *                        4608/5120. A loop is not needed.
         *     So the trigger is `rflags` in a CALLEE's clobbers set. The earlier
         *     reading looked right because CALL_IN_LOOP happens to carry both
         *     properties at once, which is exactly how a too-narrow claim
         *     survives being written down.
         *
         *     WHICH producer is right, and why the bytes part, IS established
         *     now, and not here: the declared fixture's block measures that the
         *     two are the SAME PROGRAM — .text 2045 against 2059, both 2003 once
         *     the surplus pairs are stripped, exactly four differing bytes and
         *     all four inside rel32 displacements that resolve to the same
         *     stripped offset — and attributes the cause to the reference by
         *     name. This note is left saying only where they part and by how
         *     much, because that is all this block measured.]
         *
         *     WHY THIS ROW ASKS FOR NO PE, and it is worth one sentence more
         *     here than on the two rows above, because the 400 is NOT the
         *     interesting half of this fixture's refusal: every bare `return`
         *     given a value moves the reference off 400 and onto 502, and the
         *     fully declared text moves it onto 0. What the row therefore
         *     asserts is that the C reference declines the text AS SHIPPED, and
         *     it pins the reason, so a future edit that quietly gives a `return`
         *     a value turns the row red instead of quietly changing what the
         *     fixture tests. The row is refused_by_both: the reference must
         *     refuse AND name 400 "return value required", the PE adapter must
         *     refuse on mode 1 leaving the output buffer untouched, and the
         *     object producer must refuse on mode 2. THREE checks where the old
         *     row had one false one; the old row's other two arguments (entry
         *     offset 0, expect_identical 0) never ran, because accept() returns
         *     on its first failing check.
         *
         *     THE FIXTURE TEXT IS NOT EDITED, and the measured answer to what
         *     it would take is unchanged: the NAME `rflags` together with
         *     `changes_flags`, on every function that contains an `add` or a
         *     `sub`, and a value on every `return`. DECLARED_CALL_IN_LOOP
         *     carries exactly that text and is still in the gate, one block
         *     below, where the two producers accept it and their PEs differ. */
        refused_by_both(&image, CALL_IN_LOOP, "call_inside_a_counted_loop",
                        "400 return value required");

        /* ---- THE DECLARED ROW. The one shape where BOTH producers accept and
         * the two PEs DIFFER, measured and attributed to the REFERENCE.
         * DECLARED_CALL_IN_LOOP is CALL_IN_LOOP with the clauses the reference
         * asks for, so this is not a new program: it is the row above with its
         * declarations discharged. NO PARITY IS ASSERTED, ON PURPOSE: the
         * producer is correct and the reference emits 14 bytes of inert
         * surplus, so a parity check here would be red forever for a reason
         * that is not the producer's. See the block header for the full
         * argument and for what is measured here versus reported. ---- */
        declared_loop_divergence(&image);

        /* refusals: the adapter never writes the output buffer on a failure */
        refuse(&image,
               "module m\ntarget x86_64-nexora-none\nsection .text {\n"
               "export fn a()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
               "non_uefi_target", 802);
        refuse(&image,
               "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
               "fn a()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
               "zero_exported", 800);
        refuse(&image,
               "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
               "export fn a()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n"
               "export fn b()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
               "two_exported", 800);
        refuse(&image,
               "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
               "export fn top()->u64\neffects {}\nclobbers {} {\ncall nowhere()\nreturn 0\n}\n}\n",
               "unresolved_callee", 800);
        refuse(&image,
               "module m\ntarget x86_64-nexora-uefi\nsection .text {\n}\n",
               "empty_text_section", 800);
        refuse(&image,
               "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
               "export fn a()->u64\neffects {}\nclobbers {} {\nreturn -1\n}\n}\n",
               "negative_return", 800);
        /* The export is named `main` because THIS GATE's subject is the NXO to
         * PE adapter, and a PE cannot exist without an entry: the reference
         * refuses to materialize an entryless object at nt_object_materialize
         * with 800, and the adapter refuses it with 803, so an `export fn only`
         * here was exercising a product that does not exist and answering a
         * ROUTE refusal where a PROFILE refusal was under test. Measured on the
         * reference for the renamed source: one function, main@0, entry_symbol
         * 1, PE 3072 bytes. The 827 below is the OUTPUT BUFFER being too short,
         * which is a different fact from the object having no entry. */
        refuse_short(&image,
                     "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
                     "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 5\n}\n}\n", 16,
                     "short output transactional 16");
        refuse_short(&image,
                     "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
                     "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 5\n}\n}\n", 8,
                     "short output transactional 8");

        /* the same source text reaches a file with no C driver in the middle.
         * Both exports are named `main` for the reason above, and the offsets
         * are not carried over: measured on the reference, the single function
         * fixture is main@0 (entry offset 0, PE 3072) and the two function one
         * is main@0, target@658 (entry offset 0, PE 3584) -- "main" still sorts
         * before "target", so the export stays first and the entry offset is 0
         * in both. That is a measurement, not an assumption: had the second
         * function been named "aa" the offset would have moved. */
        if (run_files_ready) {
        write_and_check(&image,
                        "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
                        "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 5\n}\n}\n",
                        "written_single", run_file[RF_WRITTEN_SINGLE]);
        write_and_check(&image,
                        "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
                        "export fn main()->u64\neffects {}\nclobbers {} {\ncall target()\nreturn 0\n}\n"
                        "fn target()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\n}\n",
                        "written_two_functions_one_call", run_file[RF_WRITTEN_CALL]);
        write_refused(&image,
                      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
                      "export fn a()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
                      "refused write keeps the non UEFI refusal", run_file[RF_REFUSED], 802);
        write_refused(&image,
                      "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
                      "export fn top()->u64\neffects {}\nclobbers {} {\ncall nowhere()\nreturn 0\n}\n}\n",
                      "refused write keeps the unresolved callee refusal", run_file[RF_REFUSED2], 800);
        }

        /* ---- the same source text to a file, with the producer own size ----
         * CONVERTED, and this is the one row of the four that was not an
         * accept() row, so the conversion is not the same shape. It was a
         * write_sized() call, and write_sized asserts FIVE properties of a
         * SUCCESSFUL mode 6 write: that mode 6 writes the PE, that it wrote
         * only the eight size bytes, that mode 1 still returns the PE, that
         * the producer's reported count equals the file's length, and that the
         * file bytes equal the in-memory PE and pass ng_pe_validate. Measured,
         * the first of those is false: CALL_IN_LOOP is refused by the C
         * reference with 400 and by the producer with 501 on mode 1, mode 2 AND
         * mode 6, so there is no file and no reported count to compare.
         *
         * WHAT REPLACES IT, refused_by_both_sized: the same three legs
         * call_inside_a_counted_loop asserts (the reference must refuse and
         * name 400, mode 1 must refuse leaving the output buffer untouched,
         * mode 2 must refuse the same), PLUS the two properties that are
         * specific to the route that owns the file -- mode 6 must refuse,
         * leave all 64 report bytes at the guard, and create no file. SIX
         * checks where the old row had one, and the one it had was false.
         *
         * WHAT THIS LOSES, stated here because a conversion that quietly drops
         * a property is the thing to be most afraid of. The reported-count
         * and file-equals-memory properties are still asserted, on an accepted
         * source: write_sized_no_overwrite compares mode 6's reported count
         * with the first file's length on ACCEPTED_ONE_CALL, and
         * write_and_check compares the file bytes with the in-memory PE and
         * runs ng_pe_validate on the result. What the conversion stops
         * measuring on ANY source is the mode 6 route on a FOUR-FUNCTION
         * program, and that narrowing is closed by the row immediately below,
         * which is the same shape on a text both producers build. So the
         * conversion costs the gate no property at all. */
        if (run_files_ready)
        refused_by_both_sized(&image, CALL_IN_LOOP, "sized_call_inside_a_counted_loop",
                              "400 return value required", run_file[RF_SIZED_LOOP]);

        /* ---- AND THE SAME SHAPE ON A SOURCE BOTH SIDES BUILD ----
         *
         * WHY THIS ROW EXISTS RATHER THAN write_sized() HAVING BEEN DELETED.
         * write_sized() asserts that mode 6's own reported byte count equals
         * the length of the file it wrote, that the file bytes equal the
         * in-memory PE of mode 1, and that the file passes ng_pe_validate.
         * Those are five properties of a SUCCESSFUL write and the converted row
         * above cannot carry any of them, because there is no write. The two
         * convenient repairs are both wrong: deleting write_sized() loses the
         * shape and the reasoning written into it, and re-homing it on a
         * two-function fixture would re-assert bytes the mode 3 rows already
         * assert. So it runs on DECLARED_CALL_IN_LOOP -- the four-function
         * program whose mode 6 coverage the conversion would otherwise have
         * dropped, and a text both producers accept.
         *
         * WHAT IS NEW AND WHAT IS NOT. Not new: mode 6 writes a PE, writes
         * only the eight size bytes, mode 1 still returns the PE, the reported
         * count equals the file's length, the file bytes equal the in-memory PE,
         * and the file validates. New in this gate: that mode 6 agrees with
         * mode 1 on a FOUR-FUNCTION source carrying a call inside a counted
         * loop. The fixture is the declared twin of the refused source above,
         * so the refusal and the success are one program seen from two sides. */
        if (run_files_ready) {
        write_sized(&image, DECLARED_CALL_IN_LOOP, "sized_declared_call_in_loop",
                    run_file[RF_SIZED_DECLARED]);
        write_sized_refused(&image,
                            "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
                            "export fn top()->u64\neffects {}\nclobbers {} {\ncall nowhere()\nreturn 0\n}\n}\n",
                            "sized write keeps the unresolved callee refusal",
                            run_file[RF_SIZED_REFUSED], 800);
        write_sized_short(&image, CALL_IN_LOOP, "sized write refuses a short report buffer",
                          run_file[RF_SIZED_SHORT]);
        write_sized_no_overwrite(&image, ACCEPTED_ONE_CALL, "sized write refuses to overwrite",
                                 run_file[RF_SIZED_TWICE]);
        }

        /* ---- the cross producer link, and the blocker that used to stand here ----
         * Two definition objects for the same imported function, byte identical
         * except for the contract text: the one the producer itself writes, read
         * back out of its own NXO, and the one the C reference builder writes
         * for the same declaration. x64_lower_nxo now writes the canonical text,
         * so the two strings are equal and both definitions resolve. What used
         * to be the blocker is now the positive case, and the negative half is
         * kept by perturbing one byte of that same text: the comparison is exact
         * and the 825 refusal is still there, it is just no longer reachable
         * through the canonical text. */
        {
            static NtBuffer empty = {0};
            static NtBuffer absent = {0};
            /* The symbol this block is about, named the way the reference
             * names it: `<the module LINK_FIXTURE itself declares>.main`.
             * This search used to be a bare "main", which is why it returned
             * NULL and the whole block below was skipped in silence while the
             * gate stayed green -- the block carrying the EVIDENCE for the
             * corrected contract claim was never executed. The expectation is
             * built by qualified_symbol() from the fixture's own `module`
             * line, so it is neither a literal that goes stale on a rename
             * nor a pattern that a wrong module would satisfy. The name
             * argument is the one thing the rename moved here, and ENTRY_ONLY
             * is renamed with it because the check below requires the two
             * fixtures to name the SAME symbol. */
            char expected[128] = {0};
            char expected_entry_only[128] = {0};
            char *produced;
            char *canonical;
            CHECK(qualified_symbol(LINK_FIXTURE, "main", expected, sizeof expected),
                  "the link fixture declares a readable module for the entry symbol");
            CHECK(qualified_symbol(ENTRY_ONLY, "main", expected_entry_only,
                                  sizeof expected_entry_only),
                  "the entry only fixture declares a readable module");
            CHECK(strcmp(expected, expected_entry_only) == 0,
                  "the two fixtures declare the module their contract texts are compared across");
            /* name against name, on both sides: a producer or a reference
             * that qualified with any other module is not found at all. */
            produced = producer_contract(&image, LINK_FIXTURE, expected);
            canonical = canonical_contract(ENTRY_ONLY, expected_entry_only);
            NtBuffer as_produced = {0};
            /* This block is the EVIDENCE for the corrected contract claim, and
             * it was being skipped in silence. A block that can be skipped
             * silently must not be evidence, so both pointers are required
             * HERE, before the `if`, and each names which one was missing.
             * Without these two CHECKs a future renaming of either side would
             * turn this whole section into a no-op that still reports green. */
            CHECK(produced != NULL,
                  "the producer's own NXO carries the entry definition");
            CHECK(canonical != NULL,
                  "the C reference object carries the entry definition");
            if (produced && canonical) {
                fprintf(stderr, "CONTRACT nova=[%s] C=[%s]\n", produced, canonical);
                CHECK(strcmp(produced, canonical) == 0,
                      "the producer writes the canonical contract text");
                as_produced = import_definition(expected, produced);
                if (as_produced.bytes) {
                    NtBuffer as_canonical = import_definition(expected, canonical);
                    if (as_canonical.bytes) {
                        char perturbed[1024];
                        size_t pn = strlen(canonical);
                        NtBuffer as_perturbed = {0};
                        linked_accept(&image, LINK_FIXTURE, &as_produced,
                                      "linked_with_the_producer_contract",
                                      LINK_PRECEDING);
                        linked_accept(&image, LINK_FIXTURE, &as_canonical,
                                      "the canonical contract text resolves the link",
                                      LINK_PRECEDING);
                        if (pn + 1 < sizeof perturbed) {
                            size_t n;
                            memcpy(perturbed, canonical, pn + 1);
                            /* the last hex digit of the clobbers mask */
                            perturbed[pn - 21] = perturbed[pn - 21] == '0' ? '1' : '0';
                            for (n = 0; n < pn; n++)
                                if (perturbed[n] != canonical[n]) break;
                            fprintf(stderr, "CONTRACT_PERTURBED at=%zu %c->%c\n", n,
                                    canonical[n], perturbed[n]);
                            as_perturbed = import_definition(expected, perturbed);
                        }
                        if (as_perturbed.bytes) {
                            linked_refuse(&image, LINK_FIXTURE, &as_perturbed,
                                          "one perturbed contract byte refuses the link with 825", 825);
                            if (run_files_ready)
                                write_linked_refused(&image, LINK_FIXTURE, &as_perturbed,
                                                  "the refused cross producer link creates no file",
                                                  run_file[RF_LINKED_825], 825);
                            free(as_perturbed.bytes);
                        } else CHECK(0, "the perturbed definition object was written");
                        free(as_canonical.bytes);
                    }
                    free(as_produced.bytes);
                }
            }
            /* A source the producer refuses never reaches the merge, the
             * conversion or the file system: the bridge forwards the decision
             * instead of papering over it. */
            linked_refuse(&image,
                          "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
                          "export fn top()->u64\neffects {}\nclobbers {} {\ncall nowhere()\nreturn 0\n}\n}\n",
                          &absent, "the linked route keeps the producer refusal 800", 800);
            if (run_files_ready)
                write_linked_refused(&image,
                                     "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
                                     "export fn top()->u64\neffects {}\nclobbers {} {\ncall nowhere()\nreturn 0\n}\n}\n",
                                     &absent, "the linked write route keeps the producer refusal 800",
                                     run_file[RF_LINKED_800], 800);
            (void)empty;
            free(produced);
            free(canonical);
        }

        /* ---- the codegen image table contract -------------------------------
         * These run with no producer behind them: they are the C oracle and the
         * codegen's own allocation rule, stated as expectations, so the shape
         * that once walked a NULL relocation table is a fact the gate asserts
         * rather than a hazard it stumbles into. */
        {
            static NtCodeReloc spare[1];
            char why[256];
            NtCodeImage bad;
            Ng5ImageShape zero, called;
            /* 1. the reported shape: symbols, no relocations, NULL table */
            ng5_image_shape("module m\ntarget x86_64-nexora-uefi\n"
                            "section .rdata {\nexport data alpha:u8=42\n}\n"
                            "section .text {\nexport fn main()->u64\neffects {}\n"
                            "clobbers {} {\nreturn 0\n}\n}\n", &zero);
            CHECKL(zero.compiled, "the zero relocation twin compiles", "image_zero_reloc_null_table");
            CHECKL(zero.symbol_count > 0, "the zero relocation twin still has symbols",
                   "image_zero_reloc_null_table");
            CHECKL(zero.relocation_count == 0, "the zero relocation twin has no relocations",
                   "image_zero_reloc_null_table");
            CHECKL(!zero.relocations_present,
                   "a zero relocation count comes with a NULL relocation table",
                   "image_zero_reloc_null_table");
            /* 2. the same source with a local call does carry the table */
            ng5_image_shape("module m\ntarget x86_64-nexora-uefi\n"
                            "section .rdata {\nexport data alpha:u8=42\n}\n"
                            "section .text {\nexport fn main()->u64\neffects {}\n"
                            "clobbers {} {\ncall lh0()\nreturn 0\n}\n"
                            "fn lh0()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n}\n", &called);
            CHECKL(called.compiled, "the calling twin compiles", "image_reloc_table_present");
            CHECKL(called.relocation_count > 0, "a local call produces a relocation",
                   "image_reloc_table_present");
            CHECKL(called.relocations_present, "a nonzero relocation count carries a table",
                   "image_reloc_table_present");
            /* 3. a violation on the relocation side is one named failure */
            memset(&bad, 0, sizeof bad);
            bad.relocation_count = 2;
            why[0] = 0;
            CHECKL(!image_tables_present(&bad, why, sizeof why),
                   "a NULL relocation table under a nonzero count is refused",
                   "image_guard_names_null_relocations");
            CHECKL(strstr(why, "relocation_count=2") && strstr(why, "NULL relocation table"),
                   "the refusal names the relocation table and the count",
                   "image_guard_names_null_relocations");
            /* 4. and the same on the symbol side */
            memset(&bad, 0, sizeof bad);
            bad.symbol_count = 3;
            why[0] = 0;
            CHECKL(!image_tables_present(&bad, why, sizeof why),
                   "a NULL symbol table under a nonzero count is refused",
                   "image_guard_names_null_symbols");
            CHECKL(strstr(why, "symbol_count=3") && strstr(why, "NULL symbol table"),
                   "the refusal names the symbol table and the count",
                   "image_guard_names_null_symbols");
            /* 5. both counts zero and both tables absent is the legal empty
             *    image, and the loops that read them must not run */
            memset(&bad, 0, sizeof bad);
            why[0] = 0;
            CHECKL(image_tables_present(&bad, why, sizeof why),
                   "zero counts with absent tables are accepted", "image_guard_accepts_empty");
            CHECKL(!(bad.relocations && 0 < bad.relocation_count),
                   "the loop head refuses to enter on an absent table", "image_guard_accepts_empty");
            /* 6. a present table under a zero count is wasteful but legal, and
             *    the count still governs the loop */
            memset(&bad, 0, sizeof bad);
            bad.relocations = spare;
            why[0] = 0;
            CHECKL(image_tables_present(&bad, why, sizeof why),
                   "a present table under a zero count is accepted", "image_guard_accepts_spare_table");
            CHECKL(!(bad.relocations && 0 < bad.relocation_count),
                   "a spare table does not make the loop run", "image_guard_accepts_spare_table");
            /* 7. positive control: the guard accepts the two real images, so
             *    the six refusals above are the guard and not a blanket reject */
            memset(&bad, 0, sizeof bad);
            bad.symbol_count = zero.symbol_count;
            bad.symbols = (NtCodeSymbol *)(uintptr_t)1;
            bad.relocation_count = called.relocation_count;
            bad.relocations = (NtCodeReloc *)(uintptr_t)1;
            why[0] = 0;
            CHECKL(image_tables_present(&bad, why, sizeof why),
                   "a populated image passes the guard", "image_guard_accepts_populated");
            /* 8. the two walks are independent: symbols can be read while the
             *    relocation table is absent, which is the whole point of the
             *    zero relocation image */
            memset(&bad, 0, sizeof bad);
            bad.symbol_count = zero.symbol_count;
            bad.symbols = (NtCodeSymbol *)(uintptr_t)1;
            why[0] = 0;
            CHECKL(image_tables_present(&bad, why, sizeof why) && bad.symbols &&
                   !(bad.relocations && 0 < bad.relocation_count),
                   "symbols stay walkable with no relocation table",
                   "image_symbols_walk_without_relocations");
            oracle_cases += 8;
        }

        /* ---- the relocation loop of the C reference, which had no case ------
         * Every twin above ends in "return 0", so nt_codegen_x64_object emitted
         * no relocation and the loop that maps a codegen function_id onto a one
         * based symbol index ran zero times in a hundred calls. These twins call
         * locally defined functions so it runs, and the data item names sort late
         * while the helper names sort early so the codegen section grouped order
         * and the global name order disagree, which is the case where an image
         * index is not a symbol index. */
        {
            static const Ng5Item late1[] = {{"zz_a", 1, 1, 2}};
            static const Ng5Item late2[] = {{"zz_a", 1, 1, 2}, {"zz_b", 2, 2, 2}};
            static const Ng5Item late3[] = {{"zz_a", 1, 1, 2}, {"zz_b", 4, 3, 3}, {"zz_c", 8, 4, 2}};
            static const Ng5Item late4[] = {{"zz_a", 2, 4660, 2}, {"zz_b", 1, 42, 2},
                                            {"zz_c", 4, 7, 3}, {"zz_d", 8, 5, 2}};
            static const Ng5Item late5[] = {{"zz_a", 8, 0x1122334455667788ull, 2},
                                            {"zz_b", 4, 0x33445566u, 3}, {"zz_c", 2, 0x1122, 2},
                                            {"zz_d", 1, 9, 3}, {"zz_e", 8, 10, 2}};
            static const Ng5Item early1[] = {{"aa_a", 1, 7, 2}};
            static const Ng5Item mixed1[] = {{"zz_a", 1, 1, 2}, {"aa_b", 2, 2, 2},
                                             {"mm_c", 4, 3, 3}, {"zz_d", 8, 4, 2}};
            static const Ng5Item mixed2[] = {{"aa_a", 1, 1, 2}, {"zz_b", 2, 2, 2},
                                             {"aa_c", 4, 3, 3}, {"mm_d", 8, 4, 2},
                                             {"zz_e", 1, 5, 2}};
            struct { const char *label; const Ng5Item *items; size_t count;
                     unsigned helpers, calls, want; } shapes[] = {
                {"reloc_one_helper_no_data", NULL, 0, 1, 1, 1},
                {"reloc_one_helper_one_late_item", late1, 1, 1, 1, 1},
                {"reloc_one_helper_two_late_items", late2, 2, 1, 1, 1},
                {"reloc_one_helper_four_late_items", late4, 4, 1, 1, 1},
                {"reloc_one_helper_mixed_sections", mixed1, 4, 1, 1, 1},
                {"reloc_one_helper_early_item", early1, 1, 1, 1, 1},
                {"reloc_two_helpers_no_data", NULL, 0, 2, 2, 2},
                {"reloc_two_helpers_one_late_item", late1, 1, 2, 2, 2},
                {"reloc_two_helpers_three_late_items", late3, 3, 2, 2, 2},
                {"reloc_two_helpers_mixed_five", mixed2, 5, 2, 2, 2},
                {"reloc_three_helpers_three_calls", late3, 3, 3, 3, 3},
                {"reloc_three_helpers_five_calls", late4, 4, 3, 5, 5},
                {"reloc_four_helpers_five_late_items", late5, 5, 4, 5, 5},
                {"reloc_four_helpers_mixed_five", mixed2, 5, 4, 4, 4},
                {"reloc_one_helper_repeated_call", late2, 2, 1, 3, 3},
                {"reloc_two_helpers_repeated_calls", mixed1, 4, 2, 4, 4}
            };
            char twin[8192];
            for (unsigned k = 0; k < sizeof shapes / sizeof shapes[0]; k++) {
                if (ng5_build_calling_twin(twin, sizeof twin, shapes[k].items,
                                           shapes[k].count, shapes[k].helpers,
                                           shapes[k].calls) > sizeof twin) {
                    CHECKL(0, "relocation twin bounded", shapes[k].label);
                    continue;
                }
                ng5_reloc_reference_case(shapes[k].label, twin, shapes[k].want);
            }
            /* the count the loop actually got through, stated once so a reader
             * can see the dead region is no longer dead */
            fprintf(stderr, "RELOC_SUMMARY reference_cases=%u\n", oracle_cases);
        }

        /* ---- the runtime edges this gate sits on ----------------------------
         * The producer borrows host memory through nova_borrow_v2, and the arena
         * and the borrow both refuse anything over 64 MiB, the cap declared at
         * runtime_v2.c:9. A refusal has to arrive as a named runtime error and
         * leave the context usable, never as a dereference, so these pin the two
         * refusal arms and the recovery that follows. The cap is written out
         * rather than imported, because BYTES_MAX is private to runtime_v2.c: if
         * it ever moves, these cases are supposed to fail. */
        {
            /* BYTES_MAX, runtime_v2.c:9 */
            const uint64_t cap = 64ull * 1024 * 1024;
            uint8_t small[8] = {0};
            NovaContextV2 c = {0};
            uint64_t h;

            /* 1. a NULL pointer with a nonzero length is an argument error */
            CHECKL(nova_context_init_v2(&c), "context init for the borrow edges", "runtime");
            h = nova_borrow_v2(&c, NULL, 16, 0);
            CHECKL(h == 0, "a NULL borrow with a length is refused", "runtime_borrow_null_with_length");
            CHECKL(c.error == NV2_ARGUMENT, "the NULL borrow raises NV2_ARGUMENT",
                   "runtime_borrow_null_with_length");
            nova_error_clear_v2(&c);

            /* 2. a length over the 64 MiB cap is refused, and the cap is checked
             *    before the table is walked, so the pointer is never touched */
            h = nova_borrow_v2(&c, small, cap + 1, 0);
            CHECKL(h == 0, "a borrow over the 64 MiB cap is refused", "runtime_borrow_over_cap");
            CHECKL(c.error == NV2_BOUNDS, "the oversized borrow raises NV2_BOUNDS",
                   "runtime_borrow_over_cap");
            nova_error_clear_v2(&c);

            /* 3. after two refusals the context still serves a legal borrow, so
             *    the refusal path leaves no wreckage behind */
            h = nova_borrow_v2(&c, small, sizeof small, 0);
            CHECKL(h != 0, "a legal borrow still succeeds after two refusals",
                   "runtime_borrow_recovers");
            CHECKL(c.error == 0, "the recovered context carries no error", "runtime_borrow_recovers");
            CHECKL(nova_context_destroy_v2(&c), "context cleanup after the borrow edges",
                   "runtime_borrow_recovers");

            /* 4. the arena arm of the same cap, reached through the runtime call
             *    table, so a request over 64 MiB allocates nothing at all */
            memset(&c, 0, sizeof c);
            CHECKL(nova_context_init_v2(&c), "context init for the arena edge", "runtime");
            h = c.runtime->calls[NV2_ALLOC](&c, cap + 1, 0, 0);
            CHECKL(h == 0, "an allocation over the 64 MiB cap is refused",
                   "runtime_arena_over_cap");
            CHECKL(c.error == NV2_BOUNDS, "the oversized allocation raises NV2_BOUNDS",
                   "runtime_arena_over_cap");
            nova_error_clear_v2(&c);

            /* 5. a zero byte allocation is legal and is owned, so it has to come
             *    back through rt_free: the leak checker is the assertion */
            h = c.runtime->calls[NV2_ALLOC](&c, 0, 0, 0);
            CHECKL(h != 0, "a zero byte allocation is granted", "runtime_arena_zero_bytes");
            CHECKL(c.error == 0, "the zero byte allocation raises nothing", "runtime_arena_zero_bytes");
            if (h) {
                uint64_t freed = c.runtime->calls[NV2_FREE](&c, h, 0, 0);
                CHECKL(freed == 0 && c.error == 0, "the zero byte allocation is released whole",
                       "runtime_arena_zero_bytes");
            }
            CHECKL(nova_context_destroy_v2(&c), "context cleanup after the arena edge",
                   "runtime_arena_zero_bytes");
            oracle_cases += 5;
        }

        /* ---- the 830 the gate cannot see, pinned as the measured 0 ----------
         * rt_open_new opens with "wbx" (runtime_v2.c:243), so a path that already
         * exists is refused with NV2_IO. The producer answers 830 in that case
         * (x64_lower_nxo_pe.nova:193), and the claim recorded next to it is that a
         * raised runtime error forces the entry's return value to 0 at the host
         * boundary, which is why 830 is unobservable from C. That claim is what
         * makes the refusals above assert NV2_IO rather than a code, so it is
         * measured here directly: the refused call must return 0, not 830. */
        {
            static NtBuffer empty = {0};
            static uint8_t reported[64];
            /* NOT GUARDED BY run_files_ready, and the reason is in the block:
             * this row increments oracle_cases on BOTH exits, so skipping it
             * would move oracle_cases off 30 and turn the census red for a
             * reason that has nothing to do with the census. The block already
             * owns the shape it needs -- SETUPL says the first write never
             * succeeded, so the property below is reported as not reached
             * rather than as passed -- and an empty path makes that first
             * write fail, which is exactly the honest answer. The run is
             * already red from run_files_open, and it stays red here. */
            const char *path = run_files_ready ? run_file[RF_PROBE_830] : "";
            const char *source = ACCEPTED_ONE_CALL;
            uint64_t first, second;
            FILE *f;
            remove(path);
            memset(reported, guard, sizeof reported);
            first = run_mode(&image, source, &empty, 6, path, reported, sizeof reported);
            /* SETUP_NOT_REACHED, and not a bare CHECKL: see the macro at the top
             * of this file. A first write that does not succeed means the
             * property below was never tested, and a reader has to be able to
             * see that from the output alone. */
            SETUPL(first == 0, "the first write of the 830 probe succeeds", "open_refused_returns_zero");
            if (first != 0) { remove(path); oracle_cases++; goto probe_done; }
            f = fopen(path, "rb");
            CHECKL(f != NULL, "the 830 probe file exists before the second write",
                   "open_refused_returns_zero");
            if (f) fclose(f);
            memset(reported, guard, sizeof reported);
            second = run_mode_refused(&image, source, &empty, 6, path, reported,
                                      sizeof reported, NV2_IO);
            /* the measured fact, stated as the expectation it justifies */
            CHECKL(second == 0, "a refused exclusive open returns 0 at the host boundary, not 830",
                   "open_refused_returns_zero");
            CHECKL(second != 830, "830 is unobservable from C, as the producer records",
                   "open_refused_returns_zero");
            fprintf(stderr, "OPEN_REFUSED second_code=%llu (830 unobservable)\n",
                    (unsigned long long)second);
            remove(path);
            oracle_cases++;
        probe_done:;
        }

        fprintf(stderr, "ORACLE_SUMMARY compared=%u diverges=%u free=%u refused=%u\n",
                oracle_compared_total, oracle_diverged_total, oracle_free_total,
                oracle_refused_total);
        CHECK(oracle_compared_total >= 4, "at least four fixtures are byte identical to the C oracle");
        /* Eleven accepted fixtures, and every one of them must land in exactly
         * one of FOUR columns. The fourth is the producer refusal, which used
         * to be an absence rather than an outcome: accept() returned before
         * the oracle block, so a refused fixture reached no column at all and
         * this sum could not reach 11 however the producer behaved. It read
         * the same whether five fixtures were refused, lost, or never run.
         *
         * The 11 IS NOT LOWERED. Lowering it to whatever survives would make
         * the check satisfiable by deleting fixtures, which is the one move
         * that turns a real accounting gap into a permanent correct-looking
         * number. The constant stays 11, so a fixture that reaches none of the
         * four columns is still a failure here, and a fixture that stops being
         * refused moves from the refused column into one of the other three
         * without this needing to change. */
        /* NEGATIVE CONTROL, in the tree, deliberately. A census that has just
         * been given a fourth column is exactly the kind of check that goes
         * green because the arithmetic was widened, and a reader cannot tell
         * that from a census that is green because every fixture is really
         * accounted for. This asserts the property that makes the widening
         * safe: the four columns are a PARTITION of the eleven fixtures, so
         * the sum can neither be satisfied by a fixture counted twice nor by
         * one counted in none of them.
         *
         * Perturbation checked once by hand, by the author of this block:
         * raising the refused constant by one, so the sum reads 12 against an
         * expected 11, turns this check red while the eight other failures
         * stand. Without that, "the census is green" and "the census counts
         * eleven distinct fixtures" are the same sentence. */
        CHECK(oracle_compared_total + oracle_diverged_total + oracle_free_total +
              oracle_refused_total == 11,
              "every accepted fixture is accounted for");
        CHECK(oracle_cases == 30, "every relocation, image table and runtime edge case ran");
        }
        free(ng5_helper_text);
    }
    if (image.memory) nova_host_unmap(&image);
    if (compiled) nt_artifact_free(&compiler);
    for (unsigned i = 0; i < 18; i++) free(sources[i]);
    /* ---- the contract oracle: the varied contract text of the C object
     *      writer, through the C reader and through the Nova accessor ---- */
    {
        NovaHostImage accessor = {0};
        NtArtifact accessor_artifact = {0};
        if (contract_image(&accessor, &accessor_artifact)) contract_suite(&accessor);
        if (accessor.memory) nova_host_unmap(&accessor);
        nt_artifact_free(&accessor_artifact);
    }
    /* setup_not_reached is printed because `checks` cannot answer the question a
     * reader actually has. `checks` counts expectations that were EVALUATED; it
     * says nothing about how many properties in this file were never reached at
     * all, because an unreached assertion does not increment it. Reading
     * checks=2482 as "2482 properties verified" is exactly the inference this
     * counter has to refuse to support, so the number of setups that failed to
     * deliver their property is now on the line and not inferable. */
    printf("NTASM_NOVA_X64_LOWER_NXO_PE checks=%u failures=%u cases=%u setup_not_reached=%u\n",
           checks, failures, cases, setup_not_reached);
    return failures ? 1 : 0;
}
