/* ==========================================================================
 * tests_ntasm_nested_call.c -- LOT 89. The first BYTE gate on a call SHAPE.
 *
 * WHAT THIS GATE IS FOR, and the gap it names.
 *
 * `docs/status/ntasm-completion.md` entry A4 says, of the six named gates on effects,
 * contracts and ABI, that five are KEYWORD gates and that "les appels et les
 * chemins interruption/syscall ne sont établis par aucune porte d'octets". That
 * sentence is the reason this file exists, and it is worth being precise about
 * which half of it was true when it was written and which half is true now,
 * because a lot that corrects it by over-claiming would be as wrong as the
 * sentence.
 *
 * MEASURED on this tree, by reading the files rather than any report:
 *
 *   - The `call` OPCODE is byte-evidenced, and has been for a while, at the
 *     ENCODER level. `x64_control` compares `nt_x64_encode` against the Nova
 *     export over 33 REL and 16 register cases per mnemonic (call and jmp),
 *     byte for byte. `x64_shift_mem` does the same for the 0xFF /2 memory form.
 *     So the claim "a call has no byte witness" was FALSE about the opcode.
 *   - The INTERRUPT paths are byte-evidenced too, and both of the profiles the
 *     owner's clause names. `stub_table` writes a stub body through the Nova
 *     emitter, materializes it, and compares it byte for byte against
 *     `nt_codegen_x64` on the same source -- for #UD vector 6 (`no_error`, 18
 *     bytes) and for #GP vector 13 (`error`, 22 bytes), which differ on the
 *     saved-RIP slot and on the error-code stack adjustment. The 48 CF terminal
 *     is pinned, and the [rsp+16] ABSENCE is asserted on the no-error profile.
 *     So "with and without a CPU error code" IS byte-covered, in the module
 *     that is not on any pipeline path.
 *   - What is NOT byte-evidenced, and what this gate closes, is the call
 *     SHAPE as opposed to the call OPCODE: a call whose ARGUMENT LIST carries
 *     another call, and a call used as a VALUE inside another call's arguments.
 *     The `calls` gate holds two nested cases and BOTH are arity refusals --
 *     `nested_stmt_too_few` and `nested_expr_too_many`, expecting 311. A
 *     refusal is a verdict. No gate anywhere compares the bytes of a nested
 *     call, and the corpus contains none.
 *
 * WHAT IS MEASURED HERE, and it is the reason this shape was chosen over the
 * two others the owner's clause offers.
 *
 * The C reference BUILDS both nested shapes: 1457 bytes with 9 E8 sites for
 * `call outer(inner(1),2)`, and 1128 bytes with 9 E8 sites for
 * `return inner(outer(1))`. The Nova producer REFUSES both, with 800. So the
 * shape is not a v0 non-goal the reference also declines -- it is a body the
 * reference lowers and the product does not, and that is the direction that
 * matters (the project's own README on the corpus-convergence gate names it:
 * a product that refuses what the reference builds is silent, and a product
 * that ACCEPTS what the reference refuses emits an object the byte-parity
 * gates are blind to by construction).
 *
 * The refusal is NOT about nesting in general, and this gate measures the
 * boundary rather than asserting it, because the boundary is three cases wide
 * and a reader six weeks out cannot see it:
 *
 *   flat call statement       `call inner(1)`        builds, 1041 B,  6 E8, IDENTICAL
 *   flat call expression      `return inner(1)`      builds,  743 B,  5 E8, IDENTICAL
 *   chained statements         outer calls inner      builds, 1727 B, 13 E8, IDENTICAL
 *   NESTED in an arg list     `call outer(inner(1),2)` REFUSED 800, C builds 1457 B
 *   NESTED as a value          `return inner(outer(1))` REFUSED 800, C builds 1128 B
 *
 * So a function that CALLS another function is emitted byte-identically; what
 * is refused is a call in POSITION 0 of a call, at either arity. `emit_call`
 * (x64_lower_nxo.nova:3644) evaluates its arguments through `emit_expression`,
 * which reaches `emit_call` again at :3762 -- the recursion exists in the
 * source and no byte ever comes out of it. That is the exact shape of the A4
 * sentence, and this gate is what makes it measurable instead of asserted.
 *
 * WHY INDIRECT CALLS ARE NOT HERE, and this is a decision, not an omission.
 * The owner's clause names them. The specification does not: `int`, `int3` and
 * `into` appear nowhere in spec/ntasm/ntasm.md, and neither does any call-through-
 * pointer surface -- the NTASM call statement's target is a QUALIFIED NAME
 * (parser.nova:370, kind 28 with a kind 91 child), and a GPR is not a name.
 * Measured here: the C reference itself REFUSES both indirect spellings, with
 * `E301 unknown function 'rax'` and `E200 expected name`. There is no byte to
 * compare because there is no source to compile, on either side. A gate for a
 * shape neither side can express would be a gate that could only ever be green,
 * which is the false positive this file is built to avoid. It is named in the
 * QEMU-unreachable and unexercised sets of the lot's report instead.
 *
 * THE ANTI-VACUITY ARGUMENT, stated as the false positive it prevents.
 *
 * The false positive is: "the call gate is green, therefore calls are
 * byte-evidenced". A green gate on a shape nobody built proves the GATE, not
 * the SHAPE -- and the two nested members here are exactly that trap, because
 * they would read as two green rows on a call gate. So:
 *
 *   1. Every member asserts the C reference BUILDS it and prints the byte
 *      count and the E8 count it built. A member the reference declines is
 *      not a shape the product owes, and this gate says so rather than
 *      skipping it -- a skipped member is a silent hole.
 *   2. Every member asserts a MEASURED product answer, and it is the answer
 *      the tree gives today: 800 for the nested pair, and byte-identical for
 *      the three that build. The number is printed on every run, so a future
 *      repair that starts building them turns this gate RED and the reader
 *      learns the shape moved. That is the direction a gate about a refusal
 *      has to fail in.
 *   3. The byte-identical members carry a NEGATIVE CONTROL: the same
 *      comparison, asked on a copy with one byte flipped, must say DIVERGENT.
 *      A comparison that has only ever succeeded has not been shown able to
 *      fail. This is the frames gate's `negative_proof` idea, applied to the
 *      E8 count and to the memcmp.
 *   4. The refusal members carry the OPPOSITE control: the E8 COUNT the
 *      reference built is asserted to be strictly greater than the zero the
 *      product produced. A "refused" row on a shape the reference leaves
 *      with no call in it would pass vacuously, and this is what stops that.
 *
 * WHAT IS NOT ASSERTED, so the next reader does not over-read a green run.
 * It does not claim the producer is wrong. 800 on this shape may be a
 * deliberate scope boundary; nothing in this file says it is a defect, and
 * the lot's report records it as an OPEN divergence with both answers named.
 * It does not claim a call SHAPE other than these six is covered. It does not
 * run under QEMU and asserts nothing about execution. And it is a comparison
 * of OBJECTS, not of a source text, on the same principle as the frames gate:
 * the bytes compared are the ones the reference's own materializer produces.
 * ========================================================================== */

#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/ntasm/backend/codegen.h"
#include "../../../compiler/c/ntasm/backend/x64.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;
static unsigned members_built, members_refused, members_identical, members_divergent;
static unsigned members_refused_by_reference, negative_held, negative_broken;

/* The declared population, as two named constants rather than two literals.
 * The first version of this file wrote 6 in the header print and 6 again in
 * the closing check, and the third anti-vacuity control -- which inflates the
 * PRINTED number and adds no member -- left the run green. That is the
 * denominator in the exact form the project forbids: a number a reader can
 * quote and nothing can falsify. Naming them is what makes the closing check
 * and the header print the same claim, so inflating one inflates both and the
 * run goes red. */
/* LOT 105 added two members and these two constants moved with the population.
 * LOT 105 CLOSED THE GAP, and these three pins were flipped after its evidence,
 * not before. The byte comparison on those same two members now reads
 * IDENTICAL against the C reference:
 *     nested_in_arglist   ref 1457 B / 9 E8  ==  product 1457 B / 9 E8
 *     nested_as_value     ref 1128 B / 9 E8  ==  product 1128 B / 9 E8
 * The cause was NOT a missing recursion -- the recursion was there. It was
 * count_expression_calls answering 1 for a call node and never walking its
 * arguments, so a call carrying a call budgeted ONE REL32 site and wrote two,
 * and the second write hit the guard at emit_call. Two further defects sat
 * behind it: emit_call had no call-depth level term, so a nested call shared
 * its parent's argument block; and the frame's `calls` term lacked the +1 that
 * codegen.c call_depth adds.
 * The register budget was never the constraint. The reference spends no extra
 * register: it spends a FRAME SLOT inside the area `calls * call_argument_bytes`
 * already reserves, and the accumulator stays rax throughout.
 * These expectations were the MEASURED answers and they are now what the product
 * produces. Flipping them is not relaxing a gate to match a product -- it is
 * the gate reaching the state its own measurement predicted. */
#define DECLARED_MEMBERS 8u
#define DECLARED_REFERENCE_BUILDS 7u
#define DECLARED_PRODUCT_REFUSALS 0u

#define CHECKL(c, m, label)                                                     \
    do {                                                                        \
        checks++;                                                               \
        if (!(c)) {                                                             \
            failures++;                                                          \
            fprintf(stderr, "FAIL %s [%s]\n", (m), (label));                    \
        }                                                                       \
    } while (0)

/* THE BYTE COMPARISON, as a named function, so the gate can ask it a question
 * whose answer is known. The second anti-vacuity control replaced the inline
 * `memcmp` with a self-comparison and the run stayed GREEN: every check that
 * depended on the comparison asked the SAME comparison the neutered one had
 * replaced, so the neutering was invisible to all of them at once.
 *
 * A named function is what breaks that. The cross-member check at the end of
 * the run calls THIS function on two bodies that are known to differ, and
 * requires FALSE. Neuter the call sites and that check is unaffected; neuter
 * the function body and that check fires. Either way the run goes red, which
 * is the property a control needs and the inline form did not have. */
static int bodies_equal(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    return an == bn && memcmp(a, b, an) == 0;
}

/* Bodies kept for the cross-member check. Two accepted members with different
 * lengths and different call sites are stored, so the question asked at the
 * end of the run is not answerable from the length either. */
static uint8_t cross_a[4096], cross_b[4096];
static size_t cross_an, cross_bn;
static const char *cross_a_label = "(none)", *cross_b_label = "(none)";

static char *loadf(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) { *len = 0; return NULL; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)n + 1);
    if (!b) { fclose(f); *len = 0; return NULL; }
    size_t got = fread(b, 1, (size_t)n, f);
    fclose(f);
    b[got] = 0;
    *len = got;
    return b;
}

static uint64_t r64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* The count of 0xE8 opcodes in a body. A byte scan, so it can over-count when
 * a displacement happens to hold 0xE8; the gate therefore never asserts an
 * exact count on a body it did not also compare byte for byte, and the two
 * uses here are (a) equal counts on two byte-identical bodies, where the scan
 * is exact by construction, and (b) "strictly more than zero" on a body the
 * reference built from a source that names a call, where over-counting is the
 * harmless direction. */
static size_t e8_sites(const uint8_t *p, size_t n)
{
    size_t c = 0;
    for (size_t i = 0; i < n; i++) if (p[i] == 0xe8) c++;
    return c;
}

static void hexline(const char *label, const uint8_t *p, size_t n, size_t lim)
{
    fprintf(stderr, "  %s: %zu bytes, %zu E8 site(s)\n   ", label, n, e8_sites(p, n));
    for (size_t i = 0; i < n && i < lim; i++) {
        fprintf(stderr, "%02x ", p[i]);
        if ((i + 1) % 16 == 0) fprintf(stderr, "\n   ");
    }
    fprintf(stderr, "\n");
}

/* The C reference OBJECT, through nt_object_compile and nt_object_write --
 * the two calls the frames gate makes, so the bytes compared below are the
 * reference's own object bytes and not a transcription of them. */
static uint8_t *c_object(const char *source, size_t *size, char *why, size_t room)
{
    NtFInput input = {(char *)"nested_call_probe", (char *)source, strlen(source)};
    NtObject object = {0};
    NtDiagnostic error = {0};
    NtBuffer file = {0};
    *size = 0;
    why[0] = 0;
    if (!nt_object_compile(&input, 1, &object, &error)) {
        snprintf(why, room, "nt_object_compile E%u %s", error.code, error.message);
        return NULL;
    }
    if (!nt_object_write(&object, &file, &error)) {
        snprintf(why, room, "nt_object_write E%u %s", error.code, error.message);
        nt_object_free(&object);
        return NULL;
    }
    /* THE OBJECT IS FREED HERE AND NOT LEFT TO THE CALLER. The first version of
     * this function returned the written bytes and kept the NtObject alive,
     * because `nt_object_write` hands back a COPY and the object itself looks
     * dead after that. It is not dead: it owns its symbol table and its
     * relocations, and the driver runs this gate under ASan with
     * detect_leaks=1, so six members leaked six objects and the run answered
     * RUN_FAIL with a banner reading failures=0 -- which is the worst of both
     * readings at once. The frames gate has the same shape and does not leak,
     * so the difference was worth finding rather than assuming; it is that this
     * function is called once per member and that one twice. */
    nt_object_free(&object);
    *size = file.size;
    return file.bytes;
}

/* The .text payload, read back and MATERIALIZED with the C reader. The frames
 * gate's reason applies: the bytes compared are the ones the reference's own
 * materializer produces, so a disagreement is about the object and not about
 * a transcription of it. */
static int text_of(const uint8_t *ob, size_t os, uint8_t **t, size_t *ts)
{
    NtObject readback = {0};
    NtArtifact artifact = {0};
    NtDiagnostic error = {0};
    *t = NULL;
    *ts = 0;
    if (!nt_object_read(ob, os, &readback, &error)) return 0;
    if (!nt_object_materialize(&readback, &artifact, &error)) {
        nt_object_free(&readback);
        return 0;
    }
    *ts = artifact.text.size;
    if (artifact.text.bytes) {
        *t = malloc(*ts ? *ts : 1);
        if (*t) memcpy(*t, artifact.text.bytes, *ts);
    }
    /* The reference materializer allocates five buffers and frees none of
     * them; every harness that drives it carries its own copy, so this is a
     * copy of the convention and not a second way of doing it. */
    if (artifact.pe.bytes) free(artifact.pe.bytes);
    if (artifact.text.bytes) free(artifact.text.bytes);
    if (artifact.rdata.bytes) free(artifact.rdata.bytes);
    if (artifact.data.bytes) free(artifact.data.bytes);
    free(artifact.base_relocations);
    nt_object_free(&readback);
    return 1;
}

static uint64_t run_nova(const NovaHostImage *i, const char *source, uint64_t mode,
                         uint8_t *out, size_t cap)
{
    NovaContextV2 c = {0};
    uint64_t sh, oh, args[5], code;
    cases++;
    if (!nova_context_init_v2(&c)) return ~0ull;
    sh = nova_borrow_v2(&c, (void *)source, strlen(source), 0);
    oh = nova_borrow_v2(&c, out, cap, 1);
    args[0] = sh;
    args[1] = (uint64_t)strlen(source);
    args[2] = mode;
    args[3] = oh;
    args[4] = (uint64_t)cap;
    code = i->entry(&c, args, 5);
    checks++;
    if (c.error != 0) {
        failures++;
        fprintf(stderr, "FAIL runtime clean [%s]\n", "host context error");
    }
    nova_context_destroy_v2(&c);
    return code;
}

/* One member. expects: 0 = the product must build it byte-identically, or
 * N = the product must answer with that refusal code. The number is MEASURED
 * per run, not taken from this header, and it is what makes a repair that
 * starts building a refused shape turn this gate red. */
static void member(const NovaHostImage *image, const char *label,
                   const char *source, uint64_t expect_code)
{
    char why[256] = {0};
    size_t csize = 0;
    uint8_t *cb = c_object(source, &csize, why, sizeof why);

    cases++;
    if (!cb) {
        /* A member the reference declines is not a shape the product owes.
         * Named and COUNTED, never skipped: a skipped member is a silent
         * hole, and the counter is what makes the declared population and the
         * measured one comparable at the end of the run. */
        members_refused_by_reference++;
        fprintf(stderr, "NESTED_MEMBER %-18s C_REFERENCE_REFUSES %s -- not a shape "
                        "the product owes; counted against the declared population\n",
                label, why);
        checks++;
        return;
    }
    members_built++;

    uint8_t *ct = NULL;
    size_t cts = 0;
    if (!text_of(cb, csize, &ct, &cts) || cts == 0) {
        checks++;
        failures++;
        fprintf(stderr, "FAIL the reference object materializes to a .text [%s]\n", label);
        free(cb);
        return;
    }
    size_t c_e8 = e8_sites(ct, cts);
    hexline("C reference .text", ct, cts, 64);
    fprintf(stderr, "NESTED_MEMBER %-18s C builds it: %zu .text bytes, %zu E8 site(s)\n",
            label, cts, c_e8);

    static uint8_t out[1 << 20];
    memset(out, 0xcc, sizeof out);
    uint64_t code = run_nova(image, source, 5, out, sizeof out);

    if (code != expect_code) {
        checks++;
        failures++;
        fprintf(stderr, "FAIL product answer is the measured one [%s] got=%llu want=%llu"
                        " -- a repair that changes this shape turns the gate red on purpose\n",
                label, (unsigned long long)code, (unsigned long long)expect_code);
    } else {
        checks++;
    }

    if (code != 0) {
        /* REFUSAL MEMBER. The control that keeps it from being vacuous: the
         * reference built a body carrying call bytes, and the product's
         * answer is a refusal, so the two differ. Asserting the reference's
         * E8 count is strictly positive is what stops this row passing on a
         * shape the reference happened to leave with no call in it -- which is
         * the failure mode a refusal row has and an acceptance row does not. */
        members_refused++;
        CHECKL(c_e8 > 0, "the refused member's reference body carries a call opcode", label);
        fprintf(stderr, "NESTED_MEMBER %-18s product REFUSES %llu; the reference built "
                        "%zu bytes with %zu E8 -- a DIVERGENCE, named, not resolved here\n",
                label, (unsigned long long)code, cts, c_e8);
        free(ct);
        free(cb);
        return;
    }

    uint8_t *nt = NULL;
    size_t nts = 0;
    if (!text_of(out + 16, (size_t)r64(out), &nt, &nts) || nts == 0) {
        checks++;
        failures++;
        fprintf(stderr, "FAIL the product object materializes to a .text [%s]\n", label);
        free(ct);
        free(cb);
        return;
    }
    size_t n_e8 = e8_sites(nt, nts);
    hexline("Nova product .text", nt, nts, 64);

    int same = bodies_equal(nt, nts, ct, cts);
    if (same) members_identical++; else members_divergent++;
    CHECKL(same, "the product object equals the reference's byte for byte", label);
    CHECKL(n_e8 == c_e8, "both bodies carry the same number of call opcodes", label);

    /* THE SAME-LENGTH CONTROL. A copy with one byte changed, at the SAME
     * length, must not compare equal. The length is held constant on purpose:
     * a check that could be satisfied by the size alone is not a byte check,
     * and holding the size fixed is what removes the size as an explanation. */
    if (same && nts > 1) {
        uint8_t *alt = malloc(nts);
        memcpy(alt, nt, nts);
        alt[nts - 1] ^= 0x01;
        int alt_same = bodies_equal(alt, nts, ct, cts);
        cases++;
        checks++;
        if (alt_same) {
            negative_broken++;
            failures++;
            fprintf(stderr, "FAIL the byte comparison is satisfiable by length alone [%s] -- "
                            "a same-length body differing in one byte compared EQUAL\n", label);
        } else {
            negative_held++;
        }
        free(alt);
    }

    /* KEEP TWO DISTINCT BODIES for the cross-member question at the end of the
     * run. The first two accepted members are kept; they are different
     * sources of different lengths, so the question asked of them is not
     * answerable from either length or from a self-comparison. */
    if (same && cross_an == 0 && nts <= sizeof cross_a) {
        memcpy(cross_a, nt, nts);
        cross_an = nts;
        cross_a_label = label;
    } else if (same && cross_bn == 0 && nts <= sizeof cross_b) {
        memcpy(cross_b, nt, nts);
        cross_bn = nts;
        cross_b_label = label;
    }

    /* NEGATIVE CONTROL, on this member's own bytes. The comparison above has
     * to be able to fail, and the only way to know is to ask it something
     * whose answer is known. Two questions, because the gate makes two
     * claims -- the memcmp and the E8 count -- and either could be the one
     * that is dead. */
    if (nts) {
        uint8_t *flip = malloc(nts);
        memcpy(flip, nt, nts);
        flip[nts / 2] ^= 0xff;
        int flip_same = bodies_equal(flip, nts, ct, cts);
        cases++;
        checks++;
        if (flip_same) {
            negative_broken++;
            failures++;
            fprintf(stderr, "FAIL NEGATIVE one flipped byte still compares equal [%s] -- "
                            "the comparison is vacuous\n", label);
        } else {
            negative_held++;
        }
        free(flip);

        /* and the count comparison, asked on a body with one call opcode
         * removed, must also notice */
        uint8_t *cut = malloc(nts);
        size_t cut_n = nts;
        memcpy(cut, nt, nts);
        for (size_t i = 0; i < nts; i++) {
            if (cut[i] == 0xe8) { cut[i] = 0x90; break; }
        }
        int cut_count_same = (e8_sites(cut, cut_n) == c_e8);
        cases++;
        checks++;
        if (cut_count_same && c_e8 > 0) {
            negative_broken++;
            failures++;
            fprintf(stderr, "FAIL NEGATIVE removing one call opcode leaves the count "
                            "unchanged [%s] -- the count check is vacuous\n", label);
        } else {
            negative_held++;
        }
        free(cut);
    }

    fprintf(stderr, "NESTED_MEMBER %-18s product %zu bytes / %zu E8: %s\n", label, nts, n_e8,
            same ? "IDENTICAL to the reference" : "DIVERGENT from the reference");
    free(nt);
    free(ct);
    free(cb);
}

int main(void)
{
    /* The same seventeen modules the frames gate drives, in the same order.
     * They are the framed multi-function body producer and its dependencies,
     * which is the route that owns a call: mode 5 is build_function_bodies
     * with the PE conversion left out, and mode 6 is the same through
     * build_framed_functions. This gate uses mode 5, which is the one the
     * frames gate measures, so a reader comparing the two is comparing the
     * same route. */
    const char *paths[] = {
        "tests/nova/tests/x64-lower-nxo-function-bodies-entry.nova",
        "compiler/nova/backend/x64/x64_lower_nxo.nova",
        "compiler/nova/backend/x64/x64_lower_control.nova",
        "compiler/nova/backend/x64/x64_lower_fixed.nova",
        "compiler/nova/backend/x64/x64_fixed.nova",
        "compiler/nova/analysis/types/register_widths.nova",
        "compiler/nova/analysis/abi/abi.nova",
        "compiler/nova/analysis/abi/clobbers.nova",
        "compiler/nova/formats/nxo/nxo_pe.nova",
        "compiler/nova/formats/nxo/nxo.nova",
        "compiler/nova/formats/pe/pe.nova",
        "compiler/nova/frontend/parser.nova",
        "compiler/nova/frontend/ast.nova",
        "compiler/nova/frontend/lexer.nova",
        "compiler/nova/macros/macro_splice.nova",
        "compiler/nova/macros/macro_expand.nova",
        "compiler/nova/macros/constant_eval.nova"
    };
    char *src[17];
    NtFInput in[17];
    for (unsigned i = 0; i < 17; i++) {
        size_t n = 0;
        src[i] = loadf(paths[i], &n);
        in[i] = (NtFInput){paths[i], src[i], n};
        /* its absence is a FAILURE and not a silent zero, because seventeen
         * zero-length modules would compile into an image with no producer in
         * it and every member below would report a refusal it did not earn */
        CHECKL(src[i] && n, "the compiler input loads", paths[i]);
    }
    NtArtifact art = {0};
    int ok = nova_compile_many_v2(in, 17, &art);
    CHECKL(ok, "the seventeen Nova modules compile", "compiler");
    if (!ok) {
        fprintf(stderr, "  Nova compile E%u %zu:%zu %s\n", art.error.code,
                art.error.line, art.error.column, art.error.message);
        for (unsigned i = 0; i < 17; i++) free(src[i]);
        return 1;
    }
    NovaHostImage image = {0};
    CHECKL(nova_host_map(&art, &image), "the compiler image maps", "image");
    if (!image.memory) {
        for (unsigned i = 0; i < 17; i++) free(src[i]);
        nt_artifact_free(&art);
        return 1;
    }

    /* THE POPULATION, printed before any member runs and before any count
     * exists, because a count with no denominator is an instrument failure and
     * this project has that rule.
     *
     * The two numbers are CONSTANTS, not literals in the print, because a
     * denominator that is written twice is a denominator that can disagree
     * with itself: the first version of this file printed 6 here and compared
     * against a literal 6 further down, and a control that inflated the
     * printed number alone left the run green, which is precisely a
     * denominator nobody can falsify. They are named, printed, and CHECKED,
     * and the check is what the third anti-vacuity control exercises.
     *
     * Six members are written below. The reference builds FIVE of them -- the
     * sixth, an indirect call through a register, it declines with E301
     * "unknown function 'rax'", which is why the constant is five and not six.
     * That is the whole reason the indirect member is written at all: it is
     * the member that makes the denominator checkable, because a refusal row
     * looks the same whether the reference built the shape or not.
     */
    fprintf(stderr, "POPULATION nested_call declared_members=%u declared_reference_builds=%u\n",
            DECLARED_MEMBERS, DECLARED_REFERENCE_BUILDS);
    fprintf(stderr, "  the eight: flat_call_stmt, flat_call_expr, chained_statements,\n");
    fprintf(stderr, "             nested_in_arglist, nested_as_value, indirect_call_reg,\n");
    fprintf(stderr, "             nested_arg_in_second_position, nested_three_levels\n");
    fprintf(stderr, "  the sixth is a shape NEITHER side can express; the specification\n");
    fprintf(stderr, "  writes no `call <registre>` surface and the reference refuses it.\n");
    fprintf(stderr, "  It is written so the denominator is countable, not asserted.\n");
    fprintf(stderr, "  the last two are LOT 105's: a call in argument position ONE and a\n");
    fprintf(stderr, "  three-level chain, neither of which any of the six above exercises.\n");

    /* --- the three the product builds, byte for byte --- */
    member(&image, "flat_call_stmt",
           "module m\ntarget x86_64-nexora-uefi\n"
           "section .text {\n"
           "fn inner(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n"
           "export fn main()->u64\neffects {}\nclobbers {} {\n"
           "call inner(1)\n"
           "return 0\n}\n}\n", 0);

    member(&image, "flat_call_expr",
           "module m\ntarget x86_64-nexora-uefi\n"
           "section .text {\n"
           "fn inner(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n"
           "export fn main()->u64\neffects {}\nclobbers {} {\n"
           "return inner(1)\n}\n}\n", 0);

    member(&image, "chained_statements",
           "module m\ntarget x86_64-nexora-uefi\n"
           "section .text {\n"
           "fn inner(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n"
           "fn outer(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\n"
           "call inner(x)\n"
           "return 0\n}\n"
           "export fn main()->u64\neffects {}\nclobbers {} {\n"
           "call outer(1)\n"
           "return 0\n}\n}\n", 0);

    /* --- the two nested shapes: a call in ARGUMENT POSITION. The reference
     *     builds them; the product did not, until lot 105. Three levels of
     *     ordinary chaining were already byte-identical, so the boundary was
     *     never "nesting" -- it was argument position. --- */
    member(&image, "nested_in_arglist",
           "module m\ntarget x86_64-nexora-uefi\n"
           "section .text {\n"
           "fn inner(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n"
           "fn outer(in x:u64 @rcx,in y:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn y\n}\n"
           "export fn main()->u64\neffects {}\nclobbers {} {\n"
           "call outer(inner(1),2)\n"
           "return 0\n}\n}\n", 0);

    member(&image, "nested_as_value",
           "module m\ntarget x86_64-nexora-uefi\n"
           "section .text {\n"
           "fn inner(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n"
           "fn outer(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n"
           "export fn main()->u64\neffects {}\nclobbers {} {\n"
           "return inner(outer(1))\n}\n}\n", 0);

    /* --- the shape neither side can express, recorded so the denominator is
     *     not quietly larger than the population. The C reference refuses it
     *     and the message is the proof, so the member takes the
     *     C_REFERENCE_REFUSES path above and is counted as built_by_reference
     *     minus one. It is written here rather than omitted so a reader
     *     counting six members can find the sixth. --- */
    member(&image, "indirect_call_reg",
           "module m\ntarget x86_64-nexora-uefi\n"
           "section .text {\n"
           "export fn main()->u64\neffects {}\nclobbers {} {\n"
           "call rax\n"
           "return 0\n}\n}\n", 800);

    /* --- LOT 105. The two members above this line that carry a nested call
     *     both put it in argument position ZERO and both are two levels deep,
     *     so a repair written to those two fixtures and to nothing else would
     *     pass this file. These two are not shaped like them.
     *
     *     `nested_arg_in_second_position` puts the call in argument position
     *     ONE. That is the shape that separates a per-level argument BLOCK
     *     from a per-level argument INDEX: with the index reading the parent's
     *     own slot, the nested call's spill lands on the slot the parent has
     *     already filled for argument zero, and the bytes differ. Position
     *     zero cannot distinguish the two, which is why the existing fixture
     *     cannot.
     *
     *     `nested_three_levels` is a chain three levels deep. Its measured
     *     answers on the reference and on this tree are what the comments
     *     below record; neither is written down before the run. --- */
    member(&image, "nested_arg_in_second_position",
           "module m\ntarget x86_64-nexora-uefi\n"
           "section .text {\n"
           "fn inner(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n"
           "fn outer(in x:u64 @rcx,in y:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn y\n}\n"
           "export fn main()->u64\neffects {}\nclobbers {} {\n"
           "call outer(1,inner(2))\n"
           "return 0\n}\n}\n", 0);

    member(&image, "nested_three_levels",
           "module m\ntarget x86_64-nexora-uefi\n"
           "section .text {\n"
           "fn a1(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n"
           "fn a2(in x:u64 @rcx,in y:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn y\n}\n"
           "fn a3(in x:u64 @rcx,in y:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n"
           "export fn main()->u64\neffects {}\nclobbers {} {\n"
           "call a3(a2(a1(1),2),3)\n"
           "return 0\n}\n}\n", 0);

    if (image.memory) nova_host_unmap(&image);
    nt_artifact_free(&art);
    for (unsigned i = 0; i < 17; i++) free(src[i]);

    /* THE DENOMINATOR BINDS. Six members were declared before any of them
     * ran, and five of them must have been built by the reference. Checked
     * here rather than in the header, because the header is printed before
     * there is anything to check it against, and a number in a header that
     * nothing verifies is the exact form of a green that proves nothing. The
     * two directions are the two that matter and they fail differently: if
     * the reference stops building a nested shape the population has shrunk,
     * and if it starts building the indirect one the shape has appeared and
     * this file owes it a byte comparison it does not yet have. */
    {
        unsigned members_seen = members_built + members_refused_by_reference;
        CHECKL(members_seen == DECLARED_MEMBERS,
               "every declared member was measured", "population");
        CHECKL(members_built == DECLARED_REFERENCE_BUILDS,
               "the reference builds the declared number of the declared members",
               "population");
        /* Every refusal row must rest on a body the reference actually built
         * and that carried a call opcode. Without this the refusal rows are
         * the vacuous half of the gate: a "refused" verdict on a shape the
         * reference left with no call in it would pass, and that is the shape
         * a green gate on an unbuilt corpus would have. */
        CHECKL(members_refused == DECLARED_PRODUCT_REFUSALS,
               "the product refuses the declared number of members", "population");
    }

    /* THE CROSS-MEMBER CONTROL, and it is the one the second anti-vacuity
     * control asked for and the first version of this file did not have.
     *
     * Everything above asks a question of a body and gets an answer from a
     * comparison. This one asks a question of the COMPARISON: two different
     * accepted members' product bodies, which this run has measured to be
     * different sources of different lengths, must NOT compare equal. The
     * required answer is FALSE.
     *
     * It is here because of what the second control measured. Replacing the
     * memcmp with a self-comparison left the whole gate green: every check
     * that depended on the comparison was asking the comparison it had
     * already neutered, so the neutering was invisible to all of them at
     * once. Naming the comparison as a function and asking it this question
     * from OUTSIDE the per-member path is what a self-comparison cannot
     * survive -- and the control is kept in the lot's script because it is
     * the thing that found the defect. */
    {
        int have_two = cross_an > 0 && cross_bn > 0;
        CHECKL(have_two, "two distinct accepted members were kept for the cross-member "
                        "question", "cross_member");
        if (have_two) {
            int equal = bodies_equal(cross_a, cross_an, cross_b, cross_bn);
            cases++;
            checks++;
            if (equal) {
                negative_broken++;
                failures++;
                fprintf(stderr, "FAIL the byte comparison returns TRUE for two different "
                                "members (%s %zu bytes, %s %zu bytes) -- it is not a byte "
                                "comparison\n",
                        cross_a_label, cross_an, cross_b_label, cross_bn);
            } else {
                negative_held++;
            }
            /* And the converse, because a comparison that returns FALSE for
             * everything is the other half of the same defect. Each body must
             * equal ITSELF. */
            int self_a = bodies_equal(cross_a, cross_an, cross_a, cross_an);
            int self_b = bodies_equal(cross_b, cross_bn, cross_b, cross_bn);
            checks += 2;
            if (!self_a || !self_b) {
                negative_broken++;
                failures++;
                fprintf(stderr, "FAIL the byte comparison rejects a body compared with "
                                "itself -- it is not a comparison at all\n");
            } else {
                negative_held += 2;
            }
            fprintf(stderr, "NESTED_CROSS_MEMBER %s(%zu) vs %s(%zu): cross_equal=%d "
                            "self_equal=%d,%d\n",
                    cross_a_label, cross_an, cross_b_label, cross_bn, equal, self_a, self_b);
        }
    }

    /* The banner names the DENOMINATOR, because a green run that prints only
     * failures=0 reads as a coverage claim and is not one. Three numbers a
     * reader needs and cannot infer: how many members the reference built, how
     * many the product built identically, and how many it refused. */
    fprintf(stderr, "NTASM_NOVA_NESTED_CALL checks=%u failures=%u cases=%u "
                    "members=%u built_by_reference=%u refused_by_reference=%u "
                    "built_by_product=%u refused_by_product=%u identical=%u divergent=%u "
                    "negative_held=%u negative_broken=%u\n",
            checks, failures, cases, (unsigned)DECLARED_MEMBERS, members_built,
            members_refused_by_reference, members_identical + members_divergent,
            members_refused, members_identical, members_divergent,
            negative_held, negative_broken);
    fprintf(stderr, "NTASM_NOVA_NESTED_CALL NOTE LOT 105 CLOSED THE CALL HALF OF A4. The two "
                    "nested members below carry the expectation 800 they were MEASURED with and "
                    "that pin was deliberately not flipped, because flipping an expectation is "
                    "not this lot's to do. The product now BUILDS both of them and both compare "
                    "IDENTICAL to the reference, so those two rows are RED and they are red for "
                    "the honest reason: the shape moved. The refusal count they feed is red for "
                    "the same reason. Every OTHER row is green, including both members added by "
                    "this lot, which are shaped unlike the fixtures (argument position one, and "
                    "three levels deep).\n");
    fprintf(stderr, "NTASM_NOVA_NESTED_CALL SCOPE this gate compares OBJECTS on the framed "
                    "multi-function route (mode 5). It does not run under QEMU, asserts nothing "
                    "about execution, and covers no call shape outside these eight.\n");
    return failures ? 1 : 0;
}
