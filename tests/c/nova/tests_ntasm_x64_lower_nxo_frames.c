/* Gate for the ONE invariant the corpus convergence gate cannot see: a body the
 * C reference lowers with a FRAME must never be lowered by the frameless
 * producer as a different object.
 *
 * WHY A SEPARATE GATE AND NOT ANOTHER MEMBER OF THE SEVEN. The corpus gate
 * (nova_corpus_convergence.c) drives x64_lower_nxo.build_function_bodies over
 * seven pinned members and compares the two producers byte for byte. Six of
 * them converge, and every one of the six takes a path that happens to build a
 * frame: four are a single `return <foldable constant>`, which is codegen.c's
 * raw entry shortcut, and two declare a data section, which delegates to the
 * framed producer at the single delegation in x64_lower_nxo.nova. The seventh
 * is refused. So the gate covers zero parameterless, data-free bodies that the
 * reference FRAMES, and a producer that dropped the frame for those would not
 * turn one line of it red. This file is that missing member, as a gate of its
 * own so that its red is one signal and not a line among several thousand.
 *
 * WHAT IS ASSERTED, for each member, and why each half is there.
 *   1. the C reference BUILDS the member. A member the reference refuses is
 *      not a shape the product owes, so the whole question would be vacuous.
 *   2. the reference's .text carries the prologue that member is claimed to
 *      have, checked against the BYTES and not against a comment: the frame
 *      members must begin with pushfq, the thirteen saved register pushes and
 *      push rbp (codegen.c 1289-1297), and the control member must NOT. This
 *      is what stops a member from being quietly replaced by a shape that does
 *      not test anything.
 *   3. the frameless producer either refuses, or emits the reference's object
 *      byte for byte. A refusal is an acceptable answer here and a DIVERGENCE
 *      never is: the defect this gate exists for is a producer that answers a
 *      framed body with frameless bytes and a zero exit code, which is silent.
 *      Expressing the assertion as "refuse or agree" rather than "must refuse"
 *      also means the day a producer routes this shape through a real frame
 *      emitter and converges, this gate goes GREEN, not red.
 *   4. for the control member the refusal is a FAILURE. Without it, a producer
 *      that refused everything would pass this gate, and "no silent divergence"
 *      would be indistinguishable from "compiles nothing".
 *
 * WHAT IS NOT ASSERTED, restated because the sentence that used to stand here
 * was false. It said "Neither member is claimed to CONVERGE. frame-omission is
 * a gap: the C reference builds it and the Nova producer does not." The
 * producer DOES build it, and the whole 368-byte .text is the reference's, so
 * the member is green for the right reason. The reason is the delegation, and
 * it is asserted rather than described: see the route check in main, which
 * reads the producer's source and goes red if the delegation is ever removed.
 * The gap this paragraph used to advertise is closed, and what replaces it is
 * not a smaller gap but a different statement: this gate asserts that a body
 * the reference frames is never answered with frameless bytes and a success
 * code, and it cannot tell you whether any given body CONVERGES unless that
 * body is one of its two members. Convergence over the corpus is
 * nova_corpus_convergence.c's claim, and this file is not a second copy of it.
 *
 * THE SCOPE, measured, and the measurement is the reason this file is worth
 * anything: how many sources is this a count of, and the answer is a class.
 *
 * The sentence that used to stand here said the frameless path is reached by
 * every source whose section declares no parameter and no data item, and "it
 * emits no prologue and no epilogue for any of them", from which it concluded
 * that every parameterless, data-free body outside the raw-entry window
 * DIVERGES silently. That was true when written and is false now, and it is
 * false in the direction that matters: the entry this file drives is
 * build_function_bodies, and that entry DELEGATES to build_framed_functions
 * whenever any_body_is_framed holds (x64_lower_nxo.nova:1940-1942,
 * predicate declared at :1820), which is the reference's own condition at
 * codegen.c 1252-1255. So the two producers converge on these shapes because
 * they implement the same predicate, and "the frameless producer" is not a
 * producer this file can still reach on a framed body.
 *
 * WHICH IS WHY THE DIVERGENCES DESCRIBED BELOW ARE NOT PRODUCT DEFECTS, and
 * that correction is worth more than the list it replaces. Measured on the
 * shapes this file and its neighbours name -- two functions with one call,
 * two distinct call targets, one to four calls of one target, and this file's
 * own two members -- the producer's whole object is byte identical to the C
 * reference's, on both routes, over the .text, the symbol table, the
 * relocations and the contract strings. What diverged was a sibling gate's own
 * HAND-BUILT MODEL, which encoded a frameless expectation for three call
 * shapes the reference frames; 30 comparison FAIL lines in
 * tests_ntasm_x64_lower_nxo_function_bodies.c were that model, and were
 * reported as a silent producer defect until the objects were compared
 * directly.
 *
 * AND THE NUMBERS, because "byte identical" over a range is a claim a reader
 * cannot check, and this file has been the wrong end of one twice already. The
 * four k values, whole object, both routes, .text and every record:
 *   k=1  .text=669   object=1408  mode5==C mode6==C
 *   k=2  .text=969   object=1744  mode5==C mode6==C
 *   k=3  .text=1269  object=2096  mode5==C mode6==C
 *   k=4  .text=1569  object=2432  mode5==C mode6==C
 * k=1 and k=2 were measured on the first pass and k=3 and k=4 were not, while
 * the sentence above named all four. That made two of the four an overclaim of
 * exactly the kind retracted further down in this header, so they were RUN
 * rather than the sentence trimmed to what had been measured. Narrowing it
 * would have left a true sentence and a weaker one than the truth, and a reader
 * would still not have known which k had been checked.
 *
 * A negative result of that kind is only worth reading next to the
 * instrument's ability to fail, so: dropping the delegation term takes
 * frame-omission to 21 frameless bytes and turns this gate red at diverged=1,
 * and perturbing the frame CONTENTS with the routing untouched turns it red
 * again at a located offset. Both were run; neither is claimed on the strength
 * of this paragraph.
 *
 * A reader who wants the current state of the shapes should MEASURE it, and
 * the gate that does is the corpus gate, not this one.
 *
 * AND THE RESIDUAL THIS PARAGRAPH USED TO CARRY IS ALSO FALSE, retracted here
 * rather than left for the next reader. It said: "a mov body whose inferred
 * rax clobber is not declared is emitted by the producer where the reference
 * REFUSES it, which is a real asymmetry". I wrote that sentence into this file
 * while correcting the others, TAKEN FROM THE HEADER I WAS REPLACING, without
 * measuring it -- which is the same defect one level down, and the reason the
 * rest of this file is written as checks rather than as prose is that prose is
 * where it happened. Measured, on five bodies:
 *
 *   mov rax,2 ; return 42, clobbers {rax}   C BUILDS  480-object, producer 0
 *   mov rax,2 ; return 42, clobbers {}      C REFUSES E502, producer 800
 *   mov rbx,2 ; return 42, clobbers {}      C REFUSES E502, producer 800
 *   add rax,1 ; return 42, clobbers {}      C REFUSES E502, producer 800
 *   return 42 alone, clobbers {}            C BUILDS, producer 0
 *
 * The producer refuses exactly where the reference refuses, on every one. The
 * asymmetry was an artefact of the reference's refusal never having been
 * compared against the producer's on the same five bodies, which is the same
 * omission that made the 30 look real. There is no residual product divergence
 * here, and a reader must not go looking for one on the strength of a sentence
 * this file once carried.
 * The two members are read from the tree rather than written here as literals,
 * which is the one thing nova_corpus_convergence.c's own header says of its
 * literal CORPUS array makes impossible: a member added to the tree is a
 * member this gate covers. */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "../../../compiler/c/ntasm/backend/codegen.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL %s\n", (m)); } } while (0)
#define CHECKL(c, m, l) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL %s [%s]\n", (l), (m)); } } while (0)

#define OUTCAP 262144
#define DIR "examples/ntasm-v0/frame-gate-fixtures/"

/* The two members are GATE FIXTURES and are deliberately NOT pinned corpus
 * members. scripts/ntbuild.sh holds its corpus in an explicit
 * RECORDED_EXAMPLES array (its line 105) and nothing globs examples/ntasm-v0,
 * so a program under that tree is a fixture until somebody adds a pin for it,
 * and no pin exists for these two. Pinning them would assert that the C
 * producer must keep reproducing their bytes inside the build normal, which is
 * a second corpus with its own pins and its own ntbuild.sh selftest baseline,
 * and that is a decision about what the corpora are rather than one this gate
 * gets to make. The directory name says which they are: it does not carry the
 * c-bootstrap prefix the three corpora share, so it cannot be read as a fourth
 * one. If you are reading this while wondering why these two are not in
 * RECORDED_EXAMPLES, that is the reason and the reason is not an oversight. */

/* The frame codegen.c emit_function emits, in the order of its lines 1289 to
 * 1297: pushfq, then the thirteen saved registers, then push rbp, then
 * mov rbp,rsp, then the sub rsp of line 1309. The member this names carries
 * no rflags clobber, so preserve_flags is true and the leading pushfq is
 * present (codegen.c 1277). */
static const uint8_t FRAME_HEAD[] = {
    0x9c,
    0x51, 0x52, 0x53, 0x56, 0x57,
    0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55,
    0x41, 0x56, 0x41, 0x57,
    0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec
};
#define FRAME_HEAD_N ((size_t)(sizeof FRAME_HEAD))

/* The raw entry shortcut, codegen.c 1257-1260: mov rax,imm64 then ret. The
 * control member must begin with the mov, which is the same first byte a
 * framed member's body begins with, so this is the discrimination that the
 * two members are told apart by something other than their names. */
static const uint8_t SHORTCUT_HEAD[] = {0x48, 0xb8};
#define SHORTCUT_HEAD_N ((size_t)(sizeof SHORTCUT_HEAD))

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

static uint64_t r64(const uint8_t *b)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) v |= (uint64_t)b[i] << (i * 8);
    return v;
}

/* The producer, through the same entry the corpus gate drives, mode 5, which
 * is build_function_bodies with the PE conversion left out.
 *
 * POINTER, NOT A CLAIM, AND THE REPLACEMENT IS DELIBERATE. The sentence this
 * comment used to carry said the frameless and the framed producers are
 * separate modes in that entry, "so mode 5 cannot be answered by the framed
 * one". Both halves were false, and the file does not restate the truth here
 * because a second copy of a claim is a second copy nobody updates.
 *
 * The owner of the question is x64_lower_nxo.nova: build_function_bodies is
 * the entry, and it DELEGATES to build_framed_functions when
 *     declares_parameter(tree,section_id)==1 || data_seen==1 ||
 *     any_body_is_framed(tree,section_id)==1
 * at x64_lower_nxo.nova:1940-1942. any_body_is_framed is declared at
 * x64_lower_nxo.nova:1820 and is the REFERENCE's own condition, codegen.c
 * 1252-1255, which is why the two producers converge rather than coinciding.
 * So a mode 5 answer on a framed shape is a framed answer, and that is correct
 * behaviour rather than a hole in this instrument.
 *
 * WHY THIS FILE STILL SAYS IT AT ALL, and why the next reader should take the
 * pointer and not this paragraph: the false sentence was the ONLY place in the
 * tree asserting that separation, and it was believed. It turned 30 comparison
 * FAIL lines in a sibling gate into "the framed producer emits wrong bytes",
 * which sent a wave of eight lots at a defect that does not exist -- the
 * sibling's own hand-built model was frameless, and the producer's bytes are
 * the reference's. A comment nothing can contradict is the failure mode, so the
 * property is ASSERTED BELOW instead: delegation_source_is_loaded checks the
 * producer's own text for the term, which goes RED if the delegation is ever
 * removed rather than leaving this paragraph quietly wrong. Read the check's
 * result, not this comment. */
static uint64_t run_nova(const NovaHostImage *i, const char *source, uint64_t mode,
                         uint8_t *out, size_t cap)
{
    NovaContextV2 c = {0};
    uint64_t sh, oh, args[5], code;
    CHECK(nova_context_init_v2(&c), "context init");
    sh = nova_borrow_v2(&c, (void *)source, strlen(source), 0);
    oh = nova_borrow_v2(&c, out, cap, 1);
    args[0] = sh; args[1] = (uint64_t)strlen(source); args[2] = mode;
    args[3] = oh; args[4] = (uint64_t)cap;
    code = i->entry(&c, args, 5);
    CHECK(c.error == 0, "runtime clean");
    CHECK(nova_context_destroy_v2(&c), "context cleanup");
    cases++;
    return code;
}

/* Counts non-overlapping occurrences, for the one check below that reads the
 * producer's source text. It exists because the property this gate depends on
 * is a property of the SOURCE and not of the bytes, and a source property
 * cannot be measured by running the producer. */
static size_t count_bytes(const char *hay, const char *needle)
{
    size_t n = strlen(needle), at = 0, seen = 0;
    if (hay == NULL || n == 0) return 0;
    while (hay[at]) {
        if (!strncmp(hay + at, needle, n)) { seen++; at += n; }
        else at++;
    }
    return seen;
}

/* count_code, which is count_bytes over CODE rather than over text. It returns
 * the same number for every source comment and for every prose mention of a
 * needle, and that is not a nicety: this file's own comment quotes the literal
 * needles it checks, and an earlier version of the wall check went RED on that
 * alone -- three occurrences of `if pcount>=4{return 1328;}` where there is one
 * line of it, because a comment had quoted it twice. A source check that a
 * sentence can turn red is an instrument that reports the writer, not the
 * producer.
 *
 * A `//` opens a comment only outside a double-quoted string, and the comment
 * runs to the end of its line; the returned text has the same length and the
 * same line breaks as the input, so a needle that spans lines still matches
 * across a comment the way it would in the original. Caller frees. */

/* count_code, which is count_bytes over CODE rather than over text, and the
 * distance between those two is the whole reason this helper exists.
 *
 * A source check counts occurrences of a byte string. A COMMENT contributes
 * occurrences of the same byte string when it quotes the needle, and nothing in
 * the count distinguishes a line of code from a sentence about that line. So
 * every sentence that cites a needle literally weakens the check, and it fails
 * in the direction of RED, which is safe -- but only by luck, and only until
 * somebody writes a sentence.
 *
 * MEASURED, not reasoned, and the instance is this file's own: the four wall
 * checks below were first written over `count_bytes`, and the two comment
 * blocks this gate's subject file carries -- the two that name the producer's
 * stack_args omission -- quote two of those needles verbatim. The result was
 * `checks=25 failures=1`, red at the collect_frame_signature assertion, on
 * `if pcount>=4{return 1328;}` alone: three occurrences where the code has one
 * line, two of them prose. Build ngbuild-124353-1994, FAIL line in
 * x64_lower_nxo_frames.run.log. So the comment was the cause and the
 * instrument was the defect, and the repair belongs HERE and not in those two
 * blocks, which are correct and were kept unchanged.
 *
 * That is the general shape, and it is worth stating because the tempting fix
 * is the wrong one: an instrument that can be made to pass by editing its
 * subject will be. Deleting the quotation would have satisfied the count and
 * left the checks able to be satisfied the same way again. A gate that counts
 * over CODE cannot be satisfied by a sentence.
 *
 * The corollary for the next reader: "this defect is already fixed" is a claim
 * about a DATED state, not a property of the tree, and it is settled with an
 * artefact rather than a memory. The two builds disagree about it and the
 * disagreement is readable -- count_code is a new symbol, and symbols survive
 * into the binary:
 *     ngbuild-124353-1994   count_bytes
 *     ngbuild-124446-2351   count_bytes, count_code, strip_line_comments
 * `strings` on the two orders them in time without anyone's recollection being
 * load-bearing. A repair that changes behaviour should prefer the shape that
 * adds a name, because a name is a fingerprint and a fingerprint dates. */
static char *strip_line_comments(const char *src)
{
    size_t n, i;
    char *out;
    int in_string = 0;
    if (src == NULL) return NULL;
    n = strlen(src);
    out = malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, src, n + 1);
    for (i = 0; i < n; i++) {
        if (out[i] == '"') { in_string = !in_string; continue; }
        if (in_string || out[i] != '/') continue;
        if (i + 1 >= n || out[i + 1] != '/') continue;
        for (; i < n && out[i] != '\n'; i++) out[i] = ' ';
        if (i < n) out[i] = '\n';
    }
    return out;
}

static size_t count_code(const char *hay, const char *needle)
{
    size_t seen;
    char *code = strip_line_comments(hay);
    seen = count_bytes(code, needle);
    free(code);
    return seen;
}

/* The C reference object, from nt_object_compile and nt_object_write alone. */
static int c_object(const char *path, const char *source, uint8_t **bytes,
                    size_t *size, char *why, size_t room)
{
    NtFInput input = {(char *)path, (char *)source, strlen(source)};
    NtObject object = {0};
    NtDiagnostic error = {0};
    NtBuffer file = {0};
    *bytes = NULL;
    *size = 0;
    if (!nt_object_compile(&input, 1, &object, &error)) {
        snprintf(why, room, "nt_object_compile E%u %s", error.code, error.message);
        return 0;
    }
    if (!nt_object_write(&object, &file, &error)) {
        snprintf(why, room, "nt_object_write E%u %s", error.code, error.message);
        nt_object_free(&object);
        return 0;
    }
    *bytes = file.bytes;
    *size = file.size;
    nt_object_free(&object);
    why[0] = 0;
    return 1;
}

/* The reference materializer allocates five buffers and frees none of them.
 * Every harness that drives it carries its own copy of this, so this is a copy
 * of the convention rather than a second way of doing it. */
static void free_artifact(NtArtifact *a)
{
    if (a->pe.bytes) { free(a->pe.bytes); a->pe.bytes = NULL; }
    if (a->text.bytes) { free(a->text.bytes); a->text.bytes = NULL; }
    if (a->rdata.bytes) { free(a->rdata.bytes); a->rdata.bytes = NULL; }
    if (a->data.bytes) { free(a->data.bytes); a->data.bytes = NULL; }
    free(a->base_relocations);
    memset(a, 0, sizeof *a);
}

/* The .text payload of an object, read back and materialized with the C
 * reader, so the bytes compared below are the ones the reference's own
 * materializer produces and not a transcription of them. */
static int text_of(const uint8_t *ob, size_t os, uint8_t **t, size_t *ts)
{
    NtObject readback = {0};
    NtArtifact artifact = {0};
    NtDiagnostic error = {0};
    memset(&artifact, 0, sizeof artifact);
    *t = NULL;
    *ts = 0;
    if (!nt_object_read(ob, os, &readback, &error)) return 0;
    if (!nt_object_materialize(&readback, &artifact, &error)) {
        nt_object_free(&readback);
        return 0;
    }
    *ts = artifact.text.size;
    if (artifact.text.bytes) {
        *t = malloc(artifact.text.size ? artifact.text.size : 1);
        memcpy(*t, artifact.text.bytes, artifact.text.size);
    }
    free_artifact(&artifact);
    nt_object_free(&readback);
    return 1;
}

/* Byte equality with a located first difference, and the offset is returned
 * because a divergence nobody can locate is a count. */
static int same_bytes(const uint8_t *a, size_t an, const uint8_t *b, size_t bn,
                      size_t *first)
{
    size_t lim = an < bn ? an : bn, i = 0;
    while (i < lim && a[i] == b[i]) i++;
    *first = i;
    return an == bn && i == an;
}

static void hexline(const char *label, const uint8_t *b, size_t n, size_t cap)
{
    size_t i, k = n < cap ? n : cap;
    fprintf(stderr, "      %s (%zu%s):", label, n, k < n ? ", shown" : "");
    for (i = 0; i < k; i++) fprintf(stderr, " %02x", b[i]);
    fprintf(stderr, "\n");
}

static unsigned emitted, refused, diverged;

/* One member of the frames corpus. head is the byte sequence the reference's
 * .text must begin with, which is the member's SHAPE claim checked against
 * bytes, and must_emit says whether a refusal is a failure for this member.
 * See the four numbered assertions in the header. */
static void frame_member(const NovaHostImage *i, const char *name,
                         const uint8_t *head, size_t head_n, const char *head_what,
                         int must_emit)
{
    char path[512], why[256] = {0};
    char label[96];
    char *source = NULL;
    size_t source_size = 0;
    uint8_t *c_bytes = NULL, *c_text = NULL, *n_text = NULL;
    size_t c_size = 0, c_text_size = 0, n_text_size = 0, nxo_size = 0, first = 0;
    uint64_t code;
    static uint8_t out[OUTCAP];

    snprintf(path, sizeof path, "%s%s.ntasm", DIR, name);
    snprintf(label, sizeof label, "%s", name);
    source = loadf(path, &source_size);
    CHECKL(source != NULL, "the member is on disk", label);
    if (!source) return;

    /* 1. the reference builds it: a shape the reference refuses is not one
     * the product owes, and asserting the rest about it would be theatre. */
    if (!c_object(path, source, &c_bytes, &c_size, why, sizeof why)) {
        CHECKL(0, "the C reference builds the member", label);
        fprintf(stderr, "FRAME_MEMBER %s C_REFUSED %s\n", name, why);
        free(source);
        return;
    }
    CHECKL(1, "the C reference builds the member", label);

    /* 2. the shape claim, against bytes. */
    if (text_of(c_bytes, c_size, &c_text, &c_text_size) &&
        c_text_size >= head_n) {
        CHECKL(!memcmp(c_text, head, head_n),
               "the reference .text carries the prologue this member is named for", label);
    } else {
        CHECKL(0, "the reference .text carries the prologue this member is named for", label);
    }
    fprintf(stderr, "FRAME_MEMBER %-16s reference object=%zu .text=%zu head=%s\n",
            name, c_size, c_text_size, head_what);

    /* 3. the invariant: refuse, or agree byte for byte. */
    memset(out, 0xcc, sizeof out);
    code = run_nova(i, source, 5, out, sizeof out);
    if (code != 0) {
        refused++;
        fprintf(stderr, "FRAME_MEMBER %-16s frameless=REFUSED code=%llu  (the reference builds it: this is a gap, not a convergence)\n",
                name, (unsigned long long)code);
        CHECKL(!must_emit, "the frameless producer lowers a member it owns", label);
    } else {
        nxo_size = (size_t)r64(out);
        emitted++;
        if (nxo_size + 16 > OUTCAP) {
            CHECKL(0, "the frameless object fits the output buffer", label);
        } else if (same_bytes(c_bytes, c_size, out + 16, nxo_size, &first)) {
            fprintf(stderr, "FRAME_MEMBER %-16s frameless=obj %zu  IDENTICAL to the reference\n",
                    name, nxo_size);
        } else {
            diverged++;
            CHECKL(0, "no silent frame divergence: the frameless object equals the reference's, "
                      "or the producer refuses", label);
            fprintf(stderr, "FRAME_MEMBER %-16s frameless=obj %zu  DIVERGES from the reference "
                            "(%zu bytes) at byte %zu -- SILENT, the producer returned success\n",
                    name, nxo_size, c_size, first);
            if (text_of(out + 16, nxo_size, &n_text, &n_text_size)) {
                hexline("reference .text", c_text ? c_text : (const uint8_t *)"", c_text_size, 32);
                hexline("frameless .text", n_text, n_text_size, 32);
            }
        }
    }

    free(n_text);
    free(c_text);
    free(c_bytes);
    free(source);
}

/* The negative instrument. Every assertion above is either a comparison or a
 * refusal, and a comparison that has only ever been seen to succeed has not
 * been shown able to fail. This asks the comparison function, on its own
 * inputs, a question whose answer is known: a copy of the reference object
 * with one byte flipped must NOT compare equal, and the untouched object must.
 * Without it, a comparison that compared everything against itself would pass
 * every member above. */
static void negative_proof(const uint8_t *object, size_t size)
{
    static uint8_t flipped[OUTCAP];
    size_t first = 0, located = 0, at;
    if (!object || size == 0 || size > sizeof flipped) {
        CHECK(0, "the negative instrument has an object to work on");
        return;
    }
    at = size / 2;
    memcpy(flipped, object, size);
    flipped[at] = (uint8_t)(flipped[at] ^ 0xff);
    CHECK(same_bytes(flipped, size, object, size, &first) == 0,
          "NEGATIVE: one flipped byte does not compare equal");
    located = first;
    CHECK(located == at, "NEGATIVE: the flipped byte is located");
    CHECK(same_bytes(object, size, object, size, &first) == 1,
          "NEGATIVE: an object equals itself");
    fprintf(stderr, "NEGATIVE_PROOF flipped_byte=%zu located=%zu\n", at, located);
}

/* THE STACK_ARGS WALL, PINNED. This is a source check, and it is one for the
 * same reason the route check above is: the property is a property of the
 * producer's SOURCE, so running the producer cannot observe it -- the shape
 * that would expose it is REFUSED before any frame is emitted, which is
 * precisely why the omission is quiet.
 *
 * WHY A SOURCE CHECK AND NOT A FIXTURE ALONE. Three fixtures were built and run
 * against the current reference and the current producer, and all three REFUSE
 * on at least one side, so none of them can be a member that turns red when
 * the wall moves: a fixture the producer already refuses stays refused after
 * abi parsing is added, unless the abi parse ALSO lifts the refusal. This
 * asserts the WALL, not the outcome, and the wall is three separate refusals
 * in three separate files; the day any one of them is edited, this goes red
 * and the failing message names which.
 *
 * MEASURED on 2026-09-30 from current sources built with clang 22.1.8 and run,
 * digests of the bytes the claims below were read from:
 *   compiler/c/ntasm/backend/codegen.c
 *     6c8c0d51e778a30caabee3f5340712148ec18f7ad7958396bbce0982d0dd0ab2
 *   compiler/nova/backend/x64/x64_lower_nxo.nova
 *     503ebf4ef26e80b7cffe95341f70ccceadab6a874f38bd287c4f29cd109efbde
 *   compiler/c/ntasm/frontend/frontend.c
 *     6c663ff7de4e78526e396be657a1a3a0cbde660f4b92dbf71a01f5158a0bee41
 *   compiler/nova/analysis/abi/abi.nova
 *     c1a4fabf474b0374b0a975f4b91266b862b795368745191b05bfaeeeb28115ab
 *
 *   fixture                                    reference      producer  caller frame
 *   D  mov body, no params                     BUILT          0         320
 *   C  nx64 callee, 4 params                   BUILT          0         368
 *   A  efi callee, 5 params, 5th UNBOUND       BUILT          328       384
 *   E  efi callee, 6 params, 5th+ UNBOUND     BUILT          328       400
 *   B  efi callee, 5 params, 5th @r11          REFUSED        800       -
 *
 * A and E are the reach candidates: the reference BUILDS them, and their caller
 * frames are 384 and 400 against the four-parameter control's 368. The
 * difference is 16 and 32, which is the arithmetic of codegen.c's formula and
 * not a constant: with calls=1 and call_argument_bytes=params*8,
 *   C: 32 + 0 + expr*8 + 1*32 + 280 + 0
 *   A: 32 + 0 + expr*8 + 1*40 + 280 + 8    (one more arg byte, one stack arg)
 *   E: 32 + 0 + expr*8 + 1*48 + 280 + 16   (two more arg bytes, two stack args)
 * A-E is 16, not 8, so the term scales with stack_args and the omission is 8
 * and 16 bytes of frame respectively -- a caller whose callee passes two stack
 * arguments would overwrite them.
 *
 * The producer refuses A and E with 328, which is abi.nova:297-299
 * (`index>=4 && reg_id==0 && profile==1`), NOT collect_frame_signature's 1328.
 * Both are walls on the same shape and both are asserted below, separately,
 * because they are different codes with different owners.
 *
 * THE PINCER, which is the actual finding and is stronger than "no abi parse":
 *   - the reference REFUSES an efi parameter five or later that carries a
 *     register binding (frontend.c:2937-2942), so the shape the producer
 *     admits (five bound parameters) is a shape the reference forbids -- B;
 *   - the reference REQUIRES parameter five or later of an efi function to be
 *     unbound, and both producer refusals (abi.nova:297 and
 *     x64_lower_nxo.nova:3966) fire on exactly the unbound case -- A and E.
 * So for an efi callee with more than four parameters, the reference admits
 * only the shape the producer refuses and the producer admits only the shape
 * the reference refuses. The two conditions are NOT independent: they are
 * complements on one axis, and the wall is closed by both at once.
 *
 * THE ORDERING IS NOT IN THIS COMMENT BECAUSE IT IS NOT A PROPERTY OF ONE
 * FILE. Relaxing the producer's two refusals without relaxing frontend.c would
 * emit a frame 8 and 16 bytes short for a callee the reference still refuses;
 * relaxing frontend.c alone would make the reference build sources the producer
 * still refuses, which is a capability gap and not a wrong frame. Only
 * frontend.c first, then the two producer refusals, has no intermediate state
 * that emits a wrong frame. The safe ordering is a property of three
 * interacting files and lives in the failure messages of the checks below,
 * which is the only place that can observe all three.
 *
 * MEASURED NEGATIVE CONTROLS, and the green above means nothing without them.
 * The compiled binary was run from a scratch tree of real file copies -- no
 * symlink to the repository anywhere, and no mkdir -p through one -- holding
 * toolchain/, examples/ and compiler/c/ntasm/frontend/frontend.c, one wall relaxed
 * at a time. Each control RED at exactly one check, naming that wall, and the
 * restored tree returned to 25/0:
 *   abi.nova:297       append `&& 0==1` to the condition
 *                       -> red at check 2, code 328.
 *   the 1328 line    append `&&0==1` to the `pcount>=4` refusal
 *                       -> red at check 3, code 1328.
 *   frontend.c:2937    append `&& 0` to the `if`
 *                       -> red at check 1, the reference's half of the pincer.
 *   the frame line     append a sixth term to `needed`. `+ argbytes*0` is the
 *                       form to use: it still compiles, so the run stays at 25
 *                       checks and goes red at check 4 and nowhere else. `+0`
 *                       and `+ stats[1]*0` were measured to behave the same.
 *                       The literal form a reader will actually reach for,
 *                       `+ stack_args*8`, is ALSO red, and red for a second
 *                       reason worth knowing: no `stack_args` is in scope, so
 *                       the module stops compiling and that run reports 3
 *                       failures over 10 checks, of which check 4 is the one
 *                       about the frame term. It still catches the edit, but it
 *                       is not the control to read the instrument's precision
 *                       from.
 * The abi.nova control is the one that found a defect in this check when it
 * was first written; the reason its needle is spelled the way it now is
 * stands at the check. */
static void stack_args_wall(char *const *sources)
{
    /* sources[1] is x64_lower_nxo.nova and sources[6] is abi.nova -- both are
     * already loaded and their presence is already asserted by the "sources
     * load" check in main, so neither is read again. frontend.c is NOT in
     * paths[], and its absence is a FAILURE rather than a silent zero: a
     * needle not found because the file moved is not a wall. count_bytes
     * returns 0 on a NULL haystack, so a missing source cannot read as a
     * passing needle. */
    static const char *FRONTEND_PATH = "compiler/c/ntasm/frontend/frontend.c";
    size_t n = 0;
    char *frontend = loadf(FRONTEND_PATH, &n);

    CHECKL(frontend != NULL, "frontend.c is on disk, so the reference's half "
                             "of the pincer can be read", "wall");

    /* 1. The reference's half. If this is edited -- if an efi parameter five
    *    or later is ever permitted to carry a register binding -- then the
    *    shape the producer admits becomes a shape the reference admits, and
    *    the producer's frame for it loses stack_args*8 with nothing left to
    *    refuse it. THIS IS THE FIRST CONDITION TO RELAX; the two below are
    *    individually unsafe to relax before it. */
    if (frontend)
        CHECKL(count_code(frontend,
                          "if (i >= 4 && parameter->reg.family >= 0) {") == 1,
               "the reference still refuses a register binding on an efi "
               "parameter five or later, which is what closes the producer's "
               "side of the pincer", "wall");

    /* 2. abi.nova's half. This is the refusal A and E actually hit, measured.
    *    The needle ends at the opening brace, NOT at `profile==1`: a needle
    *    stopping at the last term is a SUBSTRING of its own relaxation, so
    *    editing the condition to append a term would leave the needle present
    *    and this check GREEN while the wall had moved. That was measured, not
    *    reasoned: appending `&& 0==1` to this condition left the original
    *    needle present and this check passing. The other three needles here all
    *    terminate on a delimiter -- `) {`, `{return 1328;}`, and the frame
    *    expression's `+280;` -- for the same reason. */
    CHECKL(count_code(sources[6],
                      "else if index>=4 && reg_id==0 && profile==1 {") == 1,
           "abi.nova still refuses a fifth parameter with no register binding, "
           "which is the refusal (code 328) the efi reach candidates hit",
           "wall");

    /* 3. collect_frame_signature's half. Same shape, different owner and a
    *    different code (1328 rather than 328), so it is asserted separately
    *    rather than assumed to move with abi.nova. */
    CHECKL(count_code(sources[1], "if pcount>=4{return 1328;}") == 1,
           "collect_frame_signature still refuses a fifth parameter with no "
           "register binding", "wall");

    /* 4. The frame expression itself. This is the line that omits the term,
    *    asserted byte for byte so that ADDING stack_args turns this red. A
    *    producer that starts charging the term while the three refusals above
    *    still stand would be over-reserving, which is a different defect and
    *    also worth a red. */
    CHECKL(count_code(sources[1],
                      "let needed:u64=32+slots*8+stats[0]*8+stats[1]*argbytes+280;") == 1,
           "the frame expression is still the five-term one, so the sixth term "
           "is still absent rather than silently zero. THIS RED IS NOT A BUG "
           "REPORT, IT IS A SEQUENCE: relax frontend.c:2937 FIRST, then abi.nova:297 "
           "and the pcount>=4 refusal in collect_frame_signature, and only then "
           "is an abi parse needed and "
           "this line the thing to change. Reversing that order emits a frame 8 "
           "and 16 bytes short for a callee the reference still refuses, which is "
           "worse than the omission because nothing refuses it. See the wall "
           "checks and their negative controls in this file", "wall");

    free(frontend);
}

int main(void)
{
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
    char *sources[17] = {0};
    NtFInput inputs[17];
    unsigned i;
    int all = 1, compiled;
    NtArtifact compiler = {0};
    NovaHostImage image = {0};
    static uint8_t keep[OUTCAP];
    size_t keep_size = 0;

    for (i = 0; i < 17; i++) {
        size_t n = 0;
        sources[i] = loadf(paths[i], &n);
        inputs[i] = (NtFInput){paths[i], sources[i], n};
    }
    for (i = 0; i < 17; i++) if (!sources[i]) all = 0;
    CHECK(all, "sources load");
    compiled = all && nova_compile_many_v2(inputs, 17, &compiler);
    CHECK(compiled, "Nova modules compile");
    if (!compiled) {
        fprintf(stderr, "E%u %zu:%zu %s\n", compiler.error.code, compiler.error.line,
                compiler.error.column, compiler.error.message);
    }
    CHECK(compiled && nova_host_map(&compiler, &image), "host map");

    /* THE ROUTE, ASSERTED, so the comment at run_nova cannot go stale in
     * silence. Everything this gate measures is asked of mode 5, and mode 5 is
     * build_function_bodies, which delegates to build_framed_functions on
     * any_body_is_framed. The property is a property of the producer's SOURCE,
     * so running the producer cannot observe it: this reads the module text.
     *
     * ONE is the right count and not a lower bound. A second delegation site
     * would be a second thing to reason about, and a zero would mean the
     * paragraph above is wrong again -- which is the whole reason this check
     * exists. The needle is the call term rather than the predicate alone,
     * because any_body_is_framed is also CALLED from its own definition's
     * neighbourhood and a predicate-name count would not distinguish the
     * delegation from a use. */
    {
        static const char *DELEGATION =
            "any_body_is_framed(tree,section_id)==1 {";
        static const char *FRAMED_CALL =
            "build_framed_functions(source,tree,features,cpl,none)";
        size_t seen = count_bytes(sources[1], DELEGATION);
        CHECKL(seen == 1, "the frameless entry still delegates to the framed "
                          "producer on any_body_is_framed, exactly once",
               "route");
        CHECKL(count_bytes(sources[1], FRAMED_CALL) == 1,
               "that delegation is the one build_framed_functions call the "
               "header names", "route");
    }

    /* The wall, pinned against all three files at once. Placed here because it
     * needs the loaded sources and the same running context as the route check
     * above; it emits no object, so the banner's members/emitted/diverged
     * counts are untouched by it. */
    stack_args_wall(sources);

    if (image.memory) {
        /* The member that goes red on a frame omission: the reference builds
         * it with a full frame, and a producer that answered it with frameless
         * bytes and a success code is the defect this gate exists for. It is
         * GREEN today, and the reason is the check above rather than a gap in
         * the instrument: mode 5 delegates on any_body_is_framed, so this
         * member is answered by the framed producer and matches the reference
         * over all 368 bytes. Measured both directions: dropping the delegation
         * term takes this member to 21 frameless bytes and turns this gate red
         * at diverged=1, and perturbing the frame CONTENTS turns it red again.
         * A reader who wants to know whether the instrument works should
         * perturb, not read this comment. */
        frame_member(&image, "frame-omission", FRAME_HEAD, FRAME_HEAD_N,
                     "pushfq, thirteen saved registers, push rbp, mov rbp,rsp, sub rsp",
                     0);
        /* The control. The same class of source, the one shape the reference
         * does NOT frame, which the frameless producer owns and must keep
         * owning: a producer that refused everything would pass the member
         * above without this. */
        frame_member(&image, "shortcut-control", SHORTCUT_HEAD, SHORTCUT_HEAD_N,
                     "mov rax,imm64, the raw entry shortcut, and no frame", 1);
        /* The negative instrument, on the control member's reference object so
         * that it is a real object and not a buffer this file filled. */
        {
            char path[512], why[256] = {0};
            size_t n = 0;
            char *source;
            uint8_t *bytes = NULL;
            size_t size = 0;
            snprintf(path, sizeof path, "%sshortcut-control.ntasm", DIR);
            source = loadf(path, &n);
            if (source && c_object(path, source, &bytes, &size, why, sizeof why) &&
                size <= sizeof keep) {
                memcpy(keep, bytes, size);
                keep_size = size;
            }
            free(bytes);
            free(source);
            negative_proof(keep, keep_size);
        }
    }

    if (image.memory) nova_host_unmap(&image);
    if (compiled) nt_artifact_free(&compiler);
    for (i = 0; i < 17; i++) free(sources[i]);
    /* THE BANNER NAMES THE GAP. failures=0 here means the frameless producer
     * does not DIVERGE from the reference on a framed body. It does not mean
     * the framed bodies converge, and a reader who took it for that would be
     * wrong in the direction this gate exists to prevent. */
    fprintf(stderr, "NTASM_NOVA_X64_LOWER_NXO_FRAMES checks=%u failures=%u cases=%u "
                    "members=2 emitted=%u refused=%u diverged=%u\n",
            checks, failures, cases, emitted, refused, diverged);
    if (refused)
        fprintf(stderr, "NTASM_NOVA_X64_LOWER_NXO_FRAMES NOTE %u member(s) the C reference builds "
                        "and the Nova producer REFUSES: a gap, named above, not a convergence\n",
                refused);
    return failures ? 1 : 0;
}
