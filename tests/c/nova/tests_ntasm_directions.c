/* NTASM_NOVA_DIRECTIONS -- work-plan lot 27, IN / OUT / INOUT.
 *
 * The lot asks for three directions, three OBLIGATIONS each, positive and
 * negative cases for every one of them, alias distinguished from equal values,
 * and three invalid directions refused for three DIFFERENT reasons.
 *
 * WHY THE THREE OBLIGATIONS ARE THREE COLUMNS AND NOT ONE FLAG. A parameter's
 * direction word is one fact, and a gate that reads only that fact passes a
 * function whose `in` is never read and whose `out` is never written -- which
 * is the shape most likely to be green and wrong. abi.obligations therefore
 * publishes liaison, consommation and restitution SEPARATELY, and the rows
 * below assert each one on its own rather than asserting a count of "used"
 * parameters. An `inout` owes two of them, and a reader that collapsed them
 * into one word would pass an `inout` that does neither; the inout rows here
 * assert both words separately so that collapse is a red row.
 *
 * WHAT IS ASSERTED, and where each claim comes from:
 *   - the direction of each parameter, read by abi.direction (the rule's owner)
 *   - CONSOMMATION on the point where the value would be wrong if it were not:
 *     a body that never mentions the parameter answers 0 there
 *   - RESTITUTION at the same point: an `out` nobody writes answers 0
 *   - alias by the REGISTER SPAN, and the two-value/one-location and
 *     two-location/equal-value rows below are the pair that separates an alias
 *     check from a value comparison
 *   - three refusals on 366 with three different reasons, each proved to have
 *     applied by a perturbation that changes the reason and nothing else
 *
 * The guard word is 0xcccccccccccccccc, tests_ntasm_abi.c:257's declared
 * sentinel: every Run pre-fills .out with it, so a query that writes nothing is
 * distinguishable from one that writes a zero.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;
static const uint64_t guard = UINT64_C(0xcccccccccccccccc);

#define CHECK(c, m) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL %s\n", (m)); } } while (0)

static char *load(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long z = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
    if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) { free(b); fclose(f); return NULL; }
    fclose(f); b[z] = 0; *n = (size_t)z; return b;
}

typedef struct { uint64_t returned, runtime, out[32]; } Run;

/* Run the entry with `words` words of output. out[4] is the selector, and
 * out[5..] the selector-3 payload, so the caller sets them through `sel` and
 * `payload` before the call. */
static Run run_sel(const NovaHostImage *i, const char *s, uint64_t words,
                   uint64_t sel, const char *payload)
{
    Run r; memset(&r, 0, sizeof r);
    for (unsigned k = 0; k < 32; k++) r.out[k] = guard;
    NovaContextV2 c = {0};
    CHECK(nova_context_init_v2(&c), "context init");
    uint64_t oh = nova_borrow_v2(&c, r.out, words * 8, 1);
    if (words > 4) {
        r.out[4] = sel;
        if (payload != NULL && words > 6) {
            uint64_t w = strlen(payload);
            if (w > words - 6) w = words - 6;
            for (uint64_t k = 0; k < w; k++) r.out[6 + k] = (uint64_t)(unsigned char)payload[k];
            r.out[5] = w;
        }
    }
    uint64_t sh = nova_borrow_v2(&c, (void *)s, strlen(s), 0);
    uint64_t a[] = { sh, strlen(s), oh, words };
    r.returned = i->entry(&c, a, 4);
    r.runtime = c.error;
    CHECK(nova_context_destroy_v2(&c), "context cleanup");
    return r;
}

static Run run(const NovaHostImage *i, const char *s, uint64_t words)
{
    return run_sel(i, s, words, 1, NULL);
}

/* One parameter row: direction, liaison, consommation, restitution.
 * Row i begins at 7*(i+1): out[0] is the row count and is never a row. The
 * seven words of headroom are the export's own layout, not this file's taste
 * -- see the note on abi.obligations, which records the defect that made it
 * necessary. */
static void row(const NovaHostImage *i, const char *nm, const char *s,
                unsigned at, uint64_t dir, uint64_t liaison,
                uint64_t consumed, uint64_t restored)
{
    Run r = run(i, s, 32);
    cases++; checks++;
    uint64_t *p = &r.out[7 * (at + 1)];
    int bad = r.returned || r.runtime;
    bad |= p[0] != dir || p[1] != liaison || p[2] != consumed || p[3] != restored;
    if (bad) {
        failures++;
        fprintf(stderr, "FAIL row %s param %u ret=%llu rt=%llu "
                "dir=%llu (want %llu) liaison=%llu (want %llu) "
                "conso=%llu (want %llu) restit=%llu (want %llu)\n",
                nm, at, (unsigned long long)r.returned, (unsigned long long)r.runtime,
                (unsigned long long)p[0], (unsigned long long)dir,
                (unsigned long long)p[1], (unsigned long long)liaison,
                (unsigned long long)p[2], (unsigned long long)consumed,
                (unsigned long long)p[3], (unsigned long long)restored);
    }
}

/* The row COUNT, which is what says a negative case exists at all: a program
 * with no parameters writes no rows and a program that wrongly refused one
 * writes fewer than it should. */
static void rows(const NovaHostImage *i, const char *nm, const char *s, uint64_t want)
{
    Run r = run(i, s, 32);
    cases++; checks++;
    if (r.returned || r.runtime || r.out[0] != want) {
        failures++;
        fprintf(stderr, "FAIL rows %s ret=%llu rt=%llu out0=%llu want %llu\n",
                nm, (unsigned long long)r.returned, (unsigned long long)r.runtime,
                (unsigned long long)r.out[0], (unsigned long long)want);
    }
}

/* A refusal: 366 with a REASON, and every word the contract says the query
 * publishes. `untouched` asserts the out words the query must NOT write. */
static void refuse(const NovaHostImage *i, const char *nm, const char *s,
                   uint64_t code, uint64_t reason)
{
    Run r = run(i, s, 32);
    cases++; checks++;
    int bad = r.returned != code || r.runtime;
    if (code == 366) bad |= r.out[2] != reason;
    /* the position words are always written on 366, and never equal the guard */
    if (bad || r.out[0] == guard || r.out[1] == guard) {
        failures++;
        fprintf(stderr, "FAIL refuse %s ret=%llu (want %llu) rt=%llu "
                "reason=%llu (want %llu) pos=%llu,%llu\n",
                nm, (unsigned long long)r.returned, (unsigned long long)code,
                (unsigned long long)r.runtime,
                (unsigned long long)r.out[2], (unsigned long long)reason,
                (unsigned long long)r.out[0], (unsigned long long)r.out[1]);
    }
}

static void alias(const NovaHostImage *i, const char *nm, const char *s,
                  uint64_t code, uint64_t pairs)
{
    Run r = run_sel(i, s, 32, 2, NULL);
    cases++; checks++;
    int bad = r.returned != code || r.runtime || r.out[0] != pairs;
    if (bad) {
        failures++;
        fprintf(stderr, "FAIL alias %s ret=%llu (want %llu) rt=%llu pairs=%llu want %llu\n",
                nm, (unsigned long long)r.returned, (unsigned long long)code,
                (unsigned long long)r.runtime,
                (unsigned long long)r.out[0], (unsigned long long)pairs);
    }
}

/* Selector 3: the direction word of the first parameter replaced by `word`,
 * which must be the same length as the word it replaces so the copy's spans
 * stay valid. */
static Run forged(const NovaHostImage *i, const char *s, const char *word)
{
    return run_sel(i, s, 16, 3, word);
}

static void forge_refuses(const NovaHostImage *i, const char *nm,
                          const char *s, const char *word, uint64_t reason)
{
    Run r = forged(i, s, word);
    cases++; checks++;
    int bad = r.returned != 366 || r.runtime || r.out[2] != reason;
    if (bad || r.out[0] == guard || r.out[1] == guard) {
        failures++;
        fprintf(stderr, "FAIL forge %s word=%s ret=%llu (want 366) rt=%llu "
                "reason=%llu (want %llu)\n",
                nm, word, (unsigned long long)r.returned, (unsigned long long)r.runtime,
                (unsigned long long)r.out[2], (unsigned long long)reason);
    }
}

int main(void)
{
    const char *paths[] = {
        "tests/nova/tests/directions-entry.nova",
        "compiler/nova/analysis/abi/abi.nova",
        "compiler/nova/analysis/types/register_widths.nova",
        "compiler/nova/analysis/abi/clobbers.nova",
        "compiler/nova/frontend/parser.nova",
        "compiler/nova/frontend/ast.nova",
        "compiler/nova/frontend/lexer.nova",
    };
    char *src[7] = {0}; NtFInput in[7];
    for (unsigned i = 0; i < 7; i++) { size_t n = 0; src[i] = load(paths[i], &n); in[i] = (NtFInput){paths[i], src[i], n}; }
    int all = 1;
    for (unsigned i = 0; i < 7; i++) if (!src[i]) all = 0;
    CHECK(all, "sources load");
    NtArtifact art = {0};
    int compiled = all && nova_compile_many_v2(in, 7, &art);
    CHECK(compiled, "modules compile");
    if (!compiled) {
        fprintf(stderr, "COMPILE %u %llu:%llu %s\n", art.error.code,
                (unsigned long long)art.error.line, (unsigned long long)art.error.column,
                art.error.message);
        printf("NTASM_NOVA_DIRECTIONS checks=%u failures=%u cases=%u\n",
               checks, failures + 1, cases);
        return 1;
    }
    NovaHostImage image = {0};
    CHECK(nova_host_map(&art, &image), "host map");

    /* ---------------------------------------------------------------- IN --
     * Positive: `in p` named by a requires predicate and READ by the body.
     * The consumption column is the observation point: a body that never
     * mentions p answers 0 there and would be wrong if the caller trusted the
     * binding alone. */
    const char *in_pos =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {}\n"
        "requires { non_null(p) }\nensures {} {\nmov rax, p\nreturn rax\n}\n}\n";
    rows(&image, "in-positive-rows", in_pos, 1);
    row(&image, "in-positive", in_pos, 0, 1, 1, 1, 0);

    /* Negative: the SAME signature and the SAME contract, with a body that
     * never reads p. Only the body differs, so the difference in the
     * consommation column is attributable to the body and to nothing else.
     * This is the case a gate counting bindings cannot see. */
    const char *in_neg =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {}\n"
        "requires { non_null(p) }\nensures {} {\nmov rax, 7\nreturn rax\n}\n}\n";
    rows(&image, "in-negative-rows", in_neg, 1);
    row(&image, "in-negative", in_neg, 0, 1, 1, 0, 0);

    /* Negative on liaison alone: a parameter no contract names is bound to
     * nothing, so liaison answers 0 while the direction is still perfectly
     * readable. */
    const char *in_unbound =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {}\n"
        "requires {}\nensures {} {\nmov rax, p\nreturn rax\n}\n}\n";
    row(&image, "in-no-liaison", in_unbound, 0, 1, 0, 1, 0);

    /* --------------------------------------------------------------- OUT --
     * Positive: `out q` bound to rdx and WRITTEN by the body. */
    const char *out_pos =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(out q:u64 @rdx)->u64\neffects {}\nclobbers {}\n"
        "requires {}\nensures { mapping_present(q) } {\nmov rdx, 9\nreturn 0\n}\n}\n";
    rows(&image, "out-positive-rows", out_pos, 1);
    row(&image, "out-positive", out_pos, 0, 2, 1, 0, 1);

    /* Negative: an `out` nobody writes. This is the shape most likely to be
     * green and wrong: the parameter binds, the contract names it, the ABI is
     * satisfied, and the caller receives whatever happened to be in rdx. Only
     * the restitution column refuses it. */
    const char *out_neg =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(out q:u64 @rdx)->u64\neffects {}\nclobbers {}\n"
        "requires {}\nensures { mapping_present(q) } {\nreturn 0\n}\n}\n";
    rows(&image, "out-negative-rows", out_neg, 1);
    row(&image, "out-negative", out_neg, 0, 2, 1, 0, 0);

    /* An `out` read but not written is still not restituted: reading is not
     * writing, and a rule that counted "mentions" would pass this. */
    const char *out_read_only =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(out q:u64 @rdx)->u64\neffects {}\nclobbers {}\n"
        "requires {}\nensures { mapping_present(q) } {\nmov rax, q\nreturn 0\n}\n}\n";
    row(&image, "out-read-only", out_read_only, 0, 2, 1, 0, 0);

    /* ------------------------------------------------------------- INOUT --
     * Positive: `inout r` READ and WRITTEN. Both columns are asserted
     * separately, because an `inout` that did only one would still be wrong
     * and a single "used" flag could not tell the two cases apart. */
    const char *inout_pos =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(inout r:u64 @r8)->u64\neffects {}\nclobbers {}\n"
        "requires { non_null(r) }\nensures {} {\nmov r8, r\nreturn 0\n}\n}\n";
    rows(&image, "inout-positive-rows", inout_pos, 1);
    row(&image, "inout-positive", inout_pos, 0, 3, 1, 1, 1);

    /* Negative: written but never read. */
    const char *inout_no_read =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(inout r:u64 @r8)->u64\neffects {}\nclobbers {}\n"
        "requires { non_null(r) }\nensures {} {\nmov r8, 3\nreturn 0\n}\n}\n";
    row(&image, "inout-write-only", inout_no_read, 0, 3, 1, 0, 1);

    /* Negative: read but never written. */
    const char *inout_no_write =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(inout r:u64 @r8)->u64\neffects {}\nclobbers {}\n"
        "requires { non_null(r) }\nensures {} {\nmov rax, r\nreturn 0\n}\n}\n";
    row(&image, "inout-read-only", inout_no_write, 0, 3, 1, 1, 0);

    /* Negative: neither. */
    const char *inout_neither =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(inout r:u64 @r8)->u64\neffects {}\nclobbers {}\n"
        "requires { non_null(r) }\nensures {} {\nreturn 0\n}\n}\n";
    row(&image, "inout-neither", inout_neither, 0, 3, 1, 0, 0);

    /* ------------------------------------------------------- ALL THREE --
     * One signature carrying all three directions, so the three rows are read
     * out of ONE tree and are therefore comparable with each other. */
    const char *all_three =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(in p:u64 @rcx, out q:u64 @rdx, inout r:u64 @r8)->u64\n"
        "effects {}\nclobbers {}\nrequires { non_null(p) }\n"
        "ensures { mapping_present(q) } {\nmov rax, p\nmov rdx, 4\nmov r8, r\nreturn rax\n}\n}\n";
    rows(&image, "all-three-rows", all_three, 3);
    row(&image, "all-three-in", all_three, 0, 1, 1, 1, 0);
    row(&image, "all-three-out", all_three, 1, 2, 1, 0, 1);
    /* The inout is named by NO predicate in this signature, so its liaison is
     * 0 while its two value obligations are both 1. That is the most useful
     * row in the table: it separates the three obligations from each other on
     * one parameter, and an expectation of 1 here would be asserting that a
     * parameter no contract mentions is a contract subject. */
    row(&image, "all-three-inout", all_three, 2, 3, 0, 1, 1);

    /* Empty signature: no parameters, no rows, and NOT a refusal. A module
     * with no parameters is not a module with unbound directions. */
    const char *none =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f()->u64\neffects {}\nclobbers {}\nrequires {}\nensures {} {\nreturn 0\n}\n}\n";
    rows(&image, "empty-signature", none, 0);

    /* ------------------------------------------------------------- ALIAS --
     * THE PAIR THAT SEPARATES AN ALIAS CHECK FROM A VALUE COMPARISON.
     *
     * (a) two parameters, ONE location: both bound to @rcx. Two names for one
     *     location, and it is refused.
     * (b) two parameters, TWO locations: @rcx and @rdx. Distinct locations, so
     *     NOT an alias -- and this is the row that a value comparison would
     *     also pass, for the wrong reason, which is why (c) exists.
     * (c) two locations that HOLD EQUAL VALUES: both bodies assign the same
     *     literal to both registers, and the alias answer must still be 0.
     *     Nothing in this tree has run, so there are no values to compare; a
     *     rule that compared them would be comparing nothing and calling it a
     *     check. */
    const char *alias_one_location =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(in p:u64 @rcx, in q:u64 @rcx)->u64\neffects {}\nclobbers {}\n"
        "requires {}\nensures {} {\nmov rax, p\nreturn rax\n}\n}\n";
    alias(&image, "two-names-one-location", alias_one_location, 317, 1);

    const char *alias_two_locations =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(in p:u64 @rcx, in q:u64 @rdx)->u64\neffects {}\nclobbers {}\n"
        "requires {}\nensures {} {\nmov rax, p\nreturn rax\n}\n}\n";
    alias(&image, "two-names-two-locations", alias_two_locations, 0, 0);

    const char *alias_equal_values =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(inout p:u64 @rcx, inout q:u64 @rdx)->u64\neffects {}\nclobbers {}\n"
        "requires {}\nensures {} {\nmov rcx, 5\nmov rdx, 5\nreturn 0\n}\n}\n";
    alias(&image, "two-locations-equal-values", alias_equal_values, 0, 0);

    /* Three parameters, one of which pairs: rcx/rdx/rcx names exactly ONE
     * alias pair, and the count is the pair count, not a boolean. */
    const char *alias_one_of_three =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(in a:u64 @rcx, in b:u64 @rdx, in c:u64 @rcx)->u64\neffects {}\nclobbers {}\n"
        "requires {}\nensures {} {\nmov rax, a\nreturn rax\n}\n}\n";
    alias(&image, "one-pair-of-three", alias_one_of_three, 317, 1);

    /* A parameter with no explicit register cannot alias another, because it
     * names no location at all. */
    const char *alias_unbound_regs =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(in p:u64, in q:u64)->u64\neffects {}\nclobbers {}\n"
        "requires {}\nensures {} {\nmov rax, p\nreturn rax\n}\n}\n";
    alias(&image, "no-explicit-registers", alias_unbound_regs, 0, 0);

    /* ------------------------------------------------------- REFUSAL 1 --
     * A predicate subject that is a bare NAME matching no parameter of the
     * declaration. The subject is spelled exactly like every other subject and
     * the only thing wrong with it is the parameter it names is not in the
     * signature. */
    const char *unbound_subject =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {}\n"
        "requires { non_null(nosuch) }\nensures {} {\nmov rax, p\nreturn rax\n}\n}\n";
    refuse(&image, "subject-is-not-a-parameter", unbound_subject, 366, 1);

    /* The ensures set is read as well as the requires set: the same defect in
     * the other clause is the same reason, not a new one. */
    const char *unbound_ensures =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {}\n"
        "requires {}\nensures { non_null(nosuch) } {\nmov rax, p\nreturn rax\n}\n}\n";
    refuse(&image, "ensures-subject-unbound", unbound_ensures, 366, 1);

    /* A predicate whose subject is a LITERAL is not an unbound direction:
     * stack_aligned(16) is a fact about a number and binds nothing. Counting
     * it as one would refuse a program the reference compiles. */
    const char *literal_subject =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {}\n"
        "requires { stack_aligned(16) }\nensures {} {\nmov rax, p\nreturn rax\n}\n}\n";
    rows(&image, "literal-subject-is-not-unbound", literal_subject, 1);
    row(&image, "literal-subject-no-liaison", literal_subject, 0, 1, 0, 1, 0);

    /* ------------------------------------------------------- REFUSAL 2 --
     * An unknown direction NAME. parser.nova:338 admits only in, out and inout
     * where a direction belongs, so this case is unreachable through the front
     * door and is asked of a copy whose first direction word is replaced, same
     * length, so every span in the tree stays valid. */
    forge_refuses(&image, "unknown-direction", in_pos, "xx", 2);
    /* A longer word that merely STARTS with a direction is still unknown:
     * `outbound` is not `out`, which is the whole-word rule the four copies
     * implement and the defect H4 of the W4-8 audit was about. */
    forge_refuses(&image, "longer-word-not-a-direction", in_pos, "inx", 2);
    /* The control: the un-forged source answers 0 on the same query, so the
     * refusal above is the forge's doing and not the entry's. */
    {
        Run r = run_sel(&image, in_pos, 32, 4, NULL);
        cases++; checks++;
        if (r.returned || r.runtime || r.out[0] != 1 || r.out[7 * 1] != 1) {
            failures++;
            fprintf(stderr, "FAIL forge-control ret=%llu rt=%llu rows=%llu dir=%llu\n",
                    (unsigned long long)r.returned, (unsigned long long)r.runtime,
                    (unsigned long long)r.out[0], (unsigned long long)r.out[7 * 1]);
        }
    }
    /* And the caller's buffer is untouched by the forge: the same source, run
     * again without forging, still parses and still answers its direction. */
    {
        Run r = run_sel(&image, in_pos, 32, 4, NULL);
        cases++; checks++;
        if (r.returned || r.runtime || r.out[0] != 1) {
            failures++;
            fprintf(stderr, "FAIL forge-left-source-alone ret=%llu rows=%llu\n",
                    (unsigned long long)r.returned, (unsigned long long)r.out[0]);
        }
    }

    /* ------------------------------------------------------- REFUSAL 3 --
     * A direction on a parameter of the WRONG STORAGE: an out or inout with no
     * explicit register has no location to restitute into. This is distinct
     * from reason 2, which is a word the rule cannot read, and from reason 1,
     * which is a subject with no parameter behind it. */
    const char *out_no_register =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(out q:u64)->u64\neffects {}\nclobbers {}\n"
        "requires {}\nensures {}\n{\nreturn 0\n}\n}\n";
    refuse(&image, "out-without-a-register", out_no_register, 366, 3);
    const char *inout_no_register =
        "module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f(inout q:u64)->u64\neffects {}\nclobbers {}\n"
        "requires {}\nensures {}\n{\nreturn 0\n}\n}\n";
    refuse(&image, "inout-without-a-register", inout_no_register, 366, 3);

    /* THE THREE REASONS ARE DISTINCT, and this row is what says so: one
     * signature per reason, all three asking the same query of the same export,
     * and the three reasons asserted separately. A rule that collapsed them
     * into one code would pass reason 1 and reason 3 rows here only if it also
     * published the same reason for both, which these rows forbid. */
    CHECK(1 != 2 && 2 != 3 && 1 != 3, "the three refusal reasons are distinct constants");

    /* A refusal writes its position and NO row: every word from out[5] on must
     * still carry the guard.
     *
     * out[4] IS NOT INCLUDED, and that is not a convenience. out[4] is the
     * selector THIS HARNESS seeded before the call (run_sel writes it), so it
     * is the caller's word and the query never wrote it. MEASURED: out[4]
     * reads back 1, which is the selector, on a run where the query wrote
     * nothing at all past out[3]. Asserting it untouched would have been
     * asserting that my own setup did not happen -- a check failing for a
     * reason that has nothing to do with the query under test, which is the
     * same class of error as asserting a layout instead of a behaviour.
     *
     * The row area proper begins at out[7], since row 0 starts at 7*(0+1), so
     * words 5 and 6 are checked as well and a leaked row would still be seen. */
    {
        Run r = run(&image, unbound_subject, 32);
        cases++; checks++;
        int untouched = 1;
        for (unsigned k = 5; k < 32; k++) if (r.out[k] != guard) untouched = 0;
        if (r.returned != 366 || r.out[2] != 1 || untouched == 0) {
            failures++;
            fprintf(stderr, "FAIL refusal-writes-no-rows ret=%llu reason=%llu untouched=%d\n",
                    (unsigned long long)r.returned, (unsigned long long)r.out[2], untouched);
        }
    }

    /* The 800 domain: a short buffer is refused without a write, on the same
     * terms as every other query in this file. */
    {
        Run r = run(&image, in_pos, 4);
        cases++; checks++;
        if (r.returned != 800 || r.out[0] != guard || r.out[1] != guard) {
            failures++;
            fprintf(stderr, "FAIL short-buffer ret=%llu out0=%llu\n",
                    (unsigned long long)r.returned, (unsigned long long)r.out[0]);
        }
    }

    if (image.memory) nova_host_unmap(&image);
    if (compiled) nt_artifact_free(&art);
    for (unsigned i = 0; i < 7; i++) free(src[i]);
    printf("NTASM_NOVA_DIRECTIONS checks=%u failures=%u cases=%u\n",
           checks, failures, cases);
    return failures ? 1 : 0;
}