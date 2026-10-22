#ifndef NG_NTASM_PIPELINE_PARITY_H
#define NG_NTASM_PIPELINE_PARITY_H

/* ==========================================================================
   The pipeline parity helper -- one shared header, included by the
   sub-chain harnesses that assert a diagnostic code.

   WHAT THIS EXISTS FOR.  A sub-chain gate compiles a SUBSET of the 34 stage
   pipeline of validate.nova and asserts a diagnostic code on it.  Measured
   over 873 distinct NTASM literals harvested from the harnesses themselves:
   35 of the 36 sub-chains are not a prefix of the 34 stage order, one is out
   of order, 36 of 36 diverge from the full pipeline on at least one input,
   and 16 of 36 diverge with BOTH sides refusing and the two codes
   different -- 759 records.  The tree had never measured that relation, so
   every one of those 759 was a silent claim about the pipeline.

   A PREFIX RULE IS NOT THE ANSWER AND IS NOT OFFERED HERE.  Stage 1 alone
   disqualifies 35 of 36, and reordering the chains to satisfy one would gut
   them.  The rule this file enforces is one sentence:

     a gate may still run one stage in isolation; it may not claim the
     pipeline's answer for it.

   So every case a parity-aware gate asserts is run TWICE -- once through the
   gate's own entry, once through the 43 module validate image -- and the two
   verdicts are compared.  Where the chain is a prefix of the stage order,
   equality is demanded outright.  Where it is gapped or out of order, equality
   is unsatisfiable BY CONSTRUCTION and is replaced by a declared divergence
   set: every (entry_code, pipeline_code) pair the gate exhibits must be in the
   gate's own declared table, and every declared pair must actually occur.  A
   new pair fails and names it; a pair that stops occurring fails as a stale
   baseline.  That is the whole instrument: it cannot be satisfied by a gate
   that is silent, and it cannot be satisfied by a baseline nobody reads.

   WHY A HEADER.  ngbuild.sh maps a gate name to tests_ntasm_<name>.c and
   compiles it against a SHARED OBJECT LIST, so a helper that needed a new
   object would need that list edited.  The list is held and was not touched.
   A header has no such requirement: -I compiler/c finds it, and
   each harness opts in by including it.

   WHY THE PER-GATE TABLES LIVE IN THE HARNESS AND NOT HERE.  A gate knows
   which fixtures it carries and what it claims about them; the helper knows
   how to run two images and compare them.  Keeping the baseline next to the
   fixtures is what makes a new case and a new declared pair visible in the
   same diff, and it keeps this file free of per-gate knowledge that would rot
   silently when a gate is rewritten.
   ========================================================================== */

#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* gcc builds this tree with -Wall -Wextra -Werror, and a harness that uses
   one half of this header would otherwise fail on the other half's unused
   statics.  Every declaration below is therefore marked possibly-unused
   rather than being split into pieces per harness. */
#define NG_PARITY_UNUSED __attribute__((unused))

/* --------------------------------------------------------------------------
   The 43 module validate image.  This is the list the validate gate itself
   compiles, and it is written out here because a C file cannot ask the tree
   for it: the closure is not derivable from validate.nova's own import lines
   (constant_eval, parser and lexer are reached only transitively, through
   initializer_types, validate_entry and ast), so a parse of the import lines
   would be a guess.  The list is therefore a literal, and its drift is
   caught by a check that can fail rather than left to review: ng_parity_open
   reads validate.nova as text and fails if validate.nova imports a module
   this list does not carry, and fails again if the image it built publishes
   a stage order different from the 34 names below.  Adding a stage therefore
   breaks this helper loudly instead of quietly measuring a shorter pipeline.
   -------------------------------------------------------------------------- */
#define NG_PARITY_MODULES 43
NG_PARITY_UNUSED static const char *const ng_parity_paths[NG_PARITY_MODULES] = {
    "tests/nova/tests/validate-entry.nova",
    "compiler/nova/analysis/validate.nova",
    /* The splice, which validate.nova used to carry in its own body.  It is
       here because validate.nova imports it, and a list that did not carry
       it would fail ng_parity_imports_present, which is the check this file
       exists to be.  The 35 stage names below are untouched by this: the
       expansion is still stage 1 and it is still run before stages(). */
    "compiler/nova/macros/macro_splice.nova",
    "compiler/nova/formats/ntir/ntir.nova",
    "compiler/nova/macros/macro_expand.nova",
    "compiler/nova/analysis/types/constant_types.nova",
    "compiler/nova/macros/constant_eval.nova",
    "compiler/nova/analysis/types/initializer_types.nova",
    "compiler/nova/analysis/types/condition_types.nova",
    "compiler/nova/analysis/types/literal_initializers.nova",
    "compiler/nova/frontend/targets.nova",
    "compiler/nova/frontend/versions.nova",
    "compiler/nova/analysis/abi/feature_requirements.nova",
    "compiler/nova/analysis/abi/features.nova",
    "compiler/nova/analysis/types/pointer_spaces.nova",
    "compiler/nova/analysis/control_flow.nova",
    "compiler/nova/analysis/types/return_types.nova",
    "compiler/nova/analysis/abi/body_clobbers.nova",
    "compiler/nova/analysis/abi/body_intrinsics.nova",
    "compiler/nova/analysis/abi/body_effects.nova",
    "compiler/nova/analysis/calls/call_contracts.nova",
    "compiler/nova/analysis/abi/abi.nova",
    "compiler/nova/analysis/calls/call_clobbers.nova",
    "compiler/nova/analysis/calls/call_effects.nova",
    "compiler/nova/analysis/calls/call_types.nova",
    "compiler/nova/analysis/calls/calls.nova",
    "compiler/nova/frontend/refs.nova",
    "compiler/nova/analysis/abi/clobbers.nova",
    "compiler/nova/analysis/abi/contracts.nova",
    "compiler/nova/analysis/abi/effects.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/frontend/register_bindings.nova",
    "compiler/nova/frontend/bindings.nova",
    "compiler/nova/frontend/locals.nova",
    "compiler/nova/frontend/parameters.nova",
    "compiler/nova/analysis/types/types.nova",
    "compiler/nova/frontend/symbol_names.nova",
    "compiler/nova/analysis/calls/callable_names.nova",
    "compiler/nova/analysis/semantics.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova",
    /* machine_ir.nova is here because validate.nova imports it, and it is
       there because it is STAGE 35 of the image below, not because it is
       reachable from a test entry.  Before this row the module was built,
       versioned and gated, and the only thing that reached it was
       tests/nova/tests/machine-ir-entry.nova -- which is the shape
       the project's own rule for abi.obligations and stub_table calls a
       generator that is built and not wired.  Its two imports, ntir and
       register_widths, are both already in this list, so adding the row adds
       no transitive dependency and ng_parity_closure_is_the_list stays
       satisfiable in both directions. */
    "compiler/nova/ir/machine_ir.nova",
};

/* The 35 stage names, in pipeline order.  Thirty four of them are the rows of
   spec/ntasm/ntasm.md 17.7 and the thirty fifth, machine_ir, is the lowering that
   runs after them -- ntir.build, machine_ir.lower, machine_ir.verify, called
   from validate.stages as stage 35.  These are the
   names the IMAGE publishes (validate.stage_table, mode 1 of the seventh
   word), and ng_parity_open compares the image's own bytes against them, so
   this list is a claim about the product that the product is asked to confirm
   and not a second copy of it. */
#define NG_PARITY_STAGES 35
NG_PARITY_UNUSED static const char *const ng_parity_stage_names[NG_PARITY_STAGES] = {
    "expand", "index", "targets", "versions", "features", "callable_names",
    "symbol_names", "types", "constant_types", "literal_initializers",
    "parameters", "locals", "bindings", "register_bindings",
    "register_widths", "clobbers", "abi", "pointer_spaces", "effects",
    "body_effects", "body_intrinsics", "body_clobbers", "control_flow",
    "return_types", "contracts", "feature_requirements", "refs", "calls",
    "call_types", "initializer_types", "condition_types", "call_effects",
    "call_clobbers", "call_contracts", "machine_ir",
};

/* Which of the 35 stages a stage name belongs to, 1 based, 0 when the name
   is not one of the 35.  Used to VALIDATE a gate's declared stage list, so a
   gate that names a stage the pipeline does not have fails instead of being
   silently unclassified. */
NG_PARITY_UNUSED static int ng_parity_stage_index(const char *name) {
    int i;
    for (i = 0; i < NG_PARITY_STAGES; i++)
        if (strcmp(ng_parity_stage_names[i], name) == 0) return i + 1;
    return 0;
}

/* --------------------------------------------------------------------------
   Code attribution, for the MESSAGE and for one assertion.

   A code is not owned by one stage: 336 is the "cannot encode" verdict of
   body_effects, body_clobbers, control_flow AND call_contracts, and 340 is
   both pointer_spaces' unknown space and control_flow's own.  So the table
   is a bitmask over the 34 stages and a code names every stage that can
   return it.

   The rows were extracted from the stage modules with the rule

       strip // comments, then keep every 3xx literal that is the target of
       a `return` or a bare `=`

   which is the whole of the semantic diagnostic namespace.  Codes outside
   300..365 are NOT attributed: 1xx and 2xx are lexer, macro budget and
   initializer budgets, 800 is every stage's structural refusal, and 810/812
   are the decls gate's own codes, which no stage of this pipeline emits at
   all.  An unattributed code is reported as such rather than guessed at.

   HONEST LIMIT, stated here because it is a limit and not a bug: this table is
   a claim about the stage modules and nothing in the build re-derives it.  It
   is used for one assertion (below) and for the text of every message, so a
   code that moved from one stage to another keeps the same message quality;
   a code that APPEARED or DISAPPEARED silently loosens that one assertion.
   The parity assertion, the declared-set exactness and the stage-name
   validation do not read this table at all and are not exposed to it.
   -------------------------------------------------------------------------- */
typedef struct { uint64_t code, stages; } NgParityCode;
NG_PARITY_UNUSED static const NgParityCode ng_parity_codes[] = {
    {300, UINT64_C(1) << 1},   {310, (UINT64_C(1) << 26) | (UINT64_C(1) << 27)},
    {311, UINT64_C(1) << 27}, {313, UINT64_C(1) << 5},
    {314, UINT64_C(1) << 10}, {315, UINT64_C(1) << 11},
    {316, UINT64_C(1) << 12}, {317, UINT64_C(1) << 13},
    {318, UINT64_C(1) << 14}, {319, UINT64_C(1) << 6},
    {320, UINT64_C(1) << 15}, {321, UINT64_C(1) << 18},
    {322, UINT64_C(1) << 18}, {323, UINT64_C(1) << 24},
    {324, UINT64_C(1) << 24}, {325, UINT64_C(1) << 31},
    {326, (UINT64_C(1) << 22) | (UINT64_C(1) << 33)},
    {327, UINT64_C(1) << 16}, {328, UINT64_C(1) << 16},
    {329, UINT64_C(1) << 16}, {330, UINT64_C(1) << 15},
    {331, UINT64_C(1) << 32}, {332, UINT64_C(1) << 19},
    {333, UINT64_C(1) << 19}, {334, UINT64_C(1) << 20},
    {335, UINT64_C(1) << 21}, {336, (UINT64_C(1) << 19) | (UINT64_C(1) << 21) |
                                  (UINT64_C(1) << 22) | (UINT64_C(1) << 33)},
    {337, UINT64_C(1) << 22}, {338, UINT64_C(1) << 22},
    {339, UINT64_C(1) << 22}, {340, (UINT64_C(1) << 17) | (UINT64_C(1) << 22)},
    {341, UINT64_C(1) << 4},  {342, UINT64_C(1) << 4},
    {343, UINT64_C(1) << 25}, {344, UINT64_C(1) << 25},
    {345, UINT64_C(1) << 2},  {346, UINT64_C(1) << 2},
    {347, UINT64_C(1) << 3},  {348, UINT64_C(1) << 3},
    {349, UINT64_C(1) << 3},  {350, UINT64_C(1) << 7},
    {351, UINT64_C(1) << 7},  {352, UINT64_C(1) << 23},
    {353, UINT64_C(1) << 23}, {354, UINT64_C(1) << 28},
    {355, UINT64_C(1) << 9},  {356, UINT64_C(1) << 9},
    {357, UINT64_C(1) << 30}, {358, UINT64_C(1) << 30},
    {359, UINT64_C(1) << 29}, {360, UINT64_C(1) << 29},
    {361, UINT64_C(1) << 8},  {362, UINT64_C(1) << 8},
    {363, UINT64_C(1) << 8},  {364, UINT64_C(1) << 22},
    {365, UINT64_C(1) << 33},
};
#define NG_PARITY_CODE_ROWS ((int)(sizeof ng_parity_codes / sizeof ng_parity_codes[0]))

/* The stages that can return this code, as a bitmask over the 34 stages.  An
   unattributed code -- a lexer code, a macro budget code, 800, or a gate's own
   code such as decls' 812 -- returns 0, which is a real answer and not a
   failure: those codes are not verdicts of this pipeline. */
NG_PARITY_UNUSED static uint64_t ng_parity_owners(uint64_t code) {
    int i;
    for (i = 0; i < NG_PARITY_CODE_ROWS; i++)
        if (ng_parity_codes[i].code == code) return ng_parity_codes[i].stages;
    return 0;
}

/* The lowest numbered stage that can return this code, or 0 when the code is
   not one of this pipeline's.  This is the stage the pipeline would have had
   to reach first for the code to be the pipeline's answer. */
NG_PARITY_UNUSED static int ng_parity_first_owner(uint64_t code) {
    uint64_t m = ng_parity_owners(code);
    int i;
    for (i = 0; i < NG_PARITY_STAGES; i++)
        if (m & (UINT64_C(1) << i)) return i + 1;
    return 0;
}

/* The ONE stage that can return this code, or 0 when no stage can or when
   SEVERAL can.  Several is a real answer and not a gap: 310 is refs(27) and
   calls(28), 340 is pointer_spaces(18) and control_flow(23), 326 is
   control_flow(23) and call_contracts(34).  A code that names two stages does
   not identify which of them answered, so an assertion that needs to know
   cannot be built on it -- see the accept direction check, which is exactly
   that shape and was WRITTEN against the wider mask until the refs gate
   proved it wrong: a source the pipeline refused with 310 at calls(28), a
   stage the refs entry does not link, was reported as "a stage this entry
   runs can return that code" because refs(27) can also return 310. */
NG_PARITY_UNUSED static int ng_parity_unique_owner(uint64_t code) {
    uint64_t m = ng_parity_owners(code);
    int i, n = 0, at = 0;
    for (i = 0; i < NG_PARITY_STAGES; i++)
        if (m & (UINT64_C(1) << i)) { n++; at = i + 1; }
    return n == 1 ? at : 0;
}

/* "body_effects(20),control_flow(23)" for 336, "unattributed" for 800.  Only
   ever used in a message, so a table that has gone stale degrades the text and
   not a verdict. */
NG_PARITY_UNUSED static void ng_parity_owners_text(uint64_t code, char *buf, size_t n) {
    uint64_t m = ng_parity_owners(code);
    size_t at = 0;
    int i, any = 0;
    if (n == 0) return;
    buf[0] = 0;
    if (m == 0) { snprintf(buf, n, "unattributed"); return; }
    for (i = 0; i < NG_PARITY_STAGES; i++) {
        int w;
        if (!(m & (UINT64_C(1) << i))) continue;
        w = snprintf(buf + at, n - at, "%s%s(%d)", any ? "," : "",
                     ng_parity_stage_names[i], i + 1);
        if (w < 0 || (size_t)w >= n - at) return;
        at += (size_t)w;
        any = 1;
    }
}

/* ==========================================================================
   What a gate declares about itself.
   ========================================================================== */

/* A divergence the gate has examined and is standing behind.  Every one of
   these is a place where the gate answers a DIFFERENT question from the
   pipeline's, and saying so in the harness is the documentation. */
typedef struct { uint64_t entry_code, pipe_code; } NgParityPair;

#define NG_PARITY_MAX_STAGES 35

/* ONE CALL's declaration, at the call site where the mode is visible.

   sp->stages is a LINK SET: the stage modules the entry image contains.  It is
   the right thing for the A direction, where a code the pipeline returns is
   simply compared, and for the declared-pair ledger, and it is what
   `prefix=no` is computed from.  It is NOT the right thing for the B
   direction.  A B record says "the entry accepted and the pipeline refused with
   a code one of the entry's stages owns", and that is a claim about the stages
   the CALL ran: control-flow-entry links body_intrinsics and clobbers but its
   mode 0 path never calls either, so a pipeline refusal at body_intrinsics(21)
   on a mode 0 case is the pipeline being right about a stage the entry did not
   ask.

   That mistake was found by being run, not by being reasoned about: 36
   call_contracts rows and 24 control_flow rows went red on exactly that arm,
   every one of them on a probe mode whose return value is not a stage verdict
   at all.  So the declaration is per call, and it carries two facts:

     stages  which pipeline stages this invocation actually runs.  The B
             direction uses THIS, never the link set.
     verdict 1 when the invocation's return value is a stage verdict, 0 when
             it is a derived answer.  A probe that folds body_clobbers' 335
             into a boolean has SEEN that 335 and agreed with something; it has
             not accepted the module, and comparing its 0 against a pipeline
             335 asks whether a boolean equals a diagnostic.  A verdict==0 call
             is counted as `probe` and neither direction is applied to it --
             examined, classified, and not guessed at. */
typedef struct {
    const char *stages[NG_PARITY_MAX_STAGES];
    unsigned stage_count;
    int verdict;
} NgParityCall;

typedef struct {
    const char *entry;                            /* gate name, for messages */
    const char *stages[NG_PARITY_MAX_STAGES];    /* the stages this entry runs */
    unsigned stage_count;
    /* Whether this gate's non zero codes are CLAIMS about the pipeline.  Most
       gates: yes, and the comparison below is the point.  One gate in the tree
       is not: decls refuses with its own 812, which no stage of this pipeline
       emits, so comparing it against a 3xx pipeline verdict would be measuring
       a category error.  Such a gate says so, and the helper then REQUIRES
       that every code it asserts really is unattributed -- so the claim
       "these are not pipeline verdicts" is itself an assertion that can fail,
       rather than a hole. */
    unsigned claims;
    const NgParityPair *declared;                 /* the standing divergences */
    unsigned declared_count;
    /* filled in by the helper */
    unsigned checked, agree, diverged, weaker, both_ok, structural, unattributed, probe;
    unsigned char *declared_seen;
} NgParitySpec;

/* ==========================================================================
   The pipeline image.  One per process, built on first use.
   ========================================================================== */

typedef struct {
    int open;
    NovaHostImage image;
    NtArtifact artifact;
    int compiled;
    char stage_bytes[1024];
    size_t stage_len;
} NgParityState;

NG_PARITY_UNUSED static NgParityState ng_parity_state;

NG_PARITY_UNUSED static char *ng_parity_loadf(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    long z;
    char *b;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    z = ftell(f);
    fseek(f, 0, SEEK_SET);
    b = (z >= 0) ? (char *)malloc((size_t)z + 1) : NULL;
    if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) { free(b); fclose(f); return NULL; }
    fclose(f);
    b[z] = 0;
    *len = (size_t)z;
    return b;
}

/* The 34 names the IMAGE publishes, asked of the image.  This is mode 1 of the
   seventh out word of the validate entry: it copies validate.stage_table into
   a buffer the caller lends writable and reports the byte count.  Returns 0
   on success. */
NG_PARITY_UNUSED static int ng_parity_ask_stage_table(NgParityState *st) {
    char *src;
    uint64_t out[7];
    NovaContextV2 c = {0};
    uint64_t sh, oh, a[4];
    int rc = 0;
    src = (char *)malloc(sizeof st->stage_bytes);
    if (!src) return 0;
    memset(out, 0, sizeof out);
    if (!nova_context_init_v2(&c)) { free(src); return 0; }
    sh = nova_borrow_v2(&c, src, sizeof st->stage_bytes, 1);
    oh = nova_borrow_v2(&c, out, sizeof out, 1);
    out[6] = 1;
    a[0] = sh; a[1] = sizeof st->stage_bytes; a[2] = oh; a[3] = 7;
    (void)st->image.entry(&c, a, 4);
    if (c.error == 0 && out[0] != 0 && out[0] < sizeof st->stage_bytes) {
        st->stage_len = (size_t)out[0];
        memcpy(st->stage_bytes, src, st->stage_len);
        st->stage_bytes[st->stage_len] = 0;
    } else {
        rc = -1;
    }
    (void)nova_context_destroy_v2(&c);
    free(src);
    return rc;
}

/* Every module validate.nova imports must be one this list carries.  A new
   import in validate.nova that this header does not know about would shorten
   the pipeline this helper measures, silently, to the one still true after
   the new stage is removed -- which is the exact failure the whole file
   exists to catch, one level up.  Name mapping: the ntasm_ prefixed modules
   whose file is not named after the import. */
/* The missing name is COPIED into `missing` before the source is released.
   The first version returned a pointer into the buffer it had just freed and
   the caller formatted it: the check fired, through a stack-use-after-return
   the sanitizer turned the run red for a reason that had nothing to do with
   the import.  A check that goes red for the wrong reason is not a check, and
   the negative proof of this one is what found it. */

/* --------------------------------------------------------------------------
   THE COMMENT AND STRING FORMS, AND WHERE THEY COME FROM.

   This scan used to be strstr(text, "import "), which does not know what a
   comment is.  A draft of a note in validate.nova read "cannot import this
   module"; the wording changed, not the parser, and sixteen gates went down.
   The subject is worse than the geometry check's, because the text being read
   is not a document a human wrote: it is a comment inside a .nova file, which
   is CODE.  A reviewer reading the module sees a comment; a reviewer reading
   this header sees a module list.  Neither surface is wrong, which is why it
   survived until a sentence was written.

   So the forms below are not a guess about what an assembler would accept.
   They were MEASURED by running compiler/nova/frontend/lexer.nova -- the tree's
   authority on what a byte of a .nova file means -- over each shape and
   reading the tokens it emitted.  What it emitted, and nothing else, is what
   is implemented here:

     * `//` to end of line is a comment, and emits NO tokens (probe Q1, Q3,
       Q8).  A comment at end of file with no trailing newline is still a
       comment (Q3).
     * A C-style block comment is NOT a comment here.  A slash followed by a
       star lexes as the punctuation tokens 47 and 42, and the text after it
       is scanned as code (Q2).  This language has no block comment, so a
       scanner that grew a rule for one would be modelling a language nobody
       compiles -- and a half-lexer is another way for prose to be read as
       code.  (Spelled out in words here on purpose: a note that NAMED the
       two-character opener would close this comment early, which is the same
       defect one layer up.)
     * A string literal is ONE token (kind 259) and its contents are never
       scanned, so `import ` inside one is not an import and a `//` inside one
       is not a comment (Q4, Q14).
     * `import` is an ordinary NAME token, so a name that merely ENDS in
       "import" is a different token and must not match (Q10).
     * Any of space, tab or newline may separate the keyword from the name
       (Q7, Q11, Q12), so matching the literal text "import " misses a real
       import written with a tab.  That is a false NEGATIVE, and it is why
       the fix is a token scan and not a wider strstr.
     * The name is terminated by `;` or by end of line (Q13); nothing else
       terminates it.
     * An isolated CR is not whitespace: the lexer refuses the file with its
       own reason 1 (Q6).  This scan steps over it so it cannot be tricked
       into inventing a token boundary, and a file that contains one cannot
       compile, so ng_parity_open's compile is what reports it.

   WHAT THIS SCAN DOES NOT MODEL, stated because it is a limit and not a bug:
   it does not reproduce the lexer's own diagnostics.  A malformed string
   escape, a bad integer or an invalid source byte is not detected here; the
   compile that follows this check reports those, with a line number, and a
   file that cannot compile is one no import set needs to be read from.
   -------------------------------------------------------------------------- */
NG_PARITY_UNUSED static int ng_parity_idstart(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
NG_PARITY_UNUSED static int ng_parity_idchar(unsigned char c) {
    return ng_parity_idstart(c) || (c >= '0' && c <= '9');
}

/* The next `import` at or after *at, and the module name that follows it.
   Returns 1 when one was found and copies the name into `name`; returns 0 at
   the end of the text.  `*at` is left on the first byte AFTER the name, so a
   caller that loops finds each import exactly once. */
NG_PARITY_UNUSED static int ng_parity_next_import(const char *text, size_t len,
                                                  size_t *at, char *name,
                                                  size_t name_len) {
    size_t i = *at;
    while (i < len) {
        unsigned char c = (unsigned char)text[i];
        size_t j;
        if (c == '/' && i + 1 < len && text[i + 1] == '/') {
            while (i < len && text[i] != '\n') i++;
            continue;
        }
        if (c == '"') {
            i++;
            while (i < len && text[i] != '"') {
                if (text[i] == '\\' && i + 1 < len) i++;
                i++;
            }
            if (i < len) i++;
            continue;
        }
        if (!ng_parity_idstart(c)) { i++; continue; }
        for (j = i; j < len && ng_parity_idchar((unsigned char)text[j]); j++) {}
        if (j - i == 6 && memcmp(text + i, "import", 6) == 0) {
            size_t k = j, m;
            while (k < len) {
                unsigned char d = (unsigned char)text[k];
                if (d == ' ' || d == '\t' || d == '\r' || d == '\n') { k++; continue; }
                if (d == '/' && k + 1 < len && text[k + 1] == '/') {
                    while (k < len && text[k] != '\n') k++;
                    continue;
                }
                break;
            }
            if (k < len && ng_parity_idstart((unsigned char)text[k])) {
                m = k;
                while (m < len && ng_parity_idchar((unsigned char)text[m])) m++;
                if (m - k >= name_len) m = k + name_len - 1;
                memcpy(name, text + k, (size_t)(m - k));
                name[m - k] = 0;
                *at = m;
                return 1;
            }
            i = j;
            continue;
        }
        i = j;
    }
    *at = i;
    return 0;
}

/* Every import in `text` must be one this list carries.  Returns 1 when they
   all are, 0 otherwise, and on 0 copies the module FILE the list does not
   carry into `missing` -- the name after the alias mapping and the .nova
   suffix, which is what the caller prints. */

/* The imports whose FILE is not named after the import.  One table, at file
   scope, because there are now two readers of a module name in this header --
   the one-level scan and the closure walk below -- and two tables would be a
   second mapping that can disagree with the first about which file a name
   means.  That is the same defect one level up: a list beside its subject. */
static const char *const ng_parity_alias[] = {
    "ntasm_ast", "ast.nova", "ntasm_macro_expand", "macro_expand.nova",
    "ntasm_parser", "parser.nova", "ntasm_lexer", "lexer.nova",
    "ntasm_refs", "refs.nova", "ntasm_ntir", "ntir.nova",
    "ntasm_macro_splice", "macro_splice.nova",
};
NG_PARITY_UNUSED static int ng_parity_scan_imports(const char *text, size_t len,
                                                  char *missing, size_t missing_len) {
    size_t at = 0, i;
    char name[128];
    while (ng_parity_next_import(text, len, &at, name, sizeof name)) {
        char file[160], path[256];
        int aliased = 0, found = 0;
        for (i = 0; i + 1 < sizeof ng_parity_alias / sizeof ng_parity_alias[0]; i += 2) {
            if (strcmp(ng_parity_alias[i], name) == 0) {
                snprintf(file, sizeof file, "%s", ng_parity_alias[i + 1]);
                aliased = 1;
                break;
            }
        }
        if (!aliased) snprintf(file, sizeof file, "%s.nova", name);
        snprintf(path, sizeof path, "compiler/nova/%s", file);
        for (i = 0; i < NG_PARITY_MODULES; i++)
            if (strcmp(ng_parity_paths[i], path) == 0) { found = 1; break; }
        if (!found) {
            snprintf(missing, missing_len, "%s", file);
            return 0;
        }
    }
    return 1;
}

/* THE SELF-TEST, WHICH IS THE PART THAT LASTS.  Producing the red once is an
   observation; producing it again in six months, when somebody writes a note,
   is what keeps sixteen gates from going down.  So the comment is INJECTED
   into a scratch buffer here and the real scanner above is asked about it, on
   every call to ng_parity_open, and a failure turns the gate red by name.
   This is the shape check_doc_structure_selftest already established: a truth
   table over constructed inputs, half of which must be SILENT, so the check
   is shown able to be quiet as well as able to fire. */
NG_PARITY_UNUSED static int ng_parity_import_selftest(char *why, size_t whylen) {
    static const struct { const char *what; const char *text;
                           int want; const char *missing; } cases[] = {
        /* 1. An import the list carries.  Everything quiet: the case that
           says the scan can be quiet, and the case the other eleven rest on. */
        {"an import the list carries", "module m;\nimport semantics;\n",
         1, ""},
        /* 2. THE CASE THIS LOT EXISTS FOR: the incident's own wording, in a
           comment.  It must be silent, and under the strstr scan it was not. */
        {"the incident wording in a comment",
         "// this module cannot import this module\nimport semantics;\n",
         1, ""},
        /* 3. The same prose as a TRAILING comment, where the code before it is
           a real import.  A scan that finds the import and then keeps reading
           the rest of the line gets this wrong in the other direction. */
        {"the incident wording as a trailing comment",
         "import semantics; // cannot import this module\n", 1, ""},
        /* 4. A comment at end of file with no trailing newline (probe Q3). */
        {"a comment at end of file",
         "import semantics;\n// cannot import this module", 1, ""},
        /* 5. A comment naming a module the list does NOT carry.  Silent: a
           comment that says the wrong thing is still a comment. */
        {"a comment naming a missing module",
         "// cannot import ghost\nimport semantics;\n", 1, ""},
        /* 6. `import` as the tail of a longer identifier (probe Q10).  The
           strstr scan read "noimport ghost" as an import of ghost. */
        {"import as the tail of a name",
         "module m;\nlet noimport ghost:u64=1;\nimport semantics;\n", 1, ""},
        /* 7. `import ` inside a string literal (probe Q4).  One token, and a
           string is not a module list. */
        {"import inside a string literal",
         "let s:buf<u8>=\"import ghost;\";\nimport semantics;\n", 1, ""},
        /* 8. A block-comment shape, which THIS LANGUAGE DOES NOT HAVE (Q2).
           It must FIRE, and that is the assertion: a scanner that grew a
           two-character-opener rule would be modelling a language nobody
           compiles, and would go quiet here.  Refusing to certify is the
           safe direction. */
        {"a block comment shape, which is code here",
         "module m;\n/* import ghost; */\n", 0, "ghost.nova"},
        /* 9. A real import the list does not carry.  The check can still fire;
           a comment-aware scan that fires on nothing is not a check. */
        {"an import the list does not carry",
         "module m;\nimport ghost;\n", 0, "ghost.nova"},
        /* 10. The same, separated by a TAB (probe Q11).  The strstr scan
            missed this one entirely: a false negative, which is a check that
            cannot fail on a real drift. */
        {"a tab separated import the list does not carry",
         "module m;\nimport\tghost;\n", 0, "ghost.nova"},
        /* 11. The same, separated by a NEWLINE (probe Q12). */
        {"a newline separated import the list does not carry",
         "module m;\nimport\nghost;\n", 0, "ghost.nova"},
        /* 12. An isolated CR, which the lexer refuses with reason 1 (Q6).
            The scan must step over it rather than be confused by it; a file
            containing one cannot compile and is reported by the compile. */
        {"an isolated CR", "module m;\rimport semantics;\n", 1, ""},
        /* 13. Nothing at all.  A scan that reads past the end of a buffer is
            the failure this case is cheap to rule out. */
        {"an empty module", "", 1, ""},
    };
    size_t i;
    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        /* `got` is bounded, and `why` is bounded to fit what the caller prints,
           so the whole chain is provably inside ng_parity_begin's 256 bytes.
           The first version used 160 here and 256 there and gcc's
           -Wformat-truncation refused all sixteen gates, which is the check
           being right: a message that can overrun its buffer is a defect
           whatever the runtime happens to do on the day. */
        char got[64];
        int want = ng_parity_scan_imports(cases[i].text, strlen(cases[i].text),
                                          got, sizeof got);
        if (want != cases[i].want ||
            (want == 0 && strcmp(got, cases[i].missing) != 0)) {
            snprintf(why, whylen,
                     "case %zu `%s' wanted %d `%s' and the scan said %d `%s'",
                     i + 1, cases[i].what, cases[i].want, cases[i].missing,
                     want, want ? "" : got);
            return 0;
        }
    }
    return 1;
}

NG_PARITY_UNUSED static int ng_parity_imports_present(char *missing, size_t missing_len) {
    size_t len = 0;
    char *text = ng_parity_loadf("compiler/nova/analysis/validate.nova", &len);
    int ok;
    if (!text) { snprintf(missing, missing_len, "validate.nova (unreadable)"); return 0; }
    ok = ng_parity_scan_imports(text, len, missing, missing_len);
    free(text);
    return ok;
}

/* --------------------------------------------------------------------------
   THE CLOSURE, READ FROM THE TREE.  This is the check the list was missing.

   ng_parity_imports_present reads validate.nova ALONE.  That is one level,
   and this header's own note says the four modules it lists as extras --
   constant_eval, lexer, macro_expand, parser -- are reached only
   TRANSITIVELY.  So the check above is structurally blind past depth one, and
   depth two is the shape of the NEXT module: a stage module is written and
   imported by the module that uses it, not by validate.nova.  A list that is
   edited whenever its subject is edited, guarded by a check that reads one
   file, is a list that is correct by hand.

   SO THE TREE SIDE IS DERIVED, NOT LISTED, and derived independently of the
   header: this walks the import closure of NG_PARITY_ENTRY from the files'
   own bytes on disk, through the SAME scanner the one-level check uses, and
   compares the SET it reaches against ng_parity_paths AS A SET.  Nothing here
   compares a count.  NG_PARITY_MODULES can be wrong and this still passes; the
   array can be short by one entry and this still passes.  A count is a thing a
   person updates; a set is a thing a walk produces.  That is the whole design
   point, and it is why the red below names a MODULE rather than a number.

   THE ROOT, and the honest limit of that independence.  One path constant,
   NG_PARITY_ENTRY, is not derived: a walk needs somewhere to start, and the
   tree has no way to name it.  (It is not derivable from `export fn main`
   either: MANY modules in this tree export one -- every `*-entry.nova` in
   tests/ is one -- so "the module that exports main" does not pick out this
   image and never did.)  NO COUNT IS GIVEN HERE ON PURPOSE.  This comment
   first carried one, measured at 84, and it was 85 by the time the lot that
   wrote it finished its own evidence file.  A number in a comment about a
   moving tree is a hand-maintained figure with nothing that notices, which is
   the defect this whole file exists to remove -- and a comment cannot carry a
   check.  What does not decay is the claim: the set is not a singleton.
   What keeps the
   constant from being a free-floating second copy of a list line is the
   SECOND direction of the comparison: every module the list carries must be
   REACHABLE FROM THE ROOT.  Move the root onto a module that does not close
   over the image and the second direction fires by name; name a root the list
   does not carry and the first direction fires on it immediately.  The header
   holds one of the two facts and the tree holds the other, so the two have to
   agree and a stale copy of one cannot survive a change to the other.

   WHAT THIS STILL CANNOT SEE, stated because it is a limit and not a bug.  A
   module that exists under compiler/nova/ and that nothing in this
   image imports.  There are SIXTEEN such modules in that directory today
   (decls, diagnostics, machine_ir, and the nxo_*, pe_*, stub_table and x64_*
   halves) and every one of them is CORRECT to be outside this image: the image
   is the validate pipeline, not the assembler.  So "a .nova file appeared" is
   not drift and nothing should go red for it.  What IS drift is a file that
   became part of THIS image without the list carrying it, and that is the
   case the walk fires on.
   -------------------------------------------------------------------------- */
#define NG_PARITY_ENTRY "tests/nova/tests/validate-entry.nova"
#define NG_PARITY_PATH_MAX 64
/* Twice the list, so a tree that outgrew the room is a NAMED failure rather
   than a buffer overrun, and so a list of 42 that grew to 43 is compared
   rather than refused for want of space. */
#define NG_PARITY_CLOSURE_MAX (NG_PARITY_MODULES * 2)

/* The file an import names.  An import names a MODULE and not a path: the file
   is the one beside the importer, and failing that the one in
   compiler/nova/.  The ntasm_-prefixed names go through the same alias
   table the one-level scan above uses -- ONE table, at file scope, on purpose.
   Returns 1 and copies the path when a file is there, 0 when no file carries
   that name, which is itself a red: an import naming nothing cannot be part of
   any image. */
NG_PARITY_UNUSED static int ng_parity_import_path(const char *importer,
                                                  const char *name,
                                                  char *out, size_t n) {
    char file[64], cand[NG_PARITY_PATH_MAX];
    size_t i, alen = sizeof ng_parity_alias / sizeof ng_parity_alias[0],
           dlen = 0, flen;
    for (i = 0; i < alen; i++)
        if (i + 1 < alen && strcmp(ng_parity_alias[i], name) == 0) break;
    if (i + 1 < alen) flen = strlen(ng_parity_alias[i + 1]),
                        memcpy(file, ng_parity_alias[i + 1], flen + 1);
    else flen = (size_t)snprintf(file, sizeof file, "%s.nova", name);
    if (flen >= sizeof file) return 0;
    for (i = 0; importer[i]; i++) if (importer[i] == '/') dlen = i + 1;
    if (dlen && dlen + flen < sizeof cand) {
        memcpy(cand, importer, dlen);
        memcpy(cand + dlen, file, flen + 1);
        { FILE *f = fopen(cand, "rb");
          if (f) {
              fclose(f);
              /* The length copied is the length of the WHOLE path, not of
                 `file`.  The first version copied flen+1 here, which is the
                 length of the FILE NAME, so this branch returned the first
                 eleven bytes of the path with no terminator -- and a caller
                 that printed it printed whatever followed on the stack.  It
                 produced a red naming a module that does not exist in this
                 tree, which is the shape of a check that has gone wrong
                 rather than a tree that has: the tell is a red that names a
                 case nobody mutated. */
              if (dlen + flen + 1 > n) return 0;
              memcpy(out, cand, dlen + flen + 1);
              return 1;
          } }
    }
    flen = (size_t)snprintf(cand, sizeof cand, "compiler/nova/%s", file);
    if (flen >= sizeof cand) return 0;
    { FILE *f = fopen(cand, "rb");
      if (!f) return 0;
      fclose(f); }
    if (flen + 1 >= n) return 0;
    memcpy(out, cand, flen + 1);
    return 1;
}

/* The comparison itself, over two arrays and touching no file, so the
   self-test below can put both directions of being wrong in front of it
   without inventing a tree on disk.  Fires when the walk reached a module the
   list does not carry, and when the list carries a module the walk did not
   reach; quiet when the two sets are equal however they are ordered. */
NG_PARITY_UNUSED static int ng_parity_sets_are_the_same(
        const char *const *reached, size_t nreached,
        const char *const *list, size_t nlist,
        char *why, size_t whylen) {
    size_t i, k;
    for (i = 0; i < nreached; i++) {
        for (k = 0; k < nlist; k++) if (strcmp(list[k], reached[i]) == 0) break;
        if (k == nlist) {
            snprintf(why, whylen, "the tree reaches %s and the module list does not carry it",
                     reached[i]);
            return 0;
        }
    }
    for (i = 0; i < nlist; i++) {
        for (k = 0; k < nreached; k++) if (strcmp(reached[k], list[i]) == 0) break;
        if (k == nreached) {
            snprintf(why, whylen, "the module list carries %s and the tree does not reach it",
                     list[i]);
            return 0;
        }
    }
    return 1;
}

/* THE SELF-TEST, same shape and same reason as ng_parity_import_selftest
   above: a check that has only ever been seen green has not been shown able
   to fire, and one that has only ever been seen red has not been shown able
   to be quiet.  Six cases, three of which must be SILENT.  The two that must
   fire are the two directions the walk can be wrong in, so a comparison that
   lost either one is caught here rather than by the first module somebody
   adds. */
NG_PARITY_UNUSED static int ng_parity_closure_selftest(char *why, size_t whylen) {
    static const char *const a1[] = {"p.nova", "q.nova", "r.nova"};
    static const char *const a2[] = {"q.nova", "r.nova", "p.nova"};
    static const char *const with_extra[] = {"p.nova", "q.nova", "r.nova", "s.nova"};
    static const char *const without_one[] = {"p.nova", "q.nova"};
    static const struct { const char *what; const char *const *reached;
                           size_t nreached; const char *const *list;
                           size_t nlist; int want; } cases[] = {
        /* 1-2. The same set, two orders.  QUIET, twice: a comparison that
           compared positionally instead of by membership would pass one of
           these and fail the other, and the list's order is not the tree's. */
        {"the same set in the same order", a1, 3, a1, 3, 1},
        {"the same set in another order", a1, 3, a2, 3, 1},
        /* 3. A module the tree reached and the list does not carry.  This is
           THE case: a 43rd module added to the tree and imported by a module
           two levels down. */
        {"a module the list does not carry", with_extra, 4, a1, 3, 0},
        /* 4. A module the list carries and the tree does not reach.  The other
           direction, and the one that pins NG_PARITY_ENTRY: a root moved onto
           a module that does not close over the image looks exactly like this
           to every other check in the file. */
        {"a module the tree does not reach", a1, 3, with_extra, 4, 0},
        /* 5. A list that dropped one of three.  The other direction again,
           one element further out, and the shape a hand edit makes. */
        {"a list that dropped one", with_extra, 4, without_one, 2, 0},
        /* 6. Nothing on either side.  A walk that read past the end of a
           buffer is the failure this case is cheap to rule out. */
        {"nothing at all", a1, 0, a1, 0, 1},
    };
    size_t i;
    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        /* `got` is bounded at 64 so the message below provably fits `why`.
           A message that could overrun is a defect whatever the runtime
           happens to do on the day, and the CASE NAME is what identifies
           which direction broke, so a short quote costs the reader
           nothing. */
        char got[64];
        int want = ng_parity_sets_are_the_same(cases[i].reached, cases[i].nreached,
                                               cases[i].list, cases[i].nlist,
                                               got, sizeof got);
        if (want != cases[i].want) {
            /* `closure case N`, not `case N`: this file has TWO self-test
               tables that both number from 1, and a reader grepping a run log
               for "case 10" must not have to work out which table it came
               from.  The name is the identifier, and it travels with it. */
            snprintf(why, whylen, "closure case %zu `%s' wanted %d and the comparison said %d `%s'",
                     i + 1, cases[i].what, cases[i].want, want, want ? "" : got);
            return 0;
        }
    }
    return 1;
}

/* The walk.  Returns 1 when the set of modules reachable from `root` by
   imports, read from the files on disk, is exactly `list`.  On 0, `why`
   names the first difference.  Parameterised by its root AND by its list, so
   a harness that keeps a compiler-input list of its own can ask the same
   question of that list.

   WHY THE LIST IS A PARAMETER, and this is the whole reason the function is
   shaped this way.  Three gates -- diagnostics, splice, initializer_types --
   compile a DIFFERENT ENTRY (diagnostics-entry, splice-entry,
   initializer-types-entry) against the rest of this image, so each holds its
   own list rather than using ng_parity_paths.  Until this signature existed
   there was no instrument that could ask whether one of THOSE lists is the
   closure of its own entry: the walk compared itself to ng_parity_paths and to
   nothing else.  The drift that followed was silent -- machine_ir.nova became
   stage 35 and every one of those three lists went on without it, and the
   only thing in the tree that said so was the compiler's own
   `E302 <line>:<col> Nova imported module is not among compiler inputs',
   which truncates the gate at its first three checks instead of naming the
   list.  A guard that can only be pointed at one of four lists is a guard on
   one of four lists. */
NG_PARITY_UNUSED static int ng_parity_closure_is(const char *root,
                                                const char *const *list, size_t nlist,
                                                char *why, size_t whylen) {
    char store[NG_PARITY_CLOSURE_MAX][NG_PARITY_PATH_MAX];
    const char *paths[NG_PARITY_CLOSURE_MAX];
    size_t n = 0, i, k, at;
    if (strlen(root) >= NG_PARITY_PATH_MAX) {
        snprintf(why, whylen, "the root path is longer than %d bytes", NG_PARITY_PATH_MAX - 1);
        return 0;
    }
    memcpy(store[0], root, strlen(root) + 1);
    paths[0] = store[0];
    n = 1;
    for (i = 0; i < n; i++) {
        size_t len = 0;
        char name[64], next[NG_PARITY_PATH_MAX];
        char *text = ng_parity_loadf(paths[i], &len);
        if (!text) {
            snprintf(why, whylen, "the closure reached %s and the file cannot be read", paths[i]);
            return 0;
        }
        at = 0;
        while (ng_parity_next_import(text, len, &at, name, sizeof name)) {
            int dup = 0;
            /* A name that filled the buffer has been TRUNCATED, and a
               truncated module name resolves to nothing, so it is reported
               here rather than becoming a mystery "no file carries it" two
               lines later.  The check is that the name reached the end. */
            if (strlen(name) + 1 == sizeof name) {
                snprintf(why, whylen, "%s imports a module name of 63 bytes or more",
                         paths[i]);
                free(text);
                return 0;
            }
            if (!ng_parity_import_path(paths[i], name, next, sizeof next)) {
                snprintf(why, whylen, "%s imports %s and no file in the tree carries it",
                         paths[i], name);
                free(text);
                return 0;
            }
            for (k = 0; k < n; k++) if (strcmp(paths[k], next) == 0) { dup = 1; break; }
            if (dup) continue;
            if (n >= NG_PARITY_CLOSURE_MAX) {
                snprintf(why, whylen, "the tree closes over more than %d modules and this header stops counting",
                         NG_PARITY_CLOSURE_MAX);
                free(text);
                return 0;
            }
            memcpy(store[n], next, strlen(next) + 1);
            paths[n] = store[n];
            n++;
        }
        free(text);
    }
    return ng_parity_sets_are_the_same(paths, n, list, nlist, why, whylen);
}

/* The same walk against THIS header's own list.  Kept as a name of its own
   because that pairing -- the validate image and ng_parity_paths -- is the
   claim the header is written to make, and a caller reading it should not
   have to know which list it is. */
NG_PARITY_UNUSED static int ng_parity_closure_is_the_list(const char *root,
                                                         char *why, size_t whylen) {
    return ng_parity_closure_is(root, ng_parity_paths,
                                (size_t)NG_PARITY_MODULES, why, whylen);
 }

/* Build the 43 module image and check, against the image itself, the two
   things this header claims about it: the module list is the whole of
   validate.nova's closure, and the stage order it publishes is the 34 names
   above.  Returns 0 on success; on failure writes one line into err. */
NG_PARITY_UNUSED static int ng_parity_open(char *err, size_t errlen) {
    NgParityState *st = &ng_parity_state;
    char *sources[NG_PARITY_MODULES];
    NtFInput inputs[NG_PARITY_MODULES];
    /* `why` is bounded so that the message below provably FITS in the 256
       bytes ng_parity_begin's caller guarantees.  The first version of this
       took 256 and gcc's -Wformat-truncation refused the build for all
       sixteen gates, which is the check being right: a message that can
       overrun its buffer is a defect whatever the runtime happens to do. */
    char missing[160], why[160];
    size_t i, at = 0;
    if (st->open) return 0;
    /* BEFORE the open guard's work and before the real scan, and on EVERY
       call: the import scan is the instrument that decides whether the module
       list is a claim about the product or a shorter pipeline measured
       quietly, so the scan is shown able to fire and able to be quiet on
       every run rather than being trusted because it has been green. */
    if (!ng_parity_import_selftest(why, sizeof why)) {
        snprintf(err, errlen,
                 "the import scan failed its own self-test, so its verdict on "
                 "the module list is void: %s", why);
        return -1;
    }
    /* The same rule for the closure comparison, and for the same reason: it
       is the instrument that decides whether NG_PARITY_MODULES is a claim
       about the tree, and a comparison that has only ever agreed is not
       known to be able to disagree. */
    if (!ng_parity_closure_selftest(why, sizeof why)) {
        snprintf(err, errlen,
                 "the closure comparison failed its own self-test, so its "
                 "verdict on the list is void: %s", why);
        return -1;
    }
    /* The closure the tree actually has, against the list this header
       carries.  This is the check the list never had: ng_parity_imports_present
       above reads validate.nova alone, and four of the modules in the list are
       reached only transitively, so a module added and imported two levels
       down was invisible to it.  It fires in BOTH directions, so a list entry
       that outlived its module is a red too and not a silent extra module in
       a 43 module image. */
    if (!ng_parity_closure_is_the_list(NG_PARITY_ENTRY, why, sizeof why)) {
        snprintf(err, errlen, "the module list is not the tree: %s", why);
        return -1;
    }
    memset(sources, 0, sizeof sources);
    if (!ng_parity_imports_present(missing, sizeof missing)) {
        snprintf(err, errlen, "validate.nova imports %s and the parity module list does not carry it",
                 missing);
        return -1;
    }
    for (i = 0; i < NG_PARITY_MODULES; i++) {
        size_t n = 0;
        sources[i] = ng_parity_loadf(ng_parity_paths[i], &n);
        if (!sources[i]) {
            snprintf(err, errlen, "cannot read %s", ng_parity_paths[i]);
            for (i = 0; i < NG_PARITY_MODULES; i++) free(sources[i]);
            return -1;
        }
        inputs[i].name = ng_parity_paths[i];
        inputs[i].text = sources[i];
        inputs[i].length = n;
    }
    st->compiled = nova_compile_many_v2(inputs, NG_PARITY_MODULES, &st->artifact);
    for (i = 0; i < NG_PARITY_MODULES; i++) free(sources[i]);
    if (!st->compiled) {
        snprintf(err, errlen, "the 43 module validate image does not compile: code %u at line %zu",
                 st->artifact.error.code, st->artifact.error.line);
        return -1;
    }
    if (!nova_host_map(&st->artifact, &st->image) || !st->image.entry) {
        snprintf(err, errlen, "the 43 module validate image does not map");
        nt_artifact_free(&st->artifact);
        st->compiled = 0;
        return -1;
    }
    st->open = 1;
    if (ng_parity_ask_stage_table(st) != 0) {
        snprintf(err, errlen, "the validate image published no stage table");
        return -1;
    }
    for (i = 0; i < NG_PARITY_STAGES; i++) {
        size_t n = strlen(ng_parity_stage_names[i]);
        if (at + n + 1 > st->stage_len || memcmp(st->stage_bytes + at, ng_parity_stage_names[i], n) != 0
            || st->stage_bytes[at + n] != 0) {
            snprintf(err, errlen, "the validate image publishes stage %u as %s, this header claims %s",
                     (unsigned)(i + 1), at < st->stage_len ? st->stage_bytes + at : "<end>", 
                     ng_parity_stage_names[i]);
            return -1;
        }
        at += n + 1;
    }
    if (at != st->stage_len) {
        snprintf(err, errlen, "the validate image publishes %zu bytes of stage table, this header claims %zu",
                 st->stage_len, at);
        return -1;
    }
    return 0;
}

NG_PARITY_UNUSED static void ng_parity_close(void) {
    NgParityState *st = &ng_parity_state;
    if (st->image.memory) nova_host_unmap(&st->image);
    if (st->compiled) nt_artifact_free(&st->artifact);
    st->compiled = 0;
    st->open = 0;
}

/* The pipeline's verdict on one source, through the same four word calling
   convention the sub-chain gates use, so the two verdicts are comparable word
   for word and not through a widened out the unit gates never see. */
/* `ok` is 0 on a question that was asked and 1 on one that could not be, and
   the caller FAILS on 1.  The first version returned a plain 0 when the
   context would not initialise, and 0 is the pipeline's "accepted": a helper
   that could not ask would have been indistinguishable from a pipeline that
   said yes, which is the one thing this file must never be. */
NG_PARITY_UNUSED static uint64_t ng_parity_run(const char *src, int *ok) {
    NgParityState *st = &ng_parity_state;
    const uint64_t guard = UINT64_C(0xcccccccccccccccc);
    uint64_t out[4] = {guard, guard, guard, guard};
    NovaContextV2 c = {0};
    uint64_t sh, oh, a[4], code;
    *ok = 0;
    if (!st->open) return 0;
    if (!nova_context_init_v2(&c)) return 0;
    sh = nova_borrow_v2(&c, (void *)src, strlen(src), 0);
    oh = nova_borrow_v2(&c, out, sizeof out, 1);
    a[0] = sh; a[1] = strlen(src); a[2] = oh; a[3] = 4;
    code = st->image.entry(&c, a, 4);
    (void)nova_context_destroy_v2(&c);
    *ok = (c.error == 0) ? 1 : 0;
    return code;
}

/* ==========================================================================
   The comparison.
   ========================================================================== */

/* The mask of the stages the entry runs, so the checks can ask whether the
   pipeline's verdict is one of the entry's own stages. */
NG_PARITY_UNUSED static uint64_t ng_parity_mask_of(const NgParitySpec *sp) {
    uint64_t m = 0;
    unsigned i;
    for (i = 0; i < sp->stage_count && i < NG_PARITY_MAX_STAGES; i++) {
        int k = ng_parity_stage_index(sp->stages[i]);
        if (k > 0) m |= UINT64_C(1) << (k - 1);
    }
    return m;
}

/* Whether the entry's stage set is a PREFIX of the 34 stage order: stages
   1..m all present and nothing after.  When it is, equality of the two
   verdicts is demanded outright and the declared divergence table must be
   empty, because a chain that is a prefix cannot be answered differently by
   a stage it already ran.  When it is not -- 35 of the 36 sub-chains -- the
   equality is unsatisfiable by construction and the declared table is the
   contract instead.  A gate cannot choose: the answer comes from the stage
   set the gate declares, checked against the order the IMAGE publishes. */
NG_PARITY_UNUSED static int ng_parity_prefix_yes(const NgParitySpec *sp) {
    uint64_t m = ng_parity_mask_of(sp);
    int i, seen_gap = 0;
    for (i = 0; i < NG_PARITY_STAGES; i++) {
        int has = (int)((m >> i) & 1u);
        if (!has) seen_gap = 1;
        else if (seen_gap) return 0;
    }
    return sp->stage_count > 0;
}

NG_PARITY_UNUSED static int ng_parity_declared(NgParitySpec *sp, uint64_t e, uint64_t p) {
    unsigned i;
    for (i = 0; i < sp->declared_count; i++)
        if (sp->declared[i].entry_code == e && sp->declared[i].pipe_code == p) {
            if (sp->declared_seen) sp->declared_seen[i] = 1;
            return 1;
        }
    return 0;
}

/* Build the pipeline image and take ownership of the declared-pair ledger,
   before the gate's first assertion.  Returns 0 on success; on failure the
   gate is already red and must not run its cases, because a parity-aware
   gate that never opened its pipeline would report agree=0 and read as
   clean.  err must be at least 256 bytes. */
NG_PARITY_UNUSED static int ng_parity_begin(NgParitySpec *sp, unsigned *failures,
                                            char *err, size_t errlen) {
    if (ng_parity_open(err, errlen) != 0) {
        (*failures)++;
        fprintf(stderr, "FAIL parity %s: the pipeline image is not available: %s\n", sp->entry, err);
        return -1;
    }
    sp->checked = sp->agree = sp->diverged = sp->weaker = sp->both_ok = sp->unattributed = 0;
    sp->declared_seen = NULL;
    if (sp->declared_count > 0) {
        sp->declared_seen = (unsigned char *)calloc(sp->declared_count, 1);
        if (!sp->declared_seen) {
            (*failures)++;
            fprintf(stderr, "FAIL parity %s: no ledger for %u declared divergences\n",
                    sp->entry, sp->declared_count);
            return -1;
        }
    }
    return 0;
}

/* The one call a parity-aware assertion makes.  `entry_code` is what the
   gate's own entry returned -- the gate has already asserted it, this is not
   a second opinion on it -- and the pipeline is asked the same question.
   Counters are the gate's own, so the helper never keeps a private tally the
   gate's summary does not show. */
NG_PARITY_UNUSED static void ng_parity_check_as(unsigned *checks, unsigned *failures,
                                                NgParitySpec *sp, const char *name,
                                                const char *src, uint64_t entry_code,
                                                const NgParityCall *call) {
    char eb[256], pb[256];
    uint64_t pipe_code, mask;
    int at, pe, pp, asked, verdict;
    unsigned i, nst;
    (*checks)++;
    if (!ng_parity_state.open) return;
    pipe_code = ng_parity_run(src, &asked);
    sp->checked++;
    if (!asked) {
        (*failures)++;
        fprintf(stderr, "FAIL parity %s/%s: the pipeline could not be asked about this source,"
                        " so nothing was measured\n", sp->entry, name);
        return;
    }
    /* Which stages THIS call ran, and whether its return value is a stage
       verdict at all.  A gate whose entry has one path declares nothing and
       gets the link set, which is then exactly right. */
    if (call) { nst = call->stage_count; verdict = call->verdict; }
    else      { nst = sp->stage_count;  verdict = 1; }
    mask = 0;
    for (i = 0; i < nst && i < NG_PARITY_MAX_STAGES; i++) {
        const char *nm = call ? call->stages[i] : sp->stages[i];
        int k = ng_parity_stage_index(nm);
        if (k > 0) mask |= UINT64_C(1) << (k - 1);
        else {
            (*failures)++;
            fprintf(stderr, "FAIL parity %s/%s: the call declares stage %u named %s, which is not"
                            " one of the 34 stages\n", sp->entry, name, i, nm);
        }
    }
    if (!verdict) { sp->probe++; return; }
    if (entry_code == 0 && pipe_code == 0) { sp->both_ok++; return; }
    if (entry_code == 0) {
        /* The B direction: a sub-chain accepts what the pipeline refuses.  That
           is the expected weakness of a gate that runs one stage, not a wrong
           diagnostic, so it is counted and never failed.  What it does NOT get
           to do is hide a code the entry's own chain could have produced: if a
           stage this entry runs can return that code, and the entry accepted,
           then the entry is not asking the stage it declares, and THAT is a
           defect in the chain rather than the expected weakness. */
        sp->weaker++;
        /* Only a code that NAMES ONE stage can show that this entry ran the
           stage the pipeline stopped at.  A code several stages can return
           cannot, and asking it to is how the refs gate was made red for a
           pipeline that was right: 310 is refs(27) and calls(28), the
           pipeline stopped at calls(28), and the entry links only refs(27). */
        at = ng_parity_unique_owner(pipe_code);
        if (at > 0 && (mask & (UINT64_C(1) << (at - 1)))) {
            (*failures)++;
            ng_parity_owners_text(pipe_code, pb, sizeof pb);
            fprintf(stderr, "FAIL parity %s/%s: THIS CALL accepted, the pipeline refuses with %llu,"
                            " and %llu is the verdict of stage %u (%s), a stage THIS CALL runs\n",
                    sp->entry, name, (unsigned long long)pipe_code,
                    (unsigned long long)pipe_code, (unsigned)at, pb);
        }
        return;
    }
    /* 800 is the structural refusal EVERY stage of this pipeline emits, and the
       parser emits it too: it names a tree or an out buffer the stage cannot
       work with, never a defect in the module.  A gate that asserts it is
       asserting the CALLING CONVENTION, not a stage, so it is not compared.
       The helper always lends four words, and a case that deliberately lends
       three is testing exactly the width, which the pipeline cannot be asked
       about through a four word call.  Counted, named, never compared, and the
       limit is in the banner. */
    if (entry_code == 800) { sp->structural++; return; }
    if (ng_parity_owners(entry_code) == 0) {
        /* A code no stage of this pipeline emits: a lexer code, a macro budget
           code, or the gate's own (decls' 812).  Not a verdict of the pipeline,
           so parity is not the question -- but it is still counted, because "not
           a pipeline verdict" is a claim and the banner is where it is made
           visible. */
        sp->unattributed++;
    }
    if (!sp->claims) {
        /* The gate says its codes are not pipeline verdicts, and this one IS
           one, so the declaration is wrong and the gate is being run on an
           assumption the tree has just disproved. */
        (*failures)++;
        ng_parity_owners_text(entry_code, pb, sizeof pb);
        fprintf(stderr, "FAIL parity %s/%s: this entry asserts %llu, which IS a stage verdict"
                        " (%s), while the gate declares it asserts no pipeline verdict\n",
                sp->entry, name, (unsigned long long)entry_code, pb);
        return;
    }
    if (entry_code == pipe_code) { sp->agree++; return; }
    /* Both sides refuse and the two codes differ.  This is the 759. */
    if (ng_parity_declared(sp, entry_code, pipe_code)) { sp->diverged++; return; }
    (*failures)++;
    sp->diverged++;
    ng_parity_owners_text(entry_code, eb, sizeof eb);
    ng_parity_owners_text(pipe_code, pb, sizeof pb);
    pe = ng_parity_first_owner(entry_code);
    pp = ng_parity_first_owner(pipe_code);
    /* The two questions, told apart.  "The pipeline objected at an EARLIER
       stage" is the expected shape of a sub-chain gate and is what almost
       every declared pair is; "the entry's stage is one the pipeline reaches
       LATER" is the other shape and is the one worth opening.  Saying which
       is the difference between a naming problem in the harness and a real
       ordering question, and a message that only said "they differ" would
       leave the reader to work that out from the stage numbers. */
    fprintf(stderr, "FAIL parity %s/%s: this entry asserts %llu (%s); the 43 module pipeline answers"
                    " %llu (%s) for the same source. %s. Declare the pair in this harness with the"
                    " reason written down, or fix the assertion.\n",
            sp->entry, name, (unsigned long long)entry_code, eb,
            (unsigned long long)pipe_code, pb,
            (pe == 0 || pp == 0)
                ? "One of the two codes names no single stage, so the direction is not derivable"
                : (pp < pe ? "The pipeline objected at an EARLIER stage than the one this entry asserts"
                           : (pp > pe ? "The entry asserts a stage the pipeline reaches LATER"
                                      : "Both name the same stage and still differ")));
}

/* The link set, as the default call: right for a gate whose entry has one
   path, and the thing a caller overrides the moment it has modes. */
NG_PARITY_UNUSED static void ng_parity_check(unsigned *checks, unsigned *failures,
                                             NgParitySpec *sp, const char *name,
                                             const char *src, uint64_t entry_code) {
    ng_parity_check_as(checks, failures, sp, name, src, entry_code, NULL);
}

/* The banner.  It states what the helper measured, what it did NOT measure,
   and which of its own checks are unproven -- the limits live in the artefact
   and not only in a report. */
NG_PARITY_UNUSED static int ng_parity_finish(NgParitySpec *sp, unsigned *failures) {
    unsigned i;
    int bad = 0;
    /* Every stage the gate names must be one of the 34, or its mask is a guess
       and the accept direction check above is vacuous for it. */
    for (i = 0; i < sp->stage_count && i < NG_PARITY_MAX_STAGES; i++) {
        if (ng_parity_stage_index(sp->stages[i]) == 0) {
            (*failures)++;
            bad = 1;
            fprintf(stderr, "FAIL parity %s: stage %u named %s is not one of the 34 stages\n",
                    sp->entry, i, sp->stages[i]);
        }
    }
    if (sp->stage_count == 0) {
        (*failures)++;
        bad = 1;
        fprintf(stderr, "FAIL parity %s: names no stage, so the helper measures nothing about this entry\n",
 sp->entry);
    }
    /* A chain that is a prefix of the stage order cannot be answered
       differently, so a declared divergence under one is a contradiction
       between two declarations and the gate must not be trusted to pick. */
    if (ng_parity_prefix_yes(sp) && sp->declared_count > 0) {
        (*failures)++;
        bad = 1;
        fprintf(stderr, "FAIL parity %s: the stage set is a prefix of the 34 stage order, so the two"
                        " verdicts must be equal, yet %u divergences are declared\n",
                sp->entry, sp->declared_count);
    }
    /* Every declared divergence must actually occur.  A baseline nobody
       reaches is a comment, and this is what stops it from being one. */
    for (i = 0; i < sp->declared_count; i++) {
        if (sp->declared_seen && !sp->declared_seen[i]) {
            (*failures)++;
            bad = 1;
            fprintf(stderr, "FAIL parity %s: declared divergence %llu vs pipeline %llu never occurs;"
                            " delete it or restore the case that produced it\n",
                    sp->entry, (unsigned long long)sp->declared[i].entry_code,
                    (unsigned long long)sp->declared[i].pipe_code);
        }
    }
    printf("NTASM_PARITY %s modules=%d stages=%d checked=%u agree=%u diverged=%u"
           " weaker=%u both_ok=%u structural=%u unattributed=%u probe=%u declared=%u prefix=%s\n",
           sp->entry, NG_PARITY_MODULES, NG_PARITY_STAGES, sp->checked, sp->agree,
           sp->diverged, sp->weaker, sp->both_ok, sp->structural, sp->unattributed,
           sp->probe, sp->declared_count, ng_parity_prefix_yes(sp) ? "yes" : "no");
    printf("NTASM_PARITY_CLAIMS %s claims=%s\n", sp->entry, sp->claims ? "pipeline_verdicts" : "own_codes");
    printf("NTASM_PARITY_LIMITS %s limits=code_attribution_300_365_only,"
           "code_attribution_not_rederived_by_the_build,"
           "no_which_stage_the_pipeline_stopped_at(only_the_whole_pipeline_verdict),"
           "b_direction_accept_weaker_counted_not_failed,"
           "code_800_structural_not_compared(under_lent_out_is_not_a_stage_verdict),"
           "spec_stage_set_is_a_link_set(the_b_direction_uses_the_per_call_set),"
           "gates_without_the_header_are_not_covered\n", sp->entry);
    free(sp->declared_seen);
    sp->declared_seen = NULL;
    ng_parity_close();
    return bad;
}

#endif /* NG_NTASM_PIPELINE_PARITY_H */
