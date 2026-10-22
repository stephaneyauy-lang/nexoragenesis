#define _GNU_SOURCE
#include <unistd.h>
#include <signal.h>
static pid_t pipeline_bounded_fork(void) { pid_t p=fork(); if(p==0)alarm(5); return p; }
#define fork pipeline_bounded_fork
#define checks pe_checks
#define failures pe_failures
#define cases pe_cases
#pragma push_macro("main")
#undef main
#define main pe_reference_gate_main
#include "tests_ntasm_pe_exec.c"
#undef main
#pragma pop_macro("main")
#undef cases
#undef failures
#undef checks
#undef fork
#undef CHECK
#include "../../../compiler/c/ntasm/formats/object.h"

/* tests_ntasm_machine_pipeline.c -- THE PIPELINE'S GATE.
 *
 * WHAT THIS GATE IS FOR. machine_ir.nova builds a Machine IR, machine_emit.nova
 * (machine_x64.nova until 6 October 2026) reads one and writes an NXO container, and until machine_pipeline.nova existed
 * the only thing that drove the two in sequence was a test entry that threw the
 * image away. So the chain was measurable and unreachable. This gate drives the
 * new module and asserts the three things that make it a chain rather than three
 * calls in a row:
 *
 *   1. THE SAME BYTES OUT OF BOTH FACES. `build_pe(source,...)` and
 *      `build_pe_from_image(words[3],...)` must produce the same container from
 *      the same program, and the second face parses nothing -- so if they agree,
 *      the second one is a function of the image.
 *   2. A DAMAGED IMAGE STOPS OR CHANGES THE EMISSION, on the object path AND on
 *      the executable path. Three perturbations, each aimed at a different
 *      reader, each measured before it was pinned (the first attempt aimed one
 *      of them at a record nobody reads and it measured nothing at all: same
 *      code, same 336 bytes; the comment in the entry says which record and
 *      why).
 *   3. A REFUSAL NAMES ITS STAGE. Every red row asserts the code AND
 *      report[8], so a reader can tell a refusal from the object writer from a
 *      refusal from the NXO reader, which are the same number from different
 *      modules.
 *
 * TWO INDEPENDENTLY COMPILED IMAGES, and every case runs on both. One image is a
 * single sample.
 *
 * Semantic stage results and symbol identities are pinned below. Container
 * lengths and relocated text are checked against the independent C object
 * reader, writer and materializer. Successful PE images are also executed and
 * compared with an independent compilation of the source, on both passes.
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

/* THE HOST'S ERROR CODES, from compiler/c/nova/runtime/runtime_v2.h, where
 * they are an enum. A gate that wrote the numbers itself would be able to agree
 * with itself after the header renumbered, and would be wrong silently. */
#define NV2_BOUNDS 4

#define BANNER "NTASM_NOVA_MACHINE_PIPELINE checks=%u failures=%u cases=%u"

/* Every module the entry reaches, by import closure: machine_pipeline_entry
 * imports the parser, the lexer, ntir, machine_ir, ntasm_nxo, ntasm_nxo_pe and
 * machine_pipeline; machine_pipeline imports machine_emit, which imports
 * machine_ir, x64_fixed, ntasm_nxo and effects; machine_ir imports ntir and
 * register_widths; ntasm_nxo_pe imports ntasm_nxo and ntasm_pe. */
static const char *const PATHS[] = {
"tests/nova/tests/machine-pipeline-entry.nova",
"compiler/nova/ir/machine_pipeline.nova",
    "compiler/nova/frontend/stub_table.nova",
    "compiler/nova/analysis/validate.nova",
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
    "compiler/nova/ir/machine_ir.nova",
    "compiler/nova/backend/nova/machine_emit.nova",
    "compiler/nova/backend/x64/x64_fixed.nova",
    "compiler/nova/formats/nxo/nxo.nova",
    "compiler/nova/formats/nxo/nxo_pe.nova",
    "compiler/nova/formats/pe/pe.nova",
};
#define PATHS_N ((unsigned)(sizeof PATHS / sizeof PATHS[0]))

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

/* The corpus. Six bodies, one per shape the pipeline is asked to route, and the
 * shapes are chosen so the table has BOTH verdicts in it: three the encoder can
 * express and three it cannot, so a gate that collapsed "produced an image" and
 * "refused with a reason" into one notion would be red on half the rows.
 *
 * The prologue is the one the consumer's own gate uses, spelled out here rather
 * than shared, because a corpus borrowed from another gate's macro is a corpus
 * that moves when that macro moves. */
#define PROLOGUE "module m\ntarget x86_64-nexora-none\nsection .text {\n" \
                 "fn main()->u64\neffects {}\nclobbers "
#define EPILOGUE "}\n}\n"

typedef struct {
  const char *name;
  const char *body;
} Body;

static const Body BODIES[] = {
    /* THE SMALLEST PROGRAM THAT PRODUCES AN IMAGE. nop; return 42. */
    {"return42", PROLOGUE "{rax} {\nnop\nreturn 42\n" EPILOGUE},
    /* A SECOND CONSTANT, so a gate that pins one immediate is a gate that pins
     * a literal and not a path. */
    {"return7", PROLOGUE "{rax} {\nnop\nreturn 7\n" EPILOGUE},
    /* THE ADDITION, IN THE FORM THE LANGUAGE ACCEPTS. `mov rax, 5` FIRST: an
     * `in v:u64 @rax` parameter does NOT give a body the right to modify that
     * register, and the row that tried it was refused at 335 -- which is the
     * validator doing its job, not a positive addition. So the register is
     * INITIALISED in the body, the flags are declared, and the value comes from
     * nowhere but the instruction that wrote it. */
    {"add-self",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn main()->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\n"
     "mov rax, 5\nadd rax, 1\nreturn rax\n}\n}\n"},
    /* A REAL TWO-ARM BRANCH. The condition is a DECLARED PARAMETER, not the
     * `feature(sse2)` pseudo-call the earlier row used -- that one is refused at
     * 310 because `feature` is not a declared name, so the row was measuring an
     * undeclared function rather than a branch. The shape, the `let`s and the
     * `if w>0 { } else { }` spelling are the ones ATTR_DIAMOND in
     * tests_ntasm_machine_ir.c already validates, and the arms compute constants
     * rather than `a*3`, so the row measures the branch and not a multiply. */
    {"branch",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn main(in w:u8)->u64\neffects {}\nclobbers {rax,rsi} {\n"
     "let a:u64=1\nif w>0 {\nlet b:u64=2\nmov rsi,b\n}\nelse {\n"
     "let c:u64=3\nmov rsi,c\n}\nreturn rsi\n}\n}\n"},
    /* THE MACRO CASE. Shape and spelling are the ones tests_ntasm_splice.c
     * already uses for `expanded once`: a macro that expands to `return $v`,
     * invoked in the body. It exists because the expansion is the thing that was
     * silently lost -- a pipeline reparsing the caller's text would lower a body
     * with no expansion in it and would still produce a PE, for the WRONG one. */
    {"macro-ret42",
     "module m\ntarget x86_64-nexora-none\n"
     "macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\n"
     "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\n"
     "expand ret(42)\n}\n}\n"},
    /* THE SAME MACRO, A DIFFERENT ARGUMENT. Two rows because one macro row pins
     * a literal and not an expansion. */
    {"macro-ret7",
     "module m\ntarget x86_64-nexora-none\n"
     "macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\n"
     "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\n"
     "expand ret(7)\n}\n}\n"},
    /* AN IMPORT, AND THE ROW THAT SEPARATES TWO CLAIMS. This body is the
     * IMPORTER the x64_lower_nxo corpus already uses: one unresolved import, one
     * call to it, one caller. Two facts live here and the gate keeps them apart:
     * the NXO OBJECT may be valid -- an undefined symbol and a relocation against
     * it are a normal object -- while a PE produced from it ALONE cannot exist.
     * So this row expects the two faces to DISAGREE. */
    {"import-call",
     "module m\ntarget x86_64-nexora-uefi\nimport api.echo as ext: fn()->u64\n"
     "effects {}\nclobbers {}\nsection .text {\nexport fn main()->u64\n"
     "effects {}\nclobbers {} {\ncall ext()\nreturn 0\n}\n}\n"},
    /* THE IMPORT, ISOLATED IN THREE PIECES. The `import-call` row above faults
     * in the HOST (NV2_BOUNDS) while the module answers 0, and a fault that
     * names nothing is not an instrument. These three rows separate the parts:
     * a declaration alone, a call with no declaration, and the two together.
     * Whichever piece faults is where the bounds are, and the piece that does
     * NOT fault is what says the fault is not in the other one. */
    {"import-only",
     "module m\ntarget x86_64-nexora-uefi\nimport api.echo as ext: fn()->u64\n"
     "effects {}\nclobbers {}\nsection .text {\nexport fn main()->u64\n"
     "effects {}\nclobbers {} {\nreturn 0\n}\n}\n"},
    {"call-local",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "export fn main()->u64\neffects {}\nclobbers {} {\ncall helper()\n"
     "return 0\n}\n}\n"},
    /* THREE OPERANDS ON A TWO-OPERAND INSTRUCTION. The spelling is the one
     * tests_ntasm_validate_expanded.c already uses for its own 944 row, quoted
     * rather than rewritten, so the two gates measure one fact about one program.
     * `cmp` writes the flags and takes two operands; the third is the point. */
    {"cmp3",
     "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\n"
     "effects {changes_flags}\nclobbers {rax,rbx,rcx} {\n"
     "cmp rax, rbx, rcx\nreturn 0\n}\n}\n"},
    /* DELIBERATELY INVALID, and pinned as the refusal it is: `add` without
     * `changes_flags` and over a register nothing wrote. This is the row that
     * answers "validation refused => no PE, and the diagnostic reaches the
     * caller". It is kept DISTINCT from `add-self`: the two differ by two
     * declarations, and one row would make the difference invisible. */
    {"undeclared-flags",
     "module m\ntarget x86_64-nexora-none\nsection .text {\n"
     "fn main()->u64\neffects {}\nclobbers {rax} {\n"
     "add rax, 1\nreturn rax\n}\n}\n"},
    /* A LITERAL DATA SECTION AND A LOAD FROM IT, in the syntax the corpus uses
     * (`data NAME:TYPE=VALUE`) rather than an invented one. */
    {"data",
     "module m\ntarget x86_64-nexora-uefi\nsection .data {\n"
     "    data counter:u64=40\n}\nsection .text {\nexport fn main()->u64\n"
     "effects {reads_mem(user),writes_mem(user),changes_flags}\n"
     "clobbers {rax,rflags} {\n    load rax,[counter]:ptr<user,u64>\n"
     "    return rax\n}\n}\n"},
    /* THE SAME THREE SHAPES ON THE UEFI TARGET, added 6 October 2026 when the
     * emitter changed. Every body above but the import and data rows declares
     * `x86_64-nexora-none`, and an object for that target has no PE:
     * ntasm_nxo_pe answers 802, the refusal the C object path gives too. The old
     * backend stamped target 1 on every object whatever the source said, which
     * is why those rows used to reach a PE. These three keep the executable
     * face, the byte pins and the expansion proof measurable without editing
     * the rows above, whose refusal is now the fact they pin. */
    {"uefi-return42",
     "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main()->u64\neffects {}\nclobbers {rax} {\nnop\nreturn 42\n}\n}\n"},
    {"uefi-macro-ret42",
     "module m\ntarget x86_64-nexora-uefi\n"
     "macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\n"
     "section .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\n"
     "expand ret(42)\n}\n}\n"},
    {"uefi-add",
     "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\n"
     "mov rax, 5\nadd rax, 1\nreturn rax\n}\n}\n"},
};
#define BODIES_N ((unsigned)(sizeof BODIES / sizeof BODIES[0]))

/* The five stages every case runs, by the entry's own mode number. `pre` is the
 * mode that must have filled the caller's buffers first: the image faces read
 * `words`, and mode 3 is what fills it. */
typedef struct {
  uint64_t mode;
  uint64_t pre;
  const char *label;
} Stage;

static const Stage STAGES[] = {
    {3, 0, "lower"},
    {1, 0, "build_object"},
    {2, 0, "build_pe"},
    {4, 3, "object_from_image"},
    {5, 3, "pe_from_image"},
};
#define STAGES_N ((unsigned)(sizeof STAGES / sizeof STAGES[0]))

static const char *stage_label(unsigned s) { return STAGES[s].label; }

/* Source verdicts, symbol identity and fault classes are normative.
 * Frame sizes are checked by an independent C NXO roundtrip, and executable
 * semantics by the reference C producer plus the independent PE loader.
 * This replaces byte arrays captured from an older generated frame. */
typedef struct {
  const char *name;
  uint64_t code[STAGES_N];
  uint64_t symbols, entry, host_err;
} Expectation;

static const Expectation EXPECT[] = {
    {"return42", {0, 0, 802, 0, 802}, 0, 0, 0},
    {"return7", {0, 0, 802, 0, 802}, 0, 0, 0},
    {"add-self", {0, 0, 802, 0, 802}, 0, 0, 0},
    /* A4 transports typed parameters: object succeeds, PE still refuses absent entry. */
    {"branch", {0, 0, 802, 0, 802}, 0, 0, 0},
    {"macro-ret42", {0, 0, 802, 0, 802}, 0, 0, 0},
    {"macro-ret7", {0, 0, 802, 0, 802}, 0, 0, 0},
    {"import-call", {0, 0, 804, 0, 804}, 0, 0, 0},
    {"import-only", {0, 0, 804, 0, 804}, 0, 0, 0},
    {"call-local", {310, 310, 310, 980, 980}, 0, 0, 0},
    {"cmp3", {944, 944, 944, 980, 980}, 0, 0, 0},
    {"undeclared-flags", {334, 334, 334, 980, 980}, 0, 0, 0},
    {"data", {0, 0, 0, 0, 0}, 2, 2, 0},
    {"uefi-return42", {0, 0, 0, 0, 0}, 1, 1, 0},
    {"uefi-macro-ret42", {0, 0, 0, 0, 0}, 1, 1, 0},
    {"uefi-add", {0, 0, 0, 0, 0}, 1, 1, 0},
};
#define EXPECT_N ((unsigned)(sizeof EXPECT / sizeof EXPECT[0]))

/* The perturbations, by the entry's own index, with the code each one MEASURED
 * on this corpus. The table is keyed by name against nothing -- these are
 * perturbations of the image, not of a body, so there is one row per index and
 * it runs on one body. The body is named beside it because a perturbation with
 * no stated subject is a perturbation nobody can reproduce. */
typedef struct {
  uint64_t index;
  const char *subject;
  const char *label;
  uint64_t obj_code;
  uint64_t pe_code;
} Perturbation;

static const Perturbation PERTURB[] = {
    {0, "uefi-return42", "canary, no damage", 0, 0},
    {1, "uefi-return42", "record count minus one", 980, 980},
    {2, "uefi-return42", "the function record's kind", 980, 980},
    {3, "uefi-return42", "the function's name span past the source", 980, 980},
};
#define PERTURB_N ((unsigned)(sizeof PERTURB / sizeof PERTURB[0]))

/* The vocabulary the module publishes, read back through the entry rather than
 * written here, so a gate with its own copies of the numbers can only say they
 * agree today. */
typedef struct {
  uint64_t e_output;
  uint64_t e_bound;
  uint64_t stage[10];
  uint64_t report_words;
  uint64_t mir_pin;
  uint64_t nxo_version;
} Vocabulary;

/* ONE ENTRY CALL. Fourteen flat slots: three scalars and five buffers, each
 * buffer taking a handle and an element count. */
typedef struct {
  uint64_t *words;
  uint64_t *out;
  uint64_t length[4];
  uint64_t report[REPORT];
  uint64_t returned;
  uint64_t runtime;
  uint64_t out_bytes;
} Run;

static void run_init(Run *r) {
  r->words = malloc(WORDS * sizeof(uint64_t));
  r->out = malloc(TEXT);
  if (!r->words || !r->out) {
    fprintf(stderr, "SMOKE allocation failed\n");
    exit(2);
  }
  memset(r->words, 0, WORDS * sizeof(uint64_t));
  memset(r->out, 0, TEXT);
  for (unsigned i = 0; i < REPORT; i++)
    r->report[i] = GUARD;
  for (unsigned i = 0; i < 4; i++)
    r->length[i] = GUARD;
  r->out_bytes = TEXT;
}

static void run_free(Run *r) {
  free(r->words);
  free(r->out);
}

static uint64_t run(const NovaHostImage *image, const char *source, size_t size,
                    uint64_t mode, uint64_t index, Run *r) {
  NovaContextV2 c = {0};
  for (unsigned i = 0; i < REPORT; i++)
    r->report[i] = GUARD;
  for (unsigned i = 0; i < 4; i++)
    r->length[i] = GUARD;
  memset(r->out, 0xcc, r->out_bytes);
  if (!nova_context_init_v2(&c)) {
    r->runtime = 1;
    return ~0ULL;
  }
  uint64_t sh = nova_borrow_v2(&c, (void *)source, size, 0);
  uint64_t wh = nova_borrow_v2(&c, r->words, WORDS * sizeof(uint64_t), 1);
  uint64_t oh = nova_borrow_v2(&c, r->out, r->out_bytes, 1);
  uint64_t lh = nova_borrow_v2(&c, r->length, 1 * sizeof(uint64_t), 1);
  uint64_t rh = nova_borrow_v2(&c, r->report, REPORT * sizeof(uint64_t), 1);
  uint64_t args[] = {sh,     size,  mode, index, wh,   WORDS, WORDS,
                     oh,     r->out_bytes, r->out_bytes, lh, 1, rh, REPORT};
  r->returned = image->entry(&c, args, 14);
  r->runtime = c.error;
  if (c.error) fprintf(stderr,"RUNTIME_LOCATION mode=%llu source=%llu offset=%llu error=%llu\n",(unsigned long long)mode,(unsigned long long)c.error_source,(unsigned long long)c.error_offset,(unsigned long long)c.error);
  /* THE MODULE'S RETURN IS RETURNED EVEN WHEN THE HOST IS ANGRY. An earlier
   * version of this helper replaced a non-zero `c.error` with ~0, which merged
   * two different facts -- "the module refused" and "the runtime faulted" --
   * into one number that looks like a verdict. On the import row that made a
   * BOUNDS fault indistinguishable from a refusal, and the report came back all
   * zeros beside it. The fault is now published as its own word and the module's
   * own answer survives beside it. */
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return r->returned;
}

/* Where the object's own text sits inside the PE image, or 0. The gate asserts
 * that the PE CONTAINS the bytes the object carries rather than pinning the PE's
 * 3072 bytes: a container that grew a section would move every offset in it, and
 * the property worth keeping is that the program's bytes survived the two
 * hand-offs. */
/* WHERE THE PROGRAM'S OWN BYTES LIVE INSIDE A PE, read out of the PE's own
 * section table. This is an INSTRUMENT, not an assertion: it is what turns "the
 * PE carries the object's bytes" into a claim a reader can check by eye, because
 * the bytes are printed from the image the run produced rather than written down
 * from a reading of the producer. Zero when the image is not a PE at all. */
static uint64_t pe_text_offset(const uint8_t *image, uint64_t size) {
  if (size < 0x40 || image[0] != 'M' || image[1] != 'Z')
    return 0;
  uint32_t pe_off = (uint32_t)image[0x3c] | ((uint32_t)image[0x3d] << 8) |
                    ((uint32_t)image[0x3e] << 16) | ((uint32_t)image[0x3f] << 24);
  if (pe_off + 24 > size)
    return 0;
  const uint8_t *coff = image + pe_off + 4;
  uint16_t sections = (uint16_t)(coff[2] | (coff[3] << 8));
  uint16_t opt = (uint16_t)(coff[16] | (coff[17] << 8));
  const uint8_t *opt_head = coff + 20;
  const uint8_t *table = opt_head + opt;
  for (uint16_t i = 0; i < sections; i++) {
    const uint8_t *sh = table + (uint32_t)i * 40;
    if ((uint64_t)(sh - image) + 40 > size)
      return 0;
    if (sh[0] == '.' && sh[1] == 't' && sh[2] == 'e' && sh[3] == 'x' &&
        sh[4] == 't') {
      uint32_t raw = (uint32_t)sh[20] | ((uint32_t)sh[21] << 8) |
                     ((uint32_t)sh[22] << 16) | ((uint32_t)sh[23] << 24);
      return raw;
    }
  }
  return 0;
}

static uint64_t find_bytes(const Run *r, const uint8_t *want, uint64_t n) {
  if (n == 0)
    return 0;
  for (uint64_t i = 0; i + n <= r->length[0]; i++) {
    uint64_t same = 1;
    for (uint64_t k = 0; k < n; k++) {
      if (((const uint8_t *)r->out)[i + k] != want[k])
        same = 0;
    }
    if (same)
      return i;
  }
  return 0;
}

static int same_container(const unsigned char *a, size_t na,
                          const unsigned char *b, size_t nb) {
  return na==nb && (na==0 || (a && b && memcmp(a,b,na)==0));
}
int main(void) {
  size_t sizes[PATHS_N] = {0};
  char *sources[PATHS_N] = {0};
  NtFInput inputs[PATHS_N];
  int all = 1;
  for (unsigned i = 0; i < PATHS_N; i++) {
    sources[i] = loadf(PATHS[i], &sizes[i]);
    if (!sources[i])
      all = 0;
    inputs[i] = (NtFInput){PATHS[i], sources[i], sizes[i]};
  }
  CHECK(all, "the fifteen Nova sources load");
  if (!all) {
    printf(BANNER "\n", checks, failures, cases);
    return 1;
  }

  NtArtifact first = {0}, second = {0};
  int c1 = nova_compile_many_v2(inputs, PATHS_N, &first);
  int c2 = nova_compile_many_v2(inputs, PATHS_N, &second);
  CHECK(c1, "the Nova sources compile");
  CHECK(c2, "the Nova sources compile a second time");
  if (!c1 || !c2) {
    if (!c1)
      fprintf(stderr, "E%u %zu:%zu %s\n", first.error.code, first.error.line,
              first.error.column, first.error.message);
    if (!c2)
      fprintf(stderr, "E%u %zu:%zu %s\n", second.error.code, second.error.line,
              second.error.column, second.error.message);
    printf(BANNER "\n", checks, failures, cases);
    return 1;
  }
  NovaHostImage ia = {0}, ib = {0};
  CHECK(nova_host_map(&first, &ia), "the first image maps");
  CHECK(nova_host_map(&second, &ib), "the second image maps");
  CHECK(ia.entry != ib.entry, "independent images use distinct mappings");
  if (!ia.memory || !ib.memory) {
    printf(BANNER "\n", checks, failures, cases);
    return 1;
  }

  /* THE VOCABULARY, read out of the module. Every constant this gate uses to
   * read a refusal comes from here, so a code that moved in the module moves
   * here too and the rows below compare against the new one instead of failing
   * for a reason nobody can see. */
  Run r;
  /* The source face's PE, kept so the two faces can be compared as CONTAINERS
   * rather than as lengths. Two lengths that agree is a much weaker claim than
   * two containers that agree, and this block is the one that says the image
   * is the input. */
  static uint8_t pe_src[TEXT];
  /* The object path's bytes, captured before the PE path overwrites the buffer.
   * See the capture site for why the order is part of the measurement. */
  static uint8_t obj_bytes[TEXT];
  run_init(&r);
  Vocabulary vocab;
  memset(&vocab, 0, sizeof vocab);
  {
    uint64_t code = run(&ia, "", 0, 0, 0, &r);
    CHECK(code == 0, "the vocabulary mode answers");
    vocab.e_output = r.words[0];
    vocab.e_bound = r.words[1];
    for (unsigned i = 0; i < 10; i++)
      vocab.stage[i] = r.words[2 + i];
    vocab.report_words = r.words[12];
    vocab.mir_pin = r.words[13];
    vocab.nxo_version = r.words[14];
    printf("VOCAB E_OUTPUT=%llu E_BOUND=%llu stages=%llu..%llu words=%llu "
           "mir_pin=%llu nxo=%llu\n",
           (unsigned long long)vocab.e_output, (unsigned long long)vocab.e_bound,
           (unsigned long long)vocab.stage[0],
           (unsigned long long)vocab.stage[9],
           (unsigned long long)vocab.report_words,
           (unsigned long long)vocab.mir_pin,
           (unsigned long long)vocab.nxo_version);
    /* A vocabulary with two identical codes or two identical stages is a
     * vocabulary nobody can read: every refusal would name one of two things.
     * The pairwise check is over the PUBLISHED numbers, not over a table. */
    CHECK(vocab.e_output != vocab.e_bound,
          "the two refusal codes this module owns are distinguishable");
    for (unsigned i = 0; i < 10; i++) {
      for (unsigned k = i + 1; k < 10; k++) {
        char msg[160];
        snprintf(msg, sizeof msg,
                 "stages %u and %u are both %llu, so a refusal naming one of "
                 "them names the other too",
                 i, k, (unsigned long long)vocab.stage[i]);
        CHECK(vocab.stage[i] != vocab.stage[k], msg);
      }
    }
    CHECK(vocab.report_words >= 14,
          "the published report is at least fourteen words wide, which is what "
          "the rows below read");
  }

  CHECK(EXPECT_N == BODIES_N, "one expectation per corpus body");
  if (EXPECT_N == BODIES_N) {
    for (unsigned i = 0; i < BODIES_N; i++)
      CHECK(strcmp(BODIES[i].name, EXPECT[i].name) == 0,
            "the expectation table and the corpus are in the same order");
  }

  for (unsigned i = 0; i < BODIES_N && i < EXPECT_N; i++) {
    const Body *b = &BODIES[i];
    const Expectation *e = &EXPECT[i];
    size_t blen = strlen(b->body);
    unsigned char *det_bytes[STAGES_N]={0};
    size_t det_sizes[STAGES_N]={0};
    uint64_t det_codes[STAGES_N]={0}, det_runtime[STAGES_N]={0};

    for (unsigned pass = 0; pass < 2; pass++) {
      const NovaHostImage *image = pass ? &ib : &ia;
      const char *tag = pass ? "image-b" : "image-a";
      uint64_t code[STAGES_N];
      uint64_t pe_len = 0, nxo_len = 0, symbols = 0, entry = 0, text_len = 0;
      /* The OBJECT face's size, kept apart from the executable face's numbers.
       * A row may produce a valid object and refuse the PE, and the object face
       * publishes ONE word -- its byte count -- because it learns that from
       * `length[0]` and never reads its own container back. The symbol count and
       * the entry index come from the executable face, which does read it. */
      uint64_t obj_nxo = 0, independent_nxo = 0;
      uint8_t *object_text = NULL;
      size_t object_text_size = 0;
      uint64_t last_report[14];
      uint64_t face_runtime = 0;
      /* THE TWO FACES' REFUSALS, KEPT APART. A program the source face refuses
       * while lowering has no image at all, so the image face refuses for a
       * different reason at a different stage. One pair of words for both would
       * assert they agree, and they must not: the image face has less to go on
       * and therefore says something narrower. */
      uint64_t src_face_stage = 0, src_face_code = 0;
      uint64_t img_face_stage = 0, img_face_code = 0;

      memset(r.words, 0, WORDS * sizeof(uint64_t));
      for (unsigned s = 0; s < STAGES_N; s++) {
        if (STAGES[s].pre)
          run(image, b->body, blen, STAGES[s].pre, 0, &r);
        memset(r.out, 0, r.out_bytes);
        code[s] = run(image, b->body, blen, STAGES[s].mode, 0, &r);
        /* A10: compare complete serialized outputs ACROSS independently
           compiled/mapped images, not merely two faces within one image.
           Existing independent readers below still check layout correctness. */
        if (STAGES[s].mode==1 || STAGES[s].mode==2 ||
            STAGES[s].mode==4 || STAGES[s].mode==5) {
          size_t n=code[s]==0 && r.runtime==0 ? (size_t)r.length[0] : 0;
          CHECK(n<=r.out_bytes,"determinism output is inside its buffer");
          if(n>r.out_bytes)n=0;
          if(pass==0) {
            det_codes[s]=code[s];det_runtime[s]=r.runtime;det_sizes[s]=n;
            if(n) {
              det_bytes[s]=malloc(n);
              CHECK(det_bytes[s]!=NULL,"determinism snapshot allocation");
              if(det_bytes[s])memcpy(det_bytes[s],r.out,n);
            }
          } else {
            CHECK(code[s]==det_codes[s] && r.runtime==det_runtime[s],
                  "independent images agree on acceptance/refusal");
            CHECK(same_container(det_bytes[s],det_sizes[s],(const unsigned char*)r.out,n),
                  "independent images emit identical complete NXO/PE containers");
            if(n && det_bytes[s]) {
              det_bytes[s][n-1]^=1;
              CHECK(!same_container(det_bytes[s],det_sizes[s],(const unsigned char*)r.out,n),
                    "one changed container byte falsifies determinism");
              det_bytes[s][n-1]^=1;
              CHECK(!same_container(det_bytes[s],det_sizes[s],(const unsigned char*)r.out,n-1),
                    "one missing container byte falsifies determinism");
              printf("LAYOUT_DETERMINISM name=%s mode=%llu bytes=%zu images=2 equal=yes controls=2\n",
                     b->name,(unsigned long long)STAGES[s].mode,n);
            }
          }
        }

        /* The image face answers with the PE, so its report is the one that
         * carries the numbers. A source face that REFUSED carries the same
         * report, which is the point: one row of expectations, both faces. */
        if (STAGES[s].mode == 1) {
          obj_nxo = r.report[5];
          if(code[s]==0) {
            NtObject object={0};NtDiagnostic error={0};NtBuffer canonical={0};
            int decoded=r.runtime==0 && r.length[0]>0 && r.length[0]<=TEXT &&
              nt_object_read((const uint8_t*)r.out,(size_t)r.length[0],&object,&error);
            CHECK(decoded,"C reader accepts the produced NXO");
            if(decoded) {
              int encoded=nt_object_write(&object,&canonical,&error);
              CHECK(encoded,"C writer re-encodes the produced object");
              if(encoded) {
                independent_nxo=canonical.size;
                CHECK(canonical.size==r.length[0] && !memcmp(canonical.bytes,r.out,canonical.size),
                      "NXO agrees byte for byte with an independent reader/writer roundtrip");
              }
              if(e->code[2]==0) {
                NtArtifact resolved={0};
                int materialized=nt_object_materialize(&object,&resolved,&error);
                CHECK(materialized,"C materializer resolves the positive object's relocations");
                if(materialized) {
                  object_text_size=resolved.text.size;
                  object_text=malloc(object_text_size?object_text_size:1);
                  CHECK(object_text!=NULL,"relocated object text copied for independent PE comparison");
                  if(object_text)memcpy(object_text,resolved.text.bytes,object_text_size);
                  else object_text_size=0;
                }
                nt_artifact_free(&resolved);
              }
            }
            free(canonical.bytes);nt_object_free(&object);
          }
        }
        if (STAGES[s].mode == 2 || STAGES[s].mode == 5) {
          pe_len = r.length[0];
          nxo_len = r.report[5];
          symbols = r.report[7];
          entry = r.report[10];
          text_len = r.report[12];
          if (STAGES[s].mode == 2) {
            face_runtime = r.runtime;
            for (unsigned k = 0; k < 14; k++)
              last_report[k] = r.report[k];
          }
          if (code[s] != 0) {
            if (STAGES[s].mode == 2) {
              src_face_stage = r.report[8];
              src_face_code = r.report[9];
            } else {
              img_face_stage = r.report[8];
              img_face_code = r.report[9];
            }
          }
        }
      }

      if (pass == 0) {
        cases++;
        printf("CASE %-14s", b->name);
        for (unsigned s = 0; s < STAGES_N; s++)
          printf(" %s=%llu", stage_label(s), (unsigned long long)code[s]);
        printf(" nxo=%llu pe=%llu symbols=%llu entry=%llu text=%llu",
               (unsigned long long)nxo_len, (unsigned long long)pe_len,
               (unsigned long long)symbols, (unsigned long long)entry,
               (unsigned long long)text_len);
        if (code[2] != 0) {
          printf(" refusal=[stage %llu code %llu]",
                 (unsigned long long)src_face_stage,
                 (unsigned long long)src_face_code);
          /* THE HOST'S OWN ERROR, published beside the module's verdict. A
           * module that answers ~0 with a clean report and a dirty context is a
           * FAULT, not a refusal, and from the outside the two are the same
           * shape: a non-zero code and a report nobody wrote. */
          printf(" hosterr=%llu", (unsigned long long)face_runtime);
          CHECK(face_runtime == e->host_err,
                "the host error on this row is the one this gate pins; a fault "
                "and a refusal both read as a non-zero answer and an unwritten "
                "report, and only the host's own word tells them apart");
          printf(" report=[");
          for (unsigned k = 0; k < 14; k++)
            printf("%s%llu", k ? " " : "", (unsigned long long)last_report[k]);
          printf("]");
        }
        printf("\n");
        /* THE IMAGE, for a row that LOWERED and then could not be turned into an
         * object. A refusal that names a code and a record leaves the reader to
         * re-derive what the record said, and this is a case where the image is
         * the only evidence there is: the source face succeeded, so nothing
         * upstream of the encoder can say anything about the record. Printed
         * through `machine_ir`'s own serializer, so it is the module's reading of
         * its own format and not this gate's. */
        if (code[0] == 0 && code[1] != 0) {
          memset(r.words, 0, WORDS * sizeof(uint64_t));
          run(image, b->body, blen, 3, 0, &r);
          uint64_t dumped = run(image, b->body, blen, 11, 0, &r);
          if (dumped == 0 && r.length[0] > 0 && r.length[0] < TEXT) {
            fprintf(stderr, "  IMAGE %-12s", b->name);
            for (uint64_t k = 0; k < r.length[0]; k++) {
              uint8_t ch = ((const uint8_t *)r.out)[k];
              fputc(ch == '\n' ? '|' : (int)ch, stderr);
            }
            fputc('\n', stderr);
          }
        }
      }

      for (unsigned s = 0; s < STAGES_N; s++) {
        char msg[256];
        snprintf(msg, sizeof msg,
                 "%s/%s: %s answers %llu and this gate expects %llu",
                 b->name, tag, stage_label(s), (unsigned long long)code[s],
                 (unsigned long long)e->code[s]);
        CHECK(code[s] == e->code[s], msg);
      }

      /* THE OBJECT FACE, ASSERTED ON ITS OWN. The import row is the reason this
       * is separate: a valid NXO carrying an undefined symbol and a relocation
       * against it is a normal object, while a PE built from it ALONE cannot
       * exist. One row asserting both faces at once could not tell "the object
       * is bad" from "the executable image is impossible without a definition",
       * and those are facts about different modules. */
      if (code[1] != 0) {
        CHECK(code[2] == code[1],
              "a body the object face refuses cannot produce a PE either: the "
              "executable image is built from the object, so a refusal upstream "
              "must not be laundered into a different answer downstream");
      } else {
        char om[192];
        /* ONLY THE SIZE, and the reason is a property of the two paths rather
         * than an omission in this gate. `build_object_from_image` learns the
         * container's byte count from `length[0]`, which the writer filled in; it
         * never READS the container back, so it cannot know how many symbols are
         * in it or which of them is the entry. `build_pe_from_image` does read
         * it back -- it has to, the PE conversion takes an Object -- so the
         * symbol count and the entry index are ITS words, and they are pinned on
         * the executable face below. Asserting them here would assert that the
         * object writer performs a round trip it does not perform. */
        snprintf(om, sizeof om,
                 "%s/%s: the object face produced %llu NXO bytes and this gate "
                 "pins %llu",
                 b->name, tag, (unsigned long long)obj_nxo,
                 (unsigned long long)independent_nxo);
        CHECK(obj_nxo == independent_nxo, om);
      }

      /* A REFUSAL NAMES ITS STAGE, and names the code the stage returned. This
       * is what makes a red row actionable: 962 from the object writer and 962
       * from somewhere else would be the same number and a different fact. */
      if (code[2] != 0) {
        char msg[256];
        snprintf(msg, sizeof msg,
                 "%s/%s: the PE face refused %llu and named stage %llu carrying "
                 "code %llu -- a stage of zero would be a refusal that names "
                 "nothing",
                 b->name, tag, (unsigned long long)code[2],
                 (unsigned long long)src_face_stage,
                 (unsigned long long)src_face_code);
        CHECK(src_face_stage != 0 && src_face_code == code[2], msg);
        if (code[4] != 0) {
          snprintf(msg, sizeof msg,
                   "%s/%s: the image face refused %llu at stage %llu carrying "
                   "code %llu -- an image face that refused without naming its "
                   "stage would be indistinguishable from a parser failure",
                   b->name, tag, (unsigned long long)code[4],
                   (unsigned long long)img_face_stage,
                   (unsigned long long)img_face_code);
          CHECK(img_face_stage != 0 && img_face_code == code[4], msg);
        }
        CHECK(pe_len == 0,
              "a refused row produces no PE: the length is the zero written "
              "before the work, not a prefix");
      } else {
        CHECK(pe_len > 0 && pe_len <= TEXT, "the PE has a bounded nonempty representation");
        CHECK(entry == e->entry,
              "the entry symbol index read back from the object is the one "
              "this gate pins -- zero would mean a library object, and the PE "
              "conversion refuses one at 803");
        CHECK(symbols == e->symbols,
              "the symbol count read back from the object is the one this gate "
              "pins; it is a DIFFERENT fact from the entry index, and an object "
              "with one symbol and entry 0 is not this object");
        CHECK(text_len == object_text_size,
              "the .text size read back from the object is the one this gate "
              "pins");
        if (code[2] == 0 && pe_len > 0 && pe_len < TEXT) {
          /* THE BYTES THIS RUN PRODUCED, at the offset the PE's own section
           * table names. Printed on every green row and not only on a mismatch,
           * because a gate that prints its bytes only when they DISAGREE makes
           * its reader write the expectation from the failure message -- which is
           * the shape this file exists to refuse. */
          uint64_t raw = pe_text_offset((const uint8_t *)r.out, pe_len);
          fprintf(stderr, "  EMIT %-14s .text@%llu=", b->name,
                  (unsigned long long)raw);
          for (unsigned k = 0; raw != 0 && k < text_len && k < 512 && raw + k < pe_len; k++)
            fprintf(stderr, "%02x", (unsigned)((const uint8_t *)r.out)[raw + k]);
          fputc('\n', stderr);
        }
        if (object_text && object_text_size) {
          uint64_t at = find_bytes(&r, object_text, object_text_size);
          char msg[256];
          snprintf(msg, sizeof msg,
                   "%s/%s: the PE image carries the %llu independently relocated object "
                   "bytes (found at offset %llu)",
                   b->name, tag, (unsigned long long)object_text_size,
                   (unsigned long long)at);
          CHECK(at != 0 && at == pe_text_offset((const uint8_t*)r.out,pe_len), msg);
        }
      }

      if(code[2]==0 && pe_len>0 && pe_len<=TEXT && r.runtime==0) {
        NtFInput input={b->name,b->body,blen};NtArtifact reference={0};
        int accepted=nt_compile_many(&input,1,&reference)&&nt_make_pe(&reference);
        CHECK(accepted,"the independent reference accepts the positive PE source");
        if(accepted) {
          uint64_t want=0,got=0;char why_c[200]={0},why_mir[200]={0};
          int c_run=run_child(reference.pe.bytes,reference.pe.size,&want,why_c,sizeof why_c);
          int mir_run=run_child((const uint8_t*)r.out,(size_t)pe_len,&got,why_mir,sizeof why_mir);
          CHECK(c_run==0&&mir_run==0&&got==want,"both PE producers execute to the same full result");
          printf("PIPELINE_EXEC name=%s C=%llu MIR=%llu c_rc=%d mir_rc=%d\n",b->name,
                 (unsigned long long)want,(unsigned long long)got,c_run,mir_run);
        }
        nt_artifact_free(&reference);
      }
      free(object_text);

      /* A ROW THAT FAULTED IS NOT A ROW THAT WAS REFUSED, and it is not a row
       * that succeeded either. On the import body the module answers 0 -- the
       * success code -- while the runtime raises NV2_BOUNDS and no image is
       * written at all: `length` stays at the zero the entry wrote before the
       * work. Read as a verdict, that is the worst shape a pipeline can have: a
       * caller that trusts the return code writes an EMPTY FILE and reports
       * success. So the row is measured by the conjunction, and the conjunction
       * is the finding: a fault is published BESIDE the verdict, not folded into
       * it. */
      if (e->host_err != 0) {
        char msg[256];
        CHECK(face_runtime == e->host_err,
              "the host raised the error this row pins for this body");
        CHECK(pe_len == 0 && obj_nxo == 0,
              "and no image of any kind was written: the length is the zero from "
              "before the work, so a caller reading only the return code would "
              "believe in a container that does not exist");
        snprintf(msg, sizeof msg,
                 "%s/%s: this body FAULTS in the host (error %llu) while the "
                 "module answers %llu; the row is pinned as a fault and must be "
                 "re-measured when the fault is fixed, not deleted",
                 b->name, tag, (unsigned long long)e->host_err,
                 (unsigned long long)code[2]);
        CHECK(code[2] == e->code[2], msg);
      } else {
      /* THE TWO FACES AGREE, BYTE FOR BYTE. The image face parses nothing, so
       * this is the measurement that makes the image the input: if it rebuilt
       * the image from the source it would agree too -- and the perturbation
       * block below is what separates the two explanations. */
      /* The image face reads `words`, and mode 3 is what fills it. Without that
       * precondition the run answers 960 on an all-zero buffer -- which is the
       * pipeline refusing an image it does not have, and not a disagreement
       * between the faces. The first version of this block omitted it and
       * measured exactly that: 3072 against 0 on all three green rows. */
      memset(r.words, 0, WORDS * sizeof(uint64_t));
      run(image, b->body, blen, 3, 0, &r);
      memset(r.out, 0, r.out_bytes);
      run(image, b->body, blen, 5, 0, &r);
      uint64_t face_pe = r.length[0];
      uint64_t face_stage = r.report[8];
      memset(r.words, 0, WORDS * sizeof(uint64_t));
      memset(r.out, 0, r.out_bytes);
      run(image, b->body, blen, 2, 0, &r);
      uint64_t src_pe = r.length[0];
      uint64_t src_stage = r.report[8];
      char msg[256];
      if (src_pe > 0 || face_pe > 0) {
        /* ONE PRODUCED A CONTAINER, THE OTHER DID NOT. That is a disagreement
         * about the program and not about the faces, so it is reported as one
         * fact rather than as two lengths that happen to differ. */
        snprintf(msg, sizeof msg,
                 "%s/%s: the source face produced %llu bytes and the image face "
                 "produced %llu on the same program",
                 b->name, tag, (unsigned long long)src_pe,
                 (unsigned long long)face_pe);
        CHECK(src_pe == face_pe, msg);
      } else {
        /* BOTH REFUSED, and they refuse at DIFFERENT stages, which is correct:
         * the source face can refuse while parsing or lowering, and the image
         * face has no image to refuse. Asserting the stages match here would
         * be asserting that the two faces do the same work, which is the
         * opposite of what this gate exists to show. */
        snprintf(msg, sizeof msg,
                 "%s/%s: both faces refused (source stage %llu, image stage "
                 "%llu) and neither produced a container",
                 b->name, tag, (unsigned long long)src_stage,
                 (unsigned long long)face_stage);
        CHECK(src_stage != 0 && face_stage != 0, msg);
      }
      if (src_pe > 0 && face_pe > 0 && src_pe < TEXT && face_pe < TEXT) {
        memcpy(pe_src, r.out, (size_t)src_pe);
        memset(r.words, 0, WORDS * sizeof(uint64_t));
        run(image, b->body, blen, 3, 0, &r);
        memset(r.out, 0, r.out_bytes);
        run(image, b->body, blen, 5, 0, &r);
        int same = (face_pe == src_pe) &&
                   (memcmp(pe_src, r.out, (size_t)src_pe) == 0);
        CHECK(same,
              "the PE the source face produced and the PE the image face "
              "produced are the same container byte for byte, and the image "
              "face parsed nothing to produce it");
      }
      }
    }
    for(unsigned s=0;s<STAGES_N;++s) free(det_bytes[s]);
  }

  /* THE NEGATIVE CONTROL. Three perturbations of the image, each measured above
   * on both paths, plus the canary that says the damage machinery itself
   * changes nothing. The canary is the row that makes the other three mean
   * something: without it, three green refusals are consistent with a pipeline
   * that refuses everything. */
  {
    const char *subject = NULL;
    for (unsigned i = 0; i < BODIES_N; i++)
      if (!strcmp(BODIES[i].name, "uefi-return42"))
        subject = BODIES[i].body;
    CHECK(subject != NULL, "the perturbation subject is in the corpus");
    if (subject) {
      size_t slen = strlen(subject);
      /* The canary's bytes, captured once from the undamaged object path. A
       * perturbation row is compared against THESE, not against a literal, so
       * the control measures a difference rather than restating an
       * expectation. */
      uint64_t canary_len = 0;
      static uint8_t canary[TEXT];
      memset(r.words, 0, WORDS * sizeof(uint64_t));
      run(&ia, subject, slen, 3, 0, &r);
      memset(r.out, 0, r.out_bytes);
      run(&ia, subject, slen, 4, 0, &r);
      canary_len = r.length[0];
      if (canary_len > 0 && canary_len < TEXT)
        memcpy(canary, r.out, (size_t)canary_len);

      for (unsigned p = 0; p < PERTURB_N; p++) {
        const Perturbation *q = &PERTURB[p];
        uint64_t obj = 0, pe = 0, obj_len = 0, pe_len = 0;
        uint64_t obj_stage = 0, pe_stage = 0;
        memset(r.words, 0, WORDS * sizeof(uint64_t));
        run(&ia, subject, slen, 3, 0, &r);
        memset(r.out, 0, r.out_bytes);
        obj = run(&ia, subject, slen, 6, q->index, &r);
        obj_len = r.length[0];
        obj_stage = r.report[8];
        /* THE OBJECT'S BYTES, taken HERE. The mode 7 run below overwrites
         * `r.out` with a 3072-byte PE, so a comparison made after it would be a
         * comparison of a prefix of one container against a whole other one --
         * and it would be red for a reason that has nothing to do with the
         * perturbation. */
        if (obj_len > 0 && obj_len < TEXT)
          memcpy(obj_bytes, r.out, (size_t)obj_len);
        memset(r.words, 0, WORDS * sizeof(uint64_t));
        run(&ia, subject, slen, 3, 0, &r);
        memset(r.out, 0, r.out_bytes);
        pe = run(&ia, subject, slen, 7, q->index, &r);
        pe_len = r.length[0];
        pe_stage = r.report[8];
        cases++;
        printf("PERTURB %llu %-46s obj=%llu len=%llu pe=%llu len=%llu\n",
               (unsigned long long)q->index, q->label, (unsigned long long)obj,
               (unsigned long long)obj_len, (unsigned long long)pe,
               (unsigned long long)pe_len);
        char msg[256];
        snprintf(msg, sizeof msg,
                 "perturbation %llu (%s): the object path answers %llu and this "
                 "gate measured %llu -- the perturbation reached a different "
                 "reader than the one it was measured on",
                 (unsigned long long)q->index, q->label, (unsigned long long)obj,
                 (unsigned long long)q->obj_code);
        CHECK(obj == q->obj_code, msg);
        if (obj != 0) {
          /* THE OBJECT PATH'S REFUSAL NAMES THE OBJECT STAGE: the damage was
           * read behind the object stage, by the emitter, and not by a parser
           * or a lowering, which these modes never run. (An image face handed
           * an empty buffer answers the same 980 at the same stage; the
           * canary row is what says this image was not empty.) */
          snprintf(msg, sizeof msg,
                   "perturbation %llu (%s): the object path refused %llu at "
                   "stage %llu, and the object stage is %llu",
                   (unsigned long long)q->index, q->label,
                   (unsigned long long)obj, (unsigned long long)obj_stage,
                   (unsigned long long)vocab.stage[6]);
          CHECK(obj_stage == vocab.stage[6], msg);
        }
        snprintf(msg, sizeof msg,
                 "perturbation %llu (%s): the PE path answers %llu and this gate "
                 "measured %llu",
                 (unsigned long long)q->index, q->label, (unsigned long long)pe,
                 (unsigned long long)q->pe_code);
        CHECK(pe == q->pe_code, msg);
        if (q->index == 0) {
          /* THE CANARY: no damage, so the object must be the one the
           * undamaged run produced -- length AND content. A canary that only
           * checked the code would pass on a pipeline that refused everything
           * and called the refusal 0. */
          snprintf(msg, sizeof msg,
                   "the canary produced %llu bytes and the undamaged run "
                   "produced %llu: the damage machinery changed something on "
                   "the row that carries no damage",
                   (unsigned long long)obj_len,
                   (unsigned long long)canary_len);
          CHECK(obj_len == canary_len, msg);
          if (obj_len == canary_len && obj_len > 0 && obj_len < TEXT)
            CHECK(memcmp(obj_bytes, canary, (size_t)obj_len) == 0,
                  "the canary's bytes are the undamaged bytes");
        } else {
          /* THE POINT OF THE ROW. A damaged image must NOT produce the bytes
           * the undamaged one produced -- not on the object path and not on the
           * executable path. This is the claim the whole block exists for: the
           * emission is a function of the image, because the source is not
           * parsed on these modes at all. */
          int identical = 1;
          if (obj_len == canary_len && canary_len > 0 && obj_len < TEXT)
            identical = memcmp(obj_bytes, canary, (size_t)obj_len) == 0;
          if (obj_len != canary_len)
            identical = 0;
          snprintf(msg, sizeof msg,
                   "perturbation %llu (%s) produced the SAME object as the "
                   "undamaged run (%llu bytes, identical=%d): nothing downstream "
                   "of the damage read it",
                   (unsigned long long)q->index, q->label,
                   (unsigned long long)obj_len, identical);
          CHECK(!identical, msg);
          /* A refusal must carry no length at all, on both paths. */
          CHECK(pe_len == 0 && obj_len == 0,
                "a refusal carries no length on either path: the length is "
                "the zero written before the work, never a prefix of a "
                "container that was not produced");
          if (pe != 0) {
            snprintf(msg, sizeof msg,
                     "perturbation %llu (%s) refused the PE at stage %llu, so "
                     "the executable image follows the image too",
                     (unsigned long long)q->index, q->label,
                     (unsigned long long)pe_stage);
            CHECK(pe_stage != 0 && pe_len == 0, msg);
          }
        }
      }
    }
  }

  /* THE DELIVERY REFUSAL. A caller's buffer too small for the container is a
   * refusal with a name, not a short image: `length[0]` must still be the zero
   * the module wrote before it started. */
  {
    /* The UEFI body, because a `none` body is refused at the link stage (802)
     * before any container reaches delivery, and a short-buffer row must reach
     * delivery to measure it. */
    const char *subject = BODIES[0].body;
    for (unsigned i = 0; i < BODIES_N; i++)
      if (!strcmp(BODIES[i].name, "uefi-return42"))
        subject = BODIES[i].body;
    size_t slen = strlen(subject);
    r.out_bytes = 64;
    uint64_t code = run(&ia, subject, slen, 2, 0, &r);
    uint64_t stage = r.report[8];
    uint64_t length = r.length[0];
    cases++;
    printf("DELIVERY short-buffer code=%llu stage=%llu code9=%llu length=%llu\n",
           (unsigned long long)code, (unsigned long long)stage,
           (unsigned long long)r.report[9], (unsigned long long)length);
    CHECK(code == vocab.e_output,
          "a 64-byte buffer for a container this size is refused with the "
          "module's own E_OUTPUT");
    CHECK(stage == vocab.stage[9],
          "and the refusal names the delivery stage, so it is not mistaken for "
          "a refusal from the encoder");
    CHECK(length == GUARD || length == 0,
          "and the length is either untouched or the zero written before the "
          "work -- never a prefix of a container that was not delivered");
    CHECK(r.report[6] == 0,
          "and the PE size in the report stays zero: a size published for an "
          "image that was never delivered is a size nobody can use");

    /* THE SAME MISTAKE ON THE OBJECT PATH, and the two must answer the SAME
     * way. The object writer cannot tell a short buffer from a failed write --
     * it returns 0 and a zero length either way -- so the module separates them
     * with its own bound. If the two paths disagreed about the code here, a
     * caller would have to know which one it called to find out whose fault a
     * short buffer was. */
    uint64_t obj_code = run(&ia, subject, slen, 1, 0, &r);
    uint64_t obj_stage = r.report[8];
    printf("DELIVERY short-buffer object code=%llu stage=%llu length=%llu\n",
           (unsigned long long)obj_code, (unsigned long long)obj_stage,
           (unsigned long long)r.length[0]);
    CHECK(obj_code == vocab.e_output && obj_stage == vocab.stage[9],
          "the object path refuses a short caller buffer with the same code and "
          "the same stage as the PE path, so the caller does not have to know "
          "which of the two it called");
    CHECK(r.length[0] == 0,
          "and it writes no length either: the zero, not a prefix");
    r.out_bytes = TEXT;
  }

  /* ==========================================================================
   * THE TWO NEW SEAMS, and they are measured rather than declared.
   *
   * `effective_text` is what says the expansion HAPPENED, and the macro rows
   * above only say the pipeline produced something. A pipeline that reparsed the
   * caller's text would also produce something -- for the wrong program -- so the
   * claim that needs its own instrument is the one about the text itself: on a
   * body with an invocation, the effective text is LONGER than the source, and
   * on a body without one it is the source. The second half matters as much: an
   * instrument that only ever sees a longer buffer cannot tell an expansion from
   * a copy.
   */
  {
    const Body *macro = NULL;
    const Body *plain = NULL;
    for (unsigned i = 0; i < BODIES_N; i++) {
      if (!strcmp(BODIES[i].name, "macro-ret42"))
        macro = &BODIES[i];
      if (!strcmp(BODIES[i].name, "return42"))
        plain = &BODIES[i];
    }
    CHECK(macro && plain, "both subjects of the effective-text pair are in the corpus");
    if (macro && plain) {
      uint64_t source_len = (uint64_t)strlen(macro->body);
      uint64_t code = run(&ia, macro->body, source_len, 8, 0, &r);
      uint64_t effective = r.length[0];
      cases++;
      printf("EFFECTIVE macro source=%llu effective=%llu code=%llu\n",
             (unsigned long long)source_len, (unsigned long long)effective,
             (unsigned long long)code);
      CHECK(code == 0, "the effective-text mode answers");
      CHECK(effective > source_len,
            "a body whose macro was invoked develops MORE text than the caller "
            "supplied -- this is the measurement that the expansion ran, and a "
            "pipeline that reparsed the source could not produce it");

      uint64_t plain_len = (uint64_t)strlen(plain->body);
      uint64_t pcode = run(&ia, plain->body, plain_len, 8, 0, &r);
      uint64_t peff = r.length[0];
      printf("EFFECTIVE plain source=%llu effective=%llu code=%llu\n",
             (unsigned long long)plain_len, (unsigned long long)peff,
             (unsigned long long)pcode);
      CHECK(pcode == 0, "the effective-text mode answers on a body with no macro");
      CHECK(peff == plain_len,
            "a body with no invocation develops ITSELF: the effective text is "
            "the caller's text, byte for byte in length -- so the longer "
            "measurement above is an expansion and not a copy");
      if (peff == plain_len && peff < TEXT)
        CHECK(memcmp(r.out, plain->body, (size_t)peff) == 0,
              "and the bytes are the caller's own, not a rewritten copy of them");
    }
  }

  /* `lower_tree` ON ITS OWN. The macro rows above reach the Machine IR through
   * the source faces; this reaches it through the exported seam -- parse,
   * expand, hand the DEVELOPED tree to `machine_pipeline.lower_tree`, which
   * validates nothing and owns nothing -- and asks whether the image it produced
   * is the same image the source face produced for the same body. A gate that
   * only ever reached the IR one way would be testing a private chain and
   * calling it a public API. */
  {
    const Body *b = &BODIES[0];
    size_t blen = strlen(b->body);
    memset(r.words, 0, WORDS * sizeof(uint64_t));
    uint64_t via_face = run(&ia, b->body, blen, 3, 0, &r);
    uint64_t face_words[64];
    uint64_t face_count = r.report[0];
    for (unsigned k = 0; k < 64 && k < WORDS; k++)
      face_words[k] = r.words[k];
    memset(r.words, 0, WORDS * sizeof(uint64_t));
    uint64_t via_tree = run(&ia, b->body, blen, 9, 0, &r);
    uint64_t tree_count = r.report[0];
    cases++;
    printf("LOWER_TREE %-14s face=%llu count=%llu tree=%llu count=%llu\n", b->name,
           (unsigned long long)via_face, (unsigned long long)face_count,
           (unsigned long long)via_tree, (unsigned long long)tree_count);
    CHECK(via_face == 0 && via_tree == 0,
          "both routes to the Machine IR answer on the same body");
    CHECK(face_count == tree_count && face_count != 0,
          "the exported seam and the source face produce the same number of "
          "records for the same body");
    {
      int same = 1;
      for (unsigned k = 0; k < 60; k++) {
        if (face_words[k] != r.words[k])
          same = 0;
      }
      CHECK(same,
            "and the same image, word for word over the header and the first "
            "three records -- the seam is a different ROUTE, not a different "
            "product");
    }
  }

  /* THE PARAMETER MODES THE PIPELINE FILLS (second review, 7 October 2026: the
   * machine_ir gate's comment said they were measured here, and nothing here
   * measured them). machine_ir lowers every parameter FLAG_DIR_UNREAD -- the
   * machine_ir gate asserts it on this same fixture -- and
   * machine_pipeline.lower_tree asks abi.nova, the rule's owner, through
   * `abi.parameter_mode` before verifying. So the two gates read ONE source
   * through the two routes, and the pair is the discriminating measure: a
   * pipeline that skipped the resolution would answer UNREAD here as well. */
  {
    static const char facts[] =
        "module decl.facts\n"
        "target x86_64-nexora-uefi\n"
        "section .text {\n"
        "    fn helper(in a:u64 @rcx,out b:u64 @rdx,inout c:u64 @r8)->u64\n"
        "    effects {}\n"
        "    clobbers {} {\n"
        "        return a\n"
        "    }\n"
        "    export fn main()->u64\n"
        "    effects {}\n"
        "    clobbers {} {\n"
        "        return 0\n"
        "    }\n"
        "}\n";
    const uint64_t F_OUT = 8192, F_INOUT = 16384, F_UNREAD = 65536;
    const uint64_t DIRS = F_OUT | F_INOUT | F_UNREAD;
    memset(r.words, 0, WORDS * sizeof(uint64_t));
    uint64_t rc = run(&ia, facts, strlen(facts), 3, 0, &r);
    cases++;
    uint64_t n = rc == 0 && r.runtime == 0 ? r.words[3] : 0;
    uint64_t helper = 0, mode[3] = {~0ULL, ~0ULL, ~0ULL};
    const uint64_t stride = r.words[5];
    CHECK(stride == 24, "MIR/1.0 record width is published");
    for (uint64_t rec = 1; rec <= n && stride == 24 && rec <= (WORDS-10)/stride; rec++) {
      const uint64_t *w = r.words + 10 + (rec - 1) * stride;
      if (w[0] == 2051 && w[7] >= w[6] && w[7] - w[6] == 6 && w[7] <= sizeof facts &&
          !memcmp(facts + w[6], "helper", 6))
        helper = rec;
      if (w[0] == 2054 && helper && w[16] == helper && w[14] < 3)
        mode[w[14]] = w[13] & DIRS;
    }
    printf("PARAM_MODES rc=%llu runtime=%llu records=%llu helper=%llu in=%llu out=%llu inout=%llu\n",
           (unsigned long long)rc, (unsigned long long)r.runtime, (unsigned long long)n,
           (unsigned long long)helper, (unsigned long long)mode[0],
           (unsigned long long)mode[1], (unsigned long long)mode[2]);
    CHECK(rc == 0 && r.runtime == 0 && helper != 0,
          "the parameter-mode fixture lowers through the pipeline and names `helper`");
    CHECK(mode[0] == 0, "`in a` carries no direction bit after the pipeline (the in/default mode)");
    CHECK(mode[1] == F_OUT, "`out b` carries FLAG_DIR_OUT alone after the pipeline");
    CHECK(mode[2] == F_INOUT, "`inout c` carries FLAG_DIR_INOUT alone after the pipeline");
  }

  /* A generated parameter is read from effective expanded text, not its
   * invocation span. Inspect all three published direction modes directly. */
  {
    const char *src = "module generated_modes\ntarget x86_64-nexora-uefi\n"
      "macro mk()->ast.decl {\nemit quote(decl) {\n"
      "fn helper(in a:u64 @rcx,out b:u64 @rdx,inout c:u64 @r8)->u64\n"
      "effects {}\nclobbers {} {\nreturn 0;\n}\n}\n}\n"
      "section .text {\nexport fn main()->u64 effects {} clobbers {} {\n"
      "expand mk()\nreturn 42\n}\n}\n";
    memset(r.words, 0, WORDS * sizeof(uint64_t));
    uint64_t code = run(&ia,src,strlen(src),3,0,&r);
    unsigned seen[3]={0,0,0}, unread=0, unexpected=0;
    uint64_t n=code==0 && r.runtime==0 ? r.words[3] : 0;
    for(uint64_t id=1;id<=n && r.words[5]==24 && id<=(WORDS-10)/24;id++) {
      const uint64_t *w=r.words+10+(id-1)*24;
      if(w[0]!=2054)continue;
      uint64_t mode=w[13] & (8192|16384|65536);
      if(mode==0)seen[0]++; else if(mode==8192)seen[1]++;
      else if(mode==16384)seen[2]++; else if(mode & 65536)unread++; else unexpected++;
    }
    printf("GENERATED_PARAM_MODES rc=%llu runtime=%llu in=%u out=%u inout=%u unread=%u unexpected=%u\n",
      (unsigned long long)code,(unsigned long long)r.runtime,seen[0],seen[1],seen[2],unread,unexpected);
    CHECK(code==0 && r.runtime==0,"generated parameter fixture lowers");
    CHECK(seen[0]==1 && seen[1]==1 && seen[2]==1 && unread==0 && unexpected==0,
      "generated parameters publish one exact IN/OUT/INOUT mode and no UNREAD");
    cases++;
  }
  /* A numerically valid but false call effect must not be trusted by emission. */
  {
    const char *src = "module call_effect_mutant\ntarget x86_64-nexora-uefi\n"
      "section .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\n"
      "export fn main()->u64\neffects {}\nclobbers {rax} {\ncall helper()\nreturn rax\n}\n}\n";
    uint64_t code = run(&ia,src,strlen(src),3,0,&r);
    CHECK(code==0&&r.runtime==0,"call effect fixture lowers");
    uint64_t target=0;
    if(code==0&&r.runtime==0&&r.words[5]==24) {
      for(uint64_t id=1;id<=r.words[3]&&id<=(WORDS-10)/24;id++) {
        uint64_t at=10+(id-1)*24;
        if(r.words[at]==2076){target=at+23;break;}
      }
    }
    CHECK(target!=0,"a real call carries an effects word");
    if(target) {
      uint64_t original=r.words[target];r.words[target]=original^4;
      code=run(&ia,src,strlen(src),4,0,&r);
      CHECK(code==980&&r.runtime==0&&r.length[0]==0,"false call effects are refused before any object is delivered");
      r.words[target]=original;code=run(&ia,src,strlen(src),4,0,&r);
      CHECK(code==0&&r.runtime==0&&r.length[0]>0,"restored call effects produce an object");
    }
    cases++;
  }
  run_free(&r);
  for (unsigned i = 0; i < PATHS_N; i++)
    free(sources[i]);
  nova_host_unmap(&ia);
  nova_host_unmap(&ib);
  nt_artifact_free(&first);
  nt_artifact_free(&second);
  printf(BANNER "\n", checks, failures, cases);
  return failures ? 1 : 0;
}
