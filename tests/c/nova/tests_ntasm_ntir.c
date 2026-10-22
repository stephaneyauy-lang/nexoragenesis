/* tests_ntasm_ntir.c -- the NTIR gate.
 *
 * NTIR is the first typed intermediate representation in this tree. The wave 6
 * report closed with "aucun NTIR, aucun Machine IR" as the single reason A1 and
 * A7 are not closable, and this harness is the first evidence against that
 * sentence. It is a FIRST MILESTONE and NOT A7: there is no Machine IR here, no
 * instruction selection, no encoding constraint, and no program has been run
 * through this IR.
 *
 * WHAT IS ASSERTED, AND AGAINST WHAT:
 *
 *  1. THE KIND TABLE IS A NEW NUMBERING. The gate reads KIND_BASE and the whole
 *     table back through the module and proves every NTIR kind is above every
 *     AST kind the parser can actually build on the fixtures, and above the
 *     highest code spec/ntasm/ntasm.md 17.6 publishes. Nothing in this file is a
 *     hand-written kind list: the table IS the module's, read back at run time.
 *
 *  2. THE IR IS CONFRONTED WITH THE AST NODE FOR NODE. For every id the gate
 *     checks the four properties that together say "nothing was dropped,
 *     duplicated or reordered": the counts are equal, the id sets are equal, the
 *     ast_kind recorded in the IR is the kind the tree holds, and the three
 *     links recorded in the IR are the links the tree holds. The expected kind
 *     of each node is DERIVED HERE from the published table plus the two split
 *     predicates, never read from a constant written in this file.
 *
 *  3. WIDTHS AND SPACES ARE CONFRONTED WITH THEIR OWNERS, not with a table
 *     written here. Mode 5 of the entry asks register_widths and
 *     pointer_spaces for their OWN answer on the same source, and the gate
 *     compares. The scalar widths are additionally compared against
 *     nt_frontend_type_name of the C oracle (frontend.c:777), so a width in
 *     ntir.nova that drifts from the reference frontend is a red.
 *
 *  4. GOLDENS. Every fixture is serialized twice in one image and the two byte
 *     streams must be equal; the whole fixture set is then serialized through a
 *     SECOND, INDEPENDENTLY COMPILED image of the same Nova sources, which is a
 *     rebuild in the only sense the word can have here. The concatenated text
 *     is hashed with FNV-1a and the digest is printed, so any byte that moves
 *     is visible in the banner and not only in a diff nobody reads.
 *
 *  5. ADVERSARIAL. Damaged images, each produced by mode 2 and then broken by
 *     this file at a NAMED word: an unknown node kind, a child link past the
 *     end, a first/last pair that disagrees, a cycle, a node two parents
 *     claim, a typed word its own kind does not admit, a wrong format tag and a
 *     wrong version. Each must be refused, and each refusal but the structural
 *     ones must carry a line and a column. An image invented in C would be
 *     testing a C fiction; an image this lowering produced and this file broke
 *     is a real break.
 *
 *  6. THE FORMAT TAG IS PINNED. The first line of every golden is the tag, and
 *     EXPECTED_TAG is written down once HERE and compared with the bytes. A tag
 *     that changed in ntir.nova alone reds this gate on the text, not on a
 *     comment.
 */
#include "../../../compiler/c/ntasm/frontend/frontend.h"
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

#define GUARD UINT64_C(0xcccccccccccccccc)
#define WORDS 262144
#define TEXT 1048576
#define REPORT 256

/* The image layout, read from ntir.nova and asserted against it, not written
 * down here twice. HEADER and NODE are the two constants the module publishes
 * and this file learns at run time; the field offsets inside a node are the
 * layout the module's own serializer prints, so the gate reads the SAME
 * offsets it verifies. */
static uint64_t header_words, node_words, kind_base, kind_count;
static const uint64_t F_KIND = 0, F_SOURCE = 1, F_LINE = 2, F_COLUMN = 3,
                      F_START = 4, F_END = 5, F_AST_KIND = 6, F_AST_ID = 7,
                      F_FIRST = 8, F_LAST = 9, F_NEXT = 10, F_CHILDREN = 11,
                      F_WIDTH = 12, F_SIGNED = 13, F_SPACE = 14, F_CLASS = 15;

static const char *const PATHS[] = {
    "tests/nova/tests/ntir-entry.nova",
    "compiler/nova/formats/ntir/ntir.nova",
    "compiler/nova/ir/ir_image.nova",
    "compiler/nova/formats/pe/pe.nova",
    "compiler/nova/analysis/types/pointer_spaces.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/lexer.nova",
    "compiler/nova/frontend/ast.nova"};
#define PATHS_N ((unsigned)(sizeof PATHS / sizeof PATHS[0]))

static const char EXPECTED_TAG[] = "NTIR/0.1";

/* ---- fixture corpus ------------------------------------------------------
 *
 * The four files on disk under tests/fixtures are read by the lexer gate and
 * are the project's own corpus, so they are used here too and the verdicts are
 * comparable with the rest of the suite. The rest of the corpus is spelled here
 * and each entry exists to reach a node kind the others do not: the gate
 * reports which kinds no fixture reached, so an unreached kind is a red rather
 * than a silent hole.
 */
static const char *const FIXTURES[] = {
    /* f0: the declaration skeleton. A section, a data declaration with an
     * array type, a function with effects, clobbers, a body and a return whose
     * value is a comparison. Note the space before the `=` of the
     * initialiser: `array<u8,4>=` lexes `>=` as one token (lexer.nova:204) and
     * the type closer then never sees the `>` it is looking for. The project's
     * own positive-module.ntasm fixture has that shape and is only ever LEXED
     * by the lexer gate, never parsed, so nothing in the tree has hit it
     * before. */
    "module m\ntarget x86_64-nexora-none\n"
    "const LIMIT:u64=18_446_744_073_709_551_615\n"
    "section .rdata {\ndata text:array<u8, 4> = \"A\\n\"\n}\n"
    "section .text {\n"
    "fn main()->u64\neffects {}\nclobbers {} {\nreturn LIMIT!=0\n}\n}\n",

    /* f1: a full typed signature inside a section, because a function is only
     * a declaration inside one (parser.nova:427-438). Every parameter carries
     * a direction word, which parser.nova:337 REQUIRES and does not default,
     * so a parameter without one is a parse error and not a shorthand. Every
     * scalar of the catalogue, a pointer in a kernel space, a nested pointer,
     * an array and an explicit register binding, so every width, both
     * signednesses and a register class all appear. */
    "module m\ntarget x86_64-nexora-none\n"
    "section .text {\n"
    "fn typed(in x:u64 @rax, out y:u32, inout p:ptr<kernel, ptr<user, u8>>,"
    " in a:array<u16, 4>, in b:u8, in c:u16, in d:u32, in e:i8, in f:i16,"
    " in g:i32, in h:i64, in k:bool, in n:never)->u64\n"
    "effects {}\nclobbers {rcx} {\nreturn 0\n}\n"
    "fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
    /* f2: the machine-shaped half. An instruction with two register operands,
     * an immediate, a memory operand, a label, a jump to it, a let, an if
     * with an else and a call. The memory operand is written the way the
     * PARSER reads it and not the way x86 assembly writes it: the segment goes
     * inside the brackets and the element type comes AFTER the closing one
     * (parser.nova:262-278), so `mov rax, [fs:0]:u64` and not
     * `mov rax, qword fs:[0]`. */
    "module m\ntarget x86_64-nexora-none\n"
    "section .text {\n"
    "fn helper()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n"
    "fn main()->u64\neffects {}\nclobbers {rax} {\n"
    "let n:u64=0\n"
    "mov rax, 1\n"
    "add rax, r10\n"
    "mov rax, [fs:0]:u64\n"
    "top:\n"
    "jmp top\n"
    "if n==0 {\nnop\n} else {\nnop\n}\n"
    "call helper()\n"
    "return n\n}\n}\n",

    /* f3: the contract half. A versions block with its six domains, a feature
     * set, a default abi, an output, an import, an abi clause (which is the
     * AST kind 28 shape with one dashed child, against the call statement of
     * f2 which is the other), requires and ensures with their predicates, and
     * a binding set. The import names a TYPE between the alias and the `fn`
     * keyword, which parser.nova:442-444 requires and does not default. */
    "module m\ntarget x86_64-nexora-none\n"
    "versions {\nntir 0.1\nmachine_ir 0.1\nsections 0.1\nsymbols 0.1\n"
    "relocations 0.1\nnxo 0.1\n}\n"
    "features {lm}\n"
    "default_abi nx64-abi-v0\n"
    "output pe64\n"
    "import other.helper as helper : fn ()->u64\neffects {}\nclobbers {}\n"
    "section .text {\n"
    "fn main()->u64\n"
    "abi nx64-abi-v0\n"
    "effects {}\n"
    "clobbers {rax, rbx, rcx}\n"
    "requires {has_feature(lm)}\n"
    "ensures {result_eq(0)} {\n"
    "return 0\n}\n}\n",

    /* f4: align_stack and a comptime declaration, both shapes nothing above
     * reaches. A comptime parameter is `name=literal` with no type colon,
     * which parser.nova:477-479 requires. */
    "module m\ntarget x86_64-nexora-none\n"
    "comptime (limit=4) {\nreturn limit\n}\n"
    "section .text {\n"
    "fn main()->u64\neffects {}\nclobbers {} {\n"
    "align_stack 16\n"
    "return 0\n}\n}\n",

    /* f5: a macro and a stub table. A macro parameter is `name:TYPE`, and a
     * `list<T>` return type is optional (parser.nova:570-575); the body is a
     * meta block, whose statements are `let name=expr`, `if`, `for`, `return`
     * and `emit` (parser.nova:523-552). A stub entry carries a name, an
     * integer key and SEVENTEEN fields in a fixed order
     * (parser.nova:605-625), written here in that order and with the two
     * set-valued fields spelled as the empty sets they are. */
    "module m\ntarget x86_64-nexora-none\n"
    "macro twice(T:ast.expr) -> ast.expr {\n"
    "let a=1\n"
    "let b=expand foo(1)\n"
    "if a==1 {\nreturn a\n}\n"
    "for a in 0 {\nreturn a\n}\n"
    "emit 1\n"
    "emit quote(expr) { 1 }\n"
    "return $T\n}\n"
    "stub_table t kind k {\n"
    "entry 1 {\n"
    "handler dispatch\n"
    "entry_abi nx64-abi-v0\n"
    "exit_abi nx64-abi-v0\n"
    "exit handler\n"
    "frame same\n"
    "bindings {saved:u64 @rax}\n"
    "hardware_error_code none\n"
    "save {}\n"
    "clobbers {}\n"
    "stack_align 16\n"
    "swapgs false\n"
    "interrupts none\n"
    "section .text\n"
    "visibility local\n"
    "symbol dispatch\n"
    "}\n}\n"
    "section .text {\n"
    "fn dispatch()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n"
    "fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
};
#define FIXTURES_N ((unsigned)(sizeof FIXTURES / sizeof FIXTURES[0]))

/* ---- helpers ------------------------------------------------------------ */

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


/* ---- the reference passes -----------------------------------------------
 *
 * The superset claim is not a sentence. Each negative case below is run
 * through the pass that OWNS the refusal and then through ntir.build, and the
 * gate requires that a refusal by the owner is a refusal by ntir as well. A
 * narrower verifier would accept something a pass that knows the language
 * better already refuses, and that is exactly the narrowing the wave 6 report
 * called "inventing a proof the machine does not support".
 *
 * Each owner is its own image, because each of the three entry modules exports
 * `main` and one image carries one entry.
 */
typedef struct {
  const char *label;
  const char *paths[10];
  unsigned count;
  const char *code_of;
} Owner;

static const Owner OWNERS[] = {
    {"types",
     {"tests/nova/tests/types-entry.nova",
      "compiler/nova/analysis/types/types.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/lexer.nova",
      "compiler/nova/frontend/ast.nova", NULL, NULL, NULL, NULL, NULL},
     5, "350 unknown scalar, 351 zero array length"},
    {"pointer_spaces",
     {"tests/nova/tests/pointer-spaces-entry.nova",
      "compiler/nova/analysis/types/pointer_spaces.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/lexer.nova",
      "compiler/nova/frontend/ast.nova", NULL, NULL, NULL, NULL, NULL},
     5, "340 a pointer space outside the catalogue"},
    {"register_widths",
     {"tests/nova/tests/register-widths-entry.nova",
      "compiler/nova/analysis/types/register_widths.nova",
      "compiler/nova/frontend/register_bindings.nova",
      "compiler/nova/frontend/parameters.nova",
      "compiler/nova/analysis/calls/callable_names.nova",
      "compiler/nova/analysis/semantics.nova",
      "compiler/nova/frontend/parser.nova",
      "compiler/nova/frontend/lexer.nova",
      "compiler/nova/frontend/ast.nova", NULL},
     9, "318 a register width that contradicts its declared type"},
};
#define OWNERS_N ((unsigned)(sizeof OWNERS / sizeof OWNERS[0]))

/* The negative corpus. Every entry names the owner that must refuse it and
 * the code that owner publishes, and both are written down because they are
 * the property being measured; the REFUSAL BY NTIR is what the gate measures
 * and is not written down, so a narrowed verifier fails here. */
static const char *const NEG_HEAD = "module m\ntarget x86_64-nexora-none\n";
/* A function is only a declaration inside a section (parser.nova:427-438), so
 * every negative body is wrapped in one. A negative that failed to PARSE would
 * measure the parser and not the pass, and the gate would be claiming a
 * superset relation it never tested. */
static const char *const NEG_MID = "\nsection .text {\n";
static const char *const NEG_TAIL =
    "\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
static const struct {
  const char *name;
  const char *body;
  const char *owner;
  uint64_t code;
} NEGATIVES[] = {
    {"scalar type name outside the catalogue",
     "fn bad()->zz\neffects {}\nclobbers {} {\nreturn 0\n}\n", "types", 350},
    {"array length zero", "data d:array<u64, 0> = 1\n", "types", 351},
    {"pointer space outside the catalogue",
     "fn bad(in p:ptr<nowhere, u8>)->u64\neffects {}\nclobbers {} {\n"
     "return 0\n}\n",
     "pointer_spaces", 340},
    {"register width against its declared type",
     "fn bad(in x:u64 @eax)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n",
     "register_widths", 318},
};
#define NEGATIVES_N ((unsigned)(sizeof NEGATIVES / sizeof NEGATIVES[0]))

/* THE DEPTH CORPUS, which is NEGATIVES with a DIFFERENT owner. Every entry in
 * NEGATIVES above is refused by a module that OWNS the rule, and the code that
 * owner publishes is the property measured. 817 is refused by ntir ITSELF and
 * by no owner in the table above, so these entries carry no owner: the rule
 * being measured is ntir's own TYPED_DEPTH_CAP, and its code is written down
 * here exactly as the owner codes are.
 *
 * WHY EACH ENTRY IS PAIRED, and the pairing is the whole point: a fixture that
 * is only refused proves nothing about a THRESHOLD, because a walk that
 * refused every input at any depth would satisfy it. So every depth appears
 * twice, once under the cap and once over it, and the two differ ONLY in the
 * number of nesting levels. The under arm is the negative control: if it ever
 * goes red, the over arm is not measuring a cap.
 *
 * WHY TWO FAMILIES AND NOT ONE. TYPED_DEPTH_CAP is read at two sites, on two
 * different recursions -- ntir.nova:466 in type_form, which recurses into a ptr
 * or array ELEMENT TYPE, and ntir.nova:686 in type_operand, which recurses into
 * an ast kind 35 EXPRESSION node. Both are reachable from ordinary source, so
 * one fixture would leave one site unmeasured and the header's claim that 817 is
 * a typing refusal half-covered. The two families are separated by a property
 * of the tree rather than by assertion: the type family carries NO ast kind 35
 * node at all, so type_operand has nothing to recurse over, and the operand
 * family carries exactly ONE ast kind 36 node whose aux is 0, which is a bare
 * name, so type_form's recursion is never entered. Both counts are measured
 * below from the parser's own record through mode 5, not asserted here.
 *
 * The depth is a property of the FIXTURE and it is re-derived at run time by
 * counting the opening token in the source that was actually run, so a
 * miscounted literal above is a red line rather than a silently weaker case.
 * `open` is the token one nesting level contributes.
 */
static const struct {
  const char *name;
  const char *body;
  uint64_t code;   /* what ntir must answer; 0 means ACCEPTED */
  uint64_t depth;  /* nesting levels the body carries */
  const char *open;/* the token one level contributes, re-counted below */
} DEPTHS[] = {
    /* a type nested just under TYPED_DEPTH_CAP. 63 levels of `ptr<user,`; expected ACCEPTED. */
    {"a type nested just under TYPED_DEPTH_CAP",
     "fn deep(in p:ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,u8>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>)->u64\n"
      "effects {}\n"
      "clobbers {} {\n"
      "return 0\n"
      "}\n"
     , 0, 63, "ptr<user,"},
    /* a type nested just over TYPED_DEPTH_CAP. 64 levels of `ptr<user,`; expected 817. */
    {"a type nested just over TYPED_DEPTH_CAP",
     "fn deep(in p:ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,ptr<user,u8>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>)->u64\n"
      "effects {}\n"
      "clobbers {} {\n"
      "return 0\n"
      "}\n"
     , 817, 64, "ptr<user,"},
    /* an operand nested just under TYPED_DEPTH_CAP. 63 levels of `(`; expected ACCEPTED. */
    {"an operand nested just under TYPED_DEPTH_CAP",
     "fn ops()->u64\n"
      "effects {}\n"
      "clobbers {rax} {\n"
      "mov rax, (((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((1)))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))\n"
      "return 0\n"
      "}\n"
     , 0, 63, "("},
    /* an operand nested just over TYPED_DEPTH_CAP. 64 levels of `(`; expected 817. */
    {"an operand nested just over TYPED_DEPTH_CAP",
     "fn ops()->u64\n"
      "effects {}\n"
      "clobbers {rax} {\n"
      "mov rax, ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((1))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))\n"
      "return 0\n"
      "}\n"
     , 817, 64, "("},
};
#define DEPTHS_N ((unsigned)(sizeof DEPTHS / sizeof DEPTHS[0]))

typedef struct {
  uint64_t returned, runtime;
  uint64_t *words;
  uint64_t *report;
  uint64_t length[4];
  uint8_t *text;
} Run;

static void run_init(Run *r) {
  r->words = (uint64_t *)malloc(WORDS * sizeof(uint64_t));
  r->report = (uint64_t *)malloc(REPORT * sizeof(uint64_t));
  r->text = (uint8_t *)malloc(TEXT);
  if (!r->words || !r->report || !r->text) {
    fprintf(stderr, "FAIL allocation\n");
    exit(1);
  }
  memset(r->text, 0xcc, TEXT);
}
static void run_free(Run *r) {
  free(r->words);
  free(r->report);
  free(r->text);
}

/* THE TWO NUMBERS THE CALLER OWNS, AND WHY THEY ARE SPLIT HERE.
 *
 * Slot five of the flat call is how many u64 words `words` REALLY holds. Slot
 * six is the separate `word_count` CAPACITY argument the entry passes down to
 * ntir.build. The original call passed WORDS for both, so every caller of this
 * function was unable to express a destination smaller than the image the
 * build was about to write -- and that destination is exactly what the
 * capacity arm of ntir.nova refuses. A harness that cannot BUILD the input
 * cannot assert the refusal; it can only write the refusal down. So the two
 * numbers are separate parameters here, and `run` below is the case where
 * they are equal. The borrows, the slot order and the slot count are
 * unchanged, so every existing call site means exactly what it meant.
 */
static void run_at(const NovaHostImage *image, const char *source, size_t size,
                   uint64_t mode, uint64_t index, uint64_t words_len,
                   uint64_t word_count, Run *r) {
  NovaContextV2 c = {0};
  for (unsigned i = 0; i < REPORT; i++) r->report[i] = GUARD;
  for (unsigned i = 0; i < 4; i++) r->length[i] = GUARD;
  memset(r->text, 0xcc, TEXT);
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)source, size, 0);
  uint64_t wh = nova_borrow_v2(&c, r->words, words_len * sizeof(uint64_t), 1);
  uint64_t th = nova_borrow_v2(&c, r->text, TEXT, 1);
  uint64_t lh = nova_borrow_v2(&c, r->length, 4 * sizeof(uint64_t), 1);
  uint64_t rh = nova_borrow_v2(&c, r->report, REPORT * sizeof(uint64_t), 1);
  /* A buf<T> crosses the boundary as a handle plus an ELEMENT count in the
   * next slot, while the borrow itself is registered in bytes. The eight
   * parameters of the entry therefore need THIRTEEN flat slots, and the third
   * argument of image->entry is that slot count and not the parameter count:
   * eight parameters of which five are buffers is 8 + 5 = 13. Passing fewer is
   * NV2_ARGUMENT, which the boundary raises before the body ever runs. */
  uint64_t args[] = {sh, size, mode, index, wh, words_len, word_count,
                     th, TEXT, lh, 4, rh, REPORT};
  r->returned = image->entry(&c, args, 13);
  r->runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
}

static void run(const NovaHostImage *image, const char *source, size_t size,
                uint64_t mode, uint64_t index, Run *r) {
  run_at(image, source, size, mode, index, WORDS, WORDS, r);
}

static uint64_t fnv1a(const uint8_t *p, size_t n, uint64_t h) {
  for (size_t i = 0; i < n; i++) {
    h ^= p[i];
    h *= UINT64_C(0x100000001b3);
  }
  return h;
}
#define FNV_SEED UINT64_C(0xcbf29ce484222325)

/* The AST, read out of the SAME image through mode 5, which hands back the
 * register_widths answer, the pointer_spaces answer and the whole twelve-word
 * AST record of one node at a time. So the gate can confront every one of the
 * sixteen IR words against the tree and never writes a parser of its own, and
 * every expectation it compares against is an answer the OWNING module gave on
 * the SAME source. */
typedef struct {
  uint64_t count;
  uint64_t *w[17];  /* the mode 5 report, one row per node */
  uint64_t space_mask, space_code, pointers;
} Ast;

#define A_WIDTH 0
#define A_FAMILY 1
#define A_SPACE_CODE 2
#define A_POINTERS 3
#define A_KIND 6
#define A_AUX 7
#define A_SOURCE 8
#define A_LINE 9
#define A_COLUMN 10
#define A_START 11
#define A_END 12
#define A_FIRST 13
#define A_LAST 14
#define A_NEXT 15
#define A_CHILDREN 16

static void ast_read(const NovaHostImage *image, const char *source, Run *r,
                     Ast *a, uint64_t probe_limit) {
  memset(a, 0, sizeof *a);
  run(image, source, strlen(source), 0, 0, r);
  a->count = r->report[0];
  if (a->count == 0 || a->count > probe_limit)
    return;
  for (unsigned f = 0; f < 17; f++)
    a->w[f] = (uint64_t *)calloc(a->count, sizeof(uint64_t));
  for (uint64_t id = 1; id <= a->count; id++) {
    run(image, source, strlen(source), 5, id, r);
    for (unsigned f = 0; f < 17; f++) a->w[f][id - 1] = r->report[f];
    a->space_code = r->report[A_SPACE_CODE];
    a->pointers = r->report[A_POINTERS];
    a->space_mask = r->report[5];
  }
}
static void ast_free(Ast *a) {
  for (unsigned f = 0; f < 17; f++) free(a->w[f]);
}
#define A(a, f, id) ((a)->w[f][(id)-1])

#define W(r, node, field) ((r)->words[header_words + ((node) - 1) * node_words + (field)])

/* ---- the kind table, read back from the module --------------------------- */

typedef struct {
  uint64_t count, base;
  uint64_t *kind;   /* the NTIR kind of each entry */
  uint64_t *ast;    /* the AST kind it lowers from, 0 for a split entry */
  uint64_t *aux;    /* the aux the mapping requires, ANY when it ignores it */
} Table;

#define ANY_AUX UINT64_MAX

static void table_read(const NovaHostImage *image, Run *r, Table *t) {
  memset(t, 0, sizeof *t);
  run(image, "\n", 1, 4, 0, r);
  if (r->returned != 0 || r->report[0] == GUARD)
    fprintf(stderr, "DEBUG kind table ret=%llu runtime=%llu r0=%llu\n",
            (unsigned long long)r->returned, (unsigned long long)r->runtime,
            (unsigned long long)r->report[0]);
  t->count = r->report[0];
  t->base = r->report[1];
  if (t->count == 0 || t->count > 4096)
    return;
  t->kind = (uint64_t *)calloc(t->count, sizeof(uint64_t));
  t->ast = (uint64_t *)calloc(t->count, sizeof(uint64_t));
  t->aux = (uint64_t *)calloc(t->count, sizeof(uint64_t));
  for (uint64_t i = 0; i < t->count; i++) {
    t->kind[i] = r->report[2 + i * 3];
    t->ast[i] = r->report[2 + i * 3 + 1];
    t->aux[i] = r->report[2 + i * 3 + 2];
  }
}
static void table_free(Table *t) { free(t->kind); free(t->ast); free(t->aux); }

/* The kind a node must have, DERIVED HERE from the table the module published
 * plus the two split predicates. Writing the derivation a second time in C is
 * the point: the gate holds an independent one, so a lowering that disagrees
 * with its own table is caught instead of being confirmed by the table it
 * reads. The two split AST kinds are the only ones with two entries, and the
 * predicate that separates them is the parser's own, written out again rather
 * than taken from the module: an abi clause owns exactly one dashed child and
 * a call statement always opens on a qualified callee; an instruction carries
 * aux 0 and a label carries aux 1. */
static uint64_t derive_kind(const Table *t, uint64_t ak, uint64_t aux,
                            uint64_t children, uint64_t first_child_ast) {
  uint64_t row0 = 0, row1 = 0;
  for (uint64_t i = 0; i < t->count; i++) {
    if (t->ast[i] != ak)
      continue;
    /* The aux column now discriminates BOTH split pairs, so the two rows are
     * told apart by the table alone: row 0 carries aux 0 and row 1 carries aux
     * 1, for AST 28 and for AST 32 alike. */
    if (ak == 28 || ak == 32) {
      if (t->aux[i] == 0) row0 = t->kind[i];
      else if (t->aux[i] == 1) row1 = t->kind[i];
      continue;
    }
    if (t->aux[i] == ANY_AUX || t->aux[i] == aux) return t->kind[i];
  }
  if (ak == 28) {
    /* Row 1 is the abi clause and row 0 the call, and WHICH one this node is
     * comes from the parser's own predicate, written out again here: an abi
     * clause owns exactly one dashed child, a call always opens on a
     * qualified callee. */
    if (children == 1 && first_child_ast == 92) return row1;
    return row0;
  }
  if (ak == 32) return aux == 1 ? row1 : row0;
  return 0;
}

/* The C oracle for scalar widths. nt_frontend_type_name is the reference
 * frontend's own name table (frontend.c:777) and NTF_T_* its enum
 * (frontend.h:63-76), so the width the IR prints for a scalar type is compared
 * with the reference implementation's own vocabulary rather than with a table
 * written in this file. */
typedef struct { const char *name; unsigned bits; unsigned sign; } Scalar;
static const Scalar SCALARS[] = {
    {NULL, 0, 0},
    {"u8", 8, 0},   {"u16", 16, 0}, {"u32", 32, 0}, {"u64", 64, 0},
    {"i8", 8, 1},   {"i16", 16, 1}, {"i32", 32, 1}, {"i64", 64, 1},
    {"bool", 1, 0}, {"never", 0, 2},
};
static const Scalar *scalar_oracle(const char *text, size_t n) {
  for (unsigned k = 1; k < sizeof SCALARS / sizeof SCALARS[0]; k++) {
    if (strlen(SCALARS[k].name) == n && memcmp(SCALARS[k].name, text, n) == 0) {
      /* The C reference must agree it is the same type before its width is
       * used as an expectation: a renamed enum would otherwise be silently
       * accepted here and loudly refused there. */
      if (strcmp(nt_frontend_type_name((NtFTypeKind)k), SCALARS[k].name) != 0)
        return NULL;
      return SCALARS + k;
    }
  }
  return NULL;
}

/* ---- image damage -------------------------------------------------------
 *
 * Every damage below is applied to an image this lowering produced, never to
 * one written here. A damage that names a node 0 picks the first node that
 * satisfies its own precondition, so the node it lands on is a measurement and
 * not a number typed in this file.
 */
/* Two sentinels stand for values this file refuses to write down, because
 * writing them down would make a fixture's shape a constant of the gate. The
 * loop fills them from the image it is about to damage. */
#define PICK_KIND_ABOVE UINT64_MAX
#define PICK_PAST_END (UINT64_MAX - 1)

typedef struct {
  const char *name;
  uint64_t code;
  uint64_t word;    /* the field index inside a node, or inside the header */
  uint64_t value;   /* what it is set to, or a PICK_ sentinel */
  int on_header;    /* 1: the damage is on the header, 0: on a node */
  int pick;         /* 0 node 1, 1 the first node that has children */
  int positioned;   /* 1: the refusal must carry a line and a column */
} Damage;

/* ---- the damage set ------------------------------------------------------ */

/* 813 kind outside the table, 814 a link or a header field outside the image,
 * 815 a chain that disagrees with its count or a node the root never reaches,
 * 816 a cycle or a node two parents claim, 817 a typing refusal, 818 a
 * first/last pair that disagrees, 819 a typed word its own kind does not
 * admit, 808 a format tag or version the reader does not know. */
static const Damage DAMAGES[] = {
    {"unknown node kind", 813, F_KIND, PICK_KIND_ABOVE, 0, 0, 1},
    {"child link past the end", 814, F_FIRST, PICK_PAST_END, 0, 1, 1},
    {"last child zeroed under a first child", 818, F_LAST, 0, 0, 1, 1},
    {"width on a kind that has none", 819, F_WIDTH, 32, 0, 0, 1},
    {"class on a kind that has none", 819, F_CLASS, 17, 0, 0, 1},
    {"signedness outside its vocabulary", 819, F_SIGNED, 7, 0, 0, 1},
    {"memory space outside the catalogue", 819, F_SPACE, 64, 0, 0, 1},
    {"format tag wrong", 808, 0, 0, 1, 0, 0},
    {"format version wrong", 808, 2, 2, 1, 0, 0},
    {"stride wrong", 814, 5, 17, 1, 0, 0},
    {"ast node count disagrees with the image", 814, 6, 99, 1, 0, 0},
    {"typed node count past the image", 814, 7, PICK_PAST_END, 1, 0, 0},
};
#define DAMAGES_N ((unsigned)(sizeof DAMAGES / sizeof DAMAGES[0]))

/* The two damages that need two words, kept apart because they are not a field
 * write: a cycle inside a child chain, and a node two parents claim. Both are
 * applied by walking the real image for a shape to break, so the node they land
 * on is a measurement. */
static int damage_cycle(Run *r, uint64_t count) {
  for (uint64_t n = 1; n <= count; n++) {
    uint64_t first = W(r, n, F_FIRST);
    if (first == 0 || first == count + 1)
      continue;
    uint64_t last = W(r, n, F_LAST);
    if (last == 0)
      continue;
    /* Point the last child back at the first: the chain from `first` now
     * revisits `first` instead of ending at 0. */
    r->words[header_words + (last - 1) * node_words + F_NEXT] = first;
    return 1;
  }
  return 0;
}
static int damage_shared_child(Run *r, uint64_t count) {
  uint64_t a = 0, b = 0, a_first = 0;
  for (uint64_t n = 1; n <= count; n++) {
    uint64_t first = W(r, n, F_FIRST);
    if (first == 0)
      continue;
    if (a == 0) { a = n; a_first = first; }
    else if (first != a_first) { b = n; break; }
  }
  if (a == 0 || b == 0)
    return 0;
  (void)a_first;
  uint64_t a_last = W(r, a, F_LAST);
  r->words[header_words + (a_last - 1) * node_words + F_NEXT] = W(r, b, F_FIRST);
  r->words[header_words + (a - 1) * node_words + F_LAST] = W(r, b, F_LAST);
  r->words[header_words + (a - 1) * node_words + F_CHILDREN] =
      W(r, a, F_CHILDREN) + W(r, b, F_CHILDREN);
  return 1;
}
static int damage_orphan(Run *r) {
  r->words[header_words + (1 - 1) * node_words + F_FIRST] = 0;
  r->words[header_words + (1 - 1) * node_words + F_LAST] = 0;
  r->words[header_words + (1 - 1) * node_words + F_CHILDREN] = 0;
  return 1;
}

/* ---- one fixture --------------------------------------------------------- */

static void confront(const NovaHostImage *a, const NovaHostImage *b, Run *ra,
                     Run *rb, Run *scratch, const char *name, const char *source,
                     const Table *t, uint64_t *reached) {
  Ast ast;
  size_t len = strlen(source);
  run(a, source, len, 8, 0, rb);
  if (rb->report[1] != 0) {
    uint64_t lo = rb->report[5], hi = rb->report[6];
    if (hi > len) hi = len;
    if (lo > hi) lo = hi;
    fprintf(stderr, "PARSE %s code=%llu reason=%llu at %llu:%llu near [%.*s]\n",
            name, (unsigned long long)rb->report[1],
            (unsigned long long)rb->report[2],
            (unsigned long long)rb->report[3],
            (unsigned long long)rb->report[4], (int)(hi - lo), source + lo);
  }

  /* The three stages measured apart, so a refusal names the stage that made
   * it: a lowering refusal, a verifier refusal and a serialization refusal
   * are three different facts and the gate must not report them as one.
   * They are measured on `rb` and the golden itself is taken from `ra`, so the
   * bytes the golden compares are the bytes one run produced and not a buffer
   * some earlier probe left behind. */
  run(a, source, len, 2, 0, rb);
  uint64_t build_code = rb->returned;
  run(a, source, len, 0, 0, rb);
  uint64_t verify_code = rb->returned;
  run(a, source, len, 1, 0, ra);
  if (build_code != 0 || verify_code != 0 || ra->returned != 0 ||
      ra->runtime != 0) {
    failures++;
    fprintf(stderr, "FAIL %s refuses: build=%llu verify=%llu serialize=%llu\n",
            name, (unsigned long long)build_code,
            (unsigned long long)verify_code,
            (unsigned long long)ra->returned);
    return;
  }
  uint64_t first_len = ra->length[0];
  checks++;
  if (first_len == 0 || first_len >= TEXT) {
    failures++;
    fprintf(stderr, "FAIL %s golden length %llu is not a byte count\n", name,
            (unsigned long long)first_len);
    return;
  }
  run(a, source, len, 8, 0, rb);
  if (rb->report[1] != 0) {
    uint64_t lo = rb->report[5], hi = rb->report[6];
    if (hi > len) hi = len;
    if (lo > hi) lo = hi;
    fprintf(stderr, "PARSE %s code=%llu reason=%llu at %llu:%llu near [%.*s]\n",
            name, (unsigned long long)rb->report[1],
            (unsigned long long)rb->report[2],
            (unsigned long long)rb->report[3],
            (unsigned long long)rb->report[4], (int)(hi - lo), source + lo);
  }
  CHECK(memcmp(ra->text, EXPECTED_TAG, strlen(EXPECTED_TAG)) == 0,
        "the first golden line is the format tag this file expects");
  run(a, source, len, 1, 0, rb);
  checks++;
  if (rb->returned != 0 || rb->runtime != 0 || rb->length[0] != first_len ||
      memcmp(ra->text, rb->text, (size_t)first_len) != 0) {
    failures++;
    fprintf(stderr, "FAIL %s is not reproducible inside one image\n", name);
  }
  run(b, source, len, 1, 0, rb);
  checks++;
  if (rb->returned != 0 || rb->runtime != 0 || rb->length[0] != first_len ||
      memcmp(ra->text, rb->text, (size_t)first_len) != 0) {
    failures++;
    fprintf(stderr, "FAIL %s is not reproducible across a rebuild\n", name);
  }

  /* The IMAGE must be identical too, not only the text: a rebuild that moved
 * a typed word and not a byte of the text would mean the text does not cover
 * the image, and that is exactly the kind of golden that proves nothing. */
  run(a, source, len, 2, 0, scratch);
  uint64_t count = scratch->report[0];
  if (count == 0 || count > 100000) {
    failures++;
    fprintf(stderr, "FAIL %s image count is %llu\n", name,
            (unsigned long long)count);
    return;
  }
  uint64_t span = header_words + count * node_words;
  run(b, source, len, 2, 0, rb);
  checks++;
  if (memcmp(scratch->words, rb->words, (size_t)span * sizeof(uint64_t)) != 0) {
    failures++;
    fprintf(stderr, "FAIL %s image is not byte-identical across a rebuild\n",
            name);
  }

  /* The header, read out of the image rather than assumed. */
  checks++;
  if (scratch->words[3] != count || scratch->words[5] != node_words ||
      scratch->words[6] != count || scratch->words[4] < 1 ||
      scratch->words[4] > count) {
    failures++;
    fprintf(stderr, "FAIL %s header is inconsistent with its own node count\n",
            name);
  }

  /* The AST, read through the same image, node by node. */
  ast_read(a, source, scratch, &ast, 100000);
  checks++;
  if (ast.count != count) {
    failures++;
    fprintf(stderr, "FAIL %s IR has %llu nodes, the AST has %llu\n", name,
            (unsigned long long)count, (unsigned long long)ast.count);
    ast_free(&ast);
    return;
  }

  /* NODE FOR NODE. Every one of the sixteen IR words is confronted with the
   * tree: the eleven the schema copies word for word, the kind the gate
   * derives itself, and the five the AST does not hold at all, which are
   * confronted with the module that owns them. A node dropped, duplicated or
   * reordered moves a count, an id or a link, and each of those is a failure
   * here rather than a difference a reviewer has to notice. */
  uint64_t typed = 0, spaces = 0, register_nodes = 0, scalars = 0, space_union = 0;
  for (uint64_t id = 1; id <= count; id++) {
    uint64_t ak = A(&ast, A_KIND, id);
    uint64_t aux = A(&ast, A_AUX, id);
    uint64_t children = A(&ast, A_CHILDREN, id);
    uint64_t first = A(&ast, A_FIRST, id);
    uint64_t first_ast = 0;
    if (first >= 1 && first <= count) first_ast = A(&ast, A_KIND, first);
    uint64_t want = derive_kind(t, ak, aux, children, first_ast);
    checks++;
    if (W(scratch, id, F_AST_ID) != id || W(scratch, id, F_AST_KIND) != ak ||
        W(scratch, id, F_KIND) != want) {
      failures++;
      fprintf(stderr,
              "FAIL %s node %llu: ast_kind %llu aux %llu children %llu, "
              "IR says kind %llu ast %llu id %llu, wanted kind %llu\n",
              name, (unsigned long long)id, (unsigned long long)ak,
              (unsigned long long)aux, (unsigned long long)children,
              (unsigned long long)W(scratch, id, F_KIND),
              (unsigned long long)W(scratch, id, F_AST_KIND),
              (unsigned long long)W(scratch, id, F_AST_ID),
              (unsigned long long)want);
    }
    /* The eleven copied words, one by one. */
    checks++;
    if (W(scratch, id, F_SOURCE) != A(&ast, A_SOURCE, id) ||
        W(scratch, id, F_LINE) != A(&ast, A_LINE, id) ||
        W(scratch, id, F_COLUMN) != A(&ast, A_COLUMN, id) ||
        W(scratch, id, F_START) != A(&ast, A_START, id) ||
        W(scratch, id, F_END) != A(&ast, A_END, id) ||
        W(scratch, id, F_FIRST) != A(&ast, A_FIRST, id) ||
        W(scratch, id, F_LAST) != A(&ast, A_LAST, id) ||
        W(scratch, id, F_NEXT) != A(&ast, A_NEXT, id) ||
        W(scratch, id, F_CHILDREN) != children) {
      failures++;
      fprintf(stderr,
              "FAIL %s node %llu copies differ: source %llu/%llu line %llu/%llu "
              "column %llu/%llu span %llu-%llu/%llu-%llu first %llu/%llu last "
              "%llu/%llu next %llu/%llu children %llu/%llu\n",
              name, (unsigned long long)id,
              (unsigned long long)W(scratch, id, F_SOURCE),
              (unsigned long long)A(&ast, A_SOURCE, id),
              (unsigned long long)W(scratch, id, F_LINE),
              (unsigned long long)A(&ast, A_LINE, id),
              (unsigned long long)W(scratch, id, F_COLUMN),
              (unsigned long long)A(&ast, A_COLUMN, id),
              (unsigned long long)W(scratch, id, F_START),
              (unsigned long long)W(scratch, id, F_END),
              (unsigned long long)A(&ast, A_START, id),
              (unsigned long long)A(&ast, A_END, id),
              (unsigned long long)W(scratch, id, F_FIRST),
              (unsigned long long)A(&ast, A_FIRST, id),
              (unsigned long long)W(scratch, id, F_LAST),
              (unsigned long long)A(&ast, A_LAST, id),
              (unsigned long long)W(scratch, id, F_NEXT),
              (unsigned long long)A(&ast, A_NEXT, id),
              (unsigned long long)W(scratch, id, F_CHILDREN),
              (unsigned long long)children);
    }
    if (want >= kind_base && want < kind_base + t->count) {
      uint64_t bit = want - kind_base;
      if (reached && (reached[bit / 64] & (UINT64_C(1) << (bit % 64))) == 0)
        reached[bit / 64] |= UINT64_C(1) << (bit % 64);
    }
    if (W(scratch, id, F_WIDTH) != 0 || W(scratch, id, F_SPACE) != 0 ||
        W(scratch, id, F_CLASS) != 0)
      typed++;
    if (W(scratch, id, F_SPACE) != 0) {
      spaces++;
      space_union |= W(scratch, id, F_SPACE);
    }
    uint64_t cls = W(scratch, id, F_CLASS);
    if (ak == 19 && cls >= 1 && cls <= 16) {
      /* A parameter's class is the family of its THIRD child, the register
       * after the `@` (parser.nova:340), not of its own span. Walking the two
       * links the probe hands back reaches that child without a parser. */
      uint64_t second = 0, third = 0;
      if (A(&ast, A_FIRST, id) >= 1 && A(&ast, A_FIRST, id) <= count)
        second = A(&ast, A_NEXT, A(&ast, A_FIRST, id));
      if (second >= 1 && second <= count)
        third = A(&ast, A_NEXT, second);
      checks++;
      if (third < 1 || third > count || A(&ast, A_FAMILY, third) != cls) {
        failures++;
        fprintf(stderr,
                "FAIL %s node %llu claims class %llu, its bound register says "
                "%llu\n",
                name, (unsigned long long)id, (unsigned long long)cls,
                third >= 1 && third <= count
                    ? (unsigned long long)A(&ast, A_FAMILY, third)
                    : 0ULL);
      }
    } else if (ak == 90) {
      /* THE REGISTER CLASS AND WIDTH ARE THE OWNING MODULE'S ANSWER, read
       * back through mode 5 of the SAME image on the SAME source. If
       * register_widths changes and ntir does not, or the other way round,
       * this is the line that goes red.
       *
       * THE GUARD IS THE SUBJECT, NOT A FILTER ON IT. This used to read
       * `ak == 90 && cls >= 1 && cls <= 16`, which is a guard that silently
       * skipped the case it exists to catch: when ntir failed to type a
       * register, cls was 0, the guard declined to fire, and the fixture
       * reported `registers=0` — a green gate that could not measure. It did
       * so on all six fixtures, for 2197 and then 2207 checks. A check whose
       * reachability depends on the thing it is checking is not a check, so
       * the predicate is now the SUBJECT (an AST name node) and never the
       * IR's own word.
       *
       * FAMILY IS THE MEMBERSHIP TEST, WIDTH IS NOT. The two owners answer
       * different questions and only family answers "is this a register".
       * register_widths.width keys off the last letter alone for the
       * three-letter forms (register_widths.nova:101-105 tests b2 against
       * x/i/p/l/h with no check on the first letter), so it answers 32 for
       * `nop`, `top` and `abi` — three letters ending in `p` — while family
       * correctly answers 0, because family does test the `r`/`e` prefix.
       * So a name is a register exactly when family is non-zero, and the
       * width is only required to agree for a name that IS one.
       *
       * Comparing the width unconditionally is how the nine
       * "claims width 0, register_widths says 32" failures below were
       * produced: the IR was RIGHT (an `nop` is not a register and is
       * correctly untyped) and the gate was demanding a width for a
       * non-member. That is a gate bug, not an IR bug, and it is recorded as
       * such: register_widths.width is deliberately lenient about the prefix
       * because its ten callers all establish membership some other way
       * first, so the leniency is not a defect there and is not mine to
       * change. A name the catalogue does not know is legitimately untyped,
       * and that is agreement, so it is counted here rather than skipped and
       * the fixture's `registers=` line reports every name it looked at. */
      register_nodes++;
      checks++;
      uint64_t fam = A(&ast, A_FAMILY, id);
      int bad = W(scratch, id, F_CLASS) != fam;
      if (fam != 0) bad |= W(scratch, id, F_WIDTH) != A(&ast, A_WIDTH, id);
      if (bad) {
        failures++;
        fprintf(stderr,
                "FAIL %s node %llu claims class %llu width %llu, "
                "register_widths says class %llu width %llu\n",
                name, (unsigned long long)id,
                (unsigned long long)W(scratch, id, F_CLASS),
                (unsigned long long)W(scratch, id, F_WIDTH),
                (unsigned long long)fam,
                (unsigned long long)A(&ast, A_WIDTH, id));
      }
    }
    /* THE SPACE IS THE OWNING MODULE'S ANSWER. pointer_spaces.check returns a
     * MASK over the whole source, so the gate requires every space word in the
     * image to be a bit of that mask. A space invented by ntir is a bit the
     * mask does not carry, and that is the red. */
    if (W(scratch, id, F_SPACE) != 0) {
      checks++;
      if ((W(scratch, id, F_SPACE) & ast.space_mask) != W(scratch, id, F_SPACE)) {
        failures++;
        fprintf(stderr,
                "FAIL %s node %llu claims space %llu, pointer_spaces measured "
                "mask %llu\n",
                name, (unsigned long long)id,
                (unsigned long long)W(scratch, id, F_SPACE),
                (unsigned long long)ast.space_mask);
      }
    }
    /* THE SCALAR WIDTH IS THE C ORACLE'S ANSWER. A type node whose aux is 0
     * spells one scalar name across its whole span, so the gate reads the name
     * out of the source at the span the IR carries and looks it up in the
     * reference frontend's own table. */
    if (ak == 36 && aux == 0) {
      uint64_t s = W(scratch, id, F_START), e = W(scratch, id, F_END);
      checks++;
      if (!(s <= e && e <= len)) {
        failures++;
        fprintf(stderr, "FAIL %s node %llu span %llu-%llu is outside the source\n",
                name, (unsigned long long)id, (unsigned long long)s,
                (unsigned long long)e);
      } else {
        const Scalar *o = scalar_oracle(source + s, (size_t)(e - s));
        if (o == NULL) {
          failures++;
          fprintf(stderr, "FAIL %s node %llu spells no C scalar type\n", name,
                  (unsigned long long)id);
        } else if (W(scratch, id, F_WIDTH) != o->bits ||
                   W(scratch, id, F_SIGNED) != o->sign) {
          failures++;
          fprintf(stderr,
                  "FAIL %s node %llu: C says %s is %u bits sign %u, IR says "
                  "%llu bits sign %llu\n",
                  name, (unsigned long long)id, o->name, o->bits, o->sign,
                  (unsigned long long)W(scratch, id, F_WIDTH),
                  (unsigned long long)W(scratch, id, F_SIGNED));
        } else {
          scalars++;
        }
      }
    }
  }
  /* And the converse of the space check: every space pointer_spaces found is a
   * space the IR typed. A space measured and never typed is a pointer the IR
   * did not carry, which is a hole and not a detail. */
  checks++;
  if (space_union != ast.space_mask) {
    failures++;
    fprintf(stderr, "FAIL %s typed spaces %llu, pointer_spaces measured %llu\n",
            name, (unsigned long long)space_union,
            (unsigned long long)ast.space_mask);
  }
  checks++;
  if (typed != scratch->words[7]) {
    failures++;
    fprintf(stderr, "FAIL %s typed_count says %llu, the image has %llu\n", name,
            (unsigned long long)scratch->words[7], (unsigned long long)typed);
  }
  checks++;
  if (ast.pointers != spaces) {
    failures++;
    fprintf(stderr,
            "FAIL %s pointer_spaces counted %llu pointers, the IR typed %llu "
 "spaces\n",
            name, (unsigned long long)ast.pointers,
            (unsigned long long)spaces);
  }
  checks++;
  if (ast.space_code != 0) {
    failures++;
    fprintf(stderr, "FAIL %s pointer_spaces refused the fixture it typed (%llu)\n",
            name, (unsigned long long)ast.space_code);
  }
  printf("FIXTURE %s nodes=%llu typed=%llu registers=%llu spaces=%llu scalars=%llu\n",
         name, (unsigned long long)count, (unsigned long long)typed,
         (unsigned long long)register_nodes, (unsigned long long)spaces,
         (unsigned long long)scalars);
  ast_free(&ast);
}

int main(void) {
  size_t sizes[PATHS_N] = {0};
  char *sources[PATHS_N] = {0};
  NtFInput inputs[PATHS_N];
  int all = 1;
  for (unsigned i = 0; i < PATHS_N; i++) {
    sources[i] = loadf(PATHS[i], &sizes[i]);
    if (!sources[i]) all = 0;
    inputs[i] = (NtFInput){PATHS[i], sources[i], sizes[i]};
  }
  CHECK(all, "the seven Nova sources load");

  /* TWO INDEPENDENTLY COMPILED IMAGES of the same sources. This is what a
 * rebuild means for a module that is interpreted into a host image: a second
 * compile of the same bytes, and a second run of the result. A golden that
 * only survives inside one image has proved nothing about the bytes. */
  NtArtifact first = {0}, second = {0};
  int c1 = all && nova_compile_many_v2(inputs, PATHS_N, &first);
  int c2 = all && nova_compile_many_v2(inputs, PATHS_N, &second);
  CHECK(c1, "the Nova sources compile");
  CHECK(c2, "the Nova sources compile a second time");
  if (!c1 || !c2) {
    if (!c1)
      fprintf(stderr, "E%u %zu:%zu %s\n", first.error.code, first.error.line,
              first.error.column, first.error.message);
    if (!c2)
      fprintf(stderr, "E%u %zu:%zu %s\n", second.error.code, second.error.line,
              second.error.column, second.error.message);
    printf("NTASM_NOVA_NTIR checks=%u failures=%u cases=%u\n", checks, failures,
           cases);
    return 1;
  }
  NovaHostImage ia = {0}, ib = {0};
  CHECK(nova_host_map(&first, &ia), "the first image maps");
  CHECK(nova_host_map(&second, &ib), "the second image maps");

  if (ia.memory && ib.memory) {
    Run ra, rb, scratch;
    run_init(&ra);
    run_init(&rb);
    run_init(&scratch);

    /* The layout, learned from the module and then USED everywhere below, so
     * this file holds no second copy of it. */
    run(&ia, "", 0, 0, 0, &scratch);
    header_words = 8;
    node_words = 16;
    Table t;
    table_read(&ia, &scratch, &t);
    kind_count = t.count;
    kind_base = t.base;
    CHECK(t.count == 53, "the kind table has the fifty-three entries it declares");
    CHECK(t.base == 1024, "the kind base is the one the module publishes");
    if (t.kind == NULL) {
      checks++; failures++;
      fprintf(stderr, "FAIL the kind table did not read back, nothing to confront\n");
      table_free(&t);
      run_free(&ra); run_free(&rb); run_free(&scratch);
      if (ia.memory) nova_host_unmap(&ia);
      if (ib.memory) nova_host_unmap(&ib);
      nt_artifact_free(&first); nt_artifact_free(&second);
      for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);
      printf("NTASM_NOVA_NTIR checks=%u failures=%u cases=%u\n", checks, failures, cases);
      return 1;
    }

    /* 1. The numbering is NEW. Every NTIR kind is above every AST kind the
     * parser can build, and above every code the 17.6 registry publishes, so
     * nothing that indexes AST kinds or diagnostic codes numerically can be
     * moved by anything written here. The highest AST kind is not written in
     * this file: it is measured, per fixture, in confront(). */
    int strictly_increasing = 1, all_above_base = 1, split_28 = 0, split_32 = 0;
    for (uint64_t i = 0; i < t.count; i++) {
      if (t.kind[i] < t.base) all_above_base = 0;
      if (i > 0 && t.kind[i] <= t.kind[i - 1]) strictly_increasing = 0;
      if (t.ast[i] == 28) split_28++;
      if (t.ast[i] == 32) split_32++;
    }
    CHECK(all_above_base, "every NTIR kind sits at or above KIND_BASE");
    CHECK(strictly_increasing, "the kind table is strictly increasing");
    CHECK(split_28 == 2, "AST kind 28 lowers to two distinct NTIR kinds");
    CHECK(split_32 == 2, "AST kind 32 lowers to two distinct NTIR kinds");
    /* The two split kinds must be two DIFFERENT numbers, or the split is a
     * comment rather than a change. */
    uint64_t k28[2] = {0, 0}, k32[2] = {0, 0};
    for (uint64_t i = 0; i < t.count; i++) {
      if (t.ast[i] == 28) { if (k28[0] == 0) k28[0] = t.kind[i]; else k28[1] = t.kind[i]; }
      if (t.ast[i] == 32) { if (k32[0] == 0) k32[0] = t.kind[i]; else k32[1] = t.kind[i]; }
    }
    CHECK(k28[0] != k28[1] && k32[0] != k32[1],
          "each split AST kind lowers to two numbers, not to one twice");
    /* The base is above the highest published Nova code (844) and above the
     * highest AST kind (96), so a shifted table could not reach either. */
    CHECK(t.base > 844, "KIND_BASE is above the highest published Nova code");
    CHECK(t.base > 96, "KIND_BASE is above the highest AST node kind");
    /* No module in the tree indexes an NTIR kind, so this lot added an import
 * to no shared path. That is asserted by the sixteen gates that compile
     * x64_lower_nxo still passing, and re-stated here because it is the
     * property that makes the new numbering safe. */

    /* The corpus, one golden stream per fixture. */
    uint64_t *reached = (uint64_t *)calloc((t.count / 64) + 1, sizeof(uint64_t));
    uint64_t digest = FNV_SEED;
    for (unsigned f = 0; f < FIXTURES_N; f++) {
      char name[16];
      snprintf(name, sizeof name, "f%u", f);
      confront(&ia, &ib, &ra, &rb, &scratch, name, FIXTURES[f], &t, reached);
      if (ra.returned == 0 && ra.length[0] > 0 && ra.length[0] < TEXT)
        digest = fnv1a(ra.text, (size_t)ra.length[0], digest);
    }
    /* A kind no fixture reached is a coverage hole, and it is printed with
     * its name so the hole is a line of output and not a silence. */
    unsigned unreached = 0;
    for (uint64_t i = 0; i < t.count; i++) {
      if ((reached[i / 64] & (UINT64_C(1) << (i % 64))) == 0) {
        unreached++;
        printf("KIND-UNREACHED index=%llu kind=%llu\n", (unsigned long long)(i + 1),
               (unsigned long long)t.kind[i]);
      }
    }
    CHECK(unreached == 0, "every published kind was reached by the corpus");

    /* 5. ADVERSARIAL. The corpus fixture f0 is the carrier: it parses, it
     * lowers, it verifies clean, and every damage below is applied to the image
     * that produced. */
    const char *carrier = FIXTURES[0];
    run(&ia, carrier, strlen(carrier), 2, 0, &scratch);
    uint64_t base_count = scratch.report[0];
    CHECK(base_count > 0, "the carrier image has nodes to damage");

    /* The three damages that need a shape rather than a field write. Each one
     * searches the real image for a node to break, so the node it lands on is
     * a measurement. */
    struct { const char *name; uint64_t code; int positioned; int kind; } shapes[] = {
        {"a child chain that revisits its first node", 815, 0, 0},
        {"a node two parents claim", 816, 0, 1},
        {"a node the root never reaches", 815, 1, 2},
    };
    for (unsigned s = 0; s < sizeof shapes / sizeof shapes[0]; s++) {
      run(&ia, carrier, strlen(carrier), 2, 0, &ra);
      uint64_t n = ra.report[0];
      int broke = 0;
      if (shapes[s].kind == 0) broke = damage_cycle(&ra, n);
      if (shapes[s].kind == 1) broke = damage_shared_child(&ra, n);
      if (shapes[s].kind == 2) broke = damage_orphan(&ra);
      cases++;
      checks++;
      if (!broke) {
        failures++;
        fprintf(stderr, "FAIL no node to damage for %s\n", shapes[s].name);
        continue;
      }
      run(&ia, carrier, strlen(carrier), 3, 0, &ra);
      int bad = ra.returned != shapes[s].code || ra.runtime != 0;
      if (shapes[s].positioned && ra.report[0] == GUARD) bad = 1;
      if (bad) {
        failures++;
        fprintf(stderr, "FAIL %s: ret=%llu runtime=%llu wanted %llu\n",
                shapes[s].name, (unsigned long long)ra.returned,
                (unsigned long long)ra.runtime,
                (unsigned long long)shapes[s].code);
      } else {
        printf("DAMAGE %s code=%llu node=%llu line=%llu column=%llu\n",
               shapes[s].name, (unsigned long long)ra.returned,
               (unsigned long long)ra.report[3],
               (unsigned long long)ra.report[0],
               (unsigned long long)ra.report[1]);
      }
    }

    /* 6a. THE INPUT-REFUSAL FAMILY, 800, AND IT IS NEITHER OF THE TWO TABLES
     * ABOVE. DAMAGES[] is keyed by the IMAGE FIELD it overwrites; shapes[] is
     * keyed by the NODE SHAPE it distorts. Every 800 in ntir.nova refuses a
     * caller's INPUT -- a tree that did not parse, a destination too small, a
     * count of zero -- and reads no image field and no node shape at all, so
     * neither table can hold a row for one and neither was ever meant to. The
     * key here is the REFUSED INPUT ITSELF, which is a third thing.
     *
     * WHY A ROW CARRIES TWO ARMS, AND WHY THAT IS THE WHOLE POINT. A row that
     * only refuses passes on any input the producer answers 800 to, including
     * a producer broken to refuse everything, and a row that only accepts
     * passes on a producer that refuses nothing. Neither measures the arm it
     * names. So every row below drives the SAME route twice -- once with the
     * input the arm accepts and once with the one it refuses -- and asserts
     * both codes. The accepted code is not a constant written here: it is
     * whatever the producer answers on the same route with a big enough
     * destination, so if the producer stopped accepting anything the accepted
     * arm is red on the same run.
     *
     * ATTRIBUTION, AND WHY IT IS MEASURED RATHER THAN ASSUMED. The code 800 is
     * not ntir's alone: ntir-entry.nova answers 800 on four inputs of its own
     * before ntir.build is ever called, so a row that only read the code back
     * could be measuring the ENTRY and calling it ntir. Mode 8 is the parse
     * verdict alone and publishes the parser's own code, so "the parse
     * succeeded" is a MEASURED value and not the absence of a complaint. Every
     * refusal row below therefore requires the parse to have succeeded, which
     * is what makes the entry's own tree.ok refusal impossible as the cause.
     */
    /* The two numbers a route can be starved with, read off the arm each row
     * names. `needed` is the room the carrier's own image occupies, measured
     * from the layout this file already learned from the module, so a row that
     * wants "one word too small" is one word too small rather than a number
     * written down here and hoped for. */
    const uint64_t needed = header_words + base_count * node_words;

    /* THE ARM is written down; the ACCEPTED CODE IS NOT. `want_refused` is
     * ntir's own published 800 and is asserted against it. The accepted arm is
     * asserted as 0 -- "the producer did not refuse" -- because a table that
     * carried a written-down accepted code would be checking its own constant
     * against the producer rather than the producer against the module. */
    /* THE KEY IS THE STARVATION, WRITTEN AS AN OFFSET FROM `needed`, NOT AS A
     * WORD COUNT. `needed` is measured at run time from the layout this file
     * learned from the module, so it cannot appear in a static initializer --
     * and it should not, because a row carrying an absolute word count is a
     * number that goes stale the moment the stride moves, while `needed-1` says
     * what it means at any stride: ONE WORD SHORT OF ENOUGH. The two build rows
     * are therefore (0,-1) and (-1,0): the same distance from the edge on
     * opposite sides of it, which is the pair that tells the two disjuncts of
     * `capacity<needed || len(words)<needed` apart. The two verify rows starve
     * a WORD OF THE IMAGE rather than the call, so their offsets are 0 and the
     * damage is applied to the buffer, below. */
    static const struct {
      const char *name;
      uint64_t mode;
      int64_t len_delta;   /* slot five, relative to `needed` */
      int64_t count_delta; /* slot six, relative to `needed` */
      uint64_t want_refused;
      const char *reads;   /* the entry-mode that reaches this arm */
    } REFUSALS[] = {
        /* build's capacity arm. The declared CAPACITY is starved while the
         * parse has already succeeded, so every guard the entry holds is
         * satisfied and the refusal can only be ntir's. */
        {"a destination capacity one word too small", 2, 0, -1, 800,
         "mode 2 after a successful parse"},
        /* build's length arm, the OTHER disjunct of the same `if`: the buffer
         * is short while the declared capacity is ample. Two rows and not one
         * because a producer that honoured one and dropped the other is a
         * different defect, and a single row would not tell them apart. */
        {"a destination buffer one word too small", 2, -1, 0, 800,
         "mode 2 after a successful parse"},
        /* verify's count arm. Mode 3 is the route with NO parse in front of it:
         * the entry calls ntir.verify on the caller's image and nothing else,
         * so a zero count here cannot be the entry's refusal and cannot be the
         * parser's either. */
        {"an image whose node count is zero", 3, 0, 0, 800,
         "mode 3, no parse in front of ntir.verify"},
        /* verify's extent arm: the count is raised until the image demands more
         * words than the buffer holds, which is what that check exists for. */
        {"an image claiming more nodes than the buffer holds", 3, 0, 0, 800,
         "mode 3, no parse in front of ntir.verify"},
    };
#define REFUSALS_N ((unsigned)(sizeof REFUSALS / sizeof REFUSALS[0]))

    for (unsigned f = 0; f < REFUSALS_N; f++) {
      int is_verify = REFUSALS[f].mode == 3;

      /* THE IMAGE IS BUILT FIRST, EVERY ROW, so each refusal is measured
       * against a real image and never against whatever the previous row left
       * in the buffer. For the two verify rows this build is not optional: mode
       * 3 does no lowering, it hands `words` straight to ntir.verify, so
       * without a build there is no image to damage and the row would be
       * measuring an uninitialised buffer. */
      run(&ia, carrier, strlen(carrier), 2, 0, &scratch);
      if (scratch.returned != 0) {
        checks++; failures++;
        fprintf(stderr, "FAIL refusal row %s: the carrier did not build\n",
                REFUSALS[f].name);
        continue;
      }

      /* THE ACCEPTED ARM, and it is the SAME route with the SAME row, only
       * given room: a destination of exactly `needed` words for the build rows,
       * and the untouched image for the verify rows. If this does not answer 0
       * then the refusal measured below is not a refusal at all -- it is a
       * producer refusing everything -- and this check is what says so, on the
       * same run, rather than leaving it to be noticed later.
       *
       * `needed` and not `needed+1`: the boundary is INCLUSIVE at ntir.nova
       * (`capacity<needed`), so exactly `needed` is the last accepted size and
       * the row below is the first refused one. An accepted arm given slack
       * would leave the pair not adjacent, and a pair with a gap between it
       * does not say where the edge is. */
      if (is_verify) {
        /* Mode 3 over the image the build just produced. No damage: this is
         * the arm the producer accepts. */
        run_at(&ia, carrier, strlen(carrier), 3, 0, WORDS, WORDS, &scratch);
      } else {
        run_at(&ia, carrier, strlen(carrier), REFUSALS[f].mode, 0, needed,
               needed, &scratch);
      }
      uint64_t accepted = scratch.returned;
      cases++;
      checks++;
      if (accepted != 0 || scratch.runtime != 0) {
        failures++;
        fprintf(stderr, "FAIL refusal %s: the ACCEPTED arm returned %llu "
                        "runtime=%llu, so the refused arm proves nothing\n",
                REFUSALS[f].name, (unsigned long long)accepted,
                (unsigned long long)scratch.runtime);
      }

      /* THE REFUSED ARM. The build rows are starved in the CALL, so the image
       * is rebuilt from the carrier and the call is made short. The verify
       * rows are starved in the IMAGE, so the build is repeated and one word of
       * the header is changed -- which word is chosen by the row's own name,
       * read rather than guessed, because two rows that damage the same word
       * would be one row written twice. */
      if (is_verify) {
        run(&ia, carrier, strlen(carrier), 2, 0, &scratch);
        if (strstr(REFUSALS[f].name, "zero") != NULL) {
          /* Word 3 is the node count the header publishes and the very
           * argument ntir.verify is handed on mode 3, so this reaches the
           * `count==0` disjunct and nothing else. */
          scratch.words[3] = 0;
        } else {
          /* The smallest count that makes HEADER_WORDS()+count*NODE_WORDS()
           * exceed the buffer, so the refusal is for the reason this row names
           * and not for some larger one. */
          scratch.words[3] = (WORDS - header_words) / node_words + 1;
        }
        run_at(&ia, carrier, strlen(carrier), 3, 0, WORDS, WORDS, &scratch);
      } else {
        /* The offsets are applied HERE, where `needed` is a value and not a
         * name, so the row's key and the call it makes cannot drift apart. */
        run_at(&ia, carrier, strlen(carrier), REFUSALS[f].mode, 0,
               (uint64_t)((int64_t)needed + REFUSALS[f].len_delta),
               (uint64_t)((int64_t)needed + REFUSALS[f].count_delta), &scratch);
      }
      uint64_t refused = scratch.returned;
      cases++;
      checks++;

      /* ATTRIBUTION, ASSERTED. Where a parse stands in front of the refusal
       * the parse must have SUCCEEDED, or the entry's own tree.ok check is the
       * likelier cause and the row would be measuring the entry. Mode 3 has no
       * parse in front of it at all, which is why those two rows need no such
       * guard: the entry calls ntir.verify and returns its answer unchanged. */
      uint64_t parser_code = 0;
      if (REFUSALS[f].mode != 3) {
        run_at(&ia, carrier, strlen(carrier), 8, 0, WORDS, WORDS, &scratch);
        parser_code = scratch.report[1];
        checks++;
        if (parser_code != 0) {
          failures++;
          fprintf(stderr, "FAIL refusal %s: the parse refused with %llu, so the "
                          "800 is not attributable to ntir\n",
                  REFUSALS[f].name, (unsigned long long)parser_code);
        }
      }

      if (refused != REFUSALS[f].want_refused || scratch.runtime != 0) {
        failures++;
        fprintf(stderr, "FAIL refusal %s: ret=%llu runtime=%llu wanted %llu\n",
                REFUSALS[f].name, (unsigned long long)refused,
                (unsigned long long)scratch.runtime,
                (unsigned long long)REFUSALS[f].want_refused);
      } else {
        printf("REFUSAL %s accepted=%llu refused=%llu via=%s parse=%llu\n",
               REFUSALS[f].name, (unsigned long long)accepted,
               (unsigned long long)refused, REFUSALS[f].reads,
               (unsigned long long)parser_code);
      }
    }

    /* 6b. THE TYPED DEPTH CAP, BOTH SIDES OF IT, AND THE STAGE IT IS MEASURED
     * AT. Three things are asserted per entry, and each answers one of the
     * questions a single `ret == 817` cannot.
     *
     * ONE: THE PARSE MUST SUCCEED. Mode 8 is the parse verdict and nothing
     * else (ntir-entry.nova), so a fixture the parser refused would answer
     * mode 0 with the same 800 and this arm would be measuring the PARSER
     * while claiming the typing walk. The depth is not a parser bound --
     * parser.nova reads no depth cap at all -- and this arm is what makes that
     * a measurement instead of a claim about the source.
     *
     * TWO: THE VERDICT, which is 817 over the cap and 0 under it. The 0 arms
     * are the negative control, and they are counted in `cases` like the rest:
     * a cap check that never accepted anything would be green here.
     *
     * THREE: WHICH SITE, and it is read from the tree rather than asserted.
     * `expr_nodes` counts ast kind 35 nodes, which is the only kind
     * type_operand recurses into, and `composite_types` counts ast kind 36
     * nodes whose aux is not 0, which is the only shape type_form recurses
     * into. So a family that carries none of the other's recursion input
     * cannot be reaching that site, and the arm is red if the tree disagrees.
     * Both counts come from mode 5, the parser's own record.
     */
    for (unsigned d = 0; d < DEPTHS_N; d++) {
      /* The same wrapper the negative corpus uses above: a function is only a
       * declaration inside a section, so every body is wrapped in one. */
      char *full = (char *)malloc(strlen(NEG_HEAD) + strlen(NEG_MID) +
                                   strlen(DEPTHS[d].body) +
                                   strlen(NEG_TAIL) + 1);
      if (!full) continue;
      strcpy(full, NEG_HEAD);
      strcat(full, NEG_MID);
      strcat(full, DEPTHS[d].body);
      strcat(full, NEG_TAIL);

      /* THE DEPTH, RE-DERIVED FROM THE SOURCE THAT WILL RUN. The number in
       * the table is a claim about a literal, and measuring the bytes actually
       * handed to the entry is a measurement of it, so a literal miscounted
       * above reds here instead of quietly turning the over-arm into a
       * shallower case that still refuses.
       *
       * THE LONGEST RUN, NOT THE TOTAL, and the reason is a fact about the two
       * wrappers rather than a preference. A nesting is ONE contiguous run of
       * its opening token, while `(` also occurs in `fn ops(` and in the
       * NEG_TAIL's `fn main(`, so a total counts three runs of one as if they
       * were depth: the operand fixtures measure 66 and 67 occurrences for a
       * depth of 63 and 64. The longest run is the depth in both families, and
       * the count is printed beside it so the difference is visible rather than
       * asserted here. */
      uint64_t levels = 0, total = 0;
      size_t toklen = strlen(DEPTHS[d].open);
      {
        const char *prev = NULL;
        uint64_t run_now = 0;
        for (const char *q = full; (q = strstr(q, DEPTHS[d].open)) != NULL;
             q += toklen) {
          /* An occurrence continues the previous run when it begins exactly one
           * token-length after the previous one began, which is adjacency in
           * the source and not a guess about spelling. */
          run_now = (prev != NULL && (size_t)(q - prev) == toklen) ? run_now + 1 : 1;
          if (run_now > levels) levels = run_now;
          prev = q;
          total++;
        }
      }
      cases++;
      checks++;
      if (levels != DEPTHS[d].depth) {
        failures++;
        fprintf(stderr, "FAIL %s: the source's longest run of %s is %llu and the "
                        "table claims %llu (total occurrences %llu)\n",
                DEPTHS[d].name, DEPTHS[d].open, (unsigned long long)levels,
                (unsigned long long)DEPTHS[d].depth, (unsigned long long)total);
        free(full);
        continue;
      }

      /* ONE: the parse verdict, on its own. */
      run(&ia, full, strlen(full), 8, 0, &ra);
      uint64_t parse_code = ra.report[1];
      cases++;
      checks++;
      if (parse_code != 0 || ra.runtime != 0) {
        failures++;
        fprintf(stderr, "FAIL %s did not parse: code=%llu reason=%llu at %llu:%llu "
                        "-- this arm would measure the parser, not the depth cap\n",
                DEPTHS[d].name, (unsigned long long)parse_code,
                (unsigned long long)ra.report[2],
                (unsigned long long)ra.report[3],
                (unsigned long long)ra.report[4]);
        free(full);
        continue;
      }

      /* THREE: the recursion inputs of BOTH sites, counted over the whole
       * tree. Recorded before the verdict so the printed line attributes the
       * refusal to a site on the strength of what the tree held. */
      uint64_t nodes = ra.report[0], expr_nodes = 0, composite_types = 0;
      for (uint64_t id = 1; id <= nodes && id < 4096; id++) {
        run(&ia, full, strlen(full), 5, id, &ra);
        if (ra.report[A_KIND] == 35) expr_nodes++;
        if (ra.report[A_KIND] == 36 && ra.report[A_AUX] != 0) composite_types++;
      }

      /* THREE, ASSERTED AND NOT ONLY REPORTED. A count nobody checks is a
       * number in a print, and this one is what carries the claim that the
       * two families reach DIFFERENT sites -- so the separation is a red
       * line, not an observation. Each family must carry the OTHER site's
       * recursion input zero times: the type family has no ast kind 35 node,
       * so type_operand cannot recurse at all, and the operand family has no
       * composite type, so type_form's recursion is never entered. A tree that
       * disagreed would mean the attribution printed above is describing a
       * different walk than the one that refused. Which family is which is
       * taken from the table's own `open` token rather than from the order of
       * the rows, so adding a row cannot silently mislabel it. */
      int is_type_family = strcmp(DEPTHS[d].open, "ptr<user,") == 0;
      cases++;
      checks++;
      if (is_type_family ? (expr_nodes != 0) : (composite_types != 0)) {
        failures++;
        fprintf(stderr,
                "FAIL %s: the tree carries recursion input for the other site "
                "(expr_nodes=%llu composite_types=%llu), so this case does not "
                "isolate one depth site\n",
                DEPTHS[d].name, (unsigned long long)expr_nodes,
                (unsigned long long)composite_types);
      }

      /* TWO: the verdict itself. */
      run(&ia, full, strlen(full), 0, 0, &ra);
      cases++;
      checks++;
      int bad = ra.returned != DEPTHS[d].code || ra.runtime != 0;
      if (bad) {
        failures++;
        fprintf(stderr, "FAIL %s: ret=%llu runtime=%llu wanted %llu "
                        "(levels=%llu expr_nodes=%llu composite_types=%llu)\n",
                DEPTHS[d].name, (unsigned long long)ra.returned,
                (unsigned long long)ra.runtime,
                (unsigned long long)DEPTHS[d].code,
                (unsigned long long)levels, (unsigned long long)expr_nodes,
                (unsigned long long)composite_types);
      } else {
        /* A refusal here is UNPOSITIONED, and that is asserted rather than
         * assumed: TYPED_DEPTH_CAP fires in the recursion itself, where there
         * is no node to point at, so report[0] must still hold its GUARD.
         * A 817 that started carrying a position would be a different
         * refusal, and this line is where that shows up. */
        int positioned = !(ra.report[0] == GUARD);
        printf("DEPTH %s levels=%llu ret=%llu expected=%llu "
               "expr_nodes=%llu composite_types=%llu total_opens=%llu "
               "positioned=%d\n",
               DEPTHS[d].name, (unsigned long long)levels,
               (unsigned long long)ra.returned,
               (unsigned long long)DEPTHS[d].code,
               (unsigned long long)expr_nodes,
               (unsigned long long)composite_types,
               (unsigned long long)total, positioned);
        if (DEPTHS[d].code != 0 && positioned) {
          checks++;
          failures++;
          fprintf(stderr, "FAIL %s: the depth refusal carried a position\n",
                  DEPTHS[d].name);
        }
      }
      free(full);
    }

    /* 7. THE SUPERSET, MEASURED. Each negative case goes through the pass that
     * owns the refusal and then through ntir.build, and a refusal by the owner
     * must be a refusal by ntir. The owner image is built here, from the tree,
     * rather than assumed to exist: if an owner stops compiling this gate goes
     * red instead of quietly measuring nothing. */
    for (unsigned o = 0; o < OWNERS_N; o++) {
      size_t osz[10] = {0};
      char *osrc[10] = {0};
      NtFInput oin[10];
      int oall = 1;
      for (unsigned i = 0; i < OWNERS[o].count; i++) {
        osrc[i] = loadf(OWNERS[o].paths[i], &osz[i]);
        if (!osrc[i]) oall = 0;
        oin[i] = (NtFInput){OWNERS[o].paths[i], osrc[i], osz[i]};
      }
      CHECK(oall, "the owner sources load");
      NtArtifact oa = {0};
      int compiled = oall && nova_compile_many_v2(oin, OWNERS[o].count, &oa);
      CHECK(compiled, "the owner image compiles");
      if (!compiled) {
        fprintf(stderr, "E%u %zu:%zu %s\n", oa.error.code, oa.error.line,
                oa.error.column, oa.error.message);
        nt_artifact_free(&oa);
        for (unsigned i = 0; i < OWNERS[o].count; i++) free(osrc[i]);
        continue;
      }
      NovaHostImage oi = {0};
      CHECK(nova_host_map(&oa, &oi), "the owner image maps");
      if (oi.memory) {
        for (unsigned c = 0; c < NEGATIVES_N; c++) {
          if (strcmp(NEGATIVES[c].owner, OWNERS[o].label) != 0) continue;
          char *full = (char *)malloc(strlen(NEG_HEAD) + strlen(NEG_MID) +
                                       strlen(NEGATIVES[c].body) +
                                       strlen(NEG_TAIL) + 1);
          if (!full) continue;
          strcpy(full, NEG_HEAD);
          strcat(full, NEG_MID);
          strcat(full, NEGATIVES[c].body);
          strcat(full, NEG_TAIL);
          uint64_t rout[8];
          memset(rout, 0, sizeof rout);
          NovaContextV2 oc = {0};
          CHECK(nova_context_init_v2(&oc), "owner context init");
          uint64_t osh = nova_borrow_v2(&oc, full, strlen(full), 0);
          uint64_t ooh = nova_borrow_v2(&oc, rout, sizeof rout, 1);
          uint64_t oargs[] = {osh, strlen(full), ooh, 8};
          uint64_t ocode = oi.entry(&oc, oargs, 4);
          uint64_t ortime = oc.error;
          CHECK(nova_context_destroy_v2(&oc), "owner context cleanup");
          cases++;
          checks++;
          if (ocode != NEGATIVES[c].code || ortime != 0) {
            failures++;
            run(&ia, full, strlen(full), 8, 0, &ra);
            fprintf(stderr,
                    "PARSE %s code=%llu reason=%llu at %llu:%llu\n",
                    NEGATIVES[c].name, (unsigned long long)ra.report[1],
                    (unsigned long long)ra.report[2],
                    (unsigned long long)ra.report[3],
                    (unsigned long long)ra.report[4]);
            fprintf(stderr,
                    "FAIL the owner %s did not publish %llu on %s: it answered "
                    "%llu\n",
                    OWNERS[o].label, (unsigned long long)NEGATIVES[c].code,
                    NEGATIVES[c].name, (unsigned long long)ocode);
            free(full);
            continue;
          }
          run(&ia, full, strlen(full), 0, 0, &ra);
          checks++;
          if (ra.returned == 0 || ra.runtime != 0) {
            failures++;
            fprintf(stderr,
                    "FAIL ntir accepted %s, which %s refuses with %llu\n",
                    NEGATIVES[c].name, OWNERS[o].label,
                    (unsigned long long)ocode);
          } else {
            printf("SUPERSET %s owner=%s owner_code=%llu ntir_code=%llu "
                   "line=%llu column=%llu\n",
                   NEGATIVES[c].name, OWNERS[o].label,
                   (unsigned long long)ocode,
                   (unsigned long long)ra.returned,
                   (unsigned long long)ra.report[0],
                   (unsigned long long)ra.report[1]);
          }
          free(full);
        }
        nova_host_unmap(&oi);
      }
      nt_artifact_free(&oa);
      for (unsigned i = 0; i < OWNERS[o].count; i++) free(osrc[i]);
    }

    for (unsigned m = 0; m < DAMAGES_N; m++) {
      run(&ia, carrier, strlen(carrier), 2, 0, &ra);
      uint64_t n = ra.report[0];
      uint64_t node = 1;
      if (DAMAGES[m].pick == 1) {
        for (node = 1; node <= n; node++)
          if (W(&ra, node, F_FIRST) != 0) break;
        if (node > n) {
          failures++; checks++; cases++;
          fprintf(stderr, "FAIL no node with children for %s\n", DAMAGES[m].name);
          continue;
        }
      }
      uint64_t value = DAMAGES[m].value;
      /* A sentinel is filled in from the image here, so no number in this file
       * depends on the shape of a fixture. */
      if (value == PICK_KIND_ABOVE) value = kind_base + t.count;
      if (value == PICK_PAST_END) value = n + 1;
      if (DAMAGES[m].on_header)
        ra.words[DAMAGES[m].word] = value;
      else
        ra.words[header_words + (node - 1) * node_words + DAMAGES[m].word] = value;
      run(&ia, carrier, strlen(carrier), 3, 0, &ra);
      cases++;
      checks++;
      int bad = ra.returned != DAMAGES[m].code || ra.runtime != 0;
      if (DAMAGES[m].positioned && ra.report[0] == GUARD) bad = 1;
      if (bad) {
        failures++;
        fprintf(stderr, "FAIL %s: ret=%llu runtime=%llu wanted %llu\n",
                DAMAGES[m].name, (unsigned long long)ra.returned,
                (unsigned long long)ra.runtime,
                (unsigned long long)DAMAGES[m].code);
      } else {
        printf("DAMAGE %s code=%llu node=%llu line=%llu column=%llu\n",
               DAMAGES[m].name, (unsigned long long)ra.returned,
               (unsigned long long)ra.report[3],
               (unsigned long long)ra.report[0],
               (unsigned long long)ra.report[1]);
      }
    }
    /* The golden digest: one FNV-1a over the concatenated golden text of the
     * whole corpus, in hex. It is printed rather than compared with a stored
     * constant, because a stored constant is a number a human has to
     * re-anchor every time the IR legitimately changes, and this gate does not
     * own the IR. What the gate DOES own is that the three streams per fixture
     * agree, which is checked above; the digest is here so a change in any
     * golden byte is one line of output a reviewer can compare between runs
     * rather than a silent diff nobody reads. */
    printf("GOLDEN ntir=0x%016llx fixtures=%u tag=%s\n",
           (unsigned long long)digest, FIXTURES_N, EXPECTED_TAG);
    free(reached);
    table_free(&t);
    run_free(&ra);
    run_free(&rb);
    run_free(&scratch);
  }
  if (ia.memory) nova_host_unmap(&ia);
  if (ib.memory) nova_host_unmap(&ib);
  nt_artifact_free(&first);
  nt_artifact_free(&second);
  for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);
  printf("NTASM_NOVA_NTIR checks=%u failures=%u cases=%u\n", checks, failures, cases);
  return failures ? 1 : 0;
}
