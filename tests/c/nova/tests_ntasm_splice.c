/* tests_ntasm_splice.c -- the spliced tree, measured against the IR that has
 * to lower it.
 *
 * The expansion stage replaces a macro invocation by the expansion the
 * expander produced. Two sets of node ids are left behind by that: the slot a
 * produced head was copied off, and the invocation's own children, the macro
 * name and the arguments, which the expansion replaced. For years the first
 * was retired by zeroing its twelve words, so the tree carried an id inside
 * 1..node_count that nothing could reach and whose kind was 0. No pass of the
 * pipeline could see it -- a pass that dispatches on kind never meets a kind 0
 * node, and a pass that walks from the root never arrives -- and the
 * intermediate representation refused the whole image with 813, because its
 * count is the length of the id space and such a slot is a node it cannot
 * lower. validate.prune retires both sets by reachability.
 *
 * So this gate asserts the property the fix is about, on a corpus that
 * exercises it: no id the tree publishes has kind 0, and every id it
 * publishes is a node the root reaches. Both halves are asserted, because
 * they are not the same half: counting holes by kind alone sees one per
 * expansion invocation and misses the replaced children, which keep their
 * kind and are equally unreachable.
 *
 * THE SECOND ASSERTION IS A FALSE POSITIVE PROOF, AND IT IS GREEN. For every
 * fixture the pipeline accepts, the IR must accept the same tree, because the
 * point of the IR is to be an oracle the product can be held to and a refusal
 * on a valid module is the oracle being wrong. That used to hold for every
 * fixture here but one family: a literal the expander materialises from a
 * folded comptime value carried the token of the template splice position --
 * a NAME token -- and ntir.type_literal, which classifies a literal by its
 * token, refused the whole image in 817. macro_expand.emit_constant is the
 * owner and is fixed: a materialised literal now carries an INTEGER token out
 * of the caller's own token stream, taken from the range the constant was
 * folded from.
 *
 * A ROW PINNED BY ITS VERDICT IS NOT EVIDENCE, so the third assertion is the
 * one that carries this gate. The token itself is read back, per produced
 * literal, from the expander's own region, and its KIND is compared against
 * 258 -- the lexer's integer token, and exactly the value type_literal reads.
 * Reverting emit_constant without touching a single row of the table turns
 * this red while the verdict assertion is still satisfied by nothing. The
 * cause and the consequence are checked from two directions and neither is
 * derived from the other.
 *
 * The pipeline verdict is read from validate.validate, the product entry, and
 * not from this module recomputing it, so the number compared against the IR
 * is the number the product publishes.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
/* The two budget rows' fuel comes from the shared model, not from a literal
   in this file; compose_budget_rows says why. */
#include "ntasm_fuel_model.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* The closure walk, for the control on this gate's own module list. It is a
   header and not an object precisely so that a harness can opt in without the
   driver's shared object list being edited. */
#include "ntasm_pipeline_parity.h"

static unsigned checks, failures, cases;
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; \
  fprintf(stderr, "FAIL %s\n", m); } } while (0)

static char *load(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long z = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) {
    free(b); fclose(f); return NULL;
  }
  fclose(f);
  b[z] = 0;
  *n = (size_t)z;
  return b;
}

typedef struct { uint64_t returned, runtime, out[10]; } Shape;
typedef struct { uint64_t returned, runtime, out[4]; } Pipe;
typedef struct { uint64_t returned, runtime, out[64]; } Tok;

/* Two images of the same forty two sources, so the shape and the pipeline
 * verdict are two runs of the product and not one number read twice. */
static const char *const PATHS[] = {
    "tests/nova/tests/splice-entry.nova",
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
    /* machine_ir.nova, because validate.nova IMPORTS it (toolchain/
       ntasm-nova/validate.nova:43) and calls machine_ir.lower and
       machine_ir.verify at stage 35.  A list that does not carry it compiles
       nothing: the product refuses with `E302 <line>:<col> Nova imported
       module is not among compiler inputs', and the refusal is CORRECT --
       it is a fact about this list, not about the compiler.  ng_parity_paths
       in ntasm_pipeline_parity.h carries the same row for the same reason.

       AND THE CONTROL.  ng_parity_closure_is(this entry, PATHS, PATHS_N)
       asks whether this list is still the closure of its own entry, BEFORE
       the compile, and it was added on 2026-10-02 because nothing asked.
       With this row deleted on purpose the control said, in order:
         CLOSE-NO the splice module list is the closure of .../splice-entry.nova:
                the tree reaches compiler/nova/ir/machine_ir.nova and the
                module list does not carry it
         NTASM_NOVA_SPLICE checks=9 failures=6 cases=0
       against `S302 43:8 Nova imported module is not among compiler inputs',
       which names a code and a line and NOT the module.  Restored here. */
    "compiler/nova/ir/machine_ir.nova"};
#define PATHS_N ((unsigned)(sizeof PATHS / sizeof PATHS[0]))

/* The third image, and it is a different set of sources on purpose: it needs
 * the expander and nothing else, so it is six modules rather than forty two,
 * and it exposes the one export the other two do not have. It is written here
 * rather than in tests/nova/tests/ because the property it exists to
 * measure is a property of the expander's output records, and the module that
 * owns the assertion owns the instrument that reads them. Embedding a Nova
 * module as a C string is the pattern tests_ntasm_abi.c:88-101 already uses.
 *
 * out[0] is the number of literals the expander produced, and out[1+2i] and
 * out[2+2i] are one produced literal's token index and that token's kind. A
 * token index outside the caller's token stream is answered 813 rather than
 * read, so a stamped index that does not address a real token is a refusal
 * here and not an out of bounds read under the sanitizer.
 */
static const char TOKEN_ENTRY[] =
    "module splice_token_entry;\n"
    "import ntasm_ast;\n"
    "import ntasm_parser;\n"
    "import ntasm_macro_expand;\n"
    "export fn main(source:buf<u8>,out:buf<u64>)->u64 {\n"
    "    if len(out)<1 { return 800; }\n"
    "    out[0]=0;\n"
    "    let tree:ntasm_ast.Tree=ntasm_parser.parse(source,1);\n"
    "    if tree.ok==false { ntasm_ast.release(tree);return 800; }\n"
    "    let mut region:buf<u64>=alloc(runtime(),64+tree.node_count*48);\n"
    "    let mut code:u64=ntasm_macro_expand.expand(source,tree,region);\n"
    "    if code==203 {\n"
    "        let need:u64=region[3];\n"
    "        let bigger:buf<u64>=alloc(runtime(),need);\n"
    "        code=ntasm_macro_expand.expand(source,tree,bigger);\n"
    "        rt_free(runtime(),region);region=bigger;\n"
    "    }\n"
    "    if code!=0 {\n"
    "        let bad:u64=region[0];\n"
    "        rt_free(runtime(),region);ntasm_ast.release(tree);return bad;\n"
    "    }\n"
    "    let count:u64=region[1];\n"
    "    let name_words:u64=(region[2]+7)/8;\n"
    "    let tokens:buf<u64>=tree.token_words;\n"
    "    let mut found:u64=0;\n"
    "    let mut id:u64=1;\n"
    "    while id<=count {\n"
    "        let at:u64=4+name_words+(id-1)*12;\n"
    "        if region[at]==94 {\n"
    "            if 3+found*2>=len(out) {\n"
    "                rt_free(runtime(),region);ntasm_ast.release(tree);\n"
    "                return 800;\n"
    "            }\n"
    "            let index:u64=region[at+1];\n"
    "            if index>=tree.token_count {\n"
    "                rt_free(runtime(),region);ntasm_ast.release(tree);\n"
    "                return 813;\n"
    "            }\n"
    "            out[1+found*2]=index;out[2+found*2]=tokens[index*9];\n"
    "            found=found+1;\n"
    "        }\n"
    "        id=id+1;\n"
    "    }\n"
    "    out[0]=found;\n"
    "    rt_free(runtime(),region);ntasm_ast.release(tree);return 0;\n"
    "}\n";
static const char *const TOK_PATHS[] = {
    "splice-token-entry.nova",
    "compiler/nova/macros/macro_expand.nova",
    "compiler/nova/macros/constant_eval.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/lexer.nova",
    "compiler/nova/frontend/ast.nova"};
#define TOK_N ((unsigned)(sizeof TOK_PATHS / sizeof TOK_PATHS[0]))

#define MH "module m\ntarget x86_64-nexora-none\n"
#define MT "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\nexpand "
#define MF "\n}\n}\n"
#define BUDGET_BODY "macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v+1; };\n}\n"

/* pipe is what validate.validate must answer. ir is what ntir.build and then
 * ntir.verify must answer on the tree validate hands them: 0 on both, or the
 * one structural code the residual is named by.
 *
 * lit is the token half, and it is 0 or 1 and not a count, because what it
 * says is "this fixture produces at least one literal, and every literal it
 * produces carries an INTEGER token". Without the at-least-one half the check
 * is vacuous on a fixture whose expansion happens to contain no literal, which
 * is a green that costs nothing. A fixture with lit 0 still has every literal
 * it produces checked for being a literal token at all, so the invariant is
 * universal and only its non-vacuity is per row.
 */
typedef struct { const char *name; const char *src; uint64_t pipe; uint64_t ir;
                 uint64_t lit; } Fx;

/* The two budget rows below are COMPOSED at run time rather than written, and
   the only number that changes is the fuel.  It used to be a literal 8 here
   and a literal 8 in tests_ntasm_validate.c, and when the wave-17 walk
   removal moved the real figure from 30 to 8 both files were re-pinned in the
   same run without either knowing the other existed -- the coupling U29
   names, between two copies of one integer rather than between two claims.
   Both now read ng_fuel_nova(NG_FUEL_FLAT_RET, 1) out of the shared model,
   which is affine in the item count and was fitted to a measured ladder over
   this same body.  The other five figures stay literal because the model
   says nothing about them: the walk removal left arena 480, nodes 5 and
   constant 3 exactly where they were. */
static char budget_row[2][2048];

static void compose_budget_rows(void) {
  const uint64_t flat = ng_fuel_nova(NG_FUEL_FLAT_RET, 1);
  for (unsigned k = 0; k < 2; k++) {
    snprintf(budget_row[k], sizeof budget_row[0],
             MH "comptime(fuel=%llu,call_depth=1,arena_bytes=480,ast_nodes=5,"
             "expansion_depth=1,constant_bytes=3){\nreturn 1;\n}\n"
             BUDGET_BODY MT "ret(41)\n" MF,
             (unsigned long long)(k ? flat - 1 : flat));
  }
}

static const Fx FX[] = {
  /* --- one, two and three invocations: the hole this gate is about. The
   * count of retired slots is 1, 2 and 3 and the count of unreachable ids is
   * 3, 4 and 6, so the two halves of the assertion are not the same count. */
  {"expanded once",   MH"macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\n"MT"ret(41)\n"MF, 0, 0, 0},
  {"twice locals",    MH"macro mk()->ast.stmt {\nreturn quote(stmt) { let t:u64=1; };\n}\n"MT"mk()\nexpand mk()\nreturn 0\n"MF, 0, 0, 0},
  {"twice data",      MH"macro d(v:u64)->ast.decl {\nemit quote(decl) { data c:u64=$v; }\n}\n"MT"d(1)\nexpand d(2)\nreturn 0\n"MF, 0, 0, 1},
  {"three times",     MH"macro mk()->ast.stmt {\nreturn quote(stmt) { let t:u64=1; };\n}\n"MT"mk()\nexpand mk()\nexpand mk()\nreturn 0\n"MF, 0, 0, 0},
  /* A macro nobody invokes develops nothing, so the caller's own tree stands
   * and there is no hole to find. */
  {"uninvoked macro", MH"macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", 0, 0, 0},
  /* --- what an expansion may produce, and the positions the splicer puts it
   * in. Each one replaces an invocation, so each one retires a slot. */
  {"spliced if",      MH"macro br(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { if $v==1 { return 1; } else { return 0; } };\n}\nsection .text {\nfn main(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nexpand br(x)\n}\n}\n", 358, 0, 0},
  {"comptime live",   MH"comptime(fuel=4096,call_depth=64,arena_bytes=262144,ast_nodes=256,expansion_depth=4,constant_bytes=4096){\nreturn 1;\n}\n"BUDGET_BODY MT"ret(41)\n"MF, 0, 0, 0},
  /* the fuel is the model's, composed above; see compose_budget_rows */
  {"budget exact",    budget_row[0], 0, 0, 0},
  {"budget over",     budget_row[1], 201, 0, 0},
  {"makes const",     MH"macro k()->ast.decl {\nemit quote(decl) { const c:u64=1; }\n}\n"MT"k()\nreturn 0\n"MF, 0, 0, 0},
  {"makes fn",        MH"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n}\n}\n"MT"mk()\nreturn 0\n"MF, 0, 0, 0},
  {"produced param",  MH"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(in n:u64)->u64\neffects {}\nclobbers {} {\nreturn n+1;\n}\n}\n}\n"MT"mk()\nreturn 0\n"MF, 0, 0, 0},
  {"produced let",    MH"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper()->u64\neffects {}\nclobbers {} {\nlet t:u64=1;\nreturn t;\n}\n}\n}\n"MT"mk()\nreturn 0\n"MF, 0, 0, 0},
  {"direction in",    MH"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(in n:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0;\n}\n}\n}\n"MT"mk()\nreturn 0\n"MF, 0, 0, 0},
  {"direction out",   MH"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(out n:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0;\n}\n}\n}\n"MT"mk()\nreturn 0\n"MF, 0, 0, 0},
  {"direction inout", MH"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(inout n:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0;\n}\n}\n}\n"MT"mk()\nreturn 0\n"MF, 0, 0, 0},
  {"spliced argument",MH"macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\nsection .text {\nfn main(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nexpand ret(x)\n}\n}\n", 0, 0, 0},
  {"expr to data",    MH"macro d(v:ast.expr)->ast.decl {\nemit quote(decl) { data c:u64=$v; }\n}\n"MT"d(1)\nreturn 0\n"MF, 0, 0, 0},
  {"expr to data 2x", MH"macro d(v:ast.expr)->ast.decl {\nemit quote(decl) { data c:u64=$v; }\n}\n"MT"d(1)\nexpand d(2)\nreturn 0\n"MF, 0, 0, 0},
  /* --- the residual, closed. A comptime VALUE parameter is folded, not
   * cloned: the expander materialises the constant, and it used to stamp the
   * literal with the token of the template splice position itself, which is a NAME
   * token, so ntir.type_literal -- which classifies a literal by its token --
   * refused the whole image in 817 on modules the pipeline accepts. Three of
   * these four are pipeline-accepted, so before the fix they were the three
   * the gate named as residual; the other is refused by the pipeline for a
   * reason of its own, so its 817 was masked rather than absent. */
  {"value to data",   MH"macro d(v:u64)->ast.decl {\nemit quote(decl) { data c:u64=$v; }\n}\n"MT"d(1)\nreturn 0\n"MF, 0, 0, 1},
  {"value to const",  MH"macro d(v:u64)->ast.decl {\nemit quote(decl) { const c:u64=$v; }\n}\n"MT"d(1)\nreturn 0\n"MF, 363, 0, 1},
  {"value to let",    MH"macro d(v:u64)->ast.stmt {\nreturn quote(stmt) { let t:u64=$v; }; \n}\n"MT"d(7)\nreturn 0\n"MF, 800, 0, 1},
  {"value to return", MH"macro r(v:u64)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\n"MT"r(9)\n"MF, 0, 0, 1},
  /* --- the same mechanism, further out. These were NOT named by the residual
   * and three of them are pipeline-accepted, so they are the rows that say the
   * family is closed rather than three cases closed. `value to hex` proves the
   * token is not the argument's SPELLING but its kind: 0x10 lexes to the same
   * 258 as 1, and a fix that pointed at the argument's token by index would
   * pass the decimal rows and fail here. `value to u8` and `value to i32` say
   * the token is not the comptime PARAMETER's type: a narrower u8 and a signed
   * i32 both materialise, and neither is the 258 a type name would have to be
   * rewritten into. */
  {"value to hex",    MH"macro d(v:u64)->ast.decl {\nemit quote(decl) { data c:u64=$v; }\n}\n"MT"d(0x10)\nreturn 0\n"MF, 0, 0, 1},
  {"value to u8",     MH"macro d(v:u8)->ast.decl {\nemit quote(decl) { data c:u8=$v; }\n}\n"MT"d(200)\nreturn 0\n"MF, 0, 0, 1},
  {"value to i32",    MH"macro d(v:i32)->ast.decl {\nemit quote(decl) { data c:i32=$v; }\n}\n"MT"d(-7)\nreturn 0\n"MF, 0, 0, 1},
  {"value in arith",  MH"macro d(v:u64)->ast.decl {\nemit quote(decl) { data c:u64=$v+1; }\n}\n"MT"d(4)\nreturn 0\n"MF, 0, 0, 1},
  {"value in if",     MH"macro b(v:u64)->ast.stmt {\nreturn quote(stmt) { if $v==1 { return 1; } else { return 0; } };\n}\n"MT"b(1)\n"MF, 358, 0, 1},
  /* A comptime LET inside a macro body is a SECOND route to the same literal
   * and it is the route that a fix keyed on the invocation argument cannot
   * reach: `40+2` is folded, so no single argument node is its origin, and the
   * token has to come out of the folded range itself. `let from paren` is the
   * case that says so -- the folded range opens with `(`, which is not an
   * integer token, so a producer that stamped the range's FIRST token would
   * pass every other row here and fail this one. */
  {"let from fold",   MH"macro d()->ast.decl {\nlet k = 40+2;\nemit quote(decl) { data c:u64=$k; };\n}\n"MT"d()\nreturn 0\n"MF, 0, 0, 1},
  {"let from paren",  MH"macro d()->ast.decl {\nlet k = (40+2)*3;\nemit quote(decl) { data c:u64=$k; };\n}\n"MT"d()\nreturn 0\n"MF, 0, 0, 1},
  {"let from neg",    MH"macro d()->ast.decl {\nlet k = 0-5;\nemit quote(decl) { data c:i64=$k; };\n}\n"MT"d()\nreturn 0\n"MF, 0, 0, 1},
  {"let to return",   MH"macro r()->ast.stmt {\nlet k = 40+2;\nreturn quote(stmt) { return $k; };\n}\n"MT"r()\n"MF, 0, 0, 1},
  /* A comptime value bound from a boolean word has NO integer token anywhere in
   * its folded range, so it is the one shape where the producer has nothing to
   * name -- and the measurement is that the EXPANDER refuses both of these
   * before a literal exists, so nothing is stamped at all. They are pinned
   * with lit 0 for that reason, and the reason is written down rather than
   * hidden: it means the no-token branch of macro_expand.stamp_literal_token
   * is a fallback that no shape in this corpus reaches. A guard nobody can
   * reach is named here as one. It is not claimed to be load bearing, and the
   * rows above it are the ones that carry the fix. */
  {"let from word",   MH"macro d()->ast.decl {\nlet k = true;\nemit quote(decl) { data c:u64=$k; };\n}\n"MT"d()\nreturn 0\n"MF, 374, 0, 0},
  {"value from word", MH"macro d(v:u64)->ast.decl {\nemit quote(decl) { data c:u64=$v; }\n}\n"MT"d(true)\nreturn 0\n"MF, 372, 0, 0},
  /* --- what the expander refuses, which leaves the caller's tree standing:
   * no substitution, so no hole, and the IR sees the caller's own module. */
  {"capture refused", MH"const secret:u64=7\nmacro steal(v:ast.expr)->ast.expr {\nreturn quote(expr) { $v+secret };\n}\n"MT"steal(1)\n"MF, 374, 0, 0},
  {"call target",     MH"macro go(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { call helper($v) };\n}\n"MT"go(1)\nreturn 0\n"MF, 374, 0, 0},
  {"unknown macro",   MH MT"ghost(1)\n"MF, 370, 0, 0},
  {"macro arity",     MH"macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\n"MT"ret(1,2)\n"MF, 371, 0, 0},
  {"macro param kind",MH"macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\n"MT"ret(quote(type) { u8 })\n"MF, 372, 0, 0},
  {"malformed comptime",MH"comptime(fuel=16,call_depth=4,arena_bytes=262144,ast_nodes=256,expansion_depth=4){\nreturn 1;\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", 378, 0, 0},
  /* --- a template is not the module namespace. */
  {"template callee", MH"macro mk()->ast.decl {\nemit quote(decl) {\nfn ghost()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n}\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall ghost()\nreturn 0\n}\n}\n", 310, 0, 0},
  {"comptime callee", MH"comptime(fuel=4096,call_depth=64,arena_bytes=262144,ast_nodes=256,expansion_depth=4,constant_bytes=4096){\nreturn quote(decl) {\nfn ghost()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n};\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall ghost()\nreturn 0\n}\n}\n", 310, 0, 0},
  {"template and real",MH"macro mk()->ast.decl {\nemit quote(decl) {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n}\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", 0, 0, 0},
  {"callee after tpl",MH"macro mk()->ast.decl {\nemit quote(decl) {\nfn ghost()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n}\n}\nsection .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall ghost()\nreturn 0\n}\n}\n", 310, 0, 0},
  {"template and call arity","module m\ntarget x86_64-nexora-none\nmacro id(t:$u64)->ast.expr {\nreturn quote(expr) { $t };\n}\nsection .text {\nfn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n", 311, 0, 0},
  /* --- clear modules, where the caller's own tree is the tree. */
  {"clear fn",        "module m\ntarget x86_64-nexora-none\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", 0, 0, 0},
  {"clear call",      "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1)\nreturn 0\n}\n}\n", 0, 0, 0},
  {"clear data",      "module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata answer:u64=42\n}\n", 0, 0, 0},
  {"clear const",     "module m\ntarget x86_64-nexora-none\nconst v:u64=1+2\n", 0, 0, 0},
  {"clear arity",     "module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n", 311, 0, 0},
};
#define FX_N ((unsigned)(sizeof FX / sizeof FX[0]))

/* The lexer's integer and string token kinds, lexer.nova:117 and :159. These
 * are the two values ntir.nova:562-563 accepts, so they are the whole of what
 * a literal has to carry; a produced literal bearing anything else is the
 * defect this gate exists to hold shut. */
#define TOK_INT 258
#define TOK_STRING 259

static Shape shape_run(const NovaHostImage *i, const char *s) {
  Shape r = {0};
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "shape context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, sizeof r.out, 1);
  uint64_t a[] = {sh, strlen(s), oh, sizeof r.out / 8};
  r.returned = i->entry(&c, a, 4);
  r.runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "shape context cleanup");
  return r;
}

static Pipe pipe_run(const NovaHostImage *i, const char *s) {
  Pipe r = {0};
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "pipeline context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, sizeof r.out, 1);
  uint64_t a[] = {sh, strlen(s), oh, sizeof r.out / 8};
  r.returned = i->entry(&c, a, 4);
  r.runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "pipeline context cleanup");
  return r;
}

static Tok tok_run(const NovaHostImage *i, const char *s) {
  Tok r = {0};
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "token context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, sizeof r.out, 1);
  uint64_t a[] = {sh, strlen(s), oh, sizeof r.out / 8};
  r.returned = i->entry(&c, a, 4);
  r.runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "token context cleanup");
  return r;
}

int main(void) {
  size_t sizes[PATHS_N] = {0};
  char *sources[PATHS_N] = {0};
  NtFInput shape_in[PATHS_N], pipe_in[PATHS_N];
  char *pipe_source = NULL;
  int all = 1;
  for (unsigned i = 0; i < PATHS_N; i++) {
    sources[i] = load(PATHS[i], &sizes[i]);
    if (!sources[i]) all = 0;
    shape_in[i] = (NtFInput){PATHS[i], sources[i], sizes[i]};
    pipe_in[i] = shape_in[i];
  }
  /* The product entry replaces this one in the second image, so both images
   * are the same forty two sources and differ only in what they expose. */
  {
    const char *name = "tests/nova/tests/validate-entry.nova";
    size_t n = 0;
    pipe_source = load(name, &n);
    if (!pipe_source) all = 0;
    pipe_in[0] = (NtFInput){name, pipe_source, n};

  /* THE CONTROL THIS LIST NEVER HAD, and there are two claims to ask about.
     PATHS is this gate's own compiler input list -- a hand-maintained copy of
     an image the tree derives -- and pipe_in is that list with the entry row
     swapped for validate-entry, which is therefore a second hand-maintained
     claim about ng_parity_paths.  Nothing asked either of them.  On
     2026-10-02 machine_ir.nova became stage 35 of validate.nova, neither list
     carried it, both compiles were refused with E302, and the gate reported
     `checks=7 failures=4` -- four assertions out of the 607 it has.  Asking
     BEFORE the compile names the list, instead of letting the refusal
     downstream of it stand for something it is not. */
  {
    const char *why;
    char msg[160];
    const char *pipe_names[PATHS_N];
    int closed = ng_parity_closure_is(PATHS[0], PATHS, PATHS_N, msg, sizeof msg);
    CHECK(closed, closed ? "the splice module list is the closure of its entry" : msg);
    fprintf(stderr, "%s the splice module list is the closure of %s: %s\n",
            closed ? "CLOSE-OK" : "CLOSE-NO", PATHS[0], closed ? "yes" : msg);
    for (unsigned i = 0; i < PATHS_N; i++) pipe_names[i] = pipe_in[i].name;
    why = ng_parity_sets_are_the_same(pipe_names, PATHS_N, ng_parity_paths,
                                      (size_t)NG_PARITY_MODULES, msg, sizeof msg)
              ? "" : msg;
    CHECK(*why == '\0',
          *why ? why : "the pipeline image is the validate image ng_parity_paths names");
    fprintf(stderr, "%s the pipeline image is the validate image: %s\n",
            *why ? "PIPE-NO" : "PIPE-OK", *why ? why : "yes");
  }
  }
  /* The third image is six modules: the entry above, the four it imports, and
   * nothing else. Every one of the five paths is read from disk except the
   * entry, which is the string above, so the list has exactly one source that
   * is not a file and the loader is never asked for a path that does not
   * exist. */
  NtFInput tok_in[TOK_N];
  char *tok_files[TOK_N];
  size_t tok_sizes[TOK_N];
  for (unsigned i = 0; i < TOK_N; i++) {
    tok_sizes[i] = 0; tok_files[i] = NULL;
    if (i == 0) {
      tok_files[0] = NULL; /* the entry is the string, never a file */
    } else {
      tok_files[i] = load(TOK_PATHS[i], &tok_sizes[i]);
      if (!tok_files[i]) all = 0;
    }
    tok_in[i] = (NtFInput){TOK_PATHS[i], tok_files[i], tok_sizes[i]};
  }
  tok_in[0] = (NtFInput){TOK_PATHS[0], (char *)TOKEN_ENTRY, sizeof TOKEN_ENTRY - 1};
  CHECK(all, "the forty two Nova sources and the token image load");

  NtArtifact sa = {0}, pa = {0}, ta = {0};
  int sc = all && nova_compile_many_v2(shape_in, PATHS_N, &sa);
  int pc = all && nova_compile_many_v2(pipe_in, PATHS_N, &pa);
  int tc = all && nova_compile_many_v2(tok_in, TOK_N, &ta);
  CHECK(sc, "the shape image compiles");
  if (!sc)
    fprintf(stderr, "S%u %zu:%zu %s\n", sa.error.code, sa.error.line,
            sa.error.column, sa.error.message);
  CHECK(pc, "the pipeline image compiles");
  if (!pc)
    fprintf(stderr, "P%u %zu:%zu %s\n", pa.error.code, pa.error.line,
            pa.error.column, pa.error.message);
  CHECK(tc, "the token image compiles");
  if (!tc)
    fprintf(stderr, "T%u %zu:%zu %s\n", ta.error.code, ta.error.line,
            ta.error.column, ta.error.message);
  NovaHostImage shape = {0}, pipe = {0}, tok = {0};
  CHECK(sc && nova_host_map(&sa, &shape), "the shape image maps");
  CHECK(pc && nova_host_map(&pa, &pipe), "the pipeline image maps");
  CHECK(tc && nova_host_map(&ta, &tok), "the token image maps");

  if (shape.memory && pipe.memory && tok.memory) {
    compose_budget_rows();
    for (unsigned k = 0; k < FX_N; k++) {
      const Fx *f = &FX[k];
      Shape h = shape_run(&shape, f->src);
      Pipe p = pipe_run(&pipe, f->src);
      Tok t = tok_run(&tok, f->src);
      cases++;
      /* 1. the export answered, and did not leak a runtime error. */
      checks++;
      if (h.returned != 0 || h.runtime) {
        failures++;
        fprintf(stderr, "FAIL shape %s ret=%llu runtime=%llu\n", f->name,
                (unsigned long long)h.returned, (unsigned long long)h.runtime);
      }
      /* 2. no id the tree publishes has kind 0. */
      checks++;
      if (h.out[3] != 0) {
        failures++;
        fprintf(stderr, "FAIL kind zero %s nodes=%llu kind0=%llu unreachable=%llu\n",
                f->name, (unsigned long long)h.out[1], (unsigned long long)h.out[3],
                (unsigned long long)h.out[4]);
      }
      /* 3. every id the tree publishes is a node the root reaches, and the
       *    two words agree with each other. This is the half a reader that
       *    counts holes by kind cannot see. */
      checks++;
      if (h.out[4] != 0 || h.out[9] + h.out[4] != h.out[1] || h.out[9] == 0) {
        failures++;
        fprintf(stderr, "FAIL unreachable %s nodes=%llu reached=%llu unreachable=%llu\n",
                f->name, (unsigned long long)h.out[1], (unsigned long long)h.out[9],
                (unsigned long long)h.out[4]);
      }
      /* 4. the pipeline answers what the table says. */
      checks++;
      if (p.returned != f->pipe || p.runtime) {
        failures++;
        fprintf(stderr, "FAIL pipeline %s ret=%llu want=%llu runtime=%llu\n",
                f->name, (unsigned long long)p.returned,
                (unsigned long long)f->pipe, (unsigned long long)p.runtime);
      }
      /* 5. the IR answers what the table says, and a build refusal means
       *    verify never ran, so the two words are read as one verdict. */
      checks++;
      if (h.out[5] != f->ir || (f->ir == 0 ? h.out[6] : 0) != 0) {
        failures++;
        fprintf(stderr, "FAIL ir %s build=%llu verify=%llu want build=%llu verify=0 node=%llu code=%llu\n",
                f->name, (unsigned long long)h.out[5], (unsigned long long)h.out[6],
                (unsigned long long)f->ir, (unsigned long long)h.out[7],
                (unsigned long long)h.out[8]);
      }
      /* 6. THE TOKEN, read out of the expander's own region rather than
       *    inferred from the verdict above. Every literal the expander
       *    produced must carry a token ntir.type_literal can classify, and a
       *    row that asks for a literal must actually have produced one, or the
       *    check is vacuous and the green is worth nothing. The verdict in
       *    assertion 5 is a CONSEQUENCE of this one and is not derived from
       *    it: a producer that stamped the right kind on the wrong node would
       *    pass this and fail that, and a producer that stamped nothing at
       *    all would fail this even if every verdict in the table were
       *    satisfied. */
      checks++;
      {
        /* Three separate failures, each with its own line, because a count
         * that rises without a line a reader can act on is a worse defect
         * than no check at all: the run reports twelve failures and prints
         * nothing, and the only way to find them is to rebuild by hand. */
        uint64_t lits = t.returned == 0 ? t.out[0] : 0;
        if (t.runtime != 0) {
          failures++;
          fprintf(stderr, "FAIL token %s the token export leaked runtime=%llu\n",
                  f->name, (unsigned long long)t.runtime);
        }
        if (f->lit && t.returned != 0) {
          failures++;
          fprintf(stderr, "FAIL token %s the expander refused %llu, so the row pins nothing\n",
                  f->name, (unsigned long long)t.returned);
        }
        if (f->lit && lits == 0) {
          failures++;
          fprintf(stderr, "FAIL token %s produced no literal, so the token check is vacuous\n",
                  f->name);
        }
        for (uint64_t i = 0; i < lits && i < 32; i++) {
          uint64_t kind = t.out[2 + i * 2];
          int want = f->lit ? kind == TOK_INT
                            : (kind == TOK_INT || kind == TOK_STRING);
          if (!want) {
            failures++;
            fprintf(stderr, "FAIL token %s literal %llu carries token %llu of kind %llu, want %s\n",
                    f->name, (unsigned long long)i,
                    (unsigned long long)t.out[1 + i * 2], (unsigned long long)kind,
                    f->lit ? "an integer token (258)" : "a literal token (258 or 259)");
          }
        }
      }
      /* 7. a disagreement is named on the log, so a run states the residual
       *    rather than only the failures. It prints only when there is one:
       *    a line reading "the IR refuses 0" is noise on a green run. */
      if (f->pipe == 0 && f->ir != 0) {
        uint64_t code = h.out[5] != 0 ? h.out[5] : h.out[6];
        fprintf(stderr, "RESIDUAL %-16s : the pipeline accepts and the IR refuses %llu, build=%llu verify=%llu, at node %llu\n",
                f->name, (unsigned long long)code, (unsigned long long)h.out[5],
                (unsigned long long)h.out[6], (unsigned long long)h.out[7]);
      }
      if (f->pipe == 0)
        printf("FIXTURE %-22s nodes=%llu reached=%llu pipeline=0 ir=%llu literals=%llu\n",
               f->name, (unsigned long long)h.out[1], (unsigned long long)h.out[9],
               (unsigned long long)(h.out[5] == 0 ? h.out[6] : h.out[5]),
               (unsigned long long)(t.returned == 0 ? t.out[0] : 0));
    }
  }

  if (shape.memory) nova_host_unmap(&shape);
  if (pipe.memory) nova_host_unmap(&pipe);
  if (tok.memory) nova_host_unmap(&tok);
  if (sc) nt_artifact_free(&sa);
  if (pc) nt_artifact_free(&pa);
  if (tc) nt_artifact_free(&ta);
  for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);
  for (unsigned i = 1; i < TOK_N; i++) free(tok_files[i]);
  free(pipe_source);
  printf("NTASM_NOVA_SPLICE checks=%u failures=%u cases=%u\n", checks, failures, cases);
  return failures ? 1 : 0;
}
