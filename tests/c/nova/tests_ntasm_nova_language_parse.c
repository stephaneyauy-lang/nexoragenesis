/* tests_ntasm_nova_language_parse.c -- LOT 151, the gate for the NOVA
 * LANGUAGE PARSER: a node tree with nesting, a scope chain, shadowing, typed
 * arguments and returns, the eight keywords distinguished from identifiers,
 * and a type lattice whose widths and register classes ride on the node.
 *
 * WHAT THIS GATE IS FOR, and it is not a count. Three things:
 *
 *   1. ONE REAL PROGRAM TRACED. A Nova source is parsed and the resulting tree
 *      is walked: node kinds, nesting depth, the scope each name resolved in,
 *      and the width each typed node carries are all read back out of the
 *      EXECUTED module and compared against what the source text says. The
 *      expectations are literals HERE, written by reading the source, and the
 *      strides and the kind numbers come from the module through mode 3, so a
 *      renumbering in the module moves this gate instead of silently passing.
 *
 *   2. THREE PERTURBATIONS, THREE DISTINCT DIAGNOSTICS. The same program,
 *      broken three ways -- an unclosed brace, a name used before its
 *      declaration in the same block, a type applied where it cannot be
 *      carried. Each must be REFUSED, each must publish a distinct
 *      (code, reason, line, column) quadruple, and each must publish
 *      node_count == 0 so a partial tree cannot be read. A parser that
 *      accepted everything would pass every positive case in section 1, which
 *      is exactly why these exist.
 *
 *   3. THE PERTURBATIONS MUST DESTROY WHAT THEY NAME. Each negative control
 *      is paired with the assertion that its needle is GONE from the relaxed
 *      text it was derived from, and with the positive control that the
 *      unperturbed program parses. A perturbation that failed to remove the
 *      thing it names would leave the control green for the wrong reason.
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

/* THE FIVE REGIONS OF ONE SCRATCH. NODES holds the node array, SIDES the scope
 * chain, BINDS the live bindings, FIELDS the struct-field table and OUTW the
 * nine-word result block. They are REGIONS OF ONE ALLOCATION rather than five
 * mallocs so a case cannot run out of one and not another, and every region is
 * guard-filled before each call so a refusal reads as "the guard is still
 * there" and not as "some number happened to be zero". */
#define NODES 24576
#define SIDES 2048
#define BINDS 4096
#define FIELDS 1024
/* OUTW IS SIZED FOR THE READ-BACKS, NOT FOR THE RESULT BLOCK. The result block
 * is nine words; modes 1, 2 and 3 write their tables into the same buffer, and
 * the largest of them is the lattice: twelve entries of four header words plus
 * the name bytes, which is 108 words for the twelve spellings this lattice
 * carries. An earlier version left OUTW at 16 and mode 2 wrote 108 words into a
 * 16-word region -- an overflow of the caller's own scratch that ASan reports
 * as a heap-buffer-overflow inside the module, which reads as a bounds bug in
 * the producer rather than as a size the harness chose. */
#define OUTW 256
#define WORDS (NODES + SIDES + BINDS + FIELDS + OUTW)
#define GUARD UINT64_C(0xcccccccccccccccc)

static const char *const PATHS[] = {
    "tests/nova/tests/nova-language-parse-entry.nova",
    "compiler/nova/frontend/nova_language_parse.nova"};
#define PATHS_N ((unsigned)(sizeof PATHS / sizeof PATHS[0]))

/* ---- THE ORDER OF THE EIGHT. LITERALS IN C, ON PURPOSE. ------------------
 * These eight spellings, in this order, are the whole contract, and they are
 * typed HERE rather than read back from nova_language_parse.nova. The same
 * reasoning is written out at EXPECTED_NTIR_TAG in tests_ntasm_ir_image.c:
 * an expectation read from the module that produces the quantity confirms
 * only that the module agrees with itself, and a reordering THERE would move
 * the expectation with it and leave this gate green. That is the shape of a
 * check that cannot fail. */
static const char *const EXPECTED_KEYWORD[8] = {
    "export", "fn", "let", "module", "mut", "return", "struct", "while"};

static char *loadf(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long z = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) {
    free(b); fclose(f); return NULL;
  }
  fclose(f); b[z] = 0; *length = (size_t)z; return b;
}


typedef struct { uint64_t returned, runtime; } Result;

/* ---- the module's own numbers, read back through mode 3 -------------------
 * The stride, the nine result words, and the sixteen refusal codes are read
 * out of the EXECUTED module. A harness holding its own copy of "16" goes stale
 * the moment the module changed the stride, and then every node would be read
 * at the wrong offset -- a green gate over a wrong tree. */
/* The image, set by main() once it maps. Declared HERE, above run(), so no
 * function below needs a forward declaration for it. */
static const NovaHostImage *g_image;

static uint64_t g_node_words, g_result_words, g_scope_words;
static uint64_t E_UNCLOSED, E_USE_BEFORE, E_NOT_CARRYABLE, E_UNDECLARED;
/* Only the kinds and classes this gate ACTUALLY asserts on are listed. An
 * earlier version declared all twenty kinds and four classes and read all of
 * them back, then used eleven: -Werror=unused-variable refused the build, and
 * the refusal was correct -- a gate that reads a number it never checks is
 * printing a shape it has not measured. The unused ones are gone rather than
 * silenced. */
static uint64_t K_MODULE, K_STRUCT, K_FIELD, K_FN, K_PARAM, K_RETURN_NODE,
    K_BLOCK, K_LET, K_ASSIGN, K_RETURN_STMT, K_WHILE, K_NAME, K_BINARY,
    K_LITERAL, K_FIELD_ACCESS, K_TYPE;
static uint64_t REG_NONE, REG_VALUE, REG_ADDRESS, REG_PREDICATE;

/* run() packs THIRTEEN flat slots. buf<u8> crosses as two, each buf<u64> as
 * two, and the mode as one: source(2) + nodes(2) + scopes(2) + binds(2) +
 * fields(2) + out(2) + mode(1) = 13. THE COUNT IS MEASURED, not assumed: a
 * sweep of 1..16 against this exact entry found 13 to be the only count that
 * runs, and 1..12 and 14..16 are all refused with NV2_ARGUMENT (10) before the
 * body executes. The sweep is IN this gate, below, and it is what establishes
 * the number rather than the arithmetic above. */
#define SLOTS 13
static Result run(const NovaHostImage *image, uint64_t *scratch, uint64_t mode,
                  const char *source) {
  Result r = {0, 0};
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "context init");
  uint64_t sh = nova_borrow_v2(&c, (void *)source, strlen(source), 0);
  /* FIVE DISTINCT BORROWS. The first version passed ONE handle as all four
   * output buffers, which reads as an economy and is a destruction: the four
   * views alias one allocation, so the node array, the scope chain, the
   * binding table and the field table overwrite each other, and the symptom is
   * a name that resolves for a moment and then does not. It surfaced as 803
   * on a source the reference accepts. Each buffer is its own region of the
   * scratch, laid out contiguously so one malloc covers the lot. */
  uint64_t n1 = nova_borrow_v2(&c, scratch, NODES * 8, 1);
  uint64_t n2 = nova_borrow_v2(&c, scratch + NODES, SIDES * 8, 1);
  uint64_t n3 = nova_borrow_v2(&c, scratch + NODES + SIDES, BINDS * 8, 1);
  uint64_t n4 = nova_borrow_v2(&c, scratch + NODES + SIDES + BINDS, FIELDS * 8, 1);
  uint64_t oh = nova_borrow_v2(&c, scratch + NODES + SIDES + BINDS + FIELDS,
                               OUTW * 8, 1);
  uint64_t args[SLOTS] = {sh, strlen(source), n1, NODES, n2, SIDES, n3, BINDS,
                          n4, FIELDS, oh, OUTW, mode};
  r.returned = image->entry(&c, args, SLOTS);
  r.runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
  return r;
}

/* `words` is the scratch base; `nodes` is the node array at its head and `out`
 * is the result block at its tail. Both are VIEWS of one allocation, which is
 * why node_word() indexes `words` and not a second pointer. */
typedef struct {
  uint64_t *words;
  uint64_t *out;
  uint64_t *scopes;
  uint64_t node_count, root, scope_count, bind_count;
  uint64_t code, reason, line, column, start;
  Result r;
} Tree;

/* scope_parent reads the PARENT LINK out of the scope record the module wrote,
 * at the scope stride the module published (shape word 34). This is the second
 * reading of the same fact, and it is deliberately not derived from word 7 of
 * any node: word 7 is the scope a node was PARSED IN, and a BLOCK node is
 * allocated BEFORE its own scope opens, so it carries its ENCLOSING scope. An
 * earlier version of this gate read word 7 of the body block and called it
 * "the body's scope"; it is the function's scope, which is why the check for a
 * name resolved three scopes out compared 3 against 2. The parent link is the
 * fact the chain actually publishes. */
static uint64_t scope_parent(const Tree *t, uint64_t scope) {
  if (scope == 0 || scope > t->scope_count) return 0;
  return t->scopes[(scope - 1) * g_scope_words];
}

/* scope_is_ancestor: is `anc` a STRICT ancestor of `scope` -- somewhere on the
 * chain of PARENTS above it, and not `scope` itself? This is the check a table
 * of ids cannot make. It walks the links, so it fails if the chain is broken,
 * if a parent points forward, and if two ids merely happen to differ. Bounded
 * by scope_count so a cycle cannot hang the gate.
 *
 * STRICT, and the earlier version was not: it tested `s == anc` BEFORE taking
 * the first parent step, so every scope was its own ancestor and the one check
 * that was supposed to say "this is a real walk" could never fail. That is the
 * self-inclusive kind of control -- it is satisfied by construction and so
 * measures nothing. It starts at the parent. */
static int scope_is_ancestor(const Tree *t, uint64_t anc, uint64_t scope) {
  uint64_t s, steps = 0;
  if (anc == 0 || anc == scope) return 0;
  s = scope_parent(t, scope);
  while (s != 0 && steps <= t->scope_count) {
    if (s == anc) return 1;
    s = scope_parent(t, s);
    steps++;
  }
  return 0;
}

static uint64_t node_word(Tree *t, uint64_t id, uint64_t field) {
  if (id == 0 || id > t->node_count) return UINT64_MAX; /* out of tree */
  return t->words[(id - 1) * g_node_words + field];
}

/* block_own_scope: the scope a BLOCK OPENS, which is NOT word 7 of the block
 * node. The module allocates the block node and then calls open_scope, so the
 * block's word 7 is the scope it was PARSED IN -- its parent's. Its OWN scope is
 * the one its contents live in, and the first statement inside it carries it.
 *
 * So this reads the scope of the block's first child, which is a scope id the
 * module published for a node that really is inside the block. That is the
 * second reading of "the body's scope": the first was word 7 of the body node,
 * which is the function's scope, and comparing a name that resolved in scope 3
 * against it failed for exactly that reason. An EMPTY block has no child and no
 * way to publish its own scope this way, which is stated rather than papered
 * over -- this gate's program has no empty block, and a helper that guessed
 * would be the defect it is here to catch. */
static uint64_t block_own_scope(Tree *t, uint64_t block) {
  uint64_t first = node_word(t, block, 2);
  if (first == UINT64_MAX) return 0;
  return node_word(t, first, 7);
}

/* parse() runs one source and fills `t`. The scratch is guard-filled BEFORE the
 * call, so "the module wrote nothing" and "the module wrote a zero" stay
 * distinguishable -- which is the whole reason the guard exists here rather
 * than at the assertion that would have read the value. */
static int parse(Tree *t, const char *source, uint64_t mode) {
  memset(t, 0, sizeof *t);
  t->words = malloc((size_t)WORDS * 8);
  if (!t->words) { CHECK(0, "scratch malloc"); return 0; }
  for (unsigned i = 0; i < WORDS; i++) t->words[i] = GUARD;
  t->out = t->words + NODES + SIDES + BINDS + FIELDS;
  /* The scope table is its own region of the scratch, laid out right after
   * the node array, which is the layout run() hands the module. */
  t->scopes = t->words + NODES;
  t->r = run(g_image, t->words, mode, source);
  t->code = t->out[0];
  t->reason = t->out[1];
  t->line = t->out[2];
  t->column = t->out[3];
  t->start = t->out[4];
  t->node_count = t->out[5];
  t->root = t->out[6];
  t->scope_count = t->out[7];
  t->bind_count = t->out[8];
  return 1;
}
static void free_tree(Tree *t) { free(t->words); t->words = NULL; }


/* ---- THE PROGRAM. One real Nova source, read by hand below. --------------
 * It is deliberately built to exercise every property this lot claims:
 * a struct with two typed fields, a function with a typed parameter and a
 * typed return, a `let mut`, a `while` whose condition is a COMPARISON and so
 * a predicate, an assignment through a shadowing name, a nested block that
 * shadows the outer local, and a `return` of the enclosing function's type.
 *
 *   1  module shadow_probe;
 *   2  struct Counter { count:u64, limit:u64 }
 *   3  export fn walk(bound:u64) -> u64 {
 *   4      let mut total:u64 = 0;
 *   5      let outer:u64 = bound;
 *   6      while total < outer {
 *   7          {
 *   8              let outer:u64 = 3;
 *   9              total = total + outer;
 *  10          }
 *  11      }
 *  12      return total;
 *  13  }
 */
static const char *const PROGRAM =
    "module shadow_probe;\n"
    "struct Counter {\n"
    "    count:u64,\n"
    "    limit:u64\n"
    "}\n"
    "export fn walk(bound:u64) -> u64 {\n"
    "    let mut total:u64 = 0;\n"
    "    let outer:u64 = bound;\n"
    "    while total < outer {\n"
    "        {\n"
    "            let outer:u64 = 3;\n"
    "            total = total + outer;\n"
    "        }\n"
    "    }\n"
    "    return total;\n"
    "}\n";

/* The three perturbations, each derived from PROGRAM by ONE edit, and each
 * naming a different rule. The needle that each removes is asserted absent
 * below, because a perturbation that did not remove its needle would leave the
 * negative control green for the wrong reason. */
static const char *const PERTURB_UNCLOSED =
    "module shadow_probe;\n"
    "struct Counter {\n"
    "    count:u64,\n"
    "    limit:u64\n"
    "}\n"
    "export fn walk(bound:u64) -> u64 {\n"
    "    let mut total:u64 = 0;\n"
    "    while total < bound {\n"
    "        total = total + 1;\n";               /* the closing braces are gone */
static const char *const PERTURB_USE_BEFORE =
    "module shadow_probe;\n"
    "export fn walk(bound:u64) -> u64 {\n"
    "    let mut total:u64 = early;\n"           /* `early` is declared below */
    "    let early:u64 = 1;\n"
    "    return total;\n"
    "}\n";
static const char *const PERTURB_TYPE =
    "module shadow_probe;\n"
    "export fn walk(bound:u64) -> u64 {\n"
    "    let mut total:u64 = 0;\n"
    "    while total {\n"                        /* a u64 where bool is required */
    "        total = total + 1;\n"
    "    }\n"
    "    return total;\n"
    "}\n";

/* One refusal, with all four published numbers compared. */
static void expect_refusal(const char *label, const char *source,
                           uint64_t code, uint64_t reason) {
  Tree t;
  cases++;
  if (!parse(&t, source, 0)) return;
  CHECK(t.r.runtime == 0, label);
  CHECK(t.code == code, label);
  CHECK(t.reason == reason, label);
  /* A refusal publishes node_count 0: no partial tree is ever readable. */
  CHECK(t.node_count == 0, label);
  CHECK(t.line >= 1, label);
  CHECK(t.column >= 1, label);
  if (t.code != code)
    fprintf(stderr, "FAIL %s: code %llu reason %llu at %llu:%llu\n", label,
            (unsigned long long)t.code, (unsigned long long)t.reason,
            (unsigned long long)t.line, (unsigned long long)t.column);
  free_tree(&t);
}

#define T_U8 1
#define T_U64 4
#define T_BOOL 9
#define T_BUF_U8 10
#define T_BUF_U64 11
#define E_BAD_SYNTAX 804
#define R_BAD_SYNTAX 5

static const char *const SRC_U64 =
    "module bin_u64;\n"
    "export fn test_u64(a:u64, b:u64) -> u64 {\n"
    "    let mut r:u64 = 0;\n"
    "    r = a + b;\n"
    "    r = a - b;\n"
    "    r = a * b;\n"
    "    r = a / b;\n"
    "    r = a % b;\n"
    "    r = a & b;\n"
    "    r = a | b;\n"
    "    r = a ^ b;\n"
    "    r = a << b;\n"
    "    r = a >> b;\n"
    "    return r;\n"
    "}\n";

static const char *const SRC_BOOL =
    "module bin_bool;\n"
    "export fn test_bool(a:u64, b:u64, x:bool, y:bool) -> bool {\n"
    "    let mut c:bool = a < b;\n"
    "    c = a < b;\n"
    "    c = a <= b;\n"
    "    c = a > b;\n"
    "    c = a >= b;\n"
    "    c = a == b;\n"
    "    c = a != b;\n"
    "    c = x && y;\n"
    "    c = x || y;\n"
    "    return c;\n"
    "}\n";

static const char *const SRC_TRUE =
    "module lit_true;\n"
    "export fn give_true() -> bool {\n"
    "    return true;\n"
    "}\n";

static const char *const SRC_FALSE =
    "module lit_false;\n"
    "export fn give_false() -> bool {\n"
    "    return false;\n"
    "}\n";

static const char *const SRC_TRUEISH =
    "module bad_trueish;\n"
    "export fn give_bad() -> bool {\n"
    "    return trueish;\n"
    "}\n";

static const char *const SRC_FALSEHOOD =
    "module bad_falsehood;\n"
    "export fn give_bad() -> bool {\n"
    "    return falsehood;\n"
    "}\n";

static const char *const SRC_INTS =
    "module lit_ints;\n"
    "export fn give_ints() -> u64 {\n"
    "    let a:u64 = 0;\n"
    "    let b:u64 = 42;\n"
    "    let c:u64 = 0xffffffffffffffff;\n"
    "    return a;\n"
    "}\n";

static void test_a8_expressions(void) {
  /* ---- 1. Binary operators u64 & bool ---- */
  {
    NtFInput in_u64 = {"<u64_ops>", SRC_U64, strlen(SRC_U64)};
    CHECK(nova_check_many_v2(&in_u64, 1, NULL), "A8_EXPR: SRC_U64 passes nova_check_many_v2");
    Tree t_u64;
    cases++;
    CHECK(parse(&t_u64, SRC_U64, 0), "A8_EXPR: SRC_U64 parse tree malloc");
    CHECK(t_u64.r.runtime == 0, "A8_EXPR: SRC_U64 runtime 0");
    CHECK(t_u64.code == 0, "A8_EXPR: SRC_U64 parse code 0");

    static const uint64_t EXPECTED_U64_OPS[10] = {
        43,     /* + */
        45,     /* - */
        42,     /* * */
        47,     /* / */
        37,     /* % */
        38,     /* & */
        124,    /* | */
        94,     /* ^ */
        15420,  /* << (60*256+60) */
        15934   /* >> (62*256+62) */
    };
    uint64_t b_ids[16];
    unsigned b_count = 0;
    for (uint64_t i = 1; i <= t_u64.node_count; i++) {
      if (node_word(&t_u64, i, 0) == K_BINARY && b_count < 16) {
        b_ids[b_count++] = i;
      }
    }
    CHECK(b_count == 10, "A8_EXPR: found 10 u64 binary operator nodes");
    for (unsigned i = 0; i < b_count && i < 10; i++) {
      uint64_t id = b_ids[i];
      uint64_t aux = node_word(&t_u64, id, 13);
      uint64_t width = node_word(&t_u64, id, 9);
      uint64_t reg = node_word(&t_u64, id, 10);
      CHECK(aux == EXPECTED_U64_OPS[i], "A8_EXPR: u64 operator aux preserves full token identity");
      CHECK(width == 64, "A8_EXPR: u64 arithmetic/bitwise/shift width is 64");
      CHECK(reg == REG_VALUE, "A8_EXPR: u64 binary node class is REG_VALUE");
    }
    free_tree(&t_u64);

    NtFInput in_bool = {"<bool_ops>", SRC_BOOL, strlen(SRC_BOOL)};
    CHECK(nova_check_many_v2(&in_bool, 1, NULL), "A8_EXPR: SRC_BOOL passes nova_check_many_v2");
    Tree t_bool;
    cases++;
    CHECK(parse(&t_bool, SRC_BOOL, 0), "A8_EXPR: SRC_BOOL parse tree malloc");
    CHECK(t_bool.r.runtime == 0, "A8_EXPR: SRC_BOOL runtime 0");
    CHECK(t_bool.code == 0, "A8_EXPR: SRC_BOOL parse code 0");

    static const uint64_t EXPECTED_BOOL_OPS[9] = {
        60,     /* < (init) */
        60,     /* < */
        15421,  /* <= (60*256+61) */
        62,     /* > */
        15933,  /* >= (62*256+61) */
        15677,  /* == (61*256+61) */
        8509,   /* != (33*256+61) */
        9766,   /* && (38*256+38) */
        31868   /* || (124*256+124) */
    };
    b_count = 0;
    for (uint64_t i = 1; i <= t_bool.node_count; i++) {
      if (node_word(&t_bool, i, 0) == K_BINARY && b_count < 16) {
        b_ids[b_count++] = i;
      }
    }
    CHECK(b_count == 9, "A8_EXPR: found 9 comparison/bool binary operator nodes");
    for (unsigned i = 0; i < b_count && i < 9; i++) {
      uint64_t id = b_ids[i];
      uint64_t aux = node_word(&t_bool, id, 13);
      uint64_t width = node_word(&t_bool, id, 9);
      uint64_t reg = node_word(&t_bool, id, 10);
      CHECK(aux == EXPECTED_BOOL_OPS[i], "A8_EXPR: comparison/bool operator aux preserves full token identity");
      CHECK(width == 8, "A8_EXPR: comparison/bool width is 8");
      CHECK(reg == REG_PREDICATE, "A8_EXPR: comparison/bool class is REG_PREDICATE");
    }
    free_tree(&t_bool);
  }

  /* ---- 2. true and false literals & non-declared neighbours ---- */
  {
    NtFInput in_true = {"<true>", SRC_TRUE, strlen(SRC_TRUE)};
    CHECK(nova_check_many_v2(&in_true, 1, NULL), "A8_EXPR: SRC_TRUE passes nova_check_many_v2");
    Tree t_true;
    cases++;
    CHECK(parse(&t_true, SRC_TRUE, 0), "A8_EXPR: SRC_TRUE parse tree malloc");
    CHECK(t_true.r.runtime == 0, "A8_EXPR: SRC_TRUE runtime 0");
    CHECK(t_true.code == 0, "A8_EXPR: SRC_TRUE parse code 0");

    uint64_t lit_true = 0;
    for (uint64_t i = 1; i <= t_true.node_count; i++) {
      if (node_word(&t_true, i, 0) == K_LITERAL) { lit_true = i; break; }
    }
    CHECK(lit_true != 0, "A8_EXPR: SRC_TRUE contains a K_LITERAL node");
    if (lit_true != 0) {
      uint64_t st = node_word(&t_true, lit_true, 5);
      uint64_t et = node_word(&t_true, lit_true, 6);
      CHECK(et > st && et - st == 4, "A8_EXPR: true span length is 4");
      CHECK(st + 4 <= strlen(SRC_TRUE) && strncmp(SRC_TRUE + st, "true", 4) == 0, "A8_EXPR: true span content is 'true'");
      CHECK(node_word(&t_true, lit_true, 13) == 2, "A8_EXPR: true literal aux is 2");
      CHECK(node_word(&t_true, lit_true, 14) == T_BOOL, "A8_EXPR: true literal type is T_BOOL");
      CHECK(node_word(&t_true, lit_true, 9) == 8, "A8_EXPR: true literal width is 8");
      CHECK(node_word(&t_true, lit_true, 10) == REG_PREDICATE, "A8_EXPR: true literal class is REG_PREDICATE");
      CHECK(node_word(&t_true, lit_true, 15) == 1, "A8_EXPR: true word 15 holds value 1");
    }
    free_tree(&t_true);

    NtFInput in_false = {"<false>", SRC_FALSE, strlen(SRC_FALSE)};
    CHECK(nova_check_many_v2(&in_false, 1, NULL), "A8_EXPR: SRC_FALSE passes nova_check_many_v2");
    Tree t_false;
    cases++;
    CHECK(parse(&t_false, SRC_FALSE, 0), "A8_EXPR: SRC_FALSE parse tree malloc");
    CHECK(t_false.r.runtime == 0, "A8_EXPR: SRC_FALSE runtime 0");
    CHECK(t_false.code == 0, "A8_EXPR: SRC_FALSE parse code 0");

    uint64_t lit_false = 0;
    for (uint64_t i = 1; i <= t_false.node_count; i++) {
      if (node_word(&t_false, i, 0) == K_LITERAL) { lit_false = i; break; }
    }
    CHECK(lit_false != 0, "A8_EXPR: SRC_FALSE contains a K_LITERAL node");
    if (lit_false != 0) {
      uint64_t sf = node_word(&t_false, lit_false, 5);
      uint64_t ef = node_word(&t_false, lit_false, 6);
      CHECK(ef > sf && ef - sf == 5, "A8_EXPR: false span length is 5");
      CHECK(sf + 5 <= strlen(SRC_FALSE) && strncmp(SRC_FALSE + sf, "false", 5) == 0, "A8_EXPR: false span content is 'false'");
      CHECK(node_word(&t_false, lit_false, 13) == 3, "A8_EXPR: false literal aux is 3");
      CHECK(node_word(&t_false, lit_false, 14) == T_BOOL, "A8_EXPR: false literal type is T_BOOL");
      CHECK(node_word(&t_false, lit_false, 9) == 8, "A8_EXPR: false literal width is 8");
      CHECK(node_word(&t_false, lit_false, 10) == REG_PREDICATE, "A8_EXPR: false literal class is REG_PREDICATE");
      CHECK(node_word(&t_false, lit_false, 15) == 0, "A8_EXPR: false word 15 holds value 0");
    }
    free_tree(&t_false);

    expect_refusal("A8_EXPR: undeclared trueish", SRC_TRUEISH, E_UNDECLARED, 4);
    expect_refusal("A8_EXPR: undeclared falsehood", SRC_FALSEHOOD, E_UNDECLARED, 4);
  }

  /* ---- 3. Integer literals 0, 42, 0xffffffffffffffff ---- */
  {
    NtFInput in_ints = {"<ints>", SRC_INTS, strlen(SRC_INTS)};
    CHECK(nova_check_many_v2(&in_ints, 1, NULL), "A8_EXPR: SRC_INTS passes nova_check_many_v2");
    Tree t_ints;
    cases++;
    CHECK(parse(&t_ints, SRC_INTS, 0), "A8_EXPR: SRC_INTS parse tree malloc");
    CHECK(t_ints.r.runtime == 0, "A8_EXPR: SRC_INTS runtime 0");
    CHECK(t_ints.code == 0, "A8_EXPR: SRC_INTS parse code 0");

    uint64_t lit_ids[8];
    unsigned lit_count = 0;
    for (uint64_t i = 1; i <= t_ints.node_count; i++) {
      if (node_word(&t_ints, i, 0) == K_LITERAL && lit_count < 8) {
        lit_ids[lit_count++] = i;
      }
    }
    CHECK(lit_count == 3, "A8_EXPR: found 3 integer literal nodes");
    if (lit_count >= 3) {
      /* Literal 0 */
      uint64_t s0 = node_word(&t_ints, lit_ids[0], 5);
      uint64_t e0 = node_word(&t_ints, lit_ids[0], 6);
      CHECK(e0 > s0 && e0 - s0 == 1, "A8_EXPR: literal 0 span length is 1");
      CHECK(s0 < strlen(SRC_INTS) && SRC_INTS[s0] == '0', "A8_EXPR: literal 0 span text is '0'");
      CHECK(node_word(&t_ints, lit_ids[0], 13) == 0, "A8_EXPR: literal 0 aux is 0 (decimal)");
      CHECK(node_word(&t_ints, lit_ids[0], 14) == T_U64, "A8_EXPR: literal 0 type is T_U64");
      CHECK(node_word(&t_ints, lit_ids[0], 9) == 64, "A8_EXPR: literal 0 width is 64");
      CHECK(node_word(&t_ints, lit_ids[0], 15) == 0, "A8_EXPR: literal 0 word 15 holds value 0");

      /* Literal 42 */
      uint64_t s1 = node_word(&t_ints, lit_ids[1], 5);
      uint64_t e1 = node_word(&t_ints, lit_ids[1], 6);
      CHECK(e1 > s1 && e1 - s1 == 2, "A8_EXPR: literal 42 span length is 2");
      CHECK(s1 + 1 < strlen(SRC_INTS) && SRC_INTS[s1] == '4' && SRC_INTS[s1 + 1] == '2', "A8_EXPR: literal 42 span text is '42'");
      CHECK(node_word(&t_ints, lit_ids[1], 13) == 0, "A8_EXPR: literal 42 aux is 0 (decimal)");
      CHECK(node_word(&t_ints, lit_ids[1], 14) == T_U64, "A8_EXPR: literal 42 type is T_U64");
      CHECK(node_word(&t_ints, lit_ids[1], 9) == 64, "A8_EXPR: literal 42 width is 64");
      CHECK(node_word(&t_ints, lit_ids[1], 15) == 42, "A8_EXPR: literal 42 word 15 holds value 42");

      /* Literal 0xffffffffffffffff */
      uint64_t s2 = node_word(&t_ints, lit_ids[2], 5);
      uint64_t e2 = node_word(&t_ints, lit_ids[2], 6);
      CHECK(e2 > s2 && e2 - s2 == 18, "A8_EXPR: literal hex span length is 18");
      CHECK(s2 + 18 <= strlen(SRC_INTS) && strncmp(SRC_INTS + s2, "0xffffffffffffffff", 18) == 0, "A8_EXPR: literal hex text matches");
      CHECK(node_word(&t_ints, lit_ids[2], 13) == 1, "A8_EXPR: literal hex aux is 1 (hex)");
      CHECK(node_word(&t_ints, lit_ids[2], 14) == T_U64, "A8_EXPR: literal hex type is T_U64");
      CHECK(node_word(&t_ints, lit_ids[2], 9) == 64, "A8_EXPR: literal hex width is 64");
      CHECK(node_word(&t_ints, lit_ids[2], 15) == UINT64_C(0xffffffffffffffff), "A8_EXPR: literal hex word 15 holds UINT64_MAX");
    }
    free_tree(&t_ints);
  }

  /* ---- 4. Replay reference program after refusal ---- */
  {
    Tree t_clean;
    cases++;
    CHECK(parse(&t_clean, PROGRAM, 0), "A8_EXPR: replay reference program parse");
    CHECK(t_clean.r.runtime == 0, "A8_EXPR: replay reference runtime 0");
    CHECK(t_clean.code == 0, "A8_EXPR: replay reference parse code 0");
    CHECK(t_clean.node_count > 0, "A8_EXPR: replay reference has nodes");
    CHECK(t_clean.root == 1, "A8_EXPR: replay reference root 1");
    CHECK(t_clean.scope_count >= 5, "A8_EXPR: replay reference scope_count >= 5");
    CHECK(t_clean.bind_count >= 4, "A8_EXPR: replay reference bind_count >= 4");
    free_tree(&t_clean);
  }
}

/* =========================================================================
 * A8: Buffer type parsing (buf<u8>, buf<u64>, whitespace, multiple params,
 * invalid element buf<bool>, lookalikes, missing delimiters, replay)
 * ========================================================================= */

static const char *const SRC_BUF_U8 =
    "module test_buf_u8;\n"
    "export fn test_u8(src:buf<u8>) -> u64 {\n"
    "    return 42;\n"
    "}\n";

static const char *const SRC_BUF_U64_WS =
    "module test_buf_u64_ws;\n"
    "export fn test_u64(src: buf < u64 >) -> u64 {\n"
    "    return 42;\n"
    "}\n";

static const char *const SRC_BUF_MULTI =
    "module test_buf_multi;\n"
    "export fn test_multi(a: buf<u8>, b: buf<u64>, count: u64) -> u64 {\n"
    "    return 42;\n"
    "}\n";

/* Reference accepts buf<bool> as valid grammar; current Nova parser lattice does not support it */
static const char *const SRC_BUF_BOOL =
    "module test_buf_bool;\n"
    "export fn test_bool(flags: buf<bool>) -> u64 {\n"
    "    return 42;\n"
    "}\n";

static const char *const SRC_LOOKALIKE_BUFY =
    "module test_lookalike_bufy;\n"
    "export fn test_bufy(src: bufy) -> u64 {\n"
    "    return 42;\n"
    "}\n";

static const char *const SRC_LOOKALIKE_U64X =
    "module test_lookalike_u64x;\n"
    "export fn test_u64x(src: buf<u64x>) -> u64 {\n"
    "    return 42;\n"
    "}\n";

static const char *const SRC_MISSING_GT =
    "module test_missing_gt;\n"
    "export fn test_nogt(src: buf<u8) -> u64 {\n"
    "    return 42;\n"
    "}\n";

static const char *const SRC_MISSING_LT =
    "module test_missing_lt;\n"
    "export fn test_nolt(src: buf u8>) -> u64 {\n"
    "    return 42;\n"
    "}\n";

static void test_a8_buffers(void) {
  /* ---- 1. buf<u8> parameter ---- */
  {
    NtFInput in_u8 = {"<buf_u8>", SRC_BUF_U8, strlen(SRC_BUF_U8)};
    CHECK(nova_check_many_v2(&in_u8, 1, NULL), "A8_BUF: SRC_BUF_U8 accepted by C nova_check_many_v2");
    Tree t_u8;
    cases++;
    CHECK(parse(&t_u8, SRC_BUF_U8, 0), "A8_BUF: SRC_BUF_U8 parse tree malloc");
    CHECK(t_u8.r.runtime == 0, "A8_BUF: SRC_BUF_U8 runtime 0");
    CHECK(t_u8.code == 0, "A8_BUF: SRC_BUF_U8 parse code 0");

    if (t_u8.code == 0 && t_u8.node_count > 0) {
      uint64_t fn = node_word(&t_u8, t_u8.root, 2);
      CHECK(node_word(&t_u8, fn, 0) == K_FN, "A8_BUF: root child is K_FN");
      uint64_t param = node_word(&t_u8, fn, 2);
      CHECK(node_word(&t_u8, param, 0) == K_PARAM, "A8_BUF: fn first child is K_PARAM");
      CHECK(node_word(&t_u8, param, 9) == 64, "A8_BUF: buf<u8> param width is 64");
      CHECK(node_word(&t_u8, param, 10) == REG_ADDRESS, "A8_BUF: buf<u8> param class is REG_ADDRESS");
      CHECK(node_word(&t_u8, param, 13) == 2, "A8_BUF: buf<u8> param ABI slots is 2");
      CHECK(node_word(&t_u8, param, 14) == T_BUF_U8, "A8_BUF: buf<u8> param type_id is T_BUF_U8");

      /* Find K_TYPE node for buf<u8> */
      uint64_t type_node = 0;
      for (uint64_t i = 1; i <= t_u8.node_count; i++) {
        if (node_word(&t_u8, i, 0) == K_TYPE &&
            (node_word(&t_u8, i, 13) == T_BUF_U8 || node_word(&t_u8, i, 14) == T_BUF_U8)) {
          type_node = i;
          break;
        }
      }
      CHECK(type_node != 0, "A8_BUF: found K_TYPE node for buf<u8>");
      if (type_node != 0) {
        uint64_t st = node_word(&t_u8, type_node, 5);
        uint64_t et = node_word(&t_u8, type_node, 6);
        CHECK(et > st && et <= strlen(SRC_BUF_U8), "A8_BUF: buf<u8> type span in bounds");
        if (et > st && et <= strlen(SRC_BUF_U8)) {
          CHECK(strncmp(SRC_BUF_U8 + st, "buf<u8>", et - st) == 0, "A8_BUF: type span text is 'buf<u8>'");
          CHECK(SRC_BUF_U8[et - 1] == '>', "A8_BUF: type span covers closing >");
        }
        CHECK(node_word(&t_u8, type_node, 9) == 64, "A8_BUF: buf<u8> K_TYPE width is 64");
        CHECK(node_word(&t_u8, type_node, 10) == REG_ADDRESS, "A8_BUF: buf<u8> K_TYPE class is REG_ADDRESS");
        CHECK(node_word(&t_u8, type_node, 13) == T_BUF_U8, "A8_BUF: buf<u8> K_TYPE aux holds T_BUF_U8");
      }
    }
    free_tree(&t_u8);
  }

  /* ---- 2. buf<u64> parameter with whitespace ---- */
  {
    NtFInput in_u64 = {"<buf_u64_ws>", SRC_BUF_U64_WS, strlen(SRC_BUF_U64_WS)};
    CHECK(nova_check_many_v2(&in_u64, 1, NULL), "A8_BUF: SRC_BUF_U64_WS accepted by C nova_check_many_v2");
    Tree t_u64;
    cases++;
    CHECK(parse(&t_u64, SRC_BUF_U64_WS, 0), "A8_BUF: SRC_BUF_U64_WS parse tree malloc");
    CHECK(t_u64.r.runtime == 0, "A8_BUF: SRC_BUF_U64_WS runtime 0");
    CHECK(t_u64.code == 0, "A8_BUF: SRC_BUF_U64_WS parse code 0");

    if (t_u64.code == 0 && t_u64.node_count > 0) {
      uint64_t fn = node_word(&t_u64, t_u64.root, 2);
      CHECK(node_word(&t_u64, fn, 0) == K_FN, "A8_BUF: root child is K_FN");
      uint64_t param = node_word(&t_u64, fn, 2);
      CHECK(node_word(&t_u64, param, 0) == K_PARAM, "A8_BUF: fn first child is K_PARAM");
      CHECK(node_word(&t_u64, param, 9) == 64, "A8_BUF: buf<u64> param width is 64");
      CHECK(node_word(&t_u64, param, 10) == REG_ADDRESS, "A8_BUF: buf<u64> param class is REG_ADDRESS");
      CHECK(node_word(&t_u64, param, 13) == 2, "A8_BUF: buf<u64> param ABI slots is 2");
      CHECK(node_word(&t_u64, param, 14) == T_BUF_U64, "A8_BUF: buf<u64> param type_id is T_BUF_U64");

      /* Find K_TYPE node for buf<u64> */
      uint64_t type_node = 0;
      for (uint64_t i = 1; i <= t_u64.node_count; i++) {
        if (node_word(&t_u64, i, 0) == K_TYPE &&
            (node_word(&t_u64, i, 13) == T_BUF_U64 || node_word(&t_u64, i, 14) == T_BUF_U64)) {
          type_node = i;
          break;
        }
      }
      CHECK(type_node != 0, "A8_BUF: found K_TYPE node for buf<u64>");
      if (type_node != 0) {
        uint64_t st = node_word(&t_u64, type_node, 5);
        uint64_t et = node_word(&t_u64, type_node, 6);
        CHECK(et > st && et <= strlen(SRC_BUF_U64_WS), "A8_BUF: buf<u64> type span in bounds");
        if (et > st && et <= strlen(SRC_BUF_U64_WS)) {
          CHECK(strncmp(SRC_BUF_U64_WS + st, "buf < u64 >", et - st) == 0, "A8_BUF: type span text is 'buf < u64 >'");
          CHECK(SRC_BUF_U64_WS[et - 1] == '>', "A8_BUF: type span covers closing >");
        }
        CHECK(node_word(&t_u64, type_node, 9) == 64, "A8_BUF: buf<u64> K_TYPE width is 64");
        CHECK(node_word(&t_u64, type_node, 10) == REG_ADDRESS, "A8_BUF: buf<u64> K_TYPE class is REG_ADDRESS");
        CHECK(node_word(&t_u64, type_node, 13) == T_BUF_U64, "A8_BUF: buf<u64> K_TYPE aux holds T_BUF_U64");
      }
    }
    free_tree(&t_u64);
  }

  /* ---- 3. Two buffer parameters followed by a scalar parameter ---- */
  {
    NtFInput in_multi = {"<buf_multi>", SRC_BUF_MULTI, strlen(SRC_BUF_MULTI)};
    CHECK(nova_check_many_v2(&in_multi, 1, NULL), "A8_BUF: SRC_BUF_MULTI accepted by C nova_check_many_v2");
    Tree t_multi;
    cases++;
    CHECK(parse(&t_multi, SRC_BUF_MULTI, 0), "A8_BUF: SRC_BUF_MULTI parse tree malloc");
    CHECK(t_multi.r.runtime == 0, "A8_BUF: SRC_BUF_MULTI runtime 0");
    CHECK(t_multi.code == 0, "A8_BUF: SRC_BUF_MULTI parse code 0");

    if (t_multi.code == 0 && t_multi.node_count > 0) {
      uint64_t fn = node_word(&t_multi, t_multi.root, 2);
      CHECK(node_word(&t_multi, fn, 0) == K_FN, "A8_BUF: multi root child is K_FN");
      uint64_t p1 = node_word(&t_multi, fn, 2);
      uint64_t p2 = node_word(&t_multi, p1, 4);
      uint64_t p3 = node_word(&t_multi, p2, 4);
      uint64_t ret = node_word(&t_multi, p3, 4);
      uint64_t body = node_word(&t_multi, ret, 4);

      /* Param 1: a: buf<u8> */
      CHECK(node_word(&t_multi, p1, 0) == K_PARAM, "A8_BUF: p1 is K_PARAM");
      CHECK(node_word(&t_multi, p1, 9) == 64, "A8_BUF: p1 width is 64");
      CHECK(node_word(&t_multi, p1, 10) == REG_ADDRESS, "A8_BUF: p1 class is REG_ADDRESS");
      CHECK(node_word(&t_multi, p1, 13) == 2, "A8_BUF: p1 slots is 2");
      CHECK(node_word(&t_multi, p1, 14) == T_BUF_U8, "A8_BUF: p1 type_id is T_BUF_U8");

      /* Param 2: b: buf<u64> */
      CHECK(node_word(&t_multi, p2, 0) == K_PARAM, "A8_BUF: p2 is K_PARAM");
      CHECK(node_word(&t_multi, p2, 9) == 64, "A8_BUF: p2 width is 64");
      CHECK(node_word(&t_multi, p2, 10) == REG_ADDRESS, "A8_BUF: p2 class is REG_ADDRESS");
      CHECK(node_word(&t_multi, p2, 13) == 2, "A8_BUF: p2 slots is 2");
      CHECK(node_word(&t_multi, p2, 14) == T_BUF_U64, "A8_BUF: p2 type_id is T_BUF_U64");

      /* Param 3: count: u64 (scalar following buffers verifies cursor) */
      CHECK(node_word(&t_multi, p3, 0) == K_PARAM, "A8_BUF: p3 is K_PARAM");
      CHECK(node_word(&t_multi, p3, 9) == 64, "A8_BUF: p3 width is 64");
      CHECK(node_word(&t_multi, p3, 10) == REG_VALUE, "A8_BUF: p3 class is REG_VALUE");
      CHECK(node_word(&t_multi, p3, 13) == 1, "A8_BUF: p3 slots is 1 (scalar)");
      CHECK(node_word(&t_multi, p3, 14) == T_U64, "A8_BUF: p3 type_id is T_U64");

      CHECK(node_word(&t_multi, ret, 0) == K_RETURN_NODE, "A8_BUF: ret is K_RETURN_NODE");
      CHECK(node_word(&t_multi, body, 0) == K_BLOCK, "A8_BUF: body is K_BLOCK");
    }
    free_tree(&t_multi);
  }

  /* ---- 4. buf<bool>: valid in C reference, currently unsupported profile in Nova parser lattice ---- */
  {
    NtFInput in_bool = {"<buf_bool>", SRC_BUF_BOOL, strlen(SRC_BUF_BOOL)};
    CHECK(nova_check_many_v2(&in_bool, 1, NULL),
          "A8_BUF: C reference accepts buf<bool> (valid Nova grammar)");
    expect_refusal("A8_BUF: unsupported profile buf<bool> refused with 802",
                   SRC_BUF_BOOL, E_NOT_CARRYABLE, 3);
  }

  /* ---- 5. Lookalikes: bufy and u64x ---- */
  {
    NtFInput in_bufy = {"<bufy>", SRC_LOOKALIKE_BUFY, strlen(SRC_LOOKALIKE_BUFY)};
    CHECK(!nova_check_many_v2(&in_bufy, 1, NULL),
          "A8_BUF: C reference refuses unknown type bufy");
    expect_refusal("A8_BUF: lookalike type bufy refused with 802",
                   SRC_LOOKALIKE_BUFY, E_NOT_CARRYABLE, 3);

    NtFInput in_u64x = {"<u64x>", SRC_LOOKALIKE_U64X, strlen(SRC_LOOKALIKE_U64X)};
    CHECK(!nova_check_many_v2(&in_u64x, 1, NULL),
          "A8_BUF: C reference refuses unknown element u64x");
    expect_refusal("A8_BUF: lookalike element u64x refused with 802",
                   SRC_LOOKALIKE_U64X, E_NOT_CARRYABLE, 3);
  }

  /* ---- 6. Missing delimiters ---- */
  {
    NtFInput in_nogt = {"<nogt>", SRC_MISSING_GT, strlen(SRC_MISSING_GT)};
    CHECK(!nova_check_many_v2(&in_nogt, 1, NULL),
          "A8_BUF: C reference refuses missing > delimiter");
    expect_refusal("A8_BUF: missing > delimiter refused",
                   SRC_MISSING_GT, E_BAD_SYNTAX, 5);

    NtFInput in_nolt = {"<nolt>", SRC_MISSING_LT, strlen(SRC_MISSING_LT)};
    CHECK(!nova_check_many_v2(&in_nolt, 1, NULL),
          "A8_BUF: C reference refuses missing < delimiter");
    expect_refusal("A8_BUF: missing < delimiter refused",
                   SRC_MISSING_LT, E_NOT_CARRYABLE, 3);
  }

  /* ---- 7. Replay reference program after buffer refusals ---- */
  {
    Tree t_clean;
    cases++;
    CHECK(parse(&t_clean, PROGRAM, 0), "A8_BUF: replay reference program parse");
    CHECK(t_clean.r.runtime == 0, "A8_BUF: replay reference runtime 0");
    CHECK(t_clean.code == 0, "A8_BUF: replay reference parse code 0");
    CHECK(t_clean.node_count > 0, "A8_BUF: replay reference has nodes");
    CHECK(t_clean.root == 1, "A8_BUF: replay reference root 1");
    CHECK(t_clean.scope_count >= 5, "A8_BUF: replay reference scope_count >= 5");
    CHECK(t_clean.bind_count >= 4, "A8_BUF: replay reference bind_count >= 4");
    free_tree(&t_clean);
  }
}

/* =========================================================================
 * A8: Named Record Types and Receiver-Specific Field Resolution
 * ========================================================================= */

static const char *const SRC_REC_BASIC =
    "module test_rec_basic;\n"
    "struct Pair {\n"
    "    value: u64\n"
    "}\n"
    "export fn use_pair(p: Pair) -> u64 {\n"
    "    return p.value;\n"
    "}\n";

static const char *const SRC_REC_DISAMBIG_1 =
    "module test_rec_disambig1;\n"
    "struct RecA {\n"
    "    item: u8\n"
    "}\n"
    "struct RecB {\n"
    "    item: u64\n"
    "}\n"
    "export fn get_a(a: RecA) -> u8 {\n"
    "    return a.item;\n"
    "}\n"
    "export fn get_b(b: RecB) -> u64 {\n"
    "    return b.item;\n"
    "}\n";

static const char *const SRC_REC_DISAMBIG_2 =
    "module test_rec_disambig2;\n"
    "struct RecA {\n"
    "    item: u8\n"
    "}\n"
    "struct RecB {\n"
    "    item: u64\n"
    "}\n"
    "export fn get_b(b: RecB) -> u64 {\n"
    "    return b.item;\n"
    "}\n"
    "export fn get_a(a: RecA) -> u8 {\n"
    "    return a.item;\n"
    "}\n";

static const char *const SRC_REC_NESTED_ALIAS_RET =
    "module test_rec_nested;\n"
    "struct Inner {\n"
    "    count: u64\n"
    "}\n"
    "struct Outer {\n"
    "    inner: Inner\n"
    "}\n"
    "export fn get_count(o: Outer) -> u64 {\n"
    "    return o.inner.count;\n"
    "}\n"
    "export fn alias_and_identity(p: Inner) -> Inner {\n"
    "    let q: Inner = p;\n"
    "    return q;\n"
    "}\n";

static const char *const SRC_REC_PREPASS =
    "module test_rec_prepass;\n"
    "export fn use_later(p: LaterRecord) -> u64 {\n"
    "    return p.data;\n"
    "}\n"
    "struct LaterRecord {\n"
    "    data: u64\n"
    "}\n";

static const char *const SRC_REC_NEG_WRONG_FIELD =
    "module test_rec_neg_wrong_field;\n"
    "struct FirstRec {\n"
    "    only_in_first: u64\n"
    "}\n"
    "struct SecondRec {\n"
    "    only_in_second: u64\n"
    "}\n"
    "export fn bad(s: SecondRec) -> u64 {\n"
    "    return s.only_in_first;\n"
    "}\n";

static const char *const SRC_REC_NEG_FIELD_ON_SCALAR =
    "module test_rec_neg_field_on_scalar;\n"
    "export fn bad(x: u64) -> u64 {\n"
    "    return x.field;\n"
    "}\n";

static const char *const SRC_REC_NEG_DUP_TYPE =
    "module test_rec_neg_dup_type;\n"
    "struct SameName {\n"
    "    a: u64\n"
    "}\n"
    "struct SameName {\n"
    "    b: u64\n"
    "}\n"
    "export fn f(x: SameName) -> u64 {\n"
    "    return x.a;\n"
    "}\n";

static const char *const SRC_REC_NEG_DUP_FIELD =
    "module test_rec_neg_dup_field;\n"
    "struct DupFieldRec {\n"
    "    f: u64,\n"
    "    f: u64\n"
    "}\n"
    "export fn f(x: DupFieldRec) -> u64 {\n"
    "    return x.f;\n"
    "}\n";

static const char *const SRC_REC_NEG_UNKNOWN_TYPE =
    "module test_rec_neg_unknown_type;\n"
    "export fn f(x: GhostType) -> u64 {\n"
    "    return 42;\n"
    "}\n";

static const char *const SRC_REC_NEG_WRONG_RETURN =
    "module test_rec_neg_wrong_return;\n"
    "struct TypeA {\n"
    "    val: u64\n"
    "}\n"
    "struct TypeB {\n"
    "    val: u64\n"
    "}\n"
    "export fn bad(a: TypeA) -> TypeB {\n"
    "    return a;\n"
    "}\n";

static void test_a8_records(void) {
  /* ---- 1. Basic struct Pair & fn use(p: Pair) -> u64 { return p.value; } ---- */
  {
    NtFInput in_pair = {"<rec_basic>", SRC_REC_BASIC, strlen(SRC_REC_BASIC)};
    CHECK(nova_check_many_v2(&in_pair, 1, NULL), "A8_REC: SRC_REC_BASIC accepted by C nova_check_many_v2");
    Tree t_pair;
    cases++;
    CHECK(parse(&t_pair, SRC_REC_BASIC, 0), "A8_REC: SRC_REC_BASIC parse tree malloc");
    CHECK(t_pair.r.runtime == 0, "A8_REC: SRC_REC_BASIC runtime 0");
    CHECK(t_pair.code == 0, "A8_REC: SRC_REC_BASIC parse code 0");

    if (t_pair.code == 0 && t_pair.node_count > 0) {
      uint64_t st_node = 0, fn_node = 0;
      for (uint64_t i = 1; i <= t_pair.node_count; i++) {
        uint64_t k = node_word(&t_pair, i, 0);
        if (k == K_STRUCT && st_node == 0) st_node = i;
        if (k == K_FN && fn_node == 0) fn_node = i;
      }
      CHECK(st_node != 0, "A8_REC: found K_STRUCT node for Pair");
      CHECK(fn_node != 0, "A8_REC: found K_FN node for use_pair");

      if (st_node != 0) {
        CHECK(node_word(&t_pair, st_node, 9) == 0, "A8_REC: K_STRUCT declaration carries width 0");
        CHECK(node_word(&t_pair, st_node, 10) == REG_NONE, "A8_REC: K_STRUCT declaration carries REG_NONE");
      }

      uint64_t param_node = 0;
      if (fn_node != 0) {
        for (uint64_t i = 1; i <= t_pair.node_count; i++) {
          if (node_word(&t_pair, i, 0) == K_PARAM && node_word(&t_pair, i, 1) == fn_node) {
            param_node = i;
            break;
          }
        }
      }
      CHECK(param_node != 0, "A8_REC: found K_PARAM node for p:Pair");
      uint64_t param_type_id = 0;
      if (param_node != 0) {
        param_type_id = node_word(&t_pair, param_node, 14);
        CHECK(param_type_id != 0, "A8_REC: param carries non-zero record type_id");
        CHECK(param_type_id > 12, "A8_REC: param record type_id is distinct from all builtins (id > 12)");
        CHECK(node_word(&t_pair, param_node, 9) == 64, "A8_REC: record param carries 64-bit ADDRESS carrier width");
        CHECK(node_word(&t_pair, param_node, 10) == REG_ADDRESS, "A8_REC: record param carries REG_ADDRESS class");
        CHECK(node_word(&t_pair, param_node, 13) == 1, "A8_REC: record param occupies 1 ABI slot");
      }

      /* Check K_FIELD_ACCESS node */
      uint64_t field_access_node = 0;
      for (uint64_t i = 1; i <= t_pair.node_count; i++) {
        if (node_word(&t_pair, i, 0) == K_FIELD_ACCESS) {
          field_access_node = i;
          break;
        }
      }
      CHECK(field_access_node != 0, "A8_REC: found K_FIELD_ACCESS node for p.value");
      if (field_access_node != 0) {
        CHECK(node_word(&t_pair, field_access_node, 9) == 64, "A8_REC: field access p.value carries width 64");
        CHECK(node_word(&t_pair, field_access_node, 10) == REG_VALUE, "A8_REC: field access p.value carries REG_VALUE");
        uint64_t receiver = node_word(&t_pair, field_access_node, 2);
        CHECK(receiver != 0 && receiver != UINT64_MAX, "A8_REC: field access has receiver child");
        if (receiver != 0 && receiver != UINT64_MAX) {
          CHECK(node_word(&t_pair, receiver, 0) == K_NAME, "A8_REC: receiver is K_NAME");
          CHECK(node_word(&t_pair, receiver, 14) == param_type_id,
                "A8_REC: receiver K_NAME preserves param's non-zero record type identity");
          CHECK(node_word(&t_pair, receiver, 9) == 64, "A8_REC: receiver K_NAME has 64-bit width");
          CHECK(node_word(&t_pair, receiver, 10) == REG_ADDRESS, "A8_REC: receiver K_NAME has REG_ADDRESS class");
        }
      }
    }
    free_tree(&t_pair);
  }

  /* ---- 2. Receiver-specific field disambiguation across two records with same field name ---- */
  {
    /* Order 1: get_a then get_b */
    NtFInput in_d1 = {"<rec_d1>", SRC_REC_DISAMBIG_1, strlen(SRC_REC_DISAMBIG_1)};
    CHECK(nova_check_many_v2(&in_d1, 1, NULL), "A8_REC: SRC_REC_DISAMBIG_1 accepted by C reference");
    Tree t_d1;
    cases++;
    CHECK(parse(&t_d1, SRC_REC_DISAMBIG_1, 0), "A8_REC: SRC_REC_DISAMBIG_1 parse tree malloc");
    CHECK(t_d1.r.runtime == 0, "A8_REC: SRC_REC_DISAMBIG_1 runtime 0");
    CHECK(t_d1.code == 0, "A8_REC: SRC_REC_DISAMBIG_1 parse code 0");

    if (t_d1.code == 0 && t_d1.node_count > 0) {
      uint64_t fn_a = 0, fn_b = 0;
      for (uint64_t i = 1; i <= t_d1.node_count; i++) {
        if (node_word(&t_d1, i, 0) == K_FN) {
          uint64_t st = node_word(&t_d1, i, 5);
          uint64_t et = node_word(&t_d1, i, 6);
          if (et > st && et <= strlen(SRC_REC_DISAMBIG_1)) {
            if (strncmp(SRC_REC_DISAMBIG_1 + st, "get_a", 5) == 0) fn_a = i;
            if (strncmp(SRC_REC_DISAMBIG_1 + st, "get_b", 5) == 0) fn_b = i;
          }
        }
      }
      CHECK(fn_a != 0 && fn_b != 0, "A8_REC: found both get_a and get_b functions in order 1");

      uint64_t fa_a = 0, fa_b = 0;
      for (uint64_t i = 1; i <= t_d1.node_count; i++) {
        if (node_word(&t_d1, i, 0) == K_FIELD_ACCESS) {
          uint64_t p = node_word(&t_d1, i, 1);
          while (p != 0 && p != UINT64_MAX && node_word(&t_d1, p, 0) != K_FN) {
            p = node_word(&t_d1, p, 1);
          }
          if (p == fn_a) fa_a = i;
          if (p == fn_b) fa_b = i;
        }
      }
      CHECK(fa_a != 0, "A8_REC: found field access in get_a");
      CHECK(fa_b != 0, "A8_REC: found field access in get_b");
      if (fa_a != 0) {
        CHECK(node_word(&t_d1, fa_a, 9) == 8, "A8_REC: order 1 a.item resolves to u8 (width 8)");
        CHECK(node_word(&t_d1, fa_a, 10) == REG_VALUE, "A8_REC: order 1 a.item carries REG_VALUE");
      }
      if (fa_b != 0) {
        CHECK(node_word(&t_d1, fa_b, 9) == 64, "A8_REC: order 1 b.item resolves to u64 (width 64)");
        CHECK(node_word(&t_d1, fa_b, 10) == REG_VALUE, "A8_REC: order 1 b.item carries REG_VALUE");
      }
    }
    free_tree(&t_d1);

    /* Order 2: get_b then get_a (reverse order of use) */
    NtFInput in_d2 = {"<rec_d2>", SRC_REC_DISAMBIG_2, strlen(SRC_REC_DISAMBIG_2)};
    CHECK(nova_check_many_v2(&in_d2, 1, NULL), "A8_REC: SRC_REC_DISAMBIG_2 accepted by C reference");
    Tree t_d2;
    cases++;
    CHECK(parse(&t_d2, SRC_REC_DISAMBIG_2, 0), "A8_REC: SRC_REC_DISAMBIG_2 parse tree malloc");
    CHECK(t_d2.r.runtime == 0, "A8_REC: SRC_REC_DISAMBIG_2 runtime 0");
    CHECK(t_d2.code == 0, "A8_REC: SRC_REC_DISAMBIG_2 parse code 0");

    if (t_d2.code == 0 && t_d2.node_count > 0) {
      uint64_t fn_a2 = 0, fn_b2 = 0;
      for (uint64_t i = 1; i <= t_d2.node_count; i++) {
        if (node_word(&t_d2, i, 0) == K_FN) {
          uint64_t st = node_word(&t_d2, i, 5);
          uint64_t et = node_word(&t_d2, i, 6);
          if (et > st && et <= strlen(SRC_REC_DISAMBIG_2)) {
            if (strncmp(SRC_REC_DISAMBIG_2 + st, "get_a", 5) == 0) fn_a2 = i;
            if (strncmp(SRC_REC_DISAMBIG_2 + st, "get_b", 5) == 0) fn_b2 = i;
          }
        }
      }
      CHECK(fn_a2 != 0 && fn_b2 != 0, "A8_REC: found both get_a and get_b functions in order 2");

      uint64_t fa_a2 = 0, fa_b2 = 0;
      for (uint64_t i = 1; i <= t_d2.node_count; i++) {
        if (node_word(&t_d2, i, 0) == K_FIELD_ACCESS) {
          uint64_t p = node_word(&t_d2, i, 1);
          while (p != 0 && p != UINT64_MAX && node_word(&t_d2, p, 0) != K_FN) {
            p = node_word(&t_d2, p, 1);
          }
          if (p == fn_a2) fa_a2 = i;
          if (p == fn_b2) fa_b2 = i;
        }
      }
      CHECK(fa_a2 != 0, "A8_REC: found field access in get_a (order 2)");
      CHECK(fa_b2 != 0, "A8_REC: found field access in get_b (order 2)");
      if (fa_a2 != 0) {
        CHECK(node_word(&t_d2, fa_a2, 9) == 8, "A8_REC: order 2 a.item resolves to u8 (width 8)");
        CHECK(node_word(&t_d2, fa_a2, 10) == REG_VALUE, "A8_REC: order 2 a.item carries REG_VALUE");
      }
      if (fa_b2 != 0) {
        CHECK(node_word(&t_d2, fa_b2, 9) == 64, "A8_REC: order 2 b.item resolves to u64 (width 64)");
        CHECK(node_word(&t_d2, fa_b2, 10) == REG_VALUE, "A8_REC: order 2 b.item carries REG_VALUE");
      }
    }
    free_tree(&t_d2);
  }

  /* ---- 3. Nested records / field chains, local alias let q:Pair=p, and record-return identity ---- */
  {
    NtFInput in_nested = {"<rec_nested>", SRC_REC_NESTED_ALIAS_RET, strlen(SRC_REC_NESTED_ALIAS_RET)};
    CHECK(nova_check_many_v2(&in_nested, 1, NULL), "A8_REC: SRC_REC_NESTED_ALIAS_RET accepted by C reference");
    Tree t_nest;
    cases++;
    CHECK(parse(&t_nest, SRC_REC_NESTED_ALIAS_RET, 0), "A8_REC: SRC_REC_NESTED_ALIAS_RET parse tree malloc");
    CHECK(t_nest.r.runtime == 0, "A8_REC: SRC_REC_NESTED_ALIAS_RET runtime 0");
    CHECK(t_nest.code == 0, "A8_REC: SRC_REC_NESTED_ALIAS_RET parse code 0");

    if (t_nest.code == 0 && t_nest.node_count > 0) {
      /* Identify Inner and Outer record type IDs */
      uint64_t inner_type_id = 0, outer_type_id = 0;
      for (uint64_t i = 1; i <= t_nest.node_count; i++) {
        if (node_word(&t_nest, i, 0) == K_PARAM) {
          uint64_t st = node_word(&t_nest, i, 5);
          uint64_t et = node_word(&t_nest, i, 6);
          if (et > st && et <= strlen(SRC_REC_NESTED_ALIAS_RET)) {
            if (SRC_REC_NESTED_ALIAS_RET[st] == 'o' && et - st == 1) {
              outer_type_id = node_word(&t_nest, i, 14);
            }
            if (SRC_REC_NESTED_ALIAS_RET[st] == 'p' && et - st == 1) {
              inner_type_id = node_word(&t_nest, i, 14);
            }
          }
        }
      }
      CHECK(inner_type_id != 0, "A8_REC: Inner type has non-zero ID");
      CHECK(outer_type_id != 0, "A8_REC: Outer type has non-zero ID");
      CHECK(inner_type_id != outer_type_id, "A8_REC: Inner and Outer types have distinct IDs");

      /* Check chained field access: o.inner.count */
      uint64_t outer_fa = 0;
      for (uint64_t i = 1; i <= t_nest.node_count; i++) {
        if (node_word(&t_nest, i, 0) == K_FIELD_ACCESS && node_word(&t_nest, i, 9) == 64) {
          uint64_t inner_fa = node_word(&t_nest, i, 2);
          if (inner_fa != 0 && inner_fa != UINT64_MAX && node_word(&t_nest, inner_fa, 0) == K_FIELD_ACCESS) {
            outer_fa = i;
            break;
          }
        }
      }
      CHECK(outer_fa != 0, "A8_REC: found chained field access o.inner.count");
      if (outer_fa != 0) {
        uint64_t inner_fa = node_word(&t_nest, outer_fa, 2);
        CHECK(node_word(&t_nest, inner_fa, 14) == inner_type_id,
              "A8_REC: o.inner yields record type Inner");
        CHECK(node_word(&t_nest, inner_fa, 9) == 64, "A8_REC: o.inner carries carrier width 64");
        CHECK(node_word(&t_nest, inner_fa, 10) == REG_ADDRESS, "A8_REC: o.inner carries REG_ADDRESS");
        CHECK(node_word(&t_nest, outer_fa, 9) == 64, "A8_REC: o.inner.count carries width 64");
        CHECK(node_word(&t_nest, outer_fa, 10) == REG_VALUE, "A8_REC: o.inner.count carries REG_VALUE");
      }

      /* Check let q: Inner = p and return q preserves record type identity */
      uint64_t let_node = 0, ret_node = 0;
      for (uint64_t i = 1; i <= t_nest.node_count; i++) {
        if (node_word(&t_nest, i, 0) == K_LET) {
          let_node = i;
        }
        if (node_word(&t_nest, i, 0) == K_RETURN_NODE && node_word(&t_nest, i, 14) == inner_type_id) {
          ret_node = i;
        }
      }
      CHECK(let_node != 0, "A8_REC: found let q: Inner node");
      CHECK(ret_node != 0, "A8_REC: function return type node carries Inner record type ID");
      if (let_node != 0) {
        CHECK(node_word(&t_nest, let_node, 14) == inner_type_id,
              "A8_REC: local binding let q preserves Inner record type ID");
        CHECK(node_word(&t_nest, let_node, 9) == 64, "A8_REC: local let q carries carrier width 64");
        CHECK(node_word(&t_nest, let_node, 10) == REG_ADDRESS, "A8_REC: local let q carries REG_ADDRESS");
      }
    }
    free_tree(&t_nest);
  }

  /* ---- 4. Function before its record declaration (valid by prepass) ---- */
  {
    NtFInput in_prepass = {"<rec_prepass>", SRC_REC_PREPASS, strlen(SRC_REC_PREPASS)};
    CHECK(nova_check_many_v2(&in_prepass, 1, NULL), "A8_REC: SRC_REC_PREPASS accepted by C nova_check_many_v2 prepass");
    Tree t_prepass;
    cases++;
    CHECK(parse(&t_prepass, SRC_REC_PREPASS, 0), "A8_REC: SRC_REC_PREPASS parse tree malloc");
    CHECK(t_prepass.r.runtime == 0, "A8_REC: SRC_REC_PREPASS runtime 0");
    CHECK(t_prepass.code == 0, "A8_REC: SRC_REC_PREPASS parse code 0 (prepass accepts record declared after function)");

    if (t_prepass.code == 0 && t_prepass.node_count > 0) {
      uint64_t p_node = 0;
      for (uint64_t i = 1; i <= t_prepass.node_count; i++) {
        if (node_word(&t_prepass, i, 0) == K_PARAM) { p_node = i; break; }
      }
      CHECK(p_node != 0, "A8_REC: found K_PARAM in prepass function");
      if (p_node != 0) {
        CHECK(node_word(&t_prepass, p_node, 14) != 0, "A8_REC: param carries resolved LaterRecord type ID");
        CHECK(node_word(&t_prepass, p_node, 9) == 64, "A8_REC: param carries width 64");
        CHECK(node_word(&t_prepass, p_node, 10) == REG_ADDRESS, "A8_REC: param carries REG_ADDRESS");
      }
    }
    free_tree(&t_prepass);
  }

  /* ---- 5. Negative tests ---- */
  {
    /* 5a. Field exists only in other record */
    NtFInput in_n1 = {"<neg_wf>", SRC_REC_NEG_WRONG_FIELD, strlen(SRC_REC_NEG_WRONG_FIELD)};
    CHECK(!nova_check_many_v2(&in_n1, 1, NULL), "A8_REC: C reference refuses field only present in other record");
    Tree t_n1;
    cases++;
    CHECK(parse(&t_n1, SRC_REC_NEG_WRONG_FIELD, 0), "A8_REC: parse wrong field scratch");
    CHECK(t_n1.r.runtime == 0, "A8_REC: wrong field runtime 0");
    CHECK(t_n1.code != 0, "A8_REC: candidate refuses field existing only in other record");
    CHECK(t_n1.node_count == 0, "A8_REC: wrong field publishes node_count 0");
    free_tree(&t_n1);

    /* 5b. Field access on scalar */
    NtFInput in_n2 = {"<neg_scalar>", SRC_REC_NEG_FIELD_ON_SCALAR, strlen(SRC_REC_NEG_FIELD_ON_SCALAR)};
    CHECK(!nova_check_many_v2(&in_n2, 1, NULL), "A8_REC: C reference refuses field access on scalar u64");
    Tree t_n2;
    cases++;
    CHECK(parse(&t_n2, SRC_REC_NEG_FIELD_ON_SCALAR, 0), "A8_REC: parse field on scalar scratch");
    CHECK(t_n2.r.runtime == 0, "A8_REC: field on scalar runtime 0");
    CHECK(t_n2.code != 0, "A8_REC: candidate refuses field access on scalar");
    CHECK(t_n2.node_count == 0, "A8_REC: field on scalar publishes node_count 0");
    free_tree(&t_n2);

    /* 5c. Duplicate struct type name */
    NtFInput in_n3 = {"<neg_duptype>", SRC_REC_NEG_DUP_TYPE, strlen(SRC_REC_NEG_DUP_TYPE)};
    CHECK(!nova_check_many_v2(&in_n3, 1, NULL), "A8_REC: C reference refuses duplicate record type");
    Tree t_n3;
    cases++;
    CHECK(parse(&t_n3, SRC_REC_NEG_DUP_TYPE, 0), "A8_REC: parse dup record scratch");
    CHECK(t_n3.r.runtime == 0, "A8_REC: dup record runtime 0");
    CHECK(t_n3.code != 0, "A8_REC: candidate refuses duplicate record type");
    CHECK(t_n3.node_count == 0, "A8_REC: duplicate record publishes node_count 0");
    free_tree(&t_n3);

    /* 5d. Duplicate field in struct */
    NtFInput in_n4 = {"<neg_dupfield>", SRC_REC_NEG_DUP_FIELD, strlen(SRC_REC_NEG_DUP_FIELD)};
    CHECK(!nova_check_many_v2(&in_n4, 1, NULL), "A8_REC: C reference refuses duplicate field in record");
    Tree t_n4;
    cases++;
    CHECK(parse(&t_n4, SRC_REC_NEG_DUP_FIELD, 0), "A8_REC: parse dup field scratch");
    CHECK(t_n4.r.runtime == 0, "A8_REC: dup field runtime 0");
    CHECK(t_n4.code != 0, "A8_REC: candidate refuses duplicate field in record");
    CHECK(t_n4.node_count == 0, "A8_REC: duplicate field publishes node_count 0");
    free_tree(&t_n4);

    /* 5e. Unknown record type */
    NtFInput in_n5 = {"<neg_unktype>", SRC_REC_NEG_UNKNOWN_TYPE, strlen(SRC_REC_NEG_UNKNOWN_TYPE)};
    CHECK(!nova_check_many_v2(&in_n5, 1, NULL), "A8_REC: C reference refuses unknown record type");
    Tree t_n5;
    cases++;
    CHECK(parse(&t_n5, SRC_REC_NEG_UNKNOWN_TYPE, 0), "A8_REC: parse unknown type scratch");
    CHECK(t_n5.r.runtime == 0, "A8_REC: unknown type runtime 0");
    CHECK(t_n5.code != 0, "A8_REC: candidate refuses unknown record type");
    CHECK(t_n5.node_count == 0, "A8_REC: unknown record type publishes node_count 0");
    free_tree(&t_n5);

    /* 5f. Wrong record return (incompatible types with same carrier width) */
    NtFInput in_n6 = {"<neg_ret>", SRC_REC_NEG_WRONG_RETURN, strlen(SRC_REC_NEG_WRONG_RETURN)};
    CHECK(!nova_check_many_v2(&in_n6, 1, NULL), "A8_REC: C reference refuses wrong record return type");
    Tree t_n6;
    cases++;
    CHECK(parse(&t_n6, SRC_REC_NEG_WRONG_RETURN, 0), "A8_REC: parse wrong return scratch");
    CHECK(t_n6.r.runtime == 0, "A8_REC: wrong return runtime 0");
    CHECK(t_n6.code != 0, "A8_REC: candidate refuses wrong record return");
    CHECK(t_n6.node_count == 0, "A8_REC: wrong record return publishes node_count 0");
    free_tree(&t_n6);
  }

  /* ---- 6. Replay reference program after record test suite ---- */
  {
    Tree t_clean;
    cases++;
    CHECK(parse(&t_clean, PROGRAM, 0), "A8_REC: replay reference program parse");
    CHECK(t_clean.r.runtime == 0, "A8_REC: replay reference runtime 0");
    CHECK(t_clean.code == 0, "A8_REC: replay reference parse code 0");
    CHECK(t_clean.node_count > 0, "A8_REC: replay reference has nodes");
    CHECK(t_clean.root == 1, "A8_REC: replay reference root 1");
    CHECK(t_clean.scope_count >= 5, "A8_REC: replay reference scope_count >= 5");
    CHECK(t_clean.bind_count >= 4, "A8_REC: replay reference bind_count >= 4");
    free_tree(&t_clean);
  }
}

static void test_a8_record_boundaries(void) {
    char *src_buf = (char *)malloc(32768);
    CHECK(src_buf != NULL, "A8_REC_BOUNDS buffer allocation succeeded");
    if (!src_buf) return;

    /* Cases 1 & 2: Boundary test on caller FIELDS partition (146 fits, 147 overflows) */
    for (int count = 146; count <= 147; count++) {
        cases++;
        size_t off = 0;
        int n = snprintf(src_buf + off, 32768 - off, "module rec%d;\n", count);
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_REC_BOUNDS source formatting failed"); free(src_buf); return; }
        off += (size_t)n;

        for (int i = 0; i < count; i++) {
            n = snprintf(src_buf + off, 32768 - off, "struct S%d { f%d: u64 }\n", i, i);
            if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_REC_BOUNDS source formatting failed"); free(src_buf); return; }
            off += (size_t)n;
        }

        n = snprintf(src_buf + off, 32768 - off, "export fn done() -> u64 { return 42; }\n");
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_REC_BOUNDS source formatting failed"); free(src_buf); return; }
        off += (size_t)n;

        CHECK(off < 32768, count == 146 ? "A8_REC_BOUNDS 146 source built without truncation" : "A8_REC_BOUNDS 147 source built without truncation");

        NtFInput in = { "rec.nova", src_buf, off };
        CHECK(nova_check_many_v2(&in, 1, NULL), count == 146 ? "A8_REC_BOUNDS C reference accepts 146 record declarations" : "A8_REC_BOUNDS C reference accepts 147 record declarations");

        Tree t;
        int ok = parse(&t, src_buf, 0);
        CHECK(ok == 1, count == 146 ? "A8_REC_BOUNDS parse(146) returned cleanly" : "A8_REC_BOUNDS parse(147) returned cleanly");
        if (ok == 1) {
            CHECK(t.r.runtime == 0, count == 146 ? "A8_REC_BOUNDS candidate 146 no runtime panic" : "A8_REC_BOUNDS candidate 147 no runtime panic");
            if (count == 146) {
                CHECK(t.code == 0, "A8_REC_BOUNDS candidate 146 accepted");
                CHECK(t.node_count > 0, "A8_REC_BOUNDS candidate 146 published AST tree");
            } else {
                CHECK(t.code != 0, "A8_REC_BOUNDS candidate 147 rejected on table exhaustion");
                CHECK(t.node_count == 0, "A8_REC_BOUNDS candidate 147 published empty tree");
            }
            free_tree(&t);
        }
    }
    free(src_buf);

    /* Case 3: Lexically malformed field */
    cases++;
    const char *src_mal = "module bad; struct R { x: @ } export fn done() -> u64 { return 42; }";
    NtFInput in_mal = { "bad.nova", src_mal, strlen(src_mal) };
    CHECK(!nova_check_many_v2(&in_mal, 1, NULL), "A8_REC_BOUNDS C reference rejects malformed field");

    Tree t_mal;
    int ok_mal = parse(&t_mal, src_mal, 0);
    CHECK(ok_mal == 1, "A8_REC_BOUNDS parse(malformed) returned cleanly");
    if (ok_mal == 1) {
        CHECK(t_mal.r.runtime == 0, "A8_REC_BOUNDS candidate malformed no runtime panic");
        CHECK(t_mal.code != 0, "A8_REC_BOUNDS candidate malformed rejected");
        CHECK(t_mal.node_count == 0, "A8_REC_BOUNDS candidate malformed published empty tree");
        free_tree(&t_mal);
    }

    /* Case 4: Incompatible record alias */
    cases++;
    const char *src_alias = "module alias; struct A { x: u64 } struct B { x: u64 } fn bad(a: A) -> u64 { let b: B = a; return 42; }";
    NtFInput in_alias = { "alias.nova", src_alias, strlen(src_alias) };
    CHECK(!nova_check_many_v2(&in_alias, 1, NULL), "A8_REC_BOUNDS C reference rejects incompatible record alias");

    Tree t_alias;
    int ok_alias = parse(&t_alias, src_alias, 0);
    CHECK(ok_alias == 1, "A8_REC_BOUNDS parse(alias) returned cleanly");
    if (ok_alias == 1) {
        CHECK(t_alias.r.runtime == 0, "A8_REC_BOUNDS candidate alias no runtime panic");
        CHECK(t_alias.code != 0, "A8_REC_BOUNDS candidate alias rejected");
        CHECK(t_alias.node_count == 0, "A8_REC_BOUNDS candidate alias published empty tree");
        free_tree(&t_alias);
    }

    /* Case 5: Struct with runtime field */
    cases++;
    const char *src_rt = "module rtfield; struct R { x: runtime } fn done() -> u64 { return 42; }";
    NtFInput in_rt = { "rtfield.nova", src_rt, strlen(src_rt) };
    CHECK(!nova_check_many_v2(&in_rt, 1, NULL), "A8_REC_BOUNDS C reference rejects struct with runtime field");

    Tree t_rt;
    int ok_rt = parse(&t_rt, src_rt, 0);
    CHECK(ok_rt == 1, "A8_REC_BOUNDS parse(rtfield) returned cleanly");
    if (ok_rt == 1) {
        CHECK(t_rt.r.runtime == 0, "A8_REC_BOUNDS candidate rtfield no runtime panic");
        CHECK(t_rt.code != 0, "A8_REC_BOUNDS candidate rtfield rejected");
        CHECK(t_rt.node_count == 0, "A8_REC_BOUNDS candidate rtfield published empty tree");
        free_tree(&t_rt);
    }

    /* Case 6: Clean replay of standard PROGRAM */
    cases++;
    Tree t_clean;
    int ok_clean = parse(&t_clean, PROGRAM, 0);
    CHECK(ok_clean == 1, "A8_REC_BOUNDS clean replay parse returned cleanly");
    if (ok_clean == 1) {
        CHECK(t_clean.r.runtime == 0, "A8_REC_BOUNDS clean replay no runtime panic");
        CHECK(t_clean.code == 0, "A8_REC_BOUNDS clean replay succeeds");
        CHECK(t_clean.node_count > 0, "A8_REC_BOUNDS clean replay published valid tree");
        free_tree(&t_clean);
    }
}

static void test_a8_record_constructors(void) {
    /* Probe mode 3 shape for K_RECORD node kind */
    Tree shape;
    int shape_ok = parse(&shape, "", 3);
    CHECK(shape_ok == 1, "A8_REC_CTOR shape query returned cleanly");
    if (shape_ok != 1) return;
    CHECK(shape.r.runtime == 0, "A8_REC_CTOR shape query no runtime fault");
    uint64_t K_RECORD = shape.out[33];
    CHECK(K_RECORD > 0, "A8_REC_CTOR K_RECORD node kind discovered");
    free_tree(&shape);

    /* Positive 1: Field reordering, child ordinals, type identities, literal types */
    cases++;
    const char *src_pos1 = "module ctor1; struct Pair { x: u64, y: bool } fn make() -> Pair { return Pair{y: true, x: 42}; }";
    NtFInput in_pos1 = { "ctor1.nova", src_pos1, strlen(src_pos1) };
    CHECK(nova_check_many_v2(&in_pos1, 1, NULL), "A8_REC_CTOR pos1 C reference accepts out-of-order fields");
    Tree t1;
    int ok1 = parse(&t1, src_pos1, 0);
    CHECK(ok1 == 1, "A8_REC_CTOR pos1 parse returned cleanly");
    if (ok1 == 1) {
        CHECK(t1.r.runtime == 0, "A8_REC_CTOR pos1 no runtime fault");
        CHECK(t1.code == 0, "A8_REC_CTOR pos1 accepted");
        CHECK(t1.node_count > 0, "A8_REC_CTOR pos1 published valid tree");

        uint64_t ctor_id = 0;
        for (uint64_t i = 1; i <= t1.node_count; i++) {
            if (node_word(&t1, i, 0) == K_RECORD) { ctor_id = i; break; }
        }
        CHECK(ctor_id > 0, "A8_REC_CTOR pos1 found K_RECORD node");
        if (ctor_id > 0) {
            CHECK(node_word(&t1, ctor_id, 9) == 64, "A8_REC_CTOR pos1 K_RECORD carrier width 64");
            CHECK(node_word(&t1, ctor_id, 10) == REG_ADDRESS, "A8_REC_CTOR pos1 K_RECORD REG_ADDRESS");
            uint64_t pair_type_id = node_word(&t1, ctor_id, 14);
            CHECK(pair_type_id > 12, "A8_REC_CTOR pos1 K_RECORD valid record type identity");

            uint64_t f_first = node_word(&t1, ctor_id, 2);
            CHECK(f_first > 0 && node_word(&t1, f_first, 0) == K_FIELD, "A8_REC_CTOR pos1 first child is K_FIELD");
            if (f_first > 0) {
                uint64_t s1 = node_word(&t1, f_first, 5), e1 = node_word(&t1, f_first, 6);
                CHECK(s1 <= e1 && e1 <= strlen(src_pos1) && e1 - s1 == 1 && src_pos1[s1] == 'y', "A8_REC_CTOR pos1 first field name span matches y");
                CHECK(node_word(&t1, f_first, 15) == 1, "A8_REC_CTOR pos1 first child y has declaration ordinal 1");
                CHECK(node_word(&t1, f_first, 14) == 9, "A8_REC_CTOR pos1 first child y field type bool");
                uint64_t val_first = node_word(&t1, f_first, 2);
                CHECK(val_first > 0 && node_word(&t1, val_first, 0) == K_LITERAL, "A8_REC_CTOR pos1 y value is K_LITERAL");
                CHECK(node_word(&t1, val_first, 13) == 2, "A8_REC_CTOR pos1 literal true aux 2");
                CHECK(node_word(&t1, val_first, 15) == 1, "A8_REC_CTOR pos1 literal true value 1");
            }

            uint64_t f_second = f_first > 0 ? node_word(&t1, f_first, 4) : 0;
            CHECK(f_second > 0 && node_word(&t1, f_second, 0) == K_FIELD, "A8_REC_CTOR pos1 second child is K_FIELD");
            if (f_second > 0) {
                uint64_t s2 = node_word(&t1, f_second, 5), e2 = node_word(&t1, f_second, 6);
                CHECK(s2 <= e2 && e2 <= strlen(src_pos1) && e2 - s2 == 1 && src_pos1[s2] == 'x', "A8_REC_CTOR pos1 second field name span matches x");
                CHECK(node_word(&t1, f_second, 15) == 0, "A8_REC_CTOR pos1 second child x has declaration ordinal 0");
                CHECK(node_word(&t1, f_second, 14) == 4, "A8_REC_CTOR pos1 second child x field type u64");
                uint64_t val_second = node_word(&t1, f_second, 2);
                CHECK(val_second > 0 && node_word(&t1, val_second, 0) == K_LITERAL, "A8_REC_CTOR pos1 x value is K_LITERAL");
                CHECK(node_word(&t1, val_second, 15) == 42, "A8_REC_CTOR pos1 literal x value 42");
                CHECK(node_word(&t1, f_second, 4) == 0, "A8_REC_CTOR pos1 exactly two field children");
            }
        }
        free_tree(&t1);
    }

    /* Positive 2: Nested records with distinct type identities */
    cases++;
    const char *src_pos2 = "module ctor2; struct Inner { x: u64 } struct Outer { item: Inner } fn make() -> Outer { return Outer{item: Inner{x: 7}}; }";
    NtFInput in_pos2 = { "ctor2.nova", src_pos2, strlen(src_pos2) };
    CHECK(nova_check_many_v2(&in_pos2, 1, NULL), "A8_REC_CTOR pos2 C reference accepts nested record constructor");
    Tree t2;
    int ok2 = parse(&t2, src_pos2, 0);
    CHECK(ok2 == 1, "A8_REC_CTOR pos2 parse returned cleanly");
    if (ok2 == 1) {
        CHECK(t2.r.runtime == 0, "A8_REC_CTOR pos2 no runtime fault");
        CHECK(t2.code == 0, "A8_REC_CTOR pos2 accepted");
        CHECK(t2.node_count > 0, "A8_REC_CTOR pos2 published valid tree");
        uint64_t ctor_outer = 0, ctor_inner = 0;
        for (uint64_t i = 1; i <= t2.node_count; i++) {
            if (node_word(&t2, i, 0) == K_RECORD) {
                if (ctor_outer == 0) ctor_outer = i;
                else if (ctor_inner == 0) ctor_inner = i;
            }
        }
        CHECK(ctor_outer > 0 && ctor_inner > 0, "A8_REC_CTOR pos2 found two K_RECORD nodes");
        if (ctor_outer > 0 && ctor_inner > 0) {
            CHECK(node_word(&t2, ctor_outer, 14) != node_word(&t2, ctor_inner, 14), "A8_REC_CTOR pos2 nested records have distinct type IDs");
        }
        free_tree(&t2);
    }

    /* Positive 3: Buffer field in record constructor with trailing comma */
    cases++;
    const char *src_pos3 = "module ctor3; struct State { data: buf<u8>, count: u64 } fn make(src: buf<u8>, n: u64) -> State { return State{data: src, count: n + 1,}; }";
    NtFInput in_pos3 = { "ctor3.nova", src_pos3, strlen(src_pos3) };
    CHECK(nova_check_many_v2(&in_pos3, 1, NULL), "A8_REC_CTOR pos3 C reference accepts buffer field with trailing comma");
    Tree t3;
    int ok3 = parse(&t3, src_pos3, 0);
    CHECK(ok3 == 1, "A8_REC_CTOR pos3 parse returned cleanly");
    if (ok3 == 1) {
        CHECK(t3.r.runtime == 0, "A8_REC_CTOR pos3 no runtime fault");
        CHECK(t3.code == 0, "A8_REC_CTOR pos3 accepted");
        CHECK(t3.node_count > 0, "A8_REC_CTOR pos3 published valid tree");
        free_tree(&t3);
    }

    /* Positive 4: Literal u8 coercion within range (255) */
    cases++;
    const char *src_pos4 = "module ctor4; struct Byte { x: u8 } fn make() -> Byte { return Byte{x: 255}; }";
    NtFInput in_pos4 = { "ctor4.nova", src_pos4, strlen(src_pos4) };
    CHECK(nova_check_many_v2(&in_pos4, 1, NULL), "A8_REC_CTOR pos4 C reference accepts u8 literal 255");
    Tree t4;
    int ok4 = parse(&t4, src_pos4, 0);
    CHECK(ok4 == 1, "A8_REC_CTOR pos4 parse returned cleanly");
    if (ok4 == 1) {
        CHECK(t4.r.runtime == 0, "A8_REC_CTOR pos4 no runtime fault");
        CHECK(t4.code == 0, "A8_REC_CTOR pos4 accepted");
        CHECK(t4.node_count > 0, "A8_REC_CTOR pos4 published valid tree");
        uint64_t ctor4 = 0;
        for (uint64_t i = 1; i <= t4.node_count; i++) {
            if (node_word(&t4, i, 0) == K_RECORD) { ctor4 = i; break; }
        }
        CHECK(ctor4 > 0, "A8_REC_CTOR pos4 found K_RECORD node");
        uint64_t fld = ctor4 > 0 ? node_word(&t4, ctor4, 2) : 0;
        CHECK(fld > 0, "A8_REC_CTOR pos4 found field child node");
        uint64_t lit = fld > 0 ? node_word(&t4, fld, 2) : 0;
        CHECK(lit > 0, "A8_REC_CTOR pos4 found literal child node");
        if (lit > 0) {
            CHECK(node_word(&t4, lit, 9) == 8, "A8_REC_CTOR pos4 literal coerced to width 8");
            CHECK(node_word(&t4, lit, 14) == 1, "A8_REC_CTOR pos4 literal type T_U8");
        }
        free_tree(&t4);
    }

    /* Negative test helper */
    const char *negatives[] = {
        /* 0: missing field */
        "module n0; struct R { x: u64, y: u64 } fn bad() -> R { return R{x: 1}; }",
        /* 1: duplicate field in constructor */
        "module n1; struct R { x: u64 } fn bad() -> R { return R{x: 1, x: 2}; }",
        /* 2: unknown field */
        "module n2; struct R { x: u64 } fn bad() -> R { return R{x: 1, z: 2}; }",
        /* 3: type mismatch: bool for u64 */
        "module n3; struct R { x: u64 } fn bad() -> R { return R{x: true}; }",
        /* 4: literal out of range: 256 for u8 */
        "module n4; struct R { x: u8 } fn bad() -> R { return R{x: 256}; }",
        /* 5: wrong nested record type */
        "module n5; struct A { x: u64 } struct B { x: u64 } struct R { a: A } fn bad(b: B) -> R { return R{a: b}; }",
        /* 6: missing colon */
        "module n6; struct R { x: u64 } fn bad() -> R { return R{x 1}; }",
        /* 7: unclosed initializer */
        "module n7; struct R { x: u64 } fn bad() -> R { return R{x: 1; }"
    };
    const char *neg_msgs[] = {
        "missing field in record constructor",
        "duplicate field in record constructor",
        "unknown field in record constructor",
        "bool for u64 field type mismatch",
        "256 out-of-range for u8 field",
        "wrong nested record type",
        "missing colon in field initializer",
        "unclosed initializer brace"
    };
    int num_negatives = (int)(sizeof(negatives) / sizeof(negatives[0]));
    for (int i = 0; i < num_negatives; i++) {
        cases++;
        NtFInput in_neg = { "neg.nova", negatives[i], strlen(negatives[i]) };
        CHECK(!nova_check_many_v2(&in_neg, 1, NULL), neg_msgs[i]);
        Tree t_neg;
        int ok_neg = parse(&t_neg, negatives[i], 0);
        CHECK(ok_neg == 1, "A8_REC_CTOR parse negative returned cleanly");
        if (ok_neg == 1) {
            CHECK(t_neg.r.runtime == 0, "A8_REC_CTOR negative no runtime fault");
            CHECK(t_neg.code != 0, "A8_REC_CTOR candidate rejected invalid constructor");
            CHECK(t_neg.node_count == 0, "A8_REC_CTOR candidate published empty tree on negative");
            free_tree(&t_neg);
        }
    }

    /* Clean replay of standard PROGRAM */
    cases++;
    Tree t_clean;
    int ok_clean = parse(&t_clean, PROGRAM, 0);
    CHECK(ok_clean == 1, "A8_REC_CTOR clean replay parse returned cleanly");
    if (ok_clean == 1) {
        CHECK(t_clean.r.runtime == 0, "A8_REC_CTOR clean replay no runtime fault");
        CHECK(t_clean.code == 0, "A8_REC_CTOR clean replay succeeds");
        CHECK(t_clean.node_count > 0, "A8_REC_CTOR clean replay published valid tree");
        free_tree(&t_clean);
    }
}

static void test_a8_constructor_numeric_edges(void) {
    /* Case 1: ACCEPT i64 arithmetic: n + 1 -> binary type 8, width 64 */
    cases++;
    const char *src1 = "module m1; struct R { x: i64 } fn f(n: i64) -> R { return R{x: n + 1}; }";
    NtFInput in1 = { "m1.nova", src1, strlen(src1) };
    CHECK(nova_check_many_v2(&in1, 1, NULL), "A8_NUM_EDGES case1 C reference accepts i64 + 1");
    Tree t1;
    int ok1 = parse(&t1, src1, 0);
    CHECK(ok1 == 1, "A8_NUM_EDGES case1 parse returned cleanly");
    if (ok1 == 1) {
        CHECK(t1.r.runtime == 0, "A8_NUM_EDGES case1 no runtime fault");
        CHECK(t1.code == 0, "A8_NUM_EDGES case1 candidate accepted");
        CHECK(t1.node_count > 0, "A8_NUM_EDGES case1 candidate published tree");
        uint64_t bin1 = 0;
        for (uint64_t i = 1; i <= t1.node_count; i++) {
            if (node_word(&t1, i, 0) == K_BINARY) { bin1 = i; break; }
        }
        CHECK(bin1 > 0, "A8_NUM_EDGES case1 found K_BINARY node");
        if (bin1 > 0) {
            CHECK(node_word(&t1, bin1, 9) == 64, "A8_NUM_EDGES case1 binary width 64");
            CHECK(node_word(&t1, bin1, 14) == 8, "A8_NUM_EDGES case1 binary type i64 (8)");
        }
        free_tree(&t1);
    }

    /* Case 2: ACCEPT bool comparison: n < 1 -> binary type 9, width 8 */
    cases++;
    const char *src2 = "module m2; struct R { x: bool } fn f(n: i64) -> R { return R{x: n < 1}; }";
    NtFInput in2 = { "m2.nova", src2, strlen(src2) };
    CHECK(nova_check_many_v2(&in2, 1, NULL), "A8_NUM_EDGES case2 C reference accepts i64 < 1");
    Tree t2;
    int ok2 = parse(&t2, src2, 0);
    CHECK(ok2 == 1, "A8_NUM_EDGES case2 parse returned cleanly");
    if (ok2 == 1) {
        CHECK(t2.r.runtime == 0, "A8_NUM_EDGES case2 no runtime fault");
        CHECK(t2.code == 0, "A8_NUM_EDGES case2 candidate accepted");
        CHECK(t2.node_count > 0, "A8_NUM_EDGES case2 candidate published tree");
        uint64_t bin2 = 0;
        for (uint64_t i = 1; i <= t2.node_count; i++) {
            if (node_word(&t2, i, 0) == K_BINARY) { bin2 = i; break; }
        }
        CHECK(bin2 > 0, "A8_NUM_EDGES case2 found K_BINARY node");
        if (bin2 > 0) {
            CHECK(node_word(&t2, bin2, 9) == 8, "A8_NUM_EDGES case2 binary width 8");
            CHECK(node_word(&t2, bin2, 14) == 9, "A8_NUM_EDGES case2 binary type bool (9)");
        }
        free_tree(&t2);
    }

    /* Case 3: ACCEPT i64 bitwise: n & 1 -> binary type 8, width 64 */
    cases++;
    const char *src3 = "module m3; struct R { x: i64 } fn f(n: i64) -> R { return R{x: n & 1}; }";
    NtFInput in3 = { "m3.nova", src3, strlen(src3) };
    CHECK(nova_check_many_v2(&in3, 1, NULL), "A8_NUM_EDGES case3 C reference accepts i64 & 1");
    Tree t3;
    int ok3 = parse(&t3, src3, 0);
    CHECK(ok3 == 1, "A8_NUM_EDGES case3 parse returned cleanly");
    if (ok3 == 1) {
        CHECK(t3.r.runtime == 0, "A8_NUM_EDGES case3 no runtime fault");
        CHECK(t3.code == 0, "A8_NUM_EDGES case3 candidate accepted");
        CHECK(t3.node_count > 0, "A8_NUM_EDGES case3 candidate published tree");
        uint64_t bin3 = 0;
        for (uint64_t i = 1; i <= t3.node_count; i++) {
            if (node_word(&t3, i, 0) == K_BINARY) { bin3 = i; break; }
        }
        CHECK(bin3 > 0, "A8_NUM_EDGES case3 found K_BINARY node");
        if (bin3 > 0) {
            CHECK(node_word(&t3, bin3, 9) == 64, "A8_NUM_EDGES case3 binary width 64");
            CHECK(node_word(&t3, bin3, 14) == 8, "A8_NUM_EDGES case3 binary type i64 (8)");
        }
        free_tree(&t3);
    }

    /* Case 4: ACCEPT u8 bitwise: 1 | 2 -> binary type 1, width 8 */
    cases++;
    const char *src4 = "module m4; struct R { x: u8 } fn f() -> R { return R{x: 1 | 2}; }";
    NtFInput in4 = { "m4.nova", src4, strlen(src4) };
    CHECK(nova_check_many_v2(&in4, 1, NULL), "A8_NUM_EDGES case4 C reference accepts 1 | 2 for u8");
    Tree t4;
    int ok4 = parse(&t4, src4, 0);
    CHECK(ok4 == 1, "A8_NUM_EDGES case4 parse returned cleanly");
    if (ok4 == 1) {
        CHECK(t4.r.runtime == 0, "A8_NUM_EDGES case4 no runtime fault");
        CHECK(t4.code == 0, "A8_NUM_EDGES case4 candidate accepted");
        CHECK(t4.node_count > 0, "A8_NUM_EDGES case4 candidate published tree");
        uint64_t bin4 = 0;
        for (uint64_t i = 1; i <= t4.node_count; i++) {
            if (node_word(&t4, i, 0) == K_BINARY) { bin4 = i; break; }
        }
        CHECK(bin4 > 0, "A8_NUM_EDGES case4 found K_BINARY node");
        if (bin4 > 0) {
            CHECK(node_word(&t4, bin4, 9) == 8, "A8_NUM_EDGES case4 binary width 8");
            CHECK(node_word(&t4, bin4, 14) == 1, "A8_NUM_EDGES case4 binary type u8 (1)");
        }
        free_tree(&t4);
    }

    /* Case 5: REJECT u64 + bool */
    cases++;
    const char *src5 = "module m5; struct R { x: u64 } fn f(n: u64) -> R { return R{x: n + true}; }";
    NtFInput in5 = { "m5.nova", src5, strlen(src5) };
    CHECK(!nova_check_many_v2(&in5, 1, NULL), "A8_NUM_EDGES case5 C reference rejects u64 + bool");
    Tree t5;
    int ok5 = parse(&t5, src5, 0);
    CHECK(ok5 == 1, "A8_NUM_EDGES case5 parse returned cleanly");
    if (ok5 == 1) {
        CHECK(t5.r.runtime == 0, "A8_NUM_EDGES case5 no runtime fault");
        CHECK(t5.code != 0, "A8_NUM_EDGES case5 candidate rejected");
        CHECK(t5.node_count == 0, "A8_NUM_EDGES case5 published empty tree");
        free_tree(&t5);
    }

    /* Case 6: REJECT i64 overflow literal: 9223372036854775808 */
    cases++;
    const char *src6 = "module m6; struct R { x: i64 } fn f() -> R { return R{x: 9223372036854775808}; }";
    NtFInput in6 = { "m6.nova", src6, strlen(src6) };
    CHECK(!nova_check_many_v2(&in6, 1, NULL), "A8_NUM_EDGES case6 C reference rejects 9223372036854775808 for i64");
    Tree t6;
    int ok6 = parse(&t6, src6, 0);
    CHECK(ok6 == 1, "A8_NUM_EDGES case6 parse returned cleanly");
    if (ok6 == 1) {
        CHECK(t6.r.runtime == 0, "A8_NUM_EDGES case6 no runtime fault");
        CHECK(t6.code != 0, "A8_NUM_EDGES case6 candidate rejected");
        CHECK(t6.node_count == 0, "A8_NUM_EDGES case6 published empty tree");
        free_tree(&t6);
    }

    /* Case 7: REJECT mixed variable arithmetic: i64 + u64 */
    cases++;
    const char *src7 = "module m7; struct R { x: i64 } fn f(a: i64, b: u64) -> R { return R{x: a + b}; }";
    NtFInput in7 = { "m7.nova", src7, strlen(src7) };
    CHECK(!nova_check_many_v2(&in7, 1, NULL), "A8_NUM_EDGES case7 C reference rejects i64 + u64 variable addition");
    Tree t7;
    int ok7 = parse(&t7, src7, 0);
    CHECK(ok7 == 1, "A8_NUM_EDGES case7 parse returned cleanly");
    if (ok7 == 1) {
        CHECK(t7.r.runtime == 0, "A8_NUM_EDGES case7 no runtime fault");
        CHECK(t7.code != 0, "A8_NUM_EDGES case7 candidate rejected");
        CHECK(t7.node_count == 0, "A8_NUM_EDGES case7 published empty tree");
        free_tree(&t7);
    }

    /* Case 8: REJECT non-constant shift narrowing to u8 */
    cases++;
    const char *src8 = "module m8; struct R { x: u8 } fn f(n: u64) -> R { return R{x: 1 << n}; }";
    NtFInput in8 = { "m8.nova", src8, strlen(src8) };
    CHECK(!nova_check_many_v2(&in8, 1, NULL), "A8_NUM_EDGES case8 C reference rejects 1 << n for u8");
    Tree t8;
    int ok8 = parse(&t8, src8, 0);
    CHECK(ok8 == 1, "A8_NUM_EDGES case8 parse returned cleanly");
    if (ok8 == 1) {
        CHECK(t8.r.runtime == 0, "A8_NUM_EDGES case8 no runtime fault");
        CHECK(t8.code != 0, "A8_NUM_EDGES case8 candidate rejected");
        CHECK(t8.node_count == 0, "A8_NUM_EDGES case8 published empty tree");
        free_tree(&t8);
    }

    /* Case 9: ACCEPT u64 variable arithmetic: a + b -> binary type 4, width 64 */
    cases++;
    const char *src9 = "module m9; struct R { x: u64 } fn f(a: u64, b: u64) -> R { return R{x: a + b}; }";
    NtFInput in9 = { "m9.nova", src9, strlen(src9) };
    CHECK(nova_check_many_v2(&in9, 1, NULL), "A8_NUM_EDGES case9 C reference accepts u64 + u64");
    Tree t9;
    int ok9 = parse(&t9, src9, 0);
    CHECK(ok9 == 1, "A8_NUM_EDGES case9 parse returned cleanly");
    if (ok9 == 1) {
        CHECK(t9.r.runtime == 0, "A8_NUM_EDGES case9 no runtime fault");
        CHECK(t9.code == 0, "A8_NUM_EDGES case9 candidate accepted");
        CHECK(t9.node_count > 0, "A8_NUM_EDGES case9 candidate published tree");
        uint64_t bin9 = 0;
        for (uint64_t i = 1; i <= t9.node_count; i++) {
            if (node_word(&t9, i, 0) == K_BINARY) { bin9 = i; break; }
        }
        CHECK(bin9 > 0, "A8_NUM_EDGES case9 found K_BINARY node");
        if (bin9 > 0) {
            CHECK(node_word(&t9, bin9, 9) == 64, "A8_NUM_EDGES case9 binary width 64");
            CHECK(node_word(&t9, bin9, 14) == 4, "A8_NUM_EDGES case9 binary type u64 (4)");
        }
        free_tree(&t9);
    }
}

static void test_a8_constructor_depth(void) {
    char *src_buf = (char *)malloc(32768);
    CHECK(src_buf != NULL, "A8_CTOR_DEPTH buffer allocation succeeded");
    if (!src_buf) return;

    int depths[2] = { 8, 130 };
    for (int d_idx = 0; d_idx < 2; d_idx++) {
        cases++;
        int depth = depths[d_idx];
        size_t off = 0;
        int n = snprintf(src_buf + off, 32768 - off, "module d%d;\n", depth);
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_CTOR_DEPTH source formatting failed"); free(src_buf); return; }
        off += (size_t)n;

        for (int i = 0; i < depth - 1; i++) {
            n = snprintf(src_buf + off, 32768 - off, "struct R%d { v: R%d }\n", i, i + 1);
            if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_CTOR_DEPTH source formatting failed"); free(src_buf); return; }
            off += (size_t)n;
        }
        n = snprintf(src_buf + off, 32768 - off, "struct R%d { v: u64 }\n", depth - 1);
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_CTOR_DEPTH source formatting failed"); free(src_buf); return; }
        off += (size_t)n;

        n = snprintf(src_buf + off, 32768 - off, "fn make() -> R0 { return ");
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_CTOR_DEPTH source formatting failed"); free(src_buf); return; }
        off += (size_t)n;

        for (int i = 0; i < depth - 1; i++) {
            n = snprintf(src_buf + off, 32768 - off, "R%d{v: ", i);
            if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_CTOR_DEPTH source formatting failed"); free(src_buf); return; }
            off += (size_t)n;
        }
        n = snprintf(src_buf + off, 32768 - off, "R%d{v: 42}", depth - 1);
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_CTOR_DEPTH source formatting failed"); free(src_buf); return; }
        off += (size_t)n;

        for (int i = 0; i < depth - 1; i++) {
            n = snprintf(src_buf + off, 32768 - off, "}");
            if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_CTOR_DEPTH source formatting failed"); free(src_buf); return; }
            off += (size_t)n;
        }
        n = snprintf(src_buf + off, 32768 - off, "; }\n");
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_CTOR_DEPTH source formatting failed"); free(src_buf); return; }
        off += (size_t)n;

        NtFInput in = { "depth.nova", src_buf, off };
        if (depth == 8) {
            CHECK(nova_check_many_v2(&in, 1, NULL), "A8_CTOR_DEPTH C reference accepts depth 8");
            Tree t;
            int ok = parse(&t, src_buf, 0);
            CHECK(ok == 1, "A8_CTOR_DEPTH parse(8) returned cleanly");
            if (ok == 1) {
                CHECK(t.r.runtime == 0, "A8_CTOR_DEPTH candidate 8 no runtime fault");
                CHECK(t.code == 0, "A8_CTOR_DEPTH candidate 8 accepted");
                CHECK(t.node_count > 0, "A8_CTOR_DEPTH candidate 8 published tree");
                free_tree(&t);
            }
        } else {
            CHECK(!nova_check_many_v2(&in, 1, NULL), "A8_CTOR_DEPTH C reference refuses depth 130");
            Tree t;
            int ok = parse(&t, src_buf, 0);
            CHECK(ok == 1, "A8_CTOR_DEPTH parse(130) returned cleanly");
            if (ok == 1) {
                CHECK(t.r.runtime == 0, "A8_CTOR_DEPTH candidate 130 no runtime fault");
                CHECK(t.code == 812, "A8_CTOR_DEPTH candidate 130 rejected with E_TOO_SMALL (812)");
                const char *depth_at = strstr(src_buf, "R128{v:");
                CHECK(depth_at != NULL, "A8_CTOR_DEPTH candidate 130 found R128 constructor anchor");
                if (depth_at != NULL) {
                    CHECK(t.start == (uint64_t)(depth_at - src_buf), "A8_CTOR_DEPTH candidate 130 error start matches 129th constructor token");
                }
                CHECK(t.node_count == 0, "A8_CTOR_DEPTH candidate 130 published empty tree");
                free_tree(&t);
            }
        }
    }
    free(src_buf);

    /* Case 3: Empty struct constructor */
    cases++;
    const char *src_empty = "module m_empty; struct E {} fn make() -> E { return E{}; }";
    NtFInput in_empty = { "empty.nova", src_empty, strlen(src_empty) };
    CHECK(nova_check_many_v2(&in_empty, 1, NULL), "A8_CTOR_DEPTH C reference accepts empty struct constructor");
    Tree t_empty;
    int ok_empty = parse(&t_empty, src_empty, 0);
    CHECK(ok_empty == 1, "A8_CTOR_DEPTH parse(empty) returned cleanly");
    if (ok_empty == 1) {
        CHECK(t_empty.r.runtime == 0, "A8_CTOR_DEPTH candidate empty struct no runtime fault");
        CHECK(t_empty.code == 0, "A8_CTOR_DEPTH candidate empty struct accepted");
        CHECK(t_empty.node_count > 0, "A8_CTOR_DEPTH candidate empty struct published tree");
        free_tree(&t_empty);
    }

    /* Case 4: Clean replay of standard PROGRAM after deep refusal */
    cases++;
    Tree t_clean;
    int ok_clean = parse(&t_clean, PROGRAM, 0);
    CHECK(ok_clean == 1, "A8_CTOR_DEPTH clean replay parse returned cleanly");
    if (ok_clean == 1) {
        CHECK(t_clean.r.runtime == 0, "A8_CTOR_DEPTH clean replay no runtime fault");
        CHECK(t_clean.code == 0, "A8_CTOR_DEPTH clean replay succeeds");
        CHECK(t_clean.node_count > 0, "A8_CTOR_DEPTH clean replay published tree");
        free_tree(&t_clean);
    }
}

static void test_a8_function_calls(void) {
    /* Probe mode 3 shape for K_CALL node kind */
    Tree shape;
    int shape_ok = parse(&shape, "", 3);
    CHECK(shape_ok == 1, "A8_CALLS shape query returned cleanly");
    if (shape_ok != 1) return;
    CHECK(shape.r.runtime == 0, "A8_CALLS shape query no runtime fault");
    uint64_t K_CALL = shape.out[29];
    CHECK(K_CALL > 0, "A8_CALLS K_CALL node kind discovered");
    free_tree(&shape);

    /* Positive 1: Forward call with full argument binary expression */
    cases++;
    const char *src_p1 = "module p1; fn run() -> u64 { return later(1 + 2); } fn later(x: u64) -> u64 { return x; }";
    NtFInput in_p1 = { "p1.nova", src_p1, strlen(src_p1) };
    CHECK(nova_check_many_v2(&in_p1, 1, NULL), "A8_CALLS p1 C reference accepts forward call");
    Tree t1;
    int ok1 = parse(&t1, src_p1, 0);
    CHECK(ok1 == 1, "A8_CALLS p1 parse returned cleanly");
    if (ok1 == 1) {
        CHECK(t1.r.runtime == 0, "A8_CALLS p1 no runtime fault");
        CHECK(t1.code == 0, "A8_CALLS p1 candidate accepted");
        CHECK(t1.node_count > 0, "A8_CALLS p1 candidate published tree");
        uint64_t call1 = 0, fn_later = 0;
        for (uint64_t i = 1; i <= t1.node_count; i++) {
            if (node_word(&t1, i, 0) == K_CALL) call1 = i;
            if (node_word(&t1, i, 0) == K_FN) {
                uint64_t s = node_word(&t1, i, 5), e = node_word(&t1, i, 6);
                if (s <= e && e <= strlen(src_p1) && (e - s == 5) && !memcmp(src_p1 + s, "later", 5)) {
                    fn_later = i;
                }
            }
        }
        CHECK(call1 > 0, "A8_CALLS p1 found K_CALL node");
        CHECK(fn_later > 0, "A8_CALLS p1 found K_FN later node");
        if (call1 > 0 && fn_later > 0) {
            uint64_t c_fn_id = node_word(&t1, call1, 15);
            uint64_t l_fn_id = node_word(&t1, fn_later, 15);
            CHECK(c_fn_id > 0, "A8_CALLS p1 K_CALL word 15 nonzero");
            CHECK(l_fn_id > 0, "A8_CALLS p1 K_FN later word 15 nonzero");
            CHECK(c_fn_id == l_fn_id, "A8_CALLS p1 K_CALL word 15 matches K_FN identity");
            CHECK(node_word(&t1, fn_later, 14) == 4, "A8_CALLS p1 K_FN later return type u64 (4)");
            CHECK(node_word(&t1, call1, 14) == 4, "A8_CALLS p1 K_CALL word 14 return type u64 (4)");
            CHECK(node_word(&t1, call1, 9) == 64, "A8_CALLS p1 K_CALL width 64");
            CHECK(node_word(&t1, call1, 10) == REG_VALUE, "A8_CALLS p1 K_CALL REG_VALUE");
            uint64_t cs = node_word(&t1, call1, 5), ce = node_word(&t1, call1, 6);
            CHECK(cs <= ce && ce <= strlen(src_p1) && (ce - cs == 5) && !memcmp(src_p1 + cs, "later", 5), "A8_CALLS p1 call name span exactly 'later'");
            uint64_t arg1 = node_word(&t1, call1, 2);
            CHECK(arg1 > 0 && node_word(&t1, arg1, 0) == K_BINARY, "A8_CALLS p1 argument is K_BINARY");
            if (arg1 > 0) {
                CHECK(node_word(&t1, arg1, 4) == 0, "A8_CALLS p1 exactly one argument");
            }
        }
        for (uint64_t i = 1; i <= t1.node_count; i++) {
            if (node_word(&t1, i, 0) == K_FN) {
                uint64_t id_i = node_word(&t1, i, 15);
                CHECK(id_i > 0, "A8_CALLS p1 K_FN identity nonzero");
                for (uint64_t j = i + 1; j <= t1.node_count; j++) {
                    if (node_word(&t1, j, 0) == K_FN) {
                        CHECK(id_i != node_word(&t1, j, 15), "A8_CALLS p1 K_FN identities distinct");
                    }
                }
            }
        }
        free_tree(&t1);
    }

    /* Positive 2: Call returning bool in if-condition inside u64 function */
    cases++;
    const char *src_p2 = "module p2; fn yes() -> bool { return true; } fn run() -> u64 { if yes() { return 1; } return 0; }";
    NtFInput in_p2 = { "p2.nova", src_p2, strlen(src_p2) };
    CHECK(nova_check_many_v2(&in_p2, 1, NULL), "A8_CALLS p2 C reference accepts bool callee");
    Tree t2;
    int ok2 = parse(&t2, src_p2, 0);
    CHECK(ok2 == 1, "A8_CALLS p2 parse returned cleanly");
    if (ok2 == 1) {
        CHECK(t2.r.runtime == 0, "A8_CALLS p2 no runtime fault");
        CHECK(t2.code == 0, "A8_CALLS p2 candidate accepted");
        CHECK(t2.node_count > 0, "A8_CALLS p2 candidate published tree");
        uint64_t call2 = 0;
        for (uint64_t i = 1; i <= t2.node_count; i++) {
            if (node_word(&t2, i, 0) == K_CALL) { call2 = i; break; }
        }
        CHECK(call2 > 0, "A8_CALLS p2 found K_CALL node");
        if (call2 > 0) {
            CHECK(node_word(&t2, call2, 14) == 9, "A8_CALLS p2 K_CALL type bool (9)");
            CHECK(node_word(&t2, call2, 9) == 8, "A8_CALLS p2 K_CALL width 8");
            CHECK(node_word(&t2, call2, 10) == REG_PREDICATE, "A8_CALLS p2 K_CALL REG_PREDICATE");
        }
        free_tree(&t2);
    }

    /* Positive 3: Direct recursion */
    cases++;
    const char *src_p3 = "module p3; fn rec(n: u64) -> u64 { if n == 0 { return 0; } return rec(n - 1); }";
    NtFInput in_p3 = { "p3.nova", src_p3, strlen(src_p3) };
    CHECK(nova_check_many_v2(&in_p3, 1, NULL), "A8_CALLS p3 C reference accepts recursion");
    Tree t3;
    int ok3 = parse(&t3, src_p3, 0);
    CHECK(ok3 == 1, "A8_CALLS p3 parse returned cleanly");
    if (ok3 == 1) {
        CHECK(t3.r.runtime == 0, "A8_CALLS p3 no runtime fault");
        CHECK(t3.code == 0, "A8_CALLS p3 candidate accepted");
        CHECK(t3.node_count > 0, "A8_CALLS p3 candidate published tree");
        uint64_t call3 = 0, fn_rec = 0;
        for (uint64_t i = 1; i <= t3.node_count; i++) {
            if (node_word(&t3, i, 0) == K_CALL) call3 = i;
            if (node_word(&t3, i, 0) == K_FN) fn_rec = i;
        }
        CHECK(call3 > 0 && fn_rec > 0, "A8_CALLS p3 found recursive K_CALL and K_FN");
        if (call3 > 0 && fn_rec > 0) {
            uint64_t r_call_id = node_word(&t3, call3, 15);
            uint64_t r_fn_id = node_word(&t3, fn_rec, 15);
            CHECK(r_call_id > 0, "A8_CALLS p3 recursive call id nonzero");
            CHECK(r_call_id == r_fn_id, "A8_CALLS p3 recursive call matches fn identity");
        }
        free_tree(&t3);
    }

    /* Positive 4: Nested calls */
    cases++;
    const char *src_p4 = "module p4; fn id(x: u64) -> u64 { return x; } fn run() -> u64 { return id(id(1) + 2); }";
    NtFInput in_p4 = { "p4.nova", src_p4, strlen(src_p4) };
    CHECK(nova_check_many_v2(&in_p4, 1, NULL), "A8_CALLS p4 C reference accepts nested calls");
    Tree t4;
    int ok4 = parse(&t4, src_p4, 0);
    CHECK(ok4 == 1, "A8_CALLS p4 parse returned cleanly");
    if (ok4 == 1) {
        CHECK(t4.r.runtime == 0, "A8_CALLS p4 no runtime fault");
        CHECK(t4.code == 0, "A8_CALLS p4 candidate accepted");
        CHECK(t4.node_count > 0, "A8_CALLS p4 candidate published tree");
        uint64_t call_count = 0;
        for (uint64_t i = 1; i <= t4.node_count; i++) {
            if (node_word(&t4, i, 0) == K_CALL) call_count++;
        }
        CHECK(call_count == 2, "A8_CALLS p4 found exactly two K_CALL nodes");
        free_tree(&t4);
    }

    /* Positive 5: Call returning record accessed via .field */
    cases++;
    const char *src_p5 = "module p5; struct R { x: u64 } fn id(r: R) -> R { return r; } fn run(r: R) -> u64 { return id(r).x; }";
    NtFInput in_p5 = { "p5.nova", src_p5, strlen(src_p5) };
    CHECK(nova_check_many_v2(&in_p5, 1, NULL), "A8_CALLS p5 C reference accepts call returning record");
    Tree t5;
    int ok5 = parse(&t5, src_p5, 0);
    CHECK(ok5 == 1, "A8_CALLS p5 parse returned cleanly");
    if (ok5 == 1) {
        CHECK(t5.r.runtime == 0, "A8_CALLS p5 no runtime fault");
        CHECK(t5.code == 0, "A8_CALLS p5 candidate accepted");
        CHECK(t5.node_count > 0, "A8_CALLS p5 candidate published tree");
        uint64_t call5 = 0;
        for (uint64_t i = 1; i <= t5.node_count; i++) {
            if (node_word(&t5, i, 0) == K_CALL) { call5 = i; break; }
        }
        CHECK(call5 > 0, "A8_CALLS p5 found K_CALL node");
        if (call5 > 0) {
            CHECK(node_word(&t5, call5, 14) > 12, "A8_CALLS p5 K_CALL return type is record (>12)");
            CHECK(node_word(&t5, call5, 9) == 64, "A8_CALLS p5 K_CALL width 64");
            CHECK(node_word(&t5, call5, 10) == REG_ADDRESS, "A8_CALLS p5 K_CALL REG_ADDRESS");
        }
        free_tree(&t5);
    }

    /* Positive 6: Buffer parameter passed as single argument */
    cases++;
    const char *src_p6 = "module p6; fn lenlike(b: buf<u8>) -> u64 { return 1; } fn run(b: buf<u8>) -> u64 { return lenlike(b); }";
    NtFInput in_p6 = { "p6.nova", src_p6, strlen(src_p6) };
    CHECK(nova_check_many_v2(&in_p6, 1, NULL), "A8_CALLS p6 C reference accepts buffer argument");
    Tree t6;
    int ok6 = parse(&t6, src_p6, 0);
    CHECK(ok6 == 1, "A8_CALLS p6 parse returned cleanly");
    if (ok6 == 1) {
        CHECK(t6.r.runtime == 0, "A8_CALLS p6 no runtime fault");
        CHECK(t6.code == 0, "A8_CALLS p6 candidate accepted");
        CHECK(t6.node_count > 0, "A8_CALLS p6 candidate published tree");
        uint64_t call6 = 0;
        for (uint64_t i = 1; i <= t6.node_count; i++) {
            if (node_word(&t6, i, 0) == K_CALL) { call6 = i; break; }
        }
        CHECK(call6 > 0, "A8_CALLS p6 found K_CALL node");
        if (call6 > 0) {
            uint64_t a1 = node_word(&t6, call6, 2);
            CHECK(a1 > 0, "A8_CALLS p6 call has argument");
            CHECK(node_word(&t6, a1, 4) == 0, "A8_CALLS p6 exactly one logical argument node");
        }
        free_tree(&t6);
    }

    /* Positive 7: Trailing comma in call arguments */
    cases++;
    const char *src_p7 = "module p7; fn sum(a: u64, b: u64) -> u64 { return a + b; } fn run() -> u64 { return sum(1, 2,); }";
    NtFInput in_p7 = { "p7.nova", src_p7, strlen(src_p7) };
    CHECK(nova_check_many_v2(&in_p7, 1, NULL), "A8_CALLS p7 C reference accepts trailing comma in call");
    Tree t7;
    int ok7 = parse(&t7, src_p7, 0);
    CHECK(ok7 == 1, "A8_CALLS p7 parse returned cleanly");
    if (ok7 == 1) {
        CHECK(t7.r.runtime == 0, "A8_CALLS p7 no runtime fault");
        CHECK(t7.code == 0, "A8_CALLS p7 candidate accepted");
        CHECK(t7.node_count > 0, "A8_CALLS p7 candidate published tree");
        free_tree(&t7);
    }

    /* Negative test cases table */
    const char *neg_srcs[] = {
        /* 0: unknown callee */
        "module n0; fn run() -> u64 { return missing(1); }",
        /* 1: too few arguments */
        "module n1; fn f(a: u64, b: u64) -> u64 { return a + b; } fn run() -> u64 { return f(1); }",
        /* 2: too many arguments */
        "module n2; fn f(a: u64) -> u64 { return a; } fn run() -> u64 { return f(1, 2); }",
        /* 3: bool for u64 argument */
        "module n3; fn f(a: u64) -> u64 { return a; } fn run() -> u64 { return f(true); }",
        /* 4: wrong record type argument */
        "module n4; struct A { x: u64 } struct B { x: u64 } fn f(a: A) -> u64 { return a.x; } fn run(b: B) -> u64 { return f(b); }",
        /* 5: scalar variable called as function */
        "module n5; fn run(x: u64) -> u64 { return x(1); }",
        /* 6: duplicate function name */
        "module n6; fn f() -> u64 { return 1; } fn f() -> u64 { return 2; }",
        /* 7: malformed closing delimiter */
        "module n7; fn f(x: u64) -> u64 { return x; } fn run() -> u64 { return f(1}; }",
        /* 8: non-constant u64 to u8 narrowing in argument */
        "module n8; fn f(x: u8) -> u8 { return x; } fn run(n: u64) -> u8 { return f(n); }"
    };
    const char *neg_descs[] = {
        "unknown callee refused",
        "too few arguments refused",
        "too many arguments refused",
        "bool for u64 argument refused",
        "wrong record type argument refused",
        "scalar variable called as function refused",
        "duplicate function name refused",
        "malformed closing delimiter refused",
        "non-constant u64 to u8 narrowing refused"
    };
    int num_negs = (int)(sizeof(neg_srcs) / sizeof(neg_srcs[0]));
    for (int i = 0; i < num_negs; i++) {
        cases++;
        NtFInput in_neg = { "neg.nova", neg_srcs[i], strlen(neg_srcs[i]) };
        CHECK(!nova_check_many_v2(&in_neg, 1, NULL), neg_descs[i]);
        Tree t_neg;
        int ok_neg = parse(&t_neg, neg_srcs[i], 0);
        CHECK(ok_neg == 1, "A8_CALLS negative parse returned cleanly");
        if (ok_neg == 1) {
            CHECK(t_neg.r.runtime == 0, "A8_CALLS negative no runtime fault");
            CHECK(t_neg.code != 0, "A8_CALLS negative candidate refused");
            CHECK(t_neg.node_count == 0, "A8_CALLS negative published empty tree");
            free_tree(&t_neg);
        }
    }

    /* Positive 8: Buffer return type identity across call and return nodes */
    cases++;
    const char *src_p8 = "module p8; fn id(b: buf<u8>) -> buf<u8> { return b; } fn run(b: buf<u8>) -> buf<u8> { return id(b); }";
    NtFInput in_p8 = { "p8.nova", src_p8, strlen(src_p8) };
    CHECK(nova_check_many_v2(&in_p8, 1, NULL), "A8_CALLS p8 C reference accepts buffer return");
    Tree t8;
    int ok8 = parse(&t8, src_p8, 0);
    CHECK(ok8 == 1, "A8_CALLS p8 parse returned cleanly");
    if (ok8 == 1) {
        CHECK(t8.r.runtime == 0, "A8_CALLS p8 no runtime fault");
        CHECK(t8.code == 0, "A8_CALLS p8 candidate accepted");
        CHECK(t8.node_count > 0, "A8_CALLS p8 candidate published tree");
        uint64_t call8 = 0;
        for (uint64_t i = 1; i <= t8.node_count; i++) {
            if (node_word(&t8, i, 0) == K_CALL) { call8 = i; break; }
        }
        CHECK(call8 > 0, "A8_CALLS p8 found K_CALL node");
        if (call8 > 0) {
            CHECK(node_word(&t8, call8, 14) == 10, "A8_CALLS p8 K_CALL return type T_BUF_U8 (10)");
            CHECK(node_word(&t8, call8, 9) == 64, "A8_CALLS p8 K_CALL width 64");
            CHECK(node_word(&t8, call8, 10) == REG_ADDRESS, "A8_CALLS p8 K_CALL REG_ADDRESS");
        }
        for (uint64_t i = 1; i <= t8.node_count; i++) {
            if (node_word(&t8, i, 0) == K_RETURN_NODE) {
                CHECK(node_word(&t8, i, 14) == 10, "A8_CALLS p8 K_RETURN node word 14 carries T_BUF_U8 (10)");
            }
        }
        free_tree(&t8);
    }

    /* Clean replay of standard PROGRAM */
    cases++;
    Tree t_clean;
    int ok_clean = parse(&t_clean, PROGRAM, 0);
    CHECK(ok_clean == 1, "A8_CALLS clean replay parse returned cleanly");
    if (ok_clean == 1) {
        CHECK(t_clean.r.runtime == 0, "A8_CALLS clean replay no runtime fault");
        CHECK(t_clean.code == 0, "A8_CALLS clean replay succeeds");
        CHECK(t_clean.node_count > 0, "A8_CALLS clean replay published tree");
        free_tree(&t_clean);
    }
}

static void test_a8_signature_limits(void) {
    char *src_buf = (char *)malloc(32768);
    CHECK(src_buf != NULL, "A8_SIG_LIMITS buffer allocation succeeded");
    if (!src_buf) return;

    /* A) Parameter boundaries: 64 u64 accepted / 65 u64 refused; 32 buf<u8> accepted / 33 buf<u8> refused */
    struct {
        int count;
        const char *ty;
        int expect_ok;
    } param_cases[] = {
        { 64, "u64", 1 },
        { 65, "u64", 0 },
        { 32, "buf<u8>", 1 },
        { 33, "buf<u8>", 0 }
    };
    for (int p_idx = 0; p_idx < 4; p_idx++) {
        cases++;
        int count = param_cases[p_idx].count;
        const char *ty = param_cases[p_idx].ty;
        int expect_ok = param_cases[p_idx].expect_ok;

        size_t off = 0;
        int n = snprintf(src_buf + off, 32768 - off, "module p_lim;\nfn f(");
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_SIG_LIMITS param formatting failed"); free(src_buf); return; }
        off += (size_t)n;

        for (int i = 0; i < count; i++) {
            n = snprintf(src_buf + off, 32768 - off, "%sp%d: %s", (i > 0 ? ", " : ""), i, ty);
            if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_SIG_LIMITS param formatting failed"); free(src_buf); return; }
            off += (size_t)n;
        }
        n = snprintf(src_buf + off, 32768 - off, ") -> u64 { return 1; }\n");
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_SIG_LIMITS param formatting failed"); free(src_buf); return; }
        off += (size_t)n;

        NtFInput in = { "plim.nova", src_buf, off };
        if (expect_ok) {
            CHECK(nova_check_many_v2(&in, 1, NULL), "A8_SIG_LIMITS C reference accepts parameter boundary");
            Tree t;
            int ok = parse(&t, src_buf, 0);
            CHECK(ok == 1, "A8_SIG_LIMITS parse returned cleanly");
            if (ok == 1) {
                CHECK(t.r.runtime == 0, "A8_SIG_LIMITS candidate no runtime fault on valid params");
                CHECK(t.code == 0, "A8_SIG_LIMITS candidate accepted valid parameter count");
                CHECK(t.node_count > 0, "A8_SIG_LIMITS candidate published tree");
                free_tree(&t);
            }
        } else {
            CHECK(!nova_check_many_v2(&in, 1, NULL), "A8_SIG_LIMITS C reference rejects ABI overflow params");
            Tree t;
            int ok = parse(&t, src_buf, 0);
            CHECK(ok == 1, "A8_SIG_LIMITS parse returned cleanly");
            if (ok == 1) {
                CHECK(t.r.runtime == 0, "A8_SIG_LIMITS candidate no runtime fault on ABI overflow params");
                CHECK(t.code != 0, "A8_SIG_LIMITS candidate rejected ABI slot overflow");
                CHECK(t.node_count == 0, "A8_SIG_LIMITS candidate published empty tree on ABI overflow");
                free_tree(&t);
            }
        }
    }

    /* B) Binds capacity probes: custom entry with exact binds cap */
    CHECK(g_image != NULL, "A8_SIG_LIMITS g_image host image pointer available");
    if (g_image != NULL) {
        struct {
            const char *src;
            uint64_t cap;
            int expect_ok;
        } bind_probes[] = {
            { "module cap1; fn f() -> u64 { return 1; }", 4, 0 },
            { "module cap1; fn f() -> u64 { return 1; }", 5, 1 },
            { "module cap2; fn f() -> u64 { let x: u64 = 1; return x; }", 10, 0 },
            { "module cap2; fn f() -> u64 { let x: u64 = 1; return x; }", 11, 1 }
        };
        for (int b_idx = 0; b_idx < 4; b_idx++) {
            cases++;
            const char *src = bind_probes[b_idx].src;
            uint64_t cap = bind_probes[b_idx].cap;
            int expect_ok = bind_probes[b_idx].expect_ok;

            NtFInput in = { "cap.nova", src, strlen(src) };
            CHECK(nova_check_many_v2(&in, 1, NULL), "A8_SIG_LIMITS C reference accepts bind probe source");

            uint64_t *scratch = (uint64_t *)malloc(WORDS * sizeof(uint64_t));
            CHECK(scratch != NULL, "A8_SIG_LIMITS scratch allocated");
            if (scratch) {
                for (size_t i = 0; i < WORDS; i++) scratch[i] = GUARD;

                NovaContextV2 ctx = {0};
                int c_ok = nova_context_init_v2(&ctx);
                CHECK(c_ok == 1, "A8_SIG_LIMITS context initialized");
                if (c_ok == 1) {
                    size_t slen = strlen(src);
                    uint64_t sh = nova_borrow_v2(&ctx, (void *)src, slen, 0);
                    uint64_t n1 = nova_borrow_v2(&ctx, scratch + 0, NODES * 8, 1);
                    uint64_t n2 = nova_borrow_v2(&ctx, scratch + NODES, SIDES * 8, 1);
                    uint64_t n3 = nova_borrow_v2(&ctx, scratch + NODES + SIDES, cap * 8, 1);
                    uint64_t n4 = nova_borrow_v2(&ctx, scratch + NODES + SIDES + BINDS, FIELDS * 8, 1);
                    uint64_t oh = nova_borrow_v2(&ctx, scratch + NODES + SIDES + BINDS + FIELDS, OUTW * 8, 1);

                    uint64_t args[SLOTS] = { sh, (uint64_t)slen, n1, NODES, n2, SIDES, n3, cap, n4, FIELDS, oh, OUTW, 0 };
                    g_image->entry(&ctx, args, SLOTS);
                    CHECK(ctx.error == 0, "A8_SIG_LIMITS context execution finished cleanly");

                    uint64_t *out = scratch + NODES + SIDES + BINDS + FIELDS;
                    if (expect_ok) {
                        CHECK(out[0] == 0, "A8_SIG_LIMITS exact binds cap accepted");
                        CHECK(out[5] > 0, "A8_SIG_LIMITS published node_count > 0");
                    } else {
                        CHECK(out[0] == 812, "A8_SIG_LIMITS insufficient binds rejected with E_TOO_SMALL (812)");
                        CHECK(out[5] == 0, "A8_SIG_LIMITS published node_count == 0");
                    }
                    int guards_intact = 1;
                    for (size_t g = NODES + SIDES + cap; g < NODES + SIDES + BINDS; g++) {
                        if (scratch[g] != GUARD) { guards_intact = 0; break; }
                    }
                    CHECK(guards_intact, "A8_SIG_LIMITS guard words beyond cap untouched");
                    CHECK(nova_context_destroy_v2(&ctx), "A8_SIG_LIMITS context cleanup succeeded");
                }
                free(scratch);
            }
        }
    }

    /* C) Runtime pass-through */
    cases++;
    const char *src_rt_pos = "module rt_pos; fn take(r: runtime) -> u64 { return 1; } fn run(r: runtime) -> u64 { return take(r); }";
    NtFInput in_rt_pos = { "rt_pos.nova", src_rt_pos, strlen(src_rt_pos) };
    CHECK(nova_check_many_v2(&in_rt_pos, 1, NULL), "A8_SIG_LIMITS C reference accepts runtime pass-through");
    Tree t_rt_pos;
    int ok_rt_pos = parse(&t_rt_pos, src_rt_pos, 0);
    CHECK(ok_rt_pos == 1, "A8_SIG_LIMITS parse returned cleanly");
    if (ok_rt_pos == 1) {
        CHECK(t_rt_pos.r.runtime == 0, "A8_SIG_LIMITS candidate no runtime fault on runtime pass-through");
        CHECK(t_rt_pos.code == 0, "A8_SIG_LIMITS candidate accepts runtime pass-through");
        CHECK(t_rt_pos.node_count > 0, "A8_SIG_LIMITS candidate published tree on runtime pass-through");
        free_tree(&t_rt_pos);
    }

    cases++;
    const char *src_rt_neg = "module rt_neg; fn take(r: runtime) -> u64 { return 1; } fn run() -> u64 { return take(1); }";
    NtFInput in_rt_neg = { "rt_neg.nova", src_rt_neg, strlen(src_rt_neg) };
    CHECK(!nova_check_many_v2(&in_rt_neg, 1, NULL), "A8_SIG_LIMITS C reference rejects scalar 1 passed to runtime");
    Tree t_rt_neg;
    int ok_rt_neg = parse(&t_rt_neg, src_rt_neg, 0);
    CHECK(ok_rt_neg == 1, "A8_SIG_LIMITS parse returned cleanly");
    if (ok_rt_neg == 1) {
        CHECK(t_rt_neg.r.runtime == 0, "A8_SIG_LIMITS candidate no runtime fault on invalid runtime arg");
        CHECK(t_rt_neg.code != 0, "A8_SIG_LIMITS candidate rejects scalar 1 for runtime");
        CHECK(t_rt_neg.node_count == 0, "A8_SIG_LIMITS candidate published empty tree on invalid runtime arg");
        free_tree(&t_rt_neg);
    }

    /* D) Duplicate parameters in function signature */
    cases++;
    const char *src_dup_p = "module dup_p; fn f(x: u64, x: u64) -> u64 { return x; }";
    NtFInput in_dup_p = { "dup_p.nova", src_dup_p, strlen(src_dup_p) };
    CHECK(!nova_check_many_v2(&in_dup_p, 1, NULL), "A8_SIG_LIMITS C reference rejects duplicate parameter name");
    Tree t_dup_p;
    int ok_dup_p = parse(&t_dup_p, src_dup_p, 0);
    CHECK(ok_dup_p == 1, "A8_SIG_LIMITS parse returned cleanly");
    if (ok_dup_p == 1) {
        CHECK(t_dup_p.r.runtime == 0, "A8_SIG_LIMITS candidate no runtime fault on duplicate params");
        CHECK(t_dup_p.code != 0, "A8_SIG_LIMITS candidate rejects duplicate parameter names");
        CHECK(t_dup_p.node_count == 0, "A8_SIG_LIMITS candidate published empty tree on duplicate params");
        free_tree(&t_dup_p);
    }

    /* E) Nested call depth guard: 8 accepted, 130 rejected with E_TOO_SMALL (812) */
    int call_depths[2] = { 8, 130 };
    for (int cd_idx = 0; cd_idx < 2; cd_idx++) {
        cases++;
        int depth = call_depths[cd_idx];
        size_t off = 0;
        int n = snprintf(src_buf + off, 32768 - off, "module cd%d;\nfn id(x: u64) -> u64 { return x; }\nfn run() -> u64 { return ", depth);
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_SIG_LIMITS call depth formatting failed"); free(src_buf); return; }
        off += (size_t)n;

        for (int i = 0; i < depth; i++) {
            n = snprintf(src_buf + off, 32768 - off, "id(");
            if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_SIG_LIMITS call depth formatting failed"); free(src_buf); return; }
            off += (size_t)n;
        }
        n = snprintf(src_buf + off, 32768 - off, "1");
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_SIG_LIMITS call depth formatting failed"); free(src_buf); return; }
        off += (size_t)n;

        for (int i = 0; i < depth; i++) {
            n = snprintf(src_buf + off, 32768 - off, ")");
            if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_SIG_LIMITS call depth formatting failed"); free(src_buf); return; }
            off += (size_t)n;
        }
        n = snprintf(src_buf + off, 32768 - off, "; }\n");
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_SIG_LIMITS call depth formatting failed"); free(src_buf); return; }
        off += (size_t)n;

        NtFInput in = { "cd.nova", src_buf, off };
        if (depth == 8) {
            CHECK(nova_check_many_v2(&in, 1, NULL), "A8_SIG_LIMITS C reference accepts call depth 8");
            Tree t;
            int ok = parse(&t, src_buf, 0);
            CHECK(ok == 1, "A8_SIG_LIMITS parse returned cleanly");
            if (ok == 1) {
                CHECK(t.r.runtime == 0, "A8_SIG_LIMITS candidate no runtime fault on call depth 8");
                CHECK(t.code == 0, "A8_SIG_LIMITS candidate accepts call depth 8");
                CHECK(t.node_count > 0, "A8_SIG_LIMITS candidate published tree on call depth 8");
                free_tree(&t);
            }
        } else {
            CHECK(!nova_check_many_v2(&in, 1, NULL), "A8_SIG_LIMITS C reference rejects call depth 130");
            Tree t;
            int ok = parse(&t, src_buf, 0);
            CHECK(ok == 1, "A8_SIG_LIMITS parse returned cleanly");
            if (ok == 1) {
                CHECK(t.r.runtime == 0, "A8_SIG_LIMITS candidate no runtime fault on call depth 130");
                CHECK(t.code == 812, "A8_SIG_LIMITS candidate rejected call depth with E_TOO_SMALL (812)");
                CHECK(t.node_count == 0, "A8_SIG_LIMITS candidate published empty tree on call depth 130");
                free_tree(&t);
            }
        }
    }
    free(src_buf);

    /* F) Clean replay of standard PROGRAM */
    cases++;
    Tree t_clean;
    int ok_clean = parse(&t_clean, PROGRAM, 0);
    CHECK(ok_clean == 1, "A8_SIG_LIMITS clean replay parse returned cleanly");
    if (ok_clean == 1) {
        CHECK(t_clean.r.runtime == 0, "A8_SIG_LIMITS clean replay no runtime fault");
        CHECK(t_clean.code == 0, "A8_SIG_LIMITS clean replay succeeds");
        CHECK(t_clean.node_count > 0, "A8_SIG_LIMITS clean replay published tree");
        free_tree(&t_clean);
    }
}

static unsigned audit_nova_sources(const char *list_path) {
    if (!list_path || !g_image) return 1;
    FILE *f = fopen(list_path, "r");
    if (!f) {
        fprintf(stderr, "NOVA_SELF_AUDIT cannot open list file: %s\n", list_path);
        return 1;
    }

    const size_t AUDIT_NODES = 1048576;
    const size_t AUDIT_SCOPES = 131072;
    const size_t AUDIT_BINDS = 262144;
    const size_t AUDIT_FIELDS = 65536;
    const size_t AUDIT_OUT = 256;
    const size_t AUDIT_TOTAL = AUDIT_NODES + AUDIT_SCOPES + AUDIT_BINDS + AUDIT_FIELDS + AUDIT_OUT;

    uint64_t *scratch = (uint64_t *)calloc(AUDIT_TOTAL, sizeof(uint64_t));
    if (!scratch) {
        fclose(f);
        fprintf(stderr, "NOVA_SELF_AUDIT scratch allocation failed\n");
        return 1;
    }

    char line[1024];
    unsigned files = 0, parsed = 0, refused = 0, runtime_errors = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] != '\n' && !feof(f)) {
            fprintf(stderr, "NOVA_SELF_AUDIT path line truncated\n");
            runtime_errors++;
            break;
        }
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;

        files++;
        size_t src_len = 0;
        char *src = loadf(line, &src_len);
        if (!src) {
            fprintf(stderr, "NOVA_SELF_AUDIT unreadable file: %s\n", line);
            refused++;
            continue;
        }

        memset(scratch, 0, AUDIT_TOTAL * sizeof(uint64_t));

        NovaContextV2 ctx = {0};
        if (!nova_context_init_v2(&ctx)) {
            fprintf(stderr, "NOVA_SELF_AUDIT context init failed for %s\n", line);
            free(src);
            runtime_errors++;
            break;
        }

        uint64_t sh = nova_borrow_v2(&ctx, (void *)src, src_len, 0);
        uint64_t n1 = nova_borrow_v2(&ctx, scratch + 0, AUDIT_NODES * 8, 1);
        uint64_t n2 = nova_borrow_v2(&ctx, scratch + AUDIT_NODES, AUDIT_SCOPES * 8, 1);
        uint64_t n3 = nova_borrow_v2(&ctx, scratch + AUDIT_NODES + AUDIT_SCOPES, AUDIT_BINDS * 8, 1);
        uint64_t n4 = nova_borrow_v2(&ctx, scratch + AUDIT_NODES + AUDIT_SCOPES + AUDIT_BINDS, AUDIT_FIELDS * 8, 1);
        uint64_t oh = nova_borrow_v2(&ctx, scratch + AUDIT_NODES + AUDIT_SCOPES + AUDIT_BINDS + AUDIT_FIELDS, AUDIT_OUT * 8, 1);

        uint64_t args[13] = {
            sh, (uint64_t)src_len,
            n1, (uint64_t)AUDIT_NODES,
            n2, (uint64_t)AUDIT_SCOPES,
            n3, (uint64_t)AUDIT_BINDS,
            n4, (uint64_t)AUDIT_FIELDS,
            oh, (uint64_t)AUDIT_OUT,
            0
        };

        uint64_t returned = g_image->entry(&ctx, args, 13);
        uint64_t *out = scratch + AUDIT_NODES + AUDIT_SCOPES + AUDIT_BINDS + AUDIT_FIELDS;
        uint64_t code = out[0];
        uint64_t reason = out[1];
        uint64_t err_line = out[2];
        uint64_t err_col = out[3];
        uint64_t err_start = out[4];
        uint64_t node_count = out[5];

        printf("NOVA_SELF_SOURCE path=%s bytes=%zu returned=%llu runtime=%llu code=%llu reason=%llu line=%llu column=%llu offset=%llu nodes=%llu\n",
               line, src_len, (unsigned long long)returned, (unsigned long long)ctx.error,
               (unsigned long long)code, (unsigned long long)reason, (unsigned long long)err_line,
               (unsigned long long)err_col, (unsigned long long)err_start, (unsigned long long)node_count);

        if (ctx.error != 0) {
            runtime_errors++;
        } else if (returned == 0 && code == 0 && node_count > 0) {
            parsed++;
        } else {
            refused++;
        }

        if (!nova_context_destroy_v2(&ctx)) {
            fprintf(stderr, "NOVA_SELF_AUDIT context cleanup failed for %s\n", line);
            runtime_errors++;
        }
        free(src);
    }

    if (ferror(f)) {
        fprintf(stderr, "NOVA_SELF_AUDIT file read error on %s\n", list_path);
        runtime_errors++;
    }
    fclose(f);
    free(scratch);

    printf("NOVA_SELF_AUDIT files=%u parsed=%u refused=%u runtime_errors=%u\n",
           files, parsed, refused, runtime_errors);

    if (files == 0) return 1;
    return (refused + runtime_errors);
}

static void test_a8_strings_and_buffer_close(void) {
    /* Probe mode 3 shape for K_TYPE node kind if needed */
    Tree shape;
    int shape_ok = parse(&shape, "", 3);
    CHECK(shape_ok == 1, "A8_STRINGS shape query returned cleanly");
    if (shape_ok != 1) return;
    CHECK(shape.r.runtime == 0, "A8_STRINGS shape query no runtime fault");
    uint64_t K_TYPE = shape.out[31];
    CHECK(K_TYPE > 0, "A8_STRINGS K_TYPE node kind discovered");
    free_tree(&shape);

    /* Positive 1: buf<u8>="hi" with no space between > and =; decoded length 2 */
    cases++;
    const char *src_p1 = "module s1; fn f() -> buf<u8> { let s:buf<u8>=\"hi\"; return s; }";
    NtFInput in_p1 = { "s1.nova", src_p1, strlen(src_p1) };
    CHECK(nova_check_many_v2(&in_p1, 1, NULL), "A8_STRINGS p1 C reference accepts buf<u8>=\"hi\"");
    Tree t1;
    int ok1 = parse(&t1, src_p1, 0);
    CHECK(ok1 == 1, "A8_STRINGS p1 parse returned cleanly");
    if (ok1 == 1) {
        CHECK(t1.r.runtime == 0, "A8_STRINGS p1 no runtime fault");
        CHECK(t1.code == 0, "A8_STRINGS p1 candidate accepted");
        CHECK(t1.node_count > 0, "A8_STRINGS p1 published tree");
        uint64_t lit1 = 0;
        for (uint64_t i = 1; i <= t1.node_count; i++) {
            if (node_word(&t1, i, 0) == K_LITERAL && node_word(&t1, i, 13) == 4) {
                lit1 = i;
                break;
            }
        }
        CHECK(lit1 > 0, "A8_STRINGS p1 found string K_LITERAL node");
        if (lit1 > 0) {
            CHECK(node_word(&t1, lit1, 9) == 64, "A8_STRINGS p1 string width 64");
            CHECK(node_word(&t1, lit1, 10) == REG_ADDRESS, "A8_STRINGS p1 string REG_ADDRESS");
            CHECK(node_word(&t1, lit1, 14) == 10, "A8_STRINGS p1 string type T_BUF_U8 (10)");
            CHECK(node_word(&t1, lit1, 15) == 2, "A8_STRINGS p1 decoded byte length 2");
            uint64_t s = node_word(&t1, lit1, 5), e = node_word(&t1, lit1, 6);
            CHECK(s <= e && e <= strlen(src_p1) && (e - s == 4) && !memcmp(src_p1 + s, "\"hi\"", 4), "A8_STRINGS p1 span covers full quoted literal");
        }
        free_tree(&t1);
    }

    /* Positive 2: buf<u64>=b preserves type node and boundary */
    cases++;
    const char *src_p2 = "module s2; fn f(b: buf<u64>) -> buf<u64> { let c:buf<u64>=b; return c; }";
    NtFInput in_p2 = { "s2.nova", src_p2, strlen(src_p2) };
    CHECK(nova_check_many_v2(&in_p2, 1, NULL), "A8_STRINGS p2 C reference accepts buf<u64>=b");
    Tree t2;
    int ok2 = parse(&t2, src_p2, 0);
    CHECK(ok2 == 1, "A8_STRINGS p2 parse returned cleanly");
    if (ok2 == 1) {
        CHECK(t2.r.runtime == 0, "A8_STRINGS p2 no runtime fault");
        CHECK(t2.code == 0, "A8_STRINGS p2 candidate accepted");
        CHECK(t2.node_count > 0, "A8_STRINGS p2 published tree");
        uint64_t let_node = 0;
        for (uint64_t i = 1; i <= t2.node_count; i++) {
            if (node_word(&t2, i, 0) == K_LET) { let_node = i; break; }
        }
        CHECK(let_node > 0, "A8_STRINGS p2 found K_LET node");
        if (let_node > 0) {
            CHECK(node_word(&t2, let_node, 14) == 11, "A8_STRINGS p2 let carries T_BUF_U64 (11)");
        }
        const char *ann_at = strstr(src_p2, "buf<u64>=b");
        CHECK(ann_at != NULL, "A8_STRINGS p2 found annotation anchor");
        if (ann_at != NULL) {
            uint64_t ann_off = (uint64_t)(ann_at - src_p2);
            uint64_t buf_type_node = 0;
            for (uint64_t i = 1; i <= t2.node_count; i++) {
                if (node_word(&t2, i, 0) == K_TYPE && node_word(&t2, i, 5) == ann_off) {
                    buf_type_node = i;
                    break;
                }
            }
            CHECK(buf_type_node > 0, "A8_STRINGS p2 found K_TYPE at annotation offset");
            if (buf_type_node > 0) {
                uint64_t s_off = node_word(&t2, buf_type_node, 5);
                uint64_t e_off = node_word(&t2, buf_type_node, 6);
                CHECK(e_off >= s_off && e_off - s_off == 8, "A8_STRINGS p2 K_TYPE span length exactly 8");
                CHECK(e_off < strlen(src_p2) && src_p2[e_off] == '=', "A8_STRINGS p2 span boundary ends right before '='");
                CHECK(node_word(&t2, buf_type_node, 14) == 11, "A8_STRINGS p2 K_TYPE word 14 carries T_BUF_U64 (11)");
            }
        }
        free_tree(&t2);
    }

    /* Positive 3: Empty string "" decoded length 0 */
    cases++;
    const char *src_p3 = "module s3; fn f() -> buf<u8> { return \"\"; }";
    NtFInput in_p3 = { "s3.nova", src_p3, strlen(src_p3) };
    CHECK(nova_check_many_v2(&in_p3, 1, NULL), "A8_STRINGS p3 C reference accepts empty string");
    Tree t3;
    int ok3 = parse(&t3, src_p3, 0);
    CHECK(ok3 == 1, "A8_STRINGS p3 parse returned cleanly");
    if (ok3 == 1) {
        CHECK(t3.r.runtime == 0, "A8_STRINGS p3 no runtime fault");
        CHECK(t3.code == 0, "A8_STRINGS p3 candidate accepted");
        CHECK(t3.node_count > 0, "A8_STRINGS p3 published tree");
        uint64_t lit3 = 0;
        for (uint64_t i = 1; i <= t3.node_count; i++) {
            if (node_word(&t3, i, 0) == K_LITERAL && node_word(&t3, i, 13) == 4) { lit3 = i; break; }
        }
        CHECK(lit3 > 0, "A8_STRINGS p3 found string K_LITERAL node");
        if (lit3 > 0) {
            CHECK(node_word(&t3, lit3, 15) == 0, "A8_STRINGS p3 decoded byte length 0");
        }
        free_tree(&t3);
    }

    /* Positive 4: Escapes \n \r \t \0 \\ \" \x41 decoded length 7 */
    cases++;
    const char *src_p4 = "module s4; fn f() -> buf<u8> { return \"\\n\\r\\t\\0\\\\\\\"\\x41\"; }";
    NtFInput in_p4 = { "s4.nova", src_p4, strlen(src_p4) };
    CHECK(nova_check_many_v2(&in_p4, 1, NULL), "A8_STRINGS p4 C reference accepts escapes");
    Tree t4;
    int ok4 = parse(&t4, src_p4, 0);
    CHECK(ok4 == 1, "A8_STRINGS p4 parse returned cleanly");
    if (ok4 == 1) {
        CHECK(t4.r.runtime == 0, "A8_STRINGS p4 no runtime fault");
        CHECK(t4.code == 0, "A8_STRINGS p4 candidate accepted");
        CHECK(t4.node_count > 0, "A8_STRINGS p4 published tree");
        uint64_t lit4 = 0;
        for (uint64_t i = 1; i <= t4.node_count; i++) {
            if (node_word(&t4, i, 0) == K_LITERAL && node_word(&t4, i, 13) == 4) { lit4 = i; break; }
        }
        CHECK(lit4 > 0, "A8_STRINGS p4 found string K_LITERAL node");
        if (lit4 > 0) {
            CHECK(node_word(&t4, lit4, 15) == 7, "A8_STRINGS p4 decoded byte length 7");
        }
        free_tree(&t4);
    }

    /* Positive 5: String containing literal braces and grammar keywords */
    cases++;
    const char *src_p5 = "module s5; fn f() -> buf<u8> { return \"} fn bogus() -> u64 { {\"; }";
    NtFInput in_p5 = { "s5.nova", src_p5, strlen(src_p5) };
    CHECK(nova_check_many_v2(&in_p5, 1, NULL), "A8_STRINGS p5 C reference accepts braces inside string");
    Tree t5;
    int ok5 = parse(&t5, src_p5, 0);
    CHECK(ok5 == 1, "A8_STRINGS p5 parse returned cleanly");
    if (ok5 == 1) {
        CHECK(t5.r.runtime == 0, "A8_STRINGS p5 no runtime fault");
        CHECK(t5.code == 0, "A8_STRINGS p5 candidate accepted");
        CHECK(t5.node_count > 0, "A8_STRINGS p5 published tree");
        uint64_t fn_count = 0;
        for (uint64_t i = 1; i <= t5.node_count; i++) {
            if (node_word(&t5, i, 0) == K_FN) fn_count++;
        }
        CHECK(fn_count == 1, "A8_STRINGS p5 prepass ignored fake fn inside string");
        free_tree(&t5);
    }

    /* Positive 6: UTF-8 byte sequence (é is \xC3\xA9, decoded 2 bytes) */
    cases++;
    const char *src_p6 = "module s6; fn f() -> buf<u8> { return \"\xC3\xA9\"; }";
    NtFInput in_p6 = { "s6.nova", src_p6, strlen(src_p6) };
    CHECK(nova_check_many_v2(&in_p6, 1, NULL), "A8_STRINGS p6 C reference accepts raw UTF-8 bytes");
    Tree t6;
    int ok6 = parse(&t6, src_p6, 0);
    CHECK(ok6 == 1, "A8_STRINGS p6 parse returned cleanly");
    if (ok6 == 1) {
        CHECK(t6.r.runtime == 0, "A8_STRINGS p6 no runtime fault");
        CHECK(t6.code == 0, "A8_STRINGS p6 candidate accepted");
        CHECK(t6.node_count > 0, "A8_STRINGS p6 published tree");
        uint64_t lit6 = 0;
        for (uint64_t i = 1; i <= t6.node_count; i++) {
            if (node_word(&t6, i, 0) == K_LITERAL && node_word(&t6, i, 13) == 4) { lit6 = i; break; }
        }
        CHECK(lit6 > 0, "A8_STRINGS p6 found string K_LITERAL node");
        if (lit6 > 0) {
            CHECK(node_word(&t6, lit6, 15) == 2, "A8_STRINGS p6 decoded byte count is 2 (bytes, not codepoints)");
        }
        free_tree(&t6);
    }

    /* Positive 7: Spaced buffer annotation and ordinary >= binary operator in same function */
    cases++;
    const char *src_p7 = "module s7; fn check(b: buf<u8>, x: u64) -> bool { let c: buf<u8> = b; return x >= 10; }";
    NtFInput in_p7 = { "s7.nova", src_p7, strlen(src_p7) };
    CHECK(nova_check_many_v2(&in_p7, 1, NULL), "A8_STRINGS p7 C reference accepts spaced buf and >= operator");
    Tree t7;
    int ok7 = parse(&t7, src_p7, 0);
    CHECK(ok7 == 1, "A8_STRINGS p7 parse returned cleanly");
    if (ok7 == 1) {
        CHECK(t7.r.runtime == 0, "A8_STRINGS p7 no runtime fault");
        CHECK(t7.code == 0, "A8_STRINGS p7 candidate accepted");
        CHECK(t7.node_count > 0, "A8_STRINGS p7 published tree");
        free_tree(&t7);
    }

    /* Negative test cases */
    const char *neg_srcs[] = {
        /* 0: unknown escape \q */
        "module n0; fn f() -> buf<u8> { return \"\\q\"; }",
        /* 1: invalid hex \xG0 */
        "module n1; fn f() -> buf<u8> { return \"\\xG0\"; }",
        /* 2: short hex \x1 */
        "module n2; fn f() -> buf<u8> { return \"\\x1\"; }",
        /* 3: unclosed quote */
        "module n3; fn f() -> buf<u8> { return \"hello; }",
        /* 4: raw newline in string */
        "module n4; fn f() -> buf<u8> { return \"hello\nworld\"; }",
        /* 5: ending backslash without closing quote */
        "module n5; fn f() -> buf<u8> { return \"hello\\"
    };
    const char *neg_descs[] = {
        "unknown escape \\q rejected",
        "invalid hex \\xG0 rejected",
        "short hex \\x1 rejected",
        "unclosed string literal quote rejected",
        "raw newline in string literal rejected",
        "trailing backslash without quote rejected"
    };
    int num_negs = (int)(sizeof(neg_srcs) / sizeof(neg_srcs[0]));
    for (int i = 0; i < num_negs; i++) {
        cases++;
        NtFInput in_neg = { "neg.nova", neg_srcs[i], strlen(neg_srcs[i]) };
        CHECK(!nova_check_many_v2(&in_neg, 1, NULL), neg_descs[i]);
        Tree t_neg;
        int ok_neg = parse(&t_neg, neg_srcs[i], 0);
        CHECK(ok_neg == 1, "A8_STRINGS negative parse returned cleanly");
        if (ok_neg == 1) {
            CHECK(t_neg.r.runtime == 0, "A8_STRINGS negative no runtime fault");
            CHECK(t_neg.code != 0, "A8_STRINGS negative candidate rejected");
            CHECK(t_neg.node_count == 0, "A8_STRINGS negative published empty tree");
            free_tree(&t_neg);
        }
    }

    /* Clean replay of standard PROGRAM */
    cases++;
    Tree t_clean;
    int ok_clean = parse(&t_clean, PROGRAM, 0);
    CHECK(ok_clean == 1, "A8_STRINGS clean replay parse returned cleanly");
    if (ok_clean == 1) {
        CHECK(t_clean.r.runtime == 0, "A8_STRINGS clean replay no runtime fault");
        CHECK(t_clean.code == 0, "A8_STRINGS clean replay succeeds");
        CHECK(t_clean.node_count > 0, "A8_STRINGS clean replay published tree");
        free_tree(&t_clean);
    }
}

static void test_a8_token_allocation_pressure(void) {
    cases++;
    char *src_buf = (char *)malloc(32768);
    CHECK(src_buf != NULL, "A8_TOK_PRESSURE buffer allocation succeeded");
    if (!src_buf) return;

    size_t off = 0;
    int n = snprintf(src_buf + off, 32768 - off, "module tok_pressure;\nfn run() -> u64 {\n    let mut x: u64 = 0;\n");
    if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_TOK_PRESSURE header formatting failed"); free(src_buf); return; }
    off += (size_t)n;

    for (int i = 0; i < 3000; i++) {
        n = snprintf(src_buf + off, 32768 - off, "x=x+1;");
        if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_TOK_PRESSURE body formatting failed"); free(src_buf); return; }
        off += (size_t)n;
    }

    n = snprintf(src_buf + off, 32768 - off, "    return x;\n}\n");
    if (n < 0 || (size_t)n >= 32768 - off) { CHECK(0, "A8_TOK_PRESSURE footer formatting failed"); free(src_buf); return; }
    off += (size_t)n;

    NtFInput in = { "tok_pressure.nova", src_buf, off };
    CHECK(nova_check_many_v2(&in, 1, NULL), "A8_TOK_PRESSURE C reference accepts 3000 statements");

    CHECK(g_image != NULL, "A8_TOK_PRESSURE g_image host image pointer available");
    if (g_image != NULL) {
        const size_t STRESS_NODES = 524288;
        const size_t STRESS_SCOPES = 8192;
        const size_t STRESS_BINDS = 8192;
        const size_t STRESS_FIELDS = 4096;
        const size_t STRESS_OUT = 256;
        const size_t STRESS_TOTAL = STRESS_NODES + STRESS_SCOPES + STRESS_BINDS + STRESS_FIELDS + STRESS_OUT;

        uint64_t *scratch = (uint64_t *)calloc(STRESS_TOTAL, sizeof(uint64_t));
        CHECK(scratch != NULL, "A8_TOK_PRESSURE scratch allocation succeeded");
        if (scratch != NULL) {
            NovaContextV2 ctx = {0};
            int c_ok = nova_context_init_v2(&ctx);
            CHECK(c_ok == 1, "A8_TOK_PRESSURE context initialized");
            if (c_ok == 1) {
                uint64_t sh = nova_borrow_v2(&ctx, (void *)src_buf, off, 0);
                uint64_t n1 = nova_borrow_v2(&ctx, scratch + 0, STRESS_NODES * 8, 1);
                uint64_t n2 = nova_borrow_v2(&ctx, scratch + STRESS_NODES, STRESS_SCOPES * 8, 1);
                uint64_t n3 = nova_borrow_v2(&ctx, scratch + STRESS_NODES + STRESS_SCOPES, STRESS_BINDS * 8, 1);
                uint64_t n4 = nova_borrow_v2(&ctx, scratch + STRESS_NODES + STRESS_SCOPES + STRESS_BINDS, STRESS_FIELDS * 8, 1);
                uint64_t oh = nova_borrow_v2(&ctx, scratch + STRESS_NODES + STRESS_SCOPES + STRESS_BINDS + STRESS_FIELDS, STRESS_OUT * 8, 1);

                uint64_t args[13] = {
                    sh, (uint64_t)off,
                    n1, (uint64_t)STRESS_NODES,
                    n2, (uint64_t)STRESS_SCOPES,
                    n3, (uint64_t)STRESS_BINDS,
                    n4, (uint64_t)STRESS_FIELDS,
                    oh, (uint64_t)STRESS_OUT,
                    0
                };

                uint64_t returned = g_image->entry(&ctx, args, 13);
                uint64_t *out = scratch + STRESS_NODES + STRESS_SCOPES + STRESS_BINDS + STRESS_FIELDS;
                uint64_t code = out[0];
                uint64_t node_count = out[5];

                printf("NOVA_TOKEN_PRESSURE statements=3000 runtime=%llu returned=%llu code=%llu nodes=%llu\n",
                       (unsigned long long)ctx.error, (unsigned long long)returned,
                       (unsigned long long)code, (unsigned long long)node_count);

                CHECK(ctx.error == 0, "A8_TOK_PRESSURE candidate no runtime fault (runtime == 0)");
                CHECK(returned == 0, "A8_TOK_PRESSURE candidate entry returned 0");
                CHECK(code == 0, "A8_TOK_PRESSURE candidate parse code == 0");
                CHECK(node_count > 0, "A8_TOK_PRESSURE candidate published AST tree (node_count > 0)");

                CHECK(nova_context_destroy_v2(&ctx), "A8_TOK_PRESSURE context cleanup succeeded");
            }
            free(scratch);
        }
    }
    free(src_buf);

    /* Clean replay of standard PROGRAM */
    cases++;
    Tree t_clean;
    int ok_clean = parse(&t_clean, PROGRAM, 0);
    CHECK(ok_clean == 1, "A8_TOK_PRESSURE clean replay parse returned cleanly");
    if (ok_clean == 1) {
        CHECK(t_clean.r.runtime == 0, "A8_TOK_PRESSURE clean replay no runtime fault");
        CHECK(t_clean.code == 0, "A8_TOK_PRESSURE clean replay succeeds");
        CHECK(t_clean.node_count > 0, "A8_TOK_PRESSURE clean replay published tree");
        free_tree(&t_clean);
    }
}

static void test_a8_intrinsics_and_indexing(void) {
    /* Probe mode 3 shape for K_CALL and K_INDEX node kinds */
    Tree shape;
    int shape_ok = parse(&shape, "", 3);
    CHECK(shape_ok == 1, "A8_INTRIN shape query returned cleanly");
    if (shape_ok != 1) return;
    CHECK(shape.r.runtime == 0, "A8_INTRIN shape query no runtime fault");
    uint64_t K_CALL = shape.out[29];
    uint64_t K_INDEX = shape.out[32];
    CHECK(K_CALL > 0 && K_INDEX > 0, "A8_INTRIN K_CALL and K_INDEX node kinds discovered");
    free_tree(&shape);

    /* Positive table: intrinsics, casts, and buffer indexing */
    struct {
        const char *src;
        uint64_t target_kind;
        uint64_t exp_aux;
        uint64_t exp_type;
        uint64_t exp_width;
        uint64_t exp_class;
        uint64_t exp_word15;
    } pos_cases[] = {
        /* 0: len("hi") -> aux 2, type u64 (4), word15 0 */
        { "module p0; fn f() -> u64 { return len(\"hi\"); }", K_CALL, 2, 4, 64, REG_VALUE, 0 },
        /* 1: runtime() passthrough -> aux 1, type runtime (12), word15 0 */
        { "module p1; fn f() -> runtime { return runtime(); }", K_CALL, 1, 12, 80, REG_ADDRESS, 0 },
        /* 2: alloc(runtime(), 4) coerced to buf<u64> -> aux 3, type 11 */
        { "module p2; fn f() -> buf<u64> { let b: buf<u64> = alloc(runtime(), 4); return b; }", K_CALL, 3, 11, 64, REG_ADDRESS, 0 },
        /* 3: slice(b, 0, 1) -> aux 4, type 11 */
        { "module p3; fn f(b: buf<u64>) -> buf<u64> { let view: buf<u64> = slice(b, 0, 1); return view; }", K_CALL, 4, 11, 64, REG_ADDRESS, 0 },
        /* 4: rt_free(runtime(), b) -> aux 5, type 4 */
        { "module p4; fn f(b: buf<u8>) -> u64 { return rt_free(runtime(), b); }", K_CALL, 5, 4, 64, REG_VALUE, 0 },
        /* 5: rt_open_read(runtime(), p) -> aux 6, type 4 */
        { "module p5; fn f(p: buf<u8>) -> u64 { return rt_open_read(runtime(), p); }", K_CALL, 6, 4, 64, REG_VALUE, 0 },
        /* 6: rt_open_new(runtime(), p) -> aux 7, type 4 */
        { "module p6; fn f(p: buf<u8>) -> u64 { return rt_open_new(runtime(), p); }", K_CALL, 7, 4, 64, REG_VALUE, 0 },
        /* 7: rt_read(runtime(), 1, b) -> aux 8, type 4 */
        { "module p7; fn f(b: buf<u8>) -> u64 { return rt_read(runtime(), 1, b); }", K_CALL, 8, 4, 64, REG_VALUE, 0 },
        /* 8: rt_write(runtime(), 1, b) -> aux 9, type 4 */
        { "module p8; fn f(b: buf<u8>) -> u64 { return rt_write(runtime(), 1, b); }", K_CALL, 9, 4, 64, REG_VALUE, 0 },
        /* 9: rt_close(runtime(), 1) -> aux 10, type 4 */
        { "module p9; fn f() -> u64 { return rt_close(runtime(), 1); }", K_CALL, 10, 4, 64, REG_VALUE, 0 },
        /* 10: rt_diag(runtime(), b) -> aux 11, type 4 */
        { "module p10; fn f(b: buf<u8>) -> u64 { return rt_diag(runtime(), b); }", K_CALL, 11, 4, 64, REG_VALUE, 0 },
        /* 11: rt_copy(runtime(), dst, src, 1) -> aux 12, type 4 */
        { "module p11; fn f(dst: buf<u8>, src: buf<u8>) -> u64 { return rt_copy(runtime(), dst, src, 1); }", K_CALL, 12, 4, 64, REG_VALUE, 0 },
        /* 12: rt_free on named record -> aux 5, type 4 */
        { "module p12; struct R { x: u64 } fn f(r: R) -> u64 { return rt_free(runtime(), r); }", K_CALL, 5, 4, 64, REG_VALUE, 0 },
        /* 13: cast u8(256) -> aux 13, type 1, width 8 */
        { "module p13; fn f() -> u8 { return u8(256); }", K_CALL, 13, 1, 8, REG_VALUE, 0 },
        /* 14: cast u16(1) -> aux 14, type 2, width 16 */
        { "module p14; fn f() -> u16 { return u16(1); }", K_CALL, 14, 2, 16, REG_VALUE, 0 },
        /* 15: cast u32(1) -> aux 15, type 3, width 32 */
        { "module p15; fn f() -> u32 { return u32(1); }", K_CALL, 15, 3, 32, REG_VALUE, 0 },
        /* 16: cast u64(1) -> aux 16, type 4, width 64 */
        { "module p16; fn f() -> u64 { return u64(1); }", K_CALL, 16, 4, 64, REG_VALUE, 0 },
        /* 17: cast i8(1) -> aux 17, type 5, width 8 */
        { "module p17; fn f() -> i8 { return i8(1); }", K_CALL, 17, 5, 8, REG_VALUE, 0 },
        /* 18: cast i16(1) -> aux 18, type 6, width 16 */
        { "module p18; fn f() -> i16 { return i16(1); }", K_CALL, 18, 6, 16, REG_VALUE, 0 },
        /* 19: cast i32(1) -> aux 19, type 7, width 32 */
        { "module p19; fn f() -> i32 { return i32(1); }", K_CALL, 19, 7, 32, REG_VALUE, 0 },
        /* 20: cast i64(1) -> aux 20, type 8, width 64 */
        { "module p20; fn f() -> i64 { return i64(1); }", K_CALL, 20, 8, 64, REG_VALUE, 0 },
        /* 21: buf<u8> index read b[i] -> K_INDEX, type 1, width 8 */
        { "module p21; fn f(b: buf<u8>, i: u64) -> u8 { return b[i]; }", K_INDEX, 0, 1, 8, REG_VALUE, 0 },
        /* 22: buf<u64> index read b[i] -> K_INDEX, type 4, width 64 */
        { "module p22; fn f(b: buf<u64>, i: u64) -> u64 { return b[i]; }", K_INDEX, 0, 4, 64, REG_VALUE, 0 },
        /* 23: record field buffer index read s.b[i] -> K_INDEX, type 1, width 8 */
        { "module p23; struct S { b: buf<u8> } fn f(s: S, i: u64) -> u8 { return s.b[i]; }", K_INDEX, 0, 1, 8, REG_VALUE, 0 }
    };

    int num_pos = (int)(sizeof(pos_cases) / sizeof(pos_cases[0]));
    for (int i = 0; i < num_pos; i++) {
        cases++;
        const char *src = pos_cases[i].src;
        NtFInput in = { "pos_intrin.nova", src, strlen(src) };
        NtDiagnostic reference_error = {0};
        int reference_ok = nova_check_many_v2(&in, 1, &reference_error);
        CHECK(reference_ok, "A8_INTRIN C reference accepts positive intrinsic/index case");
        if (!reference_ok) printf("INTRIN_REFERENCE_FAILURE case=%d code=%u message=%s source=%s\n", i, reference_error.code, reference_error.message, src);
        Tree t;
        int ok = parse(&t, src, 0);
        CHECK(ok == 1, "A8_INTRIN parse returned cleanly");
        if (ok == 1) {
            CHECK(t.r.runtime == 0, "A8_INTRIN candidate no runtime fault");
            CHECK(t.code == 0, "A8_INTRIN candidate accepted");
            if (t.code != 0) printf("INTRIN_CANDIDATE_FAILURE case=%d code=%llu line=%llu column=%llu source=%s\n", i, (unsigned long long)t.code, (unsigned long long)t.line, (unsigned long long)t.column, src);
            CHECK(t.node_count > 0, "A8_INTRIN candidate published tree");

            uint64_t target_node = 0;
            for (uint64_t n = 1; n <= t.node_count; n++) {
                if (node_word(&t, n, 0) == pos_cases[i].target_kind) {
                    /* For K_CALL with alloc, find the alloc call inside the let statement */
                    if (pos_cases[i].target_kind == K_CALL && pos_cases[i].exp_aux > 0) {
                        if (node_word(&t, n, 13) == pos_cases[i].exp_aux) {
                            target_node = n;
                            break;
                        }
                    } else {
                        target_node = n;
                        break;
                    }
                }
            }
            CHECK(target_node > 0, "A8_INTRIN found target node");
            if (target_node > 0) {
            uint64_t exp_children = 0;
            if (pos_cases[i].target_kind == K_INDEX) {
                exp_children = 2;
            } else if (pos_cases[i].exp_aux == 1) {
                exp_children = 0;
            } else if (pos_cases[i].exp_aux == 2 || (pos_cases[i].exp_aux >= 13 && pos_cases[i].exp_aux <= 20)) {
                exp_children = 1;
            } else if (pos_cases[i].exp_aux == 3 || pos_cases[i].exp_aux == 5 || pos_cases[i].exp_aux == 6 || pos_cases[i].exp_aux == 7 || pos_cases[i].exp_aux == 10 || pos_cases[i].exp_aux == 11) {
                exp_children = 2;
            } else if (pos_cases[i].exp_aux == 4 || pos_cases[i].exp_aux == 8 || pos_cases[i].exp_aux == 9) {
                exp_children = 3;
            } else if (pos_cases[i].exp_aux == 12) {
                exp_children = 4;
            }
            uint64_t child_count = 0;
            uint64_t cur_child = node_word(&t, target_node, 2);
            while (cur_child > 0 && child_count <= t.node_count) {
                CHECK(node_word(&t, cur_child, 1) == target_node, "A8_INTRIN child parent points to target_node");
                child_count++;
                cur_child = node_word(&t, cur_child, 4);
            }
            CHECK(cur_child == 0, "A8_INTRIN child chain terminates with 0");
            CHECK(child_count == exp_children, "A8_INTRIN logical child count matches expected arity");
                if (pos_cases[i].exp_aux > 0) {
                    CHECK(node_word(&t, target_node, 13) == pos_cases[i].exp_aux, "A8_INTRIN matching aux intrinsic ID");
                }
                CHECK(node_word(&t, target_node, 14) == pos_cases[i].exp_type, "A8_INTRIN matching result type");
                CHECK(node_word(&t, target_node, 9) == pos_cases[i].exp_width, "A8_INTRIN matching width");
                CHECK(node_word(&t, target_node, 10) == pos_cases[i].exp_class, "A8_INTRIN matching reg class");
                if (pos_cases[i].target_kind == K_CALL) {
                    CHECK(node_word(&t, target_node, 15) == pos_cases[i].exp_word15, "A8_INTRIN intrinsic K_CALL word 15 is 0");
                }
            }
            free_tree(&t);
        }
    }

    /* Negative table: invalid intrinsic arguments and illegal indexing */
    const char *neg_srcs[] = {
        /* 0: runtime with arguments */
        "module n0; fn f() -> runtime { return runtime(1); }",
        /* 1: len on scalar */
        "module n1; fn f() -> u64 { return len(1); }",
        /* 2: alloc without runtime */
        "module n2; fn f() -> buf<u8> { return alloc(1, 2); }",
        /* 3: alloc with bool size */
        "module n3; fn f() -> buf<u8> { return alloc(runtime(), true); }",
        /* 4: slice with bool start */
        "module n4; fn f(b: buf<u8>) -> buf<u8> { return slice(b, true, 1); }",
        /* 5: rt_free on scalar */
        "module n5; fn f() -> u64 { return rt_free(runtime(), 1); }",
        /* 6: rt_free on record constructor expression (must be named record) */
        "module n6; struct R { x: u64 } fn f() -> u64 { return rt_free(runtime(), R{x: 1}); }",
        /* 7: rt_open_read path must be named buffer */
        "module n7; fn f() -> u64 { return rt_open_read(runtime(), \"path\"); }",
        /* 8: rt_copy with buf<u64> instead of buf<u8> */
        "module n8; fn f(b: buf<u64>) -> u64 { return rt_copy(runtime(), b, b, 1); }",
        /* 9: cast u8 on bool */
        "module n9; fn f() -> u8 { return u8(true); }",
        /* 10: indexing bool */
        "module n10; fn f(b: bool) -> u8 { return b[0]; }",
        /* 11: indexing record */
        "module n11; struct R { x: u64 } fn f(r: R) -> u64 { return r[0]; }",
        /* 12: indexing scalar */
        "module n12; fn f(n: u64) -> u64 { return n[0]; }",
        /* 13: wrong intrinsic arity (len with 2 args) */
        "module n13; fn f(b: buf<u8>) -> u64 { return len(b, 1); }",
        /* 14: indexing buffer with bool index */
        "module n14; fn f(b: buf<u8>, i: bool) -> u8 { return b[i]; }"
    };
    const char *neg_descs[] = {
        "runtime(1) refused",
        "len(1) refused",
        "alloc(1, 2) refused",
        "alloc(runtime(), true) refused",
        "slice(b, true, 1) refused",
        "rt_free(runtime(), 1) refused",
        "rt_free on constructor expression refused",
        "rt_open_read on string literal refused",
        "rt_copy on buf<u64> refused",
        "u8(true) refused",
        "bool[0] refused",
        "record[0] refused",
        "scalar[0] refused",
        "len with 2 args refused",
        "indexing buffer with bool index refused"
    };

    int num_negs = (int)(sizeof(neg_srcs) / sizeof(neg_srcs[0]));
    for (int i = 0; i < num_negs; i++) {
        cases++;
        NtFInput in_neg = { "neg_intrin.nova", neg_srcs[i], strlen(neg_srcs[i]) };
        CHECK(!nova_check_many_v2(&in_neg, 1, NULL), neg_descs[i]);
        Tree t_neg;
        int ok_neg = parse(&t_neg, neg_srcs[i], 0);
        CHECK(ok_neg == 1, "A8_INTRIN negative parse returned cleanly");
        if (ok_neg == 1) {
            CHECK(t_neg.r.runtime == 0, "A8_INTRIN negative no runtime fault");
            CHECK(t_neg.code != 0, "A8_INTRIN negative candidate rejected");
            CHECK(t_neg.node_count == 0, "A8_INTRIN negative published empty tree");
            free_tree(&t_neg);
        }
    }

    /* Real self-source audit test: nova_language_lex.nova */
    cases++;
    size_t lex_src_len = 0;
    char *lex_src = loadf("compiler/nova/frontend/nova_language_lex.nova", &lex_src_len);
    CHECK(lex_src != NULL, "A8_INTRIN loaded compiler/nova/frontend/nova_language_lex.nova");
    if (lex_src != NULL) {
        NtFInput in_lex = { "nova_language_lex.nova", lex_src, lex_src_len };
        CHECK(nova_check_many_v2(&in_lex, 1, NULL), "A8_INTRIN C reference accepts nova_language_lex.nova");
        Tree t_lex;
        int ok_lex = parse(&t_lex, lex_src, 0);
        CHECK(ok_lex == 1, "A8_INTRIN parse(nova_language_lex.nova) returned cleanly");
        if (ok_lex == 1) {
            CHECK(t_lex.r.runtime == 0, "A8_INTRIN nova_language_lex.nova no runtime fault");
            CHECK(t_lex.code == 0, "A8_INTRIN nova_language_lex.nova candidate accepted");
            CHECK(t_lex.node_count > 0, "A8_INTRIN nova_language_lex.nova candidate published tree");
            free_tree(&t_lex);
        }
        free(lex_src);
    }

    /* Clean replay of standard PROGRAM */
    cases++;
    Tree t_clean;
    int ok_clean = parse(&t_clean, PROGRAM, 0);
    CHECK(ok_clean == 1, "A8_INTRIN clean replay parse returned cleanly");
    if (ok_clean == 1) {
        CHECK(t_clean.r.runtime == 0, "A8_INTRIN clean replay no runtime fault");
        CHECK(t_clean.code == 0, "A8_INTRIN clean replay succeeds");
        CHECK(t_clean.node_count > 0, "A8_INTRIN clean replay published tree");
        free_tree(&t_clean);
    }
}

static void test_a8_allocation_contexts_and_scopes(void) {
    /* Positive table: allocation contexts, mutable buffer reassignments, and scope resolution */
    struct {
        const char *src;
        const char *desc;
    } pos_cases[] = {
        /* 0: Slice initializing a buffer local */
        { "module p_sl; fn f(b: buf<u8>) -> buf<u8> { let view: buf<u8> = slice(b, 0, 1); return view; }", "slice initializing buffer local" },
        /* 1: Mutable buffer reassignment with alloc */
        { "module p_re; fn f() -> buf<u8> { let mut b: buf<u8> = alloc(runtime(), 4); b = alloc(runtime(), 8); return b; }", "mutable buffer reassignment with alloc" },
        /* 2: Outer mutable x shadowed in inner block, then assigned and returned in outer scope */
        { "module p_sh; fn f() -> u64 { let mut x: u64 = 1; { let x: u64 = 2; } x = 3; return x; }", "outer mutable x shadowed in block then assigned and returned" }
    };

    int num_pos = (int)(sizeof(pos_cases) / sizeof(pos_cases[0]));
    for (int i = 0; i < num_pos; i++) {
        cases++;
        NtFInput in = { "pos_ctx.nova", pos_cases[i].src, strlen(pos_cases[i].src) };
        CHECK(nova_check_many_v2(&in, 1, NULL), pos_cases[i].desc);
        Tree t;
        int ok = parse(&t, pos_cases[i].src, 0);
        CHECK(ok == 1, "A8_ALLOC_CTX positive parse returned cleanly");
        if (ok == 1) {
            CHECK(t.r.runtime == 0, "A8_ALLOC_CTX positive no runtime fault");
            CHECK(t.code == 0, "A8_ALLOC_CTX positive candidate accepted");
            CHECK(t.node_count > 0, "A8_ALLOC_CTX positive published tree");

            /* Case 2: verify return x resolves to outer let with aux KEY_MUT (5) */
            if (i == 2) {
                uint64_t ret_name = 0;
                for (uint64_t n = t.node_count; n >= 1; n--) {
                    if (node_word(&t, n, 0) == K_NAME) { ret_name = n; break; }
                }
                CHECK(ret_name > 0, "A8_ALLOC_CTX found returned K_NAME");
                if (ret_name > 0) {
                    uint64_t bind_id = node_word(&t, ret_name, 15);
                    CHECK(bind_id > 0, "A8_ALLOC_CTX returned name has binding id");
                    uint64_t outer_let = 0;
                    for (uint64_t n = 1; n <= t.node_count; n++) {
                        if (node_word(&t, n, 0) == K_LET && node_word(&t, n, 15) == bind_id) {
                            outer_let = n;
                            break;
                        }
                    }
                    CHECK(outer_let > 0, "A8_ALLOC_CTX found outer K_LET for binding");
                    if (outer_let > 0) {
                        CHECK(node_word(&t, outer_let, 13) == 5, "A8_ALLOC_CTX outer let aux is KEY_MUT (5)");
                    }
                }
            }
            free_tree(&t);
        }
    }

    /* Negative table: direct return alloc/slice, alloc in struct field, assignment to immutable/param, closed block use */
    const char *neg_srcs[] = {
        /* 0: direct return of slice */
        "module n0; fn f(b: buf<u8>) -> buf<u8> { return slice(b, 0, 1); }",
        /* 1: direct return of alloc */
        "module n1; fn f() -> buf<u8> { return alloc(runtime(), 4); }",
        /* 2: alloc inside record buffer field */
        "module n2; struct S { b: buf<u8> } fn f() -> S { return S{b: alloc(runtime(), 4)}; }",
        /* 3: assignment to immutable let */
        "module n3; fn f() -> u64 { let x: u64 = 1; x = 2; return x; }",
        /* 4: assignment to parameter */
        "module n4; fn f(x: u64) -> u64 { x = 2; return x; }",
        /* 5: reference to variable only declared in closed inner block */
        "module n5; fn f() -> u64 { { let x: u64 = 1; } return x; }"
    };
    const char *neg_descs[] = {
        "direct return slice refused",
        "direct return alloc refused",
        "alloc in record field refused",
        "assignment to immutable let refused",
        "assignment to parameter refused",
        "use of variable from closed block refused"
    };

    int num_negs = (int)(sizeof(neg_srcs) / sizeof(neg_srcs[0]));
    for (int i = 0; i < num_negs; i++) {
        cases++;
        NtFInput in_neg = { "neg_ctx.nova", neg_srcs[i], strlen(neg_srcs[i]) };
        CHECK(!nova_check_many_v2(&in_neg, 1, NULL), neg_descs[i]);
        Tree t_neg;
        int ok_neg = parse(&t_neg, neg_srcs[i], 0);
        CHECK(ok_neg == 1, "A8_ALLOC_CTX negative parse returned cleanly");
        if (ok_neg == 1) {
            CHECK(t_neg.r.runtime == 0, "A8_ALLOC_CTX negative no runtime fault");
            CHECK(t_neg.code != 0, "A8_ALLOC_CTX negative candidate rejected");
            CHECK(t_neg.node_count == 0, "A8_ALLOC_CTX negative published empty tree");
            free_tree(&t_neg);
        }
    }

    /* Clean replay of standard PROGRAM */
    cases++;
    Tree t_clean;
    int ok_clean = parse(&t_clean, PROGRAM, 0);
    CHECK(ok_clean == 1, "A8_ALLOC_CTX clean replay parse returned cleanly");
    if (ok_clean == 1) {
        CHECK(t_clean.r.runtime == 0, "A8_ALLOC_CTX clean replay no runtime fault");
        CHECK(t_clean.code == 0, "A8_ALLOC_CTX clean replay succeeds");
        CHECK(t_clean.node_count > 0, "A8_ALLOC_CTX clean replay published tree");
        free_tree(&t_clean);
    }
}

static void test_a8_loop_control_and_else_if(void) {
    /* Probe mode 3 shape for K_IF, K_BREAK, and K_CONTINUE */
    Tree shape;
    int shape_ok = parse(&shape, "", 3);
    CHECK(shape_ok == 1, "A8_LOOP shape query returned cleanly");
    if (shape_ok != 1) return;
    CHECK(shape.r.runtime == 0, "A8_LOOP shape query no runtime fault");
    CHECK(shape.r.returned == 38, "A8_LOOP shape query returns extended 38 words");
    uint64_t K_IF = shape.out[25];
    uint64_t K_BREAK = shape.out[35];
    uint64_t K_CONTINUE = shape.out[36];
    CHECK(K_IF > 0, "A8_LOOP K_IF discovered");
    CHECK(K_BREAK == 22, "A8_LOOP K_BREAK is 22");
    CHECK(K_CONTINUE == 23, "A8_LOOP K_CONTINUE is 23");
    free_tree(&shape);

    /* Positive 1: Else-if chain (outer if's else-child is K_IF, inner else is K_BLOCK) */
    cases++;
    const char *src_elif = "module elif; fn f(x: u64) -> u64 { if x == 0 { return 1; } else if x == 1 { return 2; } else { return 3; } }";
    NtFInput in_elif = { "elif.nova", src_elif, strlen(src_elif) };
    CHECK(nova_check_many_v2(&in_elif, 1, NULL), "A8_LOOP C reference accepts else-if chain");
    Tree t_elif;
    int ok_elif = parse(&t_elif, src_elif, 0);
    CHECK(ok_elif == 1, "A8_LOOP parse(elif) returned cleanly");
    if (ok_elif == 1) {
        CHECK(t_elif.r.runtime == 0, "A8_LOOP elif no runtime fault");
        CHECK(t_elif.code == 0, "A8_LOOP elif candidate accepted");
        CHECK(t_elif.node_count > 0, "A8_LOOP elif published tree");
        uint64_t outer_if = 0, inner_if = 0;
        for (uint64_t i = 1; i <= t_elif.node_count; i++) {
            if (node_word(&t_elif, i, 0) == K_IF) {
                if (outer_if == 0) outer_if = i;
                else if (inner_if == 0) inner_if = i;
            }
        }
        CHECK(outer_if > 0 && inner_if > 0, "A8_LOOP found outer and inner K_IF");
        if (outer_if > 0 && inner_if > 0) {
            uint64_t cond1 = node_word(&t_elif, outer_if, 2);
            uint64_t then1 = cond1 > 0 ? node_word(&t_elif, cond1, 4) : 0;
            uint64_t else1 = then1 > 0 ? node_word(&t_elif, then1, 4) : 0;
            CHECK(else1 == inner_if, "A8_LOOP outer if else-child is directly inner K_IF");
            CHECK(node_word(&t_elif, inner_if, 1) == outer_if, "A8_LOOP inner K_IF parent is outer K_IF");
            uint64_t cond2 = node_word(&t_elif, inner_if, 2);
            uint64_t then2 = cond2 > 0 ? node_word(&t_elif, cond2, 4) : 0;
            uint64_t else2 = then2 > 0 ? node_word(&t_elif, then2, 4) : 0;
            CHECK(else2 > 0 && node_word(&t_elif, else2, 0) == K_BLOCK, "A8_LOOP inner if else-child is K_BLOCK");
        }
        free_tree(&t_elif);
    }

    /* Positive 2: while true { break; } followed by return; break target is K_WHILE */
    cases++;
    const char *src_brk = "module brk; fn f() -> u64 { while true { break; } return 0; }";
    NtFInput in_brk = { "brk.nova", src_brk, strlen(src_brk) };
    CHECK(nova_check_many_v2(&in_brk, 1, NULL), "A8_LOOP C reference accepts break in while");
    Tree t_brk;
    int ok_brk = parse(&t_brk, src_brk, 0);
    CHECK(ok_brk == 1, "A8_LOOP parse(brk) returned cleanly");
    if (ok_brk == 1) {
        CHECK(t_brk.r.runtime == 0, "A8_LOOP brk no runtime fault");
        CHECK(t_brk.code == 0, "A8_LOOP brk candidate accepted");
        CHECK(t_brk.node_count > 0, "A8_LOOP brk published tree");
        uint64_t while_id = 0, brk_id = 0;
        for (uint64_t i = 1; i <= t_brk.node_count; i++) {
            if (node_word(&t_brk, i, 0) == K_WHILE) while_id = i;
            if (node_word(&t_brk, i, 0) == K_BREAK) brk_id = i;
        }
        CHECK(while_id > 0 && brk_id > 0, "A8_LOOP found K_WHILE and K_BREAK");
        if (while_id > 0 && brk_id > 0) {
            CHECK(node_word(&t_brk, brk_id, 15) == while_id, "A8_LOOP break word 15 targets enclosing K_WHILE");
            CHECK(node_word(&t_brk, brk_id, 9) == 0, "A8_LOOP break width 0");
            CHECK(node_word(&t_brk, brk_id, 10) == REG_NONE, "A8_LOOP break class REG_NONE");
        }
        free_tree(&t_brk);
    }

    /* Positive 3: while with continue */
    cases++;
    const char *src_cnt = "module cnt; fn f() -> u64 { let mut x: u64 = 0; while x < 3 { x = x + 1; continue; } return x; }";
    NtFInput in_cnt = { "cnt.nova", src_cnt, strlen(src_cnt) };
    CHECK(nova_check_many_v2(&in_cnt, 1, NULL), "A8_LOOP C reference accepts continue in while");
    Tree t_cnt;
    int ok_cnt = parse(&t_cnt, src_cnt, 0);
    CHECK(ok_cnt == 1, "A8_LOOP parse(cnt) returned cleanly");
    if (ok_cnt == 1) {
        CHECK(t_cnt.r.runtime == 0, "A8_LOOP cnt no runtime fault");
        CHECK(t_cnt.code == 0, "A8_LOOP cnt candidate accepted");
        CHECK(t_cnt.node_count > 0, "A8_LOOP cnt published tree");
        uint64_t while_id = 0, cnt_id = 0;
        for (uint64_t i = 1; i <= t_cnt.node_count; i++) {
            if (node_word(&t_cnt, i, 0) == K_WHILE) while_id = i;
            if (node_word(&t_cnt, i, 0) == K_CONTINUE) cnt_id = i;
        }
        CHECK(while_id > 0 && cnt_id > 0, "A8_LOOP found K_WHILE and K_CONTINUE");
        if (while_id > 0 && cnt_id > 0) {
            CHECK(node_word(&t_cnt, cnt_id, 15) == while_id, "A8_LOOP continue word 15 targets enclosing K_WHILE");
        }
        free_tree(&t_cnt);
    }

    /* Positive 4: Nested while with inner break and outer continue */
    cases++;
    const char *src_nest = "module nest; fn f() -> u64 { while true { while true { if true { break; } } continue; } return 0; }";
    NtFInput in_nest = { "nest.nova", src_nest, strlen(src_nest) };
    CHECK(nova_check_many_v2(&in_nest, 1, NULL), "A8_LOOP C reference accepts nested while loops with break/continue");
    Tree t_nest;
    int ok_nest = parse(&t_nest, src_nest, 0);
    CHECK(ok_nest == 1, "A8_LOOP parse(nest) returned cleanly");
    if (ok_nest == 1) {
        CHECK(t_nest.r.runtime == 0, "A8_LOOP nest no runtime fault");
        CHECK(t_nest.code == 0, "A8_LOOP nest candidate accepted");
        CHECK(t_nest.node_count > 0, "A8_LOOP nest published tree");
        uint64_t outer_w = 0, inner_w = 0, brk_id = 0, cnt_id = 0;
        for (uint64_t i = 1; i <= t_nest.node_count; i++) {
            if (node_word(&t_nest, i, 0) == K_WHILE) {
                if (outer_w == 0) outer_w = i;
                else if (inner_w == 0) inner_w = i;
            }
            if (node_word(&t_nest, i, 0) == K_BREAK) brk_id = i;
            if (node_word(&t_nest, i, 0) == K_CONTINUE) cnt_id = i;
        }
        CHECK(outer_w > 0 && inner_w > 0 && brk_id > 0 && cnt_id > 0, "A8_LOOP found nested whiles, break and continue");
        if (outer_w > 0 && inner_w > 0 && brk_id > 0 && cnt_id > 0) {
            CHECK(node_word(&t_nest, brk_id, 15) == inner_w, "A8_LOOP break targets nearest inner while");
            CHECK(node_word(&t_nest, cnt_id, 15) == outer_w, "A8_LOOP continue targets outer while");
            /* Verify parent ancestry walk reaches inner_w from break */
            uint64_t p = node_word(&t_nest, brk_id, 1);
            int reached_inner = 0;
            uint64_t steps = 0;
            while (p > 0 && steps <= t_nest.node_count) {
                if (p == inner_w) { reached_inner = 1; break; }
                p = node_word(&t_nest, p, 1);
                steps++;
            }
            CHECK(reached_inner == 1, "A8_LOOP parent walk from break reaches inner while");
        }
        free_tree(&t_nest);
    }

    /* Positive 5: Valid identifier 'breakfast' not confused with break */
    cases++;
    const char *src_bfeast = "module bfeast; fn f() -> u64 { let breakfast: u64 = 42; return breakfast; }";
    NtFInput in_bfeast = { "bfeast.nova", src_bfeast, strlen(src_bfeast) };
    CHECK(nova_check_many_v2(&in_bfeast, 1, NULL), "A8_LOOP C reference accepts breakfast variable");
    Tree t_bfeast;
    int ok_bfeast = parse(&t_bfeast, src_bfeast, 0);
    CHECK(ok_bfeast == 1, "A8_LOOP parse(bfeast) returned cleanly");
    if (ok_bfeast == 1) {
        CHECK(t_bfeast.r.runtime == 0, "A8_LOOP bfeast no runtime fault");
        CHECK(t_bfeast.code == 0, "A8_LOOP bfeast candidate accepted");
        CHECK(t_bfeast.node_count > 0, "A8_LOOP bfeast published tree");
        free_tree(&t_bfeast);
    }

    /* Negative table: break/continue outside loop, missing semicolon, etc. */
    const char *neg_srcs[] = {
        /* 0: break outside loop */
        "module n0; fn f() -> u64 { break; return 0; }",
        /* 1: continue outside loop */
        "module n1; fn f() -> u64 { continue; return 0; }",
        /* 2: break after loop */
        "module n2; fn f() -> u64 { while true { let x: u64 = 1; } break; return 0; }",
        /* 3: break missing semicolon */
        "module n3; fn f() -> u64 { while true { break } return 0; }"
    };
    const char *neg_descs[] = {
        "break outside loop refused",
        "continue outside loop refused",
        "break after loop closed refused",
        "break missing semicolon refused"
    };
    int num_negs = (int)(sizeof(neg_srcs) / sizeof(neg_srcs[0]));
    for (int i = 0; i < num_negs; i++) {
        cases++;
        NtFInput in_neg = { "neg_loop.nova", neg_srcs[i], strlen(neg_srcs[i]) };
        CHECK(!nova_check_many_v2(&in_neg, 1, NULL), neg_descs[i]);
        Tree t_neg;
        int ok_neg = parse(&t_neg, neg_srcs[i], 0);
        CHECK(ok_neg == 1, "A8_LOOP negative parse returned cleanly");
        if (ok_neg == 1) {
            CHECK(t_neg.r.runtime == 0, "A8_LOOP negative no runtime fault");
            CHECK(t_neg.code != 0, "A8_LOOP negative candidate rejected");
            CHECK(t_neg.node_count == 0, "A8_LOOP negative published empty tree");
            free_tree(&t_neg);
        }
    }

    /* Clean replay of standard PROGRAM */
    cases++;
    Tree t_clean;
    int ok_clean = parse(&t_clean, PROGRAM, 0);
    CHECK(ok_clean == 1, "A8_LOOP clean replay parse returned cleanly");
    if (ok_clean == 1) {
        CHECK(t_clean.r.runtime == 0, "A8_LOOP clean replay no runtime fault");
        CHECK(t_clean.code == 0, "A8_LOOP clean replay succeeds");
        CHECK(t_clean.node_count > 0, "A8_LOOP clean replay published tree");
        free_tree(&t_clean);
    }
}

static void test_a8_unary_and_null(void) {
    /* Probe mode 3 shape for K_UNARY */
    Tree shape;
    int shape_ok = parse(&shape, "", 3);
    CHECK(shape_ok == 1, "A8_UNARY shape query returned cleanly");
    if (shape_ok != 1) return;
    CHECK(shape.r.runtime == 0, "A8_UNARY shape query no runtime fault");
    CHECK(shape.r.returned == 38, "A8_UNARY shape query returns extended 38 words");
    uint64_t K_UNARY = shape.out[37];
    CHECK(K_UNARY == 24, "A8_UNARY K_UNARY is 24");
    free_tree(&shape);

    /* Positive table: unary operators !, ~, - and null literals */
    struct {
        const char *src;
        const char *desc;
        uint64_t exp_op;
        uint64_t exp_type;
        uint64_t exp_width;
        uint64_t exp_class;
    } pos_cases[] = {
        /* 0: !true -> op '!' (33), type bool (9) */
        { "module u0; fn f() -> bool { return !true; }", "!true", 33, 9, 8, REG_PREDICATE },
        /* 1: !!x on bool -> outer op 33, type 9 */
        { "module u1; fn f(x: bool) -> bool { return !!x; }", "!!x on bool", 33, 9, 8, REG_PREDICATE },
        /* 2: ~x on u64 -> op '~' (126), type u64 (4) */
        { "module u2; fn f(x: u64) -> u64 { return ~x; }", "~x on u64", 126, 4, 64, REG_VALUE },
        /* 3: -x on i64 -> op '-' (45), type i64 (8) */
        { "module u3; fn f(x: i64) -> i64 { return -x; }", "-x on i64", 45, 8, 64, REG_VALUE },
        /* 4: -(a + b) on i64 -> op 45, type 8 */
        { "module u4; fn f(a: i64, b: i64) -> i64 { return -(a + b); }", "-(a + b) on i64", 45, 8, 64, REG_VALUE },
        /* 5: -128 coerced to i8 -> op 45, type i8 (5) */
        { "module u5; fn f() -> i8 { return -128; }", "-128 for i8", 45, 5, 8, REG_VALUE },
        /* 6: -9223372036854775808 coerced to i64 -> op 45, type i64 (8) */
        { "module u6; fn f() -> i64 { return -9223372036854775808; }", "-9223372036854775808 for i64", 45, 8, 64, REG_VALUE },
        /* 7: -1 for u64 unsigned wrap -> op 45, type u64 (4) */
        { "module u7; fn f() -> u64 { return -1; }", "-1 for u64", 45, 4, 64, REG_VALUE },
        /* 8: !a && b precedence: root is BINARY, left child is UNARY */
        { "module u8; fn f(a: bool, b: bool) -> bool { return !a && b; }", "!a && b precedence", 33, 9, 8, REG_PREDICATE },
        /* 9: return null for record R */
        { "module u9; struct R { x: u64 } fn f() -> R { return null; }", "return null for record", 0, 0, 0, 0 },
        /* 10: recursive struct Link with next: null */
        { "module u10; struct Link { next: Link } fn f() -> Link { return Link{next: null}; }", "Link with next: null", 0, 0, 0, 0 },
        /* 11: record comparison r == null */
        { "module u11; struct R { x: u64 } fn f(r: R) -> bool { return r == null; }", "r == null", 0, 0, 0, 0 },
        /* 12: record comparison r != null */
        { "module u12; struct R { x: u64 } fn f(r: R) -> bool { return r != null; }", "r != null", 0, 0, 0, 0 },
        /* 13: declared identifier nullish */
        { "module u13; fn f() -> u64 { let nullish: u64 = 7; return nullish; }", "nullish variable", 0, 0, 0, 0 }
    };

    int num_pos = (int)(sizeof(pos_cases) / sizeof(pos_cases[0]));
    for (int i = 0; i < num_pos; i++) {
        cases++;
        const char *src = pos_cases[i].src;
        NtFInput in = { "pos_unary.nova", src, strlen(src) };
        CHECK(nova_check_many_v2(&in, 1, NULL), pos_cases[i].desc);
        Tree t;
        int ok = parse(&t, src, 0);
        CHECK(ok == 1, "A8_UNARY positive parse returned cleanly");
        if (ok == 1) {
            CHECK(t.r.runtime == 0, "A8_UNARY positive no runtime fault");
            CHECK(t.code == 0, "A8_UNARY positive candidate accepted");
            CHECK(t.node_count > 0, "A8_UNARY positive published tree");

            if (pos_cases[i].exp_op > 0) {
                uint64_t un_node = 0;
                if (i != 8) {
                    uint64_t ret_stmt = 0;
                    for (uint64_t n = 1; n <= t.node_count; n++) {
                        if (node_word(&t, n, 0) == 11) { ret_stmt = n; break; }
                    }
                    if (ret_stmt > 0) {
                        uint64_t expr_root = node_word(&t, ret_stmt, 2);
                        if (expr_root > 0 && node_word(&t, expr_root, 0) == K_UNARY) {
                            un_node = expr_root;
                        }
                    }
                }
                if (un_node == 0) {
                    for (uint64_t n = 1; n <= t.node_count; n++) {
                        if (node_word(&t, n, 0) == K_UNARY) {
                            if (node_word(&t, n, 13) == pos_cases[i].exp_op) {
                                un_node = n;
                                break;
                            }
                        }
                    }
                }
                CHECK(un_node > 0, "A8_UNARY found K_UNARY node");
                if (un_node > 0) {
                    CHECK(node_word(&t, un_node, 13) == pos_cases[i].exp_op, "A8_UNARY op matches expected");
                    CHECK(node_word(&t, un_node, 14) == pos_cases[i].exp_type, "A8_UNARY type matches expected");
                    CHECK(node_word(&t, un_node, 9) == pos_cases[i].exp_width, "A8_UNARY width matches expected");
                    CHECK(node_word(&t, un_node, 10) == pos_cases[i].exp_class, "A8_UNARY class matches expected");
                    uint64_t child = node_word(&t, un_node, 2);
                    CHECK(child > 0, "A8_UNARY has expression child");
                    if (child > 0) {
                    if (i == 1) {
                        CHECK(node_word(&t, child, 0) == K_UNARY, "A8_UNARY !!x inner child is K_UNARY");
                        CHECK(node_word(&t, child, 13) == 33, "A8_UNARY !!x inner child op is '!'");
                        uint64_t inner_child = node_word(&t, child, 2);
                        CHECK(inner_child > 0 && node_word(&t, inner_child, 0) == 14, "A8_UNARY !!x innermost child is K_NAME (14)");
                    }
                    if (i == 5) {
                        CHECK(node_word(&t, child, 0) == 15, "A8_UNARY -128 child is K_LITERAL (15)");
                        CHECK(node_word(&t, child, 15) == 128, "A8_UNARY -128 literal magnitude 128");
                        CHECK(node_word(&t, child, 14) == 5, "A8_UNARY -128 literal coerced type i8 (5)");
                    }
                    if (i == 6) {
                        CHECK(node_word(&t, child, 0) == 15, "A8_UNARY -i64 child is K_LITERAL (15)");
                        CHECK(node_word(&t, child, 15) == UINT64_C(9223372036854775808), "A8_UNARY -i64 literal magnitude 9223372036854775808");
                        CHECK(node_word(&t, child, 14) == 8, "A8_UNARY -i64 literal coerced type i64 (8)");
                    }
                        CHECK(node_word(&t, child, 4) == 0, "A8_UNARY has exactly one child");
                        CHECK(node_word(&t, child, 1) == un_node, "A8_UNARY child parent points to unary");
                    }
                }
            }
            if (i == 8) {
                /* Check !a && b precedence: root of return is K_BINARY */
                uint64_t ret_stmt = 0;
                for (uint64_t n = 1; n <= t.node_count; n++) {
                    if (node_word(&t, n, 0) == 11) { ret_stmt = n; break; }
                }
                CHECK(ret_stmt > 0, "A8_UNARY found return statement");
                if (ret_stmt > 0) {
                    uint64_t ret_expr = node_word(&t, ret_stmt, 2);
                    CHECK(ret_expr > 0 && node_word(&t, ret_expr, 0) == 18, "A8_UNARY !a && b root is K_BINARY (18)");
                    if (ret_expr > 0) {
                        uint64_t left = node_word(&t, ret_expr, 2);
                        CHECK(left > 0 && node_word(&t, left, 0) == K_UNARY, "A8_UNARY binary left operand is K_UNARY");
                    }
                }
            }
            if (i == 9) {
                /* Check null literal in return null: K_LITERAL aux 5 */
                uint64_t null_node = 0;
                for (uint64_t n = 1; n <= t.node_count; n++) {
                    if (node_word(&t, n, 0) == 15 && node_word(&t, n, 13) == 5) {
                        null_node = n;
                        break;
                    }
                }
                CHECK(null_node > 0, "A8_UNARY found null literal node (K_LITERAL aux 5)");
                if (null_node > 0) {
                    CHECK(node_word(&t, null_node, 15) == 0, "A8_UNARY null literal value 0");
                    CHECK(node_word(&t, null_node, 10) == REG_ADDRESS, "A8_UNARY retagged null REG_ADDRESS");
                    CHECK(node_word(&t, null_node, 14) > 12, "A8_UNARY retagged null carries record type");
                }
            }
            free_tree(&t);
        }
    }

    /* Negative table: invalid unary types, unary plus, overflow, null on non-records */
    const char *neg_srcs[] = {
        /* 0: ! on integer */
        "module n0; fn f() -> bool { return !1; }",
        /* 1: ~ on bool */
        "module n1; fn f() -> bool { return ~true; }",
        /* 2: - on bool */
        "module n2; fn f() -> bool { return -false; }",
        /* 3: unary plus forbidden */
        "module n3; fn f() -> u64 { return +1; }",
        /* 4: i8 underflow: -129 */
        "module n4; fn f() -> i8 { return -129; }",
        /* 5: i64 underflow: -9223372036854775809 */
        "module n5; fn f() -> i64 { return -9223372036854775809; }",
        /* 6: -1 assigned to u8 (implicit narrow negative) */
        "module n6; fn f() -> u8 { return -1; }",
        /* 7: null returned as u64 */
        "module n7; fn f() -> u64 { return null; }",
        /* 8: null returned as bool */
        "module n8; fn f() -> bool { return null; }",
        /* 9: null returned as buf<u8> */
        "module n9; fn f() -> buf<u8> { return null; }",
        /* 10: 0 returned as record R (only null accepted, not 0) */
        "module n10; struct R { x: u64 } fn f() -> R { return 0; }",
        /* 11: null == null comparison */
        "module n11; fn f() -> bool { return null == null; }"
    };
    const char *neg_descs[] = {
        "!1 refused",
        "~true refused",
        "-false refused",
        "+1 unary plus refused",
        "i8 -129 refused",
        "i64 -9223372036854775809 refused",
        "u8 -1 refused",
        "null -> u64 refused",
        "null -> bool refused",
        "null -> buf<u8> refused",
        "0 -> record refused",
        "null == null refused"
    };

    int num_negs = (int)(sizeof(neg_srcs) / sizeof(neg_srcs[0]));
    for (int i = 0; i < num_negs; i++) {
        cases++;
        NtFInput in_neg = { "neg_unary.nova", neg_srcs[i], strlen(neg_srcs[i]) };
        CHECK(!nova_check_many_v2(&in_neg, 1, NULL), neg_descs[i]);
        Tree t_neg;
        int ok_neg = parse(&t_neg, neg_srcs[i], 0);
        CHECK(ok_neg == 1, "A8_UNARY negative parse returned cleanly");
        if (ok_neg == 1) {
            CHECK(t_neg.r.runtime == 0, "A8_UNARY negative no runtime fault");
            CHECK(t_neg.code != 0, "A8_UNARY negative candidate rejected");
            CHECK(t_neg.node_count == 0, "A8_UNARY negative published empty tree");
            free_tree(&t_neg);
        }
    }

    /* Unary recursion depth tests: 8 accepted, 130 rejected with E_TOO_SMALL (812) */
    char udepth_buf[512];
    int udepths[2] = { 8, 130 };
    for (int d_idx = 0; d_idx < 2; d_idx++) {
        cases++;
        int n_bangs = udepths[d_idx];
        size_t off = 0;
        int n = snprintf(udepth_buf + off, sizeof(udepth_buf) - off, "module ud%d; fn f() -> bool { return ", n_bangs);
        if (n < 0 || (size_t)n >= sizeof(udepth_buf) - off) { CHECK(0, "A8_UNARY depth formatting failed"); return; }
        off += (size_t)n;

        for (int b = 0; b < n_bangs; b++) {
            if (off + 1 >= sizeof(udepth_buf)) { CHECK(0, "A8_UNARY depth buffer exhausted"); return; }
            udepth_buf[off++] = '!';
        }
        n = snprintf(udepth_buf + off, sizeof(udepth_buf) - off, "true; }\n");
        if (n < 0 || (size_t)n >= sizeof(udepth_buf) - off) { CHECK(0, "A8_UNARY depth formatting failed"); return; }
        off += (size_t)n;

        NtFInput in_d = { "udepth.nova", udepth_buf, off };
        if (n_bangs == 8) {
            CHECK(nova_check_many_v2(&in_d, 1, NULL), "A8_UNARY C reference accepts unary depth 8");
            Tree t_d;
            int ok_d = parse(&t_d, udepth_buf, 0);
            CHECK(ok_d == 1, "A8_UNARY parse(8) returned cleanly");
            if (ok_d == 1) {
                CHECK(t_d.r.runtime == 0, "A8_UNARY candidate 8 no runtime fault");
                CHECK(t_d.code == 0, "A8_UNARY candidate 8 accepted");
                CHECK(t_d.node_count > 0, "A8_UNARY candidate 8 published tree");
                free_tree(&t_d);
            }
        } else {
            CHECK(!nova_check_many_v2(&in_d, 1, NULL), "A8_UNARY C reference rejects unary depth 130");
            Tree t_d;
            int ok_d = parse(&t_d, udepth_buf, 0);
            CHECK(ok_d == 1, "A8_UNARY parse(130) returned cleanly");
            if (ok_d == 1) {
                CHECK(t_d.r.runtime == 0, "A8_UNARY candidate 130 no runtime fault");
                CHECK(t_d.code == 812, "A8_UNARY candidate 130 rejected with E_TOO_SMALL (812)");
                CHECK(t_d.node_count == 0, "A8_UNARY candidate 130 published empty tree");
                free_tree(&t_d);
            }
        }
    }

    /* Clean replay of standard PROGRAM */
    cases++;
    Tree t_clean;
    int ok_clean = parse(&t_clean, PROGRAM, 0);
    CHECK(ok_clean == 1, "A8_UNARY clean replay parse returned cleanly");
    if (ok_clean == 1) {
        CHECK(t_clean.r.runtime == 0, "A8_UNARY clean replay no runtime fault");
        CHECK(t_clean.code == 0, "A8_UNARY clean replay succeeds");
        CHECK(t_clean.node_count > 0, "A8_UNARY clean replay published tree");
        free_tree(&t_clean);
    }
}

static void test_a8_token_ownership_lifecycle(void) {
    cases++;
    CHECK(g_image != NULL, "A8_TOK_LIFE g_image host image pointer available");
    if (g_image == NULL) return;

    char *src_valid = (char *)malloc(8192);
    CHECK(src_valid != NULL, "A8_TOK_LIFE valid source buffer allocated");
    char *src_invalid = (char *)malloc(8192);
    CHECK(src_invalid != NULL, "A8_TOK_LIFE invalid source buffer allocated");
    uint64_t *scratch = (uint64_t *)malloc(WORDS * sizeof(uint64_t));
    CHECK(scratch != NULL, "A8_TOK_LIFE scratch allocated");

    if (!src_valid || !src_invalid || !scratch) {
        if (src_valid) free(src_valid);
        if (src_invalid) free(src_invalid);
        if (scratch) free(scratch);
        return;
    }

    size_t off_v = 0;
    int n = snprintf(src_valid + off_v, 8192 - off_v, "module life_v;\nfn f() -> u64 {\n    let mut x: u64 = 0;\n");
    if (n < 0 || (size_t)n >= 8192 - off_v) { CHECK(0, "A8_TOK_LIFE valid header format failed"); goto cleanup; }
    off_v += (size_t)n;
    for (int i = 0; i < 200; i++) {
        n = snprintf(src_valid + off_v, 8192 - off_v, "    x = x + 1;\n");
        if (n < 0 || (size_t)n >= 8192 - off_v) { CHECK(0, "A8_TOK_LIFE valid stmt format failed"); goto cleanup; }
        off_v += (size_t)n;
    }
    n = snprintf(src_valid + off_v, 8192 - off_v, "    return x;\n}\n");
    if (n < 0 || (size_t)n >= 8192 - off_v) { CHECK(0, "A8_TOK_LIFE valid footer format failed"); goto cleanup; }
    off_v += (size_t)n;

    size_t off_iv = 0;
    n = snprintf(src_invalid + off_iv, 8192 - off_iv, "module life_iv;\nfn f() -> u64 {\n    let mut x: u64 = 0;\n");
    if (n < 0 || (size_t)n >= 8192 - off_iv) { CHECK(0, "A8_TOK_LIFE invalid header format failed"); goto cleanup; }
    off_iv += (size_t)n;
    for (int i = 0; i < 200; i++) {
        n = snprintf(src_invalid + off_iv, 8192 - off_iv, "    x = x + 1;\n");
        if (n < 0 || (size_t)n >= 8192 - off_iv) { CHECK(0, "A8_TOK_LIFE invalid stmt format failed"); goto cleanup; }
        off_iv += (size_t)n;
    }
    n = snprintf(src_invalid + off_iv, 8192 - off_iv, "    return unknown_missing_name;\n}\n");
    if (n < 0 || (size_t)n >= 8192 - off_iv) { CHECK(0, "A8_TOK_LIFE invalid footer format failed"); goto cleanup; }
    off_iv += (size_t)n;

    NtFInput in_v = { "life_v.nova", src_valid, off_v };
    CHECK(nova_check_many_v2(&in_v, 1, NULL), "A8_TOK_LIFE C reference accepts valid 200-statement source");
    NtFInput in_iv = { "life_iv.nova", src_invalid, off_iv };
    CHECK(!nova_check_many_v2(&in_iv, 1, NULL), "A8_TOK_LIFE C reference rejects invalid 200-statement source");

    NovaContextV2 ctx = {0};
    int c_ok = nova_context_init_v2(&ctx);
    CHECK(c_ok == 1, "A8_TOK_LIFE single shared context initialized");
    if (c_ok == 1) {
        uint64_t sh_v = nova_borrow_v2(&ctx, (void *)src_valid, off_v, 0);
        uint64_t sh_iv = nova_borrow_v2(&ctx, (void *)src_invalid, off_iv, 0);
        uint64_t n1 = nova_borrow_v2(&ctx, scratch, NODES * 8, 1);
        uint64_t n2 = nova_borrow_v2(&ctx, scratch + NODES, SIDES * 8, 1);
        uint64_t n3 = nova_borrow_v2(&ctx, scratch + NODES + SIDES, BINDS * 8, 1);
        uint64_t n4 = nova_borrow_v2(&ctx, scratch + NODES + SIDES + BINDS, FIELDS * 8, 1);
        uint64_t oh = nova_borrow_v2(&ctx, scratch + NODES + SIDES + BINDS + FIELDS, OUTW * 8, 1);

        CHECK(ctx.error == 0, "A8_TOK_LIFE borrows completed without context error");
        CHECK(sh_v != 0 && sh_iv != 0 && n1 != 0 && n2 != 0 && n3 != 0 && n4 != 0 && oh != 0,
              "A8_TOK_LIFE all initial borrow handles non-zero");

        uint64_t *out = scratch + NODES + SIDES + BINDS + FIELDS;
        int completed = 0;

        for (int iter = 0; iter < 100; iter++) {
            int is_valid = (iter % 2 == 0);
            uint64_t sh = is_valid ? sh_v : sh_iv;
            size_t slen = is_valid ? off_v : off_iv;
            uint64_t expected_ret = is_valid ? 0 : 803;

            for (size_t g = 0; g < WORDS; g++) scratch[g] = GUARD;
            uint64_t args[SLOTS] = { sh, (uint64_t)slen, n1, NODES, n2, SIDES, n3, BINDS, n4, FIELDS, oh, OUTW, 0 };
            uint64_t ret = g_image->entry(&ctx, args, SLOTS);

            if (ctx.error != 0) {
                fprintf(stderr, "A8_TOK_LIFE failed at iteration %d with runtime error %llu\n", iter, (unsigned long long)ctx.error);
                CHECK(ctx.error == 0, "A8_TOK_LIFE context runtime error during lifecycle loop");
                break;
            }
            if (ret != expected_ret) {
                fprintf(stderr, "A8_TOK_LIFE failed at iteration %d with entry return %llu (expected %llu)\n", iter, (unsigned long long)ret, (unsigned long long)expected_ret);
                CHECK(ret == expected_ret, "A8_TOK_LIFE entry return matches expected code");
                break;
            }

            if (is_valid) {
                if (out[0] != 0 || out[5] == 0) {
                    fprintf(stderr, "A8_TOK_LIFE valid iteration %d returned out[0]=%llu out[5]=%llu\n", iter, (unsigned long long)out[0], (unsigned long long)out[5]);
                    CHECK(out[0] == 0, "A8_TOK_LIFE valid iteration returned parse code 0");
                    CHECK(out[5] > 0, "A8_TOK_LIFE valid iteration published node_count > 0");
                    break;
                }
            } else {
                if (out[0] != 803 || out[5] != 0) {
                    fprintf(stderr, "A8_TOK_LIFE invalid iteration %d returned out[0]=%llu out[5]=%llu\n", iter, (unsigned long long)out[0], (unsigned long long)out[5]);
                    CHECK(out[0] == 803, "A8_TOK_LIFE invalid iteration returned 803 UNDECLARED");
                    CHECK(out[5] == 0, "A8_TOK_LIFE invalid iteration published empty tree");
                    break;
                }
            }
            completed++;
        }

        CHECK(completed == 100, "A8_TOK_LIFE completed all 100 iterations in single context");
        CHECK(nova_context_destroy_v2(&ctx), "A8_TOK_LIFE single context cleanup succeeded");
    }

cleanup:
    free(src_valid);
    free(src_invalid);
    free(scratch);
}

static void test_a8_contextual_keywords(void) {
    /* Positive table: keyword-spelled names as variables, functions, and struct members */
    struct {
        const char *src;
        const char *desc;
    } pos_cases[] = {
        /* 0: local variable named 'export' used in expression */
        { "module ck0; fn f() -> buf<u8> { let export: buf<u8> = \"export\"; return export; }", "local variable named export" },
        /* 1: local variable named 'while' */
        { "module ck1; fn f() -> u64 { let while: u64 = 10; return while; }", "local variable named while" },
        /* 2: local variable named 'struct' */
        { "module ck2; fn f() -> u64 { let struct: u64 = 20; return struct; }", "local variable named struct" },
        /* 3: local variable named 'let' */
        { "module ck3; fn f() -> u64 { let let: u64 = 30; return let; }", "local variable named let" },
        /* 4: function named 'export' called directly */
        { "module ck4; fn export() -> u64 { return 42; } fn f() -> u64 { return export(); }", "function named export called" },
        /* 5: struct field named 'export' accessed */
        { "module ck5; struct S { export: u64 } fn f(s: S) -> u64 { return s.export; }", "struct field named export" }
    };

    int num_pos = (int)(sizeof(pos_cases) / sizeof(pos_cases[0]));
    for (int i = 0; i < num_pos; i++) {
        cases++;
        NtFInput in = { "ck_pos.nova", pos_cases[i].src, strlen(pos_cases[i].src) };
        CHECK(nova_check_many_v2(&in, 1, NULL), pos_cases[i].desc);
        Tree t;
        int ok = parse(&t, pos_cases[i].src, 0);
        CHECK(ok == 1, "A8_CTX_KW positive parse returned cleanly");
        if (ok == 1) {
            CHECK(t.r.runtime == 0, "A8_CTX_KW positive no runtime fault");
            CHECK(t.code == 0, "A8_CTX_KW positive candidate accepted");
            CHECK(t.node_count > 0, "A8_CTX_KW positive published tree");
            free_tree(&t);
        }
    }

    /* Negative table: standalone bare keyword in expression position without binding */
    const char *neg_srcs[] = {
        /* 0: bare export without declaration */
        "module n0; fn f() -> u64 { return export; }",
        /* 1: bare while without declaration */
        "module n1; fn f() -> u64 { return while; }",
        /* 2: bare struct without declaration */
        "module n2; fn f() -> u64 { return struct; }"
    };
    const char *neg_descs[] = {
        "bare undeclared export refused",
        "bare undeclared while refused",
        "bare undeclared struct refused"
    };

    int num_negs = (int)(sizeof(neg_srcs) / sizeof(neg_srcs[0]));
    for (int i = 0; i < num_negs; i++) {
        cases++;
        NtFInput in_neg = { "ck_neg.nova", neg_srcs[i], strlen(neg_srcs[i]) };
        CHECK(!nova_check_many_v2(&in_neg, 1, NULL), neg_descs[i]);
        Tree t_neg;
        int ok_neg = parse(&t_neg, neg_srcs[i], 0);
        CHECK(ok_neg == 1, "A8_CTX_KW negative parse returned cleanly");
        if (ok_neg == 1) {
            CHECK(t_neg.r.runtime == 0, "A8_CTX_KW negative no runtime fault");
            CHECK(t_neg.code != 0, "A8_CTX_KW negative candidate rejected");
            CHECK(t_neg.node_count == 0, "A8_CTX_KW negative published empty tree");
            free_tree(&t_neg);
        }
    }

    /* Clean replay of standard PROGRAM */
    cases++;
    Tree t_clean;
    int ok_clean = parse(&t_clean, PROGRAM, 0);
    CHECK(ok_clean == 1, "A8_CTX_KW clean replay parse returned cleanly");
    if (ok_clean == 1) {
        CHECK(t_clean.r.runtime == 0, "A8_CTX_KW clean replay no runtime fault");
        CHECK(t_clean.code == 0, "A8_CTX_KW clean replay succeeds");
        CHECK(t_clean.node_count > 0, "A8_CTX_KW clean replay published tree");
        free_tree(&t_clean);
    }
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);

  char *sources[PATHS_N] = {0};
  NtFInput inputs[PATHS_N];
  for (unsigned i = 0; i < PATHS_N; i++) {
    size_t length = 0;
    sources[i] = loadf(PATHS[i], &length);
    inputs[i] = (NtFInput){PATHS[i], sources[i], length};
  }
  int loaded = 1;
  for (unsigned i = 0; i < PATHS_N; i++) if (!sources[i]) loaded = 0;
  CHECK(loaded, "Nova sources load");
  if (!loaded) {
    for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);
    printf("NTASM_NOVA_NOVA_LANGUAGE_PARSE checks=%u failures=%u cases=%u\n",
           checks, failures, 0);
    return 2;
  }

  /* TWO compiles into two artifacts and the image is mapped from the FIRST.
   * The second is the run-race check: if the artifact bytes differ, every count
   * this gate prints is a count over a coin flip. */
  NtArtifact first = {0}, second = {0};
  int c1 = nova_compile_many_v2(inputs, PATHS_N, &first);
  CHECK(c1, "modules compile");
  if (!c1) {
    fprintf(stderr, "E%u %zu:%zu %s\n", first.error.code, first.error.line,
            first.error.column, first.error.message);
    for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);
    printf("NTASM_NOVA_NOVA_LANGUAGE_PARSE checks=%u failures=%u cases=%u\n",
           checks, failures, 0);
    return 2;
  }
  int c2 = nova_compile_many_v2(inputs, PATHS_N, &second);
  CHECK(c2, "modules compile twice");
  CHECK(first.text.size == second.text.size, "two compiles agree on text size");
  CHECK(first.text.size == second.text.size &&
            memcmp(first.text.bytes, second.text.bytes, first.text.size) == 0,
        "two compiles agree on every text byte");

  NovaHostImage image = {0};
  CHECK(nova_host_map(&first, &image), "image maps");
  if (!image.memory) {
    for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);
    printf("NTASM_NOVA_NOVA_LANGUAGE_PARSE checks=%u failures=%u cases=%u\n",
           checks, failures, 0);
    return 2;
  }
  g_image = &image;

  /* ---- 0. THE ARGC SWEEP, and it is what establishes thirteen ------------
   * Every count from 1 to 16 is called against this exact entry, each in its
   * OWN context, because a handle does not outlive the context that made it.
   * A count is "running" when the host raised no runtime error -- so a count
   * that reached the body and a count that returned cleanly are both runs, and
   * a count refused at the boundary with NV2_ARGUMENT is not. The count that
   * runs is the entry's flat slot count; the sweep is what measures it, and
   * the arithmetic in run()'s comment is only a prediction of the answer. */
  {
    uint64_t *w = malloc((size_t)WORDS * 8);
    CHECK(w != NULL, "sweep scratch");
    unsigned runs = 0, running_argc = 0;
    if (w) {
      for (unsigned argc = 1; argc <= 16; argc++) {
        for (unsigned i = 0; i < WORDS; i++) w[i] = GUARD;
        NovaContextV2 cc = {0};
        if (!nova_context_init_v2(&cc)) break;
        uint64_t s2 = nova_borrow_v2(&cc, (void *)PROGRAM, strlen(PROGRAM), 0);
        uint64_t a1 = nova_borrow_v2(&cc, w, NODES * 8, 1);
        uint64_t a2 = nova_borrow_v2(&cc, w + NODES, SIDES * 8, 1);
        uint64_t a3 = nova_borrow_v2(&cc, w + NODES + SIDES, BINDS * 8, 1);
        uint64_t a4 = nova_borrow_v2(&cc, w + NODES + SIDES + BINDS, FIELDS * 8, 1);
        uint64_t o2 = nova_borrow_v2(&cc, w + NODES + SIDES + BINDS + FIELDS,
                                     OUTW * 8, 1);
        uint64_t args[16] = {s2, strlen(PROGRAM), a1, NODES, a2, SIDES, a3,
                             BINDS, a4, FIELDS, o2, OUTW, 0, 0, 0, 0};
        image.entry(&cc, args, argc);
        if (cc.error == 0) { runs++; running_argc = argc; }
        CHECK(nova_context_destroy_v2(&cc), "sweep context destroy");
      }
      /* ONE count runs. If two did, the signature would be ambiguous and every
       * case below would be reading a call the host had not validated. */
      CHECK(runs == 1, "exactly one slot count runs");
      CHECK(running_argc == SLOTS, "the running count is the one this gate packs");
      printf("NOVA_LANGUAGE_PARSE_ARGC runs=%u at=%u of 16\n", runs, running_argc);
      free(w);
    }
  }

  /* ---- 1. THE MODULE'S OWN NUMBERS, read back through mode 3 ------------- */
  {
    Tree t;
    CHECK(parse(&t, "", 3), "mode 3 parse");
    CHECK(t.r.runtime == 0, "mode 3 ran without a runtime fault");
    /* THE LAYOUT IS SHAPE_READ_BACK'S, AND IT HAS FOUR GROUPS IN IT: the two
     * strides, the four codes, the four reasons, the four classes and then the
     * twenty kinds. An earlier version read the kinds from words 6..15, which
     * are the REASONS and the CLASSES -- so every kind compared against a
     * register-class number and the whole tree read as the wrong shape while
     * the counts stayed plausible. The offsets below are the module's. */
    g_node_words = t.out[0];
    g_result_words = t.out[1];
    E_UNCLOSED = t.out[2];  E_USE_BEFORE = t.out[3];
    E_NOT_CARRYABLE = t.out[4]; E_UNDECLARED = t.out[5];
    REG_NONE = t.out[10]; REG_VALUE = t.out[11]; REG_ADDRESS = t.out[12]; REG_PREDICATE = t.out[13];
    K_MODULE = t.out[14];  K_STRUCT = t.out[15];      K_FIELD = t.out[16];
    K_FN = t.out[17];      K_PARAM = t.out[18];       K_RETURN_NODE = t.out[19];
    K_BLOCK = t.out[20];   K_LET = t.out[21];         K_ASSIGN = t.out[22];
    K_RETURN_STMT = t.out[23]; K_WHILE = t.out[24];  K_NAME = t.out[26];
    K_BINARY = t.out[30];
    K_LITERAL = t.out[27];
    K_FIELD_ACCESS = t.out[28];
    K_TYPE = t.out[31];
    /* The scope stride is word 34, published by the module for the same reason
     * as the node stride. It is READ rather than assumed because scope_parent
     * below indexes with it: a literal 3 here would read the right number off a
     * stale table and the chain walk would pass on a chain it never walked. */
    g_scope_words = t.out[34];
    CHECK(g_scope_words > 0 && t.r.returned == 38,
          "the module published the scope stride and its own word count");
    CHECK(g_node_words == 16, "the node stride is sixteen words");
    CHECK(g_result_words == 9, "the result block is nine words");
    CHECK(E_UNCLOSED != E_USE_BEFORE && E_USE_BEFORE != E_NOT_CARRYABLE &&
              E_NOT_CARRYABLE != E_UNDECLARED,
          "the four refusal codes are four different numbers");
    CHECK(K_MODULE != K_STRUCT && K_STRUCT != K_FN && K_FN != K_BLOCK,
          "the node kinds are distinct");
    printf("NOVA_LANGUAGE_PARSE_SHAPE node_words=%llu result_words=%llu "
           "codes=%llu/%llu/%llu/%llu\n",
           (unsigned long long)g_node_words, (unsigned long long)g_result_words,
           (unsigned long long)E_UNCLOSED, (unsigned long long)E_USE_BEFORE,
           (unsigned long long)E_NOT_CARRYABLE,
           (unsigned long long)E_UNDECLARED);
    free_tree(&t);
  }

  /* ---- 2. THE POSITIVE: the program parses ------------------------------ */
  Tree t;
  cases++;
  CHECK(parse(&t, PROGRAM, 0), "scratch malloc");
  CHECK(t.r.runtime == 0, "the program runs without a runtime fault");
  CHECK(t.code == 0, "the program parses");
  if (t.code != 0)
    fprintf(stderr, "FAIL the program parses: code %llu reason %llu at %llu:%llu\n",
            (unsigned long long)t.code, (unsigned long long)t.reason,
            (unsigned long long)t.line, (unsigned long long)t.column);
  CHECK(t.r.returned == 0, "parse returns 0 on success");
  CHECK(t.node_count > 0, "the program produces nodes");
  CHECK(t.root == 1, "the module node is the root");
  CHECK(t.scope_count >= 5, "the program opens at least five scopes");
  CHECK(t.bind_count >= 4, "the program binds at least four names");
  CHECK(t.line == 0 && t.column == 0,
        "a successful parse publishes no error position");
  printf("NOVA_LANGUAGE_PARSE_TREE nodes=%llu root=%llu scopes=%llu binds=%llu\n",
         (unsigned long long)t.node_count, (unsigned long long)t.root,
         (unsigned long long)t.scope_count, (unsigned long long)t.bind_count);

  /* ---- 3. THE TREE HAS THE KINDS THE SOURCE SAYS ----------------------- */
  /* module -> [struct -> [field, field], fn -> [param, return, block]]
   * The two declarations are SIBLINGS: an earlier version read the first
   * child and then expected the second to live inside it, which is the shape
   * of a tree where one declaration CONTAINS the next -- a shape no parser
   * builds and a shape this gate was asserting. */
  {
    uint64_t first = node_word(&t, t.root, 2);   /* first_child */
    uint64_t second = node_word(&t, first, 4);    /* next_sibling */
    CHECK(node_word(&t, first, 0) == K_STRUCT, "child 1 is a struct");
    CHECK(node_word(&t, second, 0) == K_FN, "child 2 is a function");
    /* the struct's two fields */
    uint64_t f0 = node_word(&t, first, 2);
    uint64_t f1 = node_word(&t, f0, 4);
    CHECK(node_word(&t, f0, 0) == K_FIELD, "struct child 1 is a field");
    CHECK(node_word(&t, f1, 0) == K_FIELD, "struct child 2 is a field");
    CHECK(node_word(&t, f1, 4) == 0, "the second field is the last sibling");
    /* BOTH fields carry width 64 and the VALUE class: `count:u64` and
     * `limit:u64`. This is the lattice ON THE NODE, not a later inference. */
    CHECK(node_word(&t, f0, 9) == 64, "field 1 carries width 64");
    CHECK(node_word(&t, f1, 9) == 64, "field 2 carries width 64");
    CHECK(node_word(&t, f0, 10) == REG_VALUE, "field 1 carries class VALUE");
    /* THE STRUCT ITSELF CARRIES NO WIDTH. A record has no width until a layout
     * is computed, and the module says so rather than inventing one. */
    CHECK(node_word(&t, first, 9) == 0, "a struct node carries no width");
    CHECK(node_word(&t, first, 10) == REG_NONE, "a struct node carries no class");
  }
  /* the function's parameter, return type and body */
  {
    uint64_t fn = node_word(&t, t.root, 2);
    fn = node_word(&t, fn, 4);
    CHECK(node_word(&t, fn, 0) == K_FN, "the function node");
    CHECK(node_word(&t, fn, 13) == 1, "the function is `export`");
    uint64_t param = node_word(&t, fn, 2);
    uint64_t ret = node_word(&t, param, 4);
    uint64_t body = node_word(&t, ret, 4);
    CHECK(node_word(&t, param, 0) == K_PARAM, "child 1 is a parameter");
    CHECK(node_word(&t, ret, 0) == K_RETURN_NODE, "child 2 is the return type");
    CHECK(node_word(&t, body, 0) == K_BLOCK, "child 3 is the body block");
    CHECK(node_word(&t, body, 4) == 0, "the body is the last child");
    /* `bound:u64` and `-> u64`: width 64 on both, VALUE on both. */
    CHECK(node_word(&t, param, 9) == 64, "the parameter carries width 64");
    CHECK(node_word(&t, param, 10) == REG_VALUE, "the parameter is a VALUE");
    CHECK(node_word(&t, ret, 9) == 64, "the return type carries width 64");
    CHECK(node_word(&t, ret, 10) == REG_VALUE, "the return type is a VALUE");
    /* a scalar parameter occupies ONE ABI slot */
    CHECK(node_word(&t, param, 13) == 1, "a scalar parameter is one slot");

    /* ---- 4. THE NESTING, which is the property a table cannot have ------- */
    /* body -> [let total, let outer, while, return] */
    uint64_t l0 = node_word(&t, body, 2);
    uint64_t l1 = node_word(&t, l0, 4);
    uint64_t wh = node_word(&t, l1, 4);
    uint64_t rs = node_word(&t, wh, 4);
    CHECK(node_word(&t, l0, 0) == K_LET, "body child 1 is a `let`");
    CHECK(node_word(&t, l1, 0) == K_LET, "body child 2 is a `let`");
    CHECK(node_word(&t, wh, 0) == K_WHILE, "body child 3 is a `while`");
    CHECK(node_word(&t, rs, 0) == K_RETURN_STMT, "body child 4 is a `return`");
    CHECK(node_word(&t, rs, 4) == 0, "the return is the last statement");
    /* `let mut total` -> aux carries MUT, and only `mut` does. */
    CHECK(node_word(&t, l0, 13) == 5, "`let mut` records MUT");
    CHECK(node_word(&t, l1, 13) == 3, "a plain `let` records LET");
    /* THE WHILE'S CONDITION IS A COMPARISON, so it is a PREDICATE of width 8.
     * `while total` with no comparison would be 802 -- see section 5. */
    uint64_t cond = node_word(&t, wh, 2);
    CHECK(node_word(&t, cond, 0) == K_BINARY, "the while condition is a binary");
    CHECK(node_word(&t, cond, 10) == REG_PREDICATE,
          "a comparison is a predicate");
    CHECK(node_word(&t, wh, 10) == REG_PREDICATE, "the while is a predicate");
    /* while -> [condition, block] and that block -> [block] and THAT block ->
     * [let, assign]. THREE levels of nesting, which is the claim. */
    uint64_t outer_block = node_word(&t, wh, 2);
    outer_block = node_word(&t, outer_block, 4);
    CHECK(node_word(&t, outer_block, 0) == K_BLOCK, "the while body is a block");
    uint64_t inner_block = node_word(&t, outer_block, 2);
    CHECK(node_word(&t, inner_block, 0) == K_BLOCK,
          "inside it is a second block: nested, not one level");
    uint64_t inner_let = node_word(&t, inner_block, 2);
    uint64_t inner_assign = node_word(&t, inner_let, 4);
    CHECK(node_word(&t, inner_let, 0) == K_LET, "the inner block's first child");
    CHECK(node_word(&t, inner_assign, 0) == K_ASSIGN,
          "the inner block's second child is an assignment");
    /* `total = total + outer`: [assign] -> [name total] and [binary] */
    uint64_t body_scope = block_own_scope(&t, body);
    uint64_t target = node_word(&t, inner_assign, 2);
    uint64_t value = node_word(&t, target, 4);
    CHECK(node_word(&t, target, 0) == K_NAME, "the assign target is a name");
    CHECK(node_word(&t, value, 0) == K_BINARY, "the assign value is a binary");
    CHECK(node_word(&t, value, 13) == 43, "the operator is `+`");

    /* ---- 5. THE SCOPE CHAIN AND THE SHADOWING --------------------------- */
    /* Four distinct scopes are open at the point of the inner `let outer`:
     * the module scope, the function scope, the while-body scope, and the
     * inner block's own. THE INNER BLOCK'S SCOPE ID DIFFERS FROM ITS
     * PARENT'S -- that difference is the shadowing, made visible.
     *
     * EACH IS THE SCOPE THAT CONSTRUCT OPENS, read from a node inside it and
     * not from the construct's own node: a BLOCK node carries the scope it was
     * PARSED IN, because the module allocates it before open_scope runs. So
     * `fn_scope` and `body_scope` used to be the SAME read of the SAME word --
     * two names for one number -- and the check below then compared a name that
     * resolved in scope 3 against scope 2 and named the difference a resolution
     * failure. Four distinct numbers are also not enough on their own: a chain
     * of four unrelated ids satisfies every `!=` above. The parent links are
     * what make it a chain, so those are walked below. */
    uint64_t inner_scope = block_own_scope(&t, inner_block);
    uint64_t outer_scope = block_own_scope(&t, outer_block);
    uint64_t fn_scope = block_own_scope(&t, body);
    /* The module's OWN scope, read the same way -- from a node inside it. The
     * module node's own word 7 is 0, because the module node is allocated
     * before parse_module opens its scope, and 0 is "no scope", not "the
     * module scope". An earlier version took mod_scope as 0 and then asked
     * whether the inner scope descends from it; nothing descends from 0, so
     * that check could never pass. */
    uint64_t mod_scope = block_own_scope(&t, t.root);
    CHECK(inner_scope != outer_scope, "the inner block opens its own scope");
    CHECK(outer_scope != fn_scope, "the while body opens its own scope");
    CHECK(fn_scope != mod_scope, "the function opens its own scope");
    CHECK(inner_scope > outer_scope && outer_scope > fn_scope &&
              fn_scope > mod_scope,
          "the scope ids are nested in the order they were opened");
    /* AND THE IDS ARE A CHAIN, not four numbers that happen to differ. Each
     * scope's parent link points at the one enclosing it, read out of the
     * module's own scope table at its own published stride. A parser that
     * resolved EVERYTHING to one scope, or that numbered scopes without linking
     * them, fails here and would pass every `!=` above. */
    CHECK(scope_parent(&t, inner_scope) == outer_scope,
          "the inner block's scope links to the while body's");
    CHECK(scope_parent(&t, outer_scope) == fn_scope,
          "the while body's scope links to the function body's");
    /* AND THE FUNCTION OPENS A SCOPE OF ITS OWN, one between the module's and
     * the body's: the module opens one, parse_fn opens one for the parameters
     * so a parameter shares a scope with the body's outermost local, and the
     * body block opens a third. FIVE scopes for this program and the chain
     * walks all five. An earlier version asked whether the body's scope parented
     * straight to the MODULE's, which skipped the function's own scope and
     * compared two ids two links apart -- and named that difference a broken
     * chain, when the chain was intact. */
    uint64_t fn_own_scope = scope_parent(&t, fn_scope);
    CHECK(fn_own_scope != 0 && fn_own_scope != mod_scope,
          "the function opens a scope between the module's and the body's");
    CHECK(scope_parent(&t, fn_own_scope) == mod_scope,
          "the function's own scope links to the module's");
    CHECK(scope_parent(&t, mod_scope) == 0,
          "the module's scope has no parent: it terminates the chain");
    CHECK(scope_is_ancestor(&t, mod_scope, inner_scope),
          "the inner scope descends from the module scope");
    /* AND NOT FROM ITSELF: the walk must be a real walk, so a scope is not its
     * own ancestor. Without this, a chain whose every parent link pointed at
     * the root would satisfy every check above. */
    CHECK(!scope_is_ancestor(&t, inner_scope, inner_scope),
          "a scope is not its own ancestor");

    /* THE SHADOWED DECLARATION. Two `let outer` nodes exist, in two scopes,
     * with two different binding ordinals -- and the USE of `outer` inside the
     * inner block resolved to the INNER one, which is what shadowing means. */
    uint64_t outer_decl_outer = l1;                 /* `let outer` at line 10 */
    CHECK(node_word(&t, outer_decl_outer, 15) != node_word(&t, inner_let, 15),
          "the two `outer` declarations are different bindings");
    /* the right operand of the inner `+` is a NAME that resolved in the INNER
     * scope, not the outer one */
    uint64_t left = node_word(&t, value, 2);
    uint64_t right = node_word(&t, left, 4);
    CHECK(node_word(&t, right, 0) == K_NAME, "the right operand is a name");
    CHECK(node_word(&t, right, 8) == inner_scope,
          "the shadowed use resolved in the INNER scope");
    CHECK(node_word(&t, right, 8) != node_word(&t, outer_decl_outer, 7),
          "the shadowed use did NOT resolve in the outer scope");
    CHECK(node_word(&t, right, 15) == node_word(&t, inner_let, 15),
          "the use and the inner declaration share a binding ordinal");
    /* and the width came FROM the binding: `outer:u64` is 64 */
    CHECK(node_word(&t, right, 9) == 64, "the shadowed use carries width 64");

    /* `total` was declared ONCE, in the function body's scope, and its uses --
     * the assignment target and the left operand of the `+` -- both resolved
     * there. That is the ordinary case and it is checked beside the shadowed
     * one so a parser that resolved EVERYTHING to the innermost scope would
     * pass the shadow case and fail this.
     *
     * AND IT RESOLVED THREE SCOPES OUT, WHICH IS THE PROPERTY, so it is
     * asserted as DISTANCE and not as an id. Three facts, and each one alone
     * would pass a parser that got the others wrong:
     *   - the use's OWN scope is the inner block's (where the text sits),
     *   - the scope it RESOLVED in is the body's (where `total` was declared),
     *   - and the body's scope is a strict ANCESTOR of the inner block's, two
     *     links up the chain the module published.
     * A parser that resolved every name to the innermost scope fails the second;
     * one that resolved every name to the outermost fails the second too; one
     * that numbered scopes without linking them fails the third. */
    CHECK(node_word(&t, target, 7) == inner_scope,
          "the use of `total` sits in the inner block's own scope");
    CHECK(node_word(&t, target, 8) == body_scope,
          "`total` resolved in the body's scope, three scopes out");
    CHECK(scope_is_ancestor(&t, body_scope, node_word(&t, target, 7)),
          "the scope it resolved in is an ANCESTOR of the scope it sits in");
    CHECK(node_word(&t, target, 8) != node_word(&t, target, 7),
          "and it is not the innermost scope: the chain was walked");
    CHECK(node_word(&t, target, 15) == node_word(&t, l0, 15),
          "both uses of `total` share one binding ordinal");
    /* AND THE DECLARATION IS IN THAT SCOPE, read from the `let mut total`
     * itself. This is what makes "the body's scope" mean the scope the
     * declaration lives in rather than a number the harness chose. */
    CHECK(node_word(&t, l0, 7) == body_scope,
          "`total` is declared in that same scope");

    /* ---- THE THREE RESOLUTION SHAPES, AS THREE DIFFERENT ANSWERS --------
     * This program contains one of each and they must be told apart. Asserting
     * them one at a time is not enough, and this gate has already had the
     * defect: three checks that each pass against a parser which resolved
     * EVERY name to one fixed scope, because such a parser is self-consistent
     * with itself. What rules that out is that the three answers are not the
     * same answer -- so all three are read and required to be pairwise
     * different, each off a DIFFERENT node. Two shapes read off one node are
     * one shape with two names.
     *
     *   (1) OWN SCOPE    `bound` in `let outer:u64 = bound`. The parameter is
     *                     declared by the parameter list, in the FUNCTION's own
     *                     scope, and used in the body block's scope. It
     *                     resolves where it was DECLARED -- one link up, and
     *                     NOT the scope it sits in.
     *   (2) ENCLOSING    `total` on the left of the inner `+`: declared in the
     *                     body's scope, used in the inner block's. Checked
     *                     above, and it is the one that was failing.
     *   (3) SHADOWING    the `outer` on the right of that same `+`: declared
     *                     twice, and this use must find the INNER one.
     *
     * MEASURED, and (1) is not what its first draft claimed: an earlier
     * version asserted the parameter resolved in the body block's own scope,
     * on the reasoning that the body block's scope is where the body was
     * parsed. The executed tree says otherwise -- it resolves in scope 2 while
     * the use sits in scope 3 -- because parse_fn opens a scope for the
     * parameters, so a parameter shares a scope with the body's outermost
     * local and NOT with the body's block. The three DISTINCT answers are the
     * property, and they are 2, 3 and 5. */
    uint64_t bound_use = node_word(&t, l1, 2);
    uint64_t own_block = node_word(&t, bound_use, 8);
    uint64_t enclosing_block = node_word(&t, target, 8);
    uint64_t shadowing = node_word(&t, right, 8);
    CHECK(own_block != 0 && own_block != node_word(&t, bound_use, 7),
          "shape 1: a parameter resolves in its own scope, not the body's");
    CHECK(enclosing_block != own_block,
          "shape 2 resolves in a DIFFERENT scope from shape 1");
    CHECK(shadowing != own_block && shadowing != enclosing_block,
          "shape 3 resolves in a THIRD scope, different from both");
    CHECK(shadowing == inner_scope,
          "and that third scope is the inner block's own");
    printf("NOVA_LANGUAGE_PARSE_SHAPES own=%llu enclosing=%llu shadowed=%llu\n",
           (unsigned long long)own_block, (unsigned long long)enclosing_block,
           (unsigned long long)shadowing);

    /* the `return total` names the same local as the `let mut total` */
    uint64_t ret_value = node_word(&t, rs, 2);
    CHECK(node_word(&t, ret_value, 0) == K_NAME, "the return names a local");
    CHECK(node_word(&t, ret_value, 15) == node_word(&t, l0, 15),
          "the return resolved to the `let mut total` binding");
  }

  /* ---- 6. THE THREE PERTURBATIONS, THREE DISTINCT DIAGNOSTICS ---------- */
  /* First: the needles are GONE from the perturbed texts. A perturbation that
   * failed to remove what it names would leave its control green for a reason
   * that has nothing to do with the rule. */
  CHECK(strstr(PROGRAM, "return total;\n}\n") != NULL,
        "the unperturbed program has its closing braces");
  CHECK(strstr(PERTURB_UNCLOSED, "return total;\n}\n") == NULL,
        "the unclosed perturbation really removed a closing brace");
  CHECK(strstr(PERTURB_UNCLOSED, "while total < bound {") != NULL,
        "the unclosed perturbation really opens the while body");
  CHECK(strstr(PERTURB_UNCLOSED, "total = total + 1;\n\";") == NULL,
        "and that body is never closed: nothing follows its last statement");
  CHECK(strstr(PROGRAM, "let mut total:u64 = 0;") != NULL,
        "the unperturbed program declares total");
  CHECK(strstr(PERTURB_USE_BEFORE, "let early:u64 = 1;") != NULL,
        "the use-before perturbation really declares `early`");
  CHECK(strstr(PERTURB_USE_BEFORE, "= early;") != NULL,
        "and really uses it before that declaration");
  CHECK(strstr(PROGRAM, "while total < outer {") != NULL,
        "the unperturbed while has a comparison");
  CHECK(strstr(PERTURB_TYPE, "while total {") != NULL,
        "the type perturbation really replaced the comparison");

  /* And the POSITIVE CONTROL: the unperturbed program is accepted, which is
   * what makes each refusal a refusal rather than a non-acceptance. */
  {
    Tree ok;
    cases++;
    CHECK(parse(&ok, PROGRAM, 0), "control scratch");
    CHECK(ok.code == 0, "the unperturbed program is accepted");
    free_tree(&ok);
  }

  expect_refusal("an unclosed brace is refused", PERTURB_UNCLOSED, E_UNCLOSED, 1);
  expect_refusal("a use before its declaration is refused", PERTURB_USE_BEFORE,
                 E_USE_BEFORE, 2);
  expect_refusal("a type that cannot be carried is refused", PERTURB_TYPE,
                 E_NOT_CARRYABLE, 3);

  /* THE THREE DIAGNOSTICS ARE DISTINCT. Not merely "each refused": each
   * refused for its OWN reason, at its OWN place. Three codes that happened to
   * be equal, or three positions that happened to coincide, would satisfy
   * "the parser refused" and prove nothing about which rule fired. */
  {
    Tree a, b, c;
    CHECK(parse(&a, PERTURB_UNCLOSED, 0), "diag a");
    CHECK(parse(&b, PERTURB_USE_BEFORE, 0), "diag b");
    CHECK(parse(&c, PERTURB_TYPE, 0), "diag c");
    CHECK(a.code != b.code && b.code != c.code && a.code != c.code,
          "the three perturbations give three different codes");
    CHECK(a.reason != b.reason && b.reason != c.reason && a.reason != c.reason,
          "the three perturbations give three different reasons");
    CHECK(a.line != b.line || a.column != b.column,
          "the three perturbations do not all point at one place");
    /* AND each refusal left the caller's memory alone where it promised to:
     * node_count is zero, so there is no partial tree to walk. */
    CHECK(a.node_count == 0 && b.node_count == 0 && c.node_count == 0,
          "no refusal publishes a node count");
    printf("NOVA_LANGUAGE_PARSE_DIAGS unclosed=%llu:%llu/%llu "
           "use_before=%llu:%llu/%llu type=%llu:%llu/%llu\n",
           (unsigned long long)a.code, (unsigned long long)a.line,
           (unsigned long long)a.reason, (unsigned long long)b.code,
           (unsigned long long)b.line, (unsigned long long)b.reason,
           (unsigned long long)c.code, (unsigned long long)c.line,
           (unsigned long long)c.reason);
    free_tree(&a); free_tree(&b); free_tree(&c);
  }

  /* ---- 6b. A REFUSAL DEEP INSIDE, AND A CALLER THAT REUSES ITS SCRATCH ----
   * The three perturbations above all fail in the FIRST few statements, so
   * every one of them is refused while the tree is still tiny. That is the easy
   * case for "publish nothing": there was almost nothing to publish. A refusal
   * that lands after a struct, a function, a parameter, a return type, two lets
   * and three nested blocks has built a real tree first, and THAT is the one
   * that could leak a partial one. So it is run, and node_count must be 0. */
  {
    Tree deep;
    cases++;
    CHECK(parse(&deep,
                "module deep;\n"
                "struct Box { w:u64 }\n"
                "export fn f(a:u64) -> u64 {\n"
                "    let mut acc:u64 = 0;\n"
                "    let seed:u64 = a;\n"
                "    while acc < seed {\n"
                "        {\n"
                "            let inner:u64 = 1;\n"
                "            {\n"
                "                let deeper:u64 = 2;\n"
                "                acc = acc + deeper;\n"
                "            }\n"
                "            acc = acc + undeclared_name;\n"
                "        }\n"
                "    }\n"
                "    return acc;\n"
                "}\n", 0), "deep scratch");
    CHECK(deep.code == E_UNDECLARED,
          "a refusal three blocks deep is still refused");
    CHECK(deep.node_count == 0,
          "a refusal after a real tree was built publishes no node count");
    CHECK(deep.root == 0 && deep.scope_count == 0 && deep.bind_count == 0,
          "and publishes no root, no scopes and no bindings either");
    /* THE POSITIVE, so "node_count == 0" is not passing because the program was
     * refused before it built anything: the same program with the needle fixed
     * must parse, and must build a tree strictly larger than a few nodes. */
    {
      Tree okdeep;
      cases++;
      CHECK(parse(&okdeep,
                  "module deep;\n"
                  "struct Box { w:u64 }\n"
                  "export fn f(a:u64) -> u64 {\n"
                  "    let mut acc:u64 = 0;\n"
                  "    let seed:u64 = a;\n"
                  "    while acc < seed {\n"
                  "        {\n"
                  "            let inner:u64 = 1;\n"
                  "            {\n"
                  "                let deeper:u64 = 2;\n"
                  "                acc = acc + deeper;\n"
                  "            }\n"
                  "            acc = acc + inner;\n"
                  "        }\n"
                  "    }\n"
                  "    return acc;\n"
                  "}\n", 0), "deep control scratch");
      CHECK(okdeep.code == 0, "the same program without the needle parses");
      CHECK(okdeep.node_count > 20,
            "and it really does build a tree, so the zero above was a decision");
      free_tree(&okdeep);
    }
    printf("NOVA_LANGUAGE_PARSE_DEEP code=%llu nodes=%llu\n",
           (unsigned long long)deep.code,
           (unsigned long long)deep.node_count);
    free_tree(&deep);
  }

  /* AND THE STALE-BUFFER CASE, which is the one the guarantee is really about.
   * `node_count == 0` is a promise about what the module PUBLISHES. A caller
   * that reuses one scratch for a good parse and then a bad one must not be able
   * to read the FIRST tree out of the second call's buffer -- the refusal has to
   * overwrite the counts, not merely leave them alone. Both calls run into the
   * SAME allocation with no guard refill between them, which is the only way to
   * ask the question: a fresh buffer per call cannot hold anything stale. */
  {
    Tree shared;
    cases++;
    CHECK(parse(&shared, PROGRAM, 0), "shared scratch");
    CHECK(shared.code == 0 && shared.node_count > 0,
          "the first call into the shared scratch parses and builds a tree");
    {
      /* Now the SAME scratch, same Tree, run a program that is refused deep. */
      uint64_t *w = shared.words;
      uint64_t *out = w + NODES + SIDES + BINDS + FIELDS;
      Result r = run(g_image, w, 0,
                     "module m2;\n"
                     "export fn f(a:u64) -> u64 {\n"
                     "    let mut acc:u64 = 0;\n"
                     "    {\n"
                     "        let x:u64 = 1;\n"
                     "        acc = acc + x + not_a_name;\n"
                     "    }\n"
                     "    return acc;\n"
                     "}\n");
      CHECK(r.runtime == 0, "the second call into the same scratch ran");
      CHECK(out[5] == 0,
            "a refusal into a USED buffer publishes no node count");
      CHECK(out[0] != 0, "and it really was a refusal, not a silent success");
      CHECK(out[6] == 0 && out[7] == 0 && out[8] == 0,
            "and no root, scopes or bindings survive from the first call");
      /* THE FIRST CALL'S TREE IS STILL IN THE NODE ARRAY -- and that is not a
       * defect, it is a caller-owned buffer the module is not allowed to clear.
       * What must not happen is the module PUBLISHING it. So the check above is
       * on the counts, and this one is here to say which of the two it is:
       * the stale bytes are real, and they are unreachable without a count. */
      CHECK(shared.node_count > 0,
            "the first call's node bytes are still in the buffer (stated, not "
            "silently relied on)");
      printf("NOVA_LANGUAGE_PARSE_STALE published_nodes=%llu code=%llu\n",
             (unsigned long long)out[5], (unsigned long long)out[0]);
    }
    free_tree(&shared);
  }

  /* ---- 7. A FOURTH, TO PROVE 801 AND 803 ARE NOT THE SAME ANSWER ------- */
  /* A name that is never declared at all must be 803 and not 801. Without
   * this, "use before declaration" could be satisfied by a parser that simply
   * refuses every unknown name, and the distinction the module draws between
   * "declared later" and "never declared" would be untested. */
  expect_refusal("a name never declared is a different refusal",
                 "module shadow_probe;\n"
                 "export fn walk(bound:u64) -> u64 {\n"
                 "    let mut total:u64 = nowhere;\n"
                 "    return total;\n"
                 "}\n",
                 E_UNDECLARED, 4);

  /* ---- 7b. THE BOUNDS OF 801, WHICH ARE A CLAIM AND NEED A PERTURBATION --
   * 801 says "this block declares it LATER". Each word of that is a boundary,
   * and a lookahead that ignored any one of them would still pass every check
   * above -- so each is cut here, one at a time, and each must land on 803
   * because the name is not declared LATER IN THIS BLOCK.
   *
   * (a) A `let` of the same name in a NESTED block. The name is declared
   *     somewhere in the source, but in a scope that ENDS before the use's own,
   *     so it cannot be the declaration this use is jumping ahead of.
   * (b) A `let` of the same name AFTER this block's closing brace. Same
   *     reasoning, and the commonest way a lookahead runs off the end.
   * (c) A `let` of the same name in an ENCLOSING block, later. This is the
   *     subtle one and the reason the bound is the BLOCK and not "somewhere
   *     ahead": a parent-scope binding is a different scope, so a use before it
   *     is 803 rather than 801. */
  expect_refusal("a `let` of that name in a NESTED block is not this block's",
                 "module shadow_probe;\n"
                 "export fn walk(bound:u64) -> u64 {\n"
                 "    let mut total:u64 = early;\n"
                 "    {\n"
                 "        let early:u64 = 1;\n"
                 "    }\n"
                 "    return total;\n"
                 "}\n",
                 E_UNDECLARED, 4);
  expect_refusal("a `let` of that name AFTER this block's brace is not either",
                 "module shadow_probe;\n"
                 "export fn walk(bound:u64) -> u64 {\n"
                 "    let mut total:u64 = early;\n"
                 "}\n"
                 "export fn other(bound:u64) -> u64 {\n"
                 "    let early:u64 = 1;\n"
                 "    return bound;\n"
                 "}\n",
                 E_UNDECLARED, 4);
  expect_refusal("a `let` of that name in an ENCLOSING block is not this block's",
                 "module shadow_probe;\n"
                 "export fn walk(bound:u64) -> u64 {\n"
                 "    {\n"
                 "        let mut total:u64 = early;\n"
                 "    }\n"
                 "    let early:u64 = 1;\n"
                 "    return bound;\n"
                 "}\n",
                 E_UNDECLARED, 4);

  /* AND THE POSITIVE FOR THE SAME BOUND, so (a)-(c) are not passing because 801
   * stopped firing at all: the control that DID make it fire is re-run here,
   * immediately after its three narrowings, and must still be 801. A gate that
   * refuses everything unknown would satisfy (a)-(c) perfectly. */
  expect_refusal("801 still fires for the same block's own later `let`",
                 "module shadow_probe;\n"
                 "export fn walk(bound:u64) -> u64 {\n"
                 "    let mut total:u64 = early;\n"
                 "    let early:u64 = 1;\n"
                 "    return total;\n"
                 "}\n",
                 E_USE_BEFORE, 2);

  /* ---- 8. A KEYWORD IS NOT AN IDENTIFIER ------------------------------- */
  /* `mutable` is not `mut`, and a name shaped like a keyword is a name. The
   * program with `mutable` in it must parse, and `mut` must be recorded as a
   * keyword on the `let` that carries it. */
  {
    Tree k;
    cases++;
    CHECK(parse(&k, "module m;\nexport fn f() -> u64 {\n"
                    "    let mutable:u64 = 1;\n"
                    "    return mutable;\n}\n", 0), "mutable scratch");
    CHECK(k.code == 0, "`mutable` is an identifier, not the keyword `mut`");
    if (k.code == 0) {
      uint64_t fn = node_word(&k, k.root, 2);
      /* fn -> [return, block]; walk to the block */
      uint64_t first = node_word(&k, fn, 2);
      if (node_word(&k, first, 0) != K_BLOCK)
        first = node_word(&k, first, 4);
      uint64_t let_node = node_word(&k, first, 2);
      CHECK(node_word(&k, let_node, 13) == 3,
            "a `let mutable` records LET, not MUT");
      free_tree(&k);
    } else {
      fprintf(stderr, "FAIL `mutable` is an identifier: code %llu reason %llu\n",
              (unsigned long long)k.code, (unsigned long long)k.reason);
      free_tree(&k);
    }
  }

  /* ---- 9. THE EIGHT, READ BACK OUT OF THE EXECUTED MODULE --------------
   *
   * WHAT MODE 1 ACTUALLY PUBLISHES, and the earlier version of this section
   * got it wrong in the reader rather than in the module. `keyword_read_back`
   * does NOT publish the eight KEY_* NUMBERS. It copies the lexer's flat
   * NUL-separated TABLE, one byte per word, into `out`, so what comes back is
   * 45 words holding "export\0fn\0let\0module\0mut\0return\0struct\0while\0"
   * widened to u64 -- MEASURED, not assumed: the read-back returned 45, and
   * out[0..7] is 101 120 112 111 114 116 0 102, which is `e x p o r t NUL f`.
   * The entry's comment says "the eight, byte per word", which is the shape
   * and not the count: it is one byte per word of the TABLE, and the table has
   * 45 of them, not 8. Reading out[k] as the k-th KEY_* number reads the k-th
   * BYTE of the spelling.
   *
   * SO THE ORDER IS CHECKED WHERE THE ORDER LIVES: word k of the read-back is
   * the k-th NUL-delimited run, and it is compared to EXPECTED_KEYWORD[k].
   * Eight checks, one per position, against a literal order written in THIS
   * file at file scope -- so the module and the harness state the order
   * independently and their disagreement is a red, which is the property
   * AGENTS.md asks for and the only one a reordering can move. */
  {
    Tree t2;
    CHECK(parse(&t2, "", 1), "mode 1 parse");
    uint64_t size = t2.r.returned;
    /* The k-th NUL-delimited run of the read-back, as bytes. ABSENCE IS NOT A
     * ZERO: a short table yields len == 0 and the caller compares the LENGTH
     * first, so a missing word cannot pass by reading as an empty string that
     * happens to match nothing. */
    uint64_t words8 = 0;
    int in_word = 0;
    for (uint64_t i = 0; i < size; i++) {
      if (t2.out[i] == 0) { in_word = 0; continue; }
      if (!in_word) { words8++; in_word = 1; }
    }
    CHECK(words8 == 8, "the keyword table holds eight words");

    uint64_t seen = 0, at = 0;
    for (unsigned k = 0; k < 8; k++) {
      uint64_t start = at;
      while (at < size && t2.out[at] != 0) at++;
      uint64_t len = at - start;          /* the k-th run, if it is there */
      uint64_t want = (uint64_t)strlen(EXPECTED_KEYWORD[k]);
      int same = (seen == k) && len == want;
      for (uint64_t j = 0; same && j < want; j++)
        if (t2.out[start + j] != (uint64_t)(unsigned char)EXPECTED_KEYWORD[k][j])
          same = 0;
      /* The message names the POSITION and the word the harness expects
       * there, so a red says which of the eight moved rather than only that
       * one did. */
      char msg[96];
      snprintf(msg, sizeof msg, "the keyword at position %u reads `%s`", k,
               EXPECTED_KEYWORD[k]);
      CHECK(same, msg);
      if (at < size) at++;                /* step over the NUL, if there is one */
      if (start < size) seen++;
    }
    printf("NOVA_LANGUAGE_PARSE_KEYWORDS words=%llu\n",
           (unsigned long long)words8);
    free_tree(&t2);
  }

  /* ---- 10. THE LATTICE, READ BACK --------------------------------------- */
  {
    Tree t2;
    CHECK(parse(&t2, "", 2), "mode 2 parse");
    /* Three words per entry plus the name bytes; the names are read and their
     * WIDTHS are read from the same run, so the table and this gate cannot
     * disagree about what `u64` is. */
    uint64_t n = t2.r.returned;
    uint64_t entries = 0, widths_seen = 0;
    for (uint64_t i = 0; i + 3 < n;) {
      uint64_t id = t2.out[i], w = t2.out[i + 1], cl = t2.out[i + 2];
      uint64_t len = t2.out[i + 3];
      if (id == 0) break;
      entries++;
      if (w > 0 && w <= 80) widths_seen++;
      if (id == 4 && (w != 64 || cl != REG_VALUE)) {
        failures++;
        fprintf(stderr, "FAIL u64 must be 64 bits and a VALUE\n");
      }
      if (id == 9 && (w != 8 || cl != REG_PREDICATE)) {
        failures++;
        fprintf(stderr, "FAIL bool must be 8 bits and a predicate\n");
      }
      i += 4 + len;
    }
    CHECK(entries == 12, "the lattice publishes twelve types");
    CHECK(widths_seen == entries, "every lattice entry carries a width");
    printf("NOVA_LANGUAGE_PARSE_LATTICE types=%llu with_width=%llu\n",
           (unsigned long long)entries, (unsigned long long)widths_seen);
    free_tree(&t2);
  }

  test_a8_expressions();
  test_a8_buffers();
  test_a8_records();
  test_a8_record_boundaries();
  test_a8_record_constructors();
  test_a8_constructor_numeric_edges();
  test_a8_constructor_depth();
  test_a8_function_calls();
  test_a8_signature_limits();
  test_a8_strings_and_buffer_close();
  test_a8_token_allocation_pressure();
  test_a8_intrinsics_and_indexing();
  test_a8_allocation_contexts_and_scopes();
  test_a8_loop_control_and_else_if();
  test_a8_unary_and_null();
  test_a8_token_ownership_lifecycle();
  test_a8_contextual_keywords();

  const char *audit_list = getenv("NOVA_SELF_PARSE_LIST");
  unsigned audit_failures = audit_list ? audit_nova_sources(audit_list) : 0;

  free_tree(&t);
  nova_host_unmap(&image);
  if (c2) nt_artifact_free(&second);
  nt_artifact_free(&first);
  for (unsigned i = 0; i < PATHS_N; i++) free(sources[i]);

  printf("NTASM_NOVA_NOVA_LANGUAGE_PARSE checks=%u failures=%u cases=%u\n",
         checks, failures, cases);
  return failures ? 1 : (audit_failures ? 2 : 0);
}