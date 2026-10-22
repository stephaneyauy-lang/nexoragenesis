/* ===========================================================================
 * NTASM_NOVA_REG_WIDTH_BINDING -- the parameter/register WIDTH compatibility
 * rule, as a CLASS. Lot 37, third task.
 *
 * THE RULE, WHICH THE PRODUCT OWES AND TODAY DOES NOT IMPLEMENT:
 *
 *   a parameter of declared integer width W may be bound to a register R if and
 *   only if width(R) == W.
 *
 * That is one rule, and it is false in exactly one place: the binding has only
 * the 64-bit half. This file asserts the rule, generates its instances from a
 * PREDICATE rather than from a list, and refuses to pass if the product's
 * verdicts do not follow it.
 *
 * WHY THE CLASS, AND NOT FIVE CASES. The obvious file is one case per width:
 * u8, u16, u32, i8, i16, i32 -- six refusals, a hand-written table, and a
 * seventh width added next week that nobody thought of. A list of members
 * rots into a set of cases nobody extends, which is the same defect one level
 * below the one this project keeps measuring. So the members here are
 * GENERATED: every integer width the language has, crossed with every register
 * family the language has, and each pair is labelled with the verdict the rule
 * REQUIRES. The generator is the rule; the table would only be a copy of it.
 *
 * THE MEASUREMENT THAT IDENTIFIED THE COMPONENT, and it is the reason this file
 * exists in this shape. The two refusal codes are not the same defect:
 *
 *   u32 @rdi  ->  402  "parameter/register width mismatch"  : the DECLARED
 *                     width is not 64 bits. The code accuses the declaration.
 *   u32 @eax  ->  400  "type mismatch for 'a'"              : the REGISTER is
 *                     not 64 bits. The code accuses the register.
 *
 * A predicate that consults ONLY the declaration would answer 402 for
 * `u32 @eax`, where declared and register are both 32 bits. It answers 400.
 * So the narrow branch is not MISSING from the product -- it EXISTS and runs --
 * and what is missing is the comparison of the two widths inside it. That is
 * why the class is "every W by every R", not "the widths that do not work":
 * the 400 row is the signature of the missing predicate, and a gate written
 * only over the 402 rows would never see it.
 *
 * AND WHAT IS NOT CLAIMED. The widths exist in the language: `let v:u8 = 1`,
 * `let v:u32 = 1`, `data v:u8 = 1`, `data v:u32 = 1` are all accepted, measured.
 * So this is NOT a missing type family.
 *
 * AND THE CORRECTION I HAD TO MAKE TO MY OWN REDUCTION, because it is the
 * most expensive shape of mistake in this project: my first rule was
 * `width(R) == W` and NOTHING ELSE, and I reported the product as half-built
 * because 16 matching pairs were refused. All 16 were `rbp` and `rsp`, and
 * frontend.c:2782 refuses them BEFORE the width predicate runs, with its own
 * message and its own code -- "rsp/rbp cannot bind an nx64 parameter",
 * NTF_E_ABI. That is a rule, not a hole, and a hole does not carry a
 * justification. The full rule is `width(R) == W` AND `R is not a frame or
 * stack pointer`, and I had written the first conjunct of a two-conjunct rule
 * and reported it as the whole. A half-rule that looks like a whole rule does
 * not break: it answers a narrower question correctly and the reader believes
 * they were answered the one they asked.
 *
 * AND THE SECOND RULE, WHICH IS AN EXCEPTION, so it is named here rather than
 * left passing. frontend.c:2788 reads
 *
 *     if (TY(p->p, type).bits != reg.bits &&
 *         !(TY(p->p, type).kind == NTF_T_BOOL && reg.bits == 8))
 *
 * so a `bool` parameter binds to an EIGHT-BIT register whatever its own width
 * is, and to nothing else. The width cross product never mentions bool, so
 * without this the gate would be blind to the one clause of :2788 that is not
 * a width comparison -- and that is exactly where a predicate escapes.
 *
 * AND `bool` in `let` and `data` is a different rule at a different site: it
 * is refused there only because an INTEGER LITERAL cannot initialise it
 * (`let b:bool = true` is accepted, measured), which has nothing to do with
 * register binding and is not this gate's business.
 * ========================================================================= */
#include "../../../compiler/c/ntasm/frontend/ntasm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures, cases;

#define CHECK(c, m)                                                             \
  do {                                                                          \
    checks++;                                                                   \
    if (!(c)) {                                                                 \
      failures++;                                                               \
      fprintf(stderr, "FAIL %s\n", (m));                                        \
    }                                                                           \
  } while (0)

/* ---------------------------------------------------------------------------
 * THE GENERATOR. The rule, in one place, and the members fall out of it.
 * ------------------------------------------------------------------------- */

/* An integer width the language declares, and its bit width. Six of them, and
 * the list is the ENUM, not a selection: NTF_T_BOOL is excluded because it is
 * not a member of this class (see the header), and NTF_T_U64/NTF_T_I64 are the
 * two that work today. */
typedef struct {
  const char *decl;
  unsigned bits;
  int expected_ok; /* what the rule REQUIRES, not what the product does */
} Width;

/* A register family, and the width it carries. Named by its 64-bit member, so
 * the family is one row and the narrow members are derived from it -- deriving
 * them keeps a new register from needing a new row. */
typedef struct {
  const char *r64;
  const char *r32;
  const char *r16;
  const char *r8;
  unsigned bits64;
  int has_narrow; /* 0 when the language spells no narrow form of this family */
} Family;

static const Width WIDTHS[] = {
    {"u8", 8, 1},  {"u16", 16, 1}, {"u32", 32, 1},
    {"u64", 64, 1}, {"i8", 8, 1},  {"i16", 16, 1},
    {"i32", 32, 1}, {"i64", 64, 1},
};
#define WIDTH_N (sizeof WIDTHS / sizeof WIDTHS[0])

static const Family FAMILIES[] = {
    {"rax", "eax", "ax", "al", 64, 1},   {"rbx", "ebx", "bx", "bl", 64, 1},
    {"rcx", "ecx", "cx", "cl", 64, 1},   {"rdx", "edx", "dx", "dl", 64, 1},
    {"rsi", "esi", "si", "sil", 64, 1},  {"rdi", "edi", "di", "dil", 64, 1},
    {"rbp", "ebp", "bp", "bpl", 64, 1},  {"rsp", "esp", "sp", "spl", 64, 1},
    {"r8", "r8d", "r8w", "r8b", 64, 1},  {"r9", "r9d", "r9w", "r9b", 64, 1},
    {"r10", "r10d", "r10w", "r10b", 64, 1}, {"r11", "r11d", "r11w", "r11b", 64, 1},
    {"r12", "r12d", "r12w", "r12b", 64, 1}, {"r13", "r13d", "r13w", "r13b", 64, 1},
    {"r14", "r14d", "r14w", "r14b", 64, 1}, {"r15", "r15d", "r15w", "r15b", 64, 1},
};
#define FAMILY_N (sizeof FAMILIES / sizeof FAMILIES[0])

/* The register spelling of a family at a given width, or NULL when the family
 * spells none. This is where the rule's second half lives: a pair is
 * COMPATIBLE iff the register's width equals the declared width, and the whole
 * class is the cross product of the two tables above. */
static const char *register_at(const Family *f, unsigned bits) {
  if (bits == 64) return f->r64;
  if (!f->has_narrow) return NULL;
  if (bits == 32) return f->r32;
  if (bits == 16) return f->r16;
  if (bits == 8) return f->r8;
  return NULL;
}

/* The verdict the product gives, as a NUMBER, so the class is compared on
 * numbers and not on prose. Returns 0 for accepted. */
/* THE BINDING, WITHOUT A CALL. This function used to write `return g(1)`, and
 * that is the whole defect Main measured out of my own source:
 *
 *     $ ntasm check  ->  E400: integer literal cannot initialize bool
 *
 * The 400 was the ARGUMENT of the call, not the binding of the parameter. The
 * integer literal `1` cannot initialise a `bool` parameter, so the source was
 * refused by a check in the argument path and my gate reported it as a verdict
 * about the binding. Every one of the fourteen red rows was that. A gate that
 * drives a CHAIN OF PASSES measures the first pass that refuses, not the one it
 * is aimed at -- the project has now named that shape three times tonight
 * (transfer_cases' silent continue, fact_live without a call site, and this),
 * and this is the third instance wearing my name.
 *
 * So the callee is DECLARED AND NEVER CALLED. The parameter binding is still
 * parsed -- that is what this gate is about -- and there is no argument, hence
 * no argument check, hence no fourth predicate in the way. */
static unsigned binding_verdict(const char *decl, const char *reg) {
  char src[1024];
  snprintf(src, sizeof src,
           "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
           "fn g(in a:%s @%s)->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n"
           "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
           "return 42\n}\n}\n",
           decl, reg);
  NtFInput in = {"width.ntasm", src, strlen(src)};
  NtArtifact a = {0};
  int ok = nt_compile_many(&in, 1, &a);
  unsigned code = a.error.code;
  if (a.pe.bytes) free(a.pe.bytes);
  if (a.text.bytes) free(a.text.bytes);
  if (a.rdata.bytes) free(a.rdata.bytes);
  if (a.data.bytes) free(a.data.bytes);
  free(a.base_relocations);
  return ok ? 0u : code;
}

/* THE CALL FORM, kept and REPORTED but never asserted, because it is the thing
 * that misled this file. It exists so the difference is visible on every run
 * rather than being a fact about one afternoon: the same declaration, called
 * with `g(true)`, and the same declaration called with `g(1)`. If those two
 * ever agree, the argument path has stopped refusing integer literals for bool
 * and this file's history needs rewriting. */
static unsigned call_verdict(const char *decl, const char *reg,
                             const char *argument) {
  char src[1024];
  snprintf(src, sizeof src,
           "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
           "fn g(in a:%s @%s)->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n"
           "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
           "return g(%s)\n}\n}\n",
           decl, reg, argument);
  NtFInput in = {"width.ntasm", src, strlen(src)};
  NtArtifact a = {0};
  int ok = nt_compile_many(&in, 1, &a);
  unsigned code = a.error.code;
  if (a.pe.bytes) free(a.pe.bytes);
  if (a.text.bytes) free(a.text.bytes);
  if (a.rdata.bytes) free(a.rdata.bytes);
  if (a.data.bytes) free(a.data.bytes);
  free(a.base_relocations);
  return ok ? 0u : code;
}

int main(void) {
  /* THE RULE, COMPLETE, AND THE SECOND HALF IS THE ONE I MISSED FIRST.
   *
   *   A parameter of declared integer width W may be bound to a register R
   *   if and only if  width(R) == W  AND  R is not a frame or stack pointer.
   *
   * The second conjunct is not my invention and I did not read it before
   * writing the rule: compiler/c/ntasm/frontend/frontend.c:2782 refuses
   * `reg.family == 4 || reg.family == 5` with the message "rsp/rbp cannot
   * bind an nx64 parameter" and the code NTF_E_ABI. That is a DELIBERATE ABI
   * rule -- rsp and rbp are the stack and frame pointers, and binding a
   * parameter to either would destroy them -- and it sits UPSTREAM of the
   * width predicate at :2788.
   *
   * I left the second conjunct out, and the gate then counted every
   * rsp/rbp pair as a width defect: 16 red rows that were the rule working.
   * A rule asserted before it has been read in the tree is a guess wearing a
   * citation, and this file carried one for a whole run. */
  unsigned compatible = 0, mismatch = 0, accepted_wrong = 0, refused_wrong = 0;
  unsigned bool_exc = 0;

  puts("WIDTH_BIND name                        decl reg   width  rule   product");
  for (unsigned w = 0; w < WIDTH_N; w++)
    for (unsigned f = 0; f < FAMILY_N; f++) {
      const char *reg = register_at(&FAMILIES[f], WIDTHS[w].bits);
      if (!reg) continue;
      /* The ABI conjunct of the rule, read at frontend.c:2782. rbp and rsp are
       * family 4 and 5 there and are refused BEFORE the width predicate runs,
       * so a matching pair on them must be REFUSED and the gate must not count
       * it as a width defect. This is the row that was red for the wrong
       * reason. */
      const int is_frame_pointer = !strcmp(FAMILIES[f].r64, "rbp") ||
                                   !strcmp(FAMILIES[f].r64, "rsp");
      cases++;
      unsigned got = binding_verdict(WIDTHS[w].decl, reg);
      const int required_ok = WIDTHS[w].expected_ok && !is_frame_pointer;
      int agrees = (got == 0) == (required_ok != 0);
      compatible++;
      /* The names here are the RULE'S verdict, not the product's: a matching
       * pair the product refuses is wrong_on_MATCHING. They were swapped at the
       * print in the first version of this file, which read as "the product
       * wrongly accepts 16" -- the exact opposite of what happened, and on the
       * dangerous-sounding direction. The count was right and the LABEL was
       * wrong, which is the worst of the two ways to be wrong. */
      if (!agrees && required_ok)
        refused_wrong++;
      if (!agrees && !required_ok)
        accepted_wrong++;
      checks++;
      if (!agrees) {
        failures++;
        fprintf(stderr,
                "FAIL width binding %s @%s: both %u bits, the rule says ACCEPT, "
                "the product answers %u\n",
                WIDTHS[w].decl, reg, WIDTHS[w].bits, got);
      }
      /* The table is printed in full so a reader can see WHICH rows carry the
       * defect and which code each one produces, rather than being handed a
       * count. The 400 rows and the 402 rows are different facts. */
      printf("  %-4s @%-5s %3u  %-6s %u\n", WIDTHS[w].decl, reg, WIDTHS[w].bits,
             required_ok ? "ACCEPT" : "REFUSE", got);
    }

  /* THE EXCEPTION, generated like everything else and named in the banner, so
   * a reader can see it is TESTED rather than tolerated. The rule at
   * frontend.c:2788: a `bool` parameter binds to an 8-bit register and to
   * nothing else. BOTH directions, because an exception tested only in the
   * direction it permits is half a rule. */
  puts("WIDTH_BIND_BOOL_RULE bool binds to an 8-bit register, and to nothing "
       "else (frontend.c:2788)");
  for (unsigned f = 0; f < FAMILY_N; f++) {
    const char *narrow = register_at(&FAMILIES[f], 8);
    if (narrow) {
      const int is_frame = !strcmp(narrow, "spl") || !strcmp(narrow, "bpl");
      cases++;
      bool_exc++;
      unsigned got = binding_verdict("bool", narrow);
      checks++;
      if ((got == 0) == (is_frame != 0)) {
        failures++;
        fprintf(stderr, "FAIL bool rule: bool @%s -> %u, the exception says %s\n",
                narrow, got, is_frame ? "REFUSE, frame pointer" : "ACCEPT");
      }
      printf("  bool @%-4s 8-bit   %-6s %u\n", narrow,
             is_frame ? "REFUSE" : "ACCEPT", got);
    }
    cases++;
    bool_exc++;
    unsigned gotw = binding_verdict("bool", FAMILIES[f].r64);
    checks++;
    if (gotw == 0) {
      failures++;
      fprintf(stderr, "FAIL bool rule: bool @%s ACCEPTED; the exception admits "
                      "8-bit registers only\n", FAMILIES[f].r64);
    }
    printf("  bool @%-4s 64-bit  %-6s %u\n", FAMILIES[f].r64, "REFUSE", gotw);
  }
  printf("WIDTH_BIND_BOOL_CLASS exception_pairs=%u\n", bool_exc);

  /* THE CONTROL MAIN ASKED FOR, and it is the one that keeps this file honest.
   * The same declaration, exercised three ways, and the verdicts must NOT all
   * agree -- because if they did, this gate would be measuring whichever pass
   * happens to refuse first and calling it the binding.
   *
   *   declared, never called   -> the BINDING, which is what this gate asserts
   *   declared and g(true)     -> the binding, plus the argument path, sound
   *   declared and g(1)        -> an INTEGER LITERAL into a bool parameter,
   *                              refused 400 by the ARGUMENT path
   *
   * The first two must agree or this gate is measuring the wrong thing; the
   * third must DIFFER, and its difference is the entire history of this file. */
  cases++;
  unsigned b_nocall = binding_verdict("bool", "al");
  unsigned b_true = call_verdict("bool", "al", "true");
  unsigned b_one = call_verdict("bool", "al", "1");
  checks++;
  if (b_nocall != b_true) {
    failures++;
    fprintf(stderr, "FAIL control: bool @al declared-and-uncalled gives %u but "
                    "called with true gives %u; this gate is not measuring the "
                    "binding\n", b_nocall, b_true);
  }
  if (b_one == b_nocall) {
    failures++;
    fprintf(stderr, "FAIL control: g(1) and g(true) now give the same verdict "
                    "%u; the argument path stopped refusing integer literals "
                    "for bool, and this file's history needs rewriting\n", b_one);
  }
  checks++;
  unsigned w64 = binding_verdict("bool", "rax");
  if (w64 == 0) {
    failures++;
    fprintf(stderr, "FAIL the 64-bit case: bool @rax was ACCEPTED, so the "
                    "clause is no longer a restriction\n");
  }
  printf("WIDTH_BIND_CONTROL nocall=%u call_true=%u call_int_literal=%u "
         "bool@rax_nocall=%u\n", b_nocall, b_true, b_one, w64);

  /* BOTH DIRECTIONS of "if and only if", and the second is what makes the
   * first mean anything. A gate that only ever asserts "this must be
   * accepted" cannot tell a correct predicate from one that ACCEPTS
   * EVERYTHING -- and accepting everything is the failure mode a width rule is
   * most likely to have, and the one this project keeps measuring as the
   * dangerous direction. So the mismatch direction is generated too: a
   * non-64-bit declared width against a 64-bit register must be REFUSED, and
   * the product's 402 says that it is. */
  for (unsigned w = 0; w < WIDTH_N; w++)
    for (unsigned f = 0; f < FAMILY_N; f++) {
      if (WIDTHS[w].bits == 64) continue;
      cases++;
      mismatch++;
      unsigned got = binding_verdict(WIDTHS[w].decl, FAMILIES[f].r64);
      checks++;
      if (got == 0) {
        failures++;
        fprintf(stderr,
                "FAIL width binding %s @%s: declared %u bits on a 64-bit "
                "register, the rule says REFUSE, the product ACCEPTS\n",
                WIDTHS[w].decl, FAMILIES[f].r64, WIDTHS[w].bits);
        refused_wrong++;
      }
      printf("  %-4s @%-5s mismatch  %-6s %u\n", WIDTHS[w].decl, FAMILIES[f].r64,
             "REFUSE", got);
    }
  printf("WIDTH_BIND_CLASS matching_pairs=%u mismatch_pairs=%u "
         "wrong_on_matching=%u wrong_on_mismatch=%u\n",
         compatible, mismatch, refused_wrong, accepted_wrong);
  printf("NTASM_NOVA_REG_WIDTH_BINDING checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  /* The gate is RED on the current tree, and that is the point: it states what
   * the specification now says at spec/ntasm/ntasm.md:239-245 and the product does
   * not yet do it. It is not a passing gate and is not reported as one. */
  return failures ? 1 : 0;
}
