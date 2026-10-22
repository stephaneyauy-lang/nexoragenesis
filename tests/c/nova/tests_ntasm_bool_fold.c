/* ===========================================================================
 * NTASM_NOVA_BOOL_FOLD -- the ACCEPTANCE divergence, reduced and closed as a
 * CLASS. Lot 37, second half.
 *
 * THE DEFECT, IN ONE SENTENCE. A product that REFUSES valid code hurts the user
 * visibly, because the error is printed and the user fixes it; a product that
 * ACCEPTS invalid code hurts the user SILENTLY, because the code compiles, ships
 * and is wrong. Only the second kind repairs itself. This file is about the
 * second kind, and it is a defect of CONFORMANCE, not a missing test.
 *
 * WHY EVERY BYTE-PARITY GATE IN THIS TREE IS BLIND TO IT, and this is the part
 * that makes it a family rather than a case. Every such gate begins by asking
 * the C reference to build the source. A source the reference DECLINES leaves
 * the comparison unrun -- a void that reads as a pass. So the whole class
 * "the reference refuses what the product accepts" cannot produce a verdict
 * from inside a parity gate, no matter how many members it has. A gate that
 * cannot fail is not a gate; a family of gates that cannot produce a verdict
 * does not measure the zone it declares to measure.
 *
 * THE ROOT CAUSE, LOCATED AND MEASURED, not inherited from a README.
 * frontend.c:1775-1777 types a comparison NTF_T_BOOL. frontend.c:1782-1786
 * then asks constant_value, which SUCCEEDS because `1 < 2` folds, and applies
 * literal_fits to the folded value. literal_fits (frontend.c:1324) opens with
 *     if (!integer_kind(t->kind)) return 0;
 * and integer_kind (frontend.c:1321) is `k >= NTF_T_U8 && k <= NTF_T_I64`.
 * The enum (frontend.h:63-77) puts NTF_T_BOOL at 10 and NTF_T_I64 at 9, so
 * bool is NOT an integer kind and literal_fits returns 0 unconditionally --
 * for EVERY folded bool, whatever its value and whatever the comparison was.
 *
 * THE DISCRIMINATOR IS FOLDING, AND THIS FILE MEASURES IT RATHER THAN
 * ASSUMING IT. Ten constant comparisons over six operators are refused; the
 * IDENTICAL shape over a parameter is accepted (x == 0, x < 1, x < y all build).
 * And the trigger is not the `if`: `let b:bool = 1 < 2` is refused with no
 * condition anywhere in the source, while `let b:bool = x < 1` is accepted.
 * So the rule is exactly: a FOLDED bool constant reaching a literal_fits call
 * is refused. That is the class, and it has far more members than the three
 * probed -- hence the refusal-oracle shape below rather than a list.
 *
 * WHO IS RIGHT. The specification, read on the tree at the phrase "La condition
 * d'un `if` doit être prouvée `bool`", lists what the initial profile proves:
 * "les littéraux booléens, les paramètres et locals de type `bool`, les
 * comparaisons, les calls locaux/importés dont le retour est `bool` et le
 * prédicat target `feature(x)`". Les comparaisons is unqualified -- nothing in
 * that sentence exempts the constant ones. So the product is right and the
 * REFERENCE is wrong, and the reference is wrong structurally: it has no bool
 * case in its constant range check and applies that check to a bool-typed
 * constant anyway. Every other divergence measured in this project has been
 * product-refuses-reference-builds; this is the first specification-versus-
 * reference one, and the first in the direction where the reference is the one
 * out of step.
 *
 * WHAT THIS GATE ASSERTS, AND WHY IT IS NOT A PARITY GATE. It asserts what the
 * PRODUCT publishes: for a source the specification blesses, the product must
 * ACCEPT it. It never asks the reference for an opinion, because asking it is
 * what makes the class invisible. The class is named as a PREDICATE over
 * sources so that the next member of the family is covered by construction --
 * a member list would rot into a set of cases nobody extends, which is the same
 * defect one level down.
 * ========================================================================= */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/frontend/ntasm.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
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

/* Drive the C reference and report its verdict. The reference is the SUBJECT
 * here, not the oracle: this gate exists because the reference is the side that
 * is wrong, so a "both agree" assertion would be asserting the bug. */
static int reference_verdict(const char *src, unsigned *code) {
  NtFInput in = {"bool-fold.ntasm", src, strlen(src)};
  NtArtifact a = {0};
  int ok = nt_compile_many(&in, 1, &a);
  *code = a.error.code;
  if (a.pe.bytes) free(a.pe.bytes);
  if (a.text.bytes) free(a.text.bytes);
  if (a.rdata.bytes) free(a.rdata.bytes);
  if (a.data.bytes) free(a.data.bytes);
  free(a.base_relocations);
  return ok;
}

/* THE CLASS PREDICATE, derived from the rule and not from a list of members.
 *
 * The rule the reference breaks: a FOLDED bool constant must satisfy the range
 * check of the type it is being initialised into, and bool's range is {0,1}.
 * The discriminator is that constant_value SUCCEEDS on the expression, so this
 * predicate is over the SOURCE TEXT of the initializer: a comparison or a
 * boolean literal whose operands are all numeric literals.
 *
 * Deriving the family this way, from the rule, is the whole point: a table of
 * members would be a set of cases, and the next case of the same family would
 * be seen by nobody. */
static int is_folded_bool_constant(const char *expr) {
  /* A comparison operator between two numeric literals. The literals are
   * matched as DIGIT RUNS with optional whitespace, so `1 < 2`, `1<2` and
   * `007  <=  42` are all members, and a member carrying a name is not. */
  static const char *OPS[] = {"==", "!=", "<=", ">=", "<", ">", NULL};
  const char *s = expr;
  while (*s == ' ' || *s == '\t') s++;
  if (!(*s >= '0' && *s <= '9')) return 0;
  while (*s >= '0' && *s <= '9') s++;
  while (*s == ' ' || *s == '\t') s++;
  for (unsigned o = 0; OPS[o]; o++) {
    size_t n = strlen(OPS[o]);
    if (strncmp(s, OPS[o], n)) continue;
    const char *r = s + n;
    while (*r == ' ' || *r == '\t') r++;
    if (*r >= '0' && *r <= '9') return 1;
    return 0;
  }
  return 0;
}

/* Build the member: a `let` whose declared type is bool and whose initializer
 * the predicate says is a folded bool constant. The slot is chosen over a SET
 * of forms, so the class is exercised in more than one position -- a single
 * position would make "the class has one member" indistinguishable from "the
 * class has many members that all sit in the same place". */
static void member_from_expr(const char *label, const char *expr) {
  cases++;
  char src[1024];
  snprintf(src, sizeof src,
           "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
           "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
           "let b:bool = %s\nreturn 42\n}\n}\n",
           expr);
  unsigned code = 0;
  int accepted = reference_verdict(src, &code);
  printf("BOOL_FOLD %-26s expr=%-10s ref=%-7s code=%u\n", label, expr,
         accepted ? "ACCEPTS" : "REFUSES", code);
  checks++;
  /* THE CLASS GATE. A folded bool constant is a form the specification blesses
   * ("les comparaisons", unqualified) and that the product accepts, so the
   * reference must accept it too. A refusal here is the divergence this whole
   * file exists to make visible. */
  if (!accepted) {
    failures++;
    fprintf(stderr, "FAIL class member refused: %s (%s) -> %u %s\n", label, expr,
            code, "the reference declines a form the specification proves");
  }
}

/* THE CONTROL, and it is what makes the class a class rather than a wish.
 * The IDENTICAL shape with an operand the front end cannot fold must be
 * ACCEPTED -- measured, and it is. If this control ever went red, the class
 * predicate would be describing something other than folding, and the failures
 * above would be about that other thing. */
static void control_unfolded_is_accepted(void) {
  cases++;
  static const char *src =
      "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "export fn main(in x:u64)->u64\neffects {}\nclobbers {rax} {\n"
      "let b:bool = x < 1\nreturn 42\n}\n}\n";
  unsigned code = 0;
  int accepted = reference_verdict(src, &code);
  printf("BOOL_FOLD_CONTROL %-18s unfolded shape ref=%s code=%u\n",
         accepted ? "ACCEPTS" : "REFUSES", accepted ? "ACCEPTS" : "REFUSES", code);
  checks++;
  if (!accepted) {
    failures++;
    fprintf(stderr, "FAIL control: the UNFOLDED shape was refused %u; the "
                    "class predicate is then about something other than "
                    "folding\n",
            code);
  }
  /* And a boolean LITERAL, which is the other member of the same family and
   * takes the other branch of literal_fits: it is not a comparison, so it is
   * not reached by this defect. It must be accepted, and it is. */
  cases++;
  static const char *lit =
      "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
      "let b:bool = true\nreturn 42\n}\n}\n";
  unsigned lcode = 0;
  int lit_ok = reference_verdict(lit, &lcode);
  checks++;
  if (!lit_ok) {
    failures++;
    fprintf(stderr, "FAIL control: the bool LITERAL was refused %u\n", lcode);
  }
  printf("BOOL_FOLD_CONTROL %-18s bool literal ref=%s code=%u\n",
         lit_ok ? "ACCEPTS" : "REFUSES", lit_ok ? "ACCEPTS" : "REFUSES", lcode);
}

/* ===========================================================================
 * THE REFUSAL PAIR FOR THE GUARD THIS FILE NAMES BUT CANNOT FIRE.
 *
 * This file's own header names frontend.c:1324 `if (!integer_kind(t->kind))
 * return 0;` -- literal_fits -- as the defect site. literal_fits is a
 * function whose entire job is to REFUSE. And the file structurally could not
 * ask it to: every one of its 24 class members is a comparison of two
 * numeric literals in {0,1,2,7}, and every comparison of two such literals is
 * 0 or 1, which is inside bool's range {0,1}. So the class it walks is the
 * class where the guard is unreachable BY CONSTRUCTION, and an
 * always-accept literal_fits yields a bit-identical banner. That is not a
 * defect in the class; it is the class being chosen well for the acceptance
 * question and therefore blind to the refusal one.
 *
 * So the refusal is a separate pair, and it is the same shape the class uses
 * -- a `let` initialised from a FOLDED constant -- with one token changed to
 * move the folded value out of the target type's range. The discriminator is
 * unchanged: constant_value SUCCEEDS on the expression, so literal_fits is
 * reached rather than skipped. `200+100` folds to 300; a u8 cannot hold 300;
 * the same initialiser bound to u16 can. One token -- the width in the type
 * name -- separates the two arms.
 *
 * MEASURED, not transcribed: the folded arm is refused with NTF_E_LITERAL 401,
 * "constant expression outside result range" (frontend.c:1851-1853, the
 * constant-expression call site of literal_fits -- not the literal call site at
 * :1617, which is a different message). The census said "a nonzero range
 * code" and declined to name it; it is 401.
 *
 * THE POISON: the artifact is filled with 0xcc first and must come back with
 * no text and no data. nt_compile clears its own output on failure, so the
 * assertion is stated as absence -- nothing was produced -- which is what a
 * refusal has to guarantee and what `accepted == 0` alone does not.
 * ======================================================================== */
static void refusal_folded_literal_out_of_range(void) {
  /* THE CONTROL: the folded 300 bound to a type that holds it. One token from
   * the refusal arm -- `u8` becomes `u16` -- and the same fold, the same
   * constant_value success, the same literal_fits call site. */
  static const char *control =
      "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
      "let x:u16 = 200+100\nreturn 42\n}\n}\n";
  /* THE REFUSAL: that same source with `u16` -> `u8`. */
  static const char *refusal =
      "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
      "let x:u8 = 200+100\nreturn 42\n}\n}\n";
  cases++;
  {
    unsigned code = 0;
    int accepted = reference_verdict(control, &code);
    checks++;
    printf("BOOL_FOLD_RANGE %-12s type=u16 folded=300 ref=%s code=%u\n",
           "control", accepted ? "ACCEPTS" : "REFUSES", code);
    if (!accepted) {
      failures++;
      fprintf(stderr,
              "FAIL range control: the folded 300 bound to u16 was refused %u. "
              "If a type that holds the value refuses it, the check below is "
              "about the width and not about the fold\n",
              code);
    }
  }
  cases++;
  {
    unsigned code = 0;
    int accepted = reference_verdict(refusal, &code);
    checks++;
    printf("BOOL_FOLD_RANGE %-12s type=u8  folded=300 ref=%s code=%u\n",
           "refusal", accepted ? "ACCEPTS" : "REFUSES", code);
    /* THE EXACT CODE. Not "nonzero": a fabricated range check that refused
     * every u8 initialiser, or accepted every folded constant, would answer
     * nonzero or zero respectively, and only 401 with 300 out of range says
     * literal_fits did the work the tree documents. */
    CHECK(!accepted && code == 401,
          "the folded constant 300 is refused for a u8 binding with the exact "
          "range code NTF_E_LITERAL 401");
    if (!accepted)
      fprintf(stderr, "BOOL_FOLD_REFUSAL code=%u\n", code);
  }
}

/* The poison stated properly: drive the refusal through a caller-owned buffer
 * so the assertion is about the ARTIFACT and not about a return value. Kept
 * separate from the code check above so a reader can see which assertion is
 * which. */
static void refusal_leaves_no_artifact(void) {
  static const char *refusal =
      "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
      "let x:u8 = 200+100\nreturn 42\n}\n}\n";
  cases++;
  NtArtifact a;
  memset(&a, 0xcc, sizeof a);
  int accepted = nt_compile(refusal, strlen(refusal), &a);
  CHECK(!accepted,
        "the u8 binding of 200+100 is refused where the u16 binding is not");
  CHECK(!a.text.bytes && !a.pe.bytes && !a.rdata.bytes && !a.data.bytes,
        "no section carries bytes on the refusal path, so no code image was "
        "fabricated behind the refusal");
  CHECK(a.base_relocation_count == 0 && !a.base_relocations,
        "no relocation table exists on the refusal path");
  if (!accepted)
    fprintf(stderr, "BOOL_FOLD_POISON code=%u %s\n", a.error.code,
            a.error.message);
  nt_artifact_free(&a);
}

int main(void) {
  /* THE CLASS, walked. Every member is a folded bool constant; the set is
   * generated over six comparison operators and four operand pairs, so it has
   * 24 members and the gate does not depend on anyone remembering to add the
   * twenty-fifth. */
  static const char *OPS[] = {"==", "!=", "<=", ">=", "<", ">", NULL};
  static const char *L[] = {"0", "1", "2", "7"};
  unsigned generated = 0;
  for (unsigned o = 0; OPS[o]; o++)
    for (unsigned a = 0; a < 4; a++)
      for (unsigned b = 0; b < 4; b++) {
        char expr[32];
        snprintf(expr, sizeof expr, "%s %s %s", L[a], OPS[o], L[b]);
        if (!is_folded_bool_constant(expr)) continue;
        char label[64];
        snprintf(label, sizeof label, "folded-%u", generated);
        member_from_expr(label, expr);
        generated++;
      }
  checks++;
  if (generated < 2) {
    failures++;
    fprintf(stderr, "FAIL the class generated %u members; a class of one is "
                    "a case, not a class\n",
            generated);
  }
  printf("BOOL_FOLD_CLASS members=%u rule=folded-bool-constant\n", generated);

  control_unfolded_is_accepted();

  /* The refusal side of literal_fits, which the class above cannot reach by
   * construction. Without these two calls the guard this file names in its own
   * header is never asked to fire, and an always-accept literal_fits prints a
   * bit-identical banner. */
  refusal_folded_literal_out_of_range();
  refusal_leaves_no_artifact();

  printf("NTASM_NOVA_BOOL_FOLD checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  return failures ? 1 : 0;
}
