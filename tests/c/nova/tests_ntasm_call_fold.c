/* Gate for the CALL FOLD and its OUTPUT REGISTER EXEMPTION -- the third rule of
 * the reference's three, and the one the landed flag patch named and did not
 * own.
 *
 * WHAT IT CHECKS, in the reference's own terms. frontend.c folds, per call, two
 * things into the caller's inferred set --
 *
 *     caller->inferred_clobbers |= target->clobbers;                            :1647
 *     caller->inferred_clobbers |= nt_conformance_output_registers(callee);      :1650
 *
 * and then refuses, per function, over the whole unit --
 *
 *     f->inferred_clobbers & ~(f->clobbers | output_registers)                  :5856
 *
 * The reference's own answers on the two corpus members, measured by RUNNING
 * it rather than read from a report:
 *
 *     0032_nova_tests_ntasm_calls        502 function 'main' omits an inferred clobber
 *     0069_nova_tests_ntasm_diagnostics  502 function 'main' omits an inferred clobber
 *
 * and neither body contains a flag-writing mnemonic, which is why the flag
 * channel's narrowing removed zero currently-green cases while these two stayed
 * red.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS GATE CALLS THE RULE AND NOT A ROUTE. A first version of this gate
 * drove mode 1 and mode 2 of the PE gate, and the RED PROOF showed it was the
 * silent kind: with the guard's two call sites removed and the rule left
 * defined, the gate produced an IDENTICAL verdict set, 60 checks and 4 failures,
 * before and after. The reason is a property of the rule and not of the gate:
 * the fold removes ZERO currently-green cases, because every source the
 * frameless and the framed cores emit is refused by an earlier shape gate of
 * their own, and every source the fold refuses is already refused without it.
 * A route cannot witness a rule that never changes a route's answer.
 *
 * So this gate calls x64_lower_nxo.call_fold through the entry
 * tests/x64-lower-nxo-call-fold-entry.nova, and it asserts the rule's PREDICATE.
 * What it does not assert is that any source this producer emits can reach it;
 * that is published below and in the GATE_SHAPE_LIMITS line the gate prints.
 *
 * ---------------------------------------------------------------------------
 * THE WALK IS ASSERTED POSITIVELY, NOT ASSUMED. The rule's failure mode is
 * silence: a walk that compiles, returns a well-formed 0 and inspects nothing.
 * The landed flag patch had exactly that failure -- its literal AST walk read
 * the function's own children, saw five declaration nodes and no instruction,
 * and never fired, because a body's statements are children of the kind 25
 * body BLOCK. So every leg here carries the number of call statements the walk
 * REACHED, and a leg that expects a refusal also asserts the walk reached its
 * call. A verdict of 0 beside a reached count of 0 is not evidence.
 *
 * ---------------------------------------------------------------------------
 * THE EXEMPTION IS EXERCISED HERE, and this is where the landed flag patch said
 * it could not be. Its reason was that the only obligation IT reached writes
 * RFLAGS and no return convention delivers RFLAGS in -- which is an argument
 * that the exemption cannot change an answer on the FLAG obligation, not that
 * it is untestable. On this rule it does change one, and the pair that proves
 * it differs in exactly one token: the same callee clobbering rcx, called from
 * a caller that either DECLARES rcx or RETURNS it through an out parameter.
 * The reference answers ACCEPT for the second and 502 for the first, measured.
 *
 * ---------------------------------------------------------------------------
 * THE THIRD CHANNEL IS NAMED AND NOT THIS GATE'S. One corpus member,
 * 0106 tests_ntasm_effects, answers 502 and is discharged by neither this rule
 * nor the flag rule: its body is `swapgs`, and x64.c:1017 gives that mnemonic
 * registers_written = 1<<18, which is an INSTRUCTION's own inferred writes
 * rather than a call's fold. body_clobbers.nova:626 already names swapgs and
 * refuses it. That is a different rule with a different owner and this gate
 * makes no claim about it.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks,failures,cases;

static char*load(const char*p,size_t*n){
  FILE*f=fopen(p,"rb");if(!f)return NULL;
  fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);
  char*b=z>=0?malloc((size_t)z+1):NULL;
  if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}
  fclose(f);b[z]=0;*n=(size_t)z;return b;
}

typedef struct{uint64_t verdict,functions,bodies,calls,runtime;}Fold;

/* The entry takes (source, out): two parameters, so FOUR argument slots. */
static Fold fold(const NovaHostImage*i,const char*s){
  Fold r={0,0,0,0,0};
  /* The OUT buffer is EIGHT words, not four. The entry refuses a shorter one
   * and returns before writing anything, and a gate that then reads the
   * untouched buffer sees a verdict of 0 -- the silent-gate failure in its
   * purest form, a number that looks like an answer and is nothing. */
  uint64_t out[8]={0,0,0,0,0,0,0,0};
  NovaContextV2 c={0};
  if(!nova_context_init_v2(&c)){r.runtime=1;return r;}
  uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0);
  uint64_t oh=nova_borrow_v2(&c,out,sizeof out,1);
  uint64_t a[4]={sh,(uint64_t)strlen(s),oh,8};
  i->entry(&c,a,4);
  r.runtime=(uint64_t)c.error;
  nova_context_destroy_v2(&c);
  r.verdict=out[0];r.functions=out[1];r.bodies=out[2];r.calls=out[3];
  return r;
}

/* The rule REFUSES this source, and the walk REACHED its call. The second half
 * is the assertion that makes this a check rather than a coincidence: a rule
 * that returned non-zero without reaching a statement would pass without it.
 *
 * The code is not asserted. The reference's 501 and 502 are the C's enum and
 * the producer's refusal code for this rule is this tree's choice, so pinning a
 * number here would pin a decision this gate has no standing over. */
static void refuses_reaching(const NovaHostImage*i,const char*n,const char*s,
                             uint64_t want_calls){
  Fold r=fold(i,s);
  cases++;
  checks++;
  if(r.runtime||r.verdict==0){
    failures++;
    fprintf(stderr,"FAIL fold %s expected a refusal, got verdict=%llu runtime=%llu\n",
            n,(unsigned long long)r.verdict,(unsigned long long)r.runtime);
    return;
  }
  checks++;
  if(r.calls!=want_calls){
    failures++;
    fprintf(stderr,"FAIL walk %s the walk reached %llu calls, want %llu -- a refusal "
                    "without a reached call proves nothing\n",
            n,(unsigned long long)r.calls,(unsigned long long)want_calls);
  }
}

/* The rule ACCEPTS this source, and the walk reached `want_calls` calls: the
 * acceptance is the positive half of a pair whose negative half is above, so a
 * fold that refuses everything fails here instead of passing silently. */
static void accepts_reaching(const NovaHostImage*i,const char*n,const char*s,
                             uint64_t want_calls){
  Fold r=fold(i,s);
  cases++;
  checks++;
  if(r.runtime||r.verdict!=0){
    failures++;
    fprintf(stderr,"FAIL fold %s expected acceptance, got verdict=%llu runtime=%llu\n",
            n,(unsigned long long)r.verdict,(unsigned long long)r.runtime);
    return;
  }
  checks++;
  if(r.calls!=want_calls){
    failures++;
    fprintf(stderr,"FAIL walk %s the walk reached %llu calls, want %llu\n",
            n,(unsigned long long)r.calls,(unsigned long long)want_calls);
  }
}

int main(void){
  const char*paths[]={
    "tests/nova/tests/x64-lower-nxo-call-fold-entry.nova",
    "compiler/nova/backend/x64/x64_lower_nxo.nova",
    "compiler/nova/formats/nxo/nxo_pe.nova",
    "compiler/nova/formats/pe/pe.nova",
    "compiler/nova/formats/nxo/nxo.nova",
    "compiler/nova/formats/nxo/nxo_link_pe.nova",
    "compiler/nova/formats/nxo/nxo_merge.nova",
    "compiler/nova/inspectors/nxo_inspect.nova",
    "compiler/nova/backend/x64/x64_lower_control.nova",
    "compiler/nova/backend/x64/x64_lower_fixed.nova",
    "compiler/nova/backend/x64/x64_fixed.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/macros/constant_eval.nova",
    "compiler/nova/macros/macro_expand.nova",
    "compiler/nova/macros/macro_splice.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova"};
  const unsigned npaths=18;
  char*sources[18]={0};NtFInput inputs[18];
  for(unsigned i=0;i<npaths;i++){size_t n=0;sources[i]=load(paths[i],&n);
    inputs[i]=(NtFInput){paths[i],sources[i],n};}
  int all=1;for(unsigned i=0;i<npaths;i++)if(!sources[i])all=0;
  checks++;if(!all){failures++;fprintf(stderr,"FAIL sources load\n");}
  NtArtifact a={0};
  int compiled=all&&nova_compile_many_v2(inputs,npaths,&a);
  checks++;if(!compiled){failures++;fprintf(stderr,"FAIL producer image compiles\n");}
  NovaContextV2 ctx={0};
  if(!nova_context_init_v2(&ctx)){failures++;fprintf(stderr,"FAIL context init\n");}
  NovaHostImage image={0};
  int mapped=compiled&&nova_host_map(&a,&image);
  checks++;if(!mapped){failures++;fprintf(stderr,"FAIL producer image mapped\n");}
  if(mapped){

    /* ---- THE ACCEPTANCE: the two corpus members, verbatim. */
    const char*member_calls=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn helper(inout outer:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn outer\n}\n"
      "fn main()->u64\neffects {}\nclobbers {} {\ncall helper(1)\nreturn 0\n}\n}\n";
    const char*member_diagnostics=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn leaf()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n"
      "fn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";
    refuses_reaching(&image,"0032_nova_tests_ntasm_calls",member_calls,1);
    refuses_reaching(&image,"0069_nova_tests_ntasm_diagnostics",member_diagnostics,1);

    /* ---- FOLD ARM 1, the callee's DECLARED clobbers. The pair differs only in
     * the caller's own clobber set, so one refusal and one acceptance
     * attribute the arm to itself. */
    const char*declared_missing=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn leaf()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n"
      "fn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";
    const char*declared_present=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn leaf()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n"
      "fn main()->u64\neffects {}\nclobbers {rax} {\ncall leaf()\nreturn 0\n}\n}\n";
    refuses_reaching(&image,"fold_declared_missing",declared_missing,1);
    accepts_reaching (&image,"fold_declared_present",declared_present,1);

    /* ---- FOLD ARM 2, the callee's OUTPUT registers. 0032 is this arm; the
     * pair again differs only in the caller's declaration. */
    const char*output_missing=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn helper(inout outer:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn outer\n}\n"
      "fn main()->u64\neffects {}\nclobbers {} {\ncall helper(1)\nreturn 0\n}\n}\n";
    const char*output_present=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn helper(inout outer:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn outer\n}\n"
      "fn main()->u64\neffects {}\nclobbers {rcx} {\ncall helper(1)\nreturn 0\n}\n}\n";
    refuses_reaching(&image,"fold_output_missing",output_missing,1);
    accepts_reaching (&image,"fold_output_present",output_present,1);

    /* ---- THE EXEMPTION, and its negative control in the same breath. These
     * two differ in ONE token: the caller either declares rcx or RETURNS it
     * through an inout parameter. The reference answers ACCEPT for the second
     * and 502 for the first, so a rule without the `| output_registers` term
     * refuses the second and fails the first leg here. rax cannot be an output
     * register -- the ABI refuses it -- so the bit is rcx on purpose. */
    const char*exempt_returning=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn leaf()->u64\neffects {}\nclobbers {rcx} {\nreturn 0\n}\n"
      "fn main(inout handback:u64 @rcx)->u64\neffects {}\nclobbers {} {\n"
      "call leaf()\nreturn handback\n}\n}\n";
    const char*exempt_absent=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn leaf()->u64\neffects {}\nclobbers {rcx} {\nreturn 0\n}\n"
      "fn main(in handback:u64 @rcx)->u64\neffects {}\nclobbers {} {\n"
      "call leaf()\nreturn handback\n}\n}\n";
    accepts_reaching(&image,"exemption_caller_returns_the_bit",exempt_returning,1);
    refuses_reaching(&image,"exemption_absent_caller_must_declare",exempt_absent,1);

    /* ---- rflags THROUGH THE FOLD. rflags is not in the family catalogue
     * family() numbers, so a fold that read the callee's set with family()
     * would answer 800 on every source that names it -- including the ones the
     * reference accepts. This pair is what caught that. */
    const char*rflags_owed=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn leaf()->u64\neffects {}\nclobbers {rflags} {\nreturn 0\n}\n"
      "fn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";
    const char*rflags_declared=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn leaf()->u64\neffects {}\nclobbers {rflags} {\nreturn 0\n}\n"
      "fn main()->u64\neffects {}\nclobbers {rflags} {\ncall leaf()\nreturn 0\n}\n}\n";
    refuses_reaching(&image,"fold_rflags_owed",rflags_owed,1);
    accepts_reaching (&image,"fold_rflags_declared",rflags_declared,1);

    /* ---- UNIT SCOPE. The under-declared caller is NOT the exported entry and
     * the reference still refuses the whole unit naming it, so a rule that
     * looked only at the exported entry would pass this and be wrong in the
     * direction that passes. */
    const char*side_missing=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn main()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n"
      "fn side()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n"
      "fn leaf()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n}\n";
    const char*side_present=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn main()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n"
      "fn side()->u64\neffects {}\nclobbers {rax} {\ncall leaf()\nreturn 0\n}\n"
      "fn leaf()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n}\n";
    refuses_reaching(&image,"unit_scope_side_missing",side_missing,1);
    accepts_reaching (&image,"unit_scope_side_present",side_present,1);

    /* ---- NO CALL, NO FOLD, and the walk really is empty here. want_calls=0
     * is the one leg that asserts zero, and it is what makes the other legs'
     * non-zero counts mean something. */
    const char*no_call=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn leaf()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n"
      "fn main()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n}\n";
    accepts_reaching(&image,"no_call_no_fold",no_call,0);

    /* ---- TWO CALLS, TWO BITS, both declared. The accumulator has to survive
     * a second call, and a fold that overwrote instead of OR-ing would refuse
     * this. */
    const char*two_calls=
      "module m\ntarget x86_64-nexora-none\nsection .text {\n"
      "fn leafr()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n"
      "fn leafc()->u64\neffects {}\nclobbers {rcx} {\nreturn 0\n}\n"
      "fn main()->u64\neffects {}\nclobbers {rax,rcx} {\ncall leafr()\ncall leafc()\n"
      "return 0\n}\n}\n";
    accepts_reaching(&image,"two_calls_both_declared",two_calls,2);
  }
  if(image.memory)nova_host_unmap(&image);
  /* main() opened its OWN context at :189 and never closed it. The helper above
   * pairs init with destroy correctly, which is why the defect was invisible by
   * reading: the gate does the right thing in one place and not in the other.
   * LeakSanitizer caught it as a 3.6 MB indirect leak reaching through the init
   * line, and the artifact free was never at fault -- nt_artifact_free releases
   * exactly the five members this gate holds. */
  nova_context_destroy_v2(&ctx);
  if(compiled)nt_artifact_free(&a);
  for(unsigned i=0;i<npaths;i++)free(sources[i]);

  /* WHAT IS ASSERTED AND WHAT IS NOT, in the gate's own output. */
  printf("GATE_SHAPE_LIMITS call_fold asserted=the_rule_predicate_matches_frontend.c "
         "not_asserted=that_any_source_this_producer_emits_can_reach_the_guard\n");
  printf("GATE_SHAPE_LIMITS_CALL_FOLD cost=0_currently_green_cases_removed "
         "reason=every_source_the_fold_refuses_is_already_refused_by_an_earlier_shape_gate\n");
  printf("GATE_SHAPE_LIMITS_CALL_FOLD exempt_from_this_gate=none; "
         "the_output_register_exemption_IS_exercised_by_exemption_caller_returns_the_bit\n");
  printf("GATE_SHAPE_LIMITS_CALL_FOLD third_channel_named=0106_tests_ntasm_effects "
         "channel=an_instruction_own_inferred_writes_swapgs_x64.c_1017_bit_18 "
         "owned_by=body_clobbers.nova_which_already_names_and_refuses_it\n");
  printf("NTASM_NOVA_CALL_FOLD checks=%u failures=%u cases=%u\n",checks,failures,cases);
  return failures?1:0;
}
