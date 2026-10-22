#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntasm_pipeline_parity.h"

/* ====================== pipeline parity ==============================
   Every non zero code this gate asserts is a CLAIM ABOUT the 34 stage
   pipeline of validate.nova, and this entry compiles a SUB-CHAIN of it:
   index (semantics), features, callable_names, register_widths, clobbers,
   effects, body_effects, body_intrinsics, body_clobbers, contracts,
   feature_requirements, refs, calls, call_effects, call_clobbers,
   call_contracts.  Nothing measured that claim until the shared helper
   nova/ntasm_pipeline_parity.h ran every source this file asserts through
   the 41 module validate image as well and compared the two verdicts.  The
   table beneath is the set of (this gate, the pipeline) divergence pairs
   this file exhibits, written down from that measurement: a pair that is
   not listed fails the gate, and a listed pair that stops occurring fails
   it too, so the table cannot rot into a comment.

   326 is the one non zero code this gate asserts.  It belongs to stage 34,
   call_contracts, and to stage 23, control_flow, and the verdict it is here
   is stage 34's: a call predicate that the caller's own declarations do not
   discharge, with the family in out[2] (1 feature, 2 non_null, 3 canonical,
   4 stack_aligned, 6 stack_in, 7 interrupts_enabled, 8 interrupts_disabled,
   9 msr_initialized, 10 mapping_present, 11 valid_user_return).  Stage 34 is
   the LAST of the 34, so every pair below is the same shape: this entry
   links sixteen stages and reaches 34, while the pipeline reaches an
   earlier stage that this entry's link set does not carry, and that stage
   refuses the same source first, with its own code for its own question.
   Every reason word below was read back out of the run log of this gate,
   through this file's own vimage, and the stage that owns each code was
   read out of the helper's own FAIL line.

     {326,330}  one case, "alone lie effects store reads only": the fixture
                writes the EFFECT atom `reads_mem` into the caller's
                `clobbers` set instead of into `effects`.  The pipeline stops
                at stage 16, clobbers, which answers 330 at 12:11 -- the
                column `reads_mem` starts in -- because a name that charges
                no register bit is an explicit refusal and never a silently
                dropped set entry.  Stage 16 IS in this entry's link set, but
                the entry's own path reaches stage 34 without asking it: the
                entry reports the call predicate, not the set.

     {326,328}  one case, "out parameter shifts subject": the callee binds
                `out p:u64 @r8` and then also writes `r8` in its body, so it
                declares `clobbers {rax,r8}`.  The pipeline stops at stage 17,
                abi, which answers 328 reason 6 at the callee declaration
                line: a clobbers entry charges a bit that one of the
                declaration's own out parameters delivers.  abi.nova is NOT
                linked here at all, so this entry cannot see it.  (The
                sibling case "out subject maps to in argument" carries the
                same 328 and is the WEAKER direction -- this entry accepts it
                -- so the helper counts it and does not fail it.)

     {326,332}  four cases, the "alone lie effects" store family including
                "alone lie all guards": the caller declares `effects {}` and
                its body really stores.  The pipeline stops at stage 20,
                body_effects, which answers 332 with the instruction
                position, category 3 (write) and the missing `writes_mem`
                bit.  This entry does link body_effects, but it runs it as
                the guard in front of stage 34 and, when the guard finds
                nothing, still answers the CALL question with 326.

     {326,334}  nine cases, the "alone lie" cli/sti/swapgs/sysretq/rdmsr/
                wrmsr/iretq/popfq family and "alone lie clobbers add rsp":
                an atom or fixed intrinsic whose effect the `effects` set
                does not name.  The pipeline stops at stage 21,
                body_intrinsics, which answers 334 with the instruction
                position, category 1 and the missing atom bitset (65, that
                is bits 1 and 64, for the `cli` case).  Linked here, run as a
                guard, and then not consulted for the answer.

     {326,353}  REMOVED 7 October 2026: "out subject unprovable" returns the
                bare register `rax`, and return_types now accepts a register
                spelling of the declared width (the C reference's own rule,
                frontend.c NTF_X_REGISTER), so the pipeline no longer stops
                at stage 24 with 353 and the gate reported the pair as one
                that never occurs.  return_types is not linked here.

     {326,335}  five cases, the "alone lie clobbers" rsp family: `mov rsp`,
                `mov esp`, `pop`, `push` and `xchg` with the `clobbers` set
                not naming the frame family.  The pipeline stops at stage 22,
                body_clobbers, which answers 335 with the missing family
                bit (16, the rsp family, for the `mov rsp,rbx` case).
                Linked here, run as a guard, and then not consulted.

     {326,354}  one case, "literal not proved": the caller writes
                `call leaf(1)` where leaf wants a `ptr<user,u64>`.  The
                pipeline stops at stage 29, call_types, which validates call
                ARGUMENT TYPES and answers 354 reason 1, argument type
                mismatch, at 13:11 -- the column the literal starts in.
                call_types is not linked here, so this entry reaches the
                predicate question without the argument question.

     {326,325}  one case, "store honest": the nested callee `side` declares
                `effects {writes_mem(user)}` and really stores, and the
                CALLER declares `effects {}`.  The pipeline stops at stage 32,
                call_effects, which requires a caller to declare a superset
                of the callee's write spaces and answers 325 category 3 with
                the missing bitset.  That is the only pair here in the OTHER
                direction: the entry reaches stage 34 while the pipeline
                objects at stage 32, so the entry asserts a stage the pipeline
                reaches LATER.  Both verdicts are correct -- main really does
                not declare the write, so its mapping_present really is not
                established -- but the entry is asked the predicate question
                alone, because this case runs the entry in mode 1, where
                tests/call-contracts-entry.nova calls call_contracts.check
                with no pass in front of it.

     {326,336}  forty four cases, the fail-closed rows: "row A/B/C alien
                opcode" over {retq, leave, pushq rax, popq rax, sfenceq,
                qwap rax}, five of the eight "row B unanchored form" rows, and
                nine of the "row B anchored memory write" rows.  336 is the
                pipeline's cannot-encode verdict, and it is the one code here
                that four stages can return -- body_effects(20),
                body_clobbers(22), control_flow(23) and call_contracts(34),
                the last two of which ARE in this entry's link set.  The
                grammar admits every NAME as a statement, so an operand shape
                the x86_64 encoder cannot represent reaches a standalone
                check; this entry fails closed by treating the form as a
                writer and then answering 326 because the call predicate is
                not discharged, while the pipeline refuses earlier with
                "cannot encode" and never reaches a predicate question.

   The stage set of this entry is a link set of sixteen, and not a prefix of
   the 34 stage order (expand, targets, versions, symbol_names, types,
   constant_types, literal_initializers, parameters, locals, bindings,
   register_bindings, abi, pointer_spaces, control_flow, return_types and
   call_types are all stages the link set skips ahead of, behind or between
   the sixteen), so the two sides are being asked different questions and
   equality of verdicts is not available here.  The helper says so in its
   own banner on every run (prefix=no) rather than leaving it to this
   comment.

   ====================== A SECOND LIMIT, AND A STRICTER ONE =============
   THE ORACLE IS NOT AUTHORITATIVE ON THE MEMORY PREDICATE, AND THIS GATE
   IS STRICTER THAN THE ORACLE THERE.  Read the family-10 rows -- the
   nested-call narrowing, and the four cycle rows -- with this in hand.

   The reference (frontend.c, nt_frontend_compile) recognises ten predicate
   names and proves four of them: feature, non_null, canonical, stack_aligned.
   Every other recognised name is answered NTF_E_UNSUPPORTED, 600, "recognized
   but proof checking is not implemented".  mapping_present is one of the six
   it does not prove.  The reference therefore has NO memory predicate, and
   so no verdict against which caller_caps bit 8 -- "no memory write" -- could
   be wide or narrow.

   This gate nonetheless answers that bit, and answers it STRICTLY: it walks
   the callee body, cuts a cycle at a depth bound, and refuses when it cannot
   prove the mapping.  So every family-10 refusal in this file is a refusal of
   a predicate the oracle does not implement, and comparing it to the
   oracle's 600 would be comparing a verdict to an absence.  The five
   reference rows at the end of main MEASURE the oracle's answer rather than
   assuming it, and the two of them under the cycle block's comment measure
   the REASON.

   WHAT THAT DOES AND DOES NOT MEAN.  It means the over-estimation of call
   memory writes is undecidable from the reference as written, and this file
   pins the coverage gap so the next reader does not re-derive it.  It does
   NOT mean this gate agrees with the reference on mapping_present, and the
   rows here must not be read as a parity claim.  It does NOT establish that
   the product's answer is correct: it establishes that the product has one
   and the reference has none, which is a fact about coverage.  Nothing here
   bounds how tight body_writes_memory_depth is, and nothing here would
   notice a fixpoint that admitted one of the four cycles. */
/* The two pairs the three-population table adds, in the same form as the
   ones above: a pair that is not listed fails this gate, and a listed pair
   that stops occurring fails it too, so neither can rot into a comment and
   leave the ledger quietly wrong.  The pairs are the two the feature row of
   the three-population table below produces, and each says what the two codes
   are answering, because "the pipeline stops earlier" is a fact about the
   link set and not a licence for the entry to be wrong.
     {326,344}  two cases, the feature row of the three-population table: the
                callee asks feature(sse2) and the module does not carry the
                sse2 bit, or carries a different one. The pass ALONE answers
                326 family 1 because the bit is simply absent from the module
                mask it was handed. The 41 module pipeline answers 344 at
                feature_requirements, stage 26, which asks the same question
                earlier and is not in this entry's sixteen-stage link set. The
                two agree on the VERDICT, which is the only thing a family-1
                refusal can be compared on: neither has a stack to walk, a
                register to have moved or a memory to have been written, so
                there is no second question for 326 to be the wrong answer to.
     {326,343}  one case, the same row's unprovable column: the callee asks
                feature(nosuch) and the name is not a feature at all. The
                pass alone treats an unknown name as a bit it cannot find and
                answers 326 family 1; the pipeline answers 343 at features,
                stage 5, which knows the catalogue and refuses the name. Here
                the two are answering DIFFERENT questions -- "is this bit set"
                against "is this a feature" -- and 343 is the stricter of the
                two, so nothing is proved here that 326 did not also refuse.
                Declared because the helper demands it, not because the two
                verdicts are the same claim. */
static const NgParityPair ng_parity_pairs[]={
  {326,325},{326,328},{326,330},{326,332},{326,334},{326,335},{326,336},
  {326,343},{326,344},{326,354}};
static NgParitySpec ng_parity={
  "call_contracts",
  {"index","features","callable_names","register_widths","clobbers","effects",
   "body_effects","body_intrinsics","body_clobbers","contracts",
   "feature_requirements","refs","calls","call_effects","call_clobbers",
   "call_contracts"},16,
  1,
  ng_parity_pairs,
  (unsigned)(sizeof ng_parity_pairs / sizeof ng_parity_pairs[0]),
  0,0,0,0,0,0,0,0,NULL};
static char ng_parity_err[256];

/* ================= the C parity oracle, asked directly ====================
   nt_x64_effects, x64.h:114 and x64.c:838, publishes the memory footprint of
   one exact validated operand form. Every expectation in the shape==3 block
   below is computed from it, not written here. Measured, not asserted:
   push, pushfq and call all publish stack_write 1 with memory_write 0, and
   ret, return, pop, popfq and iretq publish stack_read 1 with memory_write 0.
   So the oracle charges a call a stack write exactly as it charges a push,
   and the eight bytes a call and its callee push and pop are the same eight
   bytes. That is the fact the shape==3 narrowing rests on, and the harness
   reads it back at run time instead of trusting this comment. */
#define ORACLE_NO UINT64_C(0x8000000000000000)
static const NtX64Context ORACLE_CTX={NT_X64_ALL_FEATURES,0};
static NtX64Operand orx_reg(unsigned r,unsigned w){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_REG;o.reg=r;o.width=w;return o;}
static NtX64Operand orx_mem(unsigned w){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_MEM;o.width=w;o.base=3;o.index=-1;o.scale=1;return o;}
static NtX64Operand orx_imm(unsigned w){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_IMM;o.width=w;o.imm=1;return o;}
/* kind 0 register, 1 memory, 2 immediate. Footprint bits: 1 stack_write,
   2 stack_read, 4 memory_write, 8 memory_read. ORACLE_NO when
   nt_x64_encode refuses the form, which is an answer, never a zero. */
static uint64_t oracle_fp(const char*m,unsigned nops,unsigned k0,unsigned k1,unsigned w){
  NtX64Effects fx;memset(&fx,0,sizeof fx);
  if(nops>2)return ORACLE_NO;
  NtX64Operand a[2];
  for(unsigned i=0;i<nops;i++){unsigned k=i?k1:k0;
    a[i]=k==1?orx_mem(w):k==2?orx_imm(w):orx_reg(0,w);}
  if(nt_x64_effects(m,a,nops,ORACLE_CTX,&fx)!=NT_X64_OK)return ORACLE_NO;
  return (uint64_t)((fx.stack_write?1u:0u)|(fx.stack_read?2u:0u)
                   |(fx.memory_write?4u:0u)|(fx.memory_read?8u:0u));
}
/* The one fact the shape==3 narrowing turns on, computed: a call and a
   return are a balanced pair of stack accesses and neither writes memory.
   A push and a call publishing the same stack_write is what makes the pair
   the same eight bytes, so the harness refuses to take the comment on faith
   and recomputes both halves. */
static uint64_t frame_pair_balanced(void){
  uint64_t c=oracle_fp("call",1,0,0,64), r=oracle_fp("return",0,0,0,64);
  uint64_t p=oracle_fp("push",1,0,0,64);
  if(c==ORACLE_NO||r==ORACLE_NO||p==ORACLE_NO)return 0;
  if((c&1u)==0||(r&2u)==0)return 0;
  if((c&4u)||(r&4u))return 0;
  if((c&1u)!=(p&1u))return 0;
  return 1;
}
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*load(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[4];}Run;
/* The call_contracts entry takes a third parameter, its mode, and refuses an
   argument count it was not compiled for, so the two images need two call
   shapes: five words for the call_contracts entry, four for validate, whose
   entry takes two. */
/* The per-call declaration for this entry's two modes, at the one place the
   mode is visible.  ng_parity.stages is the LINK SET, all sixteen stage
   modules this image carries, and it is what `prefix=no` and the declared-pair
   ledger are computed from.  The B direction may not be handed it, because
   this entry has two paths that run different stages:

     mode 0  the shipped order: semantics.index(2), callable_names(6),
             effects(19), contracts(25), features(5),
             feature_requirements(26), ntasm_refs(27), calls(28),
             body_effects(20), body_intrinsics(21), body_clobbers(22),
             call_effects(32), call_clobbers(33), call_contracts(34).
     mode 1  call_contracts.check(34) ALONE, with no pass in front of it, so
             a case can ask what the pass proves by itself.

   Thirty six mode 1 cases went red on the B direction because this harness
   handed it the link set: a caller declaring effects {} while its body stored
   is refused by body_effects(20) in the pipeline and accepted by mode 1, and
   the link set contains body_effects.  The pipeline is right about stage 20
   and mode 1 never asked stage 20.  Both modes return a stage verdict, so
   `verdict` is 1 on both; the difference is the stage set, not the shape. */
static NgParityCall cc_call_of(uint64_t mode) {
  static const char *const m0[]={"index","callable_names","effects","contracts",
    "features","feature_requirements","refs","calls","body_effects",
    "body_intrinsics","body_clobbers","call_effects","call_clobbers",
    "call_contracts"};
  NgParityCall c; unsigned i;
  memset(&c, 0, sizeof c);
  c.verdict=1;
  if (mode==1) { c.stages[0]="call_contracts"; c.stage_count=1; return c; }
  for (i=0;i<sizeof m0/sizeof m0[0];i++) c.stages[i]=m0[i];
  c.stage_count=(unsigned)(sizeof m0/sizeof m0[0]);
  return c;
}
static NgParityCall cc_call;   /* set once by run() and run5() below */
static Run run5(const NovaHostImage*i,const char*name,const char*s,uint64_t words,uint64_t mode){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words,mode};r.returned=i->entry(&c,a,5);cc_call=cc_call_of(mode);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");ng_parity_check_as(&checks,&failures,&ng_parity,name,s,r.returned,&cc_call);return r;}
static Run run(const NovaHostImage*i,const char*name,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);cc_call=cc_call_of(0);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");ng_parity_check_as(&checks,&failures,&ng_parity,name,s,r.returned,&cc_call);return r;}
static void vok(const NovaHostImage*i,const char*n,const char*s,uint64_t d,uint64_t c,uint64_t p,uint64_t mode){Run r=run5(i,n,s,4,mode);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=d||r.out[1]!=c||r.out[2]!=p||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t d,uint64_t c,uint64_t p){vok(i,n,s,d,c,p,0);}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t words,uint64_t family,uint64_t index,int untouched){Run r=run5(i,n,s,words,0);cases++;checks++;int bad=r.returned!=326||r.runtime;if(untouched)bad|=r.out[0]!=guard||r.out[1]!=guard;else bad|=r.out[0]==guard||r.out[1]==guard||r.out[2]!=family||r.out[3]!=index;if(bad){failures++;fprintf(stderr,"FAIL error %s ret=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void badinput(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run5(i,n,s,words,0);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL invalid %s ret=%llu\n",n,(unsigned long long)r.returned);}}
/* One based line and column of the nth occurrence of needle, so every error
   case asserts the exact reported span instead of only its family. */
static void where(const char*s,const char*needle,int nth,uint64_t*line,uint64_t*column){uint64_t ln=1,col=1;int seen=0;size_t n=strlen(needle);const char*p=s;for(;;){if(*p=='\0')break;if(*p=='\n'){ln++;col=1;p++;continue;}if(strncmp(p,needle,n)==0&&(seen++==nth-1)){*line=ln;*column=col;return;}col++;p++;}}
/* Full four word position check: 326 line,column,family,ordinal and
   365 line,column,reason,ordinal, with the output buffer left untouched. */
static void verrp(const NovaHostImage*i,const char*n,const char*s,uint64_t code,const char*needle,int nth,uint64_t family,uint64_t index,uint64_t mode){uint64_t line=0,column=0;where(s,needle,nth,&line,&column);Run r=run5(i,n,s,4,mode);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=family||r.out[3]!=index){failures++;fprintf(stderr,"FAIL span %s ret=%llu want %llu at %llu,%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)code,(unsigned long long)line,(unsigned long long)column,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void errp(const NovaHostImage*i,const char*n,const char*s,uint64_t code,const char*needle,int nth,uint64_t family,uint64_t index){verrp(i,n,s,code,needle,nth,family,index,0);}
/* The same two verdicts with check alone, mode 1: no guarding pass runs first,
   so these cases ask call_contracts.check what it proves by itself. */
static void aok(const NovaHostImage*i,const char*n,const char*s,uint64_t d,uint64_t c,uint64_t p){vok(i,n,s,d,c,p,1);}
static void aerrp(const NovaHostImage*i,const char*n,const char*s,uint64_t code,const char*needle,int nth,uint64_t family,uint64_t index){verrp(i,n,s,code,needle,nth,family,index,1);}
/* Validate entry success convention: 35,token_count,node_count,0 with both
   counters nonzero. The leading 35 is validate.validate's own documented
   success token, the LAST stage, not a number this harness chooses
   (validate.nova:325 "Returns 0 after writing out[0]=35, out[1]=tree.token_count"
   and validate.nova:358 `out[0]=35;`), and it is the third value this literal
   has taken: it said 33 before the expansion stage became the first stage of
   that pipeline, 34 while the pipeline ended at call_contracts, and 35 since
   machine_ir was wired in as stage 35. All three moves were the pipeline's
   and not this harness's, and this one was missed the same way the module
   list below was: the row kept the old number because nothing connects the
   literal to the stage order. tests_ntasm_validate.c:17 reads the same token
   off the same 43 module image and says 35. */
static void okv(const NovaHostImage*i,const char*n,const char*s){Run r=run(i,n,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=35||r.out[1]==0||r.out[2]==0||r.out[3]){failures++;fprintf(stderr,"FAIL validate %s ret=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* A guarding pass verdict, identical through both entries. 332 writes the
   instruction position, category 2 read or 3 write, and the missing space bit.
   334 writes the instruction position, category 1, and the missing atom
   bitset. 335 writes the register position, category 1, and the missing
   family bit. */
/* five is 1 for the call_contracts image, whose entry takes the mode word, and
   0 for the validate image, whose entry takes two words. */
static void stage(const NovaHostImage*i,const char*n,const char*s,uint64_t code,const char*needle,int nth,uint64_t cat,uint64_t bit,int five){uint64_t line=0,column=0;where(s,needle,nth,&line,&column);Run r=five?run5(i,n,s,4,0):run(i,n,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=cat||r.out[3]!=bit){failures++;fprintf(stderr,"FAIL stage %s ret=%llu want %llu at %llu,%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)code,(unsigned long long)line,(unsigned long long)column,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* Verdict probe: prints the raw four word result of one source through one
   entry mode without asserting anything, so a RED run states in the log
   whether the predicate was proved or refused instead of only showing a
   mismatch. It is a probe, not a check: the verdict it prints is asserted by
   the errp and aerrp case that names the same source. */
static void probe(const NovaHostImage*i,const char*n,const char*s,uint64_t mode){Run r=run5(i,n,s,4,mode);cases++;checks++;fprintf(stderr,"PROBE %s mode=%llu ret=%llu out=%llu,%llu,%llu,%llu -> %s\n",n,(unsigned long long)mode,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3],(r.returned||r.runtime)?"REFUSED":"ACCEPTED");}
/* The property the shipped pipeline owes on a lying declaration: the call is
   not proved. It does not name which pass refuses, because the pipeline has
   five guarding passes in front of call_contracts and any one of them may
   legitimately be the first to catch the body. Pinning the code here would
   make this case a change detector for a file this lot does not own. */
static void noproof(const NovaHostImage*i,const char*n,const char*s,uint64_t mode){Run r=run5(i,n,s,4,mode);cases++;checks++;if(r.returned==0&&!r.runtime){failures++;fprintf(stderr,"FAIL noproof %s ret=0 out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static char S[16384];
/* Zero argument callee, one call statement in the caller. */
static const char*z(const char*creq,const char*mreq,const char*meff,const char*mclob){snprintf(S,sizeof S,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {%s} {\nreturn 0\n}\nfn main()->u64\neffects {%s}\nclobbers {%s}\nrequires {%s} {\ncall leaf()\nreturn 0\n}\n}\n",creq,meff,mclob,mreq);return S;}
/* One pointer parameter on both sides, so a subject can be remapped. */
static const char*p(const char*creq,const char*ceens,const char*meff,const char*mreq,const char*meens,const char*mclob){snprintf(S,sizeof S,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {%s}\nensures {%s} {\nreturn 0\n}\nfn main(in q:ptr<user,u64> @rdi)->u64\neffects {%s}\nclobbers {%s}\nrequires {%s}\nensures {%s} {\ncall leaf(q)\nreturn 0\n}\n}\n",creq,ceens,meff,mclob,mreq,meens);return S;}
/* Two scalar parameters, for the two argument frame predicate. */
static const char*t(const char*creq,const char*ceens,const char*mreq,const char*meens,const char*mclob,const char*call){snprintf(S,sizeof S,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in a:u64 @rdi,in b:u64 @rsi)->u64\neffects {}\nclobbers {}\nrequires {%s}\nensures {%s} {\nreturn 0\n}\nfn main(in c:u64 @rdi,in d:u64 @rsi)->u64\neffects {}\nclobbers {%s}\nrequires {%s}\nensures {%s} {\n%s\nreturn 0\n}\n}\n",creq,ceens,mclob,mreq,meens,call);return S;}
/* Ordinary callee carrying an ensures clause, for the 365 diagnostic. */
static const char*nvz(const char*ceens,const char*mreq,const char*meens){snprintf(S,sizeof S,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {}\nensures {%s} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {}\nrequires {%s}\nensures {%s} {\ncall leaf()\nreturn 0\n}\n}\n",ceens,mreq,meens);return S;}
/* The same clause on a never callee, which produces no caller post state. */
static const char*nvi(const char*ceens,const char*mreq,const char*meff,const char*mclob){snprintf(S,sizeof S,"module m\ntarget x86_64-nexora-none\nimport a.g as zleaf: fn()->never\neffects {}\nclobbers {}\nrequires {}\nensures {%s}\nsection .text {\nfn main()->u64\neffects {%s}\nclobbers {%s}\nrequires {%s} {\ncall zleaf()\nreturn 0\n}\n}\n",ceens,meff,mclob,mreq);return S;}
/* The z, p and t shapes with one injected caller body line, so a case can
   declare one thing in effects and clobbers and do another in the body. The
   body line goes before the call, inside the caller declaration span. */
static const char*zb(const char*creq,const char*mreq,const char*meff,const char*mclob,const char*body){snprintf(S,sizeof S,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {%s} {\nreturn 0\n}\nfn main()->u64\neffects {%s}\nclobbers {%s}\nrequires {%s} {\n%s\ncall leaf()\nreturn 0\n}\n}\n",creq,meff,mclob,mreq,body);return S;}
static const char*pb(const char*creq,const char*mreq,const char*meff,const char*mclob,const char*body){snprintf(S,sizeof S,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {%s} {\nreturn 0\n}\nfn main(in q:ptr<user,u64> @rdi)->u64\neffects {%s}\nclobbers {%s}\nrequires {%s} {\n%s\ncall leaf(q)\nreturn 0\n}\n}\n",creq,meff,mclob,mreq,body);return S;}
static const char*tb(const char*creq,const char*mreq,const char*mclob,const char*body){snprintf(S,sizeof S,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in a:u64 @rdi,in b:u64 @rsi)->u64\neffects {}\nclobbers {}\nrequires {%s} {\nreturn 0\n}\nfn main(in c:u64 @rdi,in d:u64 @rsi)->u64\neffects {}\nclobbers {%s}\nrequires {%s} {\n%s\ncall leaf(c,d)\nreturn 0\n}\n}\n",creq,mclob,mreq,body);return S;}
/* The p shape with an injected body line, for the 365 coverage diagnostic on
   a caller whose body is not empty. */
static const char*ps(const char*creq,const char*ceens,const char*meff,const char*mreq,const char*meens,const char*mclob,const char*body){snprintf(S,sizeof S,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {%s}\nensures {%s} {\nreturn 0\n}\nfn main(in q:ptr<user,u64> @rdi)->u64\neffects {%s}\nclobbers {%s}\nrequires {%s}\nensures {%s} {\n%s\ncall leaf(q)\nreturn 0\n}\n}\n",creq,ceens,meff,mclob,mreq,meens,body);return S;}
/* ============ shape==3: a NESTED call, and what it costs the caller =======
   The call under proof is excluded from the body halves because a call and
   the return of its callee are the balanced frame pair. ns puts a SECOND
   call statement in the same body, so the question this block asks is
   whether that second call is charged for the same reason or a different
   one. leaf is the call under proof and requires mapping_present(p); side is
   the nested callee, with sret as its return type, seff as its declared
   effects and sbody as its body. */
static const char*ns(const char*sret,const char*seff,const char*sbody,
                     const char*meff,const char*mreq){
  snprintf(S,sizeof S,
    "module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\n"
    "requires {mapping_present(p)} {\nreturn 0\n}\n"
    "fn side()->%s\neffects {%s}\nclobbers {}\nrequires {} {\n%s\nreturn 0\n}\n"
    "fn main(in q:ptr<user,u64> @rdi)->u64\neffects {%s}\nclobbers {}\n"
    "requires {%s} {\ncall side()\ncall leaf(q)\nreturn 0\n}\n}\n",
    sret,seff,sbody,meff,mreq);return S;}
/* What the pass must answer, computed. want is 1 when the nested call is a
   balanced frame pair over a callee that stores nothing, so it costs the
   caller nothing and mapping_present survives. The callee body must publish
   neither a memory_write (bit 4) nor a stack_write (bit 1): a callee that
   pushes is not balanced, because the return that closes the pair pops the
   return address and not the eight bytes the callee itself pushed. A
   stack_read is free, since it consumes what the call pushed. want is also 0
   when the callee returns never, so nothing balances the call, and when
   frame_pair_balanced is false, which would mean the oracle stopped agreeing
   that a call and a return are the same eight bytes and the narrowing would
   have to be re-derived rather than trusted. */
static void nsverdict(const char*m,unsigned nops,unsigned k0,unsigned k1,unsigned w,
                      int returns,int*want){
  uint64_t fp=oracle_fp(m,nops,k0,k1,w);
  *want=frame_pair_balanced()&&returns&&fp!=ORACLE_NO&&(fp&5u)==0;
}
/* One nested call case. The body of the nested callee is one instruction
   named by the caller of this helper, and the expectation is derived from
   nt_x64_effects for that same instruction, so a case and its answer are one
   fact read from the oracle. want 1 asserts the call is proved, want 0
   asserts it is refused with 326 at the mapping_present predicate. */
static void nscase(const NovaHostImage*i,const char*tag,const char*s,int want){
  Run r=run5(i,tag,s,4,1);cases++;checks++;
  if(want){
    if(r.returned||r.runtime){failures++;fprintf(stderr,"FAIL nested %s ret=%llu want proved out=%llu,%llu,%llu,%llu\n",tag,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}
  }else{
    if(r.returned!=326||r.runtime||r.out[2]!=10){failures++;fprintf(stderr,"FAIL nested %s ret=%llu want 326 family 10 out=%llu,%llu,%llu,%llu\n",tag,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}
  }
}
/* A whole module from a body fragment, for the rsp rows below. It is a
   file-scope function and not a fixture like z/p/t beside it, because those
   take named parts and these rows have to state a whole `effects` and a whole
   `clobbers` clause per function, which is the thing being asked about. The
   buffer is static and single: every call formats into it and consumes it
   before the next call formats over it, and no row below holds two at once. */
static char pm_scratch[4096];
static const char*PM(const char*body){
  snprintf(pm_scratch,sizeof pm_scratch,
    "module m\ntarget x86_64-nexora-none\nsection .text {\n%s}\n",body);
  return pm_scratch;
}
/* THE FULL-PIPELINE RUNNER, and it exists to settle one composition question:
   whether the stages IN FRONT of call_contracts close what call_contracts
   alone admits. The table in call_contracts.nova compares nt_compile against
   call_contracts.check ALONE, and a set containment about one pass is not a
   claim about the pipeline. This asks the 43 module validate image the same
   bodies and asserts their exact four words, so the composition is read off a
   run and a pipeline that later stops charging the stack is a red row rather
   than a different number in a log nobody diffs.

   IT DELIBERATELY BYPASSES ng_parity_check_as, which run() calls. That helper
   feeds the parity table, and a measurement instrument that also mutates the
   table it is being read next to cannot be told apart from one that changed
   it. The rows below are new sources the parity table does not declare, so
   letting them through would have moved the very counter a reader compares. */
static void verpv(const NovaHostImage*i,const char*n,const char*s,uint64_t code,
                  uint64_t w0,uint64_t w1,uint64_t w2,uint64_t w3){
  Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};
  CHECK(nova_context_init_v2(&c),"validate assert context");
  uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,4*8,1);
  uint64_t a[]={sh,strlen(s),oh,4};r.returned=i->entry(&c,a,4);r.runtime=c.error;
  CHECK(nova_context_destroy_v2(&c),"validate assert cleanup");
  cases++;checks++;
  if(r.returned!=code||r.runtime||r.out[0]!=w0||r.out[1]!=w1||r.out[2]!=w2||r.out[3]!=w3){
    failures++;fprintf(stderr,"FAIL validate %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu want %llu,%llu,%llu,%llu\n",
      n,(unsigned long long)r.returned,(unsigned long long)r.runtime,
      (unsigned long long)r.out[0],(unsigned long long)r.out[1],
      (unsigned long long)r.out[2],(unsigned long long)r.out[3],
      (unsigned long long)w0,(unsigned long long)w1,
      (unsigned long long)w2,(unsigned long long)w3);}
}
/* ===================== THE REFERENCE IS NOT AUTHORITATIVE ON THE MEMORY
   PREDICATE, AND THIS FILE IS STRICTER THAN IT IS. ======================

   Every other number in this file is a Nova verdict read off a run of the
   shipped pipeline. This block is the only one that reads the C reference
   directly, through nt_frontend_compile, and it was added because the fact
   it pins was measured NOWHERE in the tree: two harnesses name
   mapping_present -- this one and tests_ntasm_contracts.c -- and neither
   calls a reference function, so the reference's own verdict on the
   predicate that this whole gate is about had never been run.

   WHAT IT PINS. caller_caps is four bits and the predicates that consume
   them are not implemented by the reference. frontend.c recognises ten
   predicate names and proves exactly four of them -- feature, non_null,
   canonical, stack_aligned -- and answers NTF_E_UNSUPPORTED, 600, to every
   other, with the message "recognized but proof checking is not
   implemented". mapping_present is one of the other six. So the reference
   has NO verdict against which caps bit 8, "no memory write", could be wide
   or narrow, and that is what makes the over-estimation question
   undecidable as written rather than merely unsettled.

   THE PARITY CAVEAT, WHICH IS NOT OPTIONAL AND IS NOT A COMMENT SOMEWHERE
   ELSE. The rows below say the reference refuses mapping_present. They do
   NOT say this gate agrees with the reference on mapping_present, because
   this gate does not: nscase(..., want 0) at family 10 above is the PRODUCT
   proving a body writes memory and refusing, where the reference would have
   refused for the opposite and uninformative reason -- it cannot check the
   predicate at all. A gate that pinned the stricter behaviour without
   recording this would read as a parity claim it is not making. It is
   recorded here, at the rows, in the same voice the other published limits
   in this file use.

   WHAT THE BLOCK DOES NOT ESTABLISH. It does not establish that the
   product's answer is the right one. It establishes that the product has an
   answer and the reference has none, which is a fact about coverage and not
   about correctness. Nothing here bears on whether the depth bound in
   body_writes_memory_depth is tight, nor on whether a fixpoint would admit
   any of the cycles the rows above refuse.
*/
/* 0 == the reference ACCEPTED. Otherwise p.diagnostics[0].code. */
static uint64_t ref_verdict(const char*s){
  NtFInput in={"call_contracts_ref.nt",s,strlen(s)};NtFProgram p;
  nt_frontend_compile(&in,1,&p);
  uint64_t code=p.diagnostic_count?p.diagnostics[0].code:0;
  nt_frontend_free(&p);return code;}

 /* ONE SOURCE BUILDER, and it takes the parts rather than returning a
    finished source, for a reason this block learned the hard way. z, p and t
    above all format into one shared static S, so building a TABLE by calling
    them leaves every row pointing at the same bytes, the last one formatted:
    the first version of this block reported family 11 in all ten VIOLATED
    cells, which is the family of the last source in the table, and a table
    that reports one row ten times is worse than no table because it looks
    like coverage. So each cell is formatted into its OWN buffer here, from
    its OWN parts, and consumed before the next one is written. */
 static void popsrc(char*b,size_t n,unsigned shape,const char*feats,
                    const char*creq,const char*mreq,const char*mclob){
  const char*head=feats&&feats[0]?feats:"";
  if(shape==1u)
    snprintf(b,n,"module m\ntarget x86_64-nexora-none\n%s"
      "section .text {\n"
      "fn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {%s} {\nreturn 0\n}\n"
      "fn main(in q:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {%s}\nrequires {%s} {\n"
      "call leaf(q)\nreturn 0\n}\n}\n",head,creq,mclob,mreq);
  else if(shape==2u)
    snprintf(b,n,"module m\ntarget x86_64-nexora-none\n%s"
      "section .text {\n"
      "fn leaf(in a:u64 @rdi,in b:u64 @rsi)->u64\neffects {}\nclobbers {}\nrequires {%s} {\nreturn 0\n}\n"
      "fn main(in c:u64 @rdi,in d:u64 @rsi)->u64\neffects {}\nclobbers {%s}\nrequires {%s} {\n"
      "call leaf(c,d)\nreturn 0\n}\n}\n",head,creq,mclob,mreq);
  else
    snprintf(b,n,"module m\ntarget x86_64-nexora-none\n%s"
      "section .text {\n"
      "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {%s} {\nreturn 0\n}\n"
      "fn main()->u64\neffects {}\nclobbers {%s}\nrequires {%s} {\ncall leaf()\nreturn 0\n}\n}\n",
      head,creq,mclob,mreq);
 }

int main(void){const char*paths[]={"tests/nova/tests/call-contracts-entry.nova","compiler/nova/analysis/calls/call_contracts.nova","compiler/nova/analysis/calls/call_effects.nova","compiler/nova/analysis/calls/call_clobbers.nova","compiler/nova/analysis/abi/body_effects.nova","compiler/nova/analysis/abi/body_intrinsics.nova","compiler/nova/analysis/abi/body_clobbers.nova","compiler/nova/analysis/calls/calls.nova","compiler/nova/frontend/refs.nova","compiler/nova/analysis/abi/contracts.nova","compiler/nova/analysis/abi/feature_requirements.nova","compiler/nova/analysis/abi/features.nova","compiler/nova/analysis/abi/effects.nova","compiler/nova/analysis/abi/clobbers.nova","compiler/nova/analysis/types/register_widths.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova","compiler/nova/analysis/abi/abi.nova"};char*sources[21]={0};NtFInput inputs[21];for(unsigned i=0;i<21;i++){size_t n=0;sources[i]=load(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<21;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,21,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);
/* Second image: the full validate pipeline, used as the reference the
   standalone entry must agree with.

   THE LIST IS NOT WRITTEN HERE. It used to be, as a forty two name copy of
   validate.nova's import closure, and the copy is what went red: validate.nova
   imports machine_ir (validate.nova:43) and the copy did not carry it, so the
   image stopped compiling (V302 at 43:8) and every parity row below it was
   skipped, which is the eleven `declared divergence ... never occurs` lines
   this gate was printing -- not eleven stale declarations, but one missing row
   in a second copy of a list the tree already keeps checked. The list this
   image uses is ng_parity_paths, the 43 module validate image the validate
   gate itself compiles and the one ng_parity_imports_present watches: it fails
   if validate.nova imports a module it does not carry, which is the check that
   would have turned red when machine_ir was wired in. tests_ntasm_validate.c
   and ng_parity_paths carry the same 43 rows in the same order. */
char*vsources[NG_PARITY_MODULES]={0};NtFInput vinputs[NG_PARITY_MODULES];for(unsigned i=0;i<NG_PARITY_MODULES;i++){size_t n=0;vsources[i]=load(ng_parity_paths[i],&n);vinputs[i]=(NtFInput){ng_parity_paths[i],vsources[i],n};}int vall=1;for(unsigned i=0;i<NG_PARITY_MODULES;i++)if(!vsources[i])vall=0;CHECK(vall,"validate sources load");NtArtifact b={0};int vcompiled=vall&&nova_compile_many_v2(vinputs,NG_PARITY_MODULES,&b);CHECK(vcompiled,"validate modules compile");if(!vcompiled)fprintf(stderr,"V%u %zu:%zu %s\n",b.error.code,b.error.line,b.error.column,b.error.message);NovaHostImage vimage={0};CHECK(vcompiled&&nova_host_map(&b,&vimage),"validate image maps");int parity=ng_parity_begin(&ng_parity,&failures,ng_parity_err,sizeof ng_parity_err);if(image.memory&&vimage.memory&&parity==0){
/* Regression: ABI clauses share kind 28 with call statements. */
const char *explicit_abi_none="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
ok(&image,"explicit ABI is not a call",explicit_abi_none,1,0,0);
const char *explicit_abi_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn main()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";
ok(&image,"explicit ABI real contract call retained",explicit_abi_call,2,1,1);
const char *explicit_abi_missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {}\nrequires {stack_aligned(32)} {\nreturn 0\n}\nfn main()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";
err(&image,"explicit ABI unmet contract still refused",explicit_abi_missing,4,4,0,0);

 const char*none="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";ok(&image,"none",none,2,1,0);
 const char*feature_ok="module m\ntarget x86_64-nexora-none\nfeatures {sse2}\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {feature(sse2)} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {}\nrequires {feature(sse2)} {\ncall leaf()\nreturn 0\n}\n}\n";ok(&image,"feature",feature_ok,2,1,1);
 const char*feature_bad="module m\ntarget x86_64-nexora-none\nfeatures {sse2}\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {feature(sse2)} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";ok(&image,"feature module proof",feature_bad,2,1,1);
 const char*stack_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\ncall leaf()\nreturn 0\n}\n}\n";ok(&image,"stack",stack_ok,2,1,1);
 const char*stack_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(8)} {\ncall leaf()\nreturn 0\n}\n}\n";ok(&image,"stack abi baseline",stack_bad,2,1,1);
 const char*stack_too_large="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(32)} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";err(&image,"stack too large",stack_too_large,4,4,0,0);
 const char*nonnull_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {non_null(p)} {\nreturn 0\n}\nfn main(in q:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {non_null(q)} {\ncall leaf(q)\nreturn 0\n}\n}\n";ok(&image,"nonnull mapped",nonnull_ok,2,1,1);
 const char*nonnull_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {non_null(p)} {\nreturn 0\n}\nfn main(in q:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {} {\ncall leaf(q)\nreturn 0\n}\n}\n";err(&image,"nonnull missing",nonnull_bad,4,2,0,0);
 const char*canonical_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {canonical(p)} {\nreturn 0\n}\nfn main(in q:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {canonical(q)} {\ncall leaf(q)\nreturn 0\n}\n}\n";ok(&image,"canonical",canonical_ok,2,1,1);
 const char*literal_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {non_null(p)} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall leaf(1)\nreturn 0\n}\n}\n";err(&image,"literal not proved",literal_bad,4,2,0,0);
 const char*stack_in_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\ncall leaf()\nreturn 0\n}\n}\n";ok(&image,"stack_in caller fact",stack_in_ok,2,1,1);
 const char*interrupts_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {interrupts_enabled()} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {}\nrequires {interrupts_enabled()} {\ncall leaf()\nreturn 0\n}\n}\n";ok(&image,"interrupts_enabled caller fact",interrupts_ok,2,1,1);
 const char*imported="module m\ntarget x86_64-nexora-none\nfeatures {sse2}\nimport a.f as f: fn()->u64\neffects {}\nclobbers {}\nrequires {feature(sse2)}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {}\nrequires {feature(sse2)} {\nreturn f()\n}\n}\n";ok(&image,"import expression",imported,2,1,1);
   badinput(&image,"short",none,3);badinput(&image,"invalid","target x86_64-nexora-none\n",4);
  /* An out parameter register is still a direct write of the callee, so the
     callee declares it as spec 8.2 asks; the caller declares it too, which is
     the ABI half of the same rule. These two leaves previously declared only
     rax while mov r8, 0 sat in their body, a lie that only passed because this
     entry did not run body_clobbers. The verdict of both cases is unchanged:
     the subject is the remap, not the clobber declaration. */
     const char*out_mapped="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in q:ptr<user,u64> @rdi, out p:u64 @r8, in r:ptr<user,u64> @rsi, in s:ptr<user,u64> @rcx)->u64\neffects {}\nclobbers {rax,r8}\nrequires {non_null(r)} {\nmov r8, 0\nmov rax, 0\nreturn rax\n}\nfn main(in a:ptr<user,u64> @rdi, in b:ptr<user,u64> @rsi, in c:ptr<user,u64> @rdx)->u64\neffects {}\nclobbers {rax,r8}\nrequires {non_null(b)} {\ncall leaf(a, b, c)\nmov rax, 0\nreturn rax\n}\n}\n";ok(&image,"out subject maps to in argument",out_mapped,2,1,1);
     const char*out_shift="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in q:ptr<user,u64> @rdi, out p:u64 @r8, in r:ptr<user,u64> @rsi, in s:ptr<user,u64> @rcx)->u64\neffects {}\nclobbers {rax,r8}\nrequires {non_null(r)} {\nmov r8, 0\nmov rax, 0\nreturn rax\n}\nfn main(in a:ptr<user,u64> @rdi, in b:ptr<user,u64> @rsi, in c:ptr<user,u64> @rdx)->u64\neffects {}\nclobbers {rax,r8}\nrequires {non_null(c)} {\ncall leaf(a, b, c)\nmov rax, 0\nreturn rax\n}\n}\n";err(&image,"out parameter shifts subject",out_shift,4,2,0,0);
  const char*out_subject="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in q:ptr<user,u64> @rdi, out p:ptr<user,u64> @r8, in s:ptr<user,u64> @rcx)->u64\neffects {}\nclobbers {rax}\nrequires {non_null(p)} {\nmov rax, 0\nreturn rax\n}\nfn main(in a:ptr<user,u64> @rdi, in b:ptr<user,u64> @rsi)->u64\neffects {}\nclobbers {rax}\nrequires {non_null(b)} {\ncall leaf(a, b)\nmov rax, 0\nreturn rax\n}\n}\n";err(&image,"out subject unprovable",out_subject,4,2,0,0);
 /* A caller fact must match the whole callee predicate: a different predicate
    name and a different arity both leave the callee precondition unproved. */
 errp(&image,"zero arity fact cannot discharge unary",z("stack_in(kernel)","interrupts_enabled()","",""),326,"leaf",2,6,0);
 errp(&image,"unary fact cannot discharge zero arity",z("interrupts_enabled()","stack_in(kernel)","",""),326,"leaf",2,7,0);
 errp(&image,"frame fact cannot discharge non_null",p("non_null(p)","","","valid_user_return(q,q)","",""),326,"leaf",2,2,0);
 /* family 6 stack_in: the caller states the same space and cannot move rsp. */
 ok(&image,"stack_in kernel",z("stack_in(kernel)","stack_in(kernel)","",""),2,1,1);
 ok(&image,"stack_in user",z("stack_in(user)","stack_in(user)","",""),2,1,1);
 ok(&image,"stack_in mmio with other clobber",z("stack_in(mmio)","stack_in(mmio)","","rax"),2,1,1);
 ok(&image,"stack_in firmware with writes_mem",z("stack_in(firmware)","stack_in(firmware)","writes_mem",""),2,1,1);
 errp(&image,"stack_in rsp clobber",z("stack_in(kernel)","stack_in(kernel)","","rsp"),326,"leaf",2,6,0);
 errp(&image,"stack_in esp alias",z("stack_in(kernel)","stack_in(kernel)","","esp"),326,"leaf",2,6,0);
 errp(&image,"stack_in space mismatch",z("stack_in(kernel)","stack_in(user)","",""),326,"leaf",2,6,0);
 errp(&image,"stack_in no caller fact",z("stack_in(kernel)","","",""),326,"leaf",2,6,0);
 errp(&image,"stack_in unknown space",z("stack_in(nowhere)","stack_in(nowhere)","",""),326,"leaf",2,6,0);
 /* family 7 and 8: the interrupt state cannot change without an atom. */
 ok(&image,"interrupts_enabled",z("interrupts_enabled()","interrupts_enabled()","",""),2,1,1);
 ok(&image,"interrupts_disabled",z("interrupts_disabled()","interrupts_disabled()","",""),2,1,1);
 ok(&image,"interrupts_enabled reads_mem",z("interrupts_enabled()","interrupts_enabled()","reads_mem","rax"),2,1,1);
 ok(&image,"interrupts_disabled changes_flags",z("interrupts_disabled()","interrupts_disabled()","changes_flags",""),2,1,1);
 errp(&image,"interrupts_enabled interrupt_state",z("interrupts_enabled()","interrupts_enabled()","interrupt_state",""),326,"leaf",2,7,0);
 errp(&image,"interrupts_enabled control",z("interrupts_enabled()","interrupts_enabled()","control",""),326,"leaf",2,7,0);
 errp(&image,"interrupts_enabled privileged",z("interrupts_enabled()","interrupts_enabled()","privileged",""),326,"leaf",2,7,0);
 errp(&image,"interrupts_enabled polarity",z("interrupts_enabled()","interrupts_disabled()","",""),326,"leaf",2,7,0);
 errp(&image,"interrupts_disabled interrupt_state",z("interrupts_disabled()","interrupts_disabled()","interrupt_state",""),326,"leaf",2,8,0);
 errp(&image,"interrupts_disabled no caller fact",z("interrupts_disabled()","","",""),326,"leaf",2,8,0);
 /* family 9: an MSR cannot be uninitialised without touching one. */
 ok(&image,"msr selector",z("msr_initialized(16)","msr_initialized(16)","",""),2,1,1);
 ok(&image,"msr selector wide",z("msr_initialized(174)","msr_initialized(174)","",""),2,1,1);
 ok(&image,"msr selector reads_mem",z("msr_initialized(16)","msr_initialized(16)","reads_mem","rax"),2,1,1);
 ok(&image,"msr remapped subject",p("msr_initialized(p)","","","msr_initialized(q)","",""),2,1,1);
 errp(&image,"msr guard msr",z("msr_initialized(16)","msr_initialized(16)","msr",""),326,"leaf",2,9,0);
 errp(&image,"msr guard privileged",z("msr_initialized(16)","msr_initialized(16)","privileged",""),326,"leaf",2,9,0);
 errp(&image,"msr selector mismatch",z("msr_initialized(16)","msr_initialized(174)","",""),326,"leaf",2,9,0);
 errp(&image,"msr no caller fact",z("msr_initialized(16)","","",""),326,"leaf",2,9,0);
 errp(&image,"msr remap without caller fact",p("msr_initialized(p)","","","","",""),326,"leaf",2,9,0);
 /* family 10: a mapping cannot be torn down by a body that stores nothing. */
 ok(&image,"mapping remapped subject",p("mapping_present(p)","","","mapping_present(q)","",""),2,1,1);
 ok(&image,"mapping reads_mem",p("mapping_present(p)","","reads_mem","mapping_present(q)","","rax"),2,1,1);
 ok(&image,"mapping changes_flags",p("mapping_present(p)","","changes_flags","mapping_present(q)","",""),2,1,1);
 ok(&image,"mapping fixed address",z("mapping_present(4096)","mapping_present(4096)","",""),2,1,1);
 errp(&image,"mapping guard writes_mem",p("mapping_present(p)","","writes_mem","mapping_present(q)","",""),326,"leaf",2,10,0);
 errp(&image,"mapping guard writes_mem kernel",p("mapping_present(p)","","writes_mem(kernel)","mapping_present(q)","",""),326,"leaf",2,10,0);
 errp(&image,"mapping no caller fact",p("mapping_present(p)","","","","",""),326,"leaf",2,10,0);
 errp(&image,"mapping local subject",p("mapping_present(1)","","","mapping_present(q)","",""),326,"leaf",2,10,0);
 /* family 11: a return frame is a pair, remapped in order, stack unmoved. */
 ok(&image,"frame pair",t("valid_user_return(a,b)","","valid_user_return(c,d)","","","call leaf(c,d)"),2,1,1);
 ok(&image,"frame pair other clobber",t("valid_user_return(a,b)","","valid_user_return(c,d)","","rax","call leaf(c,d)"),2,1,1);
 ok(&image,"frame pair swapped subjects",t("valid_user_return(b,a)","","valid_user_return(d,c)","","","call leaf(c,d)"),2,1,1);
 ok(&image,"frame pair same subject twice",t("valid_user_return(a,a)","","valid_user_return(c,c)","","","call leaf(c,c)"),2,1,1);
 errp(&image,"frame guard rsp",t("valid_user_return(a,b)","","valid_user_return(c,d)","","rsp","call leaf(c,d)"),326,"leaf",2,11,0);
 errp(&image,"frame swapped call",t("valid_user_return(a,b)","","valid_user_return(c,d)","","","call leaf(d,c)"),326,"leaf",2,11,0);
 errp(&image,"frame half stated",t("valid_user_return(a,b)","","valid_user_return(c,0)","","","call leaf(c,d)"),326,"leaf",2,11,0);
 errp(&image,"frame literal subject",t("valid_user_return(1,2)","","valid_user_return(c,d)","","","call leaf(c,d)"),326,"leaf",2,11,0);
 /* 365: a callee ensures the caller does not re-declare is reported. */
 ok(&image,"ensures remapped",p("","non_null(p)","","","non_null(q)",""),2,1,1);
 ok(&image,"ensures stack_in",p("","stack_in(kernel)","","","stack_in(kernel)",""),2,1,1);
 ok(&image,"ensures bare",p("","interrupts_enabled()","","","interrupts_enabled()",""),2,1,1);
 ok(&image,"ensures two covered",p("","non_null(p),canonical(p)","","","non_null(q),canonical(q)",""),2,1,2);
 errp(&image,"ensures dropped",p("","non_null(p)","","","",""),365,"non_null",1,1,0);
 errp(&image,"ensures other subject",p("","non_null(p)","","","non_null(r)",""),365,"non_null",1,1,0);
 errp(&image,"ensures wrong arity",p("","non_null(p)","","","valid_user_return(q,q)",""),365,"non_null",1,1,0);
 errp(&image,"ensures second uncovered",p("","non_null(p),canonical(p)","","","non_null(q)",""),365,"canonical",1,1,1);
 errp(&image,"ensures frame dropped",t("","valid_user_return(a,b)","","","","call leaf(c,d)"),365,"valid_user_return",1,1,0);
 errp(&image,"ensures call site span",nvz("interrupts_disabled()","","") ,365,"interrupts_disabled",1,1,0);
 /* A never callee has no caller post state, so the same clause is accepted. */
  ok(&image,"ensures never callee",nvi("interrupts_disabled()","","",""),2,1,0);
  ok(&image,"ensures never callee space",nvi("stack_in(kernel)","stack_in(kernel)","",""),2,1,0);
  /* Precondition of call_contracts.check, stated and machine checked.
     Families 6 to 11 read the caller effects and clobbers sets as an
     invalidation guard, which is sound only once body_effects, body_intrinsics,
     body_clobbers, call_effects and call_clobbers have composed every caller
     body and compared it to those declarations. A standalone
     call_contracts.check cannot see the difference: it reads the declaration,
     never the body. Each source below declares the opposite of what its body
     does, so the guard reads an empty set, concludes nothing could have moved
     and proves the call. The pipeline refuses the same source first, with the
     code of the pass that owns the lie. */
  const char*lie_store="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {mapping_present(p)} {\nreturn 0\n}\nfn main(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {mapping_present(p)} {\nstore [p]:ptr<user,u64>,rax\ncall leaf(p)\nreturn 0\n}\n}\n";
  stage(&image,"lie effects store",lie_store,332,"store",1,3,1,1);
  stage(&vimage,"lie effects store validate",lie_store,332,"store",1,3,1,0);
  const char*lie_rsp="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\nmov rsp,rbx\ncall leaf()\nreturn 0\n}\n}\n";
  stage(&image,"lie clobbers rsp",lie_rsp,335,"rsp",1,1,16,1);
  stage(&vimage,"lie clobbers rsp validate",lie_rsp,335,"rsp",1,1,16,0);
  const char*lie_cli="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {interrupts_enabled()} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {}\nrequires {interrupts_enabled()} {\ncli\ncall leaf()\nreturn 0\n}\n}\n";
  stage(&image,"lie effects cli",lie_cli,334,"cli",1,1,65,1);
  stage(&vimage,"lie effects cli validate",lie_cli,334,"cli",1,1,65,0);
  const char*lie_iret="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\nreturn 0\n}\nfn main()->u64\neffects {privileged,changes_flags,control,no_return}\nclobbers {}\nrequires {stack_in(kernel)} {\niretq\ncall leaf()\nreturn 0\n}\n}\n";
  stage(&image,"lie clobbers iretq",lie_iret,335,"iretq",1,1,16,1);
  stage(&vimage,"lie clobbers iretq validate",lie_iret,335,"iretq",1,1,16,0);
  /* The same six rules still prove under the honest pipeline, so running the
     guarding passes first narrows nothing that was already sound. */
  ok(&image,"positive stack_in",z("stack_in(kernel)","stack_in(kernel)","",""),2,1,1);
  okv(&vimage,"positive stack_in validate",z("stack_in(kernel)","stack_in(kernel)","",""));
  ok(&image,"positive interrupts_enabled",z("interrupts_enabled()","interrupts_enabled()","",""),2,1,1);
  okv(&vimage,"positive interrupts_enabled validate",z("interrupts_enabled()","interrupts_enabled()","",""));
  ok(&image,"positive interrupts_disabled",z("interrupts_disabled()","interrupts_disabled()","",""),2,1,1);
  okv(&vimage,"positive interrupts_disabled validate",z("interrupts_disabled()","interrupts_disabled()","",""));
  ok(&image,"positive msr_initialized",p("msr_initialized(p)","","","msr_initialized(q)","",""),2,1,1);
  okv(&vimage,"positive msr_initialized validate",p("msr_initialized(p)","","","msr_initialized(q)","",""));
  ok(&image,"positive mapping_present",p("mapping_present(p)","","","mapping_present(q)","",""),2,1,1);
  okv(&vimage,"positive mapping_present validate",p("mapping_present(p)","","","mapping_present(q)","",""));
  ok(&image,"positive valid_user_return",t("valid_user_return(a,b)","","valid_user_return(c,d)","","","call leaf(c,d)"),2,1,1);
  okv(&vimage,"positive valid_user_return validate",t("valid_user_return(a,b)","","valid_user_return(c,d)","","","call leaf(c,d)"));
 /* check alone, mode 1: no pass runs in front of call_contracts.check, so
    these ask the pass what it proves by itself. Every source below declares
    the opposite of what its own body does. Before the guard was ANDed with
    the caller body, the declaration alone was the whole predicate, the
    guard read an empty set, and check returned a false proof for all of
    them: the same verdict as an honest module. */
 /* A real store with effects {}: the mapping_present rule needs a caller that
    stores nothing, and this caller stores. */
  aerrp(&image,"alone lie effects store",pb("mapping_present(p)","mapping_present(q)","","","store [q]:ptr<user,u64>,rax"),326,"leaf",2,10,0);
  aerrp(&image,"alone lie effects store literal",pb("mapping_present(p)","mapping_present(q)","","","store [q]:ptr<user,u64>,0"),326,"leaf",2,10,0);
  aerrp(&image,"alone lie effects store reads only",pb("mapping_present(p)","mapping_present(q)","","reads_mem","load rax,[q]:ptr<user,u64>\nstore [q]:ptr<user,u64>,rax"),326,"leaf",2,10,0);
  aerrp(&image,"alone lie effects store nested block",pb("mapping_present(p)","mapping_present(q)","","","if true {\nstore [q]:ptr<user,u64>,rax\n}"),326,"leaf",2,10,0);
 /* A real mov rsp,rbx with clobbers {}: the stack_in and the frame rules
    both need a caller that cannot have moved rsp. */
  aerrp(&image,"alone lie clobbers mov rsp",zb("stack_in(kernel)","stack_in(kernel)","","","mov rsp,rbx"),326,"leaf",2,6,0);
  aerrp(&image,"alone lie clobbers mov rsp frame",tb("valid_user_return(a,b)","valid_user_return(c,d)","","mov rsp,rbx"),326,"leaf",2,11,0);
  aerrp(&image,"alone lie clobbers add rsp",zb("stack_in(kernel)","stack_in(kernel)","","","add rsp,8"),326,"leaf",2,6,0);
  aerrp(&image,"alone lie clobbers mov esp",zb("stack_in(kernel)","stack_in(kernel)","","","mov esp,ebx"),326,"leaf",2,6,0);
 /* A stack adjustment the clobbers set cannot name: pop moves rsp without
    naming it, so clobbers {rax} is an honest declaration and still no
    proof. This is the precision the five pass order could never see. */
  aerrp(&image,"alone lie clobbers pop",zb("stack_in(kernel)","stack_in(kernel)","","rax","pop rax"),326,"leaf",2,6,0);
  aerrp(&image,"alone lie clobbers push frame",tb("valid_user_return(a,b)","valid_user_return(c,d)","","push rbx\npop rbx"),326,"leaf",2,11,0);
  aerrp(&image,"alone lie clobbers xchg second",zb("stack_in(kernel)","stack_in(kernel)","","rax","xchg rax,rsp"),326,"leaf",2,6,0);
 /* A real cli with effects {}: the interrupt state rules need a caller that
    declared no interrupt_state, control or privileged atom. */
  aerrp(&image,"alone lie effects cli",zb("interrupts_enabled()","interrupts_enabled()","","","cli"),326,"leaf",2,7,0);
  aerrp(&image,"alone lie effects sti",zb("interrupts_disabled()","interrupts_disabled()","","","sti"),326,"leaf",2,8,0);
  aerrp(&image,"alone lie effects swapgs",zb("interrupts_enabled()","interrupts_enabled()","","","swapgs"),326,"leaf",2,7,0);
  aerrp(&image,"alone lie effects sysretq",zb("interrupts_enabled()","interrupts_enabled()","","","sysretq"),326,"leaf",2,7,0);
 /* A real rdmsr with effects {}: the msr rule needs a caller that declared
    neither msr nor privileged, and rdmsr is both. */
  aerrp(&image,"alone lie effects rdmsr",zb("msr_initialized(16)","msr_initialized(16)","","","rdmsr"),326,"leaf",2,9,0);
  aerrp(&image,"alone lie effects wrmsr subject",pb("msr_initialized(p)","msr_initialized(q)","","","wrmsr"),326,"leaf",2,9,0);
 /* A real iretq with clobbers {}: iretq carries control and privileged, and
    it returns through the frame, so it invalidates the stack and the
    interrupt rules at once. */
  aerrp(&image,"alone lie clobbers iretq",zb("stack_in(kernel)","stack_in(kernel)","","","iretq"),326,"leaf",2,6,0);
  aerrp(&image,"alone lie clobbers iretq frame",tb("valid_user_return(a,b)","valid_user_return(c,d)","","iretq"),326,"leaf",2,11,0);
  aerrp(&image,"alone lie clobbers iretq interrupts",zb("interrupts_disabled()","interrupts_disabled()","","","iretq"),326,"leaf",2,8,0);
  aerrp(&image,"alone lie clobbers popfq",zb("interrupts_enabled()","interrupts_enabled()","","","popfq"),326,"leaf",2,7,0);
 /* One lie that would satisfy every guard at once is still refused. */
  aerrp(&image,"alone lie all guards",zb("stack_in(kernel)","stack_in(kernel)","","","mov rsp,rbx\ncli\nstore [rax]:ptr<user,u64>,rbx"),326,"leaf",2,6,0);
 /* Honest non empty bodies stay accepted, so the guard is not simply
    tightened into uselessness. A real register write with a matching
    clobbers entry proves nothing away. */
  aok(&image,"alone honest mov rax stack_in",zb("stack_in(kernel)","stack_in(kernel)","","rax","mov rax,0"),2,1,1);
  aok(&image,"alone honest mov rax interrupts",zb("interrupts_enabled()","interrupts_enabled()","","rax","mov rax,0"),2,1,1);
  aok(&image,"alone honest mov rax frame",tb("valid_user_return(a,b)","valid_user_return(c,d)","rax","mov rax,0"),2,1,1);
  aok(&image,"alone honest store declared",zb("stack_in(kernel)","stack_in(kernel)","writes_mem(user)","rax","store [rax]:ptr<user,u64>,rbx"),2,1,1);
  aok(&image,"alone honest load only",pb("mapping_present(p)","mapping_present(q)","reads_mem","rax","load rax,[q]:ptr<user,u64>"),2,1,1);
 /* Reading rsp is not moving it: mov rax,rsp and cmp name rsp without
    writing it, and must not cost the caller its stack fact. */
  aok(&image,"alone honest reads rsp",zb("stack_in(kernel)","stack_in(kernel)","","rax","mov rax,rsp"),2,1,1);
  aok(&image,"alone honest cmp rsp",zb("stack_in(kernel)","stack_in(kernel)","","rax","cmp rsp,0"),2,1,1);
  aok(&image,"alone honest lea rsp",zb("stack_in(kernel)","stack_in(kernel)","","rax","lea rax,[rsp+8]:ptr<user,u64>"),2,1,1);
 /* A body that really changes the interrupt state, honestly declared, still
    proves the facts that declaration leaves standing: declaring
    interrupt_state costs the interrupt rules, as it always has, but not
    stack_in, and declaring privileged and msr costs neither. */
  aok(&image,"alone honest cli declared",zb("stack_in(kernel)","stack_in(kernel)","interrupt_state,privileged","rax","cli"),2,1,1);
  aok(&image,"alone honest rdmsr declared",zb("stack_in(kernel)","stack_in(kernel)","msr,privileged","rax","rdmsr"),2,1,1);
  aok(&image,"alone honest no msr body",zb("msr_initialized(16)","msr_initialized(16)","","rax","mov rax,0"),2,1,1);
  aok(&image,"alone honest no atom body",zb("interrupts_enabled()","interrupts_enabled()","","rax","mov rax,0"),2,1,1);
 /* 365 stays fail closed: an honest body does not license dropping a callee
    ensures, and the body guard is not a coverage test. */
  aerrp(&image,"alone ensures dropped honest body",ps("","non_null(p)","","","","rax","mov rax,0"),365,"non_null",1,1,0);
  aerrp(&image,"alone ensures dropped store body",ps("","non_null(p)","writes_mem(user)","","","rax","store [q]:ptr<user,u64>,rax"),365,"non_null",1,1,0);
 /* Mode 0 and mode 1 agree on every honest source, so running the guarding
    passes first still narrows nothing that was already sound. */
  ok(&image,"mode parity stack_in",zb("stack_in(kernel)","stack_in(kernel)","","rax","mov rax,0"),2,1,1);
  ok(&image,"mode parity interrupts",zb("interrupts_enabled()","interrupts_enabled()","","rax","mov rax,0"),2,1,1);
  ok(&image,"mode parity frame",tb("valid_user_return(a,b)","valid_user_return(c,d)","rax","mov rax,0"),2,1,1);
  ok(&image,"mode parity mapping",pb("mapping_present(p)","mapping_present(q)","reads_mem","rax","load rax,[q]:ptr<user,u64>"),2,1,1);
  okv(&vimage,"mode parity validate",zb("stack_in(kernel)","stack_in(kernel)","","rax","mov rax,0"));
 /* ================ ADVERSARIAL LOT: the two remaining fail open holes ======
    Both counterexamples are the auditor's, verbatim. Each declares an empty
    effects set and an empty clobbers set, which is an honest declaration for
    neither body, and each body is a single instruction. */
 /* HOLE 1. pushfq is in the same oracle member as push, pop, popfq, ret and
    call, and the oracle gives it the same registers_written 1<<4 rsp write, so
    it belongs in the implicit rsp mover set. A pushfq only body moves rsp by
    eight and must not be able to prove stack_in(kernel), the frame pair, or,
    through the independent memory guard, a mapping. */
  probe(&image,"hole1 pushfq stack_in",zb("stack_in(kernel)","stack_in(kernel)","","","pushfq"),1);
  probe(&image,"hole1 pushfq stack_in",zb("stack_in(kernel)","stack_in(kernel)","","","pushfq"),0);
  probe(&image,"hole1 pushfq mapping",pb("mapping_present(p)","mapping_present(q)","","","pushfq"),1);
  aerrp(&image,"hole1 pushfq stack_in alone",zb("stack_in(kernel)","stack_in(kernel)","","","pushfq"),326,"leaf",2,6,0);
  aerrp(&image,"hole1 pushfq frame alone",tb("valid_user_return(a,b)","valid_user_return(c,d)","","pushfq"),326,"leaf",2,11,0);
  aerrp(&image,"hole1 pushfq mapping alone",pb("mapping_present(p)","mapping_present(q)","","","pushfq"),326,"leaf",2,10,0);
  noproof(&image,"hole1 pushfq stack_in pipeline",zb("stack_in(kernel)","stack_in(kernel)","","","pushfq"),0);
  noproof(&image,"hole1 pushfq frame pipeline",tb("valid_user_return(a,b)","valid_user_return(c,d)","","pushfq"),0);
 /* HOLE 2. push writes eight bytes of the stack through an implicit write the
    oracle publishes as stack_write, with no memory operand for a per operand
    table to see. The stack guard kills caps bit 1, but caps bit 8 is
    independent, so a push rax only body was still granted mapping_present
    while it had written memory. */
  probe(&image,"hole2 push mapping",pb("mapping_present(p)","mapping_present(q)","","","push rax"),1);
  probe(&image,"hole2 push mapping",pb("mapping_present(p)","mapping_present(q)","","","push rax"),0);
  aerrp(&image,"hole2 push mapping alone",pb("mapping_present(p)","mapping_present(q)","","","push rax"),326,"leaf",2,10,0);
  aerrp(&image,"hole2 pushfq mapping alone",pb("mapping_present(p)","mapping_present(q)","","","pushfq"),326,"leaf",2,10,0);
  aerrp(&image,"hole2 push immediate mapping alone",pb("mapping_present(p)","mapping_present(q)","","","push 7"),326,"leaf",2,10,0);
  noproof(&image,"hole2 push mapping pipeline",pb("mapping_present(p)","mapping_present(q)","","","push rax"),0);
 /* ============ the derived rule, one row per row, against both guards ===== */
 /* Row A: every instruction the oracle gives an rsp family write, with or
    without naming rsp, against the two predicates the stack guard carries.
    rspn below is the control half of the same table: the forms that name rsp
    without writing it, which must keep their stack fact. */
  {static const char*rspw[]={"push rax","pushfq","pop rax","popfq","ret","iretq",
      "align_stack 16","align_stack 8","mov rsp,rax","mov esp,ebx","add rsp,8",
      "xchg rax,rsp","xchg rsp,rax","inc rsp","neg rsp","not rsp","shl rsp,1",
      "imul rsp,rax","xchg rsp,rbx","or rsp,rax"};
   for(unsigned i=0;i<sizeof rspw/sizeof rspw[0];i++){
     aerrp(&image,"row A stack_in",zb("stack_in(kernel)","stack_in(kernel)","","rax",rspw[i]),326,"leaf",2,6,0);
     aerrp(&image,"row A frame",tb("valid_user_return(a,b)","valid_user_return(c,d)","rax",rspw[i]),326,"leaf",2,11,0);
   }}
  {static const char*rspn[]={"mov rax,rsp","mov eax,esp","cmp rsp,0","test rsp,rax",
      "bt rsp,3","lea rax,[rsp+8]:ptr<user,u64>","div rsp","mov rbx,[rsp+8]:ptr<user,u64>",
      "sysretq"};
   for(unsigned i=0;i<sizeof rspn/sizeof rspn[0];i++){
     aok(&image,"row A control reads rsp",zb("stack_in(kernel)","stack_in(kernel)","","rax",rspn[i]),2,1,1);
     aok(&image,"row A control reads rsp frame",tb("valid_user_return(a,b)","valid_user_return(c,d)","rax",rspn[i]),2,1,1);
   }}
 /* A return statement is node kind 29, not an instruction, and is not charged:
    it is the function own exit, whose epilogue restores the frame after the
    body rather than disturbing it before a call, so charging it would cost
    every function the stack facts, which is the over-tightening into rejecting
    valid code the rule must not do. The oracle charges the return opcode as an
    instruction, and adjusts_stack still names it for that reason. sysretq is
    in the same position for a different reason: the oracle gives it no rsp
    write and spec 8.3 keeps it outside the implicit set, and x64.c line 1035
    makes it terminal, so no call after it in the same body is reachable. */
  aok(&image,"return statement is not a stack write",zb("stack_in(kernel)","stack_in(kernel)","","rax","if true {\nreturn 0\n}"),2,1,1);
  aok(&image,"return statement frame",tb("valid_user_return(a,b)","valid_user_return(c,d)","rax","if true {\nreturn 0\n}"),2,1,1);
 /* Row B, implicit half: the three mnemonics the oracle gives stack_write
    with no memory operand at all. */
  {static const char*impw[]={"push rax","push rbx","pushfq","push 7","push [rax]:ptr<user,u64>"};
   for(unsigned i=0;i<sizeof impw/sizeof impw[0];i++)
     aerrp(&image,"row B implicit stack write",pb("mapping_present(p)","mapping_present(q)","","rax",impw[i]),326,"leaf",2,10,0);}
 /* Row B, anchored half: a memory operand the oracle writes. Every one of
    these was granted mapping_present while it wrote memory, because the old
    rule matched the literal store and nothing else. */
  {static const char*memw[]={
      "store [q]:ptr<user,u64>,rax","store [q]:ptr<user,u64>,7",
      "mov [q]:ptr<user,u64>,rax","mov [q]:ptr<user,u64>,7",
      "xchg rax,[q]:ptr<user,u64>","xchg [q]:ptr<user,u64>,rax",
      "add [q]:ptr<user,u64>,8","adc [q]:ptr<user,u64>,8","sub [q]:ptr<user,u64>,8",
      "sbb [q]:ptr<user,u64>,8","and [q]:ptr<user,u64>,8","or [q]:ptr<user,u64>,8",
      "xor [q]:ptr<user,u64>,8","inc [q]:ptr<user,u64>","dec [q]:ptr<user,u64>",
      "neg [q]:ptr<user,u64>","not [q]:ptr<user,u64>","shl [q]:ptr<user,u64>,3",
      "shr [q]:ptr<user,u64>,3","sar [q]:ptr<user,u64>,3","rol [q]:ptr<user,u64>,3",
      "ror [q]:ptr<user,u64>,1","imul [q]:ptr<user,u64>,rax","movzx [q]:ptr<user,u8>,rax",
      "movsx [q]:ptr<user,i64>,rax","movsxd [q]:ptr<user,i32>,rax",
      "sete [q]:ptr<user,u8>","setne [q]:ptr<user,u8>","setb [q]:ptr<user,u8>",
      "bswap [q]:ptr<user,u64>","bsf [q]:ptr<user,u64>,rax","bsr [q]:ptr<user,u64>,rax",
      "cmovne [q]:ptr<user,u64>,rax",
      "bts [q]:ptr<user,u64>,0","btr [q]:ptr<user,u64>,0","btc [q]:ptr<user,u64>,0",
      "sgdt [q]:ptr<user,u64>","sidt [q]:ptr<user,u64>","pop [q]:ptr<user,u64>"};
    for(unsigned i=0;i<sizeof memw/sizeof memw[0];i++){
     aerrp(&image,"row B anchored memory write",pb("mapping_present(p)","mapping_present(q)","","rax",memw[i]),326,"leaf",2,10,0);}}
 /* Row B control: a memory operand the oracle only reads, or does not access
    at all. A read is not a write and must not cost the mapping fact. */
  {static const char*memr[]={"load rax,[q]:ptr<user,u64>","mov rax,[q]:ptr<user,u64>",
      "movzx rax,[q]:ptr<user,u8>","movsx rax,[q]:ptr<user,i64>","movsxd rax,[q]:ptr<user,i32>",
      "div [q]:ptr<user,u64>","idiv [q]:ptr<user,u64>","mul [q]:ptr<user,u64>",
      "invlpg [q]:ptr<user,u64>","cmp [q]:ptr<user,u64>,0","test [q]:ptr<user,u64>,rax",
      "bt [q]:ptr<user,u64>,0","lea rax,[q+8]:ptr<user,u64>","and rax,[q]:ptr<user,u64>",
      "cmove rax,[q]:ptr<user,u64>","cmovne rax,[q]:ptr<user,u64>",
      "bsf rax,[q]:ptr<user,u64>","bsr rax,[q]:ptr<user,u64>"};
   for(unsigned i=0;i<sizeof memr/sizeof memr[0];i++)
     aok(&image,"row B control memory read",pb("mapping_present(p)","mapping_present(q)","reads_mem","rax",memr[i]),2,1,1);}
 /* Row B fail closed: a form the oracle does not anchor is a refusal and
    never a no-op, so it is charged a write here even where the oracle charges
    none at all. */
  {static const char*unanchored[]={"lgdt [q]:ptr<user,u64>","lidt [q]:ptr<user,u64>",
      "ltr [q]:ptr<user,u64>","load [q]:ptr<user,u64>,rax","bsf [q]:ptr<user,u64>,rax",
      "cmovne [q]:ptr<user,u64>,rax","in [rax]:ptr<user,u8>,96","read_cr [rax]:ptr<user,u64>,3"};
   for(unsigned i=0;i<sizeof unanchored/sizeof unanchored[0];i++)
     aerrp(&image,"row B unanchored form",pb("mapping_present(p)","mapping_present(q)","","rax",unanchored[i]),326,"leaf",2,10,0);}
 /* Row C: every atom carrier in the oracle vocabulary, against each of the
    three predicates an atom guard carries. rdmsr and wrmsr are privileged as
    well as msr, so they cost the interrupt rules too, and syscall is the one
    carrier the oracle leaves unprivileged, so it leaves msr_initialized up. */
  {static const char*atomb[]={"cli","sti","hlt","popfq","in al,96","out 96,al",
      "swapgs","read_cr rax,3","write_cr 3,rax","sgdt [rax]:ptr<user,u64>",
      "sidt [rax]:ptr<user,u64>","lgdt [rax]:ptr<user,u64>","lidt [rax]:ptr<user,u64>",
      "ltr [rax]:ptr<user,u64>","invlpg [rax]:ptr<user,u64>","sysretq","iretq",
      "rdmsr","wrmsr"};
   for(unsigned i=0;i<sizeof atomb/sizeof atomb[0];i++){
     aerrp(&image,"row C msr_initialized",zb("msr_initialized(16)","msr_initialized(16)","","rax",atomb[i]),326,"leaf",2,9,0);
     aerrp(&image,"row C interrupts_enabled",zb("interrupts_enabled()","interrupts_enabled()","","rax",atomb[i]),326,"leaf",2,7,0);
     aerrp(&image,"row C interrupts_disabled",zb("interrupts_disabled()","interrupts_disabled()","","rax",atomb[i]),326,"leaf",2,8,0);
   }}
  aerrp(&image,"row C syscall interrupts_enabled",zb("interrupts_enabled()","interrupts_enabled()","","rax","syscall"),326,"leaf",2,7,0);
  aerrp(&image,"row C syscall interrupts_disabled",zb("interrupts_disabled()","interrupts_disabled()","","rax","syscall"),326,"leaf",2,8,0);
  aok(&image,"row C syscall leaves msr standing",zb("msr_initialized(16)","msr_initialized(16)","","rax","syscall"),2,1,1);
 /* Row C control: an atom for one guard costs only that guard. rdmsr is not
    a stack write, syscall is not an MSR access, pushfq carries no atom, and
    cli writes no memory. */
  aok(&image,"row C rdmsr leaves stack standing",zb("stack_in(kernel)","stack_in(kernel)","","rax","rdmsr"),2,1,1);
  aok(&image,"row C rdmsr leaves frame standing",tb("valid_user_return(a,b)","valid_user_return(c,d)","rax","rdmsr"),2,1,1);
  aok(&image,"row C syscall leaves stack standing",zb("stack_in(kernel)","stack_in(kernel)","","rax","syscall"),2,1,1);
  aok(&image,"row C cli leaves mapping standing",pb("mapping_present(p)","mapping_present(q)","","rax","cli"),2,1,1);
  aok(&image,"row C pushfq leaves interrupt standing",zb("interrupts_enabled()","interrupts_enabled()","","rax","pushfq"),2,1,1);
  aok(&image,"row C pushfq leaves msr standing",zb("msr_initialized(16)","msr_initialized(16)","","rax","pushfq"),2,1,1);
  aok(&image,"row C pushfq leaves mapping standing",pb("mapping_present(p)","mapping_present(q)","","rax","mov rax,rsp"),2,1,1);
 /* Fail closed on an opcode the oracle publishes no footprint for. The
    grammar admits every NAME as a statement, so an unencodable opcode can
    reach a standalone check and must read as a writer in all three walks,
    never as a no-op. */
  {static const char*alien[]={"retq","leave","pushq rax","popq rax","sfenceq","qwap rax"};
   for(unsigned i=0;i<sizeof alien/sizeof alien[0];i++){
     aerrp(&image,"row A alien opcode stack_in",zb("stack_in(kernel)","stack_in(kernel)","","rax",alien[i]),326,"leaf",2,6,0);
     aerrp(&image,"row A alien opcode frame",tb("valid_user_return(a,b)","valid_user_return(c,d)","rax",alien[i]),326,"leaf",2,11,0);
     aerrp(&image,"row B alien opcode mapping",pb("mapping_present(p)","mapping_present(q)","","rax",alien[i]),326,"leaf",2,10,0);
     aerrp(&image,"row C alien opcode interrupts",zb("interrupts_enabled()","interrupts_enabled()","","rax",alien[i]),326,"leaf",2,7,0);
     aerrp(&image,"row C alien opcode msr",zb("msr_initialized(16)","msr_initialized(16)","","rax",alien[i]),326,"leaf",2,9,0);
   }}
 /* The call under proof is the balanced frame pair and is not charged against
    itself, which is what every positive here and every earlier case in this
    file already relies on. A second call in the same body is charged against
    the stack and the frame, because a call really does move rsp, and those
    two rows are unchanged by the shape==3 narrowing.

    The third row used to assert the same refusal for the memory guard, on the
    stated reason that whether a nested call is balanced is a frame discipline
    fact this pass does not check. That reason described the over-estimate, not
    a fact about the machine: the pass now checks it, by reading the callee,
    and leaf below has a body that returns and stores nothing, so the call and
    its return push and pop the same eight bytes and the mapping survives. The
    rows that keep a nested call charged for memory are in the shape==3 block
    below, each derived from nt_x64_effects. */
  aerrp(&image,"nested call stack_in",zb("stack_in(kernel)","stack_in(kernel)","","rax","call leaf()"),326,"leaf",2,6,0);
  aerrp(&image,"nested call frame",tb("valid_user_return(a,b)","valid_user_return(c,d)","rax","call leaf(c,d)"),326,"leaf",2,11,0);
  aok(&image,"nested call mapping",pb("mapping_present(p)","mapping_present(q)","","rax","call leaf(q)"),2,2,2);
 /* The rows hold inside a nested block too, where the statement is not a
    direct child of the declaration. */
  aerrp(&image,"nested block pushfq",zb("stack_in(kernel)","stack_in(kernel)","","rax","if true {\npushfq\n}"),326,"leaf",2,6,0);
  aerrp(&image,"nested block align_stack",zb("stack_in(kernel)","stack_in(kernel)","","rax","if true {\nalign_stack 16\n}"),326,"leaf",2,6,0);
  aerrp(&image,"nested block store",pb("mapping_present(p)","mapping_present(q)","","rax","if true {\nstore [q]:ptr<user,u64>,rax\n}"),326,"leaf",2,10,0);
  aerrp(&image,"nested block push",pb("mapping_present(p)","mapping_present(q)","","rax","if true {\npush rax\n}"),326,"leaf",2,10,0);
 /* An honest body that really writes is refused by the declaration half and
    by the body half alike, so declaring the write does not buy the fact back. */
  aerrp(&image,"declared store still no mapping",pb("mapping_present(p)","mapping_present(q)","writes_mem(user)","rax","store [q]:ptr<user,u64>,rax"),326,"leaf",2,10,0);
  aerrp(&image,"declared push still no mapping",pb("mapping_present(p)","mapping_present(q)","writes_mem(user)","rax","push rax"),326,"leaf",2,10,0);
  aerrp(&image,"declared rsp clobber still no stack_in",zb("stack_in(kernel)","stack_in(kernel)","","rsp","pushfq"),326,"leaf",2,6,0);
 /* Honest non empty bodies stay accepted for all six predicates, through the
    standalone entry and through the shipped pipeline, so the guard is
    tightened against the holes and not against valid code. */
  aok(&image,"honest body stack_in",zb("stack_in(kernel)","stack_in(kernel)","","rax","mov rax,0"),2,1,1);
  aok(&image,"honest body interrupts_enabled",zb("interrupts_enabled()","interrupts_enabled()","","rax","mov rax,0"),2,1,1);
  aok(&image,"honest body interrupts_disabled",zb("interrupts_disabled()","interrupts_disabled()","","rax","mov rax,0"),2,1,1);
  aok(&image,"honest body msr_initialized",zb("msr_initialized(16)","msr_initialized(16)","","rax","mov rax,0"),2,1,1);
  aok(&image,"honest body mapping_present",pb("mapping_present(p)","mapping_present(q)","","rax","mov rax,0"),2,1,1);
  aok(&image,"honest body valid_user_return",tb("valid_user_return(a,b)","valid_user_return(c,d)","rax","mov rax,0"),2,1,1);
  aok(&image,"honest two instruction body",zb("stack_in(kernel)","stack_in(kernel)","reads_mem","rax","mov rax,0\nmov rbx,0"),2,1,1);
  aok(&image,"honest nested block body",zb("stack_in(kernel)","stack_in(kernel)","","rax","if true {\nmov rax,0\n}"),2,1,1);
  aok(&image,"honest read only mapping body",pb("mapping_present(p)","mapping_present(q)","reads_mem","rax","load rax,[q]:ptr<user,u64>"),2,1,1);
  ok(&image,"pipeline honest body stack_in",zb("stack_in(kernel)","stack_in(kernel)","","rax","mov rax,0"),2,1,1);
  ok(&image,"pipeline honest body mapping_present",pb("mapping_present(p)","mapping_present(q)","reads_mem","rax","load rax,[q]:ptr<user,u64>"),2,1,1);
  ok(&image,"pipeline honest body frame",tb("valid_user_return(a,b)","valid_user_return(c,d)","rax","mov rax,0"),2,1,1);
  okv(&vimage,"pipeline honest body validate",zb("stack_in(kernel)","stack_in(kernel)","","rax","mov rax,0"));
 /* ================== shape==3, measured against the C oracle ==============
    The claim under test: a nested call statement over a callee that returns
    and whose body the oracle says writes no memory is the same balanced
    frame pair as the call under proof, so charging it a memory write
    refuses a mapping_present that is in fact true. Each row names the
    instruction in the nested callee, and the expectation is derived from
    nt_x64_effects for that same instruction, so no verdict here is written
    by hand. */
  {struct{const char*tag;const char*m;unsigned nops,k0,k1,w;const char*text;
          const char*seff;int returns;}rows[]={
      /* The oracle publishes no memory_write for any of these, so each is a
         balanced pair over a body that stores nothing. */
      {"empty body",       "nop",      0,0,0,0,  "nop",                     "",       1},
      {"register write",   "mov",      2,0,0,64, "mov rax,0",               "",       1},
      {"memory read",      "load",     2,0,1,64, "load rax,[rbx]:ptr<user,u64>","reads_mem",1},
      {"memory read mov",  "mov",      2,0,1,64, "mov rax,[rbx]:ptr<user,u64>", "reads_mem",1},
      {"stack read only",  "pop",      1,0,0,64, "pop rax",                 "",       1},
      /* The oracle publishes memory_write for these, so the nested callee
         really does store and the mapping must be refused. */
      {"store immediate",  "store",    2,1,2,64, "store [rbx]:ptr<user,u64>,1","",     1},
      {"store register",   "store",    2,1,0,64, "store [rbx]:ptr<user,u64>,rax","",   1},
      {"store honest",     "store",    2,1,2,64, "store [rbx]:ptr<user,u64>,1","writes_mem(user)",1},
      {"store through mov","mov",      2,1,0,64, "mov [rbx]:ptr<user,u64>,rax","",    1},
      {"store through xchg","xchg",    2,0,1,64, "xchg rax,[rbx]:ptr<user,u64>","",   1},
      /* A push is a stack_write, the same eight bytes a call pushes, so a
         callee that pushes is NOT a balanced pair: nothing pops it. */
      {"push register",    "push",     1,0,0,64, "push rax",                "",       1},
      {"push immediate",   "push",     1,2,0,64, "push 1",                  "",       1},
      {"pushfq",           "pushfq",   0,0,0,0,  "pushfq",                  "",       1}};
   for(unsigned i=0;i<sizeof rows/sizeof rows[0];i++){
     int want=0;
     nsverdict(rows[i].m,rows[i].nops,rows[i].k0,rows[i].k1,rows[i].w,
               rows[i].returns,&want);
     nscase(&image,rows[i].tag,
            ns("u64",rows[i].seff,rows[i].text,"","mapping_present(q)"),want);
   }}
 /* A callee that never returns has no return to balance its call, so the
    pair is not balanced whatever its body says. The oracle publishes
    terminal for no return in a never callee, so the expectation is the
    refusal and it is stated as such rather than derived from the body. */
  nscase(&image,"never callee",ns("never","","mov rax,0","","mapping_present(q)"),0);
 /* A nested call to an import has no body in this tree, so nothing proves
    the pair balanced and the charge stands. This is the fail-closed half of
    the narrowing: what cannot be seen is still charged. */
  nscase(&image,"import callee",
    "module m\ntarget x86_64-nexora-none\n"
    "import a.g as side: fn()->u64\neffects {}\nclobbers {}\nrequires {}\n"
    "section .text {\n"
    "fn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\n"
    "requires {mapping_present(p)} {\nreturn 0\n}\n"
    "fn main(in q:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\n"
    "requires {mapping_present(q)} {\ncall side()\ncall leaf(q)\nreturn 0\n}\n}\n",0);
 /* A cycle of helpers, a0 calls a1 calls a2 calls a0, none of which stores.
    Whether such a body writes memory is undecidable here without a fixpoint,
    so the pass must refuse rather than invent a proof, and it must terminate
    rather than recurse without end. cyc builds that body; nscase is called on
    it with want 0, so a hang fails the gate by timing out and an admitted
    proof fails it by name. */
  {struct{const char*tag;unsigned n;const char*tail;}cyc[]={
      {"cycle of 2, no store",2,""},
      {"cycle of 3, no store",3,""},
      {"cycle of 5, no store",5,""},
      {"cycle of 3, one link stores",3,"store [rbx]:ptr<user,u64>,1"}};
   for(unsigned c=0;c<sizeof cyc/sizeof cyc[0];c++){
     size_t w=0;
     w+=(size_t)snprintf(S+w,sizeof S-w,
       "module m\ntarget x86_64-nexora-none\nsection .text {\n"
       "fn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\n"
       "requires {mapping_present(p)} {\nreturn 0\n}\n");
     for(unsigned i=0;i<cyc[c].n;i++)
       w+=(size_t)snprintf(S+w,sizeof S-w,
         "fn a%u()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall a%u()\n%s\nreturn 0\n}\n",
         i,(i+1)%cyc[c].n,cyc[c].tail);
     snprintf(S+w,sizeof S-w,
       "fn main(in q:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\n"
       "requires {mapping_present(q)} {\ncall a0()\ncall leaf(q)\nreturn 0\n}\n}\n");
     nscase(&image,cyc[c].tag,S,0);
   }}
 /* The narrowing touches the memory guard only. A nested call still moves
    rsp, so stack_in and the frame pair must keep refusing exactly as before,
    and those two rows are the regression guard for that. */
  aerrp(&image,"nested call still moves the stack",
        zb("stack_in(kernel)","stack_in(kernel)","","rax","call leaf()"),326,"leaf",2,6,0);
  aerrp(&image,"nested call still moves the frame",
        tb("valid_user_return(a,b)","valid_user_return(c,d)","rax","call leaf(c,d)"),326,"leaf",2,11,0);
 /* ===================== the rsp write, and the channel that could carry it ==
    One question, asked against the product rather than read off a comment:
    the reference publishes a call's stack write in a field of its own,
    `stack_write`, separate from `registers_written` (x64.h:110, x64.c:945),
    which is the same shape as `changes_flags` duplicating bit 17. So a third
    channel is not obviously missing. The rows below ask whether the product
    has one, and they ask it in the only way that can answer it: by trying to
    declare the write in every channel the language has, and by trying to
    declare `rsp` itself and reading what that costs the callers.

    The oracle half is not asserted from a comment. frame_pair_balanced above
    already recomputes the two fields, and this block refuses to run at all
    unless the reference still agrees that a call publishes a stack write that
    a return balances: without that, the narrowing these cases describe would
    have to be re-derived rather than trusted, and a re-derivation is not what
    this gate is for. */
  CHECK(frame_pair_balanced(),"reference still separates the stack write from the register write");
 /* THE THIRD CHANNEL DOES NOT EXIST, AND IT IS NOT BECAUSE THE LANGUAGE
    FORBIDS IT. Two declarations, and the diagnostic cannot tell them apart:

      effects {stack_write}  -> 321 | 5 10 1 0
      effects {stack_writ}   -> 321 | 5 10 1 0     <- a typo

    `stack_write` is a real field of the reference with a real value, and it is
    refused here with byte-for-byte the verdict of a misspelling. That is the
    same shape effects.nova:127-152 already names for gsbase, on the other
    channel: the reference knows the name and the product has no row for it.
    So the answer to "is the language forbidding this or has nobody built the
    channel" is the second one, and it is measured rather than inferred. The
    eleven-atom table is a complete projection of the reference's eleven
    `effects` positions (x64.h:92-104); `stack_write` is not one of them,
    because it is not an atom at all but a field beside the register mask, so
    no twelfth row over the same eleven bits could name it. */
  stage(&image,"effects{stack_write} is not an atom",PM(
    "fn leaf()->u64\neffects {stack_write}\nclobbers {}\nrequires {} {\nreturn 0\n}\n"
    "fn main()->u64\neffects {}\nclobbers {}\nrequires {} {\nreturn 0\n}\n"),
    321,"stack_write",1,1,0,1);
  /* THE POSITIVE CONTROL, and it is the row that makes the row above mean
    something. The effects channel is not inert: a real memory atom is
    accepted in the same shape, at the same position, in the same program. So
    the refusal above is about the NAME and not about the channel being
    closed, which is the distinction the two rows together establish and
    neither establishes alone. */
  ok(&image,"effects{writes_mem} is accepted in the same shape",PM(
    "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {} {\nreturn 0\n}\n"
    "fn main()->u64\neffects {writes_mem}\nclobbers {}\nrequires {} {\nreturn 0\n}\n"),2,0,0);
 /* A FUNCTION CAN DECLARE THAT IT WRITES `rsp` TODAY. This is the acceptance
    question, and the answer is yes, in the language's own words, on a body
    whose only stack writer is its own return. §8.2 calls that declaration
    untrue and the product accepts it: abi.nova:513-518 says so in capitals
    and this row is the run-time half of that sentence. Nothing forbids the
    declaration; nothing verifies it either, which is the pair of facts the
    specification decision actually turns on. */
  ok(&image,"clobbers{rsp} is accepted on a return-only body",PM(
    "fn leaf()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\nreturn 0\n}\n"
    "fn main()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\nreturn 0\n}\n"),2,0,0);
 /* And the declaration is not merely permitted, it is UNVERIFIED: a lone
    function declaring `rsp` with nothing in its body but a return is accepted,
    so the product never asks whether the promise is true. A channel that
    cannot be discharged and a channel that is never read are the same
    observation from two sides, and this is the side that decides the cost. */
  ok(&image,"clobbers{rsp} is never checked for truth",PM(
    "fn lone()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\nreturn 0\n}\n"),1,0,0);
 /* WHAT THE DECLARATION COSTS, AND IT IS NOT THE COST THE ROW NAMES. The
    row says the cost is that `rsp` becomes a mandatory entry in every
    `clobbers` set. That is the cost of the BODY. The cost that decides the
    specification question is one level up: `call_clobbers` reads the mask and
    requires the callee's families to be a subset of the caller's
    (call_clobbers.nova:96, measured here as 331 with the missing family bit),
    so a callee that declares `rsp` forces every caller to declare it too.

      leaf{rsp}, main{}   -> 331 | 14 6 1 16
      leaf{rsp}, main{rsp} -> accepted

    Bit 16 is the frame family, 1<<4. So the declaration is not a local
    annotation a body opts into: it is an obligation that propagates along the
    call graph, upward, to every ancestor of the declaring body.

   The reported position is the CALL SITE, not the callee's declaration, so
   the needle below is the second occurrence of the callee name in these
   fixtures: `leaf` names the declaration first and the call second. That is
   the reference's own choice -- it reports the call expression -- and it is
   the right one for an obligation the CALLER owes, because the diagnostic
   then points at the line the reader has to edit. */
  stage(&image,"a callee declaring rsp obliges its caller",PM(
    "fn leaf()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\nreturn 0\n}\n"
    "fn main()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"),
    331,"leaf",2,1,16,1);
  ok(&image,"paying the obligation on both sides",PM(
    "fn leaf()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\nreturn 0\n}\n"
    "fn main()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"),2,1,0);
 /* AND IT CLIMBS. One rung is a cost a programmer can see and pay at the call
    site. Three rungs are a fixpoint over the call graph: every function that
    can reach the declaring body, at any depth, owes the declaration. Measured
    with leaf and mid declaring and main refusing, the refusal is at main, so
    the obligation is not satisfied at the first hop. This is the number the
    decision needs and the row does not carry: the cost of `rsp` in a
    `clobbers` set is a property of the call graph, not of the 182 bodies. */
  stage(&image,"the rsp obligation climbs the call graph",PM(
    "fn leaf()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\nreturn 0\n}\n"
    "fn mid()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"
    "fn main()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall mid()\nreturn 0\n}\n"),
    331,"mid",2,1,16,1);
  ok(&image,"three rungs all paid",PM(
    "fn leaf()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\nreturn 0\n}\n"
    "fn mid()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"
    "fn main()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\ncall mid()\nreturn 0\n}\n"),3,2,0);
 /* THE ASYMMETRY THAT CLOSES THE QUESTION. The subset rule runs callee to
    caller only, so a caller may declare MORE than its callee: `main` claiming
    `rsp` over a `leaf` that claims none is accepted. The obligation therefore
    has a direction, and the direction is the whole of the cost. A false
    declaration is not caught by the callee refusing it, because no callee ever
    reads the caller's set. This is why the two rules of the specification can
    be made to agree by moving the charge rather than by adding a check: the
    place the check would have to live is the place that does not look. */
  ok(&image,"the subset rule runs callee to caller only",PM(
    "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {} {\nreturn 0\n}\n"
    "fn main()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"),2,1,0);

 /* ============ THE FRAME CHARGE, MOVED OFF THE MASK, AND MEASUREED ======
    Everything above measures the charge WHERE IT IS: inside `clobbers`, where
    it is a set difference and therefore an obligation over the call graph.
    The block below measures the same charge in the other place, on the frame,
    and the only honest way to do that is an A/B over one entry, one mode and
    one program shape where the single varying thing is WHERE the charge sits.
    Every row runs on the standalone call_contracts entry, mode 1, so no
    guarding pass runs in front and no row can be answered by a pass that
    composes a body; the two arms therefore differ by nothing but the channel.

    ARM A, the frame channel. `leaf` writes the stack in its own body with a
    balanced push/pop pair, and declares the ONE register that pair really
    writes, `rbx`. It does NOT declare `rsp`, and that is not a lie: push and
    pop of the same register leave the stack pointer exactly where it was, so
    the entry value of `rsp` is restored at the boundary and spec 8.2 does not
    ask for it. Three rungs, and the obligation count is zero at every one of
    them: no 331 is raised anywhere, because a frame write that balances is not
    a declaration and so is not an obligation any caller can fail to pay.

    The `rbx` entry is not decoration. A first revision of this row left the
    set empty and it PASSED, because on this entry nothing composes a body and
    an empty set over a `push rbx` body is simply not checked; the honest
    declaration is what makes the two arms comparable rather than making this
    one pass. */
 aok(&image,"frame channel: a balanced frame write obliges no caller",PM(
   "fn leaf()->u64\neffects {}\nclobbers {rbx}\nrequires {} {\npush rbx\npop rbx\nreturn 0\n}\n"
   "fn mid()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall mid()\nreturn 0\n}\n"),3,2,0);
 /* The same chain one rung deeper, still with no declaration anywhere. A fix
    point that a fourth rung could break would not be a fix point. */
 aok(&image,"frame channel: four rungs, still nothing to declare",PM(
   "fn leaf()->u64\neffects {}\nclobbers {rbx}\nrequires {} {\npush rbx\npop rbx\nreturn 0\n}\n"
   "fn one()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"
   "fn two()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall one()\nreturn 0\n}\n"
   "fn three()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall two()\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall three()\nreturn 0\n}\n"),5,4,0);
 /* A lone writer, to pin the count at its minimum: one function, one frame
    write, no call and therefore no caller, and no 331. */
 aok(&image,"frame channel: a lone frame write",PM(
   "fn leaf()->u64\neffects {}\nclobbers {rbx}\nrequires {} {\npush rbx\npop rbx\nreturn 0\n}\n"),1,0,0);

 /* ARM B, THE POSITIVE CONTROL, and it is what makes ARM A mean something.
    These are the SAME three rungs, the SAME entry, the SAME mode, with the one
    change that the charge moved from the body into the callee's `clobbers`
    set. The verdict inverts: 331, category 1, missing bit 16, reported at the
    second occurrence of `leaf`, which is the call inside `mid`. */
 stage(&image,"mask channel: the same chain now refuses at the first hop",PM(
   "fn leaf()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\nreturn 0\n}\n"
   "fn mid()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall mid()\nreturn 0\n}\n"),
   331,"leaf",2,1,16,1);
 /* Paying the obligation on the first hop moves the refusal one rung UP the
    graph, and not one rung less: `leaf` and `mid` declare, and the refusal is
    now at `main`. Two rungs paid, one refusal, and the same missing bit 16. */
 stage(&image,"mask channel: paying one hop moves the refusal up a rung",PM(
   "fn leaf()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\nreturn 0\n}\n"
   "fn mid()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall mid()\nreturn 0\n}\n"),
   331,"mid",2,1,16,1);
 /* AND IT HAS NO BOTTOM. A four rung chain with two hops paid refuses at the
    third, which is what makes the cost a fix point over the call graph rather
    than a count of bodies: the number of rungs that must declare is the depth
    of the deepest path to the writer, and no fixed count of entries discharges
    it. Compare the four rung ARM A row above, which has a writer at the same
    depth and nothing at all to declare. */
 stage(&image,"mask channel: four rungs, the refusal has no bottom",PM(
   "fn leaf()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\nreturn 0\n}\n"
   "fn one()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"
   "fn two()->u64\neffects {}\nclobbers {rsp}\nrequires {} {\ncall one()\nreturn 0\n}\n"
   "fn three()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall two()\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall three()\nreturn 0\n}\n"),
   331,"two",2,1,16,1);

 /* ARM C, THE SHAPE OF THE MOVE, WHICH IS THE PART THAT IS NOT A COUNT. In
    ARM B the callee declares and the body is empty; in ARM A the body writes
    and the callee declares nothing. This row holds BOTH at once: the body
    writes the frame AND the set names `rsp`. The verdict is byte for byte the
    verdict of ARM B, the refusal at the same position with the same missing
    bit, which is the measurement that the two channels are not additive: a
    body write adds nothing to a mask charge, and a mask charge adds nothing a
    body has to say. ONE obligation, and this gate shows it is the mask that
    holds it.

    The `rbx` hops are the measured contrast, not a detail of the fixture.
    Declaring the register the body really writes is a real obligation and it
    costs one entry per rung, exactly as this row shows: `mid` and `main` each
    carry an `rbx` they never touch, because `leaf` writes it and the subset
    rule runs callee to caller. ARM A above runs the SAME chain with the SAME
    `push rbx; pop rbx` body and pays NONE of that, because there the pair
    balances and `rbx` is restored at the boundary, so no rung has anything to
    declare at all. One body, two verdicts, and the difference is entirely
    whether the entry value survives to the boundary. That is the whole of what
    the restoration rule buys, and it is why the frame charge is not the same
    kind of thing as a clobber entry. */
 stage(&image,"both channels at once: the mask still carries it all",PM(
   "fn leaf()->u64\neffects {}\nclobbers {rsp,rbx}\nrequires {} {\npush rbx\npop rbx\nreturn 0\n}\n"
   "fn mid()->u64\neffects {}\nclobbers {rbx}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {rbx}\nrequires {} {\ncall mid()\nreturn 0\n}\n"),
   331,"leaf",2,1,16,1);
 /* And the reverse half, which is the same fact seen from the other side: the
    body writes the frame, nothing is declared, and the chain proves at every
    rung. That is the frame charge discharging on its own, with no declaration
    for a caller to fail to pay, and it is the shape the charge has to take for
    the fix point over the call graph to be gone. */
 aok(&image,"frame channel: the body write discharges alone",PM(
   "fn leaf()->u64\neffects {}\nclobbers {rbx}\nrequires {} {\npush rbx\npop rbx\nreturn 0\n}\n"
   "fn mid()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall mid()\nreturn 0\n}\n"),3,2,0);

 /* ARM D, THE ASYMMETRY THAT MAKES ARM A A MOVEMENT AND NOT A WIDENING. The
    subset rule runs callee to caller only, so a caller may declare MORE than
    its callee for free. Measured here on a chain that DOES write frames at two
    rungs: declaring `rsp` at `main`, which writes nothing and is called by
    nobody, is accepted. So the frame channel removes an obligation without
    adding one anywhere, which is what the acceptance above and this row
    together establish, and it is the reason the charge can be moved rather
    than only added. */
 aok(&image,"frame channel: a caller over-declaring is still free",PM(
   "fn leaf()->u64\neffects {}\nclobbers {rbx}\nrequires {} {\npush rbx\npop rbx\nreturn 0\n}\n"
   "fn mid()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {rsp,rbx}\nrequires {} {\ncall mid()\nreturn 0\n}\n"),3,2,0);

 /* ============ FALSIFYING THE DECISION, ON THE THREE SHAPES THAT WOULD ====
    The decision under test is that the `rsp` write is a FRAME property and
    belongs to the frame rule, not to a register declaration. It rests on
    `rsp` being restored at the boundary. It is falsified by any path the
    product emits where `rsp` is NOT restored, and the brief named three. Each
    is asked here as its own row, and each row is a REAL program through the
    standalone entry, not a reading of a comment.

    (1) AN UNBALANCED EPILOGUE, AND WHAT THE PRODUCT ACTUALLY DOES WITH IT.
    The expectation that a body pushing without popping is refused while the
    same body balanced is accepted turned out to be FALSE, and the gate is how
    that is known: both are refused. The stack half of the guard is a walk over
    STATEMENTS, not a balance computation, so `push rbx` charges the caller
    whatever follows it. This is the safe direction and the file says so, and
    it is recorded here because it bears directly on the decision: the product
    never establishes that an `rsp` write is restored, it only ever refuses to
    rely on the question. The restoration the decision reasons from is the
    reference's epilogue, not something this pass proves. */
 aerrp(&image,"falsify 1: an unbalanced push is refused",PM(
   "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\n"
   "push rbx\ncall leaf()\nreturn 0\n}\n"),326,"leaf",2,6,0);
 /* THE POSITIVE CONTROL, and it is the row that makes the refusal above mean
    something: a body with no stack writer at all proves, in the same shape and
    at the same position. So the refusal is the walk seeing `push`, not a
    standing property of this program. */
 aok(&image,"falsify 1 control: no stack writer, the same shape proves",PM(
   "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\n"
   "mov rax,0\ncall leaf()\nreturn 0\n}\n"),2,1,1);
 /* And the balance half, measured rather than assumed: `push` then `pop` is
    STILL refused, which is the statement above and is asserted here so it
    cannot be quietly dropped from this file later. A guard that computed
    balance would accept this body. */
 aerrp(&image,"falsify 1: a balanced push/pop is refused too",PM(
   "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\n"
   "push rbx\npop rbx\ncall leaf()\nreturn 0\n}\n"),326,"leaf",2,6,0);

 /* (2) A NESTED FRAME, IN THE ONLY POSITION WHERE IT CAN COST ANYTHING. The
    guard reads the CALLER's own body, so a call nested inside the CALLEE is
    the callee's business and costs the caller nothing: this is accepted, and
    it is the shape==3 narrowing working as its own comment claims. */
 aok(&image,"falsify 2: a call nested in the callee costs the caller nothing",PM(
   "fn inner()->u64\neffects {}\nclobbers {}\nrequires {} {\nreturn 0\n}\n"
   "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall inner()\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\n"
   "call leaf()\nreturn 0\n}\n"),3,2,0);
 /* The other position, where the nested call IS in the caller's body. This one
    is refused, and the difference between this row and the one above is the
    whole of the locality the decision relies on: the charge lands on the one
    function whose body carries the write, and on no other. */
 aerrp(&image,"falsify 2: the same nesting inside the caller is refused",PM(
   "fn inner()->u64\neffects {}\nclobbers {}\nrequires {} {\nreturn 0\n}\n"
   "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {stack_in(kernel)} {\n"
   "call inner()\ncall leaf()\nreturn 0\n}\n"),326,"leaf",2,6,0);

 /* (3) A TAIL CALL, the shape that would break the decision hardest, because
    a tail call transfers the frame rather than restoring it: there is no
    epilogue after it. The grammar admits `jmp` as a body statement, and this
    row measures what the product then does with it rather than assuming. The
    probe prints the raw verdict; the count in `out` is declarations first, so
    2 and 0 says two declarations and ZERO calls recognised.

    THE CONTROL, and it is added because the probe above could not tell a pass
    that sees no calls from a pass that is not looking. F3C is the same two
    declarations with `call` in place of `jmp`, and it is ASSERTED, not probed:
    one call recognised, 0. If F3C ever stopped seeing its call then the 0 in
    F3 would be a property of the harness rather than of the pass, and the
    probe would be printing a broken instrument. A probe that cannot be shown
    to distinguish its two answers is not evidence about either. */
 aok(&image,"falsify 3 CONTROL: the same two declarations with a call",PM(
   "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {} {\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {} {\ncall leaf()\nreturn 0\n}\n"),2,1,0);
 probe(&image,"falsify 3: jmp as the last statement of a body",PM(
   "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {} {\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {} {\njmp leaf\nreturn 0\n}\n"),1);
 /* F3D the negative control ON THE PROBE ITSELF, and this is the row that
    says the probe is not vacuous in the other direction either: a body with
    NEITHER a jmp nor a call must report zero calls, and must still be
    accepted. If F3 and F3D printed the same four words then the instrument
    would not be reading the body at all. */
 aok(&image,"falsify 3 CONTROL: no call and no jmp reports zero calls",PM(
   "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {} {\nreturn 0\n}\n"
   "fn main()->u64\neffects {}\nclobbers {}\nrequires {} {\nreturn 0\n}\n"),2,0,0);
 /* THE COMPOSITION ROWS, AND THEY SETTLE THE QUESTION THE TABLE IN
    call_contracts.nova COULD NOT. That table compares the C reference against
    call_contracts.check ALONE, and a set containment about one pass is not a
    claim about the pipeline. These rows ask the FULL 43 module validate image
    the same bodies, so whether the stages in front close what call_contracts
    alone admits is read off a run instead of assumed. Every row is ASSERTED
    through verpv with its exact four words, not printed, so a pipeline that
    later stops charging the stack is a red row here rather than a different
    number in a log nobody diffs.

    THE MEASURED RESULT: the pipeline REFUSES all three push/pop bodies, with
    335, which is body_clobbers. So the composition holds -- the language layer
    and the contract layer together are at least as strict as the reference on
    these bodies -- and it holds for a reason worth naming, which is C1b
    against C1c below.

    C0 is the control and it is FIRST. A run in which every row says REFUSED is
    what a broken image looks like, and it is indistinguishable from a real
    "the pipeline refuses all of these" unless one row is known accepted
    first. */
 verpv(&vimage,"C0 CONTROL plain body, no stack motion",PM(
   "fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n"),0,35,39,21,0);
 verpv(&vimage,"C1 bare push rbx, no pop, honest {rbx}",PM(
   "fn main()->u64\neffects {changes_flags}\nclobbers {rbx} {\npush rbx\nreturn 0\n}\n"),
   335,7,1,1,16);
 verpv(&vimage,"C2 balanced push rbx / pop rbx, honest {rbx}",PM(
   "fn main()->u64\neffects {changes_flags}\nclobbers {rbx} {\n"
   "push rbx\npop rbx\nreturn 0\n}\n"),335,7,1,1,16);
 verpv(&vimage,"C5 bare pop rbx, no push, honest {rbx}",PM(
   "fn main()->u64\neffects {changes_flags}\nclobbers {rbx} {\npop rbx\nreturn 0\n}\n"),
   335,7,5,1,16);
 /* C1B AND C1C, THE DISCRIMINATOR, and this pair is what makes C1 mean
    something. C1 is refused 335 while its declaration already names rbx, so
    the charge cannot be an undeclared REGISTER write -- rbx is declared. Two
    rows separate the two explanations. C1b pushes rax under `clobbers {rax}`
    and gets the IDENTICAL 335, bit and column, so the charge does not follow
    the register that is named. C1c is a plain machine write against the same
    sort of honest declaration and is ACCEPTED. Together: what the pipeline
    refuses is the STACK MOTION of push and pop, not the register the operand
    happens to name, and 335 here is the frame discipline rather than a clobber
    bookkeeping slip. A reader who skipped C1b and C1c would have a 335 and no
    idea what it was about. */
 verpv(&vimage,"C1b push rax, clobbers {rax}, honest",PM(
   "fn main()->u64\neffects {changes_flags}\nclobbers {rax} {\npush rax\nreturn 0\n}\n"),
   335,7,1,1,16);
 verpv(&vimage,"C1c CONTROL mov rax,0, clobbers {rax}, honest",PM(
   "fn main()->u64\neffects {changes_flags}\nclobbers {rax} {\nmov rax,0\nreturn 0\n}\n"),
   0,35,46,31,0);
 /* And the same two bodies through call_contracts ALONE, side by side in the
    same log, so the two columns are comparable without a reader joining them
    from two runs of a file that may have moved between them. These two are the
    mode 1 side of the composition, and they are what makes the composition a
    composition: admitted here, refused above. */
 aok(&image,"C1 call_contracts alone: bare push is admitted",PM(
   "fn main()->u64\neffects {changes_flags}\nclobbers {rbx} {\npush rbx\nreturn 0\n}\n"),1,0,0);
 aok(&image,"C2 call_contracts alone: balanced pair is admitted",PM(
   "fn main()->u64\neffects {changes_flags}\nclobbers {rbx} {\n"
   "push rbx\npop rbx\nreturn 0\n}\n"),1,0,0);
 /* The never callee, the closest thing the language has to a path that does
    not come back: its body has no epilogue because it has no return. Measured
    through the module fixture, which is the only way an import reaches this
    entry, so the import stays outside the section. */
 aok(&image,"falsify 3b: a never callee returns no caller post state",nvi(
   "","stack_in(kernel)","",""),2,1,0);
/* The helper's own 41 module image is released before either of this file's
   two, and before main returns, so the leak checker sees a process that
   gave back everything it took. */
 /* ================= THE SEVEN REFERENCE ROWS, RESTORED 30 SEPTEMBER 2026 ==
    An over-wide deletion in this lot destroyed main's body, and the recovery
    copy on disk measured 1833 checks against this gate's 1840, with all 458
    cases present.  The seven missing checks were these: the header above says
    so in its own words -- "The five reference rows at the end of main MEASURE
    the oracle's answer rather than assuming it, and the two of them under the
    cycle block's comment measure the REASON" -- and the deletion kept the
    header that describes the rows and took the rows themselves.

    So the TEXT of the seven rows is not recovered; it is rewritten, and every
    number in it was measured again today through ref_verdict, the same
    nt_frontend_compile entry the deleted rows called.  The values are in
    out/lot21/probe8, and they are the values the header already asserts: the
    six predicates the oracle recognises and does not prove are answered 600
    NTF_E_UNSUPPORTED, "recognized but proof checking is not implemented", and
    the two it does implement accept the same source shape.  A reader who
    wants the original wording will not find it here; the fact is here.

    FIVE ROWS MEASURE AN ANSWER, not six, and the pair of interrupt families
    shares one row.  They are the two halves of one fact, they are measured
    by the same query, and the loss being repaired is exactly seven checks.
    Splitting the pair would make eight and the banner would carry a number
    nobody could account for.

    ONE CALL PER CHECK, and that is not tidiness.  z, p and t above all format
    into one shared static S, so holding six sources in six pointers leaves
    all six pointing at the last one formatted.  Each row calls its builder
    and consumes the result inside the same statement. */
  CHECK(ref_verdict(z("stack_in(kernel)","stack_in(kernel)","",""))==600,
        "the oracle answers 600 for stack_in, so it has no stack_in verdict for this gate to agree or disagree with");
  CHECK(ref_verdict(z("msr_initialized(1)","msr_initialized(1)","",""))==600,
        "the oracle answers 600 for msr_initialized");
  CHECK(ref_verdict(z("interrupts_enabled()","interrupts_enabled()","",""))==600
     &&ref_verdict(z("interrupts_disabled()","interrupts_disabled()","",""))==600,
        "the oracle answers 600 for both interrupt families");
  CHECK(ref_verdict(z("mapping_present(4096)","mapping_present(4096)","",""))==600,
        "the oracle answers 600 for mapping_present, so caller_caps bit 8 has no oracle to be wide or narrow against");
  CHECK(ref_verdict(t("valid_user_return(a,b)","","valid_user_return(c,d)","","","call leaf(c,d)"))==600,
        "the oracle answers 600 for valid_user_return");
  /* The two that measure the REASON.  The same two-function shape that draws
     a 600 above is ACCEPTED for a predicate the oracle does prove, so the 600
     is about the predicate and not about the harness, the target, the pointer
     syntax or the call. */
  CHECK(ref_verdict(p("non_null(p)","","","non_null(q)","",""))==0,
        "the oracle ACCEPTS the same shape under non_null, which it implements: the 600 above is about the predicate, not the source");
  CHECK(ref_verdict(z("stack_aligned(16)","stack_aligned(8)","",""))==0,
        "the oracle ACCEPTS the same shape under stack_aligned, which it implements");
 {struct pop_row{const char*predicate;uint64_t family;unsigned shape;
    /* the three columns, each as (features header, callee requires, caller
       requires). The header is "" for nine rows and "features {sse2}\n" for
       family 1, whose fact lives there and nowhere else. */
    const char*sat[3];const char*vio[3];const char*unp[3];
    uint64_t vio0;uint64_t unp0;const char*why;}rows[]={
  {"feature",1,0u,
   {"features {sse2}\n","feature(sse2)",""},
   {"","feature(sse2)",""},
   {"features {sse2}\n","feature(nosuch)",""},
   344,343,
   "the only family whose fact is the MODULE feature mask and never the "
   "caller, so neither refusal column can be raised at a call in the shipped "
   "order: mode 0 stops earlier, at feature_requirements 344 for a bit the "
   "module does not carry and at features 343 for a name that is not a "
   "feature at all, and only mode 1 reaches this pass and answers 326 family "
   "1. That asymmetry is the content of the row, not a defect in it."},
  {"non_null",2,1u,
   {"","non_null(p)","non_null(q)"},
   {"","non_null(p)",""},
   {"","non_null(0)","non_null(0)"},
   326,326,
   "the subject must be a caller PARAMETER, because that is what names a "
   "call argument; a literal names no parameter, so the remap has no step and "
   "even a caller carrying the identical bytes proves nothing"},
  {"canonical",3,1u,
   {"","canonical(p)","canonical(q)"},
   {"","canonical(p)",""},
   {"","canonical(0)","canonical(0)"},
   326,326,
   "the same remap and the same unprovable subject as non_null; the two "
   "families differ only in what the fact asserts about the pointer"},
  {"stack_aligned",4,0u,
   {"","stack_aligned(16)","stack_aligned(8)"},
   {"","stack_aligned(32)","stack_aligned(32)"},
   {"","stack_aligned(0)","stack_aligned(0)"},
   326,326,
   "N must be a power of two with 0<N<=16, a ceiling spec 17.3 states once "
   "and excludes 32 from by name. 8 discharges a callee 16 through the ABI "
   "guarantee, so the SATISFIED row is a call with a WEAKER caller fact. 32 "
   "is a power of two and discharges nothing even when the caller carries it, "
   "which is the row that was accepted before this lot; 0 is not a power of "
   "two at all."},
  {"stack_in",6,0u,
   {"","stack_in(kernel)","stack_in(kernel)"},
   {"","stack_in(kernel)",""},
   {"","stack_in(1)","stack_in(1)"},
   326,326,
   "the argument must be a pointer SPACE, and 1 is a literal naming no "
   "space, so a caller carrying stack_in(1) has not carried the callee's "
   "stack_in(kernel) even though both are proved by byte comparison"},
  {"interrupts_enabled",7,0u,
   {"","interrupts_enabled()","interrupts_enabled()"},
   {"","interrupts_enabled()",""},
   {"","interrupts_enabled()","interrupts_disabled()"},
   326,326,
   "zero arity, so there is no subject to remap and the POLARITY is the "
   "whole fact; a disabled caller cannot discharge an enabled callee"},
  {"interrupts_disabled",8,0u,
   {"","interrupts_disabled()","interrupts_disabled()"},
   {"","interrupts_disabled()",""},
   {"","interrupts_disabled()","interrupts_enabled()"},
   326,326,
   "zero arity, the mirror of family 7: an enabled caller cannot discharge a "
   "disabled callee, and the refusal names family 8, not family 7"},
  {"msr_initialized",9,0u,
   {"","msr_initialized(1)","msr_initialized(1)"},
   {"","msr_initialized(1)",""},
   {"","msr_initialized(1)","msr_initialized(2)"},
   326,326,
   "matching is BYTEWISE, so the selector is part of the fact and a caller "
   "that initialised selector 2 has not initialised selector 1"},
  {"mapping_present",10,0u,
   {"","mapping_present(4096)","mapping_present(4096)"},
   {"","mapping_present(4096)",""},
   {"","mapping_present(4096)","mapping_present(4097)"},
   326,326,
   "a fixed address subject is compared by bytes, and 4096 and 4097 are two "
   "subjects, so the caller carries a fact about a different mapping"},
  {"valid_user_return",11,2u,
   {"","valid_user_return(a,b)","valid_user_return(c,d)"},
   {"","valid_user_return(a,b)",""},
   {"","valid_user_return(a,b)","valid_user_return(d,c)"},
   326,326,
   "both subjects remap IN ORDER, so (d,c) is the same two names in the wrong "
   "order and the order is part of the fact, not of the spelling"}};
  for(unsigned i=0;i<sizeof rows/sizeof rows[0];i++){
    char sat[8192],vio[8192],unp[8192];
    popsrc(sat,sizeof sat,rows[i].shape,rows[i].sat[0],rows[i].sat[1],rows[i].sat[2],"");
    /* SATISFIED: proved, so the delivered path returns 0. This entry takes
       FIVE words, so it is reached with run5 and never with run: run passes
       four, and an entry handed the wrong arity reads its mode out of a
       register that was never set. */
    cases++;checks++;
    {Run r=run5(&image,rows[i].predicate,sat,4,0);
     if(r.returned||r.runtime)
       {failures++;fprintf(stderr,"FAIL pop %s SATISFIED ret=%llu out=%llu,%llu,%llu,%llu\n",
        rows[i].predicate,(unsigned long long)r.returned,(unsigned long long)r.out[0],
        (unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
    popsrc(vio,sizeof vio,rows[i].shape,rows[i].vio[0],rows[i].vio[1],rows[i].vio[2],"");
    popsrc(unp,sizeof unp,rows[i].shape,rows[i].unp[0],rows[i].unp[1],rows[i].unp[2],"");
    const char*col[2]={"VIOLATED","UNPROVABLE"};
    const char*src[2]={vio,unp};
    const uint64_t want0[2]={rows[i].vio0,rows[i].unp0};
    for(unsigned k=0;k<2;k++){
      /* MODE 0, the shipped order. Every cell REFUSES, and the code is pinned
         to the measured one so a pipeline that starts stopping earlier or
         later is a red row rather than a different number in a log. */
      cases++;checks++;
      Run r=run5(&image,rows[i].predicate,src[k],4,0);
      if(r.returned!=want0[k]||r.runtime){
        failures++;
        fprintf(stderr,"FAIL pop %s %s pipeline ret=%llu want %llu out=%llu,%llu,%llu,%llu\n",
          rows[i].predicate,col[k],(unsigned long long)r.returned,
          (unsigned long long)want0[k],(unsigned long long)r.out[0],
          (unsigned long long)r.out[1],(unsigned long long)r.out[2],
          (unsigned long long)r.out[3]);}
      /* MODE 1, the pass ALONE. Here the refusal is about the PREDICATE, and
         it publishes the family, which is how a refusal names what it could
         not prove. BOTH refusal columns are asked, because a pass that
         refuses the violated one and credits the unprovable one is precisely
         the conflation this table exists to make impossible. */
      cases++;checks++;
      Run a=run5(&image,rows[i].predicate,src[k],4,1);
      if(a.returned!=326||a.runtime||a.out[2]!=rows[i].family){
        failures++;
        fprintf(stderr,"FAIL pop %s %s alone ret=%llu want 326 family %llu out=%llu,%llu,%llu,%llu\n",
          rows[i].predicate,col[k],(unsigned long long)a.returned,
          (unsigned long long)rows[i].family,(unsigned long long)a.out[0],
          (unsigned long long)a.out[1],(unsigned long long)a.out[2],
          (unsigned long long)a.out[3]);}
    }
    (void)rows[i].why;}}
 }ng_parity_finish(&ng_parity,&failures);if(image.memory)nova_host_unmap(&image);if(vimage.memory)nova_host_unmap(&vimage);if(compiled)nt_artifact_free(&a);if(vcompiled)nt_artifact_free(&b);for(unsigned i=0;i<21;i++)free(sources[i]);for(unsigned i=0;i<NG_PARITY_MODULES;i++)free(vsources[i]);printf("NTASM_NOVA_CALL_CONTRACTS checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
