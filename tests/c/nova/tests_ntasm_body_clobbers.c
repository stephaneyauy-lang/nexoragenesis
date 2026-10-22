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
   index, callable_names, register_widths, clobbers, body_clobbers.  Nothing measured that claim until the shared helper
   nova/ntasm_pipeline_parity.h ran every source of this file through the
   41 module validate image as well and compared the two verdicts.  The
   table beneath is the set of (this gate, the pipeline) divergence pairs
   this file exhibits, written down from that measurement: a pair that is
   not listed fails the gate, and a listed pair that stops occurring fails
   it too, so the table cannot rot into a comment. */
/* 335 body_clobbers(22) vs 332 body_effects(20), 8 cases ("mul memory 8/16/
   32/64 missing", "mul memory bool is the wide answer", "div memory 64 half
   declared", "idiv memory 64 half declared", "xchg memory second missing"):
   a memory-destination form whose read/write family bit is missing.  The
   entry answers the missing family bit itself (335); body_effects runs two
   stages earlier and refuses the same absent effect category with 332
   (instruction position, category 2 reads / 3 writes, missing bit). */
/* 335 body_clobbers(22) vs 334 body_intrinsics(21), 13 cases ("mul rax full
   mask", "mul al/ah is rax alone", "mul ax/eax adds rdx", "div ebx full
   mask", "div bl is rax alone", "idiv r12 full mask", "btc/btr/bts writes its
   first", "iretq", "popfq"): register destinations and privileged
   intrinsics.  These need intrinsic effect atoms and the bodies declare
   none, so body_intrinsics refuses 334 one stage before the entry's own
   family-bit answer 335 is reachable. */
/* 336 body_effects/body_clobbers/control_flow/call_contracts vs 334
   body_intrinsics(21), 2 cases ("mul literal refused", "swapgs refused"):
   the entry refuses the operand list itself with 336 (unknown / non-register
   destination, body_clobbers.nova:638); the pipeline is stopped earlier by
   the same missing intrinsic atoms on the same effects block, 334. */
static const NgParityPair ng_parity_pairs[]={{335,332},{335,334},{336,334}};
static NgParitySpec ng_parity={
  "body_clobbers",
  {"index","callable_names","register_widths","clobbers","body_clobbers"},5,
  1,
  ng_parity_pairs,(unsigned)(sizeof ng_parity_pairs/sizeof ng_parity_pairs[0]),
  0,0,0,0,0,0,0,0,NULL};
static char ng_parity_err[256];
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[4];}Run;static Run run(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");ng_parity_check(&checks,&failures,&ng_parity,n,s,r.returned);return r;}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t f,uint64_t l,uint64_t v){Run r=run(i,n,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=f||r.out[1]!=l||r.out[2]!=v||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t code,uint64_t bit){Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]==guard||r.out[1]==guard||(code==335&&(r.out[2]!=1||r.out[3]!=bit))){failures++;fprintf(stderr,"FAIL err %s ret=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run(i,n,s,words);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL invalid %s\n",n);}}
/* One based line and column of the nth occurrence of needle, derived from the
   source text alone, so every span case asserts the reported position without
   reading it back from the pass under test. */
static void where(const char*s,const char*needle,int nth,uint64_t*line,uint64_t*column){uint64_t ln=1,col=1;int seen=0;size_t n=strlen(needle);const char*p=s;if(nth<1)return;for(;;){if(*p=='\0')break;if(*p=='\n'){ln++;col=1;p++;continue;}if(strncmp(p,needle,n)==0&&(seen++==nth-1)){*line=ln;*column=col;return;}col++;p++;}}
/* Full four word position check at a needle. 335 writes the position, category
   1 and the missing family bit; 336 writes the position and leaves the last
   two words at zero. */
static void verr(const NovaHostImage*i,const char*n,const char*s,uint64_t code,const char*needle,int nth,uint64_t cat,uint64_t bit){uint64_t line=0,column=0;where(s,needle,nth,&line,&column);Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=cat||r.out[3]!=bit){failures++;fprintf(stderr,"FAIL span %s ret=%llu want %llu at %llu,%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)code,(unsigned long long)line,(unsigned long long)column,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* ================= the C parity oracle, asked directly ====================
   nt_x64_effects, declared x64.h:114 and defined x64.c:838, is the
   architectural footprint of one exact validated operand form. Its
   registers_read and registers_written are the GPR bitmask bits 0..15, with
   bit17 RFLAGS, bit18 GSBASE and bit19 FSBASE outside the sixteen families
   register_widths.family numbers, so the comparison this harness makes is
   registers_written & 0xffff. It is the function the C frontend itself calls
   at frontend.c:5464 and the conformance suite at conformance.c:138, so a case
   that asks it here is asking the reference the Nova tables were read out of,
   not a second transcription of them.
   ORACLE_NO is the sentinel for a form nt_x64_effects refuses. A refusal is an
   answer too: the three helpers below turn it into the expected 336.

   WHY THE 0xffff IS A PROJECTION AND NOT A BLIND SPOT, decided by measurement
   rather than asserted. Bit 17 is not a seventeenth register. x64.c:1069-1074
   ORs it into registers_written for every form that writes or leaves undefined
   a flag AND, in the same three lines, sets NT_X64_EFFECT_CHANGES_FLAGS: the
   oracle publishes the flags channel twice, once as a register bit and once
   as an effect. The product carries that channel as the effects atom
   changes_flags, numbered bit 1 by effects.nova:78, and body_intrinsics.nova
   demands it -- refused 334 with the missing atom bitset. So masking here
   drops a duplicate encoding of an obligation the tree does enforce, not an
   unchecked one.

   The claim is a measurement and it lives where it can fail: the A4-FLAGS
   sweep in tests_ntasm_body_intrinsics.c asks nt_x64_effects and
   body_intrinsics about the same form for every branch of the x64.c effects
   chain that can set a flag, prints both charges, and FAILS on any form the
   oracle flags and the product does not demand. It reports
   oracle_bit17=31 product_demands_changes_flags=31 blind_spots=0
   over_approximations=0 over 45 forms. That instrument was shown able to
   fire: deleting the single neg row from a COPY of body_intrinsics.nova turns
   exactly that one form BLIND and moves blind_spots to 1. A negative that was
   never made to fire is not a negative, so that control is part of the result
   rather than an aside.

   WHAT THE MASK STILL DOES NOT COVER, stated because a reader of this file
   would otherwise assume it does. Bits 18 GSBASE and 19 FSBASE are not
   guarded by any effect atom: swapgs publishes registers_written 0x40000 and
   the sweep confirms body_intrinsics demands control and privileged for it,
   but no atom names GSBASE, so the bit itself has no channel anywhere. The
   0xffff mask is correct for bit 17 and is silent about 18 and 19, and this
   comment is where that is said. */
#define ORACLE_NO UINT64_C(0x8000000000000000)
static const NtX64Context ORACLE_CTX={NT_X64_ALL_FEATURES,0};
static NtX64Operand orx_reg(unsigned r,unsigned w){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_REG;o.reg=r;o.width=w;return o;}
static NtX64Operand orx_high8(unsigned r){NtX64Operand o=orx_reg(r,8);o.high8=1;return o;}
static NtX64Operand orx_mem(unsigned w){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_MEM;o.width=w;o.base=5;o.index=-1;o.scale=1;return o;}
static NtX64Operand orx_imm(uint64_t v){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_IMM;o.imm=v;return o;}
static NtX64Operand orx_rel(void){NtX64Operand o=orx_imm(4);o.kind=NT_X64_REL;o.is_signed=1;return o;}
static NtX64Operand orx_cr(unsigned r){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_CR;o.reg=r;o.width=64;return o;}
static uint64_t orx(const char*m,const NtX64Operand*o,unsigned n){NtX64Effects e;memset(&e,0,sizeof e);if(nt_x64_effects(m,o,n,ORACLE_CTX,&e)!=NT_X64_OK)return ORACLE_NO;return e.registers_written&UINT64_C(0xffff);}
/* One case, read as: the fixture body spells this instruction over this operand
   list, and the fixture clobbers set pays exactly this family bitset. The
   expected required bitset, the expected missing bitset and the expected
   charged-write count are all computed from orx(), so no answer is written in
   this file. */
typedef struct{const char*name;const NtX64Operand*ops;unsigned count;uint64_t declared;}Ask;
/* The operand lists live in compound literals, so each case states the exact
   x86-64 form the fixture spells next to the fixture itself. */
#define ASK0(nm,dec) ((Ask){nm,NULL,0,dec})
#define ASK1(nm,a1,dec) ((Ask){nm,(const NtX64Operand[]){a1},1,dec})
#define ASK2(nm,a1,a2,dec) ((Ask){nm,(const NtX64Operand[]){a1,a2},2,dec})
/* 335 without a position: only the reported missing family bitset matters, and
   it is required & ~declared with required coming from nt_x64_effects. */
static void errF(const NovaHostImage*i,const char*n,const char*s,Ask a){uint64_t required=orx(a.name,a.ops,a.count),missing=ORACLE_NO;if(required!=ORACLE_NO)missing=required&(required^(a.declared));Run r=run(i,n,s,4);cases++;checks++;if(missing==ORACLE_NO||r.returned!=335||r.runtime||r.out[0]==guard||r.out[1]==guard||r.out[2]!=1||r.out[3]!=missing){failures++;fprintf(stderr,"FAIL err %s ret=%llu want missing=%llu (oracle=%llx) out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)missing,(unsigned long long)required,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* 335 with a position: the position still comes from where() over the source
   text, exactly as before, and only the bitset comes from the oracle. */
static void verrF(const NovaHostImage*i,const char*n,const char*s,uint64_t code,const char*needle,int nth,Ask a){uint64_t line=0,column=0,required=orx(a.name,a.ops,a.count),missing=ORACLE_NO;where(s,needle,nth,&line,&column);if(required!=ORACLE_NO)missing=required&(required^(a.declared));Run r=run(i,n,s,4);cases++;checks++;if(missing==ORACLE_NO||r.returned!=code||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=1||r.out[3]!=missing){failures++;fprintf(stderr,"FAIL span %s ret=%llu want %llu missing=%llu (oracle=%llx) at %llu,%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)code,(unsigned long long)missing,(unsigned long long)required,(unsigned long long)line,(unsigned long long)column,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* A refusal: the expected code is that nt_x64_effects itself refuses the very
   operand list, so 336 is the oracle verdict relayed and not a literal. A form
   the oracle admits can never make this case pass. */
static void refuseF(const NovaHostImage*i,const char*n,const char*s,const char*needle,int nth,Ask a){uint64_t line=0,column=0;where(s,needle,nth,&line,&column);NtX64Effects e;memset(&e,0,sizeof e);int refused=nt_x64_effects(a.name,a.ops,a.count,ORACLE_CTX,&e)!=NT_X64_OK;Run r=run(i,n,s,4);cases++;checks++;if(!refused||r.returned!=336||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]||r.out[3]){failures++;fprintf(stderr,"FAIL refuse %s ret=%llu oracle_refused=%d at %llu,%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,refused,(unsigned long long)line,(unsigned long long)column,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* Accepted bodies of one or more instructions: the pass must charge one write
   per instruction whose oracle mask is non zero, and verify exactly those whose
   declared set covers it. A table that charges nothing, or charges a family the
   declaration does not pay, fails on the case. */
static void okN(const NovaHostImage*i,const char*n,const char*s,const Ask*a,unsigned k){uint64_t writes=0,verified=0,bad=0;for(unsigned j=0;j<k;j++){uint64_t q=orx(a[j].name,a[j].ops,a[j].count);if(q==ORACLE_NO){bad=1;break;}if(q==0)continue;writes++;if((q&a[j].declared)==q)verified++;}Run r=run(i,n,s,4);cases++;checks++;if(bad||r.returned||r.runtime||r.out[0]!=1||r.out[1]!=writes||r.out[2]!=verified||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu want 1,%llu,%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)writes,(unsigned long long)verified,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* One instruction body over a named clobbers set, the shape every case of the
   closed form table needs. The effect set is empty on purpose: this entry does
   not run body_intrinsics, so a form that carries changes_flags, mul and div
   among them, is asked here only what it writes to a register. */
static char B[4096];
static const char*one(const char*clob,const char*body){snprintf(B,sizeof B,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {%s} {\n%s\nreturn 0\n}\n}\n",clob,body);return B;}
/* The same with a user pointer bound to rdi, for the memory operand forms. */
static const char*onep(const char*clob,const char*body){snprintf(B,sizeof B,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {%s} {\n%s\nreturn 0\n}\n}\n",clob,body);return B;}
/* And with a kernel pointer, which is the space the auditor's counterexample
   names. */
static const char*onek(const char*clob,const char*body){snprintf(B,sizeof B,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<kernel,u64> @rdi)->u64\neffects {}\nclobbers {%s} {\n%s\nreturn 0\n}\n}\n",clob,body);return B;}
/* The sixteen condition codes, in the order variable() lists them in
   compiler/c/ntasm/backend/x64.c, so a case names the same sixteen the encoder
   admits and no more. */
static const char*SETCC[16]={"sete","setne","setb","setae","setbe","seta","sets","setns","setp","setnp","setl","setge","setle","setg","seto","setno"};
static const char*CMOVCC[16]={"cmove","cmovne","cmovb","cmovae","cmovbe","cmova","cmovs","cmovns","cmovp","cmovnp","cmovl","cmovge","cmovle","cmovg","cmovo","cmovno"};
static const char*JCC[16]={"jo","jno","jb","jae","je","jne","jbe","ja","js","jns","jp","jnp","jl","jge","jle","jg"};
/* The sixteen register families, family 1 first, so a case can sweep the whole
   family numbering instead of naming the four the closed table happens to use. */
static const char*FAM[16]={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
/* A measured divergence, not a comment. The gate prints the mask the oracle
   publishes beside the mask this pass charges, so the gap is a number in the
   log instead of a claim in a source comment. It counts as one check and it
   cannot make the gate pass or fail. */
static unsigned gaps;
static void oracle_gap(const char*form,uint64_t mask,uint64_t nova){
  gaps++;
  fprintf(stderr,"ORACLE-DIVERGENCE form=%s oracle_registers_written=0x%04llx nova_charges=0x%04llx\n",
    form,(unsigned long long)mask,(unsigned long long)nova);}
/* The whole x64.c:942 member, asked of nt_x64_effects and of this pass over the
   same one instruction body, and the two answers compared to each other at
   execution time rather than against a literal written in this file.

   required is the oracle mask for that exact form. Over a clobbers {} body the
   pass must report exactly that mask as missing, so the two agree bit for bit
   and not only on the stack family. Then the same form is put behind a clobbers
   set spelling exactly the families required names, built here from FAM, and
   must verify: the charge has to be payable, not merely computed. That second
   half is what makes a charge of 1<<4 for a form the oracle publishes a real
   obligation rather than a refusal nothing can pay.

   reachable 0 is the form the grammar cannot spell as the single kind 32
   instruction of a body, which was return and call: the parser reads them
   as keywords and gives them their own node kinds 29 and 28
   (parser.nova:362-368 and :370-374), so the kind 32 walk never reached
   them. They are no longer unreachable and no longer unasserted: they have
   their own arm in the walk, reached on those node kinds, and statementC
   below measures what that arm decides. */
static char DECLARED[192];
static const char*declared_for(uint64_t mask){
  size_t n=0;DECLARED[0]=0;
  for(unsigned k=0;k<16;k++)if(mask&(UINT64_C(1)<<k))
    n+=(size_t)snprintf(DECLARED+n,sizeof DECLARED-n,"%s%s",n?",":"",FAM[k]);
  return DECLARED;}
/* The statement-level decision for the two forms the kind 32 walk could not
   reach, and it is a decision rather than a gap.

   required is the oracle mask, which is 1<<4 for both: x64.c:942-944 gives
   the whole member that one registers_written. What the pass must NOT do is
   turn it into a clobbers obligation, because 8.2 makes a write an obligation
   only when the entry value is not restored at the boundary, and these two
   statements are the pair that restores it: a call pushes the return address
   and the callee's return pops that same eight bytes, and a return pops the
   eight bytes this function's own caller pushed. The boundary value of rsp
   is the value the caller left.

   So the case asserts the DIRECTION and not a number: the pass accepts a
   body whose only stack family writer is its own return or its own call,
   declaring nothing, and it accepts it with a clobbers {} set. The oracle
   mask is printed beside it so the gap between 1<<4 published and 0x0000
   charged is a measured number in the log and never a silent widening.

   The negative is what makes this a gate and not a comment. Every case in
   this file whose body is built by one() already ends in a return 0
   statement, so a walk that charged the statement form would move writes on
   every one of them; statementC asserts 0,0,0 for a body that holds nothing
   but the statement, and a charge would make it 335. */
static void statementC(const NovaHostImage*i,const char*n,const char*form,Ask a,const char*body){
  uint64_t required=orx(a.name,a.ops,a.count);
  if(required==ORACLE_NO){cases++;checks++;
    failures++;fprintf(stderr,"FAIL member %s the oracle refuses the operand list\n",form);return;}
  char s[1024];
  snprintf(s,sizeof s,"module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn g()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n"
    "fn f()->u64\neffects {}\nclobbers {} {\n%s\n}\n}\n",body);
  Run r=run(i,n,s,4);cases++;checks++;
  /* Two functions in the fixture, the callee g and the body under test, and
     both words of the count are zero: the statement wrote no family that any
     clobbers set has to pay. A charge would make this 335 and move writes. */
  if(r.returned||r.runtime||r.out[0]!=2||r.out[1]||r.out[2]||r.out[3]){
    failures++;
    fprintf(stderr,"FAIL member %s form=%s ret=%llu oracle=0x%04llx nova_charges=0x%04llx out=%llu,%llu,%llu,%llu\n",
      form,form,(unsigned long long)r.returned,(unsigned long long)required,
      (unsigned long long)0,(unsigned long long)r.out[0],(unsigned long long)r.out[1],
      (unsigned long long)r.out[2],(unsigned long long)r.out[3]);
    return;}
  printf("MEMBER-STATEMENT form=%-8s oracle_registers_written=0x%04llx nova_charges=0x%04llx agree=1 reason=abi-restores-rsp-at-the-boundary\n",
    form,(unsigned long long)required,(unsigned long long)0);}
static void memberC(const NovaHostImage*i,const char*form,Ask a,int reachable){
  uint64_t required=orx(a.name,a.ops,a.count);
  if(required==ORACLE_NO){cases++;checks++;
    failures++;fprintf(stderr,"FAIL member %s the oracle refuses the operand list\n",form);return;}
  if(reachable==0){
    cases++;checks++;
    failures++;fprintf(stderr,"FAIL member %s reachable=0 but the walk now reaches statements\n",form);
    return;}
  Run r=run(i,form,one("",form),4);cases++;checks++;
  uint64_t reported=r.returned==335?r.out[3]:(r.returned==0?0:ORACLE_NO);
  if(reported!=required){
    failures++;
    fprintf(stderr,"FAIL member %s form=%s ret=%llu oracle=0x%04llx nova_charges=0x%04llx\n",
      form,form,(unsigned long long)r.returned,(unsigned long long)required,(unsigned long long)reported);
    oracle_gap(form,required,reported);
    return;}
  Ask paid=a;paid.declared=required;
  okN(i,form,one(declared_for(required),form),(const Ask[]){paid},1);}
int main(void){const char*paths[]={"tests/nova/tests/body-clobbers-entry.nova","compiler/nova/analysis/abi/body_clobbers.nova","compiler/nova/analysis/abi/abi.nova","compiler/nova/analysis/abi/clobbers.nova","compiler/nova/analysis/types/register_widths.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[10]={0};NtFInput inputs[10];for(unsigned i=0;i<10;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<10;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,10,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");int parity=ng_parity_begin(&ng_parity,&failures,ng_parity_err,sizeof ng_parity_err);if(image.memory&&parity==0){
  ok(&image,"high-byte family write","module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nmov ah,1\nreturn 0\n}\n}\n",1,1,1);
  ok(&image,"OUT is a declared output","module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(out x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nmov rcx,7\nreturn 0\n}\n}\n",1,1,1);
  ok(&image,"INOUT is a declared output","module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(inout x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nmov rcx,7\nreturn 0\n}\n}\n",1,1,1);
 const char*none="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"none",none,1,0,0);
 const char*rax="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {rax} {\nload rax,[p]:ptr<user,u64>\nreturn rax\n}\n}\n";okN(&image,"rax",rax,(const Ask[]){ASK2("load",orx_reg(0,64),orx_mem(64),1)},1);
 const char*alias="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {eax} {\nload rax,[p]:ptr<user,u64>\nreturn rax\n}\n}\n";okN(&image,"alias",alias,(const Ask[]){ASK2("load",orx_reg(0,64),orx_mem(64),1)},1);
 const char*missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {} {\nload rax,[p]:ptr<user,u64>\nreturn rax\n}\n}\n";errF(&image,"missing",missing,ASK2("load",orx_reg(0,64),orx_mem(64),0));
 const char*r10="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {r10d} {\nload r10,[p]:ptr<user,u64>\nreturn r10\n}\n}\n";okN(&image,"r10",r10,(const Ask[]){ASK2("load",orx_reg(10,64),orx_mem(64),1024)},1);
 const char*unknown="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {} {\nload foo,[p]:ptr<user,u64>\nreturn 0\n}\n}\n";err(&image,"unknown",unknown,336,0);
 const char*store="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi,in v:u64 @rax)->u64\neffects {writes_mem(user)}\nclobbers {} {\nstore [p]:ptr<user,u64>,rax\nreturn 0\n}\n}\n";okN(&image,"store ignored",store,(const Ask[]){ASK2("store",orx_mem(64),orx_reg(0,64),0)},1);
 const char*separate="module m\ntarget x86_64-nexora-none\nsection .text {\nfn a(in p:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {rax} {\nload rax,[p]:ptr<user,u64>\nreturn rax\n}\nfn b(in p:ptr<kernel,u64> @rdi)->u64\neffects {reads_mem(kernel)}\nclobbers {rdx} {\nload rdx,[p]:ptr<kernel,u64>\nreturn rdx\n}\n}\n";ok(&image,"separate",separate,2,2,2);
 const char*rdtsc="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_clock}\nclobbers {rax,rdx} {\nrdtsc\nreturn 0\n}\n}\n";okN(&image,"rdtsc",rdtsc,(const Ask[]){ASK0("rdtsc",5)},1);
 const char*rdtsc_missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_clock}\nclobbers {rax} {\nrdtsc\nreturn 0\n}\n}\n";errF(&image,"rdtsc missing",rdtsc_missing,ASK0("rdtsc",1));
 const char*cpuid="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {eax,ebx,ecx,edx} {\ncpuid\nreturn 0\n}\n}\n";okN(&image,"cpuid",cpuid,(const Ask[]){ASK0("cpuid",15)},1);
 const char*syscall="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {control,changes_flags}\nclobbers {rcx,r11} {\nsyscall\nreturn 0\n}\n}\n";okN(&image,"syscall",syscall,(const Ask[]){ASK0("syscall",2|2048)},1);
 const char*syscall_missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {control,changes_flags}\nclobbers {rcx} {\nsyscall\nreturn 0\n}\n}\n";errF(&image,"syscall missing",syscall_missing,ASK0("syscall",2));
 const char*iret="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {privileged,changes_flags,control,no_return}\nclobbers {rsp} {\niretq\n}\n}\n";okN(&image,"iret",iret,(const Ask[]){ASK0("iretq",16)},1);
 const char*mov="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rbx)->u64\neffects {}\nclobbers {eax} {\nmov rax,rbx\nreturn rax\n}\n}\n";okN(&image,"mov",mov,(const Ask[]){ASK2("mov",orx_reg(0,64),orx_reg(3,64),1)},1);
 const char*mov_missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rbx)->u64\neffects {}\nclobbers {} {\nmov rax,rbx\nreturn rax\n}\n}\n";errF(&image,"mov missing",mov_missing,ASK2("mov",orx_reg(0,64),orx_reg(3,64),0));
 const char*add="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rax)->u64\neffects {changes_flags}\nclobbers {r10d} {\nadd r10,rax\nreturn r10\n}\n}\n";okN(&image,"add",add,(const Ask[]){ASK2("add",orx_reg(10,64),orx_reg(0,64),1024)},1);
 const char*compare="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rax,in y:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {} {\ncmp rax,rbx\nreturn 0\n}\n}\n";okN(&image,"cmp ignored",compare,(const Ask[]){ASK2("cmp",orx_reg(0,64),orx_reg(3,64),0)},1);
 const char*xchg="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rax,in y:u64 @rcx)->u64\neffects {}\nclobbers {eax,ecx} {\nxchg rax,rcx\nreturn rax\n}\n}\n";okN(&image,"xchg",xchg,(const Ask[]){ASK2("xchg",orx_reg(0,64),orx_reg(1,64),3)},1);
 const char*xchg_missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rax,in y:u64 @rcx)->u64\neffects {}\nclobbers {rax} {\nxchg rax,rcx\nreturn rax\n}\n}\n";errF(&image,"xchg missing",xchg_missing,ASK2("xchg",orx_reg(0,64),orx_reg(1,64),1));
 // A label definition shares node kind 32 with an instruction but carries
 // aux 1, so a label named like a fixed intrinsic declares no write.
 const char*rdtsc_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nrdtsc:\nreturn 0\n}\n}\n";ok(&image,"rdtsc label",rdtsc_label,1,0,0);
 const char*load_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {} {\nload:\nreturn 0\n}\n}\n";ok(&image,"load label",load_label,1,0,0);
 /* ---- align_stack, spec/ntasm/ntasm.md 10. The node is kind 45, not the kind 32
    an instruction carries, so a pass that only reads kind 32 charged it
    nothing: a body that displaces rsp declared clobbers {} was accepted.
    It writes the rsp family, which is family 5, so the missing bit is 16. */
 const char*align_missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {} {\nalign_stack 16\nreturn 0\n}\n}\n";verr(&image,"align_stack missing",align_missing,335,"align_stack",1,1,16);
 const char*align_eps="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {esp} {\nalign_stack 16\nreturn 0\n}\n}\n";ok(&image,"align_stack esp alias",align_eps,1,1,1);
 const char*align_declared="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nreturn 0\n}\n}\n";ok(&image,"align_stack declared",align_declared,1,2,2);
 /* pop rsp is the compensation section 17.4 could not name, because push, pop
    and leave were absent from the frozen footprint table. Three charged
    writes: the load, the align_stack and the pop. */
 const char*align_pop="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npop rsp\nreturn 0\n}\n}\n";ok(&image,"align_stack pop rsp",align_pop,1,3,3);
 const char*align_mov="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nmov rsp,rbx\nreturn 0\n}\n}\n";ok(&image,"align_stack mov rsp",align_mov,1,3,3);
 /* A label definition shares node kind 32 with an instruction but carries
    aux 1. One next to an align_stack must move nothing, or the count above
    would be four. */
 const char*align_label_after="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nrestore:\nmov rsp,rbx\nreturn 0\n}\n}\n";ok(&image,"align_stack label after",align_label_after,1,3,3);
 const char*align_label_pop="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npop:\nmov rsp,rbx\nreturn 0\n}\n}\n";ok(&image,"align_stack label named pop",align_label_pop,1,3,3);
 const char*align_nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nif feature(sse2) {\nalign_stack 16\n} else {\nnop\n}\nreturn 0\n}\n}\n";verr(&image,"align_stack nested missing",align_nested,335,"align_stack",1,1,16);
 /* ---- push and pop, added to the 17.4 footprint table. The oracle reports
    registers_written 1<<4 for both, so the rsp family is charged whether or
    not the operand names it, and push reads its operand instead of writing
    it, so push rbx costs rsp and never rbx. */
  const char*push_missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\npush rbx\nreturn 0\n}\n}\n";verrF(&image,"push missing",push_missing,335,"push",1,ASK1("push",orx_reg(3,64),0));
  const char*push_declared="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp} {\npush rbx\nreturn 0\n}\n}\n";okN(&image,"push reads its operand",push_declared,(const Ask[]){ASK1("push",orx_reg(3,64),16)},1);
  const char*push_immediate="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp} {\npush 1\nreturn 0\n}\n}\n";okN(&image,"push immediate",push_immediate,(const Ask[]){ASK1("push",orx_imm(1),16)},1);
  const char*push_both="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp,rbx} {\npush rbx\npop rbx\nreturn 0\n}\n}\n";okN(&image,"push pop declared",push_both,(const Ask[]){ASK1("push",orx_reg(3,64),16|8),ASK1("pop",orx_reg(3,64),16|8)},2);
  /* pop writes its first operand as well as rsp, so the destination family is
     charged too, and family 4 rbx is bit 8. */
  const char*pop_dest_missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp} {\npop rbx\nreturn 0\n}\n}\n";verrF(&image,"pop destination missing",pop_dest_missing,335,"rbx",1,ASK1("pop",orx_reg(3,64),16));
  const char*pop_dest="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp,rbx} {\npop rbx\nreturn 0\n}\n}\n";okN(&image,"pop destination",pop_dest,(const Ask[]){ASK1("pop",orx_reg(3,64),16|8)},1);
  const char*pop_literal="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp} {\npop 1\nreturn 0\n}\n}\n";refuseF(&image,"pop literal refused",pop_literal,"pop",1,ASK1("pop",orx_imm(1),16));
  /* A memory destination is a body_effects space and not a register clobber,
     so it keeps the rsp family and must not be refused as a non register. */
  const char*pop_memory="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {writes_mem(user)}\nclobbers {rsp} {\npop [rdi]:ptr<user,u64>\nreturn 0\n}\n}\n";okN(&image,"pop memory",pop_memory,(const Ask[]){ASK1("pop",orx_mem(64),16)},1);
  const char*pop_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\npop:\nreturn 0\n}\n}\n";ok(&image,"pop label",pop_label,1,0,0);
  /* ---- leave is a pseudo-op the grammar admits, because any NAME statement
     becomes node kind 32, but the encoder has no leave and no enter, so no
     byte for byte oracle exists for a footprint. It is refused, not charged
     nothing, and the refusal does not depend on what the clobbers set says.
     nt_x64_effects answers 401 UNKNOWN on both, so the 336 below is the
     oracle's own verdict relayed rather than a literal of this file. */
  const char*leave_declared="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp,rbp} {\nleave\nreturn 0\n}\n}\n";refuseF(&image,"leave refused",leave_declared,"leave",1,ASK0("leave",0));
  const char*leave_empty="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nleave\nreturn 0\n}\n}\n";refuseF(&image,"leave refused empty",leave_empty,"leave",1,ASK0("leave",0));
   const char*leave_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nleave:\nreturn 0\n}\n}\n";ok(&image,"leave label",leave_label,1,0,0);
   /* ================= the closed 17.4 write table, derived from the oracle ===
      Every case below is one instruction in a body whose clobbers set is named
      in the case, so the required bitset the oracle publishes and the set the
      source declares can be compared one family bit at a time. No expected
      number is written here any more: each case hands nt_x64_effects the exact
      operand list the fixture spells, and the missing bitset is
      (oracle & ~declared) with the declared set being the fixture's own
      clobbers set. The family numbering of register_widths.family is the
      oracle GPR numbering, family 1 rax is bit 0, family 5 rsp is bit 4,
      family 11 r10 is bit 10 and family 16 r15 is bit 15, so the two masks are
      the same value and are compared directly. */
   /* ---- mul, div and idiv, the accumulator pair. x64.c:927 reads the operand
      and never writes it, then publishes registers_written |= 1u when the
      operand width is 8 and 5u, rax with rdx, at every other width. The
      auditor's counterexample is the first case: before the table was derived
      from the oracle, mul of a memory operand with clobbers {} was accepted. */
   verrF(&image,"mul memory 64 missing",onek("","mul [p]:ptr<kernel,u64>"),335,"[p]",1,ASK1("mul",orx_mem(64),0));
   verrF(&image,"mul memory 8 missing",onek("","mul [p]:ptr<kernel,u8>"),335,"[p]",1,ASK1("mul",orx_mem(8),0));
   verrF(&image,"mul memory 16 missing",onek("","mul [p]:ptr<kernel,u16>"),335,"[p]",1,ASK1("mul",orx_mem(16),0));
   verrF(&image,"mul memory 32 missing",onek("","mul [p]:ptr<kernel,u32>"),335,"[p]",1,ASK1("mul",orx_mem(32),0));
   /* bool names no width the oracle can be handed, and the module's own rule
      is "a width it does not state takes the wider of the two answers", so the
      query uses 64, the wide direction that rule names. */
   verrF(&image,"mul memory bool is the wide answer",onek("","mul [p]:ptr<kernel,bool>"),335,"[p]",1,ASK1("mul",orx_mem(64),0));
   verrF(&image,"div memory 64 half declared",onek("rax","div [p]:ptr<kernel,u64>"),335,"[p]",1,ASK1("div",orx_mem(64),1));
   verrF(&image,"idiv memory 64 half declared",onek("rdx","idiv [p]:ptr<kernel,u64>"),335,"[p]",1,ASK1("idiv",orx_mem(64),4));
   okN(&image,"div memory 64 declared",onek("rax,rdx","div [p]:ptr<kernel,u64>"),(const Ask[]){ASK1("div",orx_mem(64),5)},1);
   okN(&image,"idiv memory 64 declared",onek("rax,rdx","idiv [p]:ptr<kernel,u64>"),(const Ask[]){ASK1("idiv",orx_mem(64),5)},1);
   /* The same width rule on a register source, where the width comes from the
      register spelling: al and ah are 8, ax is 16, eax is 32, rax is 64. */
   verrF(&image,"mul al is rax alone",one("","mul al"),335,"al",1,ASK1("mul",orx_reg(0,8),0));
   okN(&image,"mul al declared",one("rax","mul al"),(const Ask[]){ASK1("mul",orx_reg(0,8),1)},1);
   verrF(&image,"mul ah is rax alone",one("","mul ah"),335,"ah",1,ASK1("mul",orx_high8(0),0));
   /* The needle is the second occurrence: the first ax of this source is the
      one inside the rax of the clobbers set on line 6. */
   verrF(&image,"mul ax adds rdx",one("rax","mul ax"),335,"ax",2,ASK1("mul",orx_reg(0,16),1));
   verrF(&image,"mul eax adds rdx",one("rax","mul eax"),335,"eax",1,ASK1("mul",orx_reg(0,32),1));
   verrF(&image,"mul rax full mask",one("","mul rax"),335,"rax",1,ASK1("mul",orx_reg(0,64),0));
   okN(&image,"mul rax declared",one("rax,rdx","mul rax"),(const Ask[]){ASK1("mul",orx_reg(0,64),5)},1);
   verrF(&image,"div bl is rax alone",one("","div bl"),335,"bl",1,ASK1("div",orx_reg(1,8),0));
   verrF(&image,"div ebx full mask",one("","div ebx"),335,"ebx",1,ASK1("div",orx_reg(3,32),0));
   verrF(&image,"idiv r12 full mask",one("","idiv r12"),335,"r12",1,ASK1("idiv",orx_reg(12,64),0));
   okN(&image,"idiv r10 alias declared",one("eax,edx","idiv r10d"),(const Ask[]){ASK1("idiv",orx_reg(10,32),1|4)},1);
   /* The operand of the group is a source, so a literal is refused the way
      writes_first refuses a destination that is not a register, and a form with
      no operand at all is the transactional 800. The refusal is the oracle's:
      nt_x64_effects answers 409 FORM on pop/mul with an immediate operand. */
   refuseF(&image,"mul literal refused",one("","mul 5"),"mul",1,ASK1("mul",orx_imm(5),0));
   bad(&image,"mul without an operand",one("","mul"),4);
   /* ---- the sixteen setcc, x64.c:968 write_operand on their byte operand. */
   for(unsigned k=0;k<16;k++){char b[32];snprintf(b,sizeof b,"%s al",SETCC[k]);
     errF(&image,SETCC[k],one("",b),ASK1(SETCC[k],orx_reg(0,8),0));}
   /* The accepted half of the same loop: a body that declares exactly the family
      the oracle charges must be verified, so the setcc row cannot be satisfied
      by charging nothing. */
   for(unsigned k=0;k<16;k++){char b[32];snprintf(b,sizeof b,"%s al",SETCC[k]);
     okN(&image,SETCC[k],one("rax",b),(const Ask[]){ASK1(SETCC[k],orx_reg(0,8),1)},1);}
   okN(&image,"sete al declared",one("rax","sete al"),(const Ask[]){ASK1("sete",orx_reg(0,8),1)},1);
   verrF(&image,"setne cl is rcx",one("",  "setne cl"),335,"cl",2,ASK1("setne",orx_reg(1,8),0));
   verrF(&image,"setb r10b is r10",one("","setb r10b"),335,"r10b",1,ASK1("setb",orx_reg(10,8),0));
   verrF(&image,"setg r15b is r15",one("","setg r15b"),335,"r15b",1,ASK1("setg",orx_reg(15,8),0));
   /* ah is a known 8 bit width but register_widths.family has no high8 row, so
      a writes_first form naming one cannot name a family to charge. That is a
      gap of register_widths, which this lot does not own, and every
      writes_first row has always answered 336 for it. The oracle disagrees
      here: nt_x64_effects answers OK and publishes registers_written 1, so the
      336 is a Nova-side policy and stays a literal. RESIDUAL: a high8
      destination is charged nothing anywhere. */
   verr(&image,"sete high8 needs its family clobber",one("","sete ah"),335,"ah",1,1,1);
   okN(&image,"sete al declared",one("rax","sete al"),(const Ask[]){ASK1("sete",orx_reg(0,8),1)},1);
   /* A memory destination is a body_effects space and not a register, so it
      costs no family and must not be refused as a non register either. */
   okN(&image,"sete memory",onep("","sete [p]:ptr<user,u8>"),(const Ask[]){ASK1("sete",orx_mem(8),0)},1);
   /* ---- the sixteen cmovcc, x64.c:971 read both operands and write the
      first. Before the table was derived from the oracle every one of them was
      accepted with clobbers {}. */
   for(unsigned k=0;k<16;k++){char b[32];snprintf(b,sizeof b,"%s rax,rbx",CMOVCC[k]);
     errF(&image,CMOVCC[k],one("",b),ASK2(CMOVCC[k],orx_reg(0,64),orx_reg(3,64),0));}
   for(unsigned k=0;k<16;k++){char b[32];snprintf(b,sizeof b,"%s rax,rbx",CMOVCC[k]);
     okN(&image,CMOVCC[k],one("eax",b),(const Ask[]){ASK2(CMOVCC[k],orx_reg(0,64),orx_reg(3,64),1)},1);}
   okN(&image,"cmovne rax declared",one("eax","cmovne rax,rbx"),(const Ask[]){ASK2("cmovne",orx_reg(0,64),orx_reg(3,64),1)},1);
   verrF(&image,"cmove rbx is rbx",one("","cmove rbx,rax"),335,"rbx",1,ASK2("cmove",orx_reg(3,64),orx_reg(0,64),0));
   verrF(&image,"cmovg r12 is r12",one("","cmovg r12,rax"),335,"r12",1,ASK2("cmovg",orx_reg(12,64),orx_reg(0,64),0));
   /* cmovcc is the one new row that can name the stack family, so the frozen
      rsp overlap of the two 17.4 tables has to be stated rather than assumed. */
   okN(&image,"cmovl rsp declared",one("rsp","cmovl rsp,rbx"),(const Ask[]){ASK2("cmovl",orx_reg(4,64),orx_reg(3,64),16)},1);
   verrF(&image,"cmovl rsp missing",one("","cmovl rsp,rbx"),335,"rsp",1,ASK2("cmovl",orx_reg(4,64),orx_reg(3,64),0));
   /* A memory destination here is a form nt_x64_effects refuses (409), because
      x64.c:556 requires a register in the first position of a cmovcc, while
      body_clobbers charges no family for it and body_effects refuses the same
      body with 336. Nothing here is derivable from the oracle, so the literal
      stays. RESIDUAL: the two halves disagree on a form neither can encode. */
   ok(&image,"cmove memory",onep("","cmove [p]:ptr<user,u64>,rbx"),1,0,0);
   /* ---- xchg both directions, checked against x64.c:994, which writes both
      operands. The first-operand-missing case is the pre-existing one. */
   /* The blamed position is the first operand, which is where the table takes
      the family of both, and the missing bit is what the second operand adds. */
   verrF(&image,"xchg second only missing",one("rbx","xchg rbx,rax"),335,"rbx",2,ASK2("xchg",orx_reg(3,64),orx_reg(0,64),8));
   verrF(&image,"xchg first only missing",one("rbx","xchg rax,rbx"),335,"rax",1,ASK2("xchg",orx_reg(0,64),orx_reg(3,64),8));
   verrF(&image,"xchg both missing",one("","xchg rax,rbx"),335,"rax",1,ASK2("xchg",orx_reg(0,64),orx_reg(3,64),0));
   okN(&image,"xchg both declared",one("rax,rbx","xchg rax,rbx"),(const Ask[]){ASK2("xchg",orx_reg(0,64),orx_reg(3,64),1|8)},1);
   /* xchg rax,eax spells two widths for one family and nt_x64_effects refuses it
      with 403 WIDTH, so the query asks the width matched form: the family of
      rax and the family of eax are both family 1 and the charge is the same. */
   okN(&image,"xchg same family",one("rax","xchg rax,eax"),(const Ask[]){ASK2("xchg",orx_reg(0,64),orx_reg(0,64),1)},1);
   /* A memory second operand is the read modify write the oracle charges, and
      it costs no register, so only the first operand is required. */
   okN(&image,"xchg memory second",onep("rax","xchg rax,[p]:ptr<user,u64>"),(const Ask[]){ASK2("xchg",orx_reg(0,64),orx_mem(64),1)},1);
   verrF(&image,"xchg memory second missing",onep("","xchg rax,[p]:ptr<user,u64>"),335,"rax",1,ASK2("xchg",orx_reg(0,64),orx_mem(64),0));
   /* ---- ltr. x64.c:1050 puts ltr in the descriptor member with sgdt and sidt
      and gives a write to those two only: the task register ltr loads is not one
      of the sixteen families, so no family is charged. The operand is a r16 and
      is read, never written. */
   okN(&image,"ltr r16",one("","ltr ax"),(const Ask[]){ASK1("ltr",orx_reg(1,16),0)},1);
   okN(&image,"ltr declared does not help",one("rax,rbx","ltr cx"),(const Ask[]){ASK1("ltr",orx_reg(1,16),1|8)},1);
   /* The memory form of ltr is left a literal. nt_x64_effects publishes no
      register write for ltr, so the register side agrees, but the query is not
      made: the descriptor member of x64.c:1050 is the one the body_effects
      side of the coupling disagrees about, and naming the reason here from a
      memory operand the same pass answers 336 for would mix the two questions.
      RESIDUAL: ltr with a memory operand is refused by body_effects while the
      oracle charges it a read; the refusal is the sound direction and the
      module's own comment misstates the reason. */
   ok(&image,"ltr memory",onep("","ltr [p]:ptr<user,u64>"),1,0,0);
  ok(&image,"ltr label",one("","ltr:\nreturn 0"),1,0,0);
  /* ---- bswap, x64.c:977 reads and writes its first operand. */
   verrF(&image,"bswap missing",one("","bswap eax"),335,"eax",1,ASK1("bswap",orx_reg(0,32),0));
   okN(&image,"bswap alias declared",one("eax","bswap rax"),(const Ask[]){ASK1("bswap",orx_reg(0,64),1)},1);
   verrF(&image,"bswap r10 missing",one("","bswap r10"),335,"r10",1,ASK1("bswap",orx_reg(10,64),0));
   /* x64.c:570 requires a register operand for bswap, so the oracle refuses a
      memory destination with 409 while body_clobbers charges it nothing. The
      literal stays. RESIDUAL: a form the encoder cannot emit is accepted for
      free here. */
   ok(&image,"bswap memory",onep("","bswap [p]:ptr<user,u64>"),1,0,0);
   /* ---- bt writes no register at all: x64.c:983 excludes it from the write
      and publishes flags_written CF instead, which body_intrinsics charges as
      the changes_flags atom and not as a family. The three bit setters are the
      contrast, and they were already in the table. */
   okN(&image,"bt register",one("","bt rax,rbx"),(const Ask[]){ASK2("bt",orx_reg(0,64),orx_reg(3,64),0)},1);
   okN(&image,"bt memory",onep("","bt [p]:ptr<user,u64>,3"),(const Ask[]){ASK2("bt",orx_mem(64),orx_imm(3),0)},1);
   okN(&image,"bt immediate",one("","bt rax,7"),(const Ask[]){ASK2("bt",orx_reg(0,64),orx_imm(7),0)},1);
   verrF(&image,"bts writes its first",one("","bts rax,rbx"),335,"rax",1,ASK2("bts",orx_reg(0,64),orx_reg(3,64),0));
   verrF(&image,"btr writes its first",one("","btr eax,7"),335,"eax",1,ASK2("btr",orx_reg(0,32),orx_imm(7),0));
   verrF(&image,"btc writes its first",one("","btc r12,rbx"),335,"r12",1,ASK2("btc",orx_reg(12,64),orx_reg(3,64),0));
   /* ---- the sign extend and widen forms, x64.c:941, which publish
      registers_written of 4, rdx, for cwd, cdq and cqo and of 1, rax, for cbw,
      cwde and cdqe, with no operand at all. */
   verrF(&image,"cdq writes rdx",one("","cdq"),335,"cdq",1,ASK0("cdq",0));
   verrF(&image,"cqo writes rdx",one("","cqo"),335,"cqo",1,ASK0("cqo",0));
   verrF(&image,"cwd writes rdx",one("","cwd"),335,"cwd",1,ASK0("cwd",0));
   okN(&image,"cdq declared",one("rdx","cdq"),(const Ask[]){ASK0("cdq",4)},1);
   verrF(&image,"cbw writes rax",one("","cbw"),335,"cbw",1,ASK0("cbw",0));
   verrF(&image,"cwde writes rax",one("","cwde"),335,"cwde",1,ASK0("cwde",0));
   verrF(&image,"cdqe writes rax",one("","cdqe"),335,"cdqe",1,ASK0("cdqe",0));
   okN(&image,"cwde alias declared",one("eax","cwde"),(const Ask[]){ASK0("cwde",1)},1);
   /* ---- the forms the oracle publishes as writing no register, each of which
      was accepted by silence before, because an absent row and a zero write
      read the same. */
   okN(&image,"nop",one("","nop"),(const Ask[]){ASK0("nop",0)},1);
   okN(&image,"pause",one("","pause"),(const Ask[]){ASK0("pause",0)},1);
   okN(&image,"ud2",one("","ud2"),(const Ask[]){ASK0("ud2",0)},1);
   okN(&image,"lfence",one("","lfence"),(const Ask[]){ASK0("lfence",0)},1);
   okN(&image,"mfence",one("","mfence"),(const Ask[]){ASK0("mfence",0)},1);
   okN(&image,"cli",one("","cli"),(const Ask[]){ASK0("cli",0)},1);
   okN(&image,"sti",one("","sti"),(const Ask[]){ASK0("sti",0)},1);
   okN(&image,"hlt",one("","hlt"),(const Ask[]){ASK0("hlt",0)},1);
   okN(&image,"sysretq",one("","sysretq"),(const Ask[]){ASK0("sysretq",0)},1);
   /* wrmsr reads rax, rdx and rcx and destroys none of them, x64.c:1020. */
   okN(&image,"wrmsr",one("","wrmsr"),(const Ask[]){ASK0("wrmsr",0)},1);
   /* x64.c:475 takes the control register first for write_cr and the GPR second,
      the reverse of read_cr, so the query hands the oracle that order. */
   okN(&image,"write_cr",one("","write_cr rax,cr0"),(const Ask[]){ASK2("write_cr",orx_cr(0),orx_reg(0,64),0)},1);
   okN(&image,"out",one("","out dx,al"),(const Ask[]){ASK2("out",orx_reg(2,16),orx_reg(0,8),0)},1);
   /* The register half of the x64.c:1050 descriptor group, asked of the oracle
      over the exact operand list each form is handed, at the width the encoder
      requires: lgdt and lidt take an 80 bit memory operand and ltr a 16 bit
      one. nt_x64_effects publishes registers_written 0 for all three, so the
      required bitset is 0 and the body is accepted with no clobber declared.
      This is the register claim only, and it is not the memory one: the oracle
      gives lgdt, lidt and ltr a memory READ and sgdt and sidt a memory write,
      which body_effects charges and this table does not. The comment above the
      row in body_clobbers.nova used to say the oracle gave these three "none",
      which was false about the memory side; these cases are what pin the half
      that is true. */
   okN(&image,"lgdt",onep("","lgdt [p]:ptr<user,u64>"),(const Ask[]){ASK1("lgdt",orx_mem(80),0)},1);
   okN(&image,"lidt",onep("","lidt [p]:ptr<user,u64>"),(const Ask[]){ASK1("lidt",orx_mem(80),0)},1);
   okN(&image,"ltr memory",onep("","ltr [p]:ptr<user,u64>"),(const Ask[]){ASK1("ltr",orx_mem(16),0)},1);
   okN(&image,"invlpg",onep("","invlpg [p]:ptr<user,u64>"),(const Ask[]){ASK1("invlpg",orx_mem(0),0)},1);
   okN(&image,"sgdt memory",onep("","sgdt [p]:ptr<user,u64>"),(const Ask[]){ASK1("sgdt",orx_mem(80),0)},1);
   for(unsigned k=0;k<16;k++){char b[32];snprintf(b,sizeof b,"%s done\ndone:",JCC[k]);
     okN(&image,JCC[k],one("",b),(const Ask[]){ASK1(JCC[k],orx_rel(),0)},1);}
   okN(&image,"jmp",one("","jmp done\ndone:"),(const Ask[]){ASK1("jmp",orx_rel(),0)},1);
   okN(&image,"cmp",one("","cmp rax,rbx"),(const Ask[]){ASK2("cmp",orx_reg(0,64),orx_reg(3,64),0)},1);
   okN(&image,"test",one("","test rax,rbx"),(const Ask[]){ASK2("test",orx_reg(3,64),orx_reg(1,64),0)},1);
   /* ---- The whole x64.c:942 member, asked of the oracle and of this pass over
        the same one instruction body. The oracle gives all seven the same
        1<<4 rsp write and this pass must charge it for every form the grammar
        can spell as the single kind 32 instruction of a body, so the
        comparison is made between the two answers at execution time and not
        against a literal written here: required is the oracle mask, reported
        is what this pass asks for over clobbers {}, and the second half of each
        case puts the same form behind a clobbers {rsp} and requires it to
        verify, so the charge is payable and not merely computed.

        return and call are members of the same oracle branch and are charged
        1<<4 there, but the parser reads them as keywords 33 and 34 and gives
        them node kinds 29 and 28, so no body ever holds either of them as a
        kind 32 instruction and this pass is never asked about them. They are
        put to the sweep with reachable 0, which prints the oracle mask and
        asserts nothing else: the row is unreachable from here, and saying so is
        the whole content of the case. ---- */
   memberC(&image,"push rbx",ASK1("push",orx_reg(3,64),0),1);
   memberC(&image,"pushfq",ASK0("pushfq",0),1);
   memberC(&image,"pop rbx",ASK1("pop",orx_reg(3,64),0),1);
   memberC(&image,"popfq",ASK0("popfq",0),1);
   memberC(&image,"ret",ASK0("ret",0),1);
  /* return and call are statements, node kinds 29 and 28, so the kind 32 walk
     never reached them and this pass was never asked about the write
     x64.c:942-944 publishes for both. They have their own arm now and the two
     cases below are what it decides: a body whose only stack family writer is
     its own return, and one whose only stack family writer is its own call,
     are both accepted over a clobbers {} set. The oracle mask is printed
     beside each so the distance between 1<<4 published and 0x0000 charged is
     a number in the log and never a silent widening. */
  statementC(&image,"return","return",ASK0("return",0),"return 0");
  statementC(&image,"call","call",ASK1("call",orx_rel(),0),"call g()");
   memberC(&image,"iretq",ASK0("iretq",0),1);
   /* sysretq is the negative of the same question: the oracle publishes no GPR
      write for it at all (x64.c:1032-1036), so the pass must charge nothing. */
   memberC(&image,"sysretq",ASK0("sysretq",0),1);
  /* sysretq pins a DIRECTION and not a number, which is the whole content of
     the 8.3 reserve and the reason the literal must not be "fixed" here.

     The oracle publishes no GPR write for it at all (x64.c:1032-1036), so the
     pass charges nothing: the memberC case above asserts exactly that, with
     the expected bitset read from nt_x64_effects rather than written here, so
     it stays true if the oracle ever changes and fails if it does not.

     The direction is the part a number cannot carry. Section 8.3 authorises
     leaving sysretq out of the implicit set because that over-approximation
     costs a refusal, and forbids the opposite because it would invent a
     proof. So the two cases below assert the DIRECTION from both sides: a
     body whose only stack family writer is a sysretq is accepted, which is
     the invented-proof direction the spec forbids and which this pass must
     NOT do by charging; and a sysretq in a body that also writes rsp through
     an operand is still charged for that operand alone, which is the
     refusal direction the spec authorises and which this pass must keep
     doing. A change that made sysretq itself charge would fail the first; a
     change that made the pass charge nothing at all would fail the second. */
  ok(&image,"sysretq alone writes no family",one("","sysretq\nreturn 0"),1,0,0);
  okN(&image,"sysretq beside an rsp writer",one("rsp","sysretq\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0"),
      (const Ask[]){ASK0("sysretq",16),ASK2("load",orx_reg(4,64),orx_mem(64),16)},2);
   /* A label definition shares node kind 32 with an instruction and carries
      aux 1, so a label named after a member form is a branch target, writes
      nothing, and is never read as the form. */
   ok(&image,"pushfq label",one("","pushfq:\nreturn 0"),1,0,0);
   ok(&image,"popfq label",one("","popfq:\nreturn 0"),1,0,0);
   ok(&image,"ret label",one("","ret:\nreturn 0"),1,0,0);
   /* ---- the refusals the closed default produces. An unanchored form is a
      diagnostic and never silence, so a name outside the catalogue nt_x64_encode
      admits, and a name that is only a prefix of one, are both 336. Every one
      of those is now the oracle's own 401 UNKNOWN relayed. */
   /* swapgs is the exception: the oracle admits it and publishes
      registers_read = registers_written = 1<<18, the GS base, which
      register_widths.family has no row for. The two 336 below stay literals.
      RESIDUAL: the segment bases are outside every clobbers set, so charging
      swapgs is unpayable rather than unproved. */
   verr(&image,"swapgs refused",one("","swapgs"),336,"swapgs",1,0,0);
   verr(&image,"swapgs refused with clobbers",one("rax,rbx","swapgs"),336,"swapgs",1,0,0);
   ok(&image,"swapgs label",one("","swapgs:\nreturn 0"),1,0,0);
   refuseF(&image,"enter refused",one("","enter"),"enter",1,ASK0("enter",0));
   refuseF(&image,"enter refused with clobbers",one("rsp,rbp","enter"),"enter",1,ASK0("enter",0));
   refuseF(&image,"unknown mnemonic refused",one("","frobnicate rbx"),"frobnicate",1,ASK1("frobnicate",orx_reg(3,64),0));
   refuseF(&image,"unknown zero operand refused",one("","wobble"),"wobble",1,ASK0("wobble",0));
   refuseF(&image,"mul prefix is not mul",one("","mulg rbx"),"mulg",1,ASK1("mulg",orx_reg(3,64),0));
   refuseF(&image,"set prefix is not a setcc",one("","set rax"),"set",1,ASK1("set",orx_reg(0,64),0));
   refuseF(&image,"cmov prefix is not a cmovcc",one("","cmov rax,rbx"),"cmov",1,ASK2("cmov",orx_reg(0,64),orx_reg(3,64),0));
   refuseF(&image,"jz is not a jcc",one("","jz done\ndone:"),"jz",1,ASK1("jz",orx_rel(),0));
   /* A label definition is never read as an instruction, whichever row its
      name would have taken, so none of the new rows can be reached by one. A
      label has no operand form to hand the oracle, so these stay literals. */
   ok(&image,"mul label",one("","mul:\nreturn 0"),1,0,0);
   ok(&image,"sete label",one("","sete:\nreturn 0"),1,0,0);
   ok(&image,"cdq label",one("","cdq:\nreturn 0"),1,0,0);
   ok(&image,"bt label",one("","bt:\nreturn 0"),1,0,0);
   ok(&image,"ltr label with clobbers",one("rax","ltr:\nreturn 0"),1,0,0);
   /* ---- the sixteen register families, one case each, so the family
      numbering of register_widths.family is compared with the oracle GPR
      numbering sixteen times instead of being taken on trust from the four
      families the cases above happen to name. */
   for(unsigned k=0;k<16;k++){char b[32];snprintf(b,sizeof b,"mov %s,rbx",FAM[k]);
     errF(&image,FAM[k],one("",b),ASK2("mov",orx_reg(k,64),orx_reg(3,64),0));}
   /* ---- several forms in one body: each charged write is counted and each
      missing family is reported against the family the oracle names. */
   okN(&image,"mixed body",one("rax,rdx,rbx","mul rax\nsete bl\nbt rbx,rcx"),(const Ask[]){ASK1("mul",orx_reg(0,64),1|4|8),ASK1("sete",orx_reg(3,8),1|4|8),ASK2("bt",orx_reg(3,64),orx_reg(1,64),1|4|8)},3);
   /* The first form that cannot be paid stops the pass, so this reports mul and
      the rax of its operand, not the sete further down. The needle is the
      second rax of the source, the first being the one in the clobbers set. */
   verrF(&image,"mixed body missing",one("rax","mul rax\nsete bl\nbt rbx,rcx"),335,"rax",2,ASK1("mul",orx_reg(0,64),1));
   bad(&image,"short",none,3);bad(&image,"invalid","target x86_64-nexora-none\n",4);
}if(image.memory){ng_parity_finish(&ng_parity,&failures);nova_host_unmap(&image);}if(compiled)nt_artifact_free(&a);for(unsigned i=0;i<10;i++)free(sources[i]);printf("NTASM_NOVA_BODY_CLOBBERS checks=%u failures=%u cases=%u oracle_divergences=%u\n",checks,failures,cases,gaps);return failures?1:0;}
