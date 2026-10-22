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
   index, features, callable_names, register_widths, clobbers, effects, body_clobbers, control_flow, call_contracts.  Nothing measured that claim until the shared helper
   nova/ntasm_pipeline_parity.h ran every source of this file through the
   41 module validate image as well and compared the two verdicts.  The
   table beneath is the set of (this gate, the pipeline) divergence pairs
   this file exhibits, written down from that measurement: a pair that is
   not listed fails the gate, and a listed pair that stops occurring fails
   it too, so the table cannot rot into a comment. */
/* 364 control_flow(23) vs 334 body_intrinsics(21), 36 cases (the align_stack
   alignment, dead-code and "reason N" families): align_stack is kind 45 and
   requires the changes_flags atom (bit 2, body_intrinsics.nova:64-70), and
   these bodies declare only reads_mem(kernel)/no_return.  The pipeline
   refuses the undeclared intrinsic effects at stage 21; the entry, which
   links no intrinsics pass, goes on to its own stack-alignment refusal 364. */
/* 326 control_flow(23)+call_contracts(34) vs 334 body_intrinsics(21), 5
   cases ("align_stack call before", "align_stack 4 cannot prove 16",
   "align_stack fact dies at restore", "align_stack fact dies at pushfq",
   "align_stack fact dies at ret"): the entry cannot prove stack_aligned(16)
   at a call site and reports 326 family 4 predicate 4.  The same bodies trip
   body_intrinsics' missing-atom refusal first. */
/* 364 control_flow(23) vs 332 body_effects(20), 4 cases ("align_stack
   untyped", "align_stack never ud2", "align_stack sysretq", "align_stack
   never call"): these bodies understate `effects`, so body_effects refuses
   the missing read/write category with 332 two stages before the entry's
   364 is reachable. */
/* 340 pointer_spaces(18)+control_flow(23) vs 334 body_intrinsics(21), 4
   cases ("dead after sysretq", "dead after iretq", "sysretq inside target
   region", "iretq inside target region"): the entry reports 340, a statement
   fallthrough cannot reach; sysretq/iretq are privileged intrinsics whose
   atoms are undeclared, so the pipeline stops at 334 first. */
/* 326 control_flow(23)+call_contracts(34) vs 335 body_clobbers(22), 2 cases
   ("callee body displacement is read"): the entry proves 326 because the
   callee `sneaky` displaces rsp across the call.  The pipeline stops inside
   `sneaky` itself, where body_clobbers refuses the undeclared stack-family
   bit of its `push rbx` with 335. */
/* 336 body_effects/body_clobbers/control_flow/call_contracts vs 334
   body_intrinsics(21), 1 case ("align_stack leave beats reason 5"): the
   entry refuses `leave` as an unknown destination with 336; the pipeline is
   stopped earlier by the same missing intrinsic atoms, 334. */
/* The two {1,335} and {1,334} pairs this table first carried are GONE, and
   they are gone because a measurement said so rather than because a comment
   said so.  They came from mode 2, whose return value is this harness's own
   "the replacement witness and the footprint disagree" boolean and not a
   diagnostic code at all, and the helper proved it by refusing the pair as
   stale once the parity question was restricted to the verdict modes.  A gate
   may not assert a stage verdict it never asked a stage for. */
static const NgParityPair ng_parity_pairs[]={{364,334},{326,334},{364,332},
  {340,334},{326,335},{336,334}};
static NgParitySpec ng_parity={
  "control_flow",
  {"index","features","callable_names","register_widths","clobbers","effects","body_clobbers","control_flow","call_contracts"},9,
  1,
  ng_parity_pairs,(unsigned)(sizeof ng_parity_pairs/sizeof ng_parity_pairs[0]),
  0,0,0,0,0,0,0,0,NULL};
/* The per-call declaration, at the one place the mode is visible.
   ng_parity.stages is the LINK SET -- the stages the entry image carries --
   and it is what `prefix=no` and the declared-pair ledger are computed from.
   It is NOT what the B direction may be handed, and the difference is this
   table.  control-flow-entry.nova has five paths and they run different
   stages, so:

     mode 0  semantics.index(2), callable_names(6), control_flow(23) -- and
             nothing else, whatever the image links.  Its return value is
             control_flow's own verdict.
     mode 4  call_contracts.check(34) alone.  A stage verdict, of a stage the
             mode 0 set does not even contain.
     mode 1  body_clobbers.check(22) and control_flow.writes_stack(23).  NOT
             a stage verdict: the mode returns 0 when the two agree and 1
             when they do not, and it has SEEN a 335 and folded it into that
             boolean.  Comparing that 0 against a pipeline 335 would ask
             whether a boolean equals a diagnostic.
     mode 2  control_flow(23) only, and the same non-verdict shape over the
             displacement table.
     mode 3  no stage at all: it reports control_flow.abi_ceiling(), a
             constant.
     mode 5  control_flow(23) only, over the statement table, same
             non-verdict shape as mode 2.

   The first version of this harness handed the B direction the link set and
   restricted the whole check to modes 0 and 4.  That was wrong twice: it made
   36 rows unexamined, and the rows it did examine were checked against a set
   of stages the call never ran.  The link set is still here, for the A
   direction and for `prefix=`, and the banner says so. */
static NgParityCall ng_call_of(uint64_t mode) {
  NgParityCall c; memset(&c, 0, sizeof c);
  switch (mode) {
    case 0: c.stages[0]="index"; c.stages[1]="callable_names"; c.stages[2]="control_flow";
             c.stage_count=3; c.verdict=1; break;
    case 4: c.stages[0]="call_contracts"; c.stage_count=1; c.verdict=1; break;
    case 1: c.stages[0]="body_clobbers"; c.stages[1]="control_flow";
             c.stage_count=2; c.verdict=0; break;
    case 2: case 5: c.stages[0]="control_flow"; c.stage_count=1; c.verdict=0; break;
    default: break;
  }
  return c;
}
static char ng_parity_err[256];
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
/* mode 0 asks the verdict of control_flow.check on its own, the shape every
   verdict case of this file uses. mode 1 asks the footprint parity probe,
   which puts the one question spec/ntasm/ntasm.md 17.4 makes control_flow and
   body_clobbers share to both of them; the entry takes a third word for it
   because a buf<T> already crosses the boundary as two words. */
typedef struct{uint64_t returned,runtime,out[4];}Run;static Run run(const NovaHostImage*i,const char*n,const char*s,uint64_t words,uint64_t mode){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words,mode};r.returned=i->entry(&c,a,5);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");  { NgParityCall call=ng_call_of(mode);
    ng_parity_check_as(&checks,&failures,&ng_parity,n,s,r.returned,&call); }
  return r;}
/* ---- lot 24: WHAT IS STILL TRUE AT ONE CALL. mode 6 asks control_flow.facts,
 * which walks the caller's body up to a call and publishes one row per
 * localisation: out[0] the slot count, out[1+k] the effective family, out[2+k]
 * whether the fact still holds AT THE CALL.
 *
 * A ROW PER LOCALISATION, AND THE COUNT IS NOT A ROW. A single-slot caller puts
 * its count at out[0] and its liveness at out[2], so writing the liveness at
 * out[0] would make every dead fact read as "one slot" -- the same two
 * meanings on one word that this project's first harness died of, and the
 * reason the count is asserted separately from every liveness here.
 *
 * `run` above cannot be used: its Run carries FOUR words, and a two slot caller
 * needs six. So this has its own buffer and its own call, and it deliberately
 * does NOT go through the pipeline parity helper -- a query is not a stage
 * verdict, and asking the parity helper to compare one would invent a
 * divergence out of a question it was never built to ask.
 */
typedef struct{uint64_t returned,runtime,out[40];}FRun;
static FRun frun(const NovaHostImage*i,const char*s){
  FRun r;NovaContextV2 c={0};
  for(unsigned k=0;k<40;k++)r.out[k]=guard;
  CHECK(nova_context_init_v2(&c),"facts context init");
  uint64_t oh=nova_borrow_v2(&c,r.out,40*8,1);
  uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0);
  uint64_t a[]={sh,strlen(s),oh,40,6};
  r.returned=i->entry(&c,a,5);r.runtime=c.error;
  CHECK(nova_context_destroy_v2(&c),"facts context cleanup");
  return r;
}
/* One caller, one slot expected, one liveness expected. `family` is the
 * EFFECTIVE family, republished by the export so this never re-derives which
 * register the slot is. */
static void fact1(const NovaHostImage*i,const char*n,const char*s,
                  uint64_t family,uint64_t live){
  FRun r=frun(i,s);cases++;checks++;
  int bad=r.returned||r.runtime||r.out[0]!=1||r.out[1]!=family||r.out[2]!=live;
  if(bad){failures++;
    fprintf(stderr,"FAIL fact %s ret=%llu rt=%llu slots=%llu family=%llu live=%llu "
            "(want 1, %llu, %llu)\n",n,(unsigned long long)r.returned,
            (unsigned long long)r.runtime,(unsigned long long)r.out[0],
            (unsigned long long)r.out[1],(unsigned long long)r.out[2],
            (unsigned long long)family,(unsigned long long)live);}
}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t f,uint64_t t,uint64_t returns){Run r=run(i,n,s,4,0);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=f||r.out[1]!=t||r.out[2]!=returns||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t code,uint64_t reason){Run r=run(i,n,s,4,0);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]==guard||r.out[1]==guard||r.out[2]!=reason){failures++;fprintf(stderr,"FAIL err %s ret=%llu reason=%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[2]);}}
/* E340 must name the dead statement itself, not the function or the block. */
static void dead(const NovaHostImage*i,const char*n,const char*s,uint64_t line,uint64_t column,uint64_t reason){Run r=run(i,n,s,4,0);cases++;checks++;if(r.returned!=340||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=reason||r.out[3]){failures++;fprintf(stderr,"FAIL dead %s ret=%llu at %llu:%llu reason=%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2]);}}
static void bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run(i,n,s,words,0);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL invalid %s\n",n);}}
/* One based line and column of the nth occurrence of needle, derived from the
   source text alone, so every span case asserts the reported position without
   reading it back from the pass under test. */
static void where(const char*s,const char*needle,int nth,uint64_t*line,uint64_t*column){uint64_t ln=1,col=1;int seen=0;size_t n=strlen(needle);const char*p=s;if(nth<1)return;for(;;){if(*p=='\0')break;if(*p=='\n'){ln++;col=1;p++;continue;}if(strncmp(p,needle,n)==0&&(seen++==nth-1)){*line=ln;*column=col;return;}col++;p++;}}
/* Full four word position check at a needle: line,column,third,fourth. E364
   carries the align_stack obligation of spec/ntasm/ntasm.md 10 with reason 1 a
   value that is not a positive power of two, 2 a power of two the target ABI
   does not permit, 3 an rsp no load types as a stack in the current space,
   4 a normal return reached with the stack still displaced and 5 a terminal
   transfer reached the same way; the fourth word is the N in every case. E326
   carries the frozen shape of 8.3 for an unproved requires, so family 4 is
   stack_aligned and the fourth word the predicate ordinal. */
static void span(const NovaHostImage*i,const char*n,const char*s,uint64_t code,const char*needle,int nth,uint64_t third,uint64_t fourth){uint64_t line=0,column=0;where(s,needle,nth,&line,&column);Run r=run(i,n,s,4,0);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=third||r.out[3]!=fourth){failures++;fprintf(stderr,"FAIL span %s ret=%llu want %llu at %llu,%llu %llu,%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)code,(unsigned long long)line,(unsigned long long)column,(unsigned long long)third,(unsigned long long)fourth,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* The 17.4 footprint parity probe. The body holds one instruction and declares
   clobbers {}, so body_clobbers has to report the whole required family
   bitset as 335 and family 5, the rsp family, is bit 16 of it. The probe then
   asks control_flow the same question through its own exported predicate, so a
   private write table that drifts away from the one body_clobbers reads fails
   here instead of silently refusing or silently accepting. expect is the answer
   the frozen table gives, now computed from nt_x64_effects rather than written
   here: the question is "does the oracle charge this form the rsp family", and
   a form the oracle refuses charges nothing. out[3] is 1 when the two modules
   disagree, whatever expect says. */
#define ORACLE_NO UINT64_C(0x8000000000000000)
static const NtX64Context ORACLE_CTX={NT_X64_ALL_FEATURES,0};
static NtX64Operand orx_reg(unsigned r,unsigned w){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_REG;o.reg=r;o.width=w;return o;}
static NtX64Operand orx_mem(unsigned w){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_MEM;o.width=w;o.base=5;o.index=-1;o.scale=1;return o;}
static NtX64Operand orx_imm(uint64_t v){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_IMM;o.imm=v;return o;}
static NtX64Operand orx_rel(void){NtX64Operand o=orx_imm(4);o.kind=NT_X64_REL;o.is_signed=1;return o;}
static NtX64Operand orx_cr(unsigned r){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_CR;o.reg=r;o.width=64;return o;}
/* 1 when the oracle charges this exact form the stack family, bit 4 of its GPR
   mask, and 0 when it charges nothing, which is also the answer for a form it
   refuses: a form the encoder cannot emit writes no register anyone can
   declare. */
static uint64_t stack_family(const char*m,const NtX64Operand*o,unsigned n){NtX64Effects e;memset(&e,0,sizeof e);if(nt_x64_effects(m,o,n,ORACLE_CTX,&e)!=NT_X64_OK)return 0;return (e.registers_written&(UINT64_C(1)<<4))?1u:0u;}
/* The rsp family bit as a number, printed with the divergence lines so the
   frozen overlap is a measured number and not a claim in a comment. */
static uint64_t stack_bit(const char*m,const NtX64Operand*o,unsigned n){NtX64Effects e;memset(&e,0,sizeof e);if(nt_x64_effects(m,o,n,ORACLE_CTX,&e)!=NT_X64_OK)return 0;return (e.registers_written&UINT64_C(0xffff))&(UINT64_C(1)<<4);}
/* ============ the A4 reserve: the EXACT value, not the family bit ============
   stack_family and stack_bit both mask the oracle down to bit 4, which is the
   right question for the 17.4 parity probe and the wrong one for the reserve.
   The reserve at spec/ntasm/ntasm.md 17.4 says no gate verifies the exact
   registers_written for pushfq, popfq, ret, return or call, and that is true
   of the masked helpers: they cannot tell 0x0010 from 0x20010, and for popfq
   the difference is real. nt_x64_effects publishes registers_written
   0x20010 for popfq -- 0x10 for the rsp family plus bit 17, RFLAGS, because
   x64.c:1069-1074 ORs bit 17 in for every form that writes flags. A reader
   that masked to the sixteen families recorded popfq as an exact 0x10 and the
   reserve's own figure was wrong. The full 64 bit mask is what the four
   helpers below publish, and it is compared in that width. */
#define A4_NO UINT64_C(0x8000000000000000)
/* The whole registers_written, all 64 bits, or A4_NO for a form the encoder
   refuses. This is the exact value and not a family projection of it. */
static uint64_t a4_written(const char*m,const NtX64Operand*o,unsigned n){NtX64Effects e;memset(&e,0,sizeof e);if(nt_x64_effects(m,o,n,ORACLE_CTX,&e)!=NT_X64_OK)return A4_NO;return e.registers_written;}
/* The same value split into the part the 17.4 clobbers table speaks about --
   the sixteen GPR families register_widths numbers -- and the part it does not.
   Bit 17 is RFLAGS, 18 GSBASE, 19 FSBASE. They are separated rather than
   dropped so that popfq's bit 17 is a number in the log instead of an absence
   nobody can see.

   The sentence that used to stand here -- "those are body_intrinsics'
   question" -- was a claim with no instrument behind it, and a reader was
   entitled to doubt it. It has been measured. x64.c:1069-1074 sets bit 17 and
   NT_X64_EFFECT_CHANGES_FLAGS in the same three lines, so the oracle publishes
   the flags channel twice; the product carries it as the effects atom
   changes_flags, bit 1 by effects.nova:78, and body_intrinsics.nova refuses
   334 with that atom missing. The A4-FLAGS sweep in
   tests_ntasm_body_intrinsics.c now asks both sides about the same form for
   every branch of the x64.c chain that can set a flag and FAILS on any form
   the oracle flags and the product does not demand. It measures
   oracle_bit17=31 product_demands_changes_flags=31 blind_spots=0
   over_approximations=0 across 45 forms, and it was shown able to fire:
   deleting the single neg row from a COPY of body_intrinsics.nova turns that
   one form BLIND and moves blind_spots to 1.

   So masking here drops a duplicate encoding of an obligation the tree does
   enforce. Bits 18 and 19 are a different matter and are NOT covered by that
   measurement: no effect atom names GSBASE or FSBASE, so for swapgs, whose
   registers_written is 0x40000, the bit has no channel anywhere in the tree.
   A4_GPR is a correct projection for bit 17 and a real hole for bit 18. */
#define A4_GPR UINT64_C(0xffff)
static uint64_t a4_gpr(const char*m,const NtX64Operand*o,unsigned n){uint64_t v=a4_written(m,o,n);return v==A4_NO?A4_NO:(v&A4_GPR);}
static uint64_t a4_nonfamily(const char*m,const NtX64Operand*o,unsigned n){uint64_t v=a4_written(m,o,n);return v==A4_NO?A4_NO:(v&~A4_GPR);}
/* ---- DOES THE FROZEN 17.4 FIXED-FOOTPRINT TABLE NAME THIS FORM?  DERIVED.
   Never transcribed here, and that is the whole point.

   The question this harness asks is a question about a DOCUMENT: "does the
   frozen footprint table of 17.4 name this form".  The previous version of
   this function answered it with a literal array of seven mnemonics.  That
   array was a COPY of the table, not a reading of it, and the copy was already
   stale when it was written -- the table carries twelve rows -- so the gate
   reported unnamed_by_17.4=10 against a document that names nine of the fifteen
   charged zero-operand forms.  A copied fact and a derived fact are identical
   in the output; that is why the frozen list was not a slow drift but an
   immediate falsehood, and why nothing this file's own log printed could ever
   have said so.  Only re-reading the document, or perturbing it, finds that.

   So the table is READ.  The reader finds section 17.4 by its own heading,
   then the fixed-footprint table by the header CELLS that table declares -- a
   `formes` column standing beside the `registres_written` column, which is
   what makes it the table that names forms and publishes measured masks --
   and then the backticked tokens of the `formes` cell of every body row.  Not
   "the table with twelve rows", not "the third table": those are copies too.
   A row the document gains is a row this harness sees; a row it loses is one
   this harness stops crediting.

   The read happens once and its result is published, because an unreadable
   table is the dangerous case: it answers "the document names nothing", which
   is the most alarming number in this log and would mean nothing at all.  A
   missing heading, an empty table, an overflowed name and a truncated name are
   all FAILURES, and the count is printed beside the row count so a reader can
   see which of the two numbers they are reading. */
#define S174_MAX 64
#define S174_TOK 48
typedef struct{char tok[S174_MAX][S174_TOK];unsigned n,dropped,truncated,tables,col;int ok;}Spec174;
static Spec174 s174;
/* The backticked tokens of cell `col` of a table row -- and `col` is not a
   remembered offset, it is the index the HEADER gave to the `formes` column.
   That distinction is the whole difference between reading a table and
   guessing at it: a hard-coded "second cell" is a copy of the column order,
   and the column order is exactly what this project edits without noticing. */
static void sp174_row_forms(const char*p,const char*e,unsigned want){
  unsigned cell=0;const char*q=p;
  if(q<e&&*q=='|')q++;
  while(q<=e){
    const char*c=q;while(q<e&&*q!='|')q++;
    if(cell==want){
      const char*r=c;
      while(r<q){
        if(*r=='`'){
          const char*s=++r;while(r<q&&*r!='`')r++;
          if(r<q&&r>s){
            size_t L=(size_t)(r-s);
            if(s174.n>=S174_MAX)s174.dropped++;
            else if(L>=S174_TOK)s174.truncated++;
            else{memcpy(s174.tok[s174.n],s,L);s174.tok[s174.n][L]=0;s174.n++;}}
          if(r<q)r++;
        }else r++;}
      return;}
    cell++;
    if(q<e)q++;else break;}}
/* Does this line carry this word? The length is TAKEN from the word, never
   written next to it. */
static int sp174_has(const char*p,const char*e,const char*w){
  size_t n=strlen(w);
  for(;p+n<=e;p++)if(strncmp(p,w,n)==0)return 1;
  return 0;}
/* Which cell of this header row carries this word? The column INDEX, taken
   from the header, is what the body rows are then read by. */
static unsigned sp174_col_of(const char*p,const char*e,const char*w){
  unsigned cell=0;const char*q=p;
  if(q<e&&*q=='|')q++;
  while(q<=e){
    const char*c=q;while(q<e&&*q!='|')q++;
    if(sp174_has(c,q,w))return cell;
    cell++;
    if(q<e)q++;else break;}
  return 0;}
/* Where the document is, from the root the gate runs in. A list of candidate
   ROOTS rather than one path, so the harness is not welded to the directory
   the build script happens to cd into. A path is not a fact about the document
   and may drift without the gate noticing; this one is measured every run. */
static int sp174_load(void){
  static const char*const roots[]={"spec/ntasm/ntasm.md","../spec/ntasm.md","../../spec/ntasm.md","../../../spec/ntasm.md"};
  size_t len=0;char*b=NULL;const char*end,*sec=NULL,*send=NULL,*p;unsigned k;int in=0;
  memset(&s174,0,sizeof s174);
  for(k=0;k<sizeof roots/sizeof*roots;k++){b=loadf(roots[k],&len);if(b)break;}
  if(!b)return 0;
  end=b+len;
  for(p=b;p<end;){
    const char*e=p;while(e<end&&*e!='\n')e++;
    if(strncmp(p,"### 17.4",8)==0&&(p+8==e||p[8]==' '||p[8]=='\r')){sec=p;send=e;}
    else if(sec&&*p=='#'){send=p;break;}
    p=e<end?e+1:end;}
  if(sec)for(p=sec;p<send;){
    const char*e=p;while(e<end&&*e!='\n')e++;
    if(p<e&&*p=='|'){
      if(!in){
        /* The header, recognised by the two cells it declares and not by its
           position: this is what stops a sibling table from being read.
           A hand-counted strlen is itself a copy of the fact, and this very
           line is the proof: the first version searched 16 bytes for the
           17-byte word the document spells `registers_written`, matched
           nothing, and the gate reported the document as naming nothing at
           all -- a total failure wearing the costume of a measurement. The
           length is TAKEN, never written. */
        in=sp174_has(p,e,"formes")&&sp174_has(p,e,"registers_written");
        if(in){s174.tables++;s174.col=sp174_col_of(p,e,"formes");}
      }else sp174_row_forms(p,e,s174.col);
    }else in=0;
    p=e<end?e+1:end;}
  free(b);
  /* Exactly ONE table may answer to that header pair. Zero means the
     document was not read; two means the reader credits the union of two
     tables, which is a false derivation wearing the costume of a thorough
     one -- the same defect as the frozen list, with a parser in front of it. */
  s174.ok=(s174.tables==1&&s174.n>0&&s174.dropped==0&&s174.truncated==0);
  return s174.ok;}
static int named_174(const char*m){
  if(!s174.ok&&!sp174_load())return 0;
  for(unsigned k=0;k<s174.n;k++)if(!strcmp(m,s174.tok[k]))return 1;
  return 0;}
/* A measured divergence, not a comment. The gate prints the rsp family bit the
   oracle publishes for a form the two 17.4 tables charge differently from the
   oracle, so the gap is a number in the log rather than a claim in a comment.
   It cannot make the gate pass or fail. */
static unsigned gaps;
static void oracle_gap(const char*form,uint64_t bit,uint64_t nova){
  gaps++;
  fprintf(stderr,"ORACLE-DIVERGENCE form=%s oracle_registers_written=0x%04llx nova_charges=0x%04llx\n",
    form,(unsigned long long)bit,(unsigned long long)nova);}
/* The whole x64.c:942 member swept in one place, plus iretq from its own
   branch at x64.c:1039, and sysretq as the negative the oracle answers with no
   GPR write at all. Every expectation is derived from nt_x64_effects:
   stack_family is the bit the oracle publishes, and the probe is the answer the
   two 17.4 tables give about the same form, so a table that drifts from the
   oracle fails here instead of printing a number nobody reads.

   reachable says whether the grammar can spell this form as the single kind 32
   instruction of a one instruction body at all. It is not a literal: it is
   measured, by the probe answering 800, which is the transactional refusal a
   body holding no such instruction produces. return and call are keywords the
   parser gives node kinds 29 and 28, so no body ever holds them as a kind 32
   instruction and the 17.4 tables are never asked about them; asking anyway
   and expecting 800 is what keeps that a measured fact instead of a claim. */
/* One probe form, read as: the body spells this mnemonic over this operand
   list. The expected footprint answer is derived from nt_x64_effects. */
typedef struct{const char*name;const NtX64Operand*ops;unsigned count;}Form;
#define FR0(nm) ((Form){nm,NULL,0})
#define FR1(nm,a1) ((Form){nm,(const NtX64Operand[]){a1},1})
#define FR2(nm,a1,a2) ((Form){nm,(const NtX64Operand[]){a1,a2},2})
static void memberF(const NovaHostImage*i,const char*n,const char*form,Form f,int reachable){
  static const char head[]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\n";
  static const char tail[]="\nreturn 0\n}\n}\n";
  char s[1024];size_t hl=sizeof head-1,tl=sizeof tail-1,fl=strlen(form);
  if(hl+fl+tl>=sizeof s){checks++;failures++;fprintf(stderr,"FAIL member %s probe too long\n",form);return;}
  memcpy(s,head,hl);memcpy(s+hl,form,fl);memcpy(s+hl+fl,tail,tl);s[hl+fl+tl]=0;
  uint64_t oracle=stack_family(f.name,f.ops,f.count);
  Run r=run(i,n,s,4,1);cases++;checks++;
  if(reachable==0){
    /* Not a kind 32 instruction: the two tables are not asked, so the only
       honest expectation is the probe's own refusal, and the oracle mask is
       printed so the row the tables cannot reach stays a measured number. */
    if(r.returned!=800){failures++;
      fprintf(stderr,"FAIL member %s form=%s expected the 800 of an unspellable form, got ret=%llu out=%llu,%llu\n",
        form,form,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1]);
      return;}
    printf("MEMBER-UNREACHABLE form=%-8s oracle_registers_written=0x%04llx reason=not-a-kind-32-instruction\n",
      form,(unsigned long long)stack_bit(f.name,f.ops,f.count));
    return;}
  if(r.returned||r.runtime||r.out[0]!=oracle||r.out[1]!=oracle||r.out[3]){
    failures++;
    fprintf(stderr,"FAIL member %s form=%s ret=%llu want=0x%04llx mine=%llu theirs=%llu clobber_code=%llu\n",
      form,form,(unsigned long long)r.returned,(unsigned long long)oracle,
      (unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2]);
    oracle_gap(form,stack_bit(f.name,f.ops,f.count),r.out[0]);
    return;}
  printf("MEMBER form=%-8s oracle_registers_written=0x%04llx nova_charges=0x%04llx agree=1\n",
    form,(unsigned long long)stack_bit(f.name,f.ops,f.count),(unsigned long long)(oracle?UINT64_C(16):0));}
static void parityF(const NovaHostImage*i,const char*n,const char*form,Form f){
  static const char head[]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\n";
  static const char tail[]="\nreturn 0\n}\n}\n";
  char s[1024];size_t hl=sizeof head-1,tl=sizeof tail-1,fl=strlen(form);
  if(hl+fl+tl>=sizeof s){checks++;failures++;fprintf(stderr,"FAIL parity %s probe too long\n",n);return;}
  memcpy(s,head,hl);memcpy(s+hl,form,fl);memcpy(s+hl+fl,tail,tl);s[hl+fl+tl]=0;
  uint64_t expect=stack_family(f.name,f.ops,f.count);
  Run r=run(i,n,s,4,1);cases++;checks++;
  if(r.returned!=0||r.runtime||r.out[0]!=expect||r.out[1]!=expect||r.out[3]){
    failures++;fprintf(stderr,"FAIL parity %s form=%s ret=%llu want=%llu mine=%llu theirs=%llu clobber_code=%llu\n",
      n,form,(unsigned long long)r.returned,(unsigned long long)expect,
      (unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2]);}}
static void displacementF(const NovaHostImage*i,const char*n,const char*form,Form f,uint64_t displaces,uint64_t replaces){
  static const char head[]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\n";
  static const char tail[]="\nreturn 0\n}\n}\n";
  char s[1024];size_t hl=sizeof head-1,tl=sizeof tail-1,fl=strlen(form);
  if(hl+fl+tl>=sizeof s){checks++;failures++;fprintf(stderr,"FAIL displacement %s probe too long\n",n);return;}
  memcpy(s,head,hl);memcpy(s+hl,form,fl);memcpy(s+hl+fl,tail,tl);s[hl+fl+tl]=0;
  uint64_t writes=stack_family(f.name,f.ops,f.count);
  Run r=run(i,n,s,4,2);cases++;checks++;
  if(r.out[0]!=displaces||r.out[1]!=replaces||r.out[2]!=writes){
    failures++;fprintf(stderr,"FAIL displacement %s form=%s got %llu,%llu,%llu want %llu,%llu,%llu ret=%llu\n",
      n,form,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],
      (unsigned long long)displaces,(unsigned long long)replaces,(unsigned long long)writes,
      (unsigned long long)r.returned);}}
/* The statement-level twin of memberF, for the two forms the instruction
   path can never reach. A return is node kind 29 and a call is node kind 28
   (parser.nova:362-368 and :370-374), so the probe asks mode 5, which finds
   the one such statement in the body and puts the three 17.4 and 10
   questions to it. out[0] is the footprint, out[1] the displacement and
   out[2] whether the displacement comes back; the third is the one that
   differs between the two forms and the reason they are two rows.

   The expectation for the first two words is derived from nt_x64_effects
   exactly as memberF derives it, so the row is not a literal written here:
   the oracle publishes 1<<4 to the whole member, so both forms must answer
   yes to the footprint question and yes to the displacement question. The
   third is this pass's own rule and is asserted as such, restores=0 for a
   return and 1 for a call. */
static void statementF(const NovaHostImage*i,const char*n,const char*form,Form f,uint64_t restores){
  static const char head[]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\n";
  static const char tail[]="\n}\n}\n";
  char s[1024];size_t hl=sizeof head-1,tl=sizeof tail-1,fl=strlen(form);
  if(hl+fl+tl>=sizeof s){checks++;failures++;fprintf(stderr,"FAIL statement %s probe too long\n",n);return;}
  memcpy(s,head,hl);memcpy(s+hl,form,fl);memcpy(s+hl+fl,tail,tl);s[hl+fl+tl]=0;
  uint64_t oracle=stack_family(f.name,f.ops,f.count);
  Run r=run(i,n,s,4,5);cases++;checks++;
  if(oracle!=1){
    failures++;
    fprintf(stderr,"FAIL statement %s the oracle does not charge the stack family to %s\n",
      n,form);
    return;}
  if(r.returned||r.runtime||r.out[0]!=1||r.out[1]!=1||r.out[2]!=restores||r.out[3]){
    failures++;
    fprintf(stderr,"FAIL statement %s form=%s ret=%llu got %llu,%llu,%llu,%llu want 1,1,%llu,0\n",
      n,form,(unsigned long long)r.returned,(unsigned long long)r.out[0],
      (unsigned long long)r.out[1],(unsigned long long)r.out[2],
      (unsigned long long)r.out[3],(unsigned long long)restores);
    return;}
  printf("STATEMENT form=%-10s oracle_registers_written=0x%04llx nova_writes=0x%04llx displaces=1 restores=%llu agree=1\n",
    form,(unsigned long long)stack_bit(f.name,f.ops,f.count),
    (unsigned long long)UINT64_C(16),(unsigned long long)restores);}
/* The three questions about one instruction, asked together so the gate asserts
   the rows of the invalidation table and not only what the rows do to a later
   call. out[0] is displaces_stack, the rule this lot added, and out[1] is
   replaces_stack, the compensation witness; both are control_flow's own rules
   and are asserted from this file. out[2] is writes_stack, the 17.4 footprint
   question body_clobbers is asked in parallel, and it is derived from
   nt_x64_effects rather than written here, so the row of the table the two
   halves must share is the row the C oracle publishes. */
/* The C oracle's own answer for stack_aligned(N), asked by running the oracle
   rather than by restating its rule, because the rule this file used to
   assume is two rules and they are not the same rule. The oracle splits the
   value question in two, in frontend.c:5543-5550 for a declaration and
   frontend.c:1398-1403 at a call site:

     declares  phase 0:  N is a positive power of two and N <= 4096
     proves    the call: N is a positive power of two, N <= 16, 16 % N == 0

   So a value can be a legal predicate and still be unprovable at a call, and
   that gap between 16 and 4096 is the whole reason section 10 needs two
   refusals for one construct rather than one. Both probes run the oracle's
   frontend over a real program, so what this file asserts is what the oracle
   does, not what a comment in a Nova module says it does.

   oracle_declares compiles a callee that carries the predicate and nothing
   else; oracle_proves compiles a second function that calls it, which is the
   only shape that reaches call_predicate_proved. */
static uint64_t oracle_declares(unsigned amount){
  char s[1024];
  snprintf(s,sizeof s,"module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(%u)} {\nreturn 0\n}\n}\n",
    amount);
  NtFInput in={"m",s,strlen(s)};NtFProgram p;memset(&p,0,sizeof p);
  nt_frontend_compile(&in,1,&p);
  uint64_t ok=(p.verified!=0)?1u:0u;
  nt_frontend_free(&p);
  return ok;
}
static uint64_t oracle_proves(unsigned amount){
  char s[1024];
  snprintf(s,sizeof s,"module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(%u)} {\nreturn 0\n}\n"
    "fn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n",amount);
  NtFInput in={"m",s,strlen(s)};NtFProgram p;memset(&p,0,sizeof p);
  nt_frontend_compile(&in,1,&p);
  uint64_t ok=(p.verified!=0)?1u:0u;
  nt_frontend_free(&p);
  return ok;
}
/* The ABI stack alignment ceiling of spec/ntasm/ntasm.md 8.3 and 17.3, bound across
   the two copies of the number and to the C oracle. control_flow reads its one
   definition through abi_ceiling and refuses align_stack N above it with 364
   reason 2; call_contracts family 4 credits the guarantee up to the same N and
   reports an unproved requires with 326. Neither module can import the other,
   so the gate asks both about the same N and fails when the two answers differ,
   which is what a ceiling changed on one side only looks like.

   The expectation is oracle_proves(N). It used to be a literal written here,
   which made this an assertion about a list in a C file: the oracle could
   change and the gate would still agree with the list. Deriving it means the
   three readers of the ceiling -- abi_ceiling, call_contracts family 4 at
   call_contracts.nova:1071, and the oracle at frontend.c:1401-1402 -- have to
   keep agreeing, and the sweep below has to cover the boundaries that decide
   it rather than only the two ends of the accepted set. */
static void ceiling(const NovaHostImage*i,const char*n,unsigned amount){
  char s[1024];Run a,b;int a_ok,b_ok,want;
  snprintf(s,sizeof s,"module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn leaf()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(%u)} {\nreturn 0\n}\n"
    "fn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n",amount);
  b=run(i,n,s,4,4);
  snprintf(s,sizeof s,"module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\n"
    "load rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack %u\n"
    "load rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n",amount);
  a=run(i,n,s,4,0);
  a_ok=(a.returned==0&&!a.runtime);b_ok=(b.returned==0&&!b.runtime);
  want=(int)oracle_proves(amount);
  cases++;checks++;
  if(a_ok!=b_ok||a_ok!=want){
    failures++;fprintf(stderr,"FAIL ceiling %s N=%u control_flow=%llu call_contracts=%llu oracle_proves=%d\n",
      n,amount,(unsigned long long)a.returned,(unsigned long long)b.returned,want);}}
/* The definition itself, so that changing abi_ceiling alone fails here as well
   as in the comparison above. */
/* Which of the oracle's two refusals the value belongs to, and therefore which
   of the two reasons 364 the pass must name. The oracle's two tests are asked
   separately because a value can be declared and unproved, and that is the
   only thing that tells reason 1 from reason 2:

     not a legal predicate at all        -> 364 reason 1
     legal, and the ABI does not prove it -> 364 reason 2
     proved by the ABI                    -> accepted

   want 0 is the accepted case, 1 and 2 are the two reasons. The sweep stops
   at 4096 on purpose. Above it the oracle stops at the declaration, while
   control_flow's reason 1 tests only that N is a positive power of two and has
   no upper bound of its own, so 8192 is a reason 2 here and a reason 1 there.
   Both refuse, so it is a naming difference and not an unsound one, and it is
   pinned as its own case below rather than folded into this one. */
static void alignment_reason(const NovaHostImage*i,const char*n,
  unsigned amount,int want){
  char s[1024];
  snprintf(s,sizeof s,"module m\ntarget x86_64-nexora-none\nsection .text {\n"
    "fn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\n"
    "load rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack %u\n"
    "load rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n",amount);
  Run r=run(i,n,s,4,0);
  uint64_t declared=oracle_declares(amount),proved=oracle_proves(amount);
  int oracle_want=proved?0:(declared?2:1);
  uint64_t got=(r.returned==364)?r.out[2]:0;
  cases++;checks++;
  if(r.runtime||oracle_want!=want||got!=(uint64_t)want){
    failures++;fprintf(stderr,"FAIL alignment_reason %s N=%u got=%llu oracle_want=%d want=%d "
      "declares=%llu proves=%llu ret=%llu\n",n,amount,(unsigned long long)got,oracle_want,want,
      (unsigned long long)declared,(unsigned long long)proved,(unsigned long long)r.returned);}}
static void ceiling_value(const NovaHostImage*i,const char*n,uint64_t expect){
  const char*s="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
  Run r=run(i,n,s,4,3);cases++;checks++;
  if(r.returned||r.runtime||r.out[0]!=expect){
    failures++;fprintf(stderr,"FAIL abi_ceiling got=%llu want=%llu ret=%llu\n",
      (unsigned long long)r.out[0],(unsigned long long)expect,(unsigned long long)r.returned);}}
int main(void){const char*paths[]={"tests/nova/tests/control-flow-entry.nova","compiler/nova/analysis/control_flow.nova","compiler/nova/analysis/abi/body_clobbers.nova","compiler/nova/analysis/calls/call_contracts.nova","compiler/nova/analysis/abi/effects.nova","compiler/nova/analysis/abi/features.nova","compiler/nova/analysis/abi/clobbers.nova","compiler/nova/analysis/types/register_widths.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova","compiler/nova/analysis/abi/abi.nova"};char*sources[14]={0};NtFInput inputs[14];for(unsigned i=0;i<14;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<14;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,14,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");int parity=ng_parity_begin(&ng_parity,&failures,ng_parity_err,sizeof ng_parity_err);if(image.memory&&parity==0){
const char*value="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n}\n";ok(&image,"value",value,1,1,1);
const char*fall="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nnop\n}\n}\n";err(&image,"fall",fall,338,1);
const char*bare="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn\n}\n}\n";err(&image,"bare",bare,339,0);
const char*never_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {privileged,changes_flags,control,no_return}\nclobbers {} {\nsysretq\n}\n}\n";ok(&image,"never",never_ok,1,1,0);
const char*never_return="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {no_return}\nclobbers {} {\nreturn 0\n}\n}\n";err(&image,"never return",never_return,337,0);
const char*never_fall="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {no_return}\nclobbers {} {\nnop\n}\n}\n";err(&image,"never fall",never_fall,338,2);
const char*branches="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif feature(sse2) {\nreturn 1\n} else {\nreturn 2\n}\n}\n}\n";ok(&image,"branches",branches,1,1,2);
const char*one_branch="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif feature(sse2) {\nreturn 1\n}\n}\n}\n";err(&image,"one branch",one_branch,338,1);
const char*never_branches="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {no_return}\nclobbers {} {\nif feature(sse2) {\nud2\n} else {\nud2\n}\n}\n}\n";ok(&image,"never branches",never_branches,1,1,0);
const char*two="module m\ntarget x86_64-nexora-none\nsection .text {\nfn a()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn b()->u64\neffects {}\nclobbers {} {\nreturn 2\n}\n}\n";ok(&image,"two",two,2,2,2);
const char*never_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn halt()->never\neffects {no_return}\nclobbers {} {\nud2\n}\nfn main()->never\neffects {no_return}\nclobbers {} {\ncall halt()\n}\n}\n";ok(&image,"never call",never_call,2,2,0);
const char*never_import="module m\ntarget x86_64-nexora-none\nimport a.halt as halt: fn()->never\neffects {no_return}\nclobbers {}\nsection .text {\nfn main()->never\neffects {no_return}\nclobbers {} {\ncall halt()\n}\n}\n";ok(&image,"never import",never_import,1,1,0);
const char*value_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn value()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->never\neffects {no_return}\nclobbers {} {\ncall value()\n}\n}\n";err(&image,"value call",value_call,338,2);
 // A label definition shares node kind 32 with an instruction but carries
 // aux 1, so a trailing label named ud2 or iretq is not a terminal statement.
 const char*ud2_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nud2:\n}\n}\n";err(&image,"ud2 label",ud2_label,338,1);
   const char*iretq_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {no_return}\nclobbers {} {\niretq:\n}\n}\n";err(&image,"iretq label",iretq_label,338,2);
  /* E340: a statement after a terminal one can never execute. Reason 1 is a
     generic terminal statement, reason 2 a call to a never function. The
     diagnostic is more specific than 338 and wins when both apply. */
  const char*dead_return="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\nnop\n}\n}\n";dead(&image,"dead after return",dead_return,8,1,1);
  const char*dead_ud2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {no_return}\nclobbers {} {\nud2\nnop\n}\n}\n";dead(&image,"dead after ud2",dead_ud2,8,1,1);
  const char*dead_sysretq="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {no_return}\nclobbers {} {\nsysretq\nnop\n}\n}\n";dead(&image,"dead after sysretq",dead_sysretq,8,1,1);
  const char*dead_iretq="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {no_return}\nclobbers {} {\niretq\nnop\n}\n}\n";dead(&image,"dead after iretq",dead_iretq,8,1,1);
  const char*dead_never_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn halt()->never\neffects {no_return}\nclobbers {} {\nud2\n}\nfn main()->never\neffects {no_return}\nclobbers {} {\ncall halt()\nnop\n}\n}\n";dead(&image,"dead after never call",dead_never_call,13,1,2);
  const char*dead_if="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif feature(sse2) {\nreturn 1\n} else {\nreturn 2\n}\nnop\n}\n}\n";dead(&image,"dead after if/else",dead_if,12,1,1);
  const char*dead_branch="module m\ntarget x86_64-nexora-none\nsection .text {\nfn halt()->never\neffects {no_return}\nclobbers {} {\nud2\n}\nfn main()->never\neffects {no_return}\nclobbers {} {\nif feature(sse2) {\ncall halt()\nnop\n} else {\nud2\n}\n}\n}\n";dead(&image,"dead in branch",dead_branch,14,1,2);
  /* Negatives: E340 must not fire where the statement really can execute. */
  const char*live_before="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nnop\nreturn 0\n}\n}\n";ok(&image,"live before return",live_before,1,1,1);
  const char*live_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\ndone:\n}\n}\n";err(&image,"label after return",live_label,338,1);
  const char*live_target="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\njmp done\ndone:\nnop\n}\n}\n";err(&image,"reachable label target",live_target,338,1);
  const char*live_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn value()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall value()\nreturn 0\n}\n}\n";ok(&image,"value call then return",live_call,2,2,2);
  const char*live_never_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn halt()->never\neffects {no_return}\nclobbers {} {\nud2\n}\nfn main()->u64\neffects {no_return}\nclobbers {} {\nif feature(sse2) {\ncall halt()\n} else {\nnop\n}\nreturn 0\n}\n}\n";ok(&image,"never call not last",live_never_call,2,2,1);
   const char*empty="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\n}\n}\n";err(&image,"empty block",empty,338,1);
  /* E340 is a fallthrough diagnostic: an unconditional jmp leaves the block for
     good, a Jcc still falls through, and a label definition names a branch
     target, so it resumes fallthrough when a jmp or Jcc in the same function
     actually names it. Group A below is the reachable-after-jmp set. */
  const char*jmp_clean="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\njmp done\ndone:\nreturn 1\n}\n}\n";ok(&image,"jmp target reachable",jmp_clean,1,1,1);
  const char*jmp_gap="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\njmp done\nreturn 99\ndone:\nreturn 1\n}\n}\n";dead(&image,"jmp transfer gap",jmp_gap,8,1,1);
  const char*jmp_loop="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nloop:\nnop\njmp loop\nreturn 99\n}\n}\n";dead(&image,"jmp backward loop",jmp_loop,10,1,1);
  const char*jmp_fn="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\nfn f()->u64\neffects {}\nclobbers {} {\njmp g\nreturn 99\n}\n}\n";dead(&image,"jmp another function",jmp_fn,13,1,1);
  const char*jcc_fall="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif feature(sse2) {\nje done\n}\nreturn 1\ndone:\nreturn 2\n}\n}\n";ok(&image,"jcc fallthrough target",jcc_fall,1,1,2);
  const char*jmp_branch_last="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\nfn f()->u64\neffects {}\nclobbers {} {\nif feature(sse2) {\njmp g\n} else {\nreturn 2\n}\ndone:\nreturn 1\n}\n}\n";ok(&image,"jmp last in branch",jmp_branch_last,2,2,3);
  const char*jmp_branch_gap="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\nfn f()->u64\neffects {}\nclobbers {} {\nif feature(sse2) {\njmp g\nreturn 99\n} else {\nreturn 2\n}\ndone:\nreturn 1\n}\n}\n";dead(&image,"jmp gap in branch",jmp_branch_gap,14,1,1);
  const char*jmp_last="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\nfn f()->u64\neffects {}\nclobbers {} {\njmp g\n}\n}\n";err(&image,"jmp only",jmp_last,338,1);
  /* Group B: the target region is scanned again from the label, so a genuine
     dead statement inside it is still reported. Dropping the resumption, or
     stopping the block scan at the jmp, would accept all of these. */
  const char*dead_in_target="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\njmp done\ndone:\nreturn 1\nreturn 2\n}\n}\n";dead(&image,"dead inside target region",dead_in_target,10,1,1);
  const char*dead_in_target_nop="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\njmp done\ndone:\nnop\nreturn 1\nreturn 2\n}\n}\n";dead(&image,"label resumes then dead",dead_in_target_nop,11,1,1);
  const char*dead_in_target_ud2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {no_return}\nclobbers {} {\njmp done\ndone:\nud2\nnop\n}\n}\n";dead(&image,"ud2 inside target region",dead_in_target_ud2,10,1,1);
  const char*dead_in_target_sysretq="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {no_return}\nclobbers {} {\njmp done\ndone:\nsysretq\nnop\n}\n}\n";dead(&image,"sysretq inside target region",dead_in_target_sysretq,10,1,1);
  const char*dead_in_target_iretq="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {no_return}\nclobbers {} {\njmp done\ndone:\niretq\nnop\n}\n}\n";dead(&image,"iretq inside target region",dead_in_target_iretq,10,1,1);
  const char*dead_in_target_never="module m\ntarget x86_64-nexora-none\nsection .text {\nfn halt()->never\neffects {no_return}\nclobbers {} {\nud2\n}\nfn main()->never\neffects {no_return}\nclobbers {} {\njmp done\ndone:\ncall halt()\nnop\n}\n}\n";dead(&image,"never call inside target",dead_in_target_never,15,1,2);
  const char*dead_in_target_if="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\njmp done\ndone:\nif feature(sse2) {\nreturn 1\n} else {\nreturn 2\n}\nnop\n}\n}\n";dead(&image,"if else inside target",dead_in_target_if,14,1,1);
  const char*jcc_target_dead="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif feature(sse2) {\nje done\n}\nreturn 1\ndone:\nreturn 2\nreturn 3\n}\n}\n";dead(&image,"dead after jcc target",jcc_target_dead,13,1,1);
  /* Group C: a label only resumes fallthrough when a jmp or Jcc in the same
     function names it, so a label nothing branches to leaves the dead state in
     place. The dead report also precedes the fallthrough test, so a jmp that
     follows a terminal statement is itself dead code. */
  const char*label_no_branch="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\ndone:\nreturn 1\n}\n}\n";dead(&image,"label without branch",label_no_branch,9,1,1);
  const char*label_is_target="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\njmp done\nreturn 0\ndone:\nreturn 1\n}\n}\n";dead(&image,"labelled target resumes",label_is_target,8,1,1);
  const char*jmp_after_return="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\njmp done\ndone:\nreturn 1\n}\n}\n";dead(&image,"jmp after return",jmp_after_return,8,1,1);
  bad(&image,"short",value,3);bad(&image,"invalid","target x86_64-nexora-none\n",4);
  /* ---- align_stack, spec/ntasm/ntasm.md 10. align_stack N is node kind 45 with
     one integer literal child; the five obligations of section 10 are decided
     over that node and the body state it produces. The load of a kernel stack
     pointer is what types rsp in a space, exactly as the section 9 example
     does, and every accepted case compensates before it leaves. ---- */
  /* N must be a positive power of two. 0, 3 and 1000 are decided from the
     literal child, so they cannot be accepted as a no-op. */
  const char*align_zero="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 0\nreturn 0\n}\n}\n";span(&image,"align_stack 0",align_zero,364,"align_stack",1,1,0);
  const char*align_three="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 3\nreturn 0\n}\n}\n";span(&image,"align_stack 3",align_three,364,"align_stack",1,1,3);
  const char*align_thousand="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 1000\nreturn 0\n}\n}\n";span(&image,"align_stack 1000",align_thousand,364,"align_stack",1,1,1000);
  /* N must be permitted by the target ABI. 32 is a power of two and the
     frozen ABI guarantee of 8.3 and 17.3 stops at 16, so 32 is refused. */
  const char*align_32="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 32\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"align_stack 32",align_32,364,"align_stack",1,2,32);
  /* 16 and 1 are powers of two the ABI permits, so both are accepted once the
     displacement is compensated before the return. */
  const char*align_16="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"align_stack 16",align_16,1,1,1);
  const char*align_1="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 1\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"align_stack 1",align_1,1,1,1);
  /* rsp must be typed as a stack in the current space. No load at all, and
     two loads that disagree on the space, both leave it unknown, and an
     unknown space is a refusal. */
  const char*align_untyped="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp} {\nalign_stack 16\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"align_stack untyped",align_untyped,364,"align_stack",1,3,16);
  const char*align_two_spaces="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),reads_mem(user)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nload rsp,[gs:user_rsp]:ptr<user,u64>\nalign_stack 16\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"align_stack two spaces",align_two_spaces,364,"align_stack",1,3,16);
  /* The displacement must be compensated before a normal return. */
  const char*align_bare_return="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nreturn 0\n}\n}\n";span(&image,"align_stack uncompensated return",align_bare_return,364,"return",1,4,16);
  /* A compensation on one branch only does not compensate the other, so the
     weakest path decides and the return is still refused. */
  const char*align_half="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nif feature(sse2) {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\n} else {\nnop\n}\nreturn 0\n}\n}\n";span(&image,"align_stack one branch",align_half,364,"return",1,4,16);
  /* Both branches compensate, which is the accepted shape. */
  const char*align_both="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nif feature(sse2) {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\n} else {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\n}\nreturn 0\n}\n}\n";ok(&image,"align_stack both branches",align_both,1,1,1);
  /* A never function owes no return, so iretq, the one form 17.4 gives a
     stack write, is the transfer that discharges the obligation. */
  const char*align_never="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {privileged,control,changes_flags,no_return}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\niretq\n}\n}\n";ok(&image,"align_stack never iretq",align_never,1,1,0);
  /* ud2 transfers out without replacing the stack, so the displacement is
     still pending at the transfer. */
  const char*align_never_ud2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {no_return}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nud2\n}\n}\n";span(&image,"align_stack never ud2",align_never_ud2,364,"ud2",1,5,16);
  /* The section 9 shape, sysretq after a call: 17.4 gives no stack write to
     sysretq, so the transfer leaves the displacement pending. */
  const char*align_sysretq="module m\ntarget x86_64-nexora-none\nsection .syscall {\nexport fn entry()->never\neffects {privileged,control,changes_flags,no_return}\nclobbers {rsp,rcx,r11} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\ncall dispatch()\nsysretq\n}\nfn dispatch()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";span(&image,"align_stack sysretq",align_sysretq,364,"sysretq",1,5,16);
  /* The fact stack_aligned(N) is produced in the body state and discharges a
     callee requires. align_stack 16 before the call proves it. */
  const char*align_call_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"align_stack discharges callee",align_call_ok,2,2,2);
  /* The load kills the fact before the call, so the call cannot be discharged
     and the frozen 326 shape reports family 4 and the predicate ordinal. */
  const char*align_call_early="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\ncall wants()\nalign_stack 16\nreturn 0\n}\n}\n";span(&image,"align_stack call before",align_call_early,326,"wants",2,4,0);
  /* A weaker alignment does not prove the stronger predicate. */
  const char*align_call_weak="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 4\ncall wants()\nreturn 0\n}\n}\n";span(&image,"align_stack 4 cannot prove 16",align_call_weak,326,"wants",2,4,0);
  /* A compensation restores the stack pointer but not the alignment fact: the
     value now comes from memory and nothing proves it any more. */
  const char*align_call_after_restore="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\ncall wants()\nreturn 0\n}\n}\n";span(&image,"align_stack fact dies at restore",align_call_after_restore,326,"wants",2,4,0);
  /* A callee that clobbers the stack family may have moved it, so the fact
     does not survive the call. */
  const char*align_call_mover="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn mover()->u64\neffects {}\nclobbers {rsp} {\nmov rsp,rbx\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\ncall mover()\ncall wants()\nreturn 0\n}\n}\n";span(&image,"align_stack callee moves stack",align_call_mover,326,"wants",2,4,0);
  /* A callee that does not clobber the stack keeps it, so the fact survives
     the call and the second one is discharged. */
  const char*align_call_keeps="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn quiet()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\ncall quiet()\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"align_stack survives a quiet call",align_call_keeps,3,3,3);
  /* Repeated align_stack is legal and provably redundant rather than refused:
     align_down(align_down(x,N1),N2) is align_down(x,max) on powers of two, so
     the second statement can neither change the fact nor add a second
     compensation. Weaker then stronger reaches 16, stronger then weaker keeps
     16, and 4 alone does not reach 16. */
  const char*align_twice_up="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 4\nalign_stack 16\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"align_stack twice reaches 16",align_twice_up,2,2,2);
  const char*align_twice_down="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nalign_stack 4\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"align_stack twice keeps 16",align_twice_down,2,2,2);
  /* One compensation covers the pair, so the repeated form is not a second
     debt. */
  const char*align_twice_restore="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 4\nalign_stack 16\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"align_stack twice one restore",align_twice_restore,1,1,1);
  const char*align_twice_bare="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 4\nalign_stack 16\nreturn 0\n}\n}\n";span(&image,"align_stack twice uncompensated",align_twice_bare,364,"return",1,4,16);
  /* An align_stack inside a branch is reached by the walk and merges like any
     other: this branch compensates and the other never displaces, so the
     return is reached with a restored stack on both paths. */
  const char*align_nested_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nif feature(sse2) {\nalign_stack 16\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\n} else {\nnop\n}\nreturn 0\n}\n}\n";ok(&image,"align_stack nested compensated",align_nested_ok,1,1,1);
  /* The same shape with the displacement left pending on one path: the merge
     describes what the paths may reach, so the return is refused. */
  const char*align_nested_bare="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nif feature(sse2) {\nalign_stack 16\n} else {\nnop\n}\nreturn 0\n}\n}\n";span(&image,"align_stack nested pending",align_nested_bare,364,"return",1,4,16);
  /* A call to a never callee is a terminal transfer and replaces no stack, so
     the displacement is still pending when control leaves for good. */
  const char*align_never_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn halt()->never\neffects {no_return}\nclobbers {} {\nud2\n}\nfn f()->never\neffects {no_return}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\ncall halt()\n}\n}\n";span(&image,"align_stack never call",align_never_call,364,"halt",2,5,16);
  /* A bounded comptime block cannot hold a runtime statement, and align_stack
     is one: both are refused by the parser, so no kind 45 node can ever live
     outside a function body. */
  const char*comptime_statement="module m\ntarget x86_64-nexora-none\ncomptime budget=4 {\nnop\n}\n";bad(&image,"comptime statement",comptime_statement,4);
  const char*comptime_align="module m\ntarget x86_64-nexora-none\ncomptime budget=4 {\nalign_stack 16\n}\n";bad(&image,"comptime align_stack",comptime_align,4);
  /* align_stack outside a body is refused by the parser too, in a section and
     at the top of the module. */
  const char*align_in_section="module m\ntarget x86_64-nexora-none\nsection .text {\nalign_stack 16\n}\n";bad(&image,"align_stack in section",align_in_section,4);
  const char*align_at_top="module m\ntarget x86_64-nexora-none\nalign_stack 16\n";bad(&image,"align_stack at top",align_at_top,4);
  /* ---- The 17.4 write table is one vocabulary, and the compensation witness
        is read from it. body_clobbers charges the declared footprint of every
        form, control_flow watches the same table to decide that a displacement
        has been given back, and the two must never answer differently about
        the same mnemonic. pop rsp is the case the table was missing: it writes
        the stack pointer as its own destination, so it is the compensation the
        section 10 obligation is discharged with. ---- */
  const char*align_pop_rsp="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npop rsp\nreturn 0\n}\n}\n";ok(&image,"pop rsp compensates",align_pop_rsp,1,1,1);
  /* The same compensation before a terminal transfer. The displacement is gone
     by the time control leaves, so 364 reason 5 must not fire. */
  const char*align_pop_ud2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {reads_mem(kernel),no_return}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npop rsp\nud2\n}\n}\n";ok(&image,"pop rsp compensates before ud2",align_pop_ud2,1,1,0);
  const char*align_pop_iretq="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {reads_mem(kernel),privileged,control,changes_flags,no_return}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npop rsp\niretq\n}\n}\n";ok(&image,"pop rsp compensates before iretq",align_pop_iretq,1,1,0);
  /* A compensation on one branch compensates the other path too, because the
        merge takes the weaker of the two and here both restore the stack. */
  const char*align_pop_branch="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nif feature(sse2) {\npop rsp\n} else {\nmov rsp,rbx\n}\nreturn 0\n}\n}\n";ok(&image,"pop rsp in one branch",align_pop_branch,1,1,1);
  /* not is in the frozen writes_first row and was missing from the private
        copy as well, so the same false refusal reached it. */
  const char*align_not="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nnot rsp\nreturn 0\n}\n}\n";ok(&image,"not rsp compensates",align_not,1,1,1);
  /* xchg stays the two operand form: either side naming the stack pointer is
        a compensation, and the frozen table names both. */
  const char*align_xchg_1="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nxchg rsp,rbx\nreturn 0\n}\n}\n";ok(&image,"xchg rsp,rbx compensates",align_xchg_1,1,1,1);
  const char*align_xchg_2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nxchg rbx,rsp\nreturn 0\n}\n}\n";ok(&image,"xchg rbx,rsp compensates",align_xchg_2,1,1,1);
  /* ---- push is the other half of the same addition, and it is NOT a
        compensation. The oracle charges it with clobbers_push, so it writes
        the stack family, but it moves rsp down by the operand size and reads
        the operand instead of writing it: no value of rsp is given back, and
        the alignment it may have disturbed is not the one it restores. A
        syntactic witness that accepted any write of the stack family would
        accept this and be wrong, so the rule is stated on the operand: a
        compensation writes the stack pointer through an operand that names
        it, or replaces the stack outright. ---- */
  const char*align_push_pop="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npush rbx\npop rbx\nreturn 0\n}\n}\n";span(&image,"push pop pair is not a compensation",align_push_pop,364,"return",1,4,16);
  const char*align_push_rsp="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npush rsp\nreturn 0\n}\n}\n";span(&image,"push rsp is not a compensation",align_push_rsp,364,"return",1,4,16);
  const char*align_push_ud2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {reads_mem(kernel),no_return}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npush rbx\nud2\n}\n}\n";span(&image,"push before ud2 stays reason 5",align_push_ud2,364,"ud2",1,5,16);
  /* ---- pop compensates only when its own destination is the stack pointer.
        pop rbx and pop r12 move rsp up by the operand size and write another
        register, so the displacement they leave is still pending. ---- */
  const char*align_pop_rbx="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npop rbx\nreturn 0\n}\n}\n";span(&image,"pop rbx is not a compensation",align_pop_rbx,364,"return",1,4,16);
  const char*align_pop_r12="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,r12} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npop r12\nreturn 0\n}\n}\n";span(&image,"pop r12 is not a compensation",align_pop_r12,364,"return",1,4,16);
  const char*align_pop_rbx_ud2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {reads_mem(kernel),no_return}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npop rbx\nud2\n}\n}\n";span(&image,"pop rbx before ud2 stays reason 5",align_pop_rbx_ud2,364,"ud2",1,5,16);
  const char*align_pop_r12_ud2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {reads_mem(kernel),no_return}\nclobbers {rsp,r12} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npop r12\nud2\n}\n}\n";span(&image,"pop r12 before ud2 stays reason 5",align_pop_r12_ud2,364,"ud2",1,5,16);
  /* ---- leave is a pseudo-op the encoder cannot emit, so it has no anchorable
        footprint and the project rule is an explicit refusal. body_clobbers
        gives it 336 at the mnemonic whatever the clobbers set says, and this
        pass must reach the same verdict about the same instruction rather than
        a different one: 364 would blame an alignment the mnemonic is not even
        able to perform. ---- */
  const char*align_leave="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nleave\nreturn 0\n}\n}\n";span(&image,"align_stack leave is 336",align_leave,336,"leave",1,0,0);
  const char*align_leave_ud2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {reads_mem(kernel),no_return}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nleave\nud2\n}\n}\n";span(&image,"align_stack leave beats reason 5",align_leave_ud2,336,"leave",1,0,0);
  /* A label definition shares node kind 32 with an instruction but carries
        aux 1, so a label named leave names a branch target and moves nothing:
        the refusal is about the pseudo-op, never about the word. */
  const char*align_leave_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nleave:\nmov rsp,rbx\nreturn 0\n}\n}\n";ok(&image,"label named leave",align_leave_label,1,1,1);
  /* ---- The FACT dies at every instruction that displaces rsp without putting
        it back. 364 already reported the pending displacement at the end of a
        body, but the alignment FACT is a second, different question and nothing
        answered it. displaces_stack is the rule that answers it, and it reads
        the 17.4 footprint table plus the operand, never the footprint answer
        alone: so align_stack 16 ; push rbx ; call g, with g requiring
        stack_aligned(16), is refused with 326 even though rsp stood at 8
        (mod 16) at the call.

        The three forms this lot added rows for are the proof that the two
        questions are independent and stay so. pushfq, popfq and ret now answer
        yes to the 17.4 footprint question, exactly as push and pop always did,
        and they still kill the fact, because a form that writes the stack
        family without giving the entry pointer back has not restored anything.
        Deriving the displacement from the footprint would accept all three of
        the cases below. ---- */
  const char*stale_push="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npush rbx\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"fact dies at push",stale_push,326,"wants",2,4,0);
  const char*stale_pop="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npop rbx\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"fact dies at pop rbx",stale_pop,326,"wants",2,4,0);
  const char*stale_pushfq="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npushfq\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"fact dies at pushfq",stale_pushfq,326,"wants",2,4,0);
  const char*stale_popfq="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),privileged,changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npopfq\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"fact dies at popfq",stale_popfq,326,"wants",2,4,0);
  /* ret pops the return address, so it displaces rsp by eight and gives nothing
        back. control_flow does not read ret as a terminal statement, so the call
        after it is still walked, and the fact must be dead there. */
  const char*stale_ret="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),control}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nret\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"fact dies at ret",stale_ret,326,"wants",2,4,0);
  /* pop rsp is a compensation and still kills the fact: the entry pointer comes
        back, but the value that lands in it is the one that was on the stack. */
  const char*stale_pop_rsp="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npop rsp\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"fact dies at pop rsp",stale_pop_rsp,326,"wants",2,4,0);
  /* The A4 scenario the footprint comment used to name, with the two halves of
     the table on opposite sides of it. Every instruction in this body now
     answers yes to the 17.4 footprint question, push rbx and pop rbx through
     the frozen push and pop rows and pushfq and popfq through the rows this
     lot added, and the pair restores rsp to exactly where it was. The call
     must still be refused, because a balanced pair of displacements is not a
     compensation: neither push rbx nor pushfq gives the entry pointer back, so
     the fact is dead for the whole of what follows. Deriving the displacement
     from the footprint, which is what the closed 17.4 row would invite, accepts
     this body and discharges a callee requiring stack_aligned(16) while rsp
     stands at 8 (mod 16). */
  const char*a4_pair="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),privileged,changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npushfq\npopfq\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"A4 pushfq popfq pair is not a compensation",a4_pair,326,"wants",2,4,0);
  /* And the same body without the pushfq, so the only thing that changed is
     that the pair is present: the call is discharged and the fact stands. */
  const char*a4_quiet="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"A4 no displacement keeps the fact",a4_quiet,2,2,2);
  /* ---- call does NOT displace the fact, and this is the one negative of the
        rule, argued from the ABI. call writes the shadow area, eight bytes below
        the caller's rsp, but the return address it puts there is popped by the
        matching ret inside the callee, and a callee that returns through a
        different amount has left the ABI. So on the path out of the call rsp
        holds the value it held on the way in, and nothing about the alignment
        has moved. ---- */
  const char*call_balanced="module m\ntarget x86_64-nexora-none\nsection .text {\nfn quiet()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\ncall quiet()\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"call is ABI balanced",call_balanced,3,3,3);
  const char*call_twice="module m\ntarget x86_64-nexora-none\nsection .text {\nfn quiet()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\ncall quiet()\ncall quiet()\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"two balanced calls",call_twice,3,3,3);
  /* A callee that does not name rsp in its clobbers and does not displace it
        preserves the stack by the same ABI, so the fact stands. */
  const char*callee_keeps="module m\ntarget x86_64-nexora-none\nsection .text {\nfn keeper()->u64\neffects {}\nclobbers {rax} {\nmov rax,1\nreturn rax\n}\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\ncall keeper()\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"callee preserving rsp keeps the fact",callee_keeps,3,3,3);
  /* The ABI argument is only as good as the check behind it, so the callee is
        read in its body too and not only in its declaration: this one pushes and
        returns without popping, declares rbx and never rsp, and the body half is
        what catches it. The body half over-approximates, a push paired with a
        pop is still read as maybe-moving, exactly as 8.3 froze it for
        call_contracts. */
  const char*callee_sneaky="module m\ntarget x86_64-nexora-none\nsection .text {\nfn sneaky()->u64\neffects {changes_flags}\nclobbers {rbx} {\npush rbx\nreturn 0\n}\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\ncall sneaky()\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"callee body displacement is read",callee_sneaky,326,"wants",2,4,0);
  /* ---- A repeated align_stack is not a no-op. It displaces downward a second
        time, so it opens a second pending displacement even when the fact it
        produces is the stronger one, and after a form that killed the fact it
        rebuilds that fact from nothing. ---- */
  const char*repeat_weak="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npush rbx\nalign_stack 4\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"second align_stack 4 is a fresh fact",repeat_weak,326,"wants",2,4,0);
  const char*repeat_strong="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npush rbx\nalign_stack 16\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"second align_stack 16 rebuilds the fact",repeat_strong,2,2,2);
  /* ---- The invalidation flows through the branch merge, and the merge must
        stay conservative in both directions: one displacing arm is enough to
        lose the fact, and two inert arms must not. ---- */
  const char*branch_push="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nif feature(sse2) {\npush rbx\n} else {\nnop\n}\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"one displacing arm loses the fact",branch_push,326,"wants",2,4,0);
  const char*branch_nop="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nif feature(sse2) {\nnop\n} else {\nnop\n}\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"two inert arms keep the fact",branch_nop,2,2,2);
  /* ---- The compensation obligation is untouched by the new rule. Killing the
        fact is not paying for the displacement: pushfq and popfq move rsp
        between them and still leave it pending, so 364 reason 4 fires at the
        return and reason 5 at a terminal transfer. ---- */
  const char*pushfq_unpaid="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),privileged,changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npushfq\npopfq\nreturn 0\n}\n}\n";span(&image,"pushfq popfq is not a compensation",pushfq_unpaid,364,"return",1,4,16);
  const char*popfq_unpaid="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),privileged,changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npopfq\nreturn 0\n}\n}\n";span(&image,"popfq is not a compensation",popfq_unpaid,364,"return",1,4,16);
  const char*pushfq_ud2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {reads_mem(kernel),privileged,no_return}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\npushfq\nud2\n}\n}\n";span(&image,"pushfq before ud2 stays reason 5",pushfq_ud2,364,"ud2",1,5,16);
  /* ---- A4 consequences, shown rather than assumed. The section 10 rows for
        the two statement forms are now read from the statement table, so the
        three cases below are the consequences of those rows and they are the
        reason the rows are not decoration.

        First, a requires {stack_aligned(16)} discharged by a body that ends
        in a return statement. The return is row 7: it displaces and restores
        nothing, so the displacement align_stack opened is still pending when
        control leaves and 364 reason 4 fires at the return, naming the return
        statement and not the align_stack. This is the same verdict the
        return-with-a-pending-displacement case above already reaches, and it
        is now reached THROUGH the statement table. */
  const char*a4_return_debt="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nreturn 0\n}\n}\n";span(&image,"A4 return statement pays no pending debt",a4_return_debt,364,"return",1,4,16);
  /* The same body with the debt paid first is accepted, so the return is not
     the thing being refused: the pending displacement is. */
  const char*a4_return_paid="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"A4 return statement after the debt is paid",a4_return_paid,1,1,1);
  /* Second, a requires {stack_aligned(16)} discharged by a body with a call
        to a callee that returns. The call is row 8: it displaces and the ABI
        restores it, so the fact survives and the second call discharges. A
        walk that spent the fact on the displacement alone would refuse this
        with 326, and the gate case below is the negative of exactly that. */
  const char*a4_call_survives="module m\ntarget x86_64-nexora-none\nsection .text {\nfn quiet()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\ncall quiet()\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"A4 call statement keeps the fact",a4_call_survives,3,3,3);
  /* And the callee that does move the stack ends it, which is the check
        behind row 8: a callee whose body displaces rsp without declaring it
        is the one case where the ABI argument does not hold. */
  const char*a4_call_mover="module m\ntarget x86_64-nexora-none\nsection .text {\nfn sneaky()->u64\neffects {changes_flags}\nclobbers {rbx} {\npush rbx\nreturn 0\n}\nfn wants()->u64\neffects {}\nclobbers {}\nrequires {stack_aligned(16)} {\nreturn 0\n}\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp,rbx} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\ncall sneaky()\ncall wants()\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n";span(&image,"A4 call statement to a stack mover loses the fact",a4_call_mover,326,"wants",2,4,0);
  /* ---- Parity of the frozen footprint table. control_flow cannot import the
        table body_clobbers reads, because the return_types gate compiles
        control_flow.nova without body_clobbers.nova in the image. Every form
        below is therefore put to both modules over a one instruction body
        declaring clobbers {}, and the two must answer the same question: does
        the 17.4 footprint of this mnemonic include the stack family, family 5,
        bit 16. The first argument is the answer the frozen table gives, read
        here and not from either module; a private table that drifts away from
        the one body_clobbers reads fails on the disagreeing form instead of
        quietly refusing or quietly accepting. ---- */
  /* the writes_first row, both directions of the operand, and the two operand
     form of xchg. */
  parityF(&image,"parity mov rsp","mov rsp,rbx",FR2("mov",orx_reg(4,64),orx_reg(3,64)));
  parityF(&image,"parity mov rbx","mov rbx,rsp",FR2("mov",orx_reg(3,64),orx_reg(4,64)));
  parityF(&image,"parity mov rbx rcx","mov rbx,rcx",FR2("mov",orx_reg(3,64),orx_reg(1,64)));
  parityF(&image,"parity mov rsp immediate","mov rsp,1",FR2("mov",orx_reg(4,64),orx_imm(1)));
  parityF(&image,"parity load rsp","load rsp,[gs:kernel_rsp]:ptr<kernel,u64>",FR2("load",orx_reg(4,64),orx_mem(64)));
  /* movzx widens, so the encoder needs a source narrower than the destination
     (x64.c:503) and the fixture spelling movzx rsp,rbx is not encodable; the
     query asks the admissible 8 bit source form, and the family it names is the
     same. */
  parityF(&image,"parity movzx rsp","movzx rsp,rbx",FR2("movzx",orx_reg(4,64),orx_reg(3,8)));
  /* lea writes its first operand and the encoder admits only a memory source
     there (x64.c:173), so the fixture spelling lea rsp,rbx is not encodable and
     the query asks the admissible form. The rule the row rests on is "lea
     writes its first operand", and the family it names does not depend on the
     source. */
  parityF(&image,"parity lea rsp","lea rsp,rbx",FR2("lea",orx_reg(4,64),orx_mem(64)));
  parityF(&image,"parity not rsp","not rsp",FR1("not",orx_reg(4,64)));
  parityF(&image,"parity xchg rsp first","xchg rsp,rbx",FR2("xchg",orx_reg(4,64),orx_reg(3,64)));
  parityF(&image,"parity xchg rsp second","xchg rbx,rsp",FR2("xchg",orx_reg(3,64),orx_reg(4,64)));
  parityF(&image,"parity xchg neither","xchg rbx,rcx",FR2("xchg",orx_reg(3,64),orx_reg(1,64)));
  /* pop writes the fixed stack family whatever it names, so every pop is a
      write of it and only pop rsp is a compensation. A destination that is
      no register at all, pop 1, is deliberately not probed: there the answer
      is decided by the 336 rule of body_clobbers and by
      register_widths.family, not by the table, and control_flow can import
      neither register_widths nor the rule. That residual is stated in the
      lot report, not asserted here. */
  parityF(&image,"parity pop rsp","pop rsp",FR1("pop",orx_reg(4,64)));
  parityF(&image,"parity pop rbx","pop rbx",FR1("pop",orx_reg(3,64)));
  parityF(&image,"parity pop r12","pop r12",FR1("pop",orx_reg(12,64)));
  /* push writes the same fixed family and no operand at all, which is why it
      displaces the stack instead of restoring it. */
  parityF(&image,"parity push rsp","push rsp",FR1("push",orx_reg(4,64)));
  parityF(&image,"parity push rbx","push rbx",FR1("push",orx_reg(3,64)));
  parityF(&image,"parity push immediate","push 1",FR1("push",orx_imm(1)));
  /* ---- The whole x64.c:942 member, swept against nt_x64_effects in one
        place, plus iretq from its own branch and sysretq as the negative the
        oracle answers with no GPR write. Every expectation is derived: the
        third word of the probe is compared with the rsp family bit the oracle
        publishes for that exact form, so a table that charges a form the
        oracle does not, or misses one it does, fails here.

       The two forms the grammar cannot spell as a kind 32 instruction used to
       be put to the instruction probe here and were required to produce the
       800 of a body holding no such instruction. That measured a real thing
       and it is still measured, one line lower, but it is no longer the
       whole of the evidence: return and call now have rows of the 17.4
       table, reached on the node kinds the parser really gives them, and
       statementF asks them directly. The oracle masks for the two are no
       longer printed as an unreachable number, they are compared. ---- */
  memberF(&image,"push rbx","push rbx",FR1("push",orx_reg(3,64)),1);
  memberF(&image,"pushfq","pushfq",FR0("pushfq"),1);
  memberF(&image,"pop rbx","pop rbx",FR1("pop",orx_reg(3,64)),1);
  memberF(&image,"popfq","popfq",FR0("popfq"),1);
  memberF(&image,"ret","ret",FR0("ret"),1);
  statementF(&image,"statement return","return 0",FR0("return"),0);
  statementF(&image,"statement call","call g()",FR1("call",orx_rel()),1);
  memberF(&image,"iretq","iretq",FR0("iretq"),1);
  memberF(&image,"sysretq","sysretq",FR0("sysretq"),1);
  /* The instruction probe is still asked about the two statement forms and
     must still answer 800, because that is the structural fact the two
     tables are compared through: a return and a call are node kinds 29 and
     28, so the instruction path is not asked about them however the
     statement path is. A probe that started answering for them would mean
     only_instruction had learned to see statements, and the two paths would
     no longer be independent. */
  memberF(&image,"return 0","return 0",FR0("return"),0);
  memberF(&image,"call g()","call g()",FR1("call",orx_rel()),0);
  /* the two fixed forms that answer differently: iretq is charged the stack
     family, sysretq is charged no GPR at all. */
  parityF(&image,"parity iretq","iretq",FR0("iretq"));
  parityF(&image,"parity sysretq","sysretq",FR0("sysretq"));
  parityF(&image,"parity syscall","syscall",FR0("syscall"));
  parityF(&image,"parity rdtsc","rdtsc",FR0("rdtsc"));
  parityF(&image,"parity cpuid","cpuid",FR0("cpuid"));
  parityF(&image,"parity rdmsr","rdmsr",FR0("rdmsr"));
  /* read_cr and in are probed over their register first spelling, the order
     x64.c:475 takes for read_cr, so the two names name one rule. */
  parityF(&image,"parity read_cr","read_cr rax",FR2("read_cr",orx_reg(0,64),orx_cr(0)));
  parityF(&image,"parity in","in rax,dx",FR2("in",orx_reg(0,32),orx_reg(2,16)));
  /* the refused pseudo-op, the label free name and the forms outside the
      frozen set, which write nothing and can never be a compensation. */
  parityF(&image,"parity leave","leave",FR0("leave"));
  parityF(&image,"parity enter","enter",FR0("enter"));
  parityF(&image,"parity nop","nop",FR0("nop"));
  parityF(&image,"parity cmp","cmp rsp,rbx",FR2("cmp",orx_reg(4,64),orx_reg(3,64)));
  parityF(&image,"parity test","test rbx,rcx",FR2("test",orx_reg(3,64),orx_reg(1,64)));
  parityF(&image,"parity jmp","jmp done\ndone:",FR1("jmp",orx_rel()));
  parityF(&image,"parity jcc","je done\ndone:",FR1("je",orx_rel()));
  parityF(&image,"parity unknown","frobnicate rbx",FR1("frobnicate",orx_reg(3,64)));
  /* ---- The invalidation table itself, row by row: displaces_stack, the
        compensation witness replaces_stack, and the 17.4 footprint question
        writes_stack. The third is derived from nt_x64_effects, and it
        disagrees on purpose with the first two for the four forms the frozen
        table has no row for, which is why the fact cannot be derived from
        writes_stack. ---- */
  displacementF(&image,"displace mov rsp","mov rsp,rbx",FR2("mov",orx_reg(4,64),orx_reg(3,64)),1,1);
  displacementF(&image,"displace mov rbx","mov rbx,rsp",FR2("mov",orx_reg(3,64),orx_reg(4,64)),0,0);
  displacementF(&image,"displace xchg rsp","xchg rsp,rbx",FR2("xchg",orx_reg(4,64),orx_reg(3,64)),1,1);
  displacementF(&image,"displace xchg neither","xchg rbx,rcx",FR2("xchg",orx_reg(3,64),orx_reg(1,64)),0,0);
  displacementF(&image,"displace pop rsp","pop rsp",FR1("pop",orx_reg(4,64)),1,1);
  displacementF(&image,"displace pop rbx","pop rbx",FR1("pop",orx_reg(3,64)),1,0);
  displacementF(&image,"displace push rbx","push rbx",FR1("push",orx_reg(3,64)),1,0);
  /* pushfq, popfq and ret displace the pointer and write the stack family
     without giving the entry pointer back, which is exactly the push row: the
     third word is now derived from nt_x64_effects and is 1 for all three, so
     these three rows are ordinary rows of the table and no longer a measured
     disagreement with the oracle. displaces_stack and replaces_stack stay
     literals of this pass's own rules. */
  displacementF(&image,"displace pushfq","pushfq",FR0("pushfq"),1,0);
  displacementF(&image,"displace popfq","popfq",FR0("popfq"),1,0);
  displacementF(&image,"displace ret","ret",FR0("ret"),1,0);
  displacementF(&image,"displace sysretq","sysretq",FR0("sysretq"),1,0);
  displacementF(&image,"displace iretq","iretq",FR0("iretq"),1,1);
  displacementF(&image,"displace leave","leave",FR0("leave"),0,0);
  displacementF(&image,"displace cmp","cmp rsp,rbx",FR2("cmp",orx_reg(4,64),orx_reg(3,64)),0,0);
  displacementF(&image,"displace nop","nop",FR0("nop"),0,0);
  /* ---- The value of align_stack, bound to the C oracle.

     spec/ntasm/ntasm.md 10 and 17.5 left the VALUE of the alignment open and
     MEM.md recorded that align_stack N "is a silent no-op today". Both are
     wrong, and the sweep below is the measurement. The accepted set is
     {1,2,4,8,16} and it is the same set in three independent readers:
     control_flow.nova:886-887, call_contracts.nova:1071, and the C oracle at
     frontend.c:1401-1402. Every value is classified by the oracle's own two
     answers rather than by a literal written here, so the sweep covers the
     boundaries that decide the set -- 1, the powers of two the ABI stops at,
     the first power of two above it, the values that are not powers of two at
     all, and 4096 where the oracle stops accepting a declaration. ---- */
  ceiling_value(&image,"ceiling",16);
  ceiling(&image,"ceiling 1",1);
  ceiling(&image,"ceiling 2",2);
  ceiling(&image,"ceiling 4",4);
  ceiling(&image,"ceiling 8",8);
  ceiling(&image,"ceiling 16",16);
  ceiling(&image,"ceiling 32",32);
  ceiling(&image,"ceiling 64",64);
  ceiling(&image,"ceiling 128",128);
  ceiling(&image,"ceiling 512",512);
  ceiling(&image,"ceiling 4096",4096);
  ceiling(&image,"ceiling 0",0);
  ceiling(&image,"ceiling 3",3);
  ceiling(&image,"ceiling 5",5);
  ceiling(&image,"ceiling 6",6);
  ceiling(&image,"ceiling 7",7);
  ceiling(&image,"ceiling 12",12);
  ceiling(&image,"ceiling 15",15);
  ceiling(&image,"ceiling 17",17);
  ceiling(&image,"ceiling 24",24);
  ceiling(&image,"ceiling 1000",1000);
  /* The same values again, now asserting WHICH refusal the pass names and not
     only that it refuses. 0, 3, 5 and 1000 are not values the language can
     state at all, so reason 1; 32, 128 and 4096 are values the language can
     state and that no caller can discharge, so reason 2; 16 is the strongest
     value the ABI proves, so it is accepted. */
  alignment_reason(&image,"reason 0",0,1);
  alignment_reason(&image,"reason 3",3,1);
  alignment_reason(&image,"reason 5",5,1);
  alignment_reason(&image,"reason 1000",1000,1);
  alignment_reason(&image,"reason 32",32,2);
  alignment_reason(&image,"reason 128",128,2);
  alignment_reason(&image,"reason 4096",4096,2);
  alignment_reason(&image,"reason 16",16,0);
  /* And the one value where the two classifications part company. 8192 is a
     power of two, so control_flow's reason 1 does not fire and it reports
     reason 2, the ABI ceiling. The oracle stops at the declaration instead,
     because its declaration test also bounds N by 4096, so it would call the
     same value an invalid predicate. Both refuse, so this is a naming gap and
     not a soundness gap, and it is pinned here so that a future reason 1 that
     grows a bound of its own is a deliberate change rather than a drift. */
  {
    static const unsigned above[]={8192,65536};
    for(unsigned k=0;k<sizeof above/sizeof*above;k++){
      char s[1024];
      snprintf(s,sizeof s,"module m\ntarget x86_64-nexora-none\nsection .text {\n"
        "fn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\n"
        "load rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack %u\n"
        "load rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nreturn 0\n}\n}\n",above[k]);
      Run r=run(&image,"ceiling loop",s,4,0);
      uint64_t declared=oracle_declares(above[k]);
      cases++;checks++;
      if(r.returned!=364||r.out[2]!=2||declared!=0){
        failures++;fprintf(stderr,"FAIL above ceiling N=%u reason=%llu declares=%llu\n",
          above[k],(unsigned long long)r.out[2],(unsigned long long)declared);}
    }
  }

  /* ---- The A4 reserve, measured in full: the EXACT registers_written of the
        five forms the 17.4 fixed-footprint table does not name.

        The reserve is stated at spec/ntasm/ntasm.md 17.4 and docs/status/ntasm-completion.md
        A4: the table omits five forms the reference charges with a write to
        rsp -- pushfq, popfq, ret, return, call -- and no v0 pass reads the
        list. This block is the measurement the reserve says is missing, and
        it is deliberately NOT the parity probe above. The parity probe asks
        bit 4 and answers it; what it cannot do is publish the exact mask, and
        the exact mask is where the reserve's own figure was wrong: popfq is
        0x20010, not 0x10, because x64.c:1069-1074 ORs bit 17 (RFLAGS) into
        registers_written for every form that writes flags and x64.c:956 gives
        popfq the arithmetic set. Every value below comes from a4_written, which
        is the whole 64 bit mask; nothing here is written by hand.

        The expected column is NOT a literal. It is derived: the GPR part must
        be the 1<<4 the oracle member gives (x64.c:942-944), which is the claim
        under test, and the non-family part is whatever the oracle publishes
        and is therefore printed rather than asserted. Asserting popfq == 0x10
        would re-freeze the very error this block exists to catch. ---- */
  {
    /* The five, at the exact operand shape the grammar spells for each. return
       and call are node kinds 29 and 28, so their operand list is a property
       of the oracle and not of the Nova AST; the table is asked over the shape
       the oracle admits. */
    /* Not static: FR1 builds its operand array with a compound literal, which
       is not a constant expression, so a static initializer would not
       compile. The operands are read-only after this. */
    const struct{const char*name;Form form;const char*shape;}five[]={
      {"pushfq",FR0("pushfq"),"FR0"},
      {"popfq", FR0("popfq"), "FR0"},
      {"ret",   FR0("ret"),   "FR0"},
      {"return",FR0("return"),"FR0"},
      {"call",  FR1("call",orx_rel()),"FR1(REL)"},
    };
    for(unsigned k=0;k<sizeof five/sizeof*five;k++){
      const NtX64Operand*o=five[k].form.ops;unsigned n=five[k].form.count;
      uint64_t full=a4_written(five[k].form.name,o,n);
      uint64_t gpr=a4_gpr(five[k].form.name,o,n);
      uint64_t non=a4_nonfamily(five[k].form.name,o,n);
      cases++;checks++;
      if(full==A4_NO){
        failures++;
        fprintf(stderr,"FAIL a4 exact %s the oracle refuses the form, so the "
                "measurement is of nothing\n",five[k].name);
        continue;}
      /* The claim under test, derived from the member: every form of
         push|pushfq|pop|popfq|ret|return|call is charged 1<<4 and nothing
         else among the sixteen families. */
      if(gpr!=(UINT64_C(1)<<4)){
        failures++;
        fprintf(stderr,"FAIL a4 exact %s gpr=0x%04llx want 0x0010 (the 1<<4 "
                "x64.c:942-944 gives the whole member)\n",five[k].name,
                (unsigned long long)gpr);
        continue;}
      printf("A4-EXACT form=%-7s shape=%-9s registers_written=0x%04llx "
             "gpr=0x%04llx non_family_bits=0x%llx\n",five[k].name,five[k].shape,
             (unsigned long long)full,(unsigned long long)gpr,
             (unsigned long long)non);
    }
  }

  /* The same five over the operand shapes the oracle also admits, because the
     omission must not depend on which call form is spelled. call over a
     register target publishes the same 0x10 and reads one more family. ---- */
  {
    /* The two operand shapes of call the oracle admits. Held in named locals
       because a compound literal is not a constant expression and this
       harness compiles with -Werror. */
    const NtX64Operand rel[]={orx_rel()};
    const NtX64Operand reg[]={orx_reg(3,64)};
    uint64_t rel_rw=a4_written("call",rel,1);
    uint64_t reg_rw=a4_written("call",reg,1);
    cases++;checks++;
    if(a4_gpr("call",rel,1)!=(UINT64_C(1)<<4)
       ||a4_gpr("call",reg,1)!=(UINT64_C(1)<<4)
       ||(rel_rw&~A4_GPR)||(reg_rw&~A4_GPR)){
      failures++;
      fprintf(stderr,"FAIL a4 call shapes rel=0x%llx reg=0x%llx\n",
        (unsigned long long)rel_rw,(unsigned long long)reg_rw);}
    else
      printf("A4-EXACT-SHAPES call-rel=0x%04llx call-reg=0x%04llx agree=1\n",
        (unsigned long long)rel_rw,(unsigned long long)reg_rw);
  }

  /* ---- THE STRUCTURAL CLAIM, and it is false. The reserve reads as though a
        footprint table could not carry these five because a declared footprint
        is computed from an operand list, a zero-operand form has an operand
        list of zero, and zero cannot express a stack write. The table is keyed
        on the MNEMONIC, not on an operand list, so that is not a constraint --
        and the reference itself demonstrates it, publishing 1<<4 for a
        zero-operand form over a zero-operand form. The block below is the
        falsification attempt: every zero-operand form the oracle admits, with
        the exact mask it publishes. A single nonzero one refutes the claim. */
  {
    static const char*const zero[]={
      "nop","pause","lfence","sfence","mfence","ud2","cli","sti","hlt",
      "swapgs","rdtsc","rdmsr","cpuid","syscall","sysretq","iretq",
      "pushfq","popfq","ret","return","cbw","cwde","cdqe","cwd","cdq","cqo",
      "leave","enter"};
    unsigned z,admitted=0,charged=0,unnamed=0;
    for(z=0;z<sizeof zero/sizeof*zero;z++){
      uint64_t full=a4_written(zero[z],NULL,0);
      uint64_t gpr;
      cases++;checks++;
      if(full==A4_NO){printf("A4-ZERO form=%-8s admitted=no\n",zero[z]);continue;}
      admitted++;gpr=full&A4_GPR;
      if(gpr)charged++;
      /* Which of these the 17.4 fixed-footprint table names, DERIVED from the
         table itself (see named_174). The counter answers "how many charged
         forms the document does not name", so it is a number about the
         DOCUMENT: naming one more form in 17.4 must make it go DOWN. It went
         up under the previous literal, and it went up because the literal had
         stopped being the table. */
      if(gpr&&!named_174(zero[z]))unnamed++;
      printf("A4-ZERO form=%-8s admitted=yes registers_written=0x%llx gpr=0x%04llx\n",
        zero[z],(unsigned long long)full,(unsigned long long)gpr);
    }
    /* What the derived check read, printed so the number above is never read
       alone. rows= is the document's own row count for this table, not a
       constant: it moves when the document moves. */
    printf("A4-SPEC-174 tables=%u rows=%u named_and_charged=%u dropped=%u "
           "truncated=%u readable=%u\n",s174.tables,s174.n,charged-unnamed,
           s174.dropped,s174.truncated,(unsigned)s174.ok);
    /* Two controls, because an instrument that reads nothing and an instrument
       that reads everything both print plausible numbers.
       (1) The read itself. A section that moved, a header reworded, a name too
           long for the buffer: each of those makes named_174 answer "not
           named" for every form, and the summary would then read as the
           document's deficiency. It is this gate's own blindness instead, and
           it must be a FAILURE. */
    checks++;
    if(!s174.ok){
      failures++;
      fprintf(stderr,"FAIL a4 spec 17.4 read: rows=%u dropped=%u truncated=%u "
              "-- the table was not found or not read whole, so unnamed_by_17.4 "
              "would be this gate's blindness and not the document's\n",
              s174.n,s174.dropped,s174.truncated);}
    checks++;
    if(s174.tables!=1){
      failures++;
      fprintf(stderr,"FAIL a4 spec 17.4: %u tables in the section carry the "
              "`formes` + `registers_written` header, and exactly one must\n",
              s174.tables);}
    /* (2) The derivation is non-vacuous: a read that credits this document
         with none of the forms it demonstrably charges would also satisfy (1). */
    checks++;
    if(charged>0&&charged-unnamed==0){
      failures++;
      fprintf(stderr,"FAIL a4 spec 17.4 credits none of the %u charged forms: "
              "the derivation reads but names nothing\n",charged);}
    printf("A4-ZERO-SUMMARY listed=%u admitted=%u charged_nonzero_gpr=%u "
           "unnamed_by_17.4=%u\n",(unsigned)(sizeof zero/sizeof*zero),admitted,
           charged,unnamed);
    /* The falsification itself, asserted. An empty class would make the claim
       this block refutes vacuously true, which is the state an instrument must
       never be left in -- the rule this project has been burned by five times
       in three days. */
    checks++;
    if(charged==0){
      failures++;
      fprintf(stderr,"FAIL a4 zero class is empty: the claim under test has "
              "become vacuously true\n");}
  }

  /* ---- THE REAL LIMIT, which is not the table. Two of the five cannot be
        reached by an instruction table at all: a return is node kind 29 and a
        call is node kind 28 (parser.nova:362-368, :370-374), so no body ever
        holds either as the kind 32 instruction an instruction table is keyed
        on. That is a fact about the AST, and the fix is a second declaration
        site reached on those kinds -- which is what the mode 5 statement probe
        above already exercises. So the reserve is a five-row fix for three of
        the five and a second declaration site for two, and NOT a design
        change. ---- */
  {
    uint64_t ret_gpr=a4_gpr("ret",NULL,0);
    uint64_t rets=stack_family("ret",NULL,0);
    cases++;checks++;
    if(ret_gpr!=(UINT64_C(1)<<4)||rets!=1){
      failures++;
      fprintf(stderr,"FAIL a4 ret gpr=0x%llx parity=%llu\n",
        (unsigned long long)ret_gpr,(unsigned long long)rets);}
    else
      printf("A4-AST ret=kind32-reachable-else-statement gpr=0x%04llx "
             "return=kind29 call=kind28\n",(unsigned long long)ret_gpr);
  }

  /* ---- The negative, so the block above is not vacuous: sysretq is the one
        form of the neighbourhood the oracle charges NO GPR write to
        (x64.c:1032-1036, it reads rcx and r11 and writes nothing), and a
        sweep that answered 0x10 for everything would get it wrong. Its bit 17
        is real and is not a GPR write, which is why the split above exists. */
  {
    uint64_t gpr=a4_gpr("sysretq",NULL,0);
    uint64_t non=a4_nonfamily("sysretq",NULL,0);
    cases++;checks++;
    if(gpr!=0||non==0){
      failures++;
      fprintf(stderr,"FAIL a4 sysretq gpr=0x%llx non_family=0x%llx want 0 and "
              "nonzero\n",(unsigned long long)gpr,(unsigned long long)non);}
    else
      printf("A4-NEGATIVE sysretq gpr=0x%04llx non_family_bits=0x%llx "
             "writes_no_gpr=1\n",(unsigned long long)gpr,(unsigned long long)non);
  }

}/* ---- the three programs the invalidation core is proved on. P is the
 * production defect: the caller overwrites the register its own parameter
 * arrived in and then calls a callee that requires non_null of it. Q is the
 * one-armed branch, which is the only program that can tell the MEET from the
 * SPEND: a fact invalidated but lost at the join is a fact that never existed,
 * so proving the spend without the join proves half a rule. R and Q2 are the
 * two controls, and without them a rule that killed every fact would be green.
 */
const char*fact_p="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants(in p:u64 @rcx)->u64\neffects {}\nclobbers {}\nrequires { non_null(p) } {\nreturn p\n}\nfn caller(in p:u64 @rcx)->u64\neffects {}\nclobbers {rax}\nrequires { non_null(p) } {\nmov rcx, 7\ncall wants(p)\nmov rax, 0\nreturn rax\n}\n}\n";
const char*fact_r="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants(in p:u64 @rcx)->u64\neffects {}\nclobbers {}\nrequires { non_null(p) } {\nreturn p\n}\nfn caller(in p:u64 @rcx)->u64\neffects {}\nclobbers {rax}\nrequires { non_null(p) } {\nmov rax, p\ncall wants(p)\nreturn rax\n}\n}\n";
const char*fact_q="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants(in p:u64 @rcx)->u64\neffects {}\nclobbers {}\nrequires { non_null(p) } {\nreturn p\n}\nfn caller(in p:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {rax}\nrequires { non_null(p) } {\nif feature(sse2) {\nmov rcx, 7\n} else {\nmov rax, 0\n}\ncall wants(p)\nreturn rax\n}\n}\n";
const char*fact_q2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn wants(in p:u64 @rcx)->u64\neffects {}\nclobbers {}\nrequires { non_null(p) } {\nreturn p\n}\nfn caller(in p:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {rax}\nrequires { non_null(p) } {\nif feature(sse2) {\nmov rax, 0\n} else {\nmov rax, 1\n}\ncall wants(p)\nreturn rax\n}\n}\n";
if(image.memory){
  fact1(&image,"P the fact is false before the call",fact_p,2,0);
  fact1(&image,"R no write keeps it",fact_r,2,1);
  fact1(&image,"Q one arm spends it and the join keeps the loss",fact_q,2,0);
  fact1(&image,"Q2 two inert arms keep it",fact_q2,2,1);
}
if(image.memory){ng_parity_finish(&ng_parity,&failures);nova_host_unmap(&image);}if(compiled)nt_artifact_free(&a);for(unsigned i=0;i<14;i++)free(sources[i]);printf("NTASM_NOVA_CONTROL_FLOW checks=%u failures=%u cases=%u oracle_divergences=%u\n",checks,failures,cases,gaps);return failures?1:0;}
