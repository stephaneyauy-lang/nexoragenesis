#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntasm_pipeline_parity.h"
#include "../../../compiler/c/ntasm/backend/x64.h"

/* ====================== pipeline parity ==============================
   Every non zero code this gate asserts is a CLAIM ABOUT the 34 stage
   pipeline of validate.nova, and this entry compiles a SUB-CHAIN of it:
   index, callable_names, effects, body_intrinsics.  Nothing measured that claim until the shared helper
   nova/ntasm_pipeline_parity.h ran every source of this file through the
   41 module validate image as well and compared the two verdicts.  The
   table beneath is the set of (this gate, the pipeline) divergence pairs
   this file exhibits, written down from that measurement: a pair that is
   not listed fails the gate, and a listed pair that stops occurring fails
   it too, so the table cannot rot into a comment. */
static const NgParityPair ng_parity_pairs[]={{0,0}};
static NgParitySpec ng_parity={
  "body_intrinsics",
  {"index","callable_names","effects","body_intrinsics"},4,
  1,
  ng_parity_pairs,0,
  0,0,0,0,0,0,0,0,NULL};
static char ng_parity_err[256];
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[4];}Run;static Run run(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");ng_parity_check(&checks,&failures,&ng_parity,n,s,r.returned);return r;}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t f,uint64_t c,uint64_t v){Run r=run(i,n,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=f||r.out[1]!=c||r.out[2]!=v||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu\n",n,(unsigned long long)r.returned);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t missing){Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=334||r.runtime||r.out[0]==guard||r.out[1]==guard||r.out[2]!=1||r.out[3]!=missing){failures++;fprintf(stderr,"FAIL err %s ret=%llu miss=%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[3]);}}
static void bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run(i,n,s,words);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL invalid %s\n",n);}}
/* One based line and column of the nth occurrence of needle, derived from the
   source text alone, so every span case asserts the reported position without
   reading it back from the pass under test. */
static void where(const char*s,const char*needle,int nth,uint64_t*line,uint64_t*column){uint64_t ln=1,col=1;int seen=0;size_t n=strlen(needle);const char*p=s;if(nth<1)return;for(;;){if(*p=='\0')break;if(*p=='\n'){ln++;col=1;p++;continue;}if(strncmp(p,needle,n)==0&&(seen++==nth-1)){*line=ln;*column=col;return;}col++;p++;}}
/* 334 at a needle: the instruction position, category 1 and the missing atom
   bitset, with the whole output checked so a wrong position cannot pass. */
static void verr(const NovaHostImage*i,const char*n,const char*s,const char*needle,int nth,uint64_t missing){uint64_t line=0,column=0;where(s,needle,nth,&line,&column);Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=334||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=1||r.out[3]!=missing){failures++;fprintf(stderr,"FAIL span %s ret=%llu want 334 at %llu,%llu miss=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)line,(unsigned long long)column,(unsigned long long)missing,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}

/* ============================ the RFLAGS channel, decided by measurement ==
   x64.c:1069-1074 ORs bit 17 into registers_written for every form that
   writes or leaves undefined a flag, and in the same breath sets
   NT_X64_EFFECT_CHANGES_FLAGS. Bit 17 is therefore not a seventeenth
   register: it is the flags channel spelled a second time. Every clobbers
   reader in the tree masks down to the sixteen families at 0xffff -- orx in
   tests_ntasm_body_clobbers.c and A4_GPR in tests_ntasm_control_flow.c -- so
   neither can see that bit, and the question this sweep answers is the only
   one that can decide whether the mask is a legitimate projection or a blind
   spot: IS the product's obligation for the flags channel the oracle's bit
   17, form for form?

   A comment asserting the answer is what the mask already had, and a comment
   cannot fail. So the two are asked over the same form and compared at run
   time. bit17 is the oracle's own tail bit, chg is the oracle's
   NT_X64_EFFECT_CHANGES_FLAGS effect, and the 334 this gate already writes
   carries the pass's demand as an atom bitset whose bit 1 is changes_flags
   (effects.nova:78). A form the oracle flags and the product does not demand
   is a blind spot and fails this gate, because nothing else in the tree could
   see it. A form the product demands and the oracle does not flag is the 8.3
   over-approximation, which costs only a refusal: it is counted and printed
   rather than failed, and a sweep that started producing them would be the
   evidence that this pass had gone conservative.

   Scope, stated so the count is not read as more than it is: one admitted
   operand list per mnemonic, covering every branch of the x64.c effects
   chain that can set a flag, plus a negative control of forms that cannot.
   It is not the whole encoder catalogue, and a form the oracle itself
   refuses is counted as unmeasured rather than quietly folded into either
   side. */
static const NtX64Context AF_CTX={NT_X64_ALL_FEATURES,0};
static NtX64Operand af_reg(unsigned r){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_REG;o.reg=r;o.width=64;return o;}
static NtX64Operand af_imm(uint64_t v){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_IMM;o.imm=v;return o;}
static unsigned af_listed,af_flagged,af_demanded,af_blind,af_over,af_unmeasured;
static void af_case(const NovaHostImage*i,const char*m,const char*spell,const NtX64Operand*ops,unsigned n){
 NtX64Effects e;memset(&e,0,sizeof e);
 af_listed++;
 if(nt_x64_effects(m,ops,n,AF_CTX,&e)!=NT_X64_OK){af_unmeasured++;
   printf("A4-FLAGS form=%-8s unmeasured: the oracle refuses this operand list, so it has no bit 17 to compare\n",m);return;}
 unsigned bit17=(unsigned)((e.registers_written>>17)&1u);
 unsigned chg=(e.effects&NT_X64_EFFECT_CHANGES_FLAGS)?1u:0u;
 char s[1024];
 snprintf(s,sizeof s,"module m\ntarget x86_64-nexora-none\nsection .text {\n"
   "fn f()->u64\neffects {}\nclobbers {} {\n%s\nreturn 0\n}\n}\n",spell);
 Run r=run(i,m,s,4);cases++;checks++;
 int demand;
 if(r.returned==0)demand=0;
 else if(r.returned==334&&r.out[2]==1)demand=(int)((r.out[3]>>1)&1u);
 else{af_unmeasured++;
   fprintf(stderr,"A4-FLAGS form=%-8s unmeasured: code %llu came from an earlier pass, not this one\n",
     m,(unsigned long long)r.returned);return;}
 if(bit17)af_flagged++;
 if(demand)af_demanded++;
 if(bit17&&!demand){af_blind++;failures++;
   fprintf(stderr,"FAIL a4 flags blind spot: the oracle writes flags for %s "
     "(registers_written=0x%05llx, CHANGES_FLAGS=1) and this pass demands no changes_flags "
     "atom. Both 0xffff masks drop the bit and no other instrument in the tree can see it, so "
     "the form would be accepted on an unchecked flags write.\n",m,(unsigned long long)e.registers_written);
   return;}
 if(!bit17&&demand)af_over++;
 printf("A4-FLAGS form=%-8s oracle_registers_written=0x%05llx oracle_CHANGES_FLAGS=%u "
   "product_demands_changes_flags=%d code=%llu missing_atoms=0x%llx verdict=%s\n",
   m,(unsigned long long)e.registers_written,chg,demand,
   (unsigned long long)r.returned,(unsigned long long)r.out[3],
   bit17?"guarded":(demand?"over-approximated":"no-flags-channel"));
}
static void af_sweep(const NovaHostImage*i){
 NtX64Operand r0=af_reg(0),r1=af_reg(1),one=af_imm(1);
 af_case(i,"add","add rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"adc","adc rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"sub","sub rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"sbb","sbb rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"and","and rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"or","or rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"xor","xor rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"cmp","cmp rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"test","test rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"inc","inc rax",(const NtX64Operand[]){r0},1);
 af_case(i,"dec","dec rax",(const NtX64Operand[]){r0},1);
 af_case(i,"neg","neg rax",(const NtX64Operand[]){r0},1);
 af_case(i,"shl","shl rax,1",(const NtX64Operand[]){r0,one},2);
 af_case(i,"shr","shr rax,1",(const NtX64Operand[]){r0,one},2);
 af_case(i,"sar","sar rax,1",(const NtX64Operand[]){r0,one},2);
 af_case(i,"rol","rol rax,1",(const NtX64Operand[]){r0,one},2);
 af_case(i,"ror","ror rax,1",(const NtX64Operand[]){r0,one},2);
 af_case(i,"imul","imul rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"mul","mul rbx",(const NtX64Operand[]){r1},1);
 af_case(i,"div","div rbx",(const NtX64Operand[]){r1},1);
 af_case(i,"idiv","idiv rbx",(const NtX64Operand[]){r1},1);
 af_case(i,"bt","bt rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"bts","bts rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"btr","btr rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"btc","btc rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"bsf","bsf rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"bsr","bsr rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"popfq","popfq",NULL,0);
 af_case(i,"syscall","syscall",NULL,0);
 af_case(i,"sysretq","sysretq",NULL,0);
 af_case(i,"iretq","iretq",NULL,0);
 /* Negative control. not is the sharp one: it shares the inc/dec/neg branch
    of x64.c and is excluded from it by a strcmp, so a predicate that matched
    the branch instead of the flags would demand an atom here. */
 af_case(i,"not","not rax",(const NtX64Operand[]){r0},1);
 af_case(i,"pushfq","pushfq",NULL,0);
 af_case(i,"nop","nop",NULL,0);
 af_case(i,"mov","mov rax,rbx",(const NtX64Operand[]){r0,r1},2);
 af_case(i,"bswap","bswap rax",(const NtX64Operand[]){r0},1);
 af_case(i,"cbw","cbw",NULL,0);
 af_case(i,"cpuid","cpuid",NULL,0);
 af_case(i,"rdtsc","rdtsc",NULL,0);
 af_case(i,"cli","cli",NULL,0);
 af_case(i,"hlt","hlt",NULL,0);
 af_case(i,"lfence","lfence",NULL,0);
 af_case(i,"swapgs","swapgs",NULL,0);
 af_case(i,"ret","ret",NULL,0);
 af_case(i,"push","push rbx",(const NtX64Operand[]){r1},1);
 printf("A4-FLAGS-SUMMARY listed=%u oracle_bit17=%u product_demands_changes_flags=%u "
   "blind_spots=%u over_approximations=%u unmeasured=%u\n",
   af_listed,af_flagged,af_demanded,af_blind,af_over,af_unmeasured);
}
int main(void){const char*paths[]={"tests/nova/tests/body-intrinsics-entry.nova","compiler/nova/analysis/abi/body_intrinsics.nova","compiler/nova/analysis/abi/effects.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[8]={0};NtFInput inputs[8];for(unsigned i=0;i<8;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<8;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,8,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");int parity=ng_parity_begin(&ng_parity,&failures,ng_parity_err,sizeof ng_parity_err);if(image.memory&&parity==0){
const char*none="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nnop\nreturn 0\n}\n}\n";ok(&image,"none",none,1,0,0);
const char*clock="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_clock}\nclobbers {rax,rdx} {\nrdtsc\nreturn 0\n}\n}\n";ok(&image,"clock",clock,1,1,1);
const char*clock_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax,rdx} {\nrdtsc\nreturn 0\n}\n}\n";err(&image,"clock missing",clock_bad,512);
const char*cli="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {privileged,interrupt_state}\nclobbers {} {\ncli\nreturn 0\n}\n}\n";ok(&image,"cli",cli,1,1,1);
const char*cli_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {interrupt_state}\nclobbers {} {\ncli\nreturn 0\n}\n}\n";err(&image,"cli privileged",cli_bad,1);
const char*syscall_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {control}\nclobbers {rcx,r11} {\nsyscall\nreturn 0\n}\n}\n";err(&image,"syscall flags",syscall_bad,2);
const char*sysret="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {privileged,changes_flags,control,no_return}\nclobbers {} {\nsysretq\n}\n}\n";ok(&image,"sysret",sysret,1,1,1);
const char*sysret_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {privileged,changes_flags,control}\nclobbers {} {\nsysretq\n}\n}\n";err(&image,"sysret no return",sysret_bad,128);
const char*msr="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {privileged,msr}\nclobbers {rax,rdx} {\nrdmsr\nreturn 0\n}\n}\n";ok(&image,"msr",msr,1,1,1);
const char*io="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {privileged,io_port}\nclobbers {rax} {\nin rax,1\nreturn rax\n}\n}\n";ok(&image,"io",io,1,1,1);
const char*add="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rax)->u64\neffects {changes_flags}\nclobbers {r10} {\nadd r10,rax\nreturn r10\n}\n}\n";ok(&image,"add flags",add,1,1,1);
const char*add_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rax)->u64\neffects {}\nclobbers {r10} {\nadd r10,rax\nreturn r10\n}\n}\n";err(&image,"add missing",add_bad,2);
const char*compare="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rax,in y:u64 @rbx)->u64\neffects {changes_flags}\nclobbers {} {\ncmp rax,rbx\nreturn 0\n}\n}\n";ok(&image,"cmp flags",compare,1,1,1);
const char*shift_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rax)->u64\neffects {}\nclobbers {rax} {\nshl rax,1\nreturn rax\n}\n}\n";err(&image,"shift missing",shift_bad,2);
const char*mov="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rbx)->u64\neffects {}\nclobbers {rax} {\nmov rax,rbx\nreturn rax\n}\n}\n";ok(&image,"mov no flags",mov,1,0,0);
const char*pushfq="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\npushfq\nreturn 0\n}\n}\n";ok(&image,"pushfq no contract",pushfq,1,0,0);
const char*popfq="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {privileged,changes_flags}\nclobbers {} {\npopfq\nreturn 0\n}\n}\n";ok(&image,"popfq declared",popfq,1,1,1);
const char*popfq_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\npopfq\nreturn 0\n}\n}\n";err(&image,"popfq missing",popfq_bad,3);
const char*popfq_flags="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\npopfq\nreturn 0\n}\n}\n";err(&image,"popfq privileged",popfq_flags,1);
const char*xchg="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rax,in y:u64 @rcx)->u64\neffects {}\nclobbers {rax,rcx} {\nxchg rax,rcx\nreturn rax\n}\n}\n";ok(&image,"xchg no flags",xchg,1,0,0);
 // A label definition shares node kind 32 with an instruction but carries
 // aux 1, so a label named rdtsc or add declares no effect.
 const char*rdtsc_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nrdtsc:\nreturn 0\n}\n}\n";ok(&image,"rdtsc label",rdtsc_label,1,0,0);
 const char*add_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rax)->u64\neffects {}\nclobbers {} {\nadd:\nreturn 0\n}\n}\n";ok(&image,"add label",add_label,1,0,0);
 /* ---- align_stack, spec/ntasm/ntasm.md 10. The node is kind 45, not the kind 32 an
    instruction carries, so a pass that only reads kind 32 checked it for no
    atom at all: effects {} on a checked stack adjustment was accepted. The
    only atom provable from the tree is changes_flags, bit 2. */
 const char*align_missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp} {\nalign_stack 16\nreturn 0\n}\n}\n";verr(&image,"align_stack missing",align_missing,"align_stack",1,2);
 const char*align_declared="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {rsp} {\nalign_stack 16\nreturn 0\n}\n}\n";ok(&image,"align_stack declared",align_declared,1,1,1);
 const char*align_partial="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel)}\nclobbers {rsp} {\nalign_stack 16\nreturn 0\n}\n}\n";verr(&image,"align_stack reads_mem only",align_partial,"align_stack",1,2);
 const char*align_with_load="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_mem(kernel),changes_flags}\nclobbers {rsp} {\nload rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\nreturn 0\n}\n}\n";ok(&image,"align_stack with load",align_with_load,1,1,1);
 const char*align_nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {rsp} {\nif feature(sse2) {\nalign_stack 16\n} else {\nnop\n}\nreturn 0\n}\n}\n";ok(&image,"align_stack nested",align_nested,1,1,1);
 const char*align_nested_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp} {\nif feature(sse2) {\nalign_stack 16\n} else {\nnop\n}\nreturn 0\n}\n}\n";verr(&image,"align_stack nested missing",align_nested_bad,"align_stack",1,2);
 const char*align_twice="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {rsp} {\nalign_stack 16\nalign_stack 8\nreturn 0\n}\n}\n";ok(&image,"align_stack twice",align_twice,1,2,2);
 const char*align_iretq="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {privileged,changes_flags,control,no_return}\nclobbers {rsp} {\nalign_stack 16\niretq\n}\n}\n";ok(&image,"align_stack iretq",align_iretq,1,2,2);
 /* align_stack is keyword 77, so a label cannot be spelled that way: the
    parser takes the align_stack branch and asks for an integer literal. The
    label that can sit next to it still carries aux 1 and declares no atom. */
 const char*align_label_after="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {rsp} {\nalign_stack 16\nrestore:\nreturn 0\n}\n}\n";ok(&image,"align_stack label after",align_label_after,1,1,1);
 const char*align_label_before="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {rsp} {\nrestore:\nalign_stack 16\nreturn 0\n}\n}\n";ok(&image,"align_stack label before",align_label_before,1,1,1);
 const char*align_label_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {rsp} {\nalign_stack:\nreturn 0\n}\n}\n";bad(&image,"align_stack as label",align_label_bad,4);
 /* ---- push and pop carry no atom: the oracle leaves flags_written at zero
    for both, so adding their footprints to 17.4 must not invent an effect. */
 const char*push_no_atom="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp} {\npush rbx\nreturn 0\n}\n}\n";ok(&image,"push no atom",push_no_atom,1,0,0);
 const char*pop_no_atom="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp,rbx} {\npop rbx\nreturn 0\n}\n}\n";ok(&image,"pop no atom",pop_no_atom,1,0,0);
 const char*pop_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\npop:\nreturn 0\n}\n}\n";ok(&image,"pop label",pop_label,1,0,0);
 const char*popfq_still="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {privileged,changes_flags}\nclobbers {rsp} {\npopfq\nreturn 0\n}\n}\n";ok(&image,"popfq unchanged",popfq_still,1,1,1);
 af_sweep(&image);
 bad(&image,"short",none,3);bad(&image,"invalid","target x86_64-nexora-none\n",4);
}if(image.memory){ng_parity_finish(&ng_parity,&failures);nova_host_unmap(&image);}if(compiled)nt_artifact_free(&a);for(unsigned i=0;i<8;i++)free(sources[i]);printf("NTASM_NOVA_BODY_INTRINSICS checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
