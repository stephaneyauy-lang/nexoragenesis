#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks,failures,cases;
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
static char*load(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[4];}Run;
static Run run(const NovaHostImage*i,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return r;}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t sets,uint64_t entries,uint64_t nonempty){Run r=run(i,s,3);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=sets||r.out[1]!=entries||r.out[2]!=nonempty){failures++;fprintf(stderr,"FAIL ok %s\n",n);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t words,uint64_t code,int untouched){Run r=run(i,s,words);cases++;checks++;if(r.returned!=code||r.runtime||(untouched&&(r.out[0]!=guard||r.out[1]!=guard))||(!untouched&&r.out[0]==guard)){failures++;fprintf(stderr,"FAIL error %s ret=%llu\n",n,(unsigned long long)r.returned);}}
/* One function whose clobbers set spells the given comma separated names, so a
   case below reads as the set it is about instead of as an escaped module. */
static void set_case(char*buf,size_t n,const char*set){
 snprintf(buf,n,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {%s} {\nreturn 0\n}\n}\n",set);
}
/* The union mask clobbers.check publishes in out[3] when lent four words, or
   UINT64_MAX if the pass refused. A pure getter: it counts no case and judges
   nothing, because only the caller knows whether it is testing "charged the
   wrong bit" or "not charged at all", and one of those is a pass. */
static uint64_t mask_of(const NovaHostImage*i,const char*s){
 Run r=run(i,s,4);
 if(r.returned||r.runtime) return UINT64_MAX;
 return r.out[3];
}
int main(void){const char*paths[]={"tests/nova/tests/clobbers-entry.nova","compiler/nova/analysis/abi/clobbers.nova","compiler/nova/analysis/types/register_widths.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[8]={0};NtFInput inputs[8];for(unsigned i=0;i<8;i++){size_t n=0;sources[i]=load(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<8;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,8,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");
 if(image.memory){const char*distinct="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax,rcx} {\nreturn 0\n}\n}\n";ok(&image,"distinct",distinct,1,2,1);const char*dup="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax,rax} {\nreturn 0\n}\n}\n";err(&image,"duplicate",dup,3,320,0);const char*empty="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"empty",empty,1,0,0);const char*separate="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\nfn g()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n}\n";ok(&image,"separate",separate,2,2,2);const char*imported="module m\ntarget x86_64-nexora-none\nimport a.f as f: fn()->u64\neffects {}\nclobbers {rax}\n";ok(&image,"import",imported,1,1,1);const char*families[][2]={{"rax","eax"},{"rcx","ecx"},{"rdx","edx"},{"rbx","ebx"},{"rsp","esp"},{"rbp","ebp"},{"rsi","esi"},{"rdi","edi"},{"r8","r8d"},{"r9","r9b"},{"r10","r10d"},{"r11","r11w"},{"r12","r12b"},{"r13","r13d"},{"r14","r14w"},{"r15","r15b"}};for(unsigned k=0;k<16;k++){char alias[512];snprintf(alias,sizeof(alias),"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {%s,%s} {\nreturn 0\n}\n}\n",families[k][0],families[k][1]);err(&image,families[k][0],alias,3,320,0);}err(&image,"short",distinct,2,800,1);err(&image,"invalid","target x86_64-nexora-none\n",3,800,1);}
 if(image.memory){const char*unknown="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {foo} {\nreturn 0\n}\n}\n";err(&image,"unknown",unknown,3,330,0);const char*qualified="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {cpu.rax} {\nreturn 0\n}\n}\n";err(&image,"qualified",qualified,3,330,0);}
 if(image.memory){
  /* ---- rflags, the one clobber family outside the sixteen GPRs ----
     register_widths.clobber_bit charges 1<<17 for rflags, and that 17 is the
     oracle's rather than this product's, so it is confronted here and not
     asserted. frontend.c:769 answers 17, codegen.c:1277 reads bit 17, and
     frontend.h:95 documents the whole space. If the oracle ever moves
     rflags, the literal in register_widths.nova is wrong and these checks go
     red in the same binary that runs the module. r15 and rip are asked for
     because the product refuses rip and the reason is the bit either side of
     rflags, and gsbase and fsbase because the product refuses those too and a
     reader deserves to see that the refusal is a choice, not the table simply
     running out. */
  {const struct{const char*name;int family;}fam[6]={{"rax",0},{"r15",15},
      {"rip",16},{"rflags",17},{"gsbase",18},{"fsbase",19}};
   for(unsigned k=0;k<6;k++){cases++;checks++;
     int got=nt_frontend_register(fam[k].name).family;
     if(got!=fam[k].family){failures++;fprintf(stderr,"FAIL oracle family %s got %d want %d\n",fam[k].name,got,fam[k].family);}}
   const char*absent[2]={"foo","eflags"};
   for(unsigned k=0;k<2;k++){cases++;checks++;
     int got=nt_frontend_register(absent[k]).family;
     if(got!=-1){failures++;fprintf(stderr,"FAIL oracle family %s got %d want -1\n",absent[k],got);}}}
  char s[512],pair[512],lab[96];
  /* Accepted. The first is the spelling examples/ntasm-v0/c-bootstrap/
     mutable-data.ntasm uses, a program the C oracle compiles and that this
     pass answered 330 for. */
  set_case(s,sizeof s,"rax,rflags");ok(&image,"rax and rflags",s,1,2,1);
  set_case(s,sizeof s,"rflags");ok(&image,"rflags alone",s,1,1,1);
  /* The negative half of the same question: a function that does not declare
     it is untouched, so accepting this one name did not become accepting
     anything else. */
  set_case(s,sizeof s,"rax");ok(&image,"no rflags",s,1,1,1);
  set_case(s,sizeof s,"");ok(&image,"empty alongside rflags",s,1,0,0);
  /* A duplicate is a bit charged twice, frontend.c:1874. This fails if the
     rflags row is removed, which turns it into 330, and it fails if rflags is
     ever handed a bit some other name already charges. */
  set_case(s,sizeof s,"rflags,rflags");err(&image,"rflags duplicate",s,3,320,0);
  /* The sixteen families, one case each and both orders, so rflags is measured
     against the oracle's sixteen rather than trusted to differ from the four
     the cases above happen to name. Removing the rflags row turns all thirty
     two into 330; giving rflags any GPR's bit turns the matching one into
     320. Either way the table changed and this gate says so. */
  {const char*gpr[16]={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                       "r8","r9","r10","r11","r12","r13","r14","r15"};
   for(unsigned k=0;k<16;k++){
     snprintf(pair,sizeof pair,"%s,rflags",gpr[k]);
     set_case(s,sizeof s,pair);snprintf(lab,sizeof lab,"%s with rflags",gpr[k]);
     ok(&image,lab,s,1,2,1);
     snprintf(pair,sizeof pair,"rflags,%s",gpr[k]);
     set_case(s,sizeof s,pair);snprintf(lab,sizeof lab,"rflags with %s",gpr[k]);
     ok(&image,lab,s,1,2,1);}}
  /* Still refused, each for a reason the oracle makes checkable rather than a
     fact about where the table stops. The rule is that a clobbers set may only
     charge a bit some consumer of the mask can discharge; the oracle accepts
     all four of these names, and each one here would set a bit that nothing
     in this product reads, which is the false acceptance 330 exists to stop.
     rip is the interesting one: it is the oracle's 16, the bit between the
     sixteen GPRs and rflags, so leaving it empty is what keeps 1<<17 honest. */
  {const char*refused[1]={"cpu.rflags"};
   for(unsigned k=0;k<1;k++){set_case(s,sizeof s,refused[k]);
     err(&image,refused[k],s,3,330,0);}}
  /* THE BIT, CONFRONTED AGAINST THE ORACLE, WHICH IS THE GATE THAT WAS MISSING.
     Everything above establishes that rflags is a family and that it is not
     any of the sixteen. Neither of those pins WHICH BIT it charges, and that
     is not a detail: register_widths.clobber_bit answers 1<<17 for rflags,
     bit 16 is charged by no name in the product at all, and so a wrong bit
     collides with nothing. No duplicate can fire, every counter is unchanged,
     and mutating the 131072 to 65536 leaves the whole tree green. That was
     measured, not assumed.
     So each charged name is measured against UINT64_C(1) <<
     nt_frontend_register(name).family, DERIVED from the oracle at run time in
     the same binary that runs the module. It is a table over the seventeen
     names the product charges rather than a hand-picked rflags case, and it
     follows the oracle if the oracle ever renumbers: the expected value moves
     and the module's literal does not, so the disagreement shows up here.
     The negative proof is the same loop read the other way: every row is a
     claim that would fail if the module charged a different bit, and
     substituting 1<<16 for rflags fails exactly one row, the rflags one. */
  {const char*charged[20]={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                           "r8","r9","r10","r11","r12","r13","r14","r15",
                           "rflags","rip","gsbase","fsbase"};
   for(unsigned k=0;k<20;k++){
     int family=nt_frontend_register(charged[k]).family;
     uint64_t want=UINT64_C(1)<<family;
     set_case(s,sizeof s,charged[k]);
     uint64_t got=mask_of(&image,s);
     cases++;checks++;
     if(got!=want){failures++;
       fprintf(stderr,"FAIL bit %s got %llu want %llu\n",charged[k],
               (unsigned long long)got,(unsigned long long)want);}}}
  /* Two names in one set must OR, not collide, and the two families either
     side of the gap must both be reachable in one mask. */
  {set_case(s,sizeof s,"rax,rflags");
   uint64_t got=mask_of(&image,s);
   uint64_t want=(UINT64_C(1)<<nt_frontend_register("rax").family)
                |(UINT64_C(1)<<nt_frontend_register("rflags").family);
   cases++;checks++;
   if(got!=want){failures++;
     fprintf(stderr,"FAIL bit rax|rflags got %llu want %llu\n",
             (unsigned long long)got,(unsigned long long)want);}}
  /* A refused name charges nothing, and says so by refusing rather than by
     quietly producing a set with one bit missing. mask_of reports a refusal
     as UINT64_MAX, so this row is the negative half of the table above. */
  {set_case(s,sizeof s,"rip");
   uint64_t got=mask_of(&image,s);
   cases++;checks++;
   if(got!=(UINT64_C(1)<<16)){failures++;
     fprintf(stderr,"FAIL bit rip got %llu want bit16\n",(unsigned long long)got);}}
 }
 if(image.memory) nova_host_unmap(&image);
 if(compiled) nt_artifact_free(&a);
 for(unsigned i=0;i<8;i++) free(sources[i]);
 printf("NTASM_NOVA_CLOBBERS checks=%u failures=%u cases=%u\n",checks,failures,cases);
 return failures?1:0;
}
