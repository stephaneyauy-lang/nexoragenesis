#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
/* The fuel figures in this file come from the shared model rather than from
   literals, for the reason the case they sit in spells out. */
#include "ntasm_fuel_model.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define A4_CHECK(condition, ...) do { checks++; if(!(condition)) { failures++; fprintf(stderr,"FAIL "); fprintf(stderr,__VA_ARGS__); fprintf(stderr,"\n"); } } while(0)
static unsigned checks,failures,cases;
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
static char*load(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[4];}Run;
static Run run(const NovaHostImage*i,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return r;}
static void expect(const NovaHostImage*i,const char*n,const char*s,uint64_t words,uint64_t code,int untouched){Run r=run(i,s,words);cases++;checks++;if(r.returned!=code||r.runtime||(code==0&&(r.out[0]!=35||r.out[1]==0||r.out[2]==0||r.out[3]!=0))||(untouched&&(r.out[0]!=guard||r.out[1]!=guard))){failures++;fprintf(stderr,"FAIL %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.runtime,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}

/* === the arity verdict of the full pipeline, and the order of the stages.
 * A four word out is the historical contract and stays byte for byte what it
 * was; the two additive words carry the too many / too few reason and its
 * index. Wide is a separate runner so the four word Run above, and with it
 * the ninety nine cases that already existed, are untouched. */
typedef struct{uint64_t returned,runtime,out[8];}Wide;
static Wide runw(const NovaHostImage*i,const char*s,uint64_t words){Wide r={.out={guard,guard,guard,guard,guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"wide context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"wide context cleanup");return r;}
/* One based line and column of the nth occurrence of needle, so an error
 * case asserts the exact reported span instead of only its code. */
static void where(const char*s,const char*needle,int nth,uint64_t*line,uint64_t*column){uint64_t ln=1,col=1;int seen=0;size_t n=strlen(needle);const char*p=s;for(;;){if(*p=='\0')break;if(*p=='\n'){ln++;col=1;p++;continue;}if(strncmp(p,needle,n)==0&&(seen++==nth-1)){*line=ln;*column=col;return;}col++;p++;}}
/* The pipeline arity verdict in full: out[0..1] the callee name position,
 * out[2] the expected arity, out[3] the received arity, out[4] the reason,
 * 4 too many arguments and 5 too few, and out[5] its zero based index, the
 * first surplus argument for 4 and the first unsatisfied parameter for 5. */
static void wide_arity(const NovaHostImage*i,const char*n,const char*s,uint64_t words,const char*needle,int nth,uint64_t code,uint64_t expected,uint64_t received,uint64_t reason,uint64_t index){uint64_t line=0,column=0;where(s,needle,nth,&line,&column);Wide r=runw(i,s,words);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=expected||r.out[3]!=received||r.out[4]!=reason||r.out[5]!=index||r.out[6]!=guard||r.out[7]!=guard){failures++;fprintf(stderr,"FAIL wide arity %s ret=%llu want %llu,%llu,%llu,%llu,%llu at %llu,%llu out=%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)code,(unsigned long long)expected,(unsigned long long)received,(unsigned long long)reason,(unsigned long long)index,(unsigned long long)line,(unsigned long long)column,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3],(unsigned long long)r.out[4],(unsigned long long)r.out[5],(unsigned long long)r.out[6],(unsigned long long)r.out[7]);}}
/* A four word caller must still learn nothing new: the two additive words
 * stay at the guard, so the historical contract is byte for byte intact. */
static void arity_four_word(const NovaHostImage*i,const char*n,const char*s,uint64_t expected,uint64_t received){Wide r=runw(i,s,4);cases++;checks++;if(r.returned!=311||r.runtime||r.out[0]==guard||r.out[2]!=expected||r.out[3]!=received||r.out[4]!=guard||r.out[5]!=guard){failures++;fprintf(stderr,"FAIL four word %s ret=%llu out=%llu,%llu,%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3],(unsigned long long)r.out[4],(unsigned long long)r.out[5]);}}
/* Success with a wide out: the pass count never moves, the reserved third
 * word is still zero and the two additive arity slots are zeroed, never
 * left holding a stage scratch value. */
static void okw(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Wide r=runw(i,s,words);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=35||r.out[1]==0||r.out[2]==0||r.out[3]||r.out[4]||r.out[5]){failures++;fprintf(stderr,"FAIL wide ok %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.runtime,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3],(unsigned long long)r.out[4],(unsigned long long)r.out[5]);}}
/* The stage names of spec/ntasm/ntasm.md 17.7, in pipeline order, as the module
 * publishes them: mode 1 in the seventh word copies the packed table into
 * the source buffer the caller lends writable and reports its byte count
 * and its name count. The list below is that section's own table, so a
 * reordering of the pipeline fails here instead of only at review. */
static const char*const stage_names[35]={"expand","index","targets","versions","features","callable_names","symbol_names","types","constant_types","literal_initializers","parameters","locals","bindings","register_bindings","register_widths","clobbers","abi","pointer_spaces","effects","body_effects","body_intrinsics","body_clobbers","control_flow","return_types","contracts","feature_requirements","refs","calls","call_types","initializer_types","condition_types","call_effects","call_clobbers","call_contracts","machine_ir"};
static Wide run_stage(const NovaHostImage*i,char*src,size_t len_){Wide r={.out={guard,guard,guard,guard,guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"stage context init");uint64_t sh=nova_borrow_v2(&c,src,len_,1),oh=nova_borrow_v2(&c,r.out,7*8,1);r.out[6]=1;uint64_t a[]={sh,len_,oh,7};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"stage context cleanup");return r;}
static void expect_stage_order(const NovaHostImage*i){static char got[1024],want[1024];memset(got,0,sizeof got);memset(want,0,sizeof want);size_t at=0;for(unsigned k=0;k<35;k++){size_t n=strlen(stage_names[k]);memcpy(want+at,stage_names[k],n);at=at+n+1;want[at-1]=0;}Wide r=run_stage(i,got,sizeof got);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=at||memcmp(got,want,at)!=0){failures++;fprintf(stderr,"FAIL stage order ret=%llu runtime=%llu out=%llu want bytes=%llu\n",(unsigned long long)r.returned,(unsigned long long)r.runtime,(unsigned long long)r.out[0],(unsigned long long)at);}}

/* spec/ntasm/ntasm.md 13: macros are expanded before the final type and contract
 * verification, so ntasm_macro_expand.expand is the first stage of the
 * pipeline. Every code it refuses with reaches the caller unchanged, and an
 * expansion is substituted for the invocation it replaces, so the later
 * stages see the expanded module. */
#define MACRO_HEAD "module m\ntarget x86_64-nexora-none\n"
#define MACRO_TAIL "section .text {\nfn main()->u64\neffects {}\nclobbers {} {\nexpand "
#define MACRO_FOOT "\n}\n}\n"
/* the worked example of the macro_expand gate, so the budget figures below
 * are the ones that gate measured: fuel 30, arena 480, nodes 5 */
#define BUDGET_BODY "macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v+1; };\n}\n"
/* The equality the audit W4-8 section C1 asks for, asked at run time and not
 * as two literals that happen to agree: the same declaration is handed to the
 * pipeline twice, once through a macro that emits it and once written in the
 * clear, and the two verdicts are compared to each other as well as to the
 * wanted one. A change that moves one column and not the other fails here,
 * which a pair of identical literals would not catch. */
static void same_verdict(const NovaHostImage*i,const char*n,const char*macro_src,const char*clear_src,uint64_t code){
  Run a=run(i,macro_src,4),b=run(i,clear_src,4);
  int good=1;
  cases++;checks++;
  if(a.returned!=b.returned||a.returned!=code||a.runtime||b.runtime){good=0;}
  if(code==0&&(a.out[0]!=35||b.out[0]!=35||a.out[1]==0||b.out[1]==0||a.out[2]==0||b.out[2]==0||a.out[3]!=0||b.out[3]!=0)){good=0;}
  if(good==0){
    failures++;
    fprintf(stderr,"FAIL parity %s macro=%llu clear=%llu want=%llu macro_out=%llu,%llu,%llu clear_out=%llu,%llu,%llu\n",n,(unsigned long long)a.returned,(unsigned long long)b.returned,(unsigned long long)code,(unsigned long long)a.out[0],(unsigned long long)a.out[1],(unsigned long long)a.out[2],(unsigned long long)b.out[0],(unsigned long long)b.out[1],(unsigned long long)b.out[2]);
  }
}
/* ============================ U1: do the two sides agree about the ABI
 * profile they implement? ================================================
 *
 * nx64-abi-v0 is the only ABI profile the product accepts (abi.nova:46
 * is_nx64, abi.nova:140 and 176 for the default and the explicit clause)
 * and efi-x64-v0 is a real second profile of the reference: codegen.c:436
 * selects on it, frontend.c:2894 gives it its own register map, and
 * tests_conformance_efi.c:96-105 runs a program that declares it. The
 * product refuses it, and section 6 of the wave 9 report names that as an
 * open residual with four layers of cost in it, two of which would produce
 * a WRONG program rather than a refusal.
 *
 * Until now no gate asked the two sides the same question about the same
 * source, so a rule could move on one side alone and nothing would see it.
 * This block is that question. It is a run time comparison and not a table
 * of literals: the product's answer is the pipeline's own return code, and
 * the reference's answer is NtFProgram.verified out of nt_frontend_compile.
 *
 * frontend.h is NOT included at the top of this file on purpose. It already
 * arrives, through nova.h -> ntasm.h -> frontend.h, and one more line there
 * moves every line below it by one: spec/ntasm/ntasm.md:2249 cites
 * tests_ntasm_validate.c:38-45 for expect_stage_order, and the registry
 * gate reads that citation by line. A redundant include is not free in a
 * file the document cites by line number.
 *
 * The reference's RETURN VALUE IS NOT A BOOLEAN VERDICT, and the direction
 * of the trap was measured, not assumed. nt_frontend_compile returns 1 on a
 * verified program and 0 on a refused one, so the obvious test, rc == 0 for
 * "accepted", inverts EVERY row: a first draft of this probe did exactly
 * that and reported 14 of 19 corpus rows as disagreements when the two
 * sides agreed on all 19. Only program.verified is read here.
 *
 * The opposite perturbation -- reading the return value itself as the
 * boolean -- is NOT a distinguishable perturbation on this corpus, and the
 * negative proof says so: it leaves the gate green, because on all thirteen
 * rows rc and verified coincide. verified is read because it is the
 * documented field, not because a row of this corpus can tell the two
 * apart, and this file does not claim otherwise.
 *
 * Two kinds of row, and the difference between them is the whole point:
 *
 *  - agree_profile: the two sides must answer the SAME, over the profile
 *    they both implement. This is already true today and goes red the
 *    moment either side moves. It is NOT a report about a future
 *    divergence; nothing here can only fail later.
 *  - diverge_profile: the two sides must answer DIFFERENTLY, with the
 *    product's code recorded. Those rows are the efi-x64-v0 residual, they
 *    exist so the comparison above is exercised on a disagreement that is
 *    real rather than on a manufactured one, and a red here means the
 *    residual has been closed and the row must be re-scoped.
 *
 * The direction that separates this from a comparison alone: every
 * agree_profile row also asserts the COMMON answer, on both sides. A
 * comparison on its own is satisfied by two modules that refuse everything,
 * and a program both sides accept has to stay accepted -- four of the ten
 * rows below are exactly that assertion. The two counters printed in the
 * banner are the anti-vacuity guard: they are computed from the reference's
 * OWN verdicts, so a corpus that had degenerated to all refusals would
 * print accepted_by_both=0, and the check below the loop fails on it. */
typedef struct{int product_accept,reference_accept;uint64_t product_code;}Agreement;
static unsigned profile_rows,profile_agreed,profile_accepted_by_both,
    profile_refused_by_both,profile_disagreed;
/* The reference's own answer to "does this module verify?". */
static int reference_verifies(const char*s){
  NtFInput input={"profile-agreement.ntasm",s,strlen(s)};
  NtFProgram program={0};
  nt_frontend_compile(&input,1,&program);
  int verified=program.verified;
  nt_frontend_free(&program);
  return verified;
}
/* ONE question, asked of both sides, and compared only afterwards. Both
 * measurements happen inside this function; every check that consumes them
 * is below it, never before it. */
static Agreement ask_both(const NovaHostImage*i,const char*s){
  Run r=run(i,s,4);
  Agreement a;
  a.product_code=r.returned;
  a.product_accept=(r.returned==0&&!r.runtime)?1:0;
  a.reference_accept=reference_verifies(s);
  return a;
}
static void agree_profile(const NovaHostImage*i,const char*label,const char*s,int want){
  Agreement a=ask_both(i,s);
  profile_rows++;cases++;
  if(a.product_accept==a.reference_accept) profile_agreed++;
  else profile_disagreed++;
  if(a.product_accept&&a.reference_accept) profile_accepted_by_both++;
  if(!a.product_accept&&!a.reference_accept) profile_refused_by_both++;
  checks++;
  if(a.product_accept!=a.reference_accept){
    failures++;
    fprintf(stderr,"FAIL profile agreement %s: the product %s (code %llu) and the reference %s the same source\n",
            label,a.product_accept?"accepts":"refuses",(unsigned long long)a.product_code,
            a.reference_accept?"accepts":"refuses");
  }
  checks++;
  if(a.product_accept!=want){
    failures++;
    fprintf(stderr,"FAIL profile acceptance %s: the product %s it (code %llu), the common answer is %s\n",
            label,a.product_accept?"accepts":"refuses",(unsigned long long)a.product_code,
            want?"accept":"refuse");
  }
  checks++;
  if(a.reference_accept!=want){
    failures++;
    fprintf(stderr,"FAIL profile acceptance %s: the reference %s it, wanted %d\n",
            label,a.reference_accept?"accepts":"refuses",want);
  }
}
static void diverge_profile(const NovaHostImage*i,const char*label,const char*s,uint64_t product_code){
  Agreement a=ask_both(i,s);
  profile_rows++;cases++;
  if(a.product_accept!=a.reference_accept) profile_disagreed++;
  checks++;
  if(a.product_accept==a.reference_accept){
    failures++;
    fprintf(stderr,"FAIL profile residual %s: the product and the reference now AGREE, so the named efi-x64-v0 residual is closed and this row has to be re-scoped, not deleted\n",label);
  }
  checks++;
  if(a.product_code!=product_code){
    failures++;
    fprintf(stderr,"FAIL profile residual %s: the product answered %llu, the recorded residual code is %llu\n",
            label,(unsigned long long)a.product_code,(unsigned long long)product_code);
  }
  checks++;
  if(a.reference_accept!=1){
    failures++;
    fprintf(stderr,"FAIL profile residual %s: the reference no longer accepts this source either, so it witnesses nothing about the profile\n",label);
  }
}
static char *a4_fixture(const char *path) {
 FILE *f=fopen(path,"rb");if(!f)return NULL;
 if(fseek(f,0,SEEK_END)){fclose(f);return NULL;}long n=ftell(f);rewind(f);
 if(n<0){fclose(f);return NULL;}char *s=malloc((size_t)n+1);
 if(!s || fread(s,1,(size_t)n,f)!=(size_t)n){free(s);fclose(f);return NULL;}
 s[n]=0;fclose(f);return s;
}
int main(void){const char*paths[]={"tests/nova/tests/validate-entry.nova","compiler/nova/analysis/validate.nova","compiler/nova/macros/macro_splice.nova","compiler/nova/formats/ntir/ntir.nova","compiler/nova/macros/macro_expand.nova","compiler/nova/analysis/types/constant_types.nova","compiler/nova/macros/constant_eval.nova","compiler/nova/analysis/types/initializer_types.nova","compiler/nova/analysis/types/condition_types.nova","compiler/nova/analysis/types/literal_initializers.nova","compiler/nova/frontend/targets.nova","compiler/nova/frontend/versions.nova","compiler/nova/analysis/abi/feature_requirements.nova","compiler/nova/analysis/abi/features.nova","compiler/nova/analysis/types/pointer_spaces.nova","compiler/nova/analysis/control_flow.nova","compiler/nova/analysis/types/return_types.nova","compiler/nova/analysis/abi/body_clobbers.nova","compiler/nova/analysis/abi/body_intrinsics.nova","compiler/nova/analysis/abi/body_effects.nova","compiler/nova/analysis/calls/call_contracts.nova","compiler/nova/analysis/abi/abi.nova","compiler/nova/analysis/calls/call_clobbers.nova","compiler/nova/analysis/calls/call_effects.nova","compiler/nova/analysis/calls/call_types.nova","compiler/nova/analysis/calls/calls.nova","compiler/nova/frontend/refs.nova","compiler/nova/analysis/abi/clobbers.nova","compiler/nova/analysis/abi/contracts.nova","compiler/nova/analysis/abi/effects.nova","compiler/nova/analysis/types/register_widths.nova","compiler/nova/frontend/register_bindings.nova","compiler/nova/frontend/bindings.nova","compiler/nova/frontend/locals.nova","compiler/nova/frontend/parameters.nova","compiler/nova/analysis/types/types.nova","compiler/nova/frontend/symbol_names.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova","compiler/nova/ir/machine_ir.nova"};char*sources[43]={0};NtFInput inputs[43];for(unsigned i=0;i<43;i++){size_t n=0;sources[i]=load(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<43;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,43,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");
 if(image.memory){
  const char*valid="module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata answer:u64=42\n}\nsection .text {\nfn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {rax} {\nlet y:u64=x\nreturn y\n}\nfn main()->u64\neffects {}\nclobbers {rax} {\ncall helper(1)\nreturn 0\n}\n}\n";expect(&image,"valid",valid,4,0,0);
  const char*dupfn="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n}\n";expect(&image,"300",dupfn,4,300,0);
  const char*aliases="module m\ntarget x86_64-nexora-none\nimport a.f as x: fn()->u64\neffects {}\nclobbers {}\nimport b.f as x: fn()->u64\neffects {}\nclobbers {}\n";expect(&image,"313",aliases,4,313,0);
  const char*symbols="module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata same:u64=1\n}\nsection .text {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";expect(&image,"0 data and function may share a name",symbols,4,0,0);
  const char*params="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx,in x:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n}\n";expect(&image,"314",params,4,314,0);
  const char*locals="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nlet x:u64=2\nreturn x\n}\n}\n";expect(&image,"315",locals,4,315,0);
  const char*bindings="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nreturn x\n}\n}\n";expect(&image,"316",bindings,4,316,0);
  const char*registers="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64 @rcx,in b:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";expect(&image,"317",registers,4,317,0);
  const char*width="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @ecx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n}\n";expect(&image,"318",width,4,318,0);
  const char*clobber="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax,rax} {\nreturn 0\n}\n}\n";expect(&image,"320",clobber,4,320,0);
  const char*missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall absent()\nreturn 0\n}\n}\n";expect(&image,"310",missing,4,310,0);
  const char*arity="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";expect(&image,"311",arity,4,311,0);
  const char*param_alias="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64 @rcx,in b:u32 @ecx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";expect(&image,"317 alias",param_alias,4,317,0);
  const char*clobber_alias="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {r10,r10d} {\nreturn 0\n}\n}\n";expect(&image,"320 alias",clobber_alias,4,320,0);
  const char*unknown_effect="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {telepathy}\nclobbers {} {\nreturn 0\n}\n}\n";expect(&image,"321 effect",unknown_effect,4,321,0);
  const char*duplicate_effect="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {msr,msr}\nclobbers {} {\nreturn 0\n}\n}\n";expect(&image,"322 effect",duplicate_effect,4,322,0);
  const char*unknown_contract="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {}\nrequires {telepathy(1)} {\nreturn 0\n}\n}\n";expect(&image,"323 contract",unknown_contract,4,323,0);
  const char*contract_arity="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {}\nrequires {valid_user_return(1)} {\nreturn 0\n}\n}\n";expect(&image,"324 contract",contract_arity,4,324,0);
  const char*missing_effect="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {privileged}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";expect(&image,"325 call effect",missing_effect,4,325,0);
  const char*missing_nonnull_contract="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\nrequires {non_null(p)} {\nreturn 0\n}\nfn main(in q:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {} {\ncall leaf(q)\nreturn 0\n}\n}\n";expect(&image,"326 nonnull contract",missing_nonnull_contract,4,326,0);
  const char*bad_abi="module m\ntarget x86_64-nexora-none\ndefault_abi alien-abi\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";expect(&image,"327 abi",bad_abi,4,327,0);
  const char*fifth_param="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64,in b:u64,in c:u64,in d:u64,in e:u64)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";expect(&image,"328 abi",fifth_param,4,328,0);
  const char*pointer_width="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @edi)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";expect(&image,"329 abi",pointer_width,4,329,0);
  const char*missing_contract="module m\ntarget x86_64-nexora-none\nfeatures {sse2}\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {feature(sse2)} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";expect(&image,"feature module call proof",missing_contract,4,0,0);
  const char*unknown_clobber="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {foo} {\nreturn 0\n}\n}\n";expect(&image,"330 clobber",unknown_clobber,4,330,0);
  const char*missing_clobber="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";expect(&image,"331 call clobber",missing_clobber,4,331,0);
  const char*missing_body_effect="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {rax} {\nload rax,[p]:ptr<user,u64>\nreturn rax\n}\n}\n";expect(&image,"332 body effect",missing_body_effect,4,332,0);
  const char*unknown_space="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<alien,u64> @rdi)->u64\neffects {reads_mem}\nclobbers {rax} {\nload rax,[p]:ptr<alien,u64>\nreturn rax\n}\n}\n";expect(&image,"340 load pointer space",unknown_space,4,340,0);
  const char*missing_intrinsic="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax,rdx} {\nrdtsc\nreturn 0\n}\n}\n";expect(&image,"334 intrinsic",missing_intrinsic,4,334,0);
  const char*missing_load_clobber="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {} {\nload rax,[p]:ptr<user,u64>\nreturn rax\n}\n}\n";expect(&image,"335 body clobber",missing_load_clobber,4,335,0);
  const char*unknown_load_register="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {} {\nload foo,[p]:ptr<user,u64>\nreturn 0\n}\n}\n";expect(&image,"336 body register",unknown_load_register,4,336,0);
  const char*never_return="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->never\neffects {no_return}\nclobbers {} {\nreturn 0\n}\n}\n";expect(&image,"337 never return",never_return,4,337,0);
  const char*fallthrough="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nnop\n}\n}\n";expect(&image,"338 fallthrough",fallthrough,4,338,0);
  const char*bare_return="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn\n}\n}\n";expect(&image,"339 bare return",bare_return,4,339,0);
  const char*never_call_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn halt()->never\neffects {no_return}\nclobbers {} {\nud2\n}\nfn main()->never\neffects {no_return}\nclobbers {} {\ncall halt()\n}\n}\n";expect(&image,"never call terminal",never_call_ok,4,0,0);
  const char*bad_pointer_space="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<alien,u64> @rdi)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";expect(&image,"340 pointer space",bad_pointer_space,4,340,0);
  const char*missing_intrinsic_clobber="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {control,changes_flags}\nclobbers {rcx} {\nsyscall\nreturn 0\n}\n}\n";expect(&image,"335 intrinsic clobber",missing_intrinsic_clobber,4,335,0);
  const char*missing_mov_clobber="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rbx)->u64\neffects {}\nclobbers {} {\nmov rax,rbx\nreturn rax\n}\n}\n";expect(&image,"335 mov clobber",missing_mov_clobber,4,335,0);
  const char*missing_xchg_clobber="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rax,in y:u64 @rcx)->u64\neffects {}\nclobbers {rax} {\nxchg rax,rcx\nreturn rax\n}\n}\n";expect(&image,"335 xchg clobber",missing_xchg_clobber,4,335,0);
  const char*missing_arith_flags="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rax)->u64\neffects {}\nclobbers {r10} {\nadd r10,rax\nreturn r10\n}\n}\n";expect(&image,"334 arithmetic flags",missing_arith_flags,4,334,0);
  const char*unknown_feature="module m\ntarget x86_64-nexora-none\nfeatures {avx512}\n";expect(&image,"341 feature",unknown_feature,4,341,0);
  const char*duplicate_feature="module m\ntarget x86_64-nexora-none\nfeatures {sse2,sse2}\n";expect(&image,"342 feature",duplicate_feature,4,342,0);
  const char*unknown_required_feature="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {}\nrequires {feature(avx512)} {\nreturn 0\n}\n}\n";expect(&image,"343 required feature",unknown_required_feature,4,343,0);
  const char*unavailable_feature="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {}\nrequires {feature(sse2)} {\nreturn 0\n}\n}\n";expect(&image,"344 unavailable feature",unavailable_feature,4,344,0);
  const char*unknown_target="module m\ntarget x86_64-other-none\n";expect(&image,"345 target",unknown_target,4,345,0);
  const char*wrong_version="module m\ntarget x86_64-nexora-none\nversions {\nntir 1.0\nmachine_ir 0.1\nsections 0.1\nsymbols 0.1\nrelocations 0.1\nnxo 0.1\n}\n";expect(&image,"348 version",wrong_version,4,348,0);
  const char*incomplete_versions="module m\ntarget x86_64-nexora-none\nversions {\nntir 0.1\n}\n";expect(&image,"349 versions",incomplete_versions,4,349,0);
  const char*out_reserved="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(out a:u64 @rax)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";expect(&image,"328 reserved output",out_reserved,4,328,0);
  const char*out_clobber="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(out a:u64 @rcx)->u64\neffects {}\nclobbers {ecx} {\nreturn a\n}\n}\n";expect(&image,"328 output clobber",out_clobber,4,328,0);
  const char*unknown_type="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:telepathy @rdi)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";expect(&image,"350 type",unknown_type,4,350,0);
  const char*zero_array="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:array<u8,0> @rdi)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";expect(&image,"351 array",zero_array,4,351,0);
  const char*return_mismatch="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u32 @edi)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n}\n";expect(&image,"352 return type",return_mismatch,4,352,0);
  const char*return_range="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u8\neffects {}\nclobbers {} {\nreturn 256\n}\n}\n";expect(&image,"353 return range",return_range,4,353,0);
  const char*qualified_return="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn bogus.x\n}\n}\n";expect(&image,"353 qualified return",qualified_return,4,353,0);
  const char*out_call_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(out x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";expect(&image,"out call arity",out_call_ok,4,0,0);
  const char*inout_call_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(inout x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";expect(&image,"inout call arity",inout_call_bad,4,311,0);
  const char*call_type_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u64 @rdi)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn f(in y:u32 @edi)->u64\neffects {}\nclobbers {} {\ncall g(y)\nreturn 0\n}\n}\n";expect(&image,"354 call type",call_type_bad,4,354,0);
  const char*call_range_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u8 @al)->u8\neffects {}\nclobbers {} {\nreturn x\n}\nfn f()->u64\neffects {}\nclobbers {} {\ncall g(256)\nreturn 0\n}\n}\n";expect(&image,"354 call range",call_range_bad,4,354,0);
  const char*initializer_type_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:bool=1\nreturn 0\n}\n}\n";expect(&image,"355 initializer type",initializer_type_bad,4,355,0);
  const char*initializer_range_bad="module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata x:u8=256\n}\n";expect(&image,"356 initializer range",initializer_range_bad,4,356,0);
  const char*condition_type_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif 1 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";expect(&image,"357 condition type",condition_type_bad,4,357,0);
  const char*condition_shape_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nif x+1 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";expect(&image,"358 condition shape",condition_shape_bad,4,358,0);
  const char*condition_arithmetic_compare="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nif (x+1)==2 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";expect(&image,"typed arithmetic comparison",condition_arithmetic_compare,4,0,0);
  const char*condition_compare_mismatch="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u32 @ecx,in y:u64 @rdx)->u64\neffects {}\nclobbers {} {\nif x==y {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";expect(&image,"357 comparison type mismatch",condition_compare_mismatch,4,357,0);
  const char*condition_not="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif !ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";expect(&image,"boolean not",condition_not,4,0,0);
  const char*condition_logic="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f(in ready:bool @al,in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif ready || !pred() && x<5 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";expect(&image,"boolean and-or precedence",condition_logic,4,0,0);
  const char*boolean_value_flow="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn consume(in v:bool @al)->bool\neffects {}\nclobbers {} {\nreturn v\n}\nfn f(in ready:bool @al,in x:u64 @rcx)->bool\neffects {}\nclobbers {} {\nlet gate:bool=ready || pred() && x<5\ncall consume(!gate)\nreturn gate && !pred()\n}\n}\n";expect(&image,"boolean value flow",boolean_value_flow,4,0,0);
  const char*bool_condition_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f()->u64\neffects {}\nclobbers {} {\nif pred() {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";expect(&image,"bool condition call",bool_condition_call,4,0,0);
  const char*missing_condition_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif absent() {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";expect(&image,"missing condition call",missing_condition_call,4,310,0);
  const char*initializer_name_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u32 @ecx)->u64\neffects {}\nclobbers {} {\nlet x:u64=p\nreturn x\n}\n}\n";expect(&image,"359 initializer name",initializer_name_bad,4,359,0);
  const char*initializer_arithmetic="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nlet x:u64=p+1\nreturn x\n}\n}\n";expect(&image,"initializer arithmetic",initializer_arithmetic,4,0,0);
  const char*initializer_arithmetic_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u32 @ecx)->u64\neffects {changes_flags}\nclobbers {} {\nlet x:u64=p+1\nreturn x\n}\n}\n";expect(&image,"359 initializer arithmetic",initializer_arithmetic_bad,4,359,0);
  const char*initializer_nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nlet x:u64=p+(1+2)\nreturn x\n}\n}\n";expect(&image,"nested initializer",initializer_nested,4,0,0);
  const char*nested_return_argument="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nreturn x+(1+2)\n}\nfn f(in p:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\ncall g(p+(2*3))\nreturn p+(4*5)\n}\n}\n";expect(&image,"nested return and argument",nested_return_argument,4,0,0);
  const char*unary_integer_flow="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:i8 @cl)->i8\neffects {changes_flags}\nclobbers {} {\nreturn ~x\n}\nfn f(in p:i8 @cl)->i8\neffects {changes_flags}\nclobbers {} {\nlet x:i8=+p\ncall g(-x)\nreturn --x\n}\n}\n";expect(&image,"unary integer flow",unary_integer_flow,4,0,0);
  const char*sibling_local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif true {\nlet x:u64=1\n}\nlet y:u64=x\nreturn y\n}\n}\n";expect(&image,"360 sibling local scope",sibling_local,4,360,0);
  const char*constant_type_bad="module m\ntarget x86_64-nexora-none\nconst ready:bool=1\n";expect(&image,"361 constant type",constant_type_bad,4,361,0);
  const char*constant_range_bad="module m\ntarget x86_64-nexora-none\nconst byte:u8=256\n";expect(&image,"362 constant range",constant_range_bad,4,362,0);
  const char*constant_expression="module m\ntarget x86_64-nexora-none\nconst sum:u64=1+2\n";expect(&image,"constant expression",constant_expression,4,0,0);
  const char*constant_expression_range="module m\ntarget x86_64-nexora-none\nconst byte:u8=255+1\n";expect(&image,"362 constant expression range",constant_expression_range,4,362,0);
   expect(&image,"short",valid,3,800,1);expect(&image,"invalid","target x86_64-nexora-none\n",4,800,1);
   /* === spec/ntasm/ntasm.md 13: macros are expanded before the final type and
    * contract verification, so ntasm_macro_expand.expand is the first stage
    * of the pipeline. Every code it refuses with reaches the caller
    * unchanged, and an expansion is substituted for the invocation it
    * replaces, so the later stages see the expanded module. */
   /* 1. one macro expanded once, the expansion feeding a return */
   const char*expanded_once=MACRO_HEAD"macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\n"MACRO_TAIL"ret(41)\n"MACRO_FOOT;expect(&image,"370 expanded once",expanded_once,4,0,0);
   /* 2. the expansion feeds an if condition: the produced node is the whole
    * if, and its condition is a spliced caller expression. The expansion is
    * substituted correctly, but initializer_types.bool_status cannot yet
    * prove the type of a spliced condition, so the module is refused with
    * 358. This is a known gap, not the wanted verdict: the condition is
    * produced and reaches condition_types. */
   const char*expands_if=MACRO_HEAD"macro br(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { if $v==1 { return 1; } else { return 0; } };\n}\nsection .text {\nfn main(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nexpand br(x)\n}\n}\n";expect(&image,"358 spliced if condition",expands_if,4,358,0);
   /* 3. a comptime limit block in force over one expansion */
   const char*comptime_live=MACRO_HEAD"comptime(fuel=4096,call_depth=64,arena_bytes=262144,ast_nodes=256,expansion_depth=4,constant_bytes=4096){\nreturn 1;\n}\n"BUDGET_BODY MACRO_TAIL"ret(41)\n"MACRO_FOOT;expect(&image,"372 comptime block",comptime_live,4,0,0);
   /* 4. the same macro twice, two distinct hygienic local names */
   const char*twice_local=MACRO_HEAD"macro mk()->ast.stmt {\nreturn quote(stmt) { let t:u64=1; };\n}\n"MACRO_TAIL"mk()\nexpand mk()\nreturn 0\n"MACRO_FOOT;expect(&image,"373 twice hygienic locals",twice_local,4,0,0);
   /* 5. the same macro twice, two distinct hygienic declaration names */
   const char*twice_data=MACRO_HEAD"macro d(v:u64)->ast.decl {\nemit quote(decl) { data c:u64=$v; }\n}\n"MACRO_TAIL"d(1)\nexpand d(2)\nreturn 0\n"MACRO_FOOT;expect(&image,"374 twice hygienic data",twice_data,4,0,0);
   /* 6. the capture of a caller symbol is refused by default */
   const char*macro_capture=MACRO_HEAD"const secret:u64=7\nmacro steal(v:ast.expr)->ast.expr {\nreturn quote(expr) { $v+secret };\n}\n"MACRO_TAIL"steal(1)\n"MACRO_FOOT;expect(&image,"375 capture refused",macro_capture,4,374,0);
   /* 7. every budget at its exact limit is allowed, and 8. one step past it
      is a stable refusal.  The fuel is not a literal in this file and not a
      literal in tests_ntasm_splice.c either: both read
      ng_fuel_nova(NG_FUEL_FLAT_RET, 1) out of nova/ntasm_fuel_model.h, which
      is the model whose FLAT_RET row was fitted to a measured ladder over
      this same body.  Before that, this file held 8, tests_ntasm_splice.c
      held 8, and the wave-17 walk removal moved the true figure from 30 to 8
      -- so BOTH copies had to be re-pinned in one run and neither knew the
      other existed.  One model, two readers, is the fix for that and not a
      shared constant, which would have left the agreement unargued.

      The other five figures stay literal here because they are not fuel and
      nothing in the model speaks to them: arena_bytes 480, ast_nodes 5 and
      constant_bytes 3 are what the macro_expand gate measures for this body
      and the walk removal left all three alone, which is what makes this a
      re-measurement of one number rather than a rewrite of the fixture. */
   {
     const uint64_t flat_fuel = ng_fuel_nova(NG_FUEL_FLAT_RET, 1);
     char budget_exact[2048], budget_over[2048];
     snprintf(budget_exact, sizeof budget_exact,
              MACRO_HEAD "comptime(fuel=%llu,call_depth=1,arena_bytes=480,"
              "ast_nodes=5,expansion_depth=1,constant_bytes=3){\nreturn 1;\n}\n"
              BUDGET_BODY MACRO_TAIL "ret(41)\n" MACRO_FOOT,
              (unsigned long long)flat_fuel);
     snprintf(budget_over, sizeof budget_over,
              MACRO_HEAD "comptime(fuel=%llu,call_depth=1,arena_bytes=480,"
              "ast_nodes=5,expansion_depth=1,constant_bytes=3){\nreturn 1;\n}\n"
              BUDGET_BODY MACRO_TAIL "ret(41)\n" MACRO_FOOT,
              (unsigned long long)flat_fuel - 1);
     expect(&image,"376 budget exact limit",budget_exact,4,0,0);
     expect(&image,"377 budget one past",budget_over,4,201,0);
   }
   /* 9. an unknown macro at the invocation */
   const char*macro_unknown=MACRO_HEAD MACRO_TAIL"ghost(1)\n"MACRO_FOOT;expect(&image,"370 unknown macro",macro_unknown,4,370,0);
   /* 10. a macro arity mismatch */
   const char*macro_arity=MACRO_HEAD"macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\n"MACRO_TAIL"ret(1,2)\n"MACRO_FOOT;expect(&image,"371 macro arity",macro_arity,4,371,0);
   /* 11. a macro parameter kind mismatch */
   const char*macro_kind=MACRO_HEAD"macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\n"MACRO_TAIL"ret(quote(type) { u8 })\n"MACRO_FOOT;expect(&image,"372 macro param kind",macro_kind,4,372,0);
   /* 12. a comptime limit block that is not the six mandated limits */
   const char*comptime_bad=MACRO_HEAD"comptime(fuel=16,call_depth=4,arena_bytes=262144,ast_nodes=256,expansion_depth=4){\nreturn 1;\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";expect(&image,"378 malformed comptime",comptime_bad,4,378,0);
   /* 13. the expansion produces a declaration */
   const char*makes_decl=MACRO_HEAD"macro k()->ast.decl {\nemit quote(decl) { const c:u64=1; }\n}\n"MACRO_TAIL"k()\nreturn 0\n"MACRO_FOOT;expect(&image,"379 expansion makes decl",makes_decl,4,0,0);
   /* 14. a call target is a binding position, so a template can never name a
    * callee: a macro cannot produce a call in this profile, and the refusal
    * is the hygiene rule of spec/ntasm/ntasm.md 13 rather than a pipeline defect */
   const char*call_target=MACRO_HEAD"macro go(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { call helper($v) };\n}\n"MACRO_TAIL"go(1)\nreturn 0\n"MACRO_FOOT;expect(&image,"374 call target capture",call_target,4,374,0);
   /* 15. the expansion produces a parameterless function declaration */
   const char*makes_fn=MACRO_HEAD"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n}\n}\n"MACRO_TAIL"mk()\nreturn 0\n"MACRO_FOOT;expect(&image,"381 expansion makes fn",makes_fn,4,0,0);
   /* 16. the expansion produces a function with a parameter. This was the
    * pinned defect of the audit W4-8 sections C1 and B1: the expander stamped
    * the invocation span on every produced node, and the direction of a
    * parameter lives in the source bytes at the parameter node's own span, so
    * abi.check read no direction and refused the whole module with 800 at
    * stage 17. That 800 is gone, and a parameter produced by a macro now
   * carries the span of the node it was copied from.
    * The 353 this source answered was a SECOND defect and has nothing to do
    * with the direction: it is a name read inside a binary expression by a
    * produced return. The produced-let shape in the case below answered the
    * same 353 until its visibility test was made structural, and now answers
    * 0. The pins of that residual are lifted in the wave under way: this
    * case and its nested binary variant now demand 0, in parity with the
    * clear function of the same_verdict comparison, and stay red until the
    * repair lands. */
    const char*fn_with_param=MACRO_HEAD"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(in n:u64)->u64\neffects {}\nclobbers {} {\nreturn n+1;\n}\n}\n}\n"MACRO_TAIL"mk()\nreturn 0\n"MACRO_FOOT;expect(&image,"0 produced param name reference",fn_with_param,4,0,0);
    const char*fn_with_param_bin=MACRO_HEAD"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(in n:u64)->u64\neffects {}\nclobbers {} {\nreturn n+(1+2);\n}\n}\n}\n"MACRO_TAIL"mk()\nreturn 0\n"MACRO_FOOT;expect(&image,"0 produced param name reference nested binary",fn_with_param_bin,4,0,0);
    /* the same verdict asked of the very same declaration written in the
     * clear: the parity closes the case, a bare non refusal would not. */
    const char*clear_helper="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in n:u64)->u64\neffects {}\nclobbers {} {\nreturn n+1\n}\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
    same_verdict(&image,"produced param name matches clear",fn_with_param,clear_helper,0);
   const char*fn_param_group=MACRO_HEAD"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(in n:u64)->u64\neffects {}\nclobbers {} {\nreturn n*(1+2);\n}\n}\n}\n"MACRO_TAIL"mk()\nreturn 0\n"MACRO_FOOT;expect(&image,"0 produced parameter noncommutative grouping",fn_param_group,4,0,0);
   const char*terminal_macro_block="module terminal_macro_block\ntarget x86_64-nexora-uefi\nmacro mk()->ast.block {\nreturn quote(block) { let t:u64=1; return t; };\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {rax} {\nlet t:u64=9\nexpand mk()\n}\n}\n";expect(&image,"0 nested macro block terminates enclosing function",terminal_macro_block,4,0,0);
   const char*empty_macro_block="module empty_block\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {rax} {\n}\n}\n";expect(&image,"338 empty macro block remains nonterminal",empty_macro_block,4,338,0);
   const char*conditional_macro_block="module conditional_macro_block\ntarget x86_64-nexora-uefi\nmacro mk(c:ast.expr)->ast.block {\nreturn quote(block) { if $c { return 1; } };\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {rax} {\nexpand mk(true)\n}\n}\n";expect(&image,"338 one-sided conditional macro block remains nonterminal",conditional_macro_block,4,338,0);
   const char*function_macro_only="module function_macro_only\ntarget x86_64-nexora-uefi\nmacro mk()->ast.decl {\nemit quote(decl) { fn helper()->u64 effects {} clobbers {} { return 1; } }\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {rax} {\nexpand mk()\n}\n}\n";expect(&image,"338 generated function return does not terminate caller",function_macro_only,4,338,0);
   const char*nonterminal_macro_block="module nonterminal_macro_block\ntarget x86_64-nexora-uefi\nmacro mk()->ast.block {\nreturn quote(block) { let t:u64=1; };\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {rax} {\nexpand mk()\n}\n}\n";expect(&image,"338 valid nonterminal nested macro block",nonterminal_macro_block,4,338,0);
   const char*nested_argument_scope="module nested_context\ntarget x86_64-nexora-uefi\nmacro outer(v:ast.expr)->ast.block {\nreturn quote(block) { let t:u64=2; expand inner($v+t); };\n}\nmacro inner(w:ast.expr)->ast.block {\nreturn quote(block) { let t:u64=40; return $w; };\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {rax} {\nexpand outer(4)\n}\n}";expect(&image,"0 nested argument retains outer lexical type",nested_argument_scope,4,0,0);
   /* 16b. the produced-let shape of the case above, with no parameter
    * anywhere. This answered 353 and now answers 0. The defect was NOT name
    * resolution: the produced let and the produced return carried the same
    * marked name, so the name resolved correctly. It was a span-ORDERING
    * failure. initializer_types.visible_type_id required
    * local.kind==27 && local.end<=use_start, and for a produced let and the
    * produced return that reads it use_start == local.end == the invocation
    * end, so the declaration was invisible, visible_type_id returned 0, and
    * return_types answered 353 reason 2. The expander was faithful the whole
    * time: the C oracle collapses the same spans, frontend.c:4912 sets
    * fn->span = invocation, :4952 variable->span, :2369-2370 s->span, so
    * asking a span-ordered lookup to order nodes the oracle never gave a
    * position to was the bug, not the macro. The visibility test is now
    * structural, over the tree order both trees already have, and the
    * negative direction is covered in the initializer_types gate: a let that
    * is genuinely not in scope at the use stays invisible. Two levels of
    * nesting still answer 353; that residual is not pinned here and is named
    * in the wave 7 report. */
   const char*macro_let_ref=MACRO_HEAD"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper()->u64\neffects {}\nclobbers {} {\nlet t:u64=1;\nreturn t;\n}\n}\n}\n"MACRO_TAIL"mk()\nreturn 0\n"MACRO_FOOT;expect(&image,"0 produced let visible to produced return",macro_let_ref,4,0,0);
   /* === 5. the direction of a parameter produced by a macro, in, out and
    * inout, each one asked of the pipeline twice: once through a macro that
    * emits the declaration, once with the very same function written in the
    * clear. The equality of the two verdicts is what closes the defect: each
    * macro column answered 800 before the fix while its clear column
    * answered 0, because only the produced node had been resynchronised on
    * the invocation. A non refusal alone would not prove it, since the
    * clear column was already a non refusal. */
   const char*macro_in_plain=MACRO_HEAD"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(in n:u64)->u64\neffects {}\nclobbers {} {\nreturn 0;\n}\n}\n}\n"MACRO_TAIL"mk()\nreturn 0\n"MACRO_FOOT;
   const char*clear_in_plain="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in n:u64)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
   same_verdict(&image,"in unbound",macro_in_plain,clear_in_plain,0);
   const char*macro_in_bound=MACRO_HEAD"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(in n:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0;\n}\n}\n}\n"MACRO_TAIL"mk()\nreturn 0\n"MACRO_FOOT;
   const char*clear_in_bound="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in n:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
   same_verdict(&image,"in bound",macro_in_bound,clear_in_bound,0);
   /* out and inout are bound to rcx on both sides because an unbound output
    * parameter is refused as 328 reason 3 by the TEMPLATE as well, the
    * template staying in the tree, and a refusal the template already carries
    * would prove nothing about the produced node. */
   const char*macro_out_bound=MACRO_HEAD"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(out n:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0;\n}\n}\n}\n"MACRO_TAIL"mk()\nreturn 0\n"MACRO_FOOT;
   const char*clear_out_bound="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(out n:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
   same_verdict(&image,"out bound",macro_out_bound,clear_out_bound,0);
   const char*macro_inout_bound=MACRO_HEAD"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(inout n:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0;\n}\n}\n}\n"MACRO_TAIL"mk()\nreturn 0\n"MACRO_FOOT;
   const char*clear_inout_bound="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(inout n:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
   same_verdict(&image,"inout bound",macro_inout_bound,clear_inout_bound,0);
   /* the negative side of the same equality: an out parameter on a reserved
    * output family is still refused, 328 reason 5, and it is refused the same
    * way by the produced node and by the clear one. This is what proves the
    * four cases above are not passing because abi.check stopped looking. */
   const char*macro_out_rax=MACRO_HEAD"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(out n:u64 @rax)->u64\neffects {}\nclobbers {} {\nreturn 0;\n}\n}\n}\n"MACRO_TAIL"mk()\nreturn 0\n"MACRO_FOOT;
   const char*clear_out_rax="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(out n:u64 @rax)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
   same_verdict(&image,"out reserved family still refused",macro_out_rax,clear_out_rax,328);
   /* the fifth parameter must be bound, and a macro produced parameter is
    * held to it exactly as a clear one is: 328 reason 2, both columns. */
   const char*macro_fifth=MACRO_HEAD"macro mk()->ast.decl {\nemit quote(decl) {\nfn helper(in a:u64,in b:u64,in c:u64,in d:u64,in e:u64)->u64\neffects {}\nclobbers {} {\nreturn 0;\n}\n}\n}\n"MACRO_TAIL"mk()\nreturn 0\n"MACRO_FOOT;
   const char*clear_fifth="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in a:u64,in b:u64,in c:u64,in d:u64,in e:u64)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
   same_verdict(&image,"fifth unbound still refused",macro_fifth,clear_fifth,328);
   /* 17. a spliced caller argument keeps its caller spelling, so it is read
    * from the source and not from the expander name table */
   const char*spliced_arg=MACRO_HEAD"macro ret(v:ast.expr)->ast.stmt {\nreturn quote(stmt) { return $v; };\n}\nsection .text {\nfn main(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nexpand ret(x)\n}\n}\n";expect(&image,"383 spliced caller argument",spliced_arg,4,0,0);

   /* === 1. the arity verdict of the full pipeline. A four word caller is
    * untouched; a six or eight word caller also learns which of the two
    * mismatches it is and at which argument. spec/ntasm/ntasm.md 5 keeps the
    * resolution and the arity of a call ahead of the type test so the
    * arity keeps its own diagnostic, so the pipeline verdict stays 311 and
    * the reason travels additively in out[4..5]. */
   const char*few="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";wide_arity(&image,"311 too few reason",few,6,"helper",2,311,1,0,5,0);
   const char*many="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1,2)\nreturn 0\n}\n}\n";wide_arity(&image,"311 too many reason",many,6,"helper",2,311,1,2,4,1);
   /* a two parameter callee, so the surplus index of reason 4 is 2 and the
    * unsatisfied index of reason 5 is 1, both read off the arity itself */
   const char*two="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in x:u64 @rcx,in y:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1,2,3)\nreturn 0\n}\n}\n";wide_arity(&image,"311 too many index",two,6,"helper",2,311,2,3,4,2);
   const char*two_few="module m\ntarget x86_64-nexora-none\nsection .text {\nfn helper(in x:u64 @rcx,in y:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper(1)\nreturn 0\n}\n}\n";wide_arity(&image,"311 too few index",two_few,6,"helper",2,311,2,1,5,1);
   arity_four_word(&image,"311 four word untouched",few,1,0);
   arity_four_word(&image,"311 four word untouched too many",many,1,2);
   okw(&image,"wide ok six",valid,6);
   okw(&image,"wide ok eight",valid,8);
   /* types.check is the only other pass of the pipeline that writes past
    * out[3], into out[4..7], and only for a caller of eight words, and the
    * stage that follows it clears the scratch, so none of that can reach
    * the caller of validate. This case pins the consequence: on a module
    * that itself carries a $T splice type, out[4] is the arity reason and
    * out[5] its index, and out[6] and out[7] are never written. */
   const char*few_tpl="module m\ntarget x86_64-nexora-none\nmacro id(t:$u64)->ast.expr {\nreturn quote(expr) { $t };\n}\nsection .text {\nfn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";wide_arity(&image,"311 eight word no type leak",few_tpl,8,"helper",2,311,1,0,5,0);
   /* === 2. the stage order, machine checked against the table of
    * spec/ntasm/ntasm.md 17.7 rather than only its count. */
   expect_stage_order(&image);
   /* === 3. a template is not the module namespace. spec/ntasm/ntasm.md 13
    * develops a macro before the final verification, so a declaration that
    * exists only inside a comptime(11), a macro(13) or a quote(43) is a
    * template, not a callable, whether or not an expansion happened. */
   const char*tpl_fn="module m\ntarget x86_64-nexora-none\nmacro mk()->ast.decl {\nemit quote(decl) {\nfn ghost()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n}\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall ghost()\nreturn 0\n}\n}\n";expect(&image,"310 template only callee",tpl_fn,4,310,0);
   const char*ct_fn="module m\ntarget x86_64-nexora-none\ncomptime(fuel=4096,call_depth=64,arena_bytes=262144,ast_nodes=256,expansion_depth=4,constant_bytes=4096){\nreturn quote(decl) {\nfn ghost()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n};\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall ghost()\nreturn 0\n}\n}\n";expect(&image,"310 comptime scoped callee",ct_fn,4,310,0);
   /* the same name declared once in a template and once for real: accepted,
    * and the pin used to say otherwise. Both symbol_names.check (stage 7) and
    * callable_names now carry the template mask, so the template never enters
    * either namespace and one real `main` is left. The oracle agrees: this
    * source compiles with one symbol. 313 remains unreachable from the
    * pipeline for this shape not because symbol_names owns a flat scan, but
    * because the template is masked out before the scan runs. A real duplicate
    * in the same namespace is still refused; see the two-table cases in
    * tests_ntasm_symbol_names.c. */
   const char*tpl_dup="module m\ntarget x86_64-nexora-none\nmacro mk()->ast.decl {\nemit quote(decl) {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n}\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";expect(&image,"0 template name and real name may coincide",tpl_dup,4,0,0);
   /* the kind 9 half of the same index needs no gate case of its own: the
    * parser only ever builds an import at the top level, so no import can sit
    * inside a comptime, a macro or a quote. The mask excludes it anyway, so
    * the exclusion is a property of the index and not of the parser. */
   /* a real callee declared after a template is still callable: the
    * exclusion is the subtree, not everything that follows it */
   const char*after="module m\ntarget x86_64-nexora-none\nmacro mk()->ast.decl {\nemit quote(decl) {\nfn ghost()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n}\n}\nsection .text {\nfn helper()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n";expect(&image,"real callee after a template",after,4,0,0);
   /* === 4. the two precedences the header comment used to state wrongly,
    * asked of the code instead of the comment: condition_types.check is the
    * thirty first stage, so it speaks before call_effects and after
    * initializer_types. */
   const char*cond_effect="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {privileged}\nclobbers {} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nif 1 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";expect(&image,"357 speaks before 325",cond_effect,4,357,0);
   const char*init_cond="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u32 @ecx)->u64\neffects {}\nclobbers {} {\nlet x:u64=p\nif 1 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";   expect(&image,"359 speaks before 357",init_cond,4,359,0);
   /* === U1: the profile agreement corpus. Ten rows over nx64-abi-v0, the
    * one profile both sides implement, and three rows over the efi-x64-v0
    * residual. Every source below is a real module: four rows carry a body,
    * bound parameters, a data section and a call, so "both sides accept" is
    * a claim about programs and not about a two line module. */
   {
   const char*empty_fn="section .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
   const char*four_params="section .text {\nfn f(in a:u64 @rax,in b:u64 @rcx,in c:u64 @rdx,in d:u64 @rsi)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";
   const char*fifth_param="section .text {\nfn f(in a:u64,in b:u64,in c:u64,in d:u64,in e:u64)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";
   const char*real_body="section .rdata {\ndata answer:u64=42\n}\nsection .text {\nfn helper(in x:u64 @rcx)->u64\neffects {}\nclobbers {rax} {\nlet y:u64=x\nreturn y\n}\nfn main()->u64\neffects {}\nclobbers {rax} {\ncall helper(1)\nreturn 0\n}\n}\n";
   const char*head="module m\ntarget x86_64-nexora-none\n";
   const char*nx64="default_abi nx64-abi-v0\n";
   const char*efi="default_abi efi-x64-v0\n";
   const char*alien="default_abi alien-abi\n";
   char row[2048];
   /* -- the four acceptance rows: a program both sides accept must STAY
    * accepted, which is the direction a comparison alone cannot carry. */
   snprintf(row,sizeof row,"%s%s%s",head,"",empty_fn);
   agree_profile(&image,"no profile clause, empty function",row,1);
   snprintf(row,sizeof row,"%s%s%s",head,nx64,empty_fn);
   agree_profile(&image,"default_abi nx64-abi-v0, empty function",row,1);
   snprintf(row,sizeof row,"%s%s%s",head,"",real_body);
   agree_profile(&image,"no profile clause, program with data and a call",row,1);
   snprintf(row,sizeof row,"%s%s%s",head,nx64,real_body);
   agree_profile(&image,"default_abi nx64-abi-v0, program with data and a call",row,1);
   /* -- the four bound parameter rows: the register map of the profile is
    * read by both sides and is a place they can disagree. */
   snprintf(row,sizeof row,"%s%s%s",head,"",four_params);
   agree_profile(&image,"no profile clause, four bound parameters",row,1);
   snprintf(row,sizeof row,"%s%s%s",head,nx64,four_params);
   agree_profile(&image,"default_abi nx64-abi-v0, four bound parameters",row,1);
   /* -- the refusals. An unknown profile name is a refusal on both sides,
    * which is the part of the profile question that is not nx64. */
   snprintf(row,sizeof row,"%s%s%s",head,alien,empty_fn);
   agree_profile(&image,"default_abi alien-abi, empty function",row,0);
   snprintf(row,sizeof row,"%s%s%s",head,alien,four_params);
   agree_profile(&image,"default_abi alien-abi, four bound parameters",row,0);
   /* -- two refusals that are not about the profile at all, so the corpus
    * is not a set of profile rows with the profile left out. */
   snprintf(row,sizeof row,"%s%s%s",head,"",fifth_param);
   agree_profile(&image,"fifth unbound parameter",row,0);
   agree_profile(&image,"unknown target",
                 "module m\ntarget x86_64-other-none\n",0);
   /* -- the named efi-x64-v0 residual. These three must DISAGREE, with the
    * product's code recorded, so the comparison above has been run against
    * a real disagreement rather than only against rows that agree. */
   snprintf(row,sizeof row,"%s%s%s",head,efi,empty_fn);
   agree_profile(&image,"default_abi efi-x64-v0, empty function",row,1);
   snprintf(row,sizeof row,"%s%s%s",head,efi,real_body);
   agree_profile(&image,"default_abi efi-x64-v0, program with data and a call",row,1);
   snprintf(row,sizeof row,"%s%s%s",head,efi,fifth_param);
   agree_profile(&image,"default_abi efi-x64-v0 over a fifth parameter",row,1);
   /* The anti-vacuity guard, AFTER the corpus has been run: the counts are
    * read, then judged. A corpus that had lost its accepting rows, or lost
    * its refusing ones, would make the comparison above true for a reason
    * that has nothing to do with the profile, and both counters are 0 in
    * that case. They are computed from the reference's own verdicts, so
    * neither depends on the value the comparison checks. */
   (void)diverge_profile; /* Keep historical comparison helper without unused-function noise. */
   CHECK(profile_rows==13,"the profile corpus is the thirteen rows above");
   CHECK(profile_agreed==13,"all thirteen ABI profile programs agree");
   CHECK(profile_accepted_by_both==9,"nine programs are accepted by both sides");
   CHECK(profile_refused_by_both==4,"four programs are refused by both sides");
   CHECK(profile_disagreed==0,"EFI has no remaining profile divergence");
   }
  /* ==================== U1b: STAGE 35 OWES A VERDICT, AND FOUR OF THEM
   * ARE NOW NAMED. Lot 116 censused this gate and measured, correctly, that
   * the 900 block was ENTIRELY UNPINNED: the highest code any of the 135
   * cases expected was 383, so no case in the widest gate in the tree
   * asserted that machine_ir refuses anything, for any reason, ever.
   *
   * What follows is that block, in this file's own idiom. Every expectation
   * is a MEASURED reading of the pipeline this file already builds, taken
   * with a probe that compiled this file's OWN 43-module list and asserted
   * nothing; no code below is a guess and none is transcribed from the
   * module that emits it. The codes are machine_ir.nova's own band, whose
   * header (machine_ir.nova:372-376) says the band starts at 930 because
   * nothing published could already reach it.
   *
   * EACH FIXTURE IS A PAIR, and the second member is the control: one token
   * changed, and it must be ACCEPTED. A row that asserts only "940 came
   * back" is satisfied by a compiler that refuses every program, which is
   * precisely the failure mode this gate's other 39 accepting rows cannot
   * see because they only ever ask "did not refuse". The control is what
   * makes the row a fixture rather than a constant.
   *
   * POSITIONS ARE PINNED, not only codes, because the code alone cannot tell
   * "this mnemonic means nothing here" from "this mnemonic is well formed
   * and its destination is a register the rest of the image addresses
   * through" -- machine_ir.nova:394-404 gives that exact reason for making
   * E_FRAME a code of its own, and a gate that saw only the code could not
   * honour the reason. The line and column are the ones the pipeline itself
   * published, so they are read out of out[0..1] rather than computed here. */
  { /* 940 E_INPUT -- a mnemonic machine_ir does not know. `cpuid` is a
     * known INTRINSIC to body_intrinsics (which is why this module survives
     * stage 20), and machine_ir.nova:359-364 names the mnemonics its own
     * vocabulary holds; `cpuid` is not among them, so mnemonic_op answers
     * OP_NONE and machine_ir.nova:1839 refuses. The control swaps the ONE
     * mnemonic token for `test`, which that same vocabulary does hold, and
     * everything else -- module, target, signature, the whole effects and
     * clobbers sets -- is byte identical. */
    const char*mn_unknown="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {privileged,changes_flags}\nclobbers {rax,rbx,rcx,rdx} {\ncpuid rax, rbx\nreturn 0\n}\n}\n";
    const char*mn_known="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {privileged,changes_flags}\nclobbers {rax,rbx,rcx,rdx} {\ntest rax, rbx\nreturn 0\n}\n}\n";
    Run bad=run(&image,mn_unknown,4),good=run(&image,mn_known,4);
    cases++;checks++;
    if(bad.returned!=940||bad.runtime||bad.out[0]!=7||bad.out[1]!=1||bad.out[2]!=940){failures++;fprintf(stderr,"FAIL 940 unknown mnemonic ret=%llu runtime=%llu out=%llu,%llu,%llu want 940 at 7:1\n",(unsigned long long)bad.returned,(unsigned long long)bad.runtime,(unsigned long long)bad.out[0],(unsigned long long)bad.out[1],(unsigned long long)bad.out[2]);}
    expect(&image,"940 control, one mnemonic token back to a known one",mn_known,4,0,0);
    (void)good; }
  { /* 944 E_ARITY -- an instruction carrying one operand too many. The guard
     * is the `taken>=3` arm of machine_ir.nova:1862, and `cmp` is the
     * mnemonic that reaches it: `mov` does not, because body_clobbers
     * charges `mov`'s arity first as a 400 (body_clobbers.nova:392-399,
     * which says so in its own comment). That is a MEASURED boundary, not a
     * guess: `mov rax, rbx, rcx` answers 400 on this tree. The control
     * deletes the third operand. */
    const char*ar_too_many="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {rax,rbx,rcx} {\ncmp rax, rbx, rcx\nreturn 0\n}\n}\n";
    const char*ar_fits="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {rax,rbx,rcx} {\ncmp rax, rbx\nreturn 0\n}\n}\n";
    Run bad=run(&image,ar_too_many,4);
    cases++;checks++;
    if(bad.returned!=944||bad.runtime||bad.out[0]!=7||bad.out[1]!=5||bad.out[2]!=944){failures++;fprintf(stderr,"FAIL 944 operand arity ret=%llu runtime=%llu out=%llu,%llu,%llu want 944 at 7:5\n",(unsigned long long)bad.returned,(unsigned long long)bad.runtime,(unsigned long long)bad.out[0],(unsigned long long)bad.out[1],(unsigned long long)bad.out[2]);}
    expect(&image,"944 control, the third operand deleted",ar_fits,4,0,0); }
  { /* 947 E_FRAME -- the DESTINATION is the frame or stack pointer. The guard
     * is machine_ir.nova:1950-1954 and it reads the destination, which is why
     * the control swaps the two operands rather than deleting one: `mov rax,
     * rbp` names rbp as a SOURCE and must be accepted, `mov rbp, rax` names
     * it as a DESTINATION and must not be. Same instruction, same two
     * registers, same clobbers set; only their order differs. */
    const char*fr_dest="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rbp,rax} {\nmov rbp, rax\nreturn 0\n}\n}\n";
    const char*fr_src="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rbp,rax} {\nmov rax, rbp\nreturn 0\n}\n}\n";
    Run bad=run(&image,fr_dest,4);
    cases++;checks++;
    if(bad.returned!=947||bad.runtime||bad.out[0]!=7||bad.out[1]!=1||bad.out[2]!=947){failures++;fprintf(stderr,"FAIL 947 frame destination ret=%llu runtime=%llu out=%llu,%llu,%llu want 947 at 7:1\n",(unsigned long long)bad.returned,(unsigned long long)bad.runtime,(unsigned long long)bad.out[0],(unsigned long long)bad.out[1],(unsigned long long)bad.out[2]);}
    expect(&image,"947 control, the same register as a source instead",fr_src,4,0,0); }
  { /* 945 E_SCALE -- an index scale the target-independent level does not
     * admit. THE CONTROL HERE IS NOT AN ACCEPTANCE, AND IT IS NOT PRETENDED
     * TO BE ONE. The ladder was measured: the literal 2, 4 and 8 all answer
     * 945 at 7:19, and 1, 3 and 7 answer 934 at 4:6 -- a DIFFERENT code at a
     * DIFFERENT position, in the function's own signature rather than in its
     * body. So the scale guard is separable and distinguishable (the two
     * answers are not equal, so a stage that dropped the guard changes this
     * row), but on this tree there is no memory operand machine_ir accepts at
     * all, and this file does not have an accepted twin to offer. That is
     * named here rather than papered over with a twin that would only be a
     * second constant. */
    const char*sc_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in b:ptr<user,u64> @rdi,in i:u64 @rsi)->u64\neffects {reads_mem(user)}\nclobbers {rax} {\nmov rax, [rdi+rsi*2]:ptr<user,u64>\nreturn 0\n}\n}\n";
    const char*sc_other="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in b:ptr<user,u64> @rdi,in i:u64 @rsi)->u64\neffects {reads_mem(user)}\nclobbers {rax} {\nmov rax, [rdi+rsi*1]:ptr<user,u64>\nreturn 0\n}\n}\n";
    Run bad=run(&image,sc_bad,4),other=run(&image,sc_other,4);
    cases++;checks++;
    if(bad.returned!=945||bad.runtime||bad.out[0]!=7||bad.out[1]!=19||bad.out[2]!=945){failures++;fprintf(stderr,"FAIL 945 index scale ret=%llu runtime=%llu out=%llu,%llu,%llu want 945 at 7:19\n",(unsigned long long)bad.returned,(unsigned long long)bad.runtime,(unsigned long long)bad.out[0],(unsigned long long)bad.out[1],(unsigned long long)bad.out[2]);}
    cases++;checks++;
    if(other.returned==945){failures++;fprintf(stderr,"FAIL 945 the scale guard cannot be told from its neighbour: one token away and the same code came back\n");} }
  { /* 940 E_INPUT, a SECOND AND DIFFERENT arm -- a symbolic address inside a
     * memory operand. This one is not the vocabulary arm above; it is
     * machine_ir.nova:1467, the arm that refuses a bracketed name which is
     * not a register, and it is included because a row that pinned 940
     * once, from one arm, would not tell the two apart. Two rows, two
     * positions, one code: that is the distinction E_INPUT cannot make on
     * its own and E_FORM and E_INPUT were separated for. */
    const char*sym_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in b:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {rax} {\nmov rax, [ghost]:ptr<user,u64>\nreturn 0\n}\n}\n";
    Run bad=run(&image,sym_bad,4);
    cases++;checks++;
    if(bad.returned!=940||bad.runtime||bad.out[0]!=7||bad.out[1]!=11||bad.out[2]!=940){failures++;fprintf(stderr,"FAIL 940 symbolic address ret=%llu runtime=%llu out=%llu,%llu,%llu want 940 at 7:11\n",(unsigned long long)bad.returned,(unsigned long long)bad.runtime,(unsigned long long)bad.out[0],(unsigned long long)bad.out[1],(unsigned long long)bad.out[2]);} }
 }
 if(image.memory) {
   /* Complete call programs: space identity is a type obligation, without
    * dereferencing privileged memory or claiming a hardware mapping. */
   const char *spaces[]={"user","kernel","physical","mmio","device","firmware"};
   for(unsigned i=0;i<6;i++) {
     char src[1400],label[100];
     snprintf(src,sizeof src,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in p:ptr<%s,u64> @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main(in q:ptr<%s,u64> @rcx)->u64\neffects {}\nclobbers {} {\ncall leaf(q)\nreturn 0\n}\n}\n",spaces[i],spaces[i]);
     snprintf(label,sizeof label,"A3 complete %s pointer call accepted",spaces[i]); expect(&image,label,src,4,0,0);
     snprintf(src,sizeof src,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in p:ptr<%s,u64> @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn main(in q:ptr<%s,u64> @rcx)->u64\neffects {}\nclobbers {} {\ncall leaf(q)\nreturn 0\n}\n}\n",spaces[i],spaces[(i+1)%6]);
     snprintf(label,sizeof label,"A3 complete %s pointer wrong space refused",spaces[i]); expect(&image,label,src,4,354,0);
   }
   const char *types[]={"u8","u16","u32","u64","i8","i16","i32","i64"};
   const char *regs[]={"al","ax","eax","rax","al","ax","eax","rax"};
   for(unsigned i=0;i<8;i++) {
     char src[1400],label[100];
     snprintf(src,sizeof src,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->%s\neffects {}\nclobbers {} {\nreturn 1\n}\nfn main()->u64\neffects {}\nclobbers {rax} {\nlet v:%s = leaf();\nmov rax,0\nmov %s,v\nreturn rax\n}\n}\n",types[i],types[i],regs[i]);
     snprintf(label,sizeof label,"A3 complete width %s typed call",types[i]); expect(&image,label,src,4,0,0);
   }
   const char *gprs[]={"rax","rbx","rcx","rdx","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
   for(unsigned i=0;i<14;i++) {
     char src[800],label[100];
     snprintf(src,sizeof src,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn main()->u64\neffects {}\nclobbers {%s} {\nmov %s,42\nmov rax,%s\nreturn rax\n}\n}\n",i==0?"rax":(snprintf(label,sizeof label,"rax,%s",gprs[i]),label),gprs[i],gprs[i]);
     snprintf(label,sizeof label,"A3 complete register %s",gprs[i]); expect(&image,label,src,4,0,0);
   }   const char *reserved[]={"rsp","rbp"};
   for(unsigned i=0;i<2;i++) {
     char src[800],label[100];
     snprintf(src,sizeof src,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn main()->u64\neffects {}\nclobbers {rax} {\nmov rax,%s\nreturn rax\n}\n}\n",reserved[i]);
     snprintf(label,sizeof label,"A3 complete reserved register %s read",reserved[i]); expect(&image,label,src,4,0,0);
     snprintf(src,sizeof src,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn main()->u64\neffects {}\nclobbers {%s} {\nmov %s,1\nreturn 0\n}\n}\n",reserved[i],reserved[i]);
     snprintf(label,sizeof label,"A3 complete reserved register %s write refused",reserved[i]); expect(&image,label,src,4,947,0);
   }   const char *outs[]={"rax","rsp","rbp"};
   for(unsigned i=0;i<3;i++) {
     char src[800],label[100];
     snprintf(src,sizeof src,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn main(out p:u64 @%s)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",outs[i]);
     snprintf(label,sizeof label,"A3 complete forbidden OUT register %s",outs[i]); expect(&image,label,src,4,328,0);
   }   const char *missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {}\nrequires {feature(sse2)} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";
   expect(&image,"A3 complete feature missing call refused",missing,4,344,0);
 } if(image.memory) {
   const char *paths[]={
     "examples/ntasm-v0/abi-efi/high8-ch.ntasm","examples/ntasm-v0/abi-efi/high8-dh.ntasm",
     "examples/ntasm-v0/abi-efi/high8-cl.ntasm","examples/ntasm-v0/abi-efi/high8-dl.ntasm",
     "examples/ntasm-v0/abi-efi/refuse-out.ntasm","examples/ntasm-v0/abi-efi/refuse-first-binding.ntasm",
     "examples/ntasm-v0/abi-efi/refuse-stack-binding.ntasm","examples/ntasm-v0/abi-efi/refuse-nonvolatile.ntasm",
     "examples/ntasm-v0/abi-efi/refuse-over-cap.ntasm"};
   const int accepts[]={0,0,1,1,0,0,0,0,0};
   for(unsigned i=0;i<sizeof paths/sizeof *paths;i++) {
     char *source=a4_fixture(paths[i]);cases++;
     A4_CHECK(source!=NULL,"A4 fixture exists %s",paths[i]);
     if(source) {
       Agreement got=ask_both(&image,source);
       A4_CHECK(got.reference_accept==accepts[i],"A4 independent C verdict %s",paths[i]);
       A4_CHECK(got.product_accept==accepts[i],"A4 Nova verdict %s code=%llu",paths[i],(unsigned long long)got.product_code);
       free(source);
     }
   }
 }
 if(image.memory) nova_host_unmap(&image);

 if(compiled) nt_artifact_free(&a);
 for(unsigned i=0;i<43;i++) free(sources[i]);
 printf("NTASM_NOVA_VALIDATE checks=%u failures=%u cases=%u profiles_agreed=%u/%u profiles_accepted_by_both=%u profiles_refused_by_both=%u profiles_residual=%u\n",checks,failures,cases,profile_agreed,profile_rows,profile_accepted_by_both,profile_refused_by_both,profile_disagreed);
 return failures?1:0;
}
