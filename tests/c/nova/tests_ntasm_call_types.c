#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntasm_pipeline_parity.h"
/* ====================== pipeline parity ==============================
   Every non zero code this gate asserts is a CLAIM ABOUT the 34 stage
   pipeline of validate.nova, and this entry compiles a SUB-CHAIN of it:
   index, callable_names, types, register_widths, refs, calls, call_types,
   initializer_types.  Nothing measured that claim until the shared helper
   nova/ntasm_pipeline_parity.h ran every source of this file through the
   41 module validate image as well and compared the two verdicts.  The
   table beneath is the set of (this gate, the pipeline) divergence pairs
   this file exhibits, written down from that measurement: a pair that is
   not listed fails the gate, and a listed pair that stops occurring fails
   it too, so the table cannot rot into a comment. */
// (354 -> 311)  The SOLO cases only. runm with selector 1 asks call_types.check
// alone, so it answers 354 for an arity mismatch; the 41 module pipeline runs
// stage calls(28) first, and calls.check answers 311 for the same source. This
// gate asserts both, on purpose: 311 is the four word arity contract the
// pipeline can actually see and 354 is the six word extension, and only
// call_types-alone reaches the extension.
// (354 -> 329)  inout wrong type. abi(17) refuses 329 reason 1 -- an inout
// (direction 3) parameter whose type is neither integer nor pointer (`bool`),
// which this fixture's `fn g(inout x:bool @al)` is -- and stage 17 runs long
// before call_types(29), so the pipeline never reaches 354. The gate's own
// sub-chain does not carry abi at all.
// (354 -> 317)  The two bool-argument cases whose callee signature binds @cl
// and @rcx in one declaration. register_bindings(14) refuses 317 on the second
// occurrence of the same register family -- register_widths.family maps both
// `cl` and `rcx` to family 2 -- and stage 14 runs before call_types(29). The
// gate's sub-chain does not carry register_bindings.
// (354 -> 375)  The two depth cases (65 nested parens, 64 nested `!`). 375 is
// macro_expand's walk-depth cap (`return fail(env,375,9,...)`, macro_expand.nova
// :1408/:1881); stage expand(1) is the first stage, so the pipeline stops there
// and never reaches call_types' own reason-3 depth verdict. The gate's
// sub-chain does not carry macro_expand.
static const NgParityPair ng_parity_pairs[]={
  {354,311},{354,329},{354,317},{354,375}};
static NgParitySpec ng_parity={
  "call_types",
  {"index","callable_names","types","register_widths","refs","calls","call_types","initializer_types"},8,
  1,
  ng_parity_pairs,(unsigned)(sizeof ng_parity_pairs/sizeof ng_parity_pairs[0]),
  0,0,0,0,0,0,0,0,NULL};
static char ng_parity_err[256];
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[5];}Run;
// runm passes a `words`-word out buffer. A fifth word is preloaded with the
// stage selector the entry module reads (0 full prefix, 1 call_types alone).
static Run runm(const NovaHostImage*i,const char*n,const char*s,uint64_t words,uint64_t selector){Run r={.out={guard,guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);if(words>=5){r.out[4]=selector;}uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");ng_parity_check(&checks,&failures,&ng_parity,n,s,r.returned);return r;}
static Run run(const NovaHostImage*i,const char*n,const char*s,uint64_t words){return runm(i,n,s,words,0);}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t calls,uint64_t args,uint64_t checked){Run r=run(i,n,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=calls||r.out[1]!=args||r.out[2]!=checked||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu out=%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2]);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t reason,uint64_t index){Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=354||r.runtime||r.out[0]==guard||r.out[1]==guard||r.out[2]!=reason||r.out[3]!=index){failures++;fprintf(stderr,"FAIL err %s ret=%llu out=%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run(i,n,s,words);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL invalid %s\n",n);}}
// call_types.check alone: selector 1 in out[4], five-word out.
static void solo_ok(const NovaHostImage*i,const char*n,const char*s,uint64_t calls,uint64_t args,uint64_t checked){Run r=runm(i,n,s,5,1);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=calls||r.out[1]!=args||r.out[2]!=checked||r.out[3]){failures++;fprintf(stderr,"FAIL solo ok %s ret=%llu out=%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2]);}}
static void solo_err(const NovaHostImage*i,const char*n,const char*s,uint64_t reason,uint64_t index){Run r=runm(i,n,s,5,1);cases++;checks++;if(r.returned!=354||r.runtime||r.out[0]==guard||r.out[1]==guard||r.out[2]!=reason||r.out[3]!=index){failures++;fprintf(stderr,"FAIL solo err %s ret=%llu reason=%llu index=%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void solo_bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=runm(i,n,s,words,1);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL solo invalid %s ret=%llu\n",n,(unsigned long long)r.returned);}}
// call_types.check alone, exact reported position: out[0]=line, out[1]=column.
static void solo_at(const NovaHostImage*i,const char*n,const char*s,uint64_t reason,uint64_t index,uint64_t line,uint64_t column){Run r=runm(i,n,s,5,1);cases++;checks++;if(r.returned!=354||r.runtime||r.out[2]!=reason||r.out[3]!=index||r.out[0]!=line||r.out[1]!=column){failures++;fprintf(stderr,"FAIL solo at %s ret=%llu reason=%llu index=%llu line=%llu column=%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[2],(unsigned long long)r.out[3],(unsigned long long)r.out[0],(unsigned long long)r.out[1]);}}
// The full prefix: calls.check answers every arity mismatch with 311 before
// call_types.check runs, writing expected and received arity to out[2..3].
static void arity311(const NovaHostImage*i,const char*n,const char*s,uint64_t expected,uint64_t received){Run r=runm(i,n,s,4,0);cases++;checks++;if(r.returned!=311||r.runtime||r.out[0]==guard||r.out[1]==guard||r.out[2]!=expected||r.out[3]!=received){failures++;fprintf(stderr,"FAIL arity %s ret=%llu expected=%llu received=%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
int main(void){const char*paths[]={"tests/nova/tests/call-types-entry.nova","compiler/nova/analysis/calls/call_types.nova","compiler/nova/analysis/types/initializer_types.nova","compiler/nova/analysis/types/register_widths.nova","compiler/nova/analysis/calls/calls.nova","compiler/nova/frontend/refs.nova","compiler/nova/analysis/types/types.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[12]={0};NtFInput inputs[12];for(unsigned i=0;i<12;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<12;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,12,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");int parity=ng_parity_begin(&ng_parity,&failures,ng_parity_err,sizeof ng_parity_err);if(image.memory&&parity==0){
/* Regression: ABI clauses share kind 28 with call statements. */
const char *explicit_abi_none="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
ok(&image,"explicit ABI is not a call",explicit_abi_none,0,0,0);
const char *explicit_abi_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in x:u8 @al)->u8\nabi nx64-abi-v0\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {} {\ncall leaf(255)\nreturn 0\n}\n}\n";
ok(&image,"explicit ABI real call retained",explicit_abi_call,1,1,1);
const char *explicit_abi_range="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf(in x:u8 @al)->u8\nabi nx64-abi-v0\neffects {}\nclobbers {} {\nreturn x\n}\nfn main()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {} {\ncall leaf(256)\nreturn 0\n}\n}\n";
err(&image,"explicit ABI range still refused",explicit_abi_range,2,0);

const char*literal="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u8 @al)->u8\neffects {}\nclobbers {} {\nreturn x\n}\nfn f()->u64\neffects {}\nclobbers {} {\ncall g(255)\nreturn 0\n}\n}\n";ok(&image,"literal",literal,1,1,1);
const char*range="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u8 @al)->u8\neffects {}\nclobbers {} {\nreturn x\n}\nfn f()->u64\neffects {}\nclobbers {} {\ncall g(256)\nreturn 0\n}\n}\n";err(&image,"range",range,2,0);
const char*param="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u32 @edi)->u32\neffects {}\nclobbers {} {\nreturn x\n}\nfn f(in y:u32 @edi)->u64\neffects {}\nclobbers {} {\ncall g(y)\nreturn 0\n}\n}\n";ok(&image,"param",param,1,1,1);
const char*param_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u64 @rdi)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn f(in y:u32 @edi)->u64\neffects {}\nclobbers {} {\ncall g(y)\nreturn 0\n}\n}\n";err(&image,"param mismatch",param_bad,1,0);
const char*local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u16 @di)->u16\neffects {}\nclobbers {} {\nreturn x\n}\nfn f()->u64\neffects {}\nclobbers {} {\nlet y:u16=1\ncall g(y)\nreturn 0\n}\n}\n";ok(&image,"local",local,1,1,1);
const char*nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn h()->u32\neffects {}\nclobbers {} {\nreturn 1\n}\nfn g(in x:u32 @edi)->u32\neffects {}\nclobbers {} {\nreturn x\n}\nfn f()->u64\neffects {}\nclobbers {} {\ncall g(h())\nreturn 0\n}\n}\n";ok(&image,"nested call",nested,2,1,1);
const char*nested_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn h()->u32\neffects {}\nclobbers {} {\nreturn 1\n}\nfn g(in x:u64 @rdi)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn f()->u64\neffects {}\nclobbers {} {\ncall g(h())\nreturn 0\n}\n}\n";err(&image,"nested mismatch",nested_bad,1,0);
const char*out_only="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(out x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f()->u64\neffects {}\nclobbers {} {\ncall g()\nreturn 0\n}\n}\n";ok(&image,"out",out_only,1,0,0);
const char*boolean="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:bool @al)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f()->u64\neffects {}\nclobbers {} {\ncall g(true)\nreturn 0\n}\n}\n";ok(&image,"bool",boolean,1,1,1);
const char*expression="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u64 @rdi)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\ncall g(1+(2*3))\nreturn 0\n}\n}\n";ok(&image,"nested expression",expression,1,1,1);
const char*expression_mismatch="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u64 @rdi)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn f(in y:u32 @edi)->u64\neffects {changes_flags}\nclobbers {} {\ncall g(1+(y*3))\nreturn 0\n}\n}\n";err(&image,"nested mismatch",expression_mismatch,1,0);
const char*expression_range="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u8 @al)->u8\neffects {}\nclobbers {} {\nreturn x\n}\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\ncall g(1+(2*256))\nreturn 0\n}\n}\n";err(&image,"nested range",expression_range,2,0);
const char*expression_unknown="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u64 @rdi)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\ncall g(1+(-2))\nreturn 0\n}\n}\n";err(&image,"unsigned negative mismatch",expression_unknown,1,0);
const char*pointer="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in p:ptr<user,u8> @rdi)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f(in q:ptr<user,u8> @rdi)->u64\neffects {}\nclobbers {} {\ncall g(q)\nreturn 0\n}\n}\n";ok(&image,"pointer",pointer,1,1,1);
const char*second_arg="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in a:u64 @rcx,in b:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn f(in y:u32 @ecx)->u64\neffects {changes_flags}\nclobbers {} {\ncall g(1,1+(y*3))\nreturn 0\n}\n}\n";err(&image,"second argument mismatch",second_arg,1,1);
char deep[1024]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in x:u64 @rdi)->u64\neffects {}\nclobbers {} {\nreturn x\n}\nfn f()->u64\neffects {}\nclobbers {} {\ncall g(";
for(unsigned i=0;i<65;i++)strcat(deep,"(");
strcat(deep,"1");
for(unsigned i=0;i<65;i++)strcat(deep,")");
strcat(deep,")\nreturn 0\n}\n}\n");
err(&image,"depth limit",deep,3,0);
const char*sibling="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in v:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn v\n}\nfn f()->u64\neffects {}\nclobbers {} {\nif true {\nlet x:u64=1\n}\ncall g(x)\nreturn 0\n}\n}\n";err(&image,"sibling local not visible",sibling,3,0);
const char*simple_local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in v:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn v\n}\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\ncall g(x)\nreturn 0\n}\n}\n";ok(&image,"simple argument name",simple_local,1,1,1);
const char*qualified_local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in v:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn v\n}\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\ncall g(bogus.x)\nreturn 0\n}\n}\n";err(&image,"qualified argument rejected",qualified_local,3,0);
const char*unary_arguments="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in a:u64 @rcx,in b:u64 @rdx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn f(in x:u64 @rcx,in y:u64 @rdx)->u64\neffects {}\nclobbers {} {\ncall g(+x,~y)\nreturn 0\n}\n}\n";ok(&image,"unary plus and bitnot arguments",unary_arguments,1,2,2);
const char*negative_min="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in a:i8 @cl)->i8\neffects {}\nclobbers {} {\nreturn a\n}\nfn f()->u64\neffects {}\nclobbers {} {\ncall g(-128)\nreturn 0\n}\n}\n";ok(&image,"negative signed minimum argument",negative_min,1,1,1);
const char*negative_range="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in a:i8 @cl)->i8\neffects {}\nclobbers {} {\nreturn a\n}\nfn f()->u64\neffects {}\nclobbers {} {\ncall g(-129)\nreturn 0\n}\n}\n";err(&image,"negative signed range argument",negative_range,2,0);
const char*negative_unsigned="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in a:u8 @al)->u8\neffects {}\nclobbers {} {\nreturn a\n}\nfn f()->u64\neffects {}\nclobbers {} {\ncall g(-1)\nreturn 0\n}\n}\n";err(&image,"negative unsigned argument",negative_unsigned,1,0);
const char*bool_mixed="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn g(in b:bool @al)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f(in ready:bool @cl,in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\ncall g(!(ready) && (pred() || (x<5)))\nreturn 0\n}\n}\n";ok(&image,"call bool argument mixed expression",bool_mixed,2,1,1);
const char*bool_comparison="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in b:bool @al)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\ncall g(x<5)\nreturn 0\n}\n}\n";ok(&image,"call bool argument comparison",bool_comparison,1,1,1);
const char*bool_second="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in a:u64 @rcx,in b:bool @al)->u64\neffects {}\nclobbers {} {\nreturn a\n}\nfn f(in ready:bool @cl,in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\ncall g(1,ready && bogus.q)\nreturn 0\n}\n}\n";err(&image,"call second bool argument unproved",bool_second,3,1);
const char*bool_nonbool="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in b:bool @al)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f(in ready:bool @cl,in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\ncall g(ready && x)\nreturn 0\n}\n}\n";err(&image,"call bool argument with integer operand",bool_nonbool,1,0);
const char*bool_unproved="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in b:bool @al)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f(in ready:bool @cl)->u64\neffects {}\nclobbers {} {\ncall g(ready && bogus.x)\nreturn 0\n}\n}\n";err(&image,"call bool argument with unproved operand",bool_unproved,3,0);
char deep_not_ok[1024]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in b:bool @al)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f(in ready:bool @cl)->u64\neffects {}\nclobbers {} {\ncall g(";for(unsigned i=0;i<63;i++)strcat(deep_not_ok,"!");strcat(deep_not_ok,"ready)\nreturn 0\n}\n}\n");ok(&image,"call bool argument depth 64",deep_not_ok,1,1,1);
char deep_not_bad[1024]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g(in b:bool @al)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\nfn f(in ready:bool @cl)->u64\neffects {}\nclobbers {} {\ncall g(";for(unsigned i=0;i<64;i++)strcat(deep_not_bad,"!");strcat(deep_not_bad,"ready)\nreturn 0\n}\n}\n");err(&image,"call bool argument depth 65",deep_not_bad,3,0);
// Direction words are read whole. A parameter span opens on the direction
// keyword, so `outbound`, `input`, `outer` and `inoutbox` are ordinary
// in-direction names and must never be read as out.
const char*head="module m\ntarget x86_64-nexora-none\nsection .text {\n";
const char*tail_f="fn f()->u64\neffects {}\nclobbers {} {\n";
const char*tail_e="return 0\n}\n}\n";
char ob_in[512],ob_in_bad[512],ob_out[512],in_name[512],outer_ok[512],outer_bad[512],inoutbox[512],inout_ok[512],inout_bad[512],inout_named[512];
sprintf(ob_in,"%sfn g(in outbound:u8 @al)->u8\neffects {}\nclobbers {} {\nreturn outbound\n}\n%scall g(1)\n%s",head,tail_f,tail_e);
sprintf(ob_in_bad,"%sfn g(in outbound:bool @al)->bool\neffects {}\nclobbers {} {\nreturn outbound\n}\n%scall g(1)\n%s",head,tail_f,tail_e);
sprintf(ob_out,"%sfn g(out outbound:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n%scall g()\n%s",head,tail_f,tail_e);
sprintf(in_name,"%sfn g(in input:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn input\n}\n%scall g(1)\n%s",head,tail_f,tail_e);
sprintf(outer_ok,"%sfn g(in outer:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn outer\n}\n%scall g(1)\n%s",head,tail_f,tail_e);
sprintf(outer_bad,"%sfn g(in outer:u8 @al)->u8\neffects {}\nclobbers {} {\nreturn outer\n}\n%scall g(256)\n%s",head,tail_f,tail_e);
sprintf(inoutbox,"%sfn g(in inoutbox:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn inoutbox\n}\n%scall g(1)\n%s",head,tail_f,tail_e);
sprintf(inout_ok,"%sfn g(inout x:u8 @al)->u8\neffects {}\nclobbers {} {\nreturn x\n}\n%scall g(1)\n%s",head,tail_f,tail_e);
sprintf(inout_bad,"%sfn g(inout x:bool @al)->bool\neffects {}\nclobbers {} {\nreturn x\n}\n%scall g(1)\n%s",head,tail_f,tail_e);
sprintf(inout_named,"%sfn g(inout inoutbox:u8 @al)->u8\neffects {}\nclobbers {} {\nreturn inoutbox\n}\n%scall g(1)\n%s",head,tail_f,tail_e);
ok(&image,"outbound in",ob_in,1,1,1);solo_ok(&image,"outbound in solo",ob_in,1,1,1);
err(&image,"outbound in wrong type",ob_in_bad,1,0);solo_err(&image,"outbound in wrong type solo",ob_in_bad,1,0);
ok(&image,"outbound out",ob_out,1,0,0);solo_ok(&image,"outbound out solo",ob_out,1,0,0);
ok(&image,"input in",in_name,1,1,1);solo_ok(&image,"input in solo",in_name,1,1,1);
ok(&image,"outer in",outer_ok,1,1,1);solo_ok(&image,"outer in solo",outer_ok,1,1,1);
err(&image,"outer in wrong type",outer_bad,2,0);solo_err(&image,"outer in wrong type solo",outer_bad,2,0);
ok(&image,"inoutbox in",inoutbox,1,1,1);solo_ok(&image,"inoutbox in solo",inoutbox,1,1,1);
ok(&image,"inout consumes",inout_ok,1,1,1);solo_ok(&image,"inout consumes solo",inout_ok,1,1,1);
err(&image,"inout wrong type",inout_bad,1,0);solo_err(&image,"inout wrong type solo",inout_bad,1,0);
ok(&image,"inout named inoutbox",inout_named,1,1,1);solo_ok(&image,"inout named inoutbox solo",inout_named,1,1,1);
// Arity: an out parameter consumes no argument, so a call must supply
// exactly as many arguments as the callee has in/inout parameters.
char exact[512],extra1[512],extra4[512],out_ok[512],out_extra[512],few[512];
sprintf(exact,"%sfn g(in a:u8 @al,in b:u8 @dl)->u8\neffects {}\nclobbers {} {\nreturn a\n}\n%scall g(1,2)\n%s",head,tail_f,tail_e);
sprintf(extra1,"%sfn g(in a:u8 @al)->u8\neffects {}\nclobbers {} {\nreturn a\n}\n%scall g(1,2)\n%s",head,tail_f,tail_e);
sprintf(extra4,"%sfn g(in a:u8 @al)->u8\neffects {}\nclobbers {} {\nreturn a\n}\n%scall g(1,2,3,4)\n%s",head,tail_f,tail_e);
sprintf(out_ok,"%sfn g(in a:u8 @al,out r:u64 @rcx)->u8\neffects {}\nclobbers {} {\nreturn a\n}\n%scall g(1)\n%s",head,tail_f,tail_e);
sprintf(out_extra,"%sfn g(in a:u8 @al,out r:u64 @rcx)->u8\neffects {}\nclobbers {} {\nreturn a\n}\n%scall g(1,2)\n%s",head,tail_f,tail_e);
sprintf(few,"%sfn g(in a:u8 @al,in b:u8 @dl)->u8\neffects {}\nclobbers {} {\nreturn a\n}\n%scall g(1)\n%s",head,tail_f,tail_e);
ok(&image,"exact arity",exact,1,2,2);solo_ok(&image,"exact arity solo",exact,1,2,2);
arity311(&image,"one too many",extra1,1,2);solo_err(&image,"one too many solo",extra1,4,1);
solo_at(&image,"surplus argument position",extra1,4,1,12,10);
arity311(&image,"many too many",extra4,1,4);solo_err(&image,"many too many solo",extra4,4,1);
const char*import_surplus_src="module m\ntarget x86_64-nexora-none\nimport math.add as add: fn(in x:u64 @rcx)->u64\neffects {}\nclobbers {}\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\ncall add(1,2)\nreturn 0\n}\n}\n";
arity311(&image,"import surplus",import_surplus_src,1,2);solo_err(&image,"import surplus solo",import_surplus_src,4,1);
ok(&image,"out parameter consumes none",out_ok,1,1,1);solo_ok(&image,"out parameter consumes none solo",out_ok,1,1,1);
arity311(&image,"out parameter surplus",out_extra,1,2);solo_err(&image,"out parameter surplus solo",out_extra,4,1);
solo_at(&image,"out parameter surplus position",out_extra,4,1,12,10);
arity311(&image,"too few",few,2,1);solo_err(&image,"too few solo",few,5,1);
solo_at(&image,"too few position",few,5,1,4,18);
bad(&image,"short",literal,3);bad(&image,"short bool argument",bool_mixed,3);bad(&image,"invalid","target x86_64-nexora-none\n",4);
solo_bad(&image,"solo short",literal,3);solo_bad(&image,"solo short bool argument",bool_mixed,3);solo_bad(&image,"solo invalid","target x86_64-nexora-none\n",5);
}if(image.memory){ng_parity_finish(&ng_parity,&failures);nova_host_unmap(&image);}if(compiled)nt_artifact_free(&a);for(unsigned i=0;i<12;i++)free(sources[i]);printf("NTASM_NOVA_CALL_TYPES checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
