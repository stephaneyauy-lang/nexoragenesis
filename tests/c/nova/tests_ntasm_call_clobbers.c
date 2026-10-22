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
   index, callable_names, register_widths, clobbers, refs, calls, call_clobbers.  Nothing measured that claim until the shared helper
   nova/ntasm_pipeline_parity.h ran every source of this file through the
   41 module validate image as well and compared the two verdicts.  The
   table beneath is the set of (this gate, the pipeline) divergence pairs
   this file exhibits, written down from that measurement: a pair that is
   not listed fails the gate, and a listed pair that stops occurring fails
   it too, so the table cannot rot into a comment. */
static const NgParityPair ng_parity_pairs[]={{0,0}};
static NgParitySpec ng_parity={
  "call_clobbers",
  {"index","callable_names","register_widths","clobbers","refs","calls","call_clobbers"},7,
  1,
  ng_parity_pairs,0,
  0,0,0,0,0,0,0,0,NULL};
static char ng_parity_err[256];
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*load(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[4];}Run;
static Run run(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");ng_parity_check(&checks,&failures,&ng_parity,n,s,r.returned);return r;}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t d,uint64_t c,uint64_t v){Run r=run(i,n,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=d||r.out[1]!=c||r.out[2]!=v||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu\n",n,(unsigned long long)r.returned);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t code,uint64_t missing){Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]==guard||r.out[1]==guard||(code==331&&(r.out[2]!=1||r.out[3]!=missing))){failures++;fprintf(stderr,"FAIL err %s ret=%llu out=%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run(i,n,s,words);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL invalid %s\n",n);}}
int main(void){const char*paths[]={"tests/nova/tests/call-clobbers-entry.nova","compiler/nova/analysis/calls/call_clobbers.nova","compiler/nova/analysis/calls/calls.nova","compiler/nova/frontend/refs.nova","compiler/nova/analysis/abi/clobbers.nova","compiler/nova/analysis/types/register_widths.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[11]={0};NtFInput inputs[11];for(unsigned i=0;i<11;i++){size_t n=0;sources[i]=load(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<11;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,11,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");int parity=ng_parity_begin(&ng_parity,&failures,ng_parity_err,sizeof ng_parity_err);if(image.memory&&parity==0){
/* Regression: ABI clauses share kind 28 with call statements. */
const char *explicit_abi_none="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
ok(&image,"explicit ABI is not a call",explicit_abi_none,1,0,0);
const char *explicit_abi_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {rax} {\nreturn 0\n}\nfn main()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {rax} {\ncall leaf()\nreturn 0\n}\n}\n";
ok(&image,"explicit ABI real clobber call retained",explicit_abi_call,2,1,1);
const char *explicit_abi_missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {rax} {\nreturn 0\n}\nfn main()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";
err(&image,"explicit ABI missing clobber still refused",explicit_abi_missing,331,1);

const char*none="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"none",none,1,0,0);
const char*alias="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {eax} {\ncall leaf()\nreturn 0\n}\n}\n";ok(&image,"alias",alias,2,1,1);
const char*missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {} {\ncall leaf()\nreturn 0\n}\n}\n";err(&image,"missing",missing,331,1);
const char*r10="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {r10} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {r10d} {\ncall leaf()\nreturn 0\n}\n}\n";ok(&image,"r10",r10,2,1,1);
const char*superset="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {rax,rcx} {\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {rax,rcx,rdx} {\ncall leaf()\nreturn 0\n}\n}\n";ok(&image,"superset",superset,2,1,1);
const char*imported="module m\ntarget x86_64-nexora-none\nimport a.f as f: fn()->u64\neffects {}\nclobbers {r11}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {r11d} {\ncall f()\nreturn 0\n}\n}\n";ok(&image,"import",imported,2,1,1);
const char*chain="module m\ntarget x86_64-nexora-none\nsection .text {\nfn leaf()->u64\neffects {}\nclobbers {rdx} {\nreturn 0\n}\nfn mid()->u64\neffects {}\nclobbers {rdx} {\ncall leaf()\nreturn 0\n}\nfn main()->u64\neffects {}\nclobbers {rdx} {\nreturn mid()\n}\n}\n";ok(&image,"chain",chain,3,2,2);
const char*unknown="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {foo} {\nreturn 0\n}\n}\n";err(&image,"unknown",unknown,330,0);
bad(&image,"short",none,3);bad(&image,"invalid","target x86_64-nexora-none\n",4);
}if(image.memory){ng_parity_finish(&ng_parity,&failures);nova_host_unmap(&image);}if(compiled)nt_artifact_free(&a);for(unsigned i=0;i<11;i++)free(sources[i]);printf("NTASM_NOVA_CALL_CLOBBERS checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
