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
   features, contracts, feature_requirements.  Nothing measured that claim until the shared helper
   nova/ntasm_pipeline_parity.h ran every source of this file through the
   41 module validate image as well and compared the two verdicts.  The
   table beneath is the set of (this gate, the pipeline) divergence pairs
   this file exhibits, written down from that measurement: a pair that is
   not listed fails the gate, and a listed pair that stops occurring fails
   it too, so the table cannot rot into a comment. */
/* 344 feature_requirements(26) vs 334 body_intrinsics(21), 1 case ("intrinsic
   syscall missing"): the body spells `syscall` under `effects {}`, so the
   intrinsic's required atoms are undeclared.  feature_requirements answers
   "this intrinsic needs a feature you have not enabled" (344), but
   body_intrinsics runs five stages earlier and refuses the same missing
   effect atoms first, with 334. */
static const NgParityPair ng_parity_pairs[]={{344,334}};
static NgParitySpec ng_parity={
  "feature_requirements",
  {"features","contracts","feature_requirements"},3,
  1,
  ng_parity_pairs,(unsigned)(sizeof ng_parity_pairs/sizeof ng_parity_pairs[0]),
  0,0,0,0,0,0,0,0,NULL};
static char ng_parity_err[256];
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[4];}Run;static Run run(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");ng_parity_check(&checks,&failures,&ng_parity,n,s,r.returned);return r;}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t p,uint64_t a,uint64_t m){Run r=run(i,n,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=p||r.out[1]!=a||r.out[2]!=m||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu\n",n,(unsigned long long)r.returned);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t code){Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]==guard||r.out[1]==guard){failures++;fprintf(stderr,"FAIL err %s ret=%llu\n",n,(unsigned long long)r.returned);}}
static void bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run(i,n,s,words);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL invalid %s\n",n);}}
int main(void){const char*paths[]={"tests/nova/tests/feature-requirements-entry.nova","compiler/nova/analysis/abi/feature_requirements.nova","compiler/nova/analysis/abi/features.nova","compiler/nova/analysis/abi/contracts.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[7]={0};NtFInput inputs[7];for(unsigned i=0;i<7;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<7;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,7,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");int parity=ng_parity_begin(&ng_parity,&failures,ng_parity_err,sizeof ng_parity_err);if(image.memory&&parity==0){
const char*none="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"none",none,0,0,0);
const char*sse="module m\ntarget x86_64-nexora-none\nfeatures {sse2}\nsection .text {\nfn f()->u64\neffects {}\nclobbers {}\nrequires {feature(sse2)} {\nreturn 0\n}\n}\n";ok(&image,"sse",sse,1,1,8);
const char*missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {}\nrequires {feature(sse2)} {\nreturn 0\n}\n}\n";err(&image,"missing",missing,344);
const char*unknown="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {}\nrequires {feature(avx512)} {\nreturn 0\n}\n}\n";err(&image,"unknown",unknown,343);
const char*lm="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {}\nrequires {feature(lm)} {\nreturn 0\n}\n}\n";ok(&image,"lm",lm,1,1,1);
const char*ensures="module m\ntarget x86_64-nexora-none\nfeatures {tsc}\nsection .text {\nfn f()->u64\neffects {}\nclobbers {}\nensures {feature(tsc)} {\nreturn 0\n}\n}\n";ok(&image,"ensures",ensures,1,1,16);
const char*imported="module m\ntarget x86_64-nexora-none\nfeatures {msr}\nimport a.f as f: fn()->u64\neffects {}\nclobbers {}\nrequires {feature(msr)}\n";ok(&image,"import",imported,1,1,2);
bad(&image,"short",none,3);bad(&image,"invalid","target x86_64-nexora-none\n",4);
   /* Feature closure for x86_64 intrinsics: an intrinsic whose catalog feature
      is not in the module mask is 344, exactly like a feature(x) predicate. */
   const char*rdtsc_plain="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {reads_clock}\nclobbers {rax,rdx} {\nrdtsc\nreturn 0\n}\n}\n";err(&image,"intrinsic tsc missing",rdtsc_plain,344);
   const char*rdtsc_ok="module m\ntarget x86_64-nexora-none\nfeatures {tsc}\nsection .text {\nfn f()->u64\neffects {reads_clock}\nclobbers {rax,rdx} {\nrdtsc\nreturn 0\n}\n}\n";ok(&image,"intrinsic tsc declared",rdtsc_ok,0,0,0);
   const char*rdmsr_plain="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {privileged,msr}\nclobbers {rax,rdx} {\nrdmsr\nreturn 0\n}\n}\n";err(&image,"intrinsic msr missing",rdmsr_plain,344);
   const char*rdmsr_ok="module m\ntarget x86_64-nexora-none\nfeatures {msr}\nsection .text {\nfn f()->u64\neffects {privileged,msr}\nclobbers {rax,rdx} {\nrdmsr\nreturn 0\n}\n}\n";ok(&image,"intrinsic msr declared",rdmsr_ok,0,0,0);
   const char*syscall_plain="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax,rcx,r11} {\nsyscall\nreturn 0\n}\n}\n";err(&image,"intrinsic syscall missing",syscall_plain,344);
   const char*syscall_ok="module m\ntarget x86_64-nexora-none\nfeatures {syscall}\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax,rcx,r11} {\nsyscall\nreturn 0\n}\n}\n";ok(&image,"intrinsic syscall declared",syscall_ok,0,0,0);
   const char*fence_ok="module m\ntarget x86_64-nexora-none\nfeatures {sse2}\nsection .text {\nfn f()->u64\neffects {memory_ordering}\nclobbers {} {\nlfence\nreturn 0\n}\n}\n";ok(&image,"intrinsic sse2 declared",fence_ok,0,0,0);
   const char*fence_plain="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {memory_ordering}\nclobbers {} {\nlfence\nreturn 0\n}\n}\n";err(&image,"intrinsic sse2 missing",fence_plain,344);
   /* A plain body intrinsic needs nothing beyond the implicit lm bit. */
   const char*nop_plain="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nnop\nreturn 0\n}\n}\n";ok(&image,"lm-only intrinsic",nop_plain,0,0,0);
   /* Predicate and intrinsic closure compose: predicate proven, intrinsic not. */
   const char*both="module m\ntarget x86_64-nexora-none\nfeatures {sse2}\nsection .text {\nfn f()->u64\neffects {reads_clock}\nclobbers {rax,rdx}\nrequires {feature(sse2)} {\nrdtsc\nreturn 0\n}\n}\n";err(&image,"predicate ok intrinsic not",both,344);
   /* A label definition shares node kind 32 with an instruction but carries
      aux 1: a label named rdtsc or syscall needs no catalog feature. */
   const char*rdtsc_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nrdtsc:\nreturn 0\n}\n}\n";ok(&image,"tsc label",rdtsc_label,0,0,0);
   const char*syscall_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nsyscall:\nreturn 0\n}\n}\n";ok(&image,"syscall label",syscall_label,0,0,0);
   }if(image.memory){ng_parity_finish(&ng_parity,&failures);nova_host_unmap(&image);}if(compiled)nt_artifact_free(&a);for(unsigned i=0;i<7;i++)free(sources[i]);printf("NTASM_NOVA_FEATURE_REQUIREMENTS checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
