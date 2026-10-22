#include "../../../compiler/c/nova/frontend/nova.h"
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
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t f,uint64_t p,uint64_t l){Run r=run(i,s,3);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=f||r.out[1]!=p||r.out[2]!=l){failures++;fprintf(stderr,"FAIL ok %s ret=%llu out=%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2]);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t words,uint64_t code,int untouched){Run r=run(i,s,words);cases++;checks++;if(r.returned!=code||r.runtime||(untouched&&(r.out[0]!=guard||r.out[1]!=guard))||(!untouched&&r.out[0]==guard)){failures++;fprintf(stderr,"FAIL error %s ret=%llu\n",n,(unsigned long long)r.returned);}}
/* A 316 must publish the exact line and column of the offending let keyword
   and must leave every other word of out untouched. */
static void err_at(const NovaHostImage*i,const char*n,const char*s,uint64_t code,uint64_t line,uint64_t column){Run r=run(i,s,3);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=guard){failures++;fprintf(stderr,"FAIL error %s ret=%llu out=%llu,%llu,%llu want %llu at %llu:%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)code,(unsigned long long)line,(unsigned long long)column);}}
int main(void){
 const char*paths[]={"tests/nova/tests/bindings-entry.nova","compiler/nova/frontend/bindings.nova","compiler/nova/frontend/locals.nova","compiler/nova/frontend/parameters.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};
 char*sources[9]={0};NtFInput inputs[9];
 for(unsigned i=0;i<9;i++){size_t n=0;sources[i]=load(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}
 int all=1;for(unsigned i=0;i<9;i++)if(!sources[i])all=0;
 CHECK(all,"sources load");
 NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,9,&a);
 CHECK(compiled,"modules compile");
 if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);
 NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");
 if(image.memory){
 /* The rule under test: a let never takes the name of a parameter of the
    same function, in the body block and in every nested block alike. A let
    may shadow another let of the same function; the innermost enclosing
    block answers for that name. */
 const char*distinct="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nreturn p+x\n}\n}\n";ok(&image,"distinct",distinct,1,1,1);
 const char*collision="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nreturn x\n}\n}\n";err_at(&image,"collision",collision,316,7,1);
 const char*nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif true {\nlet x:u64=2\nreturn x\n}\nreturn x\n}\n}\n";err_at(&image,"nested shadow of a parameter",nested,316,8,1);
 const char*deep_nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif true {\nif true {\nlet x:u64=2\nreturn x\n}\nreturn x\n}\nreturn x\n}\n}\n";err_at(&image,"nested shadow two levels",deep_nested,316,9,1);
 const char*second_param="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx,in q:u32 @edx)->u64\neffects {}\nclobbers {} {\nlet a:u64=1\nif true {\nlet q:u32=2\nreturn a\n}\nreturn p\n}\n}\n";err_at(&image,"nested shadow of the second parameter",second_param,316,9,1);
 const char*distinct_nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {} {\nlet a:u64=1\nif true {\nlet b:u64=2\nreturn b\n}\nreturn a\n}\n}\n";ok(&image,"nested let with its own name",distinct_nested,1,1,1);
 const char*no_local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif true {\nreturn x\n}\nreturn x\n}\n}\n";ok(&image,"parameter read inside a nested block",no_local,1,1,0);
 const char*outer_let="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nif true {\nlet x:u32=2\nreturn x\n}\nreturn x\n}\n}\n";ok(&image,"nested shadow of an outer let",outer_let,1,0,1);
 const char*sibling="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif true {\nlet x:u64=1\nreturn x\n} else {\nlet x:u64=2\nreturn x\n}\nreturn 0\n}\n}\n";ok(&image,"sibling blocks share the name",sibling,1,0,0);
 const char*order="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {} {\nlet q:u64=1\nlet p:u32=2\nif true {\nlet p:u32=3\nreturn q\n}\nreturn q\n}\n}\n";err_at(&image,"body collision reported before the nested one",order,316,8,1);
 const char*two="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:u64 @rcx)->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nreturn p\n}\nfn g(in p:u64 @rdx)->u64\neffects {}\nclobbers {} {\nlet x:u64=2\nreturn p\n}\n}\n";ok(&image,"two",two,2,2,2);
 const char*empty="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"empty",empty,1,0,0);
 err(&image,"short",distinct,2,800,1);
 err(&image,"invalid","target x86_64-nexora-none\n",3,800,1);
 }
 if(image.memory) nova_host_unmap(&image);
 if(compiled) nt_artifact_free(&a);
 for(unsigned i=0;i<9;i++) free(sources[i]);
 printf("NTASM_NOVA_BINDINGS checks=%u failures=%u cases=%u\n",checks,failures,cases);
 return failures?1:0;
}
