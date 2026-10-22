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
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t b,uint64_t l,uint64_t e){Run r=run(i,s,3);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=b||r.out[1]!=l||r.out[2]!=e){failures++;fprintf(stderr,"FAIL ok %s ret=%llu out=%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2]);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t words,uint64_t code,int untouched){Run r=run(i,s,words);cases++;checks++;if(r.returned!=code||r.runtime||(untouched&&(r.out[0]!=guard||r.out[1]!=guard))||(!untouched&&r.out[0]==guard)){failures++;fprintf(stderr,"FAIL error %s ret=%llu\n",n,(unsigned long long)r.returned);}}
/* A refusal must publish the exact line and column of the offending name and
   must leave every other word of out untouched. */
static void err_at(const NovaHostImage*i,const char*n,const char*s,uint64_t code,uint64_t line,uint64_t column){Run r=run(i,s,3);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=guard){failures++;fprintf(stderr,"FAIL error %s ret=%llu out=%llu,%llu,%llu want %llu at %llu:%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)code,(unsigned long long)line,(unsigned long long)column);}}
int main(void){
 const char*paths[]={"tests/nova/tests/locals-entry.nova","compiler/nova/frontend/locals.nova","compiler/nova/frontend/parameters.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};
 char*sources[8]={0};NtFInput inputs[8];
 for(unsigned i=0;i<8;i++){size_t n=0;sources[i]=load(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}
 CHECK(sources[0]&&sources[1]&&sources[2]&&sources[3]&&sources[4]&&sources[5]&&sources[6]&&sources[7],"sources load");
 NtArtifact a={0};int compiled=1;
 for(unsigned i=0;i<8;i++)if(!sources[i])compiled=0;
 if(compiled)compiled=nova_compile_many_v2(inputs,8,&a);
 CHECK(compiled,"modules compile");
 if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);
 NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");
 if(image.memory){
 /* The rule under test: a name is unique inside one block (315), and a
    nested block may reuse the name of an enclosing block because the
    resolver answers the innermost enclosing block. Types are irrelevant
    here, so a same name of another type is accepted too. */
 const char*unique="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet a:u64=1\nlet b:u64=2\nreturn a+b\n}\n}\n";ok(&image,"unique",unique,1,2,1);
 const char*dup="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nlet x:u64=2\nreturn x\n}\n}\n";err_at(&image,"duplicate",dup,315,8,5);
 const char*shadow="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nif true {\nlet x:u64=2\nreturn x\n}\nreturn x\n}\n}\n";ok(&image,"nested shadow",shadow,2,2,2);
 const char*typed_shadow="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nif true {\nlet x:u32=2\nreturn x\n}\nreturn x\n}\n}\n";ok(&image,"nested shadow other type",typed_shadow,2,2,2);
 const char*deep_shadow="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nif true {\nif true {\nlet x:u64=2\nreturn x\n}\nreturn x\n}\nreturn x\n}\n}\n";ok(&image,"nested shadow two levels",deep_shadow,3,2,2);
 const char*chain="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet y:u64=1\nif true {\nlet y:u32=2\nreturn y\n}\nreturn y\n}\n}\n";ok(&image,"chain reuses the name",chain,2,2,2);
 const char*sibling="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif true {\nlet x:u64=1\nreturn x\n} else {\nlet x:u64=2\nreturn x\n}\nreturn 0\n}\n}\n";ok(&image,"sibling blocks share the name",sibling,3,2,2);
 const char*nested_dup="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif true {\nlet y:u64=1\nlet y:u64=2\nreturn y\n}\nreturn 0\n}\n}\n";err_at(&image,"duplicate inside a nested block",nested_dup,315,9,5);
 const char*late_dup="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet a:u64=1\nlet b:u64=2\nlet a:u64=3\nreturn b\n}\n}\n";err_at(&image,"duplicate reported at the second name",late_dup,315,9,5);
 const char*functions="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet x:u64=1\nreturn x\n}\nfn g()->u64\neffects {}\nclobbers {} {\nlet x:u64=2\nreturn x\n}\n}\n";ok(&image,"separate functions",functions,2,2,2);
 const char*empty="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"empty",empty,1,0,0);
 err(&image,"short",unique,2,800,1);
 err(&image,"invalid","target x86_64-nexora-none\n",3,800,1);
 }
 if(image.memory) nova_host_unmap(&image);
 if(compiled) nt_artifact_free(&a);
 for(unsigned i=0;i<8;i++) free(sources[i]);
 printf("NTASM_NOVA_LOCALS checks=%u failures=%u cases=%u\n",checks,failures,cases);
 return failures?1:0;
}
