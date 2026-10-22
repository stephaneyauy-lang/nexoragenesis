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
   types, register_widths, initializer_types, condition_types.  Nothing measured that claim until the shared helper
   nova/ntasm_pipeline_parity.h ran every source of this file through the
   41 module validate image as well and compared the two verdicts.  The
   table beneath is the set of (this gate, the pipeline) divergence pairs
   this file exhibits, written down from that measurement: a pair that is
   not listed fails the gate, and a listed pair that stops occurring fails
   it too, so the table cannot rot into a comment. */
/* 358 condition_types(31) vs 375 expand(1), 4 cases ("comparison depth limit",
   "not depth limit", "logical depth 65", "bool proof depth 65"): 64-deep
   `!`/`&&` nesting in the condition.  Alone the entry's proof-depth cap
   reports 358 reason 2; the pipeline stops in macro_expand's clone walk at
   the same depth bound (walk_depth_cap 64) with 375 reason 9.  375 is outside
   the 300-365 attribution band, hence "unattributed" in the helper's
   wording; macro_expand.nova:1408 is its owner. */
/* 358 condition_types(31) vs 310 refs(27)+calls(28), 2 cases ("logical
   unknown call", "mixed nested bool with missing call"): both conditions
   name `missing()`, an undeclared callee.  The entry reaches its own verdict
   358 reason 3 ("cannot prove this operand is bool"), but refs and calls run
   three to four stages earlier and refuse the unknown callee with 310. */
static const NgParityPair ng_parity_pairs[]={{358,375},{358,310}};
static NgParitySpec ng_parity={
  "condition_types",
  {"types","register_widths","initializer_types","condition_types"},4,
  1,
  ng_parity_pairs,(unsigned)(sizeof ng_parity_pairs/sizeof ng_parity_pairs[0]),
  0,0,0,0,0,0,0,0,NULL};
static char ng_parity_err[256];
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[4];}Run;static Run run(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");ng_parity_check(&checks,&failures,&ng_parity,n,s,r.returned);return r;}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t c,uint64_t l,uint64_t names,uint64_t derived){Run r=run(i,n,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=c||r.out[1]!=l||r.out[2]!=names||r.out[3]!=derived){failures++;fprintf(stderr,"FAIL %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.runtime,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t code,uint64_t reason){Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]==0||r.out[1]==0||r.out[2]!=reason||r.out[3]!=0){failures++;fprintf(stderr,"FAIL %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.runtime,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run(i,n,s,words);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL %s ret=%llu runtime=%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.runtime);}}
int main(void){const char*paths[]={"tests/nova/tests/condition-types-entry.nova","compiler/nova/analysis/types/condition_types.nova","compiler/nova/analysis/types/initializer_types.nova","compiler/nova/analysis/types/register_widths.nova","compiler/nova/analysis/types/types.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[8]={0};NtFInput inputs[8];for(unsigned i=0;i<8;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<8;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,8,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");int parity=ng_parity_begin(&ng_parity,&failures,ng_parity_err,sizeof ng_parity_err);if(image.memory&&parity==0){
const char*truth="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif true {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"true",truth,1,1,0,0);
const char*param="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"bool param",param,1,0,1,0);
const char*local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nlet ready:bool=false\nif ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"bool local",local,1,0,1,0);
const char*compare="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif x==0 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"comparison",compare,1,0,0,1);
const char*feature="module m\ntarget x86_64-nexora-none\nfeatures {sse2}\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif feature(sse2) {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"feature predicate",feature,1,0,0,1);
const char*integer="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif 1 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"integer literal",integer,357,1);
const char*wrong="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif x {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"integer name",wrong,357,2);
const char*arithmetic="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nif x+1 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"arithmetic unsupported",arithmetic,358,2);
const char*call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f()->u64\neffects {}\nclobbers {} {\nif pred() {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"bool call",call,1,0,0,1);
const char*nonbool_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn value()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\nfn f()->u64\neffects {}\nclobbers {} {\nif value() {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"nonbool call",nonbool_call,357,2);
const char*arithmetic_compare="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nif (x+1)==2 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"arithmetic comparison",arithmetic_compare,1,0,0,1);
const char*compare_mismatch="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u32 @ecx,in y:u64 @rdx)->u64\neffects {changes_flags}\nclobbers {} {\nif x+1==y {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"comparison type mismatch",compare_mismatch,357,3);
const char*compare_range="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u8 @cl)->u64\neffects {changes_flags}\nclobbers {} {\nif x+256==1 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"comparison literal range",compare_range,357,3);
const char*compare_unknown="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nif x+(-1)==2 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"unsigned negative mismatch",compare_unknown,357,3);
const char*compare_no_anchor="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nif 1+2==3 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"comparison no type anchor",compare_no_anchor,358,2);
const char*simple_bool_compare="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif true==false {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"simple bool comparison unchanged",simple_bool_compare,1,0,0,1);
const char*simple_mismatch="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u32 @ecx,in y:u64 @rdx)->u64\neffects {}\nclobbers {} {\nif x==y {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"simple type mismatch",simple_mismatch,357,3);
const char*simple_range="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u8 @cl)->u64\neffects {}\nclobbers {} {\nif x==256 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"simple literal range",simple_range,357,3);
const char*simple_category="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif true==1 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"simple category mismatch",simple_category,357,3);
const char*simple_numbers="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif 1<2 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"two bounded numeric literals",simple_numbers,1,0,0,1);
const char*simple_bool_name="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif ready==true {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"bool name and literal",simple_bool_name,1,0,0,1);
const char*simple_pointer="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:ptr<user,u8> @rcx,in b:ptr<user,u8> @rdx)->u64\neffects {}\nclobbers {} {\nif a==b {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"equal pointer types",simple_pointer,1,0,0,1);
const char*pointer_arithmetic="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:ptr<user,u8> @rcx,in b:ptr<user,u8> @rdx)->u64\neffects {changes_flags}\nclobbers {} {\nif a+1==b {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"pointer arithmetic not proved",pointer_arithmetic,358,2);
const char*bool_order="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif true<false {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"bool ordering rejected",bool_order,357,3);
char deep[1024]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {} {\nif x+";
for(unsigned i=0;i<65;i++)strcat(deep,"(");
strcat(deep,"1");
for(unsigned i=0;i<65;i++)strcat(deep,")");
strcat(deep,"==2 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n");
err(&image,"comparison depth limit",deep,358,2);
const char*sibling="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif true {\nlet ready:bool=true\n}\nif ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"sibling local not visible",sibling,358,1);
const char*simple_local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"simple condition name",simple_local,1,0,1,0);
const char*qualified_local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif bogus.ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"qualified condition rejected",qualified_local,358,2);
const char*not_name="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif !ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"not bool name",not_name,1,0,0,1);
const char*not_compare="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif !(x==0) {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"not comparison",not_compare,1,0,0,1);
const char*not_group="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif !((ready)) {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"not grouped name",not_group,1,0,0,1);
const char*not_nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif !!!ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"nested not",not_nested,1,0,0,1);
const char*not_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f()->u64\neffects {}\nclobbers {} {\nif !pred() {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"not bool call",not_call,1,0,0,1);
const char*not_integer="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif !x {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"not nonbool rejected",not_integer,357,2);
const char*bitnot="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif ~ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"bitwise not out of scope",bitnot,358,2);
char not_deep[1024]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif ";for(unsigned i=0;i<65;i++)strcat(not_deep,"!");strcat(not_deep,"ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n");err(&image,"not depth limit",not_deep,358,2);
const char*negative_min="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:i8 @cl)->u64\neffects {}\nclobbers {} {\nif x==-128 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"negative signed minimum comparison",negative_min,1,0,0,1);
const char*unary_compare="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif +x==~x {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"unary plus and bitnot comparison",unary_compare,1,0,0,1);
const char*negative_range="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:i8 @cl)->u64\neffects {}\nclobbers {} {\nif x==-129 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"negative signed range comparison",negative_range,357,3);
const char*negative_unsigned="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u8 @al)->u64\neffects {}\nclobbers {} {\nif x==-1 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"negative unsigned comparison",negative_unsigned,357,3);
const char*logical_nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f(in ready:bool @al,in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif ready && (pred() || x==0) {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"logical nested bool",logical_nested,1,0,0,1);
const char*logical_precedence="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f(in ready:bool @al,in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif ready || !pred() && x<5 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"logical precedence",logical_precedence,1,0,0,1);
const char*logical_name_mismatch="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al,in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif ready && x {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"logical integer name rejected",logical_name_mismatch,357,2);
const char*logical_literal_mismatch="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif true || 1 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"logical integer literal rejected",logical_literal_mismatch,357,1);
const char*logical_unknown_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif ready && missing() {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"logical unknown call",logical_unknown_call,358,3);
char logical_deep_ok[2048]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif ";for(unsigned i=0;i<63;i++)strcat(logical_deep_ok,"ready&&");strcat(logical_deep_ok,"ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n");ok(&image,"logical depth 64",logical_deep_ok,1,0,0,1);
char logical_deep_bad[2048]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif ";for(unsigned i=0;i<64;i++)strcat(logical_deep_bad,"ready&&");strcat(logical_deep_bad,"ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n");err(&image,"logical depth 65",logical_deep_bad,358,2);
    const char*mixed_nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f(in ready:bool @al,in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif !(ready) && (pred() || (x<5)) {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"mixed nested bool",mixed_nested,1,0,0,1);
    const char*group_and_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif (pred()) && !ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"group call and not",group_and_call,1,0,0,1);
    const char*group_name="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif (ready) {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"grouped name",group_name,1,0,0,1);
    const char*feature_mixed="module m\ntarget x86_64-nexora-none\nfeatures {sse2}\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif feature(sse2) && !feature(lm) {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"feature inside logical expression",feature_mixed,1,0,0,1);
    const char*not_nonbool="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif !x {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"not applied to integer name",not_nonbool,357,2);
    const char*not_literal="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif !1 {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"not applied to integer literal",not_literal,357,1);
    char deep_not_ok[1024]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif ";for(unsigned i=0;i<63;i++)strcat(deep_not_ok,"!");strcat(deep_not_ok,"ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n");ok(&image,"bool proof depth 64",deep_not_ok,1,0,0,1);
    char deep_not_bad[1024]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->u64\neffects {}\nclobbers {} {\nif ";for(unsigned i=0;i<64;i++)strcat(deep_not_bad,"!");strcat(deep_not_bad,"ready {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n");err(&image,"bool proof depth 65",deep_not_bad,358,2);
    const char*mixed_missing_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f(in ready:bool @al,in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif !(ready) && (pred() || missing()) {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"mixed nested bool with missing call",mixed_missing_call,358,3);
    const char*mixed_nonbool="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al,in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif !(ready) && (x || false) {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";err(&image,"mixed nested bool with integer operand",mixed_nonbool,357,2);
    const char*mixed_comparison_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al,in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nif !(ready) && ((x<5) || (x>9)) {\nreturn 1\n} else {\nreturn 0\n}\n}\n}\n";ok(&image,"mixed nested bool comparisons",mixed_comparison_ok,1,0,0,1);
    bad(&image,"short",truth,3);bad(&image,"short nested bool",mixed_nested,3);bad(&image,"short missing call",mixed_missing_call,3);bad(&image,"invalid","target x86_64-nexora-none\n",4);
}if(image.memory){ng_parity_finish(&ng_parity,&failures);nova_host_unmap(&image);}if(compiled)nt_artifact_free(&a);for(unsigned i=0;i<8;i++)free(sources[i]);printf("NTASM_NOVA_CONDITION_TYPES checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
