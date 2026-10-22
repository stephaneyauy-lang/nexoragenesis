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
   index, callable_names, register_widths, control_flow, return_types, initializer_types.  Nothing measured that claim until the shared helper
   nova/ntasm_pipeline_parity.h ran every source of this file through the
   41 module validate image as well and compared the two verdicts.  The
   table beneath is the set of (this gate, the pipeline) divergence pairs
   this file exhibits, written down from that measurement: a pair that is
   not listed fails the gate, and a listed pair that stops occurring fails
   it too, so the table cannot rot into a comment. */
/* 353 return_types(24) vs 375 expand(1), 2 cases ("depth limit", "return bool
   proof depth 65"): both nest 64 unary `!` deep in the returned expression.
   Run alone the entry's own proof-depth cap fires and reports 353 reason 2;
   the pipeline reaches stage 1, where macro_expand's clone walk has the same
   bound (walk_depth_cap 64) and reports 375 reason 9 before any type stage
   runs.  375 is outside the 300-365 band the helper attributes, so the
   helper names it "unattributed"; the fixture and macro_expand.nova:1408
   name its owner. */
static const NgParityPair ng_parity_pairs[]={{353,375}};
static NgParitySpec ng_parity={
  "return_types",
  {"index","callable_names","register_widths","control_flow","return_types","initializer_types"},6,
  1,
  ng_parity_pairs,(unsigned)(sizeof ng_parity_pairs/sizeof ng_parity_pairs[0]),
  0,0,0,0,0,0,0,0,NULL};
static char ng_parity_err[256];
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[4];}Run;static Run run(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");ng_parity_check(&checks,&failures,&ng_parity,n,s,r.returned);return r;}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t f,uint64_t rts,uint64_t c){Run r=run(i,n,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=f||r.out[1]!=rts||r.out[2]!=c||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu out=%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2]);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t code,uint64_t reason){Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]==guard||r.out[1]==guard||r.out[2]!=reason){failures++;fprintf(stderr,"FAIL err %s ret=%llu reason=%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[2]);}}
static void bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run(i,n,s,words);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL invalid %s\n",n);}}
int main(void){const char*paths[]={"tests/nova/tests/return-types-entry.nova","compiler/nova/analysis/types/return_types.nova","compiler/nova/analysis/types/initializer_types.nova","compiler/nova/analysis/types/register_widths.nova","compiler/nova/analysis/abi/abi.nova","compiler/nova/analysis/abi/clobbers.nova","compiler/nova/analysis/control_flow.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[12]={0};NtFInput inputs[12];for(unsigned i=0;i<12;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<12;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,12,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");int parity=ng_parity_begin(&ng_parity,&failures,ng_parity_err,sizeof ng_parity_err);if(image.memory&&parity==0){
const char*u8ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u8\neffects {}\nclobbers {} {\nreturn 255\n}\n}\n";ok(&image,"u8",u8ok,1,1,1);
const char*u8bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u8\neffects {}\nclobbers {} {\nreturn 256\n}\n}\n";err(&image,"u8 range",u8bad,353,1);
const char*boolok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->bool\neffects {}\nclobbers {} {\nreturn true\n}\n}\n";ok(&image,"bool",boolok,1,1,1);
const char*boolbad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->bool\neffects {}\nclobbers {} {\nreturn 1\n}\n}\n";err(&image,"bool int",boolbad,352,0);
const char*param="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u32 @edi)->u32\neffects {}\nclobbers {} {\nreturn x\n}\n}\n";ok(&image,"param",param,1,1,1);
const char*parambad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u32 @edi)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n}\n";err(&image,"param mismatch",parambad,352,0);
const char*local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u16\neffects {}\nclobbers {} {\nlet x:u16=1\nreturn x\n}\n}\n";ok(&image,"local",local,1,1,1);
const char*call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g()->u32\neffects {}\nclobbers {} {\nreturn 1\n}\nfn f()->u32\neffects {}\nclobbers {} {\nreturn g()\n}\n}\n";ok(&image,"call",call,2,2,2);
const char*callbad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn g()->u32\neffects {}\nclobbers {} {\nreturn 1\n}\nfn f()->u64\neffects {}\nclobbers {} {\nreturn g()\n}\n}\n";err(&image,"call mismatch",callbad,352,0);
const char*expression="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nreturn 1+(2*3)\n}\n}\n";ok(&image,"nested expression",expression,1,1,1);
const char*expression_mismatch="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u32 @edi)->u64\neffects {changes_flags}\nclobbers {} {\nreturn 1+(x*3)\n}\n}\n";err(&image,"nested mismatch",expression_mismatch,352,0);
const char*expression_range="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u8\neffects {changes_flags}\nclobbers {} {\nreturn 1+(2*256)\n}\n}\n";err(&image,"nested range",expression_range,353,1);
const char*expression_unknown="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nreturn 1+(-2)\n}\n}\n";err(&image,"unsigned negative mismatch",expression_unknown,352,0);
const char*i8bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->i8\neffects {}\nclobbers {} {\nreturn 128\n}\n}\n";err(&image,"i8 range",i8bad,353,1);
const char*pointer="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u8> @rdi)->ptr<user,u8>\neffects {}\nclobbers {} {\nreturn p\n}\n}\n";ok(&image,"pointer",pointer,1,1,1);
char deep[1024]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn ";
for(unsigned i=0;i<65;i++)strcat(deep,"(");
strcat(deep,"1");
for(unsigned i=0;i<65;i++)strcat(deep,")");
strcat(deep,"\n}\n}\n");
err(&image,"depth limit",deep,353,2);
const char*sibling="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nif true {\nlet x:u64=1\n}\nreturn x\n}\n}\n";err(&image,"sibling local not visible",sibling,353,2);
const char*simple_local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n}\n";ok(&image,"simple return name",simple_local,1,1,1);
const char*qualified_local="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn bogus.x\n}\n}\n";err(&image,"qualified return rejected",qualified_local,353,2);
const char*unary_plus="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn +x\n}\n}\n";ok(&image,"unary plus",unary_plus,1,1,1);
const char*unary_bitnot="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn ~x\n}\n}\n";ok(&image,"unary bitnot",unary_bitnot,1,1,1);
const char*unary_negative="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:i8 @cl)->i8\neffects {}\nclobbers {} {\nreturn -x\n}\n}\n";ok(&image,"unary signed negative",unary_negative,1,1,1);
const char*negative_min="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->i8\neffects {}\nclobbers {} {\nreturn -128\n}\n}\n";ok(&image,"negative signed minimum",negative_min,1,1,1);
const char*negative_range="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->i8\neffects {}\nclobbers {} {\nreturn -129\n}\n}\n";err(&image,"negative signed range",negative_range,353,1);
const char*negative_unsigned="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u8\neffects {}\nclobbers {} {\nreturn -1\n}\n}\n";err(&image,"negative unsigned mismatch",negative_unsigned,352,0);
const char*unary_nested="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:i8 @cl)->i8\neffects {}\nclobbers {} {\nreturn --x\n}\n}\n";ok(&image,"nested unary cardinality",unary_nested,1,1,1);
const char*bool_mixed="module m\ntarget x86_64-nexora-none\nsection .text {\nfn pred()->bool\neffects {}\nclobbers {} {\nreturn true\n}\nfn f(in ready:bool @al,in x:u64 @rcx)->bool\neffects {changes_flags}\nclobbers {} {\nreturn !(ready) && (pred() || (x<5))\n}\n}\n";ok(&image,"return bool mixed expression",bool_mixed,2,2,2);
const char*bool_comparison="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in x:u64 @rcx)->bool\neffects {changes_flags}\nclobbers {} {\nreturn x<5\n}\n}\n";ok(&image,"return bool comparison",bool_comparison,1,1,1);
const char*bool_nonbool="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al,in x:u64 @rcx)->bool\neffects {}\nclobbers {} {\nreturn ready && x\n}\n}\n";err(&image,"return bool with integer operand",bool_nonbool,352,0);
const char*bool_missing_call="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->bool\neffects {}\nclobbers {} {\nreturn ready && missing()\n}\n}\n";err(&image,"return bool with missing call",bool_missing_call,353,2);
char deep_not_ok[1024]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->bool\neffects {}\nclobbers {} {\nreturn ";for(unsigned i=0;i<63;i++)strcat(deep_not_ok,"!");strcat(deep_not_ok,"ready\n}\n}\n");ok(&image,"return bool proof depth 64",deep_not_ok,1,1,1);
char deep_not_bad[1024]="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in ready:bool @al)->bool\neffects {}\nclobbers {} {\nreturn ";for(unsigned i=0;i<64;i++)strcat(deep_not_bad,"!");strcat(deep_not_bad,"ready\n}\n}\n");err(&image,"return bool proof depth 65",deep_not_bad,353,2);
 /* === A5 residual: the same name reference read through an operator. The
    produced let of the macro column is a bare `return t`; `return t+1` is
    the same reference one operator down and it was resolved by the position
    ordered search alone, which cannot order two nodes the expander gave the
    same invocation span, so it answered "unsupported" and the pass refused
    with 353. These are the clear column of that walk at one, two and three
    operators, and the negative direction at each: a name that is not in
    scope at the use must stay invisible, and the structural search that now
    backs the position one must not make a sibling block or a later
    declaration answer. */
 const char*ret_op1="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nlet t:u64=1\nreturn t+1\n}\n}\n";ok(&image,"return name under one operator",ret_op1,1,1,1);
 const char*ret_op2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nlet t:u64=1\nreturn (t+1)+1\n}\n}\n";ok(&image,"return name under two operators",ret_op2,1,1,1);
 const char*ret_op3="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nlet t:u64=1\nreturn ((t+1)+1)+1\n}\n}\n";ok(&image,"return name under three operators",ret_op3,1,1,1);
 /* The negative half of the pair the bare "sibling local not visible" case
    above already pins: the same sibling, read one operator down. */
 const char*ret_op_sibling="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nif true {\nlet x:u64=1\n}\nreturn x+1\n}\n}\n";err(&image,"sibling local under an operator",ret_op_sibling,353,2);
 /* A name that IS in scope and has the wrong type is a proved mismatch, so
    this one moves 353 to 352. The oracle refuses it too. */
 const char*ret_op_wrong="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {changes_flags}\nclobbers {} {\nlet x:u32=1\nreturn x+1\n}\n}\n";err(&image,"wrong type under an operator",ret_op_wrong,352,0);

const char*other_param="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in n:u64)->u64\neffects {}\nclobbers {} {\nreturn n\n}\nfn g()->u64\neffects {}\nclobbers {} {\nreturn n+1\n}\n}\n";err(&image,"other function parameter stays invisible",other_param,353,2);
const char*wrong_param="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in n:u8 @cl)->u64\neffects {}\nclobbers {} {\nreturn n\n}\n}\n";err(&image,"parameter type mismatch remains refused",wrong_param,352,0);
const char*nested_param="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in n:u64)->u64\neffects {}\nclobbers {} {\nif true {\nreturn n+1\n}\nreturn n+2\n}\n}\n";ok(&image,"parameter visible in nested own block",nested_param,1,2,2);
bad(&image,"short",u8ok,3);bad(&image,"short bool expression",bool_mixed,3);bad(&image,"invalid","target x86_64-nexora-none\n",4);
}if(image.memory){ng_parity_finish(&ng_parity,&failures);nova_host_unmap(&image);}if(compiled)nt_artifact_free(&a);for(unsigned i=0;i<12;i++)free(sources[i]);printf("NTASM_NOVA_RETURN_TYPES checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
