#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[5];}Run;static Run run(const NovaHostImage*i,const char*s,uint64_t words){Run r={0,0,{guard,guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return r;}
// Success also pins the value observed at out[4]: the value constant_eval
// produced for the first const declaration.
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t constants,uint64_t checked,uint64_t bools,uint64_t integers,uint64_t value){Run r=run(i,s,5);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=constants||r.out[1]!=checked||r.out[2]!=bools||r.out[3]!=integers||r.out[4]!=value){failures++;fprintf(stderr,"FAIL %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu value=%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.runtime,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3],(unsigned long long)r.out[4]);}}
// A diagnostic must also leave the value channel untouched, proving the
// output is one transaction: either counts or line,column, never both.
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t code){Run r=run(i,s,5);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]==0||r.out[1]==0||r.out[2]!=0||r.out[3]!=0||r.out[4]!=guard){failures++;fprintf(stderr,"FAIL %s ret=%llu runtime=%llu out=%llu,%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.runtime,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3],(unsigned long long)r.out[4]);}}
static void bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run(i,s,words);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL %s\n",n);}}
static char*nested(unsigned depth){static const char head[]="module m\ntarget x86_64-nexora-none\nconst v:u64=";size_t at=0;char*b=malloc(strlen(head)+2*(size_t)depth+3);if(!b)return NULL;for(size_t k=0;head[k];k++)b[at++]=head[k];for(unsigned k=0;k<depth;k++)b[at++]='(';b[at++]='1';for(unsigned k=0;k<depth;k++)b[at++]=')';b[at++]='\n';b[at]=0;return b;}
#define SRC(t,v) "module m\ntarget x86_64-nexora-none\nconst v:" t "=" v "\n"
#define U 18446744073709551615ULL
#define H 9223372036854775808ULL
int main(void){const char*paths[]={"tests/nova/tests/constant-types-entry.nova","compiler/nova/analysis/types/constant_types.nova","compiler/nova/macros/constant_eval.nova","compiler/nova/analysis/types/types.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[7]={0};NtFInput inputs[7];for(unsigned i=0;i<7;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<7;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,7,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");if(image.memory){
const char*valid="module m\ntarget x86_64-nexora-none\nconst answer:u64=42\nconst ready:bool=true\n";ok(&image,"valid",valid,2,2,1,1,42);
 const char*u8ok=SRC("u8","255");ok(&image,"u8 max",u8ok,1,1,0,1,255);
 const char*i64ok=SRC("i64","9223372036854775807");ok(&image,"i64 max",i64ok,1,1,0,1,9223372036854775807ULL);
 const char*hex=SRC("u64","0xFF");ok(&image,"hex literal",hex,1,1,0,1,255);
 const char*boolword=SRC("bool","true");ok(&image,"bool word",boolword,1,1,1,0,0);
 const char*prec=SRC("u64","2+3*4");ok(&image,"precedence",prec,1,1,0,1,14);
 const char*group=SRC("u64","(2+3)*4");ok(&image,"group",group,1,1,0,1,20);
 const char*groupone=SRC("u64","(42)");ok(&image,"single group",groupone,1,1,0,1,42);
 const char*plus=SRC("u64","+7");ok(&image,"unary plus",plus,1,1,0,1,7);
 const char*plusgroup=SRC("u64","+(1+2)");ok(&image,"unary plus group",plusgroup,1,1,0,1,3);
 const char*tile=SRC("u64","~0");ok(&image,"tilde zero",tile,1,1,0,1,U);
 const char*tile15=SRC("u64","~15");ok(&image,"tilde fifteen",tile15,1,1,0,1,U-15);
 const char*add=SRC("u64","7+5");ok(&image,"add",add,1,1,0,1,12);
 const char*sub=SRC("u64","7-5");ok(&image,"sub",sub,1,1,0,1,2);
 const char*mul=SRC("u64","7*5");ok(&image,"mul",mul,1,1,0,1,35);
 const char*div=SRC("u64","22/7");ok(&image,"div",div,1,1,0,1,3);
 const char*mod=SRC("u64","22%7");ok(&image,"mod",mod,1,1,0,1,1);
 const char*band=SRC("u64","12&10");ok(&image,"and",band,1,1,0,1,8);
 const char*bor=SRC("u64","12|10");ok(&image,"or",bor,1,1,0,1,14);
 const char*bxor=SRC("u64","12^10");ok(&image,"xor",bxor,1,1,0,1,6);
 const char*shl=SRC("u64","1<<63");ok(&image,"shl 63",shl,1,1,0,1,H);
 const char*shr=SRC("u64","9223372036854775808>>63");ok(&image,"shr 63",shr,1,1,0,1,1);
 const char*max=SRC("u64","18446744073709551615");ok(&image,"u64 max",max,1,1,0,1,U);
 const char*zero=SRC("u64","5*0");ok(&image,"mul zero",zero,1,1,0,1,0);
 const char*i8min=SRC("i8","-128");ok(&image,"i8 min",i8min,1,1,0,1,U-127);
 const char*i16min=SRC("i16","-32768");ok(&image,"i16 min",i16min,1,1,0,1,U-32767);
 const char*i32min=SRC("i32","-2147483648");ok(&image,"i32 min",i32min,1,1,0,1,U-2147483647);
 const char*i64min=SRC("i64","-9223372036854775808");ok(&image,"i64 min",i64min,1,1,0,1,H);
 const char*inegone=SRC("i64","-1");ok(&image,"i64 minus one",inegone,1,1,0,1,U);
 const char*u8expr=SRC("u8","1+1");ok(&image,"u8 from expression",u8expr,1,1,0,1,2);
 const char*u8edge=SRC("u8","200+55");ok(&image,"u8 max from expression",u8edge,1,1,0,1,255);
 char*deep64=nested(63);char*deep65=nested(64);
 if(deep64){ok(&image,"depth 64",deep64,1,1,0,1,1);}else{failures++;fprintf(stderr,"FAIL depth 64 allocation\n");}
 if(deep65){err(&image,"depth 65",deep65,363);}else{failures++;fprintf(stderr,"FAIL depth 65 allocation\n");}
 free(deep64);free(deep65);
 const char*u8ok0="module m\ntarget x86_64-nexora-none\nconst byte:u8=255\n";ok(&image,"u8 max literal",u8ok0,1,1,0,1,255);
const char*range=SRC("u8","256");err(&image,"literal range",range,362);
const char*exprrange=SRC("u8","200+100");err(&image,"expression range",exprrange,362);
const char*negU8=SRC("u8","-1");err(&image,"negative into u8",negU8,362);
const char*i8low=SRC("i8","-129");err(&image,"i8 underflow range",i8low,362);
const char*i16low=SRC("i16","-32769");err(&image,"i16 underflow range",i16low,362);
const char*i32low=SRC("i32","-2147483649");err(&image,"i32 underflow range",i32low,362);
// A magnitude of 2^63 written as a positive literal does not fit i64. The
// old bit-pattern range test read the high bit as a sign and accepted it, and
// the wrap of 2^63+1 was accepted as well. Both are range failures.
const char*i64low=SRC("i64","-9223372036854775809");err(&image,"i64 below minimum",i64low,362);
const char*i64minlit=SRC("i64","9223372036854775808");err(&image,"i64 bare high bit literal",i64minlit,362);
const char*ovfadd=SRC("u64","18446744073709551615+1");err(&image,"add overflow",ovfadd,362);
const char*unfl=SRC("u64","0-1");err(&image,"sub underflow",unfl,362);
const char*ovfmul=SRC("u64","9223372036854775808*2");err(&image,"mul overflow",ovfmul,362);
const char*divzero=SRC("u64","5/0");err(&image,"divide by zero",divzero,362);
const char*modzero=SRC("u64","5%0");err(&image,"modulo by zero",modzero,362);
const char*divmin=SRC("i64","-9223372036854775808/-1");err(&image,"signed division overflow",divmin,362);
const char*shl64=SRC("u64","1<<64");err(&image,"shift left 64",shl64,362);
const char*shl65=SRC("u64","1<<65");err(&image,"shift left 65",shl65,362);
const char*shr64=SRC("u64","1>>64");err(&image,"shift right 64",shr64,362);
const char*boolint=SRC("bool","1");err(&image,"bool int",boolint,361);
const char*intbool=SRC("u64","false");err(&image,"int bool",intbool,361);
const char*boolexpr=SRC("bool","1+2");err(&image,"bool expression",boolexpr,361);
const char*name=SRC("u64","other");err(&image,"name",name,363);
const char*call=SRC("u64","helper()");err(&image,"call",call,363);
const char*cmp=SRC("u64","1<2");err(&image,"comparison",cmp,363);
const char*logic=SRC("u64","1&&2");err(&image,"logical and",logic,363);
const char*nameexpr=SRC("u64","1+other");err(&image,"name inside expression",nameexpr,363);
const char*badexpr=SRC("u64","1/0+1");err(&image,"nested zero divisor",badexpr,362);
// Regression for the reported false acceptance: a positive result of
// magnitude 2^63 was accepted for i64 because the evaluated value kept only a
// u64 bit pattern. Every positive high-bit result must now fail the range.
const char*hiadd=SRC("i64","0+9223372036854775808");err(&image,"i64 high bit from add",hiadd,362);
const char*himul=SRC("i64","4611686018427387904*2");err(&image,"i64 high bit from mul",himul,362);
const char*hisub=SRC("i64","18446744073709551615-9223372036854775807");err(&image,"i64 high bit from sub",hisub,362);
const char*higroup=SRC("i64","(0+9223372036854775808)");err(&image,"i64 high bit in group",higroup,362);
const char*hi8=SRC("i8","0+128");err(&image,"i8 high bit from add",hi8,362);
const char*hi16=SRC("i16","0+32768");err(&image,"i16 high bit from add",hi16,362);
const char*hi32=SRC("i32","0+2147483648");err(&image,"i32 high bit from add",hi32,362);
const char*hilit8=SRC("i8","128");err(&image,"i8 bare high bit literal",hilit8,362);
const char*himax=SRC("u64","0+18446744073709551615");ok(&image,"u64 high bit accepted",himax,1,1,0,1,U);
const char*hiu8=SRC("u8","0+256");err(&image,"u8 high bit from add",hiu8,362);
// Unary negative minima stay accepted for every signed width: the sign is
// carried by the source, not by the high bit of a pattern.
const char*min8=SRC("i8","-128");ok(&image,"i8 minimum from unary minus",min8,1,1,0,1,U-127);
const char*min16=SRC("i16","-32768");ok(&image,"i16 minimum from unary minus",min16,1,1,0,1,U-32767);
const char*min32=SRC("i32","-2147483648");ok(&image,"i32 minimum from unary minus",min32,1,1,0,1,U-2147483647);
const char*min64=SRC("i64","-9223372036854775808");ok(&image,"i64 minimum from unary minus",min64,1,1,0,1,H);
const char*min8g=SRC("i8","-(-127)");ok(&image,"i8 maximum from double negation",min8g,1,1,0,1,127);
const char*negzero=SRC("i64","-0+0");ok(&image,"negative zero normalises",negzero,1,1,0,1,0);
const char*negzero2=SRC("i64","0-0");ok(&image,"zero minus zero",negzero2,1,1,0,1,0);
// Checked signed-magnitude arithmetic keeps the sign of the operands.
const char*negadd=SRC("i64","-6+2");ok(&image,"negative add",negadd,1,1,0,1,U-3);
const char*negsub=SRC("i64","-6-2");ok(&image,"negative sub",negsub,1,1,0,1,U-7);
const char*negsub2=SRC("i64","2-(-6)");ok(&image,"subtract a negative",negsub2,1,1,0,1,8);
const char*negmixed=SRC("i64","6-(-2)-4");ok(&image,"mixed signs",negmixed,1,1,0,1,4);
const char*negcancel=SRC("i64","-5+5");ok(&image,"signs cancel",negcancel,1,1,0,1,0);
const char*negun=SRC("i64","-(-5)");ok(&image,"double negation",negun,1,1,0,1,5);
const char*negunplus=SRC("i64","+(-5)");ok(&image,"unary plus keeps sign",negunplus,1,1,0,1,U-4);
const char*negmul=SRC("i64","-3*2");ok(&image,"negative product",negmul,1,1,0,1,U-5);
const char*negmul2=SRC("i64","-3*-2");ok(&image,"product of two negatives",negmul2,1,1,0,1,6);
const char*negzero3=SRC("i64","-5*0");ok(&image,"negative times zero",negzero3,1,1,0,1,0);
const char*negdiv=SRC("i64","-7/2");ok(&image,"negative division truncates",negdiv,1,1,0,1,U-2);
const char*negdiv2=SRC("i64","-7/-2");ok(&image,"division of two negatives",negdiv2,1,1,0,1,3);
const char*negmod=SRC("i64","-7%2");ok(&image,"negative remainder",negmod,1,1,0,1,U);
const char*negmod2=SRC("i64","-7%-2");ok(&image,"remainder of two negatives",negmod2,1,1,0,1,U);
const char*neggroup=SRC("i64","-(2+3)*2");ok(&image,"negative group product",neggroup,1,1,0,1,U-9);
const char*negmax=SRC("i64","-18446744073709551615/1");err(&image,"u64 magnitude rejected by i64",negmax,362);
// Boundaries of the signed-magnitude domain.
const char*minsub=SRC("i64","0-9223372036854775808");ok(&image,"i64 minimum by subtraction",minsub,1,1,0,1,H);
const char*minsub2=SRC("i64","1-9223372036854775808");ok(&image,"i64 maximum negative by subtraction",minsub2,1,1,0,1,9223372036854775809ULL);
const char*minpast=SRC("i64","-9223372036854775808-1");err(&image,"one below the i64 minimum",minpast,362);
const char*minhalf=SRC("i64","-9223372036854775808/-2");ok(&image,"i64 minimum halved",minhalf,1,1,0,1,4611686018427387904ULL);
const char*i8sum=SRC("i8","-1+-127");ok(&image,"i8 minimum by addition",i8sum,1,1,0,1,U-127);
const char*i8past=SRC("i8","-1+-128");err(&image,"one below the i8 minimum",i8past,362);
const char*negadd2=SRC("i64","-1+-1");ok(&image,"two negatives added",negadd2,1,1,0,1,U-1);
const char*self=SRC("u64","18446744073709551615-18446744073709551615");ok(&image,"subtract a value from itself",self,1,1,0,1,0);
const char*shift0=SRC("i64","5<<0");ok(&image,"shift by zero",shift0,1,1,0,1,5);
// The complement of a non negative operand stays non negative in this
// profile, so ~0 is the u64 maximum and is outside i64.
const char*tilezero=SRC("i64","~0");err(&image,"complement of zero is not negative",tilezero,362);
const char*tilezero2=SRC("u64","~0");ok(&image,"complement of zero is the u64 maximum",tilezero2,1,1,0,1,U);
// Undefined negative bitwise and shift cases fail closed instead of being
// read as positive results.
const char*band1=SRC("u64","-1&255");err(&image,"negative and",band1,362);
const char*bor1=SRC("u64","-1|0");err(&image,"negative or",bor1,362);
const char*bxor1=SRC("u64","-1^0");err(&image,"negative xor",bxor1,362);
const char*tile1=SRC("i64","~(-1)");err(&image,"negative complement",tile1,362);
const char*shr1=SRC("i64","-1>>63");err(&image,"negative right shift",shr1,362);
const char*shl1=SRC("i64","-8<<1");err(&image,"negative left shift",shl1,362);
const char*shamt=SRC("i64","1<<-1");err(&image,"negative shift amount",shamt,362);
const char*shramt=SRC("i64","1>>-1");err(&image,"negative right shift amount",shramt,362);
const char*bitdeep=SRC("u64","1+(-2&1)");err(&image,"negative and inside a sum",bitdeep,362);
bad(&image,"short",valid,3);bad(&image,"invalid","target x86_64-nexora-none\n",4);
}if(image.memory)nova_host_unmap(&image);if(compiled)nt_artifact_free(&a);for(unsigned i=0;i<7;i++)free(sources[i]);printf("NTASM_NOVA_CONSTANT_TYPES checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
