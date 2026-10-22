#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks,failures,cases;
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static const uint8_t guard=0xcc;
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime;uint8_t out[32];}Run;
static Run run(const NovaHostImage*i,const char*source,uint64_t features,uint64_t cpl,uint64_t words){Run r;memset(&r,0,sizeof r);memset(r.out,guard,sizeof r.out);NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)source,strlen(source),0),oh=nova_borrow_v2(&c,r.out,words,1);uint64_t a[]={sh,strlen(source),features,cpl,oh,words};r.returned=i->entry(&c,a,6);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return r;}
static void ok(const NovaHostImage*i,const char*name,const char*source,uint64_t features,uint64_t cpl,const char**instructions,unsigned count){uint8_t expected[31]={0};size_t total=0;for(unsigned n=0;n<count;n++){NtX64Instruction encoded={0};NtX64Context context={(uint32_t)features,(unsigned)cpl};NtX64Error e=nt_x64_encode(instructions[n],NULL,0,context,&encoded);CHECK(e==0,"oracle encode");memcpy(expected+total,encoded.bytes,encoded.length);total+=encoded.length;}Run r=run(i,source,features,cpl,32);cases++;checks++;int bad=r.returned||r.runtime||r.out[0]!=total||memcmp(r.out+1,expected,total);if(bad){failures++;fprintf(stderr,"FAIL %s ret=%llu total=%u observed=%u\n",name,(unsigned long long)r.returned,(unsigned)total,r.out[0]);}}
static void err(const NovaHostImage*i,const char*name,const char*source,uint64_t features,uint64_t cpl,uint64_t code,uint64_t words){Run r=run(i,source,features,cpl,words);cases++;checks++;int bad=r.returned!=code||r.runtime;for(unsigned k=0;k<words&&k<32;k++)bad|=r.out[k]!=guard;if(bad){failures++;fprintf(stderr,"FAIL %s ret=%llu expected=%llu\n",name,(unsigned long long)r.returned,(unsigned long long)code);}}
/* ---- load/store access width against the pointed element ---------------
 * The rule, as the oracle states it at frontend.c:5403-5412: the element
 * type of the pointer the memory operand carries must have the same width in
 * bits as the register operand. For a load the register operand is mandatory,
 * so the rule always applies; for a store it applies when the source is a
 * register. Measured against the oracle the element width is a perfect
 * diagonal -- u8/i8 = 8, u16/i16 = 16, u32/i32 = 32, u64/i64 = 64, and bool
 * matches no register at all, not even al.
 *
 * The code is the encoder's own width code, NT_X64_WIDTH, defined at
 * x64.h:55 as 403 and spelled "operand width mismatch" at x64.c:778. The
 * module already answers it at x64_lower_fixed.nova:540 for a
 * register/register operand, so this is the same refusal for the same defect
 * and not a new number. */
static void enc(const NovaHostImage*i,const char*name,const char*source,uint64_t features,uint64_t cpl){Run r=run(i,source,features,cpl,32);cases++;checks++;if(r.returned||r.runtime||r.out[0]==0){failures++;fprintf(stderr,"FAIL width %s ret=%llu bytes=%u\n",name,(unsigned long long)r.returned,(unsigned)r.out[0]);}}
/* Two sources identical except for the element width of the pointer, with
 * the register held constant, must get opposite verdicts. This is the
 * anti-tautology: while the element width was ignored both took their width
 * from the register alone, both encoded, and both produced the same bytes.
 * Demanding the pair therefore fails the moment the rule stops deciding the
 * verdict, whichever way it stops. */
static void element_decides(const NovaHostImage*i,const char*name,const char*refused,const char*accepted,uint64_t features,uint64_t cpl){Run a=run(i,refused,features,cpl,32),b=run(i,accepted,features,cpl,32);cases++;checks++;if(a.runtime||b.runtime||a.returned!=NT_X64_WIDTH||b.returned!=0||b.out[0]==0){failures++;fprintf(stderr,"FAIL width %s refused=%llu accepted=%llu accepted_bytes=%u\n",name,(unsigned long long)a.returned,(unsigned long long)b.returned,(unsigned)b.out[0]);}}
/* A load, a store and a mov over the same data symbol, in a complete module.
 * The element width is the only thing that varies between the rows. */
#define WIDE(mnem,reg,elem) "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rbx,rax,rcx,rsi} {\n" mnem " " reg ",[rbx]:ptr<user," elem ">\nreturn 0\n}\n}\n"
#define STORE(elem,reg) "module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rbx,rsi} {\nstore [rbx]:ptr<user," elem ">," reg "\nreturn 0\n}\n}\n"

static void rr_ok(const NovaHostImage*i,const char*name,const char*source,const char*mnemonic,NtX64Operand*operands,size_t count){NtX64Instruction encoded={0};NtX64Context context={1,3};CHECK(nt_x64_encode(mnemonic,operands,count,context,&encoded)==0,"oracle encode");uint8_t expected[31]={0};size_t total=encoded.length;memcpy(expected,encoded.bytes,total);Run r=run(i,source,1,3,32);cases++;int bad=r.returned||r.runtime||r.out[0]!=total||memcmp(r.out+1,expected,total);if(bad){failures++;fprintf(stderr,"FAIL %s ret=%llu expected_bytes=%u observed=%u\n",name,(unsigned long long)r.returned,(unsigned)total,r.out[0]);}else{checks++;}}
int main(void){const char*paths[]={"tests/nova/tests/x64-lower-fixed-entry.nova","compiler/nova/backend/x64/x64_lower_fixed.nova","compiler/nova/backend/x64/x64_fixed.nova","compiler/nova/analysis/types/register_widths.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[7]={0};NtFInput inputs[7];for(unsigned i=0;i<7;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<7;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,7,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");if(image.memory){const char*basic="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nnop\npause\nreturn 0\n}\n}\n";const char*basic_names[]={"nop","pause"};ok(&image,"basic",basic,1,3,basic_names,2);const char*system="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nrdtsc\nlfence\nreturn 0\n}\n}\n";const char*system_names[]={"rdtsc","lfence"};ok(&image,"features",system,25,0,system_names,2);const char*privileged="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nhlt\nreturn 0\n}\n}\n";err(&image,"privilege",privileged,1,3,405,32);const char*unknown="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\ntelepathy\nreturn 0\n}\n}\n";err(&image,"unknown",unknown,1,3,401,32);const char*operands="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nmov rax,rbx\nreturn 0\n}\n}\n";NtX64Operand rr[2]={{.kind=NT_X64_REG,.width=64,.reg=0},{.kind=NT_X64_REG,.width=64,.reg=3}};rr_ok(&image,"operand form",operands,"mov",rr,2);err(&image,"short",basic,1,3,800,2);err(&image,"invalid","target x86_64-nexora-none\n",1,3,800,32);
/* --- refused: the register width and the element width disagree --- */
err(&image,"load rax<-u8",WIDE("load","rax","u8"),1,3,NT_X64_WIDTH,32);
err(&image,"load eax<-u8",WIDE("load","eax","u8"),1,3,NT_X64_WIDTH,32);
err(&image,"load al<-u64",WIDE("load","al","u64"),1,3,NT_X64_WIDTH,32);
err(&image,"load eax<-u64",WIDE("load","eax","u64"),1,3,NT_X64_WIDTH,32);
err(&image,"load al<-u16",WIDE("load","al","u16"),1,3,NT_X64_WIDTH,32);
err(&image,"load ax<-u32",WIDE("load","ax","u32"),1,3,NT_X64_WIDTH,32);
err(&image,"load rsi<-i32",WIDE("load","rsi","i32"),1,3,NT_X64_WIDTH,32);
err(&image,"store rsi<-u8",STORE("u8","rsi"),1,3,NT_X64_WIDTH,32);
err(&image,"store rsi<-i16",STORE("i16","rsi"),1,3,NT_X64_WIDTH,32);
err(&image,"store rsi<-u32",STORE("u32","rsi"),1,3,NT_X64_WIDTH,32);
/* A non machine scalar element states no width to compare. The module
 * already answers that refusal 409 in encode_one_operand_memory
 * (x64_lower_fixed.nova:246); the load and store path must answer the same
 * number and never invent a width. */
err(&image,"load rax<-bool",WIDE("load","rax","bool"),1,3,409,32);
err(&image,"store rsi<-bool",STORE("bool","rsi"),1,3,409,32);

/* --- accepted: the widths agree, and must keep encoding --- */
enc(&image,"load rax<-u64",WIDE("load","rax","u64"),1,3);
enc(&image,"load al<-u8",WIDE("load","al","u8"),1,3);
enc(&image,"load ax<-u16",WIDE("load","ax","u16"),1,3);
enc(&image,"load eax<-u32",WIDE("load","eax","u32"),1,3);
enc(&image,"load rax<-i64",WIDE("load","rax","i64"),1,3);
enc(&image,"load eax<-i32",WIDE("load","eax","i32"),1,3);
enc(&image,"store rsi<-u64",STORE("u64","rsi"),1,3);
enc(&image,"store sil<-u8",STORE("u8","sil"),1,3);
/* The element width decides the verdict, with the register held constant. */
element_decides(&image,"element width decides load",WIDE("load","rax","u8"),WIDE("load","rax","u64"),1,3);
element_decides(&image,"element width decides store",STORE("u8","rsi"),STORE("u64","rsi"),1,3);
element_decides(&image,"element width decides signed",WIDE("load","rax","i32"),WIDE("load","rax","i64"),1,3);
/* The oracle states the rule for load and store only. mov over the same
 * pointer is the encoder's own operand check and must not be answered here. */
enc(&image,"mov rax<-u64",WIDE("mov","rax","u64"),1,3);
}if(image.memory)nova_host_unmap(&image);if(compiled)nt_artifact_free(&a);for(unsigned i=0;i<7;i++)free(sources[i]);printf("NTASM_NOVA_X64_LOWER_FIXED checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
