#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntasm_pipeline_parity.h"
/* ====================== pipeline parity ==============================
   This gate compiles a SUB-CHAIN of the 34 stage pipeline -- the entry runs
   semantics.index (stage 2), callable_names (6), effects (19) and
   body_effects (20) and nothing else -- and asserts a diagnostic code on it.
   That makes every code below a CLAIM ABOUT THE PIPELINE, and until this
   lot nothing in the tree measured the claim.  The shared helper
   nova/ntasm_pipeline_parity.h runs every one of these sources through the
   41 module validate image as well and compares the two verdicts.

   The stage set is a link set, not a prefix of the stage order, so equality
   is unsatisfiable by construction here and the table below is the contract
   instead: every (this gate's code, the pipeline's code) pair this file can
   produce must be listed, and every listed pair must occur.  The pairs are
   written down AFTER the sweep, from what the pipeline actually answered, so
   the table is a record of a measurement and not a guess.  The meaning of
   each is spelled out beneath the table. */
/* The measured divergences of this gate, written down from what the 41 module
   pipeline actually answered and not from a guess.  Six cases of this file
   fall in one of the two shapes below and no other shape exists: the helper
   fails on any pair that is not listed here, and fails on any listed pair
   that stops occurring, so this table cannot rot into a comment.

     {333,340}  four cases: the fixture types a pointer over a space that is
                not one of the six v0 spaces.  body_effects names the MEMORY
                OPERAND and answers 333, which is the right answer to the
                question stage 20 asks.  The pipeline stops at stage 18,
                pointer_spaces, which reads the same token off the same
                DECLARATION and answers 340.  Same program, same bytes, two
                gates green at the same instant until now.

     {333,350}  two cases: same shape, but the token is in the ELEMENT
                position of a ptr<space,element>, so stage 8 types refuses it
                first and never lets stage 18 or stage 20 be reached.

   The stage set of this entry is a link set -- semantics.index, then
   callable_names, then effects, then body_effects -- and not a prefix of the
   34 stage order, so the two sides are being asked different questions and
   equality of verdicts is not available here.  The helper says so in its own
   banner on every run (prefix=no) rather than leaving it to this comment. */
static const NgParityPair ng_parity_pairs[]={{333,340},{333,350}};
static NgParitySpec ng_parity={
  "body_effects",
  {"index","callable_names","effects","body_effects"},4,
  1,
  ng_parity_pairs,
  (unsigned)(sizeof ng_parity_pairs / sizeof ng_parity_pairs[0]),
  0,0,0,0,0,0,0,0,NULL};
static char ng_parity_err[256];
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[4];}Run;static Run run(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");ng_parity_check(&checks,&failures,&ng_parity,n,s,r.returned);return r;}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t f,uint64_t a,uint64_t v){Run r=run(i,n,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=f||r.out[1]!=a||r.out[2]!=v||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t code,uint64_t cat,uint64_t bit){Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]==guard||r.out[1]==guard||r.out[2]!=cat||r.out[3]!=bit){failures++;fprintf(stderr,"FAIL err %s ret=%llu out=%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run(i,n,s,words);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL invalid %s\n",n);}}
/* One based line and column of the nth occurrence of needle, derived from the
   source text alone, so a position case asserts what the pass reports without
   reading the position back out of the pass under test. */
static void where(const char*s,const char*needle,int nth,uint64_t*line,uint64_t*column){uint64_t ln=1,col=1;int seen=0;size_t n=strlen(needle);const char*p=s;if(nth<1)return;for(;;){if(*p=='\0')break;if(*p=='\n'){ln++;col=1;p++;continue;}if(strncmp(p,needle,n)==0&&(seen++==nth-1)){*line=ln;*column=col;return;}col++;p++;}}
/* Full four word check at a needle: 332 names the instruction, 333 and 336
   name the memory operand, so the three positions are pinned apart here. */
static void span(const NovaHostImage*i,const char*n,const char*s,uint64_t code,const char*needle,int nth,uint64_t third,uint64_t fourth){uint64_t line=0,column=0;where(s,needle,nth,&line,&column);Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=third||r.out[3]!=fourth){failures++;fprintf(stderr,"FAIL span %s ret=%llu want %llu at %llu,%llu %llu,%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)code,(unsigned long long)line,(unsigned long long)column,(unsigned long long)third,(unsigned long long)fourth,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* ================= the C parity oracle, asked directly ====================
   nt_x64_effects, x64.h:114 and x64.c:838, publishes memory_read and
   memory_write for one exact validated operand form. It publishes them as one
   aggregate over the operand list, so a per position answer is obtained by
   isolation: asking the same mnemonic with the memory operand alone in that
   position and a register in every other position leaves exactly that
   position's shape, because read_operand and write_operand at x64.c:807 and
   :813 each look at one operand. Four shapes, the same numbering
   body_effects.form uses: 0 no access, 1 read, 2 write, 3 read and write, and
   ORACLE_NO when nt_x64_encode refuses the form, which the pass must answer 336.
   ORACLE_NO is the sentinel for a form nt_x64_effects refuses. A refusal is an
   answer too: the two helpers below turn it into the expected 336. */
#define ORACLE_NO UINT64_C(0x8000000000000000)
static const NtX64Context ORACLE_CTX={NT_X64_ALL_FEATURES,0};
static NtX64Operand orx_reg(unsigned r,unsigned w){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_REG;o.reg=r;o.width=w;return o;}
static NtX64Operand orx_mem(unsigned w){NtX64Operand o;memset(&o,0,sizeof o);o.kind=NT_X64_MEM;o.width=w;o.base=5;o.index=-1;o.scale=1;return o;}
/* The shape of one operand position, isolated. operands is the arity
   nt_x64_encode requires for this mnemonic, so a position the arity does not
   admit is ORACLE_NO without a second guess, and ri names the register the
   non memory position carries, because the shift and rotation forms accept
   only cl there (x64.c:339). */
static uint64_t shape_at(const char*m,unsigned position,unsigned operands,unsigned mw,unsigned rw,unsigned ri){
  NtX64Effects fx;memset(&fx,0,sizeof fx);
  if(operands==1){
    if(position!=1)return ORACLE_NO;
    NtX64Operand a[1]={orx_mem(mw)};
    if(nt_x64_effects(m,a,1,ORACLE_CTX,&fx)!=NT_X64_OK)return ORACLE_NO;
    return (uint64_t)(fx.memory_read|(fx.memory_write?2u:0u));
  }
  NtX64Operand a[2]={orx_reg(ri,rw),orx_mem(mw)};
  if(position==1){a[0]=orx_mem(mw);a[1]=orx_reg(ri,rw);}
  if(nt_x64_effects(m,a,2,ORACLE_CTX,&fx)!=NT_X64_OK)return ORACLE_NO;
  return (uint64_t)(fx.memory_read|(fx.memory_write?2u:0u));
}
/* one, defined below, builds the one instruction fixture these two probes
   share with every case in this file. */
static char *one(const char *effects,const char *clob,const char *instr,const char *space,const char *element);
/* ================= the same question asked of the pass ====================
   What the pass charges for one memory operand, read back from the verdicts
   it returns and never from a table in this file. Two probes separate the
   five answers body_effects.form can give. With an empty declaration a
   refusal is 336, a read is 332 category 2, and a write that charges no read
   is 332 category 3; with reads_mem declared a read no longer refuses while
   a write still reports 332 category 3. So a read modify write answers 332
   category 2 on the first probe and 332 category 3 on the second, which is
   what separates shape 3 from shape 2. A verdict this file does not
   recognise is a broken fixture, not a free operand, so it fails. */
static uint64_t nova_shape(const NovaHostImage*i,const char*instr,const char*space,const char*element,const char*label){
  Run a=run(i,label,one("","",instr,space,element),4);
  Run b=run(i,label,one("reads_mem","",instr,space,element),4);
  uint64_t bits=0;
  if(a.returned==336||b.returned==336)return 4;
  if(a.returned==332&&a.out[2]==2)bits|=1;
  if((a.returned==332&&a.out[2]==3)||(b.returned==332&&b.out[2]==3))bits|=2;
  if(!((a.returned==0||a.returned==332)&&(b.returned==0||b.returned==332))){
    checks++;cases++;
    failures++;
    fprintf(stderr,"FAIL nova_shape %s unrecognised verdicts %llu/%llu %llu/%llu\n",label,
      (unsigned long long)a.returned,(unsigned long long)a.out[2],
      (unsigned long long)b.returned,(unsigned long long)b.out[2]);
    return 5;
  }
  return bits;
}
/* One form asked twice: nt_x64_effects publishes a shape and the pass
   charges one, and the two are compared in the direction that matters. A
   pass answer missing a bit the oracle publishes would let a real memory
   access through uncharged, and that fails here whatever else holds. A pass
   answer with a bit the oracle does not publish is the sound over charge,
   which invlpg keeps because the x86_64 architecture really does take its
   page address from memory, so equality is demanded of it separately. A
   pass answer of 4 is a refusal: it cannot under charge, so it passes the
   first comparison on its own, and it fails the exact one, which is the
   point, because refusing a form the oracle answers costs an accepted proof
   for nothing. The three descriptor loads are compared exactly, so neither a
   silent under charge nor a hidden refusal can come back. */
static void confront(const NovaHostImage*i,const char*mn,const char*instr,unsigned operands,unsigned mw,unsigned rw,unsigned ri,unsigned position,const char*space,const char*element,int exact){
  uint64_t oracle=shape_at(mn,position,operands,mw,rw,ri);
  uint64_t nova=nova_shape(i,instr,space,element,mn);
  cases++;checks++;
  if(oracle==ORACLE_NO){
    failures++;
    fprintf(stderr,"FAIL confront %s nt_x64_effects refuses the form, the probe is wrong\n",mn);
    return;
  }
  if(nova==4){
    failures++;
    fprintf(stderr,"FAIL confront %s refuses a form the oracle answers: oracle=%llu\n",mn,
      (unsigned long long)oracle);
    return;
  }
  if((nova&oracle)!=oracle){
    failures++;
    fprintf(stderr,"FAIL confront %s under charges: oracle=%llu nova=%llu\n",mn,
      (unsigned long long)oracle,(unsigned long long)nova);
    return;
  }
  if(exact&&nova!=oracle){
    failures++;
    fprintf(stderr,"FAIL confront %s diverges from the oracle: oracle=%llu nova=%llu\n",mn,
      (unsigned long long)oracle,(unsigned long long)nova);
  }
}
/* The six v0 address spaces and their bits, the same numbering effects.summarize
   and body_effects.space_bit use. */
static uint64_t space_bit(const char*n){if(!strcmp(n,"user"))return 1;if(!strcmp(n,"kernel"))return 2;if(!strcmp(n,"physical"))return 4;if(!strcmp(n,"mmio"))return 8;if(!strcmp(n,"device"))return 16;if(!strcmp(n,"firmware"))return 32;return 0;}
/* The space bitset a declared effect set covers, read straight out of the
   string this file built for the fixture: reads_mem or writes_mem, bounded to
   one space in parentheses or unbounded. A byte scanner over the fixture, not a
   second reader of effects.nova. */
static uint64_t effect_bits(const char*set,int writes){
  const char*key=writes?"writes_mem":"reads_mem";size_t klen=strlen(key);
  const char*p=set;uint64_t bits=0;
  for(;;){
    p=strstr(p,key);
    if(!p)break;
    if(p>set&&((p[-1]>='a'&&p[-1]<='z')||(p[-1]>='A'&&p[-1]<='Z')||p[-1]=='_')){p+=klen;continue;}
    p+=klen;
    if(*p=='('){char name[16];const char*q=++p;while(*p&&*p!=')')p++;
      size_t n2=(size_t)(p-q);
      if(n2<sizeof name){memcpy(name,q,n2);name[n2]=0;bits|=space_bit(name);}}
    else bits|=UINT64_C(0x3f);
  }
  return bits;
}
/* One case, read as: the fixture body spells this mnemonic over this operand
   list, the memory operand stands at this position, its annotation names this
   space, and the function declares this effect set. Everything the assertion
   expects is computed from shape_at() and effect_bits(); nothing is written in
   this file. */
typedef struct{const char*name;unsigned operands;unsigned mw;unsigned rw;unsigned position;const char*space;const char*effects;unsigned ri;}Shape;
/* What the pass must answer, computed. The read atom is checked before the
   write atom, which is the order body_effects.check uses, so the category a
   refusal reports is the first atom the declaration does not cover. */
static void verdict(const Shape*a,uint64_t*code,uint64_t*cat,uint64_t*bit,uint64_t*accesses){
  uint64_t shape=shape_at(a->name,a->position,a->operands,a->mw,a->rw,a->ri);
  uint64_t sb=space_bit(a->space);
  *code=0;*cat=0;*bit=0;*accesses=0;
  if(shape==ORACLE_NO||sb==0){*code=336;return;}
  if(shape==0)return;
  (*accesses)++;
  if((shape&1)&&(sb&effect_bits(a->effects,0))!=sb){*code=332;*cat=2;*bit=sb;return;}
  if((shape&2)&&(sb&effect_bits(a->effects,1))!=sb){*code=332;*cat=3;*bit=sb;return;}
}
static void errM(const NovaHostImage*i,const char*n,const char*s,Shape a){uint64_t code=0,cat=0,bit=0,acc=0;verdict(&a,&code,&cat,&bit,&acc);Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]==guard||r.out[1]==guard||r.out[2]!=cat||r.out[3]!=bit){failures++;fprintf(stderr,"FAIL err %s ret=%llu want %llu,%llu,%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)code,(unsigned long long)cat,(unsigned long long)bit,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void okM(const NovaHostImage*i,const char*n,const char*s,const Shape*a,unsigned k){uint64_t writes=0,verified=0,bad=0;for(unsigned j=0;j<k;j++){uint64_t code=0,cat=0,bit=0,acc=0;verdict(&a[j],&code,&cat,&bit,&acc);if(code==336){bad=1;break;}if(!acc)continue;writes++;if(!code)verified++;}Run r=run(i,n,s,4);cases++;checks++;if(bad||r.returned||r.runtime||r.out[0]!=1||r.out[1]!=writes||r.out[2]!=verified||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu want 1,%llu,%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)writes,(unsigned long long)verified,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* 332 or 336 with a position: the position still comes from where() over the
   source text, and the code, the category and the space bit come from the
   oracle shape. */
static void spanM(const NovaHostImage*i,const char*n,const char*s,const char*needle,int nth,Shape a){uint64_t line=0,column=0,code=0,cat=0,bit=0,acc=0;where(s,needle,nth,&line,&column);verdict(&a,&code,&cat,&bit,&acc);Run r=run(i,n,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]!=line||r.out[1]!=column||r.out[2]!=cat||r.out[3]!=bit){failures++;fprintf(stderr,"FAIL span %s ret=%llu want %llu at %llu,%llu %llu,%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)code,(unsigned long long)line,(unsigned long long)column,(unsigned long long)cat,(unsigned long long)bit,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* One instruction in one function. Every case of the table below differs from
   the next by the mnemonic, by the declared effect set or by the pointer
   annotation of the memory operand, so the module is built from those three
   parts rather than escaped by hand one hundred times. %P is the memory
   operand of the function parameter, typed ptr<space,element> with the
   element this call asks for; %A and %B are a second and a third memory
   operand, always ptr<user,u64> and ptr<kernel,u64>, so a two memory form
   tells its two spaces apart. */
static char *one(const char *effects,const char *clob,const char *instr,const char *space,const char *element){
    static char body[512];static char text[2048];size_t w=0;const char *p=instr;int n;
    while(*p){
        if(p[0]=='%'&&(p[1]=='P'||p[1]=='A'||p[1]=='B')){
            const char *sp=p[1]=='A'?"user":p[1]=='B'?"kernel":space;
            const char *reg=p[1]=='A'?"r14":p[1]=='B'?"r13":"r12";
            n=snprintf(body+w,sizeof body-w,"[%s]:ptr<%s,u64>",reg,sp);
            if(n<0||(size_t)n>=sizeof body-w){fprintf(stderr,"fixture body too long\n");exit(2);}
            w+=(size_t)n;p+=2;
        }else body[w++]=*p++;
    }
    body[w]=0;
    n=snprintf(text,sizeof text,"module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<%s,%s> @rdi)->u64\neffects {%s}\nclobbers {%s} {\n%s\nreturn 0\n}\n}\n",space,element,effects,clob,body);
    if(n<0||(size_t)n>=sizeof text){fprintf(stderr,"fixture too long\n");exit(2);}
    return text;
}
int main(void){const char*paths[]={"tests/nova/tests/body-effects-entry.nova","compiler/nova/analysis/abi/body_effects.nova","compiler/nova/analysis/abi/effects.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[8]={0};NtFInput inputs[8];for(unsigned i=0;i<8;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<8;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,8,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");int parity=ng_parity_begin(&ng_parity,&failures,ng_parity_err,sizeof ng_parity_err);if(image.memory&&parity==0){
  // The descriptor group of x64.c:1050, asked of the oracle and of the pass
  // in one comparison. nt_x64_effects charges lgdt, lidt and ltr a read of
  // the operand they take the descriptor from, so the pass charges the same
  // read: a declared reads_mem covers them and an empty one is 332. The
  // widths are the ones nt_x64_encode requires, 80 bits for the four
  // descriptor stores and loads and 16 for the ltr task selector, and a
  // probe with any other width is refused by the encoder and would prove
  // nothing.
  okM(&image,"lgdt m read",one("reads_mem(kernel)","","lgdt %P","kernel","u64"),(const Shape[]){{"lgdt",1,80,0,1,"kernel","reads_mem(kernel)",0}},1);
  errM(&image,"lgdt m no effect",one("","","lgdt %P","kernel","u64"),(Shape){"lgdt",1,80,0,1,"kernel","",0});
  okM(&image,"lidt m read",one("reads_mem(kernel)","","lidt %P","kernel","u64"),(const Shape[]){{"lidt",1,80,0,1,"kernel","reads_mem(kernel)",0}},1);
  errM(&image,"lidt m no effect",one("","","lidt %P","kernel","u64"),(Shape){"lidt",1,80,0,1,"kernel","",0});
  okM(&image,"ltr m read",one("reads_mem(kernel)","","ltr [p]:ptr<kernel,u16>","kernel","u16"),(const Shape[]){{"ltr",1,16,0,1,"kernel","reads_mem(kernel)",0}},1);
  errM(&image,"ltr m no effect",one("","","ltr [p]:ptr<kernel,u16>","kernel","u16"),(Shape){"ltr",1,16,0,1,"kernel","",0});
  confront(&image,"sgdt","sgdt %P",1,80,0,0,1,"kernel","u64",1);
  confront(&image,"sidt","sidt %P",1,80,0,0,1,"kernel","u64",1);
  confront(&image,"lgdt","lgdt %P",1,80,0,0,1,"kernel","u64",1);
  confront(&image,"lidt","lidt %P",1,80,0,0,1,"kernel","u64",1);
  confront(&image,"ltr","ltr [p]:ptr<kernel,u16>",1,16,0,0,1,"kernel","u16",1);
  confront(&image,"invlpg","invlpg %P",1,0,0,0,1,"kernel","u64",0);
const char*none="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"none",none,1,0,0);
 const char*load_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {rax} {\nload rax,[p]:ptr<user,u64>\nreturn rax\n}\n}\n";okM(&image,"load",load_ok,(const Shape[]){{"load",2,64,64,2,"user","reads_mem(user)",0}},1);
 const char*load_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {rax} {\nload rax,[p]:ptr<user,u64>\nreturn rax\n}\n}\n";errM(&image,"load missing",load_bad,(Shape){"load",2,64,64,2,"user","",0});
 const char*store_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<kernel,u64> @rdi,in v:u64 @rax)->u64\neffects {writes_mem(kernel)}\nclobbers {} {\nstore [p]:ptr<kernel,u64>,rax\nreturn 0\n}\n}\n";okM(&image,"store",store_ok,(const Shape[]){{"store",2,64,64,1,"kernel","writes_mem(kernel)",0}},1);
 const char*store_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<kernel,u64> @rdi,in v:u64 @rax)->u64\neffects {writes_mem(user)}\nclobbers {} {\nstore [p]:ptr<kernel,u64>,rax\nreturn 0\n}\n}\n";errM(&image,"store missing",store_bad,(Shape){"store",2,64,64,1,"kernel","writes_mem(user)",0});
 const char*all="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:ptr<firmware,u64> @rdi,in b:ptr<physical,u64> @rsi)->u64\neffects {reads_mem,writes_mem}\nclobbers {rax} {\nload rax,[a]:ptr<firmware,u64>\nstore [b]:ptr<physical,u64>,rax\nreturn 0\n}\n}\n";okM(&image,"all",all,(const Shape[]){{"load",2,64,64,2,"firmware","reads_mem,writes_mem",0},(Shape){"store",2,64,64,1,"physical","reads_mem,writes_mem",0}},2);
 const char*separate="module m\ntarget x86_64-nexora-none\nsection .text {\nfn a(in p:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {rax} {\nload rax,[p]:ptr<user,u64>\nreturn rax\n}\nfn b(in p:ptr<kernel,u64> @rdi)->u64\neffects {reads_mem(kernel)}\nclobbers {rax} {\nload rax,[p]:ptr<kernel,u64>\nreturn rax\n}\n}\n";ok(&image,"separate",separate,2,2,2);
 const char*unknown="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<alien,u64> @rdi)->u64\neffects {reads_mem}\nclobbers {rax} {\nload rax,[p]:ptr<alien,u64>\nreturn rax\n}\n}\n";err(&image,"space",unknown,333,0,0);
  // The token is spelled twice in this fixture, once on the parameter and once
  // on the memory operand, and only the second one is blamed. 333 names the
  // memory operand's OWN annotation, never the declaration it was copied from,
  // so the span is the second `alien` at 7,18 and not the first at 4,15. The
  // three cases below spell their token once, so nothing else pins the rule.
  span(&image,"space names the operand",unknown,333,"alien",2,0,0);
  // A store source operand is read, never written. The first memory operand is
  // the write destination; any later memory operand is a read source. The three
  // cases below stay literals because nt_x64_encode refuses a store whose first
  // operand is a register (x64.c:165), so the oracle has no answer to relay for
  // the second position. RESIDUAL: the pass charges a read on a form the
  // encoder cannot emit, which is the sound direction but is not derived.
  const char*src_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:ptr<user,u64> @rdi,in b:ptr<kernel,u64> @rsi)->u64\neffects {writes_mem(user),reads_mem(kernel)}\nclobbers {} {\nstore [a]:ptr<user,u64>,[b]:ptr<kernel,u64>\nreturn 0\n}\n}\n";ok(&image,"store memory source",src_ok,1,2,2);
  const char*src_not_read="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:ptr<user,u64> @rdi,in b:ptr<kernel,u64> @rsi)->u64\neffects {writes_mem(user),writes_mem(kernel)}\nclobbers {} {\nstore [a]:ptr<user,u64>,[b]:ptr<kernel,u64>\nreturn 0\n}\n}\n";err(&image,"store source not read",src_not_read,332,2,2);
  const char*src_dst_missing="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:ptr<user,u64> @rdi,in b:ptr<kernel,u64> @rsi)->u64\neffects {reads_mem(kernel)}\nclobbers {} {\nstore [a]:ptr<user,u64>,[b]:ptr<kernel,u64>\nreturn 0\n}\n}\n";err(&image,"store destination write",src_dst_missing,332,3,1);
  // A label definition shares node kind 32 with an instruction but carries
  // aux 1: a label named load or store performs no memory access. A label has
  // no operand form, so it is not an oracle question and stays a literal.
  const char*load_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {reads_mem(user)}\nclobbers {rax} {\nload:\nreturn 0\n}\n}\n";ok(&image,"load label",load_label,1,0,0);
  const char*store_label="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {writes_mem(user)}\nclobbers {} {\nstore:\nreturn 0\n}\n}\n";ok(&image,"store label",store_label,1,0,0);
  // ---------------------------------------------------------------------
  // The table of memory forms. Before this lot body_effects recognised only
  // the two mnemonics spelled load and store, so every other instruction that
  // touches memory was free. The cases below walk the whole table: a read only
  // form is accepted with reads_mem and refused with writes_mem, a write only
  // form the other way round, a read modify write needs both, lea addresses
  // without accessing, and a form nothing anchors is refused with 336.
  // Every expected code, category and space bit below is computed from the
  // oracle shape of the position the memory operand occupies, isolated as
  // shape_at() documents, and from the declared effect set of the fixture.
  //
  // xchg is the reported hole: the oracle reads and writes both operands, so
  // a memory operand in second position is a read modify write and the space
  // it wrote was never charged.
  errM(&image,"xchg r/m no effect",one("","rax","xchg rax,%P","kernel","u64"),(Shape){"xchg",2,64,64,2,"kernel","",0});
  errM(&image,"xchg r/m read only",one("reads_mem(kernel)","rax","xchg rax,%P","kernel","u64"),(Shape){"xchg",2,64,64,2,"kernel","reads_mem(kernel)",0});
  errM(&image,"xchg r/m write only",one("writes_mem(kernel)","rax","xchg rax,%P","kernel","u64"),(Shape){"xchg",2,64,64,2,"kernel","writes_mem(kernel)",0});
  okM(&image,"xchg r/m both",one("reads_mem,writes_mem","rax","xchg rax,%P","kernel","u64"),(const Shape[]){{"xchg",2,64,64,2,"kernel","reads_mem,writes_mem",0}},1);
  okM(&image,"xchg r/m both bounded",one("reads_mem(kernel),writes_mem(kernel)","rax","xchg rax,%P","kernel","u64"),(const Shape[]){{"xchg",2,64,64,2,"kernel","reads_mem(kernel),writes_mem(kernel)",0}},1);
  errM(&image,"xchg r/m bounded wrong space",one("reads_mem,writes_mem(user)","rax","xchg rax,%P","kernel","u64"),(Shape){"xchg",2,64,64,2,"kernel","reads_mem,writes_mem(user)",0});
  errM(&image,"xchg r/m space user",one("reads_mem,writes_mem(kernel)","rax","xchg rax,%P","user","u64"),(Shape){"xchg",2,64,64,2,"user","reads_mem,writes_mem(kernel)",0});
  // xchg at every v0 space and at every scalar width: the space bit is what the
  // diagnostic publishes and the width never changes it. The fixture always
  // spells a u64 memory operand, so the query uses the width the encoder
  // requires for xchg, 64, which is the same width; the width cases below
  // change only the parameter type the fixture declares and therefore exercise
  // the space bit alone.
  errM(&image,"xchg space user",one("","rax","xchg rax,%P","user","u64"),(Shape){"xchg",2,64,64,2,"user","",0});
  errM(&image,"xchg space kernel",one("","rax","xchg rax,%P","kernel","u64"),(Shape){"xchg",2,64,64,2,"kernel","",0});
  errM(&image,"xchg space physical",one("","rax","xchg rax,%P","physical","u64"),(Shape){"xchg",2,64,64,2,"physical","",0});
  errM(&image,"xchg space mmio",one("","rax","xchg rax,%P","mmio","u64"),(Shape){"xchg",2,64,64,2,"mmio","",0});
  errM(&image,"xchg space device",one("","rax","xchg rax,%P","device","u64"),(Shape){"xchg",2,64,64,2,"device","",0});
  errM(&image,"xchg space firmware",one("","rax","xchg rax,%P","firmware","u64"),(Shape){"xchg",2,64,64,2,"firmware","",0});
  errM(&image,"xchg width u8",one("","rax","xchg rax,%P","kernel","u8"),(Shape){"xchg",2,64,64,2,"kernel","",0});
  errM(&image,"xchg width u16",one("","rax","xchg rax,%P","kernel","u16"),(Shape){"xchg",2,64,64,2,"kernel","",0});
  errM(&image,"xchg width u32",one("","rax","xchg rax,%P","kernel","u32"),(Shape){"xchg",2,64,64,2,"kernel","",0});
  errM(&image,"xchg width u64",one("","rax","xchg rax,%P","kernel","u64"),(Shape){"xchg",2,64,64,2,"kernel","",0});
  // A memory operand in first position is not a form the oracle admits: xchg
  // writes its first operand and the encoder requires a register there, so the
  // refusal is the oracle's 409 relayed.
  errM(&image,"xchg m/r refused",one("reads_mem,writes_mem","rax","xchg %P,rax","kernel","u64"),(Shape){"xchg",2,64,64,1,"kernel","reads_mem,writes_mem",0});
  errM(&image,"xchg m/m refused",one("reads_mem,writes_mem","rax","xchg %A,%B","kernel","u64"),(Shape){"xchg",2,64,64,1,"user","reads_mem,writes_mem",0});
  err(&image,"xchg alien space",one("reads_mem,writes_mem","rax","xchg rax,[p]:ptr<alien,u64>","kernel","u64"),333,0,0);
  err(&image,"xchg alien element",one("reads_mem,writes_mem","rax","xchg rax,[p]:ptr<user,banana>","user","u64"),333,0,0);
  err(&image,"xchg not a pointer",one("reads_mem,writes_mem","rax","xchg rax,[p]:u64","kernel","u64"),333,0,0);
  spanM(&image,"xchg 332 names the instruction",one("","rax","xchg rax,%P","kernel","u64"),"xchg rax",1,(Shape){"xchg",2,64,64,2,"kernel","",0});
  spanM(&image,"xchg 336 names the operand",one("reads_mem,writes_mem","rax","xchg %P,rax","kernel","u64"),"[r12]",1,(Shape){"xchg",2,64,64,1,"kernel","reads_mem,writes_mem",0});
  span(&image,"xchg 333 names the space",one("reads_mem,writes_mem","rax","xchg rax,[p]:ptr<alien,u64>","kernel","u64"),333,"alien",1,0,0);
  span(&image,"xchg 333 names the element",one("reads_mem,writes_mem","rax","xchg rax,[p]:ptr<user,banana>","user","u64"),333,"banana",1,0,0);
  span(&image,"xchg 333 names the operand",one("reads_mem,writes_mem","rax","xchg rax,[p]:u64","kernel","u64"),333,"[p]",1,0,0);
 //
  // Read only forms. The oracle reads the memory operand and writes only a
  // register, so reads_mem alone covers the instruction and writes_mem alone
  // does not. The width handed to the oracle is the width the encoder requires
  // for the mnemonic, which is not always the u64 the fixture annotation spells:
  // x64.c:503 wants an 8 or 16 bit source for movzx and movsx, and x64.c:498 a
  // 32 bit one for movsxd. The read/write shape does not depend on that width.
  okM(&image,"cmove read",one("reads_mem(kernel)","rax","cmove rax,%P","kernel","u64"),(const Shape[]){{"cmove",2,64,64,2,"kernel","reads_mem(kernel)",0}},1);
  errM(&image,"cmove write only",one("writes_mem(kernel)","rax","cmove rax,%P","kernel","u64"),(Shape){"cmove",2,64,64,2,"kernel","writes_mem(kernel)",0});
  errM(&image,"cmovne write only",one("writes_mem(kernel)","rax","cmovne rax,%P","kernel","u64"),(Shape){"cmovne",2,64,64,2,"kernel","writes_mem(kernel)",0});
  okM(&image,"cmovl read",one("reads_mem(kernel)","rax","cmovl rax,%P","kernel","u64"),(const Shape[]){{"cmovl",2,64,64,2,"kernel","reads_mem(kernel)",0}},1);
  okM(&image,"cmovg read",one("reads_mem(kernel)","rax","cmovg rax,%P","kernel","u64"),(const Shape[]){{"cmovg",2,64,64,2,"kernel","reads_mem(kernel)",0}},1);
  okM(&image,"bsf read",one("reads_mem(user)","rax","bsf rax,%P","user","u64"),(const Shape[]){{"bsf",2,64,64,2,"user","reads_mem(user)",0}},1);
  errM(&image,"bsf write only",one("writes_mem(user)","rax","bsf rax,%P","user","u64"),(Shape){"bsf",2,64,64,2,"user","writes_mem(user)",0});
  okM(&image,"bsr read",one("reads_mem(physical)","rax","bsr rax,%P","physical","u64"),(const Shape[]){{"bsr",2,64,64,2,"physical","reads_mem(physical)",0}},1);
  errM(&image,"bsr no effect",one("","rax","bsr rax,%P","physical","u64"),(Shape){"bsr",2,64,64,2,"physical","",0});
  okM(&image,"movzx read",one("reads_mem(mmio)","rax","movzx rax,%P","mmio","u64"),(const Shape[]){{"movzx",2,8,64,2,"mmio","reads_mem(mmio)",0}},1);
  errM(&image,"movzx write only",one("writes_mem(mmio)","rax","movzx rax,%P","mmio","u64"),(Shape){"movzx",2,8,64,2,"mmio","writes_mem(mmio)",0});
  okM(&image,"movsx read",one("reads_mem(device)","rax","movsx rax,%P","device","u64"),(const Shape[]){{"movsx",2,8,64,2,"device","reads_mem(device)",0}},1);
  errM(&image,"movsx no effect",one("","rax","movsx rax,%P","device","u64"),(Shape){"movsx",2,8,64,2,"device","",0});
  okM(&image,"movsxd read",one("reads_mem(kernel)","rax","movsxd rax,[p]:ptr<kernel,u32>","kernel","u32"),(const Shape[]){{"movsxd",2,32,64,2,"kernel","reads_mem(kernel)",0}},1);
  /* bt with a memory SECOND operand is refused by nt_x64_encode (x64.c:595
     accepts a register or an immediate count there) while the pass charges a
     read, the same coverage gap as bts and btr below, so these two stay
     literals. RESIDUAL: the pass charges a read on a form the encoder cannot
     emit. */
  ok(&image,"bt r/m read",one("reads_mem(firmware)","rax","bt rax,%P","firmware","u64"),1,1,1);
  err(&image,"bt r/m write only",one("writes_mem(firmware)","rax","bt rax,%P","firmware","u64"),332,2,32);
  okM(&image,"bt m/r read",one("reads_mem(kernel)","rax","bt %P,rax","kernel","u64"),(const Shape[]){{"bt",2,64,64,1,"kernel","reads_mem(kernel)",0}},1);
  /* bts, btr and btc with a memory SECOND operand, and every b* form with an
     immediate count, are refused by nt_x64_encode (x64.c:595 accepts a register
     or an immediate there), while the pass charges a read. That is a coverage
     gap of the C encoder rather than of the Nova table, so these two cases
     stay literals. RESIDUAL: the pass charges a read on a form the encoder
     cannot emit. */
  ok(&image,"bts r/m read",one("reads_mem(kernel)","rax","bts rax,%P","kernel","u64"),1,1,1);
  ok(&image,"btr r/m read",one("reads_mem(kernel)","rax","btr rax,%P","kernel","u64"),1,1,1);
  okM(&image,"imul r/m read",one("reads_mem(user)","rax","imul rax,%P","user","u64"),(const Shape[]){{"imul",2,64,64,2,"user","reads_mem(user)",0}},1);
  errM(&image,"imul r/m no effect",one("","rax","imul rax,%P","user","u64"),(Shape){"imul",2,64,64,2,"user","",0});
  okM(&image,"mul m read",one("reads_mem(kernel)","rax,rdx","mul %P","kernel","u64"),(const Shape[]){{"mul",1,64,0,1,"kernel","reads_mem(kernel)",0}},1);
  okM(&image,"div m read",one("reads_mem(kernel)","rax,rdx","div %P","kernel","u64"),(const Shape[]){{"div",1,64,0,1,"kernel","reads_mem(kernel)",0}},1);
  okM(&image,"idiv m read",one("reads_mem(kernel)","rax,rdx","idiv %P","kernel","u64"),(const Shape[]){{"idiv",1,64,0,1,"kernel","reads_mem(kernel)",0}},1);
  okM(&image,"cmp m/r read",one("reads_mem(kernel)","","cmp %P,rax","kernel","u64"),(const Shape[]){{"cmp",2,64,64,1,"kernel","reads_mem(kernel)",0}},1);
  okM(&image,"cmp r/m read",one("reads_mem(kernel)","","cmp rax,%P","kernel","u64"),(const Shape[]){{"cmp",2,64,64,2,"kernel","reads_mem(kernel)",0}},1);
  errM(&image,"cmp r/m write only",one("writes_mem(kernel)","","cmp rax,%P","kernel","u64"),(Shape){"cmp",2,64,64,2,"kernel","writes_mem(kernel)",0});
  okM(&image,"test m/r read",one("reads_mem(kernel)","","test %P,rax","kernel","u64"),(const Shape[]){{"test",2,64,64,1,"kernel","reads_mem(kernel)",0}},1);
  okM(&image,"push m read",one("reads_mem(kernel)","rsp","push %P","kernel","u64"),(const Shape[]){{"push",1,64,0,1,"kernel","reads_mem(kernel)",0}},1);
  errM(&image,"push m write only",one("writes_mem(kernel)","rsp","push %P","kernel","u64"),(Shape){"push",1,64,0,1,"kernel","writes_mem(kernel)",0});
  okM(&image,"mov r/m read",one("reads_mem(kernel)","rax","mov rax,%P","kernel","u64"),(const Shape[]){{"mov",2,64,64,2,"kernel","reads_mem(kernel)",0}},1);
  errM(&image,"mov r/m write only",one("writes_mem(kernel)","rax","mov rax,%P","kernel","u64"),(Shape){"mov",2,64,64,2,"kernel","writes_mem(kernel)",0});
  okM(&image,"sub r/m read",one("reads_mem(kernel)","rax","sub rax,%P","kernel","u64"),(const Shape[]){{"sub",2,64,64,2,"kernel","reads_mem(kernel)",0}},1);
  okM(&image,"or r/m read",one("reads_mem(kernel)","rax","or rax,%P","kernel","u64"),(const Shape[]){{"or",2,64,64,2,"kernel","reads_mem(kernel)",0}},1);
  okM(&image,"jmp m read",one("reads_mem(kernel)","","jmp %P","kernel","u64"),(const Shape[]){{"jmp",1,64,0,1,"kernel","reads_mem(kernel)",0}},1);
  /* invlpg reads a page table entry the x86_64 architecture takes from
     memory, and nt_x64_effects is silent about it: the descriptor group at
     x64.c:1050 calls read_operand for every member except invlpg, so the
     oracle publishes no memory effect while the pass charges a read. That is
     an over charge and never an under charge, so the two stay literals here
     because the oracle has no answer to derive them from; what is derived is
     the confront below, which asks the oracle and the pass about invlpg and
     accepts the extra read while refusing to accept a missing one.
     RESIDUAL: the oracle under-reports invlpg. */
  ok(&image,"invlpg m read",one("reads_mem(kernel)","","invlpg %P","kernel","u64"),1,1,1);
  err(&image,"invlpg m write only",one("writes_mem(kernel)","","invlpg %P","kernel","u64"),332,2,2);
  // load reads its memory operand and writes its register, so reads_mem alone
  // covers it and writes_mem alone never does.
  okM(&image,"load read",one("reads_mem(kernel)","rax","load rax,%P","kernel","u64"),(const Shape[]){{"load",2,64,64,2,"kernel","reads_mem(kernel)",0}},1);
  errM(&image,"load write only",one("writes_mem(kernel)","rax","load rax,%P","kernel","u64"),(Shape){"load",2,64,64,2,"kernel","writes_mem(kernel)",0});
  // lea computes an address and reads no memory at all, so the operand is
  // charged nothing and any declared set, including the empty one, covers it.
  okM(&image,"lea no effect",one("","rax","lea rax,%P","kernel","u64"),(const Shape[]){{"lea",2,64,64,2,"kernel","",0}},1);
  okM(&image,"lea wide effect",one("reads_mem,writes_mem","rax","lea rax,%P","kernel","u64"),(const Shape[]){{"lea",2,64,64,2,"kernel","reads_mem,writes_mem",0}},1);
  //
  // Write only forms. sgdt and sidt store the descriptor they read, setcc
  // writes its byte operand, pop writes its operand and mov or store writes
  // the destination. The descriptor forms want the 80 bit descriptor width
  // (x64.c:659) and the setcc forms an 8 bit operand (x64.c:530), so the query
  // uses those widths; the space bit and the read/write shape do not depend on
  // them, and the u64 the fixture annotation spells is itself a form the
  // encoder refuses.
  okM(&image,"mov m/r write",one("writes_mem(kernel)","rax","mov %P,rax","kernel","u64"),(const Shape[]){{"mov",2,64,64,1,"kernel","writes_mem(kernel)",0}},1);
  errM(&image,"mov m/r read only",one("reads_mem(kernel)","rax","mov %P,rax","kernel","u64"),(Shape){"mov",2,64,64,1,"kernel","reads_mem(kernel)",0});
  okM(&image,"store write",one("writes_mem(kernel)","","store %P,rax","kernel","u64"),(const Shape[]){{"store",2,64,64,1,"kernel","writes_mem(kernel)",0}},1);
  errM(&image,"store read only",one("reads_mem(kernel)","","store %P,rax","kernel","u64"),(Shape){"store",2,64,64,1,"kernel","reads_mem(kernel)",0});
  okM(&image,"sgdt write",one("writes_mem(kernel)","","sgdt %P","kernel","u64"),(const Shape[]){{"sgdt",1,80,0,1,"kernel","writes_mem(kernel)",0}},1);
  errM(&image,"sgdt read only",one("reads_mem(kernel)","","sgdt %P","kernel","u64"),(Shape){"sgdt",1,80,0,1,"kernel","reads_mem(kernel)",0});
  okM(&image,"sidt write",one("writes_mem(physical)","","sidt %P","physical","u64"),(const Shape[]){{"sidt",1,80,0,1,"physical","writes_mem(physical)",0}},1);
  errM(&image,"sidt read only",one("reads_mem(physical)","","sidt %P","physical","u64"),(Shape){"sidt",1,80,0,1,"physical","reads_mem(physical)",0});
  okM(&image,"sete write",one("writes_mem(user)","","sete %P","user","u8"),(const Shape[]){{"sete",1,8,0,1,"user","writes_mem(user)",0}},1);
  errM(&image,"sete read only",one("reads_mem(user)","","sete %P","user","u8"),(Shape){"sete",1,8,0,1,"user","reads_mem(user)",0});
  okM(&image,"setne write",one("writes_mem(user)","","setne %P","user","u8"),(const Shape[]){{"setne",1,8,0,1,"user","writes_mem(user)",0}},1);
  okM(&image,"seto write",one("writes_mem(user)","","seto %P","user","u8"),(const Shape[]){{"seto",1,8,0,1,"user","writes_mem(user)",0}},1);
  okM(&image,"pop m write",one("writes_mem(user)","rsp,rax","pop %P","user","u64"),(const Shape[]){{"pop",1,64,0,1,"user","writes_mem(user)",0}},1);
  errM(&image,"pop m read only",one("reads_mem(user)","rsp,rax","pop %P","user","u64"),(Shape){"pop",1,64,0,1,"user","reads_mem(user)",0});
  // Two memory operands of mov: the first is written, the second supplies the
  // stored value and is therefore read. x64.c:182 admits a register or an
  // immediate as the second operand only, so the oracle refuses this shape and
  // the case stays a literal. RESIDUAL: the pass charges a read on a form the
  // encoder cannot emit.
  ok(&image,"mov m/m",one("writes_mem(user),reads_mem(kernel)","","mov %A,%B","kernel","u64"),1,2,2);
  // A composite element is a type node of its own, and the space of the
  // annotation does not depend on the width, so a nested pointer is charged
  // like a scalar one. examples/os/boot/stage0.ntasm spells this form.
  okM(&image,"load nested element",one("reads_mem(firmware)","rax","load rax,[p]:ptr<firmware,ptr<firmware,u64>>","firmware","u64"),(const Shape[]){{"load",2,64,64,2,"firmware","reads_mem(firmware)",0}},1);
  errM(&image,"load nested element no effect",one("","rax","load rax,[p]:ptr<firmware,ptr<firmware,u64>>","firmware","u64"),(Shape){"load",2,64,64,2,"firmware","",0});
  //
  // Read modify write forms. The oracle reads and writes the destination, so
  // the space must be declared on both atoms and a set that covers only one of
  // them is refused with the category of the atom that is missing.
  okM(&image,"add m/r both",one("reads_mem,writes_mem","","add %P,rax","kernel","u64"),(const Shape[]){{"add",2,64,64,1,"kernel","reads_mem,writes_mem",0}},1);
  errM(&image,"add m/r write only",one("writes_mem(kernel)","","add %P,rax","kernel","u64"),(Shape){"add",2,64,64,1,"kernel","writes_mem(kernel)",0});
  errM(&image,"add m/r read only",one("reads_mem(kernel)","","add %P,rax","kernel","u64"),(Shape){"add",2,64,64,1,"kernel","reads_mem(kernel)",0});
  okM(&image,"adc m/r both",one("reads_mem,writes_mem","","adc %P,rax","kernel","u64"),(const Shape[]){{"adc",2,64,64,1,"kernel","reads_mem,writes_mem",0}},1);
  okM(&image,"sub m/r both",one("reads_mem,writes_mem","","sub %P,rax","kernel","u64"),(const Shape[]){{"sub",2,64,64,1,"kernel","reads_mem,writes_mem",0}},1);
  okM(&image,"sbb m/r both",one("reads_mem,writes_mem","","sbb %P,rax","kernel","u64"),(const Shape[]){{"sbb",2,64,64,1,"kernel","reads_mem,writes_mem",0}},1);
  okM(&image,"and m/r both",one("reads_mem,writes_mem","","and %P,rax","kernel","u64"),(const Shape[]){{"and",2,64,64,1,"kernel","reads_mem,writes_mem",0}},1);
  okM(&image,"or m/r both",one("reads_mem,writes_mem","","or %P,rax","kernel","u64"),(const Shape[]){{"or",2,64,64,1,"kernel","reads_mem,writes_mem",0}},1);
  okM(&image,"xor m/r both",one("reads_mem,writes_mem","","xor %P,rax","kernel","u64"),(const Shape[]){{"xor",2,64,64,1,"kernel","reads_mem,writes_mem",0}},1);
  okM(&image,"inc m both",one("reads_mem,writes_mem","","inc %P","kernel","u64"),(const Shape[]){{"inc",1,64,0,1,"kernel","reads_mem,writes_mem",0}},1);
  errM(&image,"inc m read only",one("reads_mem(kernel)","","inc %P","kernel","u64"),(Shape){"inc",1,64,0,1,"kernel","reads_mem(kernel)",0});
  okM(&image,"dec m both",one("reads_mem,writes_mem","","dec %P","kernel","u64"),(const Shape[]){{"dec",1,64,0,1,"kernel","reads_mem,writes_mem",0}},1);
  okM(&image,"neg m both",one("reads_mem,writes_mem","","neg %P","kernel","u64"),(const Shape[]){{"neg",1,64,0,1,"kernel","reads_mem,writes_mem",0}},1);
  okM(&image,"not m both",one("reads_mem,writes_mem","","not %P","kernel","u64"),(const Shape[]){{"not",1,64,0,1,"kernel","reads_mem,writes_mem",0}},1);
  errM(&image,"not m write only",one("writes_mem(kernel)","","not %P","kernel","u64"),(Shape){"not",1,64,0,1,"kernel","writes_mem(kernel)",0});
  okM(&image,"shl m both",one("reads_mem,writes_mem","","shl %P,1","kernel","u64"),(const Shape[]){{"shl",2,64,8,1,"kernel","reads_mem,writes_mem",1}},1);
  okM(&image,"shr m both",one("reads_mem,writes_mem","","shr %P,1","kernel","u64"),(const Shape[]){{"shr",2,64,8,1,"kernel","reads_mem,writes_mem",1}},1);
  okM(&image,"sar m both",one("reads_mem,writes_mem","","sar %P,1","kernel","u64"),(const Shape[]){{"sar",2,64,8,1,"kernel","reads_mem,writes_mem",1}},1);
  okM(&image,"rol m both",one("reads_mem,writes_mem","","rol %P,1","kernel","u64"),(const Shape[]){{"rol",2,64,8,1,"kernel","reads_mem,writes_mem",1}},1);
  okM(&image,"ror m both",one("reads_mem,writes_mem","","ror %P,1","kernel","u64"),(const Shape[]){{"ror",2,64,8,1,"kernel","reads_mem,writes_mem",1}},1);
  okM(&image,"bts m/r both",one("reads_mem,writes_mem","","bts %P,rax","kernel","u64"),(const Shape[]){{"bts",2,64,64,1,"kernel","reads_mem,writes_mem",0}},1);
  errM(&image,"bts m/r write only",one("writes_mem(kernel)","","bts %P,rax","kernel","u64"),(Shape){"bts",2,64,64,1,"kernel","writes_mem(kernel)",0});
  okM(&image,"btr m/r both",one("reads_mem,writes_mem","","btr %P,rax","kernel","u64"),(const Shape[]){{"btr",2,64,64,1,"kernel","reads_mem,writes_mem",0}},1);
  okM(&image,"btc m/r both",one("reads_mem,writes_mem","","btc %P,rax","kernel","u64"),(const Shape[]){{"btc",2,64,64,1,"kernel","reads_mem,writes_mem",0}},1);
  //
  // Forms nothing anchors, refused with 336 rather than accepted for free.
  // Every 336 below is now nt_x64_encode's own refusal of that exact form.
  errM(&image,"load m/r refused",one("reads_mem(kernel)","rax","load %P,rax","kernel","u64"),(Shape){"load",2,64,64,1,"kernel","reads_mem(kernel)",0});
  // A later memory operand of a store supplies the stored value, so it is a
  // read whatever the first operand is. That is the rule spec/ntasm/ntasm.md 17.4
  // already froze, and nt_x64_encode refuses it (x64.c:165), so these two
  // cases stay literals: RESIDUAL, the pass charges a read on a form the
  // encoder cannot emit.
  err(&image,"store r/m is a read",one("writes_mem(kernel)","rax","store rax,%P","kernel","u64"),332,2,2);
  ok(&image,"store r/m read",one("reads_mem(kernel)","rax","store rax,%P","kernel","u64"),1,1,1);
  errM(&image,"movzx m/r refused",one("reads_mem,writes_mem","rax","movzx %P,rax","kernel","u64"),(Shape){"movzx",2,8,64,1,"kernel","reads_mem,writes_mem",0});
  errM(&image,"cmovl m/r refused",one("reads_mem,writes_mem","rax","cmovl %P,rax","kernel","u64"),(Shape){"cmovl",2,64,64,1,"kernel","reads_mem,writes_mem",0});
  errM(&image,"bsf m/r refused",one("reads_mem,writes_mem","rax","bsf %P,rax","kernel","u64"),(Shape){"bsf",2,64,64,1,"kernel","reads_mem,writes_mem",0});
  errM(&image,"lea m/r refused",one("reads_mem,writes_mem","rax","lea %P,rax","kernel","u64"),(Shape){"lea",2,64,64,1,"kernel","reads_mem,writes_mem",0});
  errM(&image,"test r/m refused",one("reads_mem,writes_mem","","test rax,%P","kernel","u64"),(Shape){"test",2,64,64,2,"kernel","reads_mem,writes_mem",0});
  errM(&image,"shl r/m refused",one("reads_mem,writes_mem","rax","shl rax,%P","kernel","u64"),(Shape){"shl",2,64,64,2,"kernel","reads_mem,writes_mem",0});
  errM(&image,"push r/m refused",one("reads_mem,writes_mem","rsp","push rax,%P","kernel","u64"),(Shape){"push",1,64,0,2,"kernel","reads_mem,writes_mem",0});
  errM(&image,"bswap m refused",one("reads_mem,writes_mem","rax","bswap %P","kernel","u64"),(Shape){"bswap",1,64,0,1,"kernel","reads_mem,writes_mem",0});
  errM(&image,"write_cr m refused",one("reads_mem,writes_mem","","write_cr %P,cr0","kernel","u64"),(Shape){"write_cr",2,64,64,1,"kernel","reads_mem,writes_mem",0});
  errM(&image,"in r/m refused",one("reads_mem,writes_mem","rax","in rax,%P","kernel","u64"),(Shape){"in",2,64,32,2,"kernel","reads_mem,writes_mem",0});
  errM(&image,"out m/r refused",one("reads_mem,writes_mem","rax","out %P,rax","kernel","u64"),(Shape){"out",2,64,8,1,"kernel","reads_mem,writes_mem",0});
  errM(&image,"je m refused",one("reads_mem,writes_mem","","je %P","kernel","u64"),(Shape){"je",1,64,0,1,"kernel","reads_mem,writes_mem",0});
  errM(&image,"hlt m refused",one("","","hlt %P","kernel","u64"),(Shape){"hlt",0,64,0,1,"kernel","",0});
  errM(&image,"nop m refused",one("","","nop %P","kernel","u64"),(Shape){"nop",0,64,0,1,"kernel","",0});
  errM(&image,"rdtsc m refused",one("reads_clock","","rdtsc %P","kernel","u64"),(Shape){"rdtsc",0,64,0,1,"kernel","reads_clock",0});
  /* ---- the six v0 spaces, both directions of the two operand form, so the
     space bit the diagnostic publishes is derived for every space and not only
     for the four the cases above happen to name. ---- */
  {static const char*sp[6]={"user","kernel","physical","mmio","device","firmware"};
   for(unsigned k=0;k<6;k++){char b[32];snprintf(b,sizeof b,"mov %%P,%s",k&1u?"rbx":"rax");
     errM(&image,"mov space write",one("reads_mem",k&1u?"rbx":"rax",b,sp[k],"u64"),(Shape){"mov",2,64,64,1,sp[k],"reads_mem",0});
     snprintf(b,sizeof b,"mov %s,%%P",k&1u?"rbx":"rax");
     errM(&image,"mov space read",one("writes_mem",k&1u?"rbx":"rax",b,sp[k],"u64"),(Shape){"mov",2,64,64,2,sp[k],"writes_mem",0});}}
  bad(&image,"short",none,3);bad(&image,"invalid","target x86_64-nexora-none\n",4);
}if(image.memory){ng_parity_finish(&ng_parity,&failures);nova_host_unmap(&image);}if(compiled)nt_artifact_free(&a);for(unsigned i=0;i<8;i++)free(sources[i]);printf("NTASM_NOVA_BODY_EFFECTS checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
