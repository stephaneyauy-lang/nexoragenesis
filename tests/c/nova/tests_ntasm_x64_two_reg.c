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
/* One NtX64Operand in the native order. kind1 is a register and kind3 is
 * memory, the native enum numbering; the memory descriptor is shared because
 * every family of this lot holds at most one memory operand. */
typedef struct{uint64_t kind,reg,high8,width;}Part;
typedef struct{uint64_t base,index,scale,disp,segment;}Desc;
static const Desc no_memory={0,16,1,0,0};
static Part gpr(uint64_t r,uint64_t w,uint64_t h){Part p={1,r,h,w};return p;}
static Part mem(uint64_t w){Part p={3,0,0,w};return p;}
typedef struct{uint64_t returned,runtime;uint8_t out[16];}Run;
static Run run(const NovaHostImage*i,uint64_t mode,const char*name,uint64_t count,Part a0,Part a1,Desc d,uint64_t features,uint64_t cpl,uint64_t words){
    Run r;memset(&r,0,sizeof r);memset(r.out,guard,sizeof r.out);
    NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");
    uint64_t nh=nova_borrow_v2(&c,(void*)name,strlen(name),0),oh=nova_borrow_v2(&c,r.out,words,1);
    uint64_t a[]={mode,nh,strlen(name),count,a0.kind,a0.reg,a0.high8,a0.width,a1.kind,a1.reg,a1.high8,a1.width,d.base,d.index,d.scale,d.disp,d.segment,features,cpl,oh,words};
    r.returned=i->entry(&c,a,21);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return r;
}
static NtX64Operand native(Part p,Desc d){
    NtX64Operand o={0};o.kind=(NtX64Kind)p.kind;o.reg=(unsigned)p.reg;o.high8=(unsigned)p.high8;o.width=(unsigned)p.width;
    o.base=d.base==16?-1:d.base==17?-2:(int)d.base;
    o.index=d.index==16?-1:(int)d.index;o.scale=(unsigned)d.scale;
    memcpy(&o.disp,&d.disp,sizeof o.disp);
    o.segment=(NtX64Segment)d.segment;return o;
}
static void compare(const NovaHostImage*i,uint64_t mode,const char*name,uint64_t count,Part a0,Part a1,Desc d,uint64_t features,uint64_t cpl){
    NtX64Operand operands[3]={native(a0,d),native(a1,d),{0}};
    NtX64Instruction expected={0};
    NtX64Context context={(uint32_t)features,(unsigned)cpl};
    NtX64Error e=nt_x64_encode(name,operands,(size_t)count,context,&expected);
    Run r=run(i,mode,name,count,a0,a1,d,features,cpl,16);
    cases++;checks++;
    int bad=r.returned!=(uint64_t)e||r.runtime;
    if(!e){bad|=r.out[0]!=expected.length;for(unsigned k=0;k<15;k++)bad|=r.out[k+1]!=(k<expected.length?expected.bytes[k]:0);}
    else for(unsigned k=0;k<16;k++)bad|=r.out[k]!=guard;
    if(bad){failures++;fprintf(stderr,"FAIL mode=%llu %s count=%llu a0=(%llu,%llu,%llu,%llu) a1=(%llu,%llu,%llu,%llu) mem=(%llu,%llu,%llu,%lld,%llu) f=%llu p=%llu ret=%llu oracle=%u out=%u,%u,%u,%u,%u\n",
        (unsigned long long)mode,name,(unsigned long long)count,
        (unsigned long long)a0.kind,(unsigned long long)a0.reg,(unsigned long long)a0.high8,(unsigned long long)a0.width,
        (unsigned long long)a1.kind,(unsigned long long)a1.reg,(unsigned long long)a1.high8,(unsigned long long)a1.width,
        (unsigned long long)d.base,(unsigned long long)d.index,(unsigned long long)d.scale,(long long)(int64_t)d.disp,(unsigned long long)d.segment,
        (unsigned long long)features,(unsigned long long)cpl,(unsigned long long)r.returned,(unsigned)e,r.out[0],r.out[1],r.out[2],r.out[3],r.out[4]);}
}
/* The immediate test forms of the native encoder belong to a different export
 * than this lot owns, so parity cannot be asserted for them. Prove the boundary
 * instead of hiding it: the export must refuse exactly what the native encoder
 * accepts. */
static void boundary(const NovaHostImage*i,uint64_t mode,const char*name,uint64_t count,Part a0,Part a1,Desc d,uint64_t features,uint64_t cpl,uint64_t exported){
    NtX64Operand operands[3]={native(a0,d),native(a1,d),{0}};
    NtX64Instruction expected={0};
    NtX64Context context={(uint32_t)features,(unsigned)cpl};
    NtX64Error e=nt_x64_encode(name,operands,(size_t)count,context,&expected);
    Run r=run(i,mode,name,count,a0,a1,d,features,cpl,16);
    cases++;checks++;
    int bad=r.returned!=exported||r.runtime||e!=0;
    for(unsigned k=0;k<16;k++)bad|=r.out[k]!=guard;
    if(bad){failures++;fprintf(stderr,"FAIL boundary mode=%llu %s ret=%llu want=%llu oracle=%u\n",
        (unsigned long long)mode,name,(unsigned long long)r.returned,(unsigned long long)exported,(unsigned)e);}
}
/* Diagnostic 408 is the point of this lot: a second register operand that
 * forces REX 0x40 next to a high8 operand, the condition no
 * single-register-operand export could reach. Both the native encoder and the
 * export must answer exactly 408, and the count is checked at the end. */
static unsigned high8_reachable;
static void high8_case(const NovaHostImage*i,uint64_t mode,const char*name,Part a0,Part a1,Desc d){
    NtX64Operand operands[2]={native(a0,d),native(a1,d)};
    NtX64Instruction expected={0};
    NtX64Context context={1,3};
    NtX64Error e=nt_x64_encode(name,operands,2,context,&expected);
    Run r=run(i,mode,name,2,a0,a1,d,1,3,16);
    cases++;checks++;
    int bad=r.returned!=408||r.runtime||e!=NT_X64_HIGH8_REX;
    for(unsigned k=0;k<16;k++)bad|=r.out[k]!=guard;
    if(bad){failures++;fprintf(stderr,"FAIL 408 mode=%llu %s ret=%llu oracle=%u\n",
        (unsigned long long)mode,name,(unsigned long long)r.returned,(unsigned)e);}
    else high8_reachable++;
}
/* mode0 xchg, mode1 cmov*, mode2 bsf/bsr, mode3 movzx/movsx/movsxd, mode4 test. */
int main(void){
    const char*paths[]={"tests/nova/tests/x64-two-reg-entry.nova","compiler/nova/backend/x64/x64_fixed.nova"};
    char*sources[2]={0};NtFInput inputs[2];
    for(unsigned i=0;i<2;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}
    int all=sources[0]&&sources[1];
    CHECK(all,"sources load");
    NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,2,&a);
    CHECK(compiled,"modules compile");
    if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);
    NovaHostImage image={0};
    CHECK(compiled&&nova_host_map(&a,&image),"image maps");
    if(image.memory){
        const uint64_t widths[]={8,16,32,64};
        const uint64_t pairs[][2]={{0,1},{1,0},{0,0},{8,9},{9,8},{0,8},{8,0},{12,15},{4,5},{2,3}};
        const Desc descs[]={{0,16,1,0,0},{5,16,1,0,0},{4,16,1,0,0},{12,16,1,0,0},{8,16,1,127,0},
                            {13,16,1,0,0},{0,1,2,128,0},{0,12,8,UINT64_MAX-127,0},{16,16,1,32,0},
                            {16,2,4,UINT64_MAX-128,0},{17,16,1,2147483647,0},{0,16,1,1,1},{0,16,1,1,2}};
        const char*cmovs[]={"cmove","cmovne","cmovb","cmovae","cmovbe","cmova","cmovs","cmovns",
                            "cmovp","cmovnp","cmovl","cmovge","cmovle","cmovg","cmovo","cmovno"};

        /* I26 xchg: register/register, the same-register spelling, memory both
         * directions, every high8 partner, and the refusals. */
        for(unsigned w=0;w<4;w++)for(unsigned p=0;p<10;p++)
            compare(&image,0,"xchg",2,gpr(pairs[p][0],widths[w],0),gpr(pairs[p][1],widths[w],0),no_memory,1,3);
        for(unsigned h=0;h<4;h++)for(unsigned r=0;r<8;r++)for(unsigned hh=0;hh<2;hh++)
            compare(&image,0,"xchg",2,gpr(h,8,1),gpr((const uint64_t[]){0,1,2,3,4,5,8,12}[r],8,hh),no_memory,1,3);
        for(unsigned w=0;w<4;w++)for(unsigned r=0;r<3;r++)for(unsigned m=0;m<5;m++)
            compare(&image,0,"xchg",2,gpr((const uint64_t[]){0,8,15}[r],widths[w],0),mem(widths[w]),descs[m],1,3);
        for(unsigned h=0;h<4;h++)for(unsigned m=0;m<3;m++)
            compare(&image,0,"xchg",2,gpr(h,8,1),mem(8),descs[m],1,3);
        for(unsigned w=0;w<4;w++)compare(&image,0,"xchg",2,mem(widths[w]),gpr(0,widths[w],0),no_memory,1,3);
        for(unsigned w=0;w<4;w++)compare(&image,0,"xchg",2,gpr(0,widths[w],0),mem(widths[w]*2),descs[0],1,3);
        for(unsigned k=0;k<3;k++)compare(&image,0,"xchg",(const uint64_t[]){0,1,3}[k],gpr(0,64,0),gpr(1,64,0),no_memory,1,3);
        compare(&image,0,"xchg",2,gpr(0,64,0),gpr(1,64,0),no_memory,0,3);
        compare(&image,0,"xchg",2,gpr(0,64,0),gpr(1,64,0),no_memory,1,4);
        compare(&image,0,"telepathy",2,gpr(0,64,0),gpr(1,64,0),no_memory,1,3);
        compare(&image,0,"xchg",2,gpr(16,64,0),gpr(1,64,0),no_memory,1,3);
        compare(&image,0,"xchg",2,gpr(0,24,0),gpr(1,24,0),no_memory,1,3);
        compare(&image,0,"xchg",2,gpr(0,8,2),gpr(1,8,0),no_memory,1,3);
        compare(&image,0,"xchg",2,gpr(4,8,1),gpr(1,8,0),no_memory,1,3);
        for(uint64_t k=0;k<4;k++)compare(&image,0,"xchg",2,gpr(0,64,0),(Part){k,0,0,64},no_memory,1,3);
        compare(&image,0,"xchg",2,gpr(0,64,0),mem(64),(Desc){18,16,1,0,0},1,3);
        compare(&image,0,"xchg",2,gpr(0,64,0),mem(64),(Desc){0,4,1,0,0},1,3);
        compare(&image,0,"xchg",2,gpr(0,64,0),mem(64),(Desc){0,17,1,0,0},1,3);
        compare(&image,0,"xchg",2,gpr(0,64,0),mem(64),(Desc){0,16,3,0,0},1,3);
        compare(&image,0,"xchg",2,gpr(0,64,0),mem(64),(Desc){0,16,2,0,0},1,3);
        compare(&image,0,"xchg",2,gpr(0,64,0),mem(64),(Desc){17,1,1,0,0},1,3);
        compare(&image,0,"xchg",2,gpr(0,64,0),mem(64),(Desc){0,16,1,2147483648ULL,0},1,3);
        compare(&image,0,"xchg",2,gpr(0,64,0),mem(64),(Desc){0,16,1,0,3},1,3);
        compare(&image,0,"xchg",2,gpr(0,64,0),(Part){3,0,0,80},no_memory,1,3);

        /* I22 cmov: sixteen conditions in both legal directions, plus the
         * memory destination the native encoder refuses. */
        for(unsigned n=0;n<16;n++)for(unsigned w=1;w<4;w++){
            compare(&image,1,cmovs[n],2,gpr(0,widths[w],0),gpr(1,widths[w],0),no_memory,1,3);
            compare(&image,1,cmovs[n],2,gpr(8,widths[w],0),gpr(15,widths[w],0),no_memory,1,3);
            compare(&image,1,cmovs[n],2,gpr(0,widths[w],0),mem(widths[w]),descs[0],1,3);
            compare(&image,1,cmovs[n],2,gpr(0,widths[w],0),mem(widths[w]),descs[10],1,3);
            compare(&image,1,cmovs[n],2,gpr(0,widths[w],0),gpr(1,widths[w]*2,0),no_memory,1,3);
        }
        for(unsigned n=0;n<16;n++){
            compare(&image,1,cmovs[n],2,mem(32),gpr(1,32,0),descs[0],1,3);
            compare(&image,1,cmovs[n],2,gpr(0,8,0),gpr(1,8,0),no_memory,1,3);
            compare(&image,1,cmovs[n],2,gpr(0,8,1),gpr(1,8,1),no_memory,1,3);
            compare(&image,1,cmovs[n],1,gpr(0,32,0),gpr(1,32,0),no_memory,1,3);
        }
        compare(&image,1,"cmovq",2,gpr(0,32,0),gpr(1,32,0),no_memory,1,3);
        compare(&image,1,"cmove",2,gpr(0,32,0),gpr(1,32,0),no_memory,0,3);
        compare(&image,1,"cmove",2,gpr(0,32,0),gpr(1,32,0),no_memory,1,4);
        compare(&image,1,"cmove",2,gpr(16,32,0),gpr(1,32,0),no_memory,1,3);
        compare(&image,1,"cmove",2,gpr(0,32,0),(Part){4,0,0,32},no_memory,1,3);
        compare(&image,1,"cmove",2,gpr(0,32,0),mem(32),(Desc){0,16,1,0,7},1,3);

        /* I25 bsf/bsr: register and memory sources, width 16/32/64 only. */
        for(unsigned n=0;n<2;n++)for(unsigned w=1;w<4;w++)for(unsigned p=0;p<6;p++)
            compare(&image,2,(const char*[]){"bsf","bsr"}[n],2,gpr(pairs[p][0],widths[w],0),gpr(pairs[p][1],widths[w],0),no_memory,1,3);
        for(unsigned n=0;n<2;n++)for(unsigned w=1;w<4;w++)for(unsigned m=0;m<4;m++)
            compare(&image,2,(const char*[]){"bsf","bsr"}[n],2,gpr(8,widths[w],0),mem(widths[w]),descs[m],1,3);
        for(unsigned n=0;n<2;n++){
            compare(&image,2,(const char*[]){"bsf","bsr"}[n],2,gpr(0,8,0),gpr(1,8,0),no_memory,1,3);
            compare(&image,2,(const char*[]){"bsf","bsr"}[n],2,gpr(0,8,1),gpr(1,8,0),no_memory,1,3);
            compare(&image,2,(const char*[]){"bsf","bsr"}[n],2,mem(32),gpr(1,32,0),descs[0],1,3);
            compare(&image,2,(const char*[]){"bsf","bsr"}[n],2,gpr(0,32,0),(Part){2,0,0,32},no_memory,1,3);
            compare(&image,2,(const char*[]){"bsf","bsr"}[n],3,gpr(0,32,0),gpr(1,32,0),no_memory,1,3);
        }
        compare(&image,2,"bsz",2,gpr(0,32,0),gpr(1,32,0),no_memory,1,3);
        compare(&image,2,"bsf",2,gpr(0,32,0),gpr(1,32,0),no_memory,0,3);

        /* I05/I06/I07 movzx/movsx/movsxd: every legal width pair, both sources,
         * every high8 source, and every illegal pair the native refuses. */
        for(unsigned n=0;n<2;n++)for(unsigned d=0;d<5;d++)for(unsigned r=0;r<3;r++)for(unsigned s=0;s<4;s++)for(unsigned h=0;h<2;h++)
            compare(&image,3,(const char*[]){"movzx","movsx"}[n],2,
                gpr((const uint64_t[]){0,8,15}[r],(const uint64_t[]){16,32,64,32,64}[d],0),
                gpr((const uint64_t[]){0,1,4,8}[s],(const uint64_t[]){8,8,8,16,16}[d],h),no_memory,1,3);
        for(unsigned n=0;n<2;n++)for(unsigned d=0;d<5;d++)for(unsigned r=0;r<3;r++)for(unsigned m=0;m<3;m++)
            compare(&image,3,(const char*[]){"movzx","movsx"}[n],2,
                gpr((const uint64_t[]){0,8,15}[r],(const uint64_t[]){16,32,64,32,64}[d],0),
                mem((const uint64_t[]){8,8,8,16,16}[d]),descs[m],1,3);
        for(unsigned r=0;r<3;r++)for(unsigned s=0;s<4;s++)for(unsigned h=0;h<2;h++)
            compare(&image,3,"movsxd",2,gpr((const uint64_t[]){0,8,15}[r],64,0),gpr((const uint64_t[]){0,1,4,8}[s],32,h),no_memory,1,3);
        for(unsigned r=0;r<3;r++)for(unsigned m=0;m<3;m++)
            compare(&image,3,"movsxd",2,gpr((const uint64_t[]){0,8,15}[r],64,0),mem(32),descs[m],1,3);
        for(unsigned n=0;n<2;n++)for(unsigned d=0;d<6;d++)
            compare(&image,3,(const char*[]){"movzx","movsx"}[n],2,gpr(0,(const uint64_t[]){8,16,16,32,32,64}[d],0),gpr(1,(const uint64_t[]){8,8,16,8,32,32}[d],0),no_memory,1,3);
        for(unsigned d=0;d<5;d++)
            compare(&image,3,"movsxd",2,gpr(0,(const uint64_t[]){64,64,32,16,8}[d],0),gpr(1,(const uint64_t[]){8,16,32,32,32}[d],0),no_memory,1,3);
        for(unsigned n=0;n<2;n++){
            compare(&image,3,(const char*[]){"movzx","movsx"}[n],2,mem(32),gpr(1,8,0),descs[0],1,3);
            compare(&image,3,(const char*[]){"movzx","movsx"}[n],2,gpr(0,32,0),(Part){0,0,0,32},no_memory,1,3);
            compare(&image,3,(const char*[]){"movzx","movsx"}[n],1,gpr(0,32,0),gpr(1,8,0),no_memory,1,3);
            compare(&image,3,(const char*[]){"movzx","movsx"}[n],2,gpr(0,32,2),gpr(1,8,0),no_memory,1,3);
        }
        compare(&image,3,"movzbw",2,gpr(0,32,0),gpr(1,8,0),no_memory,1,3);
        compare(&image,3,"movsxd",2,gpr(0,64,0),gpr(1,32,0),no_memory,0,3);
        compare(&image,3,"movsxd",2,gpr(0,64,0),mem(32),(Desc){0,16,1,1,2},1,3);

        /* I09 test: register/register, memory/register, the memory/register
         * spelling the native encoder refuses, and the flags-only form. */
        for(unsigned w=0;w<4;w++)for(unsigned p=0;p<10;p++)
            compare(&image,4,"test",2,gpr(pairs[p][0],widths[w],0),gpr(pairs[p][1],widths[w],0),no_memory,1,3);
        for(unsigned h=0;h<4;h++)for(unsigned r=0;r<8;r++)for(unsigned hh=0;hh<2;hh++)
            compare(&image,4,"test",2,gpr(h,8,1),gpr((const uint64_t[]){0,1,2,3,4,5,8,12}[r],8,hh),no_memory,1,3);
        for(unsigned w=0;w<4;w++)for(unsigned m=0;m<4;m++)
            compare(&image,4,"test",2,mem(widths[w]),gpr(1,widths[w],0),descs[m],1,3);
        for(unsigned m=0;m<3;m++)compare(&image,4,"test",2,mem(8),gpr(0,8,1),descs[m],1,3);
        for(unsigned w=0;w<4;w++)compare(&image,4,"test",2,gpr(0,widths[w],0),mem(widths[w]),descs[0],1,3);
        for(unsigned w=0;w<4;w++)compare(&image,4,"test",2,mem(widths[w]),mem(widths[w]),descs[0],1,3);
        for(unsigned w=0;w<4;w++)compare(&image,4,"test",2,mem(widths[w]),gpr(1,widths[w]*2,0),descs[0],1,3);
        compare(&image,4,"test",2,gpr(0,64,0),gpr(1,64,0),no_memory,1,3);
        compare(&image,4,"test",2,gpr(0,64,0),gpr(1,64,0),no_memory,0,3);
        compare(&image,4,"test",2,gpr(0,64,0),gpr(1,64,0),no_memory,1,4);
        compare(&image,4,"test",2,gpr(16,64,0),gpr(1,64,0),no_memory,1,3);
        compare(&image,4,"test",2,gpr(0,24,0),gpr(1,24,0),no_memory,1,3);
        compare(&image,4,"test",2,gpr(0,8,2),gpr(1,8,0),no_memory,1,3);
        compare(&image,4,"test",2,mem(80),gpr(1,80,0),descs[0],1,3);
        compare(&image,4,"test",2,gpr(0,64,0),(Part){4,0,0,64},no_memory,1,3);
        /* Out of this lot: the native immediate test forms, which the native
         * encoder accepts and encode_test_two refuses. */
        for(unsigned w=0;w<4;w++)for(unsigned r=0;r<2;r++)
            boundary(&image,4,"test",2,gpr(r?3:0,widths[w],0),(Part){2,0,0,0},no_memory,1,3,409);
        boundary(&image,4,"test",2,mem(32),(Part){2,0,0,0},descs[0],1,3,409);
        boundary(&image,4,"test",2,gpr(0,32,0),(Part){2,0,0,0},no_memory,1,3,409);

        /* 408: a high8 operand plus a second register operand that forces REX.
         * xchg, test, movzx and movsx reach it; the memory-destination cmov and
         * bsf/bsr cannot, because a width other than 8 leaves no high8 operand. */
        for(unsigned h=0;h<4;h++){
            high8_case(&image,0,"xchg",gpr(h,8,1),gpr(8,8,0),no_memory);
            high8_case(&image,0,"xchg",gpr(h,8,1),gpr(4,8,0),no_memory);
            high8_case(&image,0,"xchg",gpr(8,8,0),gpr(h,8,1),no_memory);
            high8_case(&image,0,"xchg",gpr(h,8,1),mem(8),(Desc){8,16,1,0,0});
            high8_case(&image,4,"test",gpr(h,8,1),gpr(8,8,0),no_memory);
            high8_case(&image,4,"test",mem(8),gpr(h,8,1),(Desc){8,16,1,0,0});
            high8_case(&image,3,"movzx",gpr(8,32,0),gpr(h,8,1),no_memory);
            high8_case(&image,3,"movsx",gpr(8,32,0),gpr(h,8,1),no_memory);
            high8_case(&image,3,"movzx",gpr(0,64,0),gpr(h,8,1),no_memory);
            high8_case(&image,3,"movsx",gpr(0,64,0),gpr(h,8,1),no_memory);
            high8_case(&image,3,"movzx",gpr(8,64,0),gpr(h,8,1),no_memory);
        }
        CHECK(high8_reachable==44,"408 reachable in 44 two-register cases");
        CHECK(high8_reachable>=3,"408 reachable at least three times");

        /* Transactional output: a short buffer, an unknown mode, and a
         * diagnostic that must leave every byte of out untouched. */
        Run short_=run(&image,0,"xchg",2,gpr(0,64,0),gpr(1,64,0),no_memory,1,3,15);
        cases++;
        int bad=short_.returned!=800||short_.runtime!=0;
        for(unsigned k=0;k<16;k++)bad|=short_.out[k]!=guard;
        CHECK(bad==0,"short output transactional");
        Run mode_=run(&image,9,"xchg",2,gpr(0,64,0),gpr(1,64,0),no_memory,1,3,16);
        cases++;
        bad=mode_.returned!=800||mode_.runtime!=0;
        for(unsigned k=0;k<16;k++)bad|=mode_.out[k]!=guard;
        CHECK(bad==0,"unknown mode transactional");
    }
    if(image.memory)nova_host_unmap(&image);
    if(compiled)nt_artifact_free(&a);
    for(unsigned i=0;i<2;i++)free(sources[i]);
    printf("NTASM_NOVA_X64_TWO_REG checks=%u failures=%u cases=%u\n",checks,failures,cases);
    return failures?1:0;
}
