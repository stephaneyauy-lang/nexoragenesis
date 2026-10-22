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
typedef struct{uint64_t returned,runtime;uint8_t out[16];}Run;
static Run run_seg(const NovaHostImage*,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
static Run run(const NovaHostImage*i,uint64_t reg,uint64_t width,uint64_t base,uint64_t index,uint64_t scale,uint64_t disp,uint64_t features,uint64_t cpl,uint64_t words){return run_seg(i,reg,width,base,index,scale,disp,0,features,cpl,words);}
static Run run_seg(const NovaHostImage*i,uint64_t reg,uint64_t width,uint64_t base,uint64_t index,uint64_t scale,uint64_t disp,uint64_t segment,uint64_t features,uint64_t cpl,uint64_t words){Run r;memset(&r,0,sizeof r);memset(r.out,guard,sizeof r.out);NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t oh=nova_borrow_v2(&c,r.out,words,1);uint64_t a[]={reg,width,base,index,scale,disp,segment,features,cpl,oh,words};r.returned=i->entry(&c,a,11);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return r;}
/* Every case in this gate, at every width, is confronted with nt_x64_encode:
 * where the oracle encodes, the bytes are compared; where it refuses, the code
 * and the untouched output buffer are compared. There is no reimplementation
 * here any more. I04 of the v0 catalogue lists lea with width 64 only and
 * x64.c:176 answers NT_X64_WIDTH for every other destination width, so the
 * narrow rows below are oracle refusals like any other; they used to be
 * compared against an architectural encoding recomputed in this file, which
 * made the narrow half of the gate a second opinion rather than an oracle.
 * That was a real weakness of the evidence and it is closed by the
 * specification, not by this file: encode_lea now refuses what the oracle
 * refuses. */
static Run run_seg(const NovaHostImage*,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
static void compare_seg(const NovaHostImage*,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
static void compare(const NovaHostImage*i,uint64_t reg,uint64_t width,uint64_t base,uint64_t index,uint64_t scale,uint64_t disp,uint64_t features,uint64_t cpl){compare_seg(i,reg,width,base,index,scale,disp,0,features,cpl);}
static void compare_seg(const NovaHostImage*i,uint64_t reg,uint64_t width,uint64_t base,uint64_t index,uint64_t scale,uint64_t disp,uint64_t segment,uint64_t features,uint64_t cpl){
    int mapped_base=base==16?-1:base==17?-2:(int)base;
    int mapped_index=index==16?-1:(int)index;
    int64_t signed_disp=0;
    memcpy(&signed_disp,&disp,sizeof signed_disp);
    NtX64Operand operands[2]={{.kind=NT_X64_REG,.width=(unsigned)width,.reg=(unsigned)reg},
                              {.kind=NT_X64_MEM,.width=(unsigned)width,.base=mapped_base,.index=mapped_index,.scale=(unsigned)scale,.disp=signed_disp,.segment=(NtX64Segment)segment}};
    NtX64Instruction expected={0};
    NtX64Context context={(uint32_t)features,(unsigned)cpl};
    NtX64Error e=nt_x64_encode("lea",operands,2,context,&expected);
    Run r=run_seg(i,reg,width,base,index,scale,disp,segment,features,cpl,16);
    cases++;checks++;
    int bad=r.runtime!=0;
    bad|=r.returned!=(uint64_t)e;
    if(!e){bad|=r.out[0]!=expected.length;for(unsigned k=0;k<15;k++)bad|=r.out[k+1]!=(k<expected.length?expected.bytes[k]:0);}
    else for(unsigned k=0;k<16;k++)bad|=r.out[k]!=guard;
    if(bad){failures++;fprintf(stderr,"FAIL seg=%llu reg=%llu width=%llu base=%llu index=%llu scale=%llu disp=%lld f=%llu p=%llu ret=%llu oracle=%u out=%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",(unsigned long long)segment,(unsigned long long)reg,(unsigned long long)width,(unsigned long long)base,(unsigned long long)index,(unsigned long long)scale,(long long)signed_disp,(unsigned long long)features,(unsigned long long)cpl,(unsigned long long)r.returned,(unsigned)e,r.out[0],r.out[1],r.out[2],r.out[3],r.out[4],r.out[5],r.out[6],r.out[7],r.out[8],r.out[9]);}
}
typedef struct{uint64_t base,index,scale,disp;}Desc;
int main(void){
    const char*paths[]={"tests/nova/tests/x64-lea-entry.nova","compiler/nova/backend/x64/x64_fixed.nova"};
    char*sources[2]={0};
    NtFInput inputs[2];
    for(unsigned i=0;i<2;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}
    int all=sources[0]&&sources[1];
    CHECK(all,"sources load");
    NtArtifact a={0};
    int compiled=all&&nova_compile_many_v2(inputs,2,&a);
    CHECK(compiled,"modules compile");
    if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);
    NovaHostImage image={0};
    CHECK(compiled&&nova_host_map(&a,&image),"image maps");
    if(image.memory){
        const uint64_t regs[]={0,8,15};
        const Desc descs[]={
            {0,16,1,0},{5,16,1,0},{4,16,1,0},{12,16,1,0},{13,16,1,0},
            {0,16,1,127},{0,16,1,128},{0,16,1,UINT64_MAX-127},{0,16,1,UINT64_MAX-128},
            {0,16,1,0xFFFFFFFF7FFFFFFFULL},{0,16,1,0xFFFFFFFF80000000ULL},
            {0,1,1,0},{0,1,2,0},{0,1,4,0},{0,1,8,0},{0,12,8,64},{5,15,4,UINT64_MAX-1},
            {16,16,1,32},{16,2,4,0},{17,16,1,2147483647},{17,16,1,UINT64_MAX-7},{17,16,1,0}};
        for(unsigned r=0;r<3;r++)for(unsigned m=0;m<sizeof descs/sizeof *descs;m++)
            compare(&image,regs[r],64,descs[m].base,descs[m].index,descs[m].scale,descs[m].disp,1,3);
        const uint64_t narrow[]={8,16,32,64};
        const Desc shapes[]={{0,16,1,0},{12,16,1,0},{0,1,4,32},{17,16,1,64},{4,15,2,0}};
        for(unsigned w=0;w<4;w++)for(unsigned r=0;r<2;r++)for(unsigned m=0;m<sizeof shapes/sizeof *shapes;m++)
            compare(&image,r==0?0:15,narrow[w],shapes[m].base,shapes[m].index,shapes[m].scale,shapes[m].disp,1,3);
        compare(&image,0,64,0,4,1,0,1,3);
        compare(&image,0,64,0,16,3,0,1,3);
        compare(&image,0,64,0,16,8,0,1,3);
        compare(&image,0,64,17,1,1,0,1,3);
        compare(&image,0,64,18,16,1,0,1,3);
        compare(&image,0,64,0,17,1,0,1,3);
        compare(&image,0,64,0,16,1,2147483648ULL,1,3);
        compare(&image,0,64,0,16,1,0xFFFFFFFF80000001ULL,1,3);
        compare(&image,16,64,0,16,1,0,1,3);
        compare(&image,0,24,0,16,1,0,1,3);
        compare(&image,0,8,0,16,1,0,1,3);
        compare(&image,0,0,0,16,1,0,1,3);
        compare(&image,0,80,0,16,1,0,1,3);
        compare(&image,0,64,0,16,1,0,0,3);
        compare(&image,0,64,0,16,1,0,1,4);
        /* The fs/gs channel, across the descriptor shapes, confronted with the
         * oracle. encode_lea used to take no segment at all and answered the
         * same bytes for all three, so these rows are the ones that pin the
         * fix; the oracle decides the length, the bytes and the code, so no
         * expected byte is written here. */
        static const struct { const char*label; unsigned seg; } segs[] = {
            {"fs", NT_X64_FS}, {"gs", NT_X64_GS}};
        for (unsigned s2 = 0; s2 < 2; s2++)
            for (unsigned r2 = 0; r2 < 3; r2++)
                for (unsigned m = 0; m < sizeof shapes / sizeof *shapes; m++)
                    compare_seg(&image, regs[r2], 64, shapes[m].base, shapes[m].index,
                                shapes[m].scale, shapes[m].disp, segs[s2].seg, 1, 3);
        /* The segment that does not exist: the oracle answers NT_X64_SEGMENT
         * and the export must answer the same code, not emit a prefix. */
        compare_seg(&image, 0, 64, 3, 16, 1, 8, 3, 1, 3);
        compare_seg(&image, 0, 64, 3, 16, 1, 8, 16, 1, 3);
        /* RIP and the SIB forms with a segment, where the prefix still comes
         * first and the RIP displacement field must not move. */
        compare_seg(&image, 0, 64, 17, 16, 1, 16, NT_X64_FS, 1, 3);
        compare_seg(&image, 0, 64, 17, 16, 1, 16, NT_X64_GS, 1, 3);
        compare_seg(&image, 8, 64, 12, 13, 8, -128, NT_X64_FS, 1, 3);
        Run short_=run(&image,0,64,0,16,1,0,1,3,15);
        cases++;
        int bad=short_.returned!=800||short_.runtime!=0;
        for(unsigned k=0;k<16;k++)bad|=short_.out[k]!=guard;
        CHECK(bad==0,"short output transactional");
    }
    if(image.memory)nova_host_unmap(&image);
    if(compiled)nt_artifact_free(&a);
    for(unsigned i=0;i<2;i++)free(sources[i]);
    printf("NTASM_NOVA_X64_LEA checks=%u failures=%u cases=%u\n",checks,failures,cases);
    return failures?1:0;
}
