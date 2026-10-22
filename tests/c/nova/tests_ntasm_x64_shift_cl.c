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
static Run run(const NovaHostImage*i,uint64_t kind,const char*name,uint64_t count,uint64_t dest,uint64_t width,uint64_t count_register,uint64_t high8,uint64_t amount,uint64_t features,uint64_t cpl,uint64_t words){Run r;memset(&r,0,sizeof r);memset(r.out,guard,sizeof r.out);NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t nh=nova_borrow_v2(&c,(void*)name,strlen(name),0),oh=nova_borrow_v2(&c,r.out,words,1);uint64_t a[]={kind,nh,strlen(name),count,dest,width,count_register,high8,amount,features,cpl,oh,words};r.returned=i->entry(&c,a,13);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return r;}
/* kind0: the CL form (operand 1 is a register); kind1: the immediate form, kept
 * in the same entry so the untouched encode_shift_imm path stays observable. */
static void compare(const NovaHostImage*i,uint64_t kind,const char*name,uint64_t count,uint64_t dest,uint64_t width,uint64_t count_register,uint64_t high8,uint64_t amount,uint64_t features,uint64_t cpl){
    NtX64Operand operands[2]={{.kind=NT_X64_REG,.width=(unsigned)width,.reg=(unsigned)dest,.high8=(unsigned)high8},{.kind=NT_X64_REG,.width=8,.reg=(unsigned)count_register}};
    if(kind)operands[1]=(NtX64Operand){.kind=NT_X64_IMM,.imm=amount};
    NtX64Instruction expected={0};
    NtX64Context context={(uint32_t)features,(unsigned)cpl};
    NtX64Error e=nt_x64_encode(name,operands,(size_t)count,context,&expected);
    Run r=run(i,kind,name,count,dest,width,count_register,high8,amount,features,cpl,16);
    cases++;checks++;
    int bad=r.returned!=(uint64_t)e||r.runtime;
    if(!e){bad|=r.out[0]!=expected.length;for(unsigned k=0;k<15;k++){uint8_t want=k<expected.length?expected.bytes[k]:(k<5?0:guard);bad|=r.out[k+1]!=want;}}
    else for(unsigned k=0;k<16;k++)bad|=r.out[k]!=guard;
    if(bad){failures++;fprintf(stderr,"FAIL kind=%llu %s count=%llu reg=%llu width=%llu countreg=%llu high8=%llu amount=%llu ret=%llu oracle=%u out=%u,%u,%u,%u,%u\n",(unsigned long long)kind,name,(unsigned long long)count,(unsigned long long)dest,(unsigned long long)width,(unsigned long long)count_register,(unsigned long long)high8,(unsigned long long)amount,(unsigned long long)r.returned,(unsigned)e,r.out[0],r.out[1],r.out[2],r.out[3],r.out[4]);}
}
int main(void){
    const char*paths[]={"tests/nova/tests/x64-shift-cl-entry.nova","compiler/nova/backend/x64/x64_fixed.nova"};
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
        const char*names[]={"rol","ror","shl","shr","sar"};
        const uint64_t widths[]={8,16,32,64};
        const uint64_t regs[]={0,4,8,12,15};
        for(unsigned n=0;n<5;n++)for(unsigned w=0;w<4;w++)for(unsigned r=0;r<5;r++)
            compare(&image,0,names[n],2,regs[r],widths[w],1,0,0,1,3);
        for(unsigned n=0;n<5;n++)for(unsigned h=0;h<4;h++)
            compare(&image,0,names[n],2,h,8,1,1,0,1,3);
        for(unsigned n=0;n<5;n++)for(unsigned w=0;w<4;w++)for(unsigned r=0;r<5;r++)for(unsigned m=0;m<3;m++)
            compare(&image,1,names[n],2,regs[r],widths[w],1,0,m==0?0:1,1,3);
        for(unsigned n=0;n<5;n++)for(unsigned m=0;m<3;m++)
            compare(&image,1,names[n],2,regs[m],64,1,0,m==0?0:255,1,3);
        compare(&image,0,"telepathy",2,0,64,1,0,0,1,3);
        compare(&image,0,"shl",1,0,64,1,0,0,1,3);
        compare(&image,0,"shl",3,0,64,1,0,0,1,3);
        compare(&image,0,"shl",2,24,64,1,0,0,1,3);
        compare(&image,0,"shl",2,16,64,1,0,0,1,3);
        compare(&image,0,"shl",2,0,64,0,0,0,1,3);
        compare(&image,0,"shl",2,0,64,2,0,0,1,3);
        compare(&image,0,"shl",2,0,64,16,0,0,1,3);
        compare(&image,0,"shl",2,0,32,1,2,0,1,3);
        compare(&image,0,"shl",2,4,8,1,1,0,1,3);
        compare(&image,0,"shl",2,0,64,1,0,0,0,3);
        compare(&image,0,"shl",2,0,64,1,0,0,1,4);
        Run short_=run(&image,0,"shl",2,0,64,1,0,0,1,3,5);
        cases++;
        int bad=short_.returned!=800||short_.runtime!=0;
        for(unsigned k=0;k<16;k++)bad|=short_.out[k]!=guard;
        CHECK(bad==0,"short output transactional");
    }
    if(image.memory)nova_host_unmap(&image);
    if(compiled)nt_artifact_free(&a);
    for(unsigned i=0;i<2;i++)free(sources[i]);
    printf("NTASM_NOVA_X64_SHIFT_CL checks=%u failures=%u cases=%u\n",checks,failures,cases);
    return failures?1:0;
}
