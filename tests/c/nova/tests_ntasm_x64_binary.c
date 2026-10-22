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
typedef struct{uint64_t kind,reg,high8,width;}Part;
typedef struct{uint64_t base,index,scale,disp,segment;}Desc;
static const Desc plain={0,16,1,0,0};
static Part reg(unsigned r,unsigned w,unsigned h){Part p={1,r,h,w};return p;}
static Part mem(unsigned w){Part p={3,0,0,w};return p;}
static Part imm(unsigned w){Part p={2,0,0,w};return p;}
static Part cr(unsigned r){Part p={5,r,0,64};return p;}
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
static NtX64Operand native(Part p,Desc d,uint64_t value,unsigned sign){
    NtX64Operand o={0};o.kind=(NtX64Kind)p.kind;o.reg=(unsigned)p.reg;o.high8=(unsigned)p.high8;o.width=(unsigned)p.width;
    o.base=d.base==16?-1:d.base==17?-2:(int)d.base;o.index=d.index==16?-1:(int)d.index;o.scale=(unsigned)d.scale;
    memcpy(&o.disp,&d.disp,sizeof o.disp);o.segment=(NtX64Segment)d.segment;o.imm=value;o.is_signed=sign;return o;
}
static void compare(const NovaHostImage*i,const char*name,unsigned count,Part a0,Part a1,Desc d,uint64_t value,unsigned sign,unsigned features,unsigned cpl){
    NtX64Operand operands[3]={native(a0,d,value,sign),native(a1,d,value,sign),{0}};
    NtX64Instruction expected={0};NtX64Context context={features,cpl};
    NtX64Error e=nt_x64_encode(name,operands,count,context,&expected);
    uint8_t out[16];memset(out,0xcc,sizeof out);NovaContextV2 ctx={0};CHECK(nova_context_init_v2(&ctx),"context init");
    uint64_t nh=nova_borrow_v2(&ctx,(void*)name,strlen(name),0),oh=nova_borrow_v2(&ctx,out,16,1);
    uint64_t args[]={nh,strlen(name),count,a0.kind,a0.reg,a0.high8,a0.width,a1.kind,a1.reg,a1.high8,a1.width,d.base,d.index,d.scale,d.disp,d.segment,value,sign,features,cpl,oh,16};
    uint64_t result=i->entry(&ctx,args,22),runtime=ctx.error;CHECK(nova_context_destroy_v2(&ctx),"context cleanup");
    cases++;checks++;int bad=result!=(uint64_t)e||runtime;
    if(!e){bad|=out[0]!=expected.length;for(unsigned k=0;k<15;k++)bad|=out[k+1]!=(k<expected.length?expected.bytes[k]:0);}
    else for(unsigned k=0;k<16;k++)bad|=out[k]!=0xcc;
    if(bad){failures++;fprintf(stderr,"FAIL %s n=%u a0=%llu,%llu,%llu,%llu a1=%llu,%llu,%llu,%llu d=%llu,%llu,%llu,%lld,%llu imm=%llu sign=%u f=%u cpl=%u ret=%llu C=%u runtime=%llu\n",name,count,
        (unsigned long long)a0.kind,(unsigned long long)a0.reg,(unsigned long long)a0.high8,(unsigned long long)a0.width,
        (unsigned long long)a1.kind,(unsigned long long)a1.reg,(unsigned long long)a1.high8,(unsigned long long)a1.width,
        (unsigned long long)d.base,(unsigned long long)d.index,(unsigned long long)d.scale,(long long)(int64_t)d.disp,(unsigned long long)d.segment,
        (unsigned long long)value,sign,features,cpl,(unsigned long long)result,(unsigned)e,(unsigned long long)runtime);}
}
int main(void){
    const char*paths[]={"tests/nova/tests/x64-binary-entry.nova","compiler/nova/backend/x64/x64_fixed.nova"};char*sources[2]={0};NtFInput inputs[2];
    for(unsigned k=0;k<2;k++){size_t n=0;sources[k]=loadf(paths[k],&n);inputs[k]=(NtFInput){paths[k],sources[k],n};}
    NtArtifact artifact={0};int compiled=sources[0]&&sources[1]&&nova_compile_many_v2(inputs,2,&artifact);CHECK(compiled,"modules compile");
    if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",artifact.error.code,artifact.error.line,artifact.error.column,artifact.error.message);
    NovaHostImage image={0};CHECK(compiled&&nova_host_map(&artifact,&image),"image maps");
    if(image.memory){
        const unsigned widths[]={8,16,32,64};const unsigned registers[]={0,1,3,4,8,15};
        const char*names[]={"mov","load","store","add","or","adc","sbb","and","sub","xor","cmp","test"};
        const Desc addresses[]={{0,16,1,0,0},{5,16,1,0,1},{12,9,4,128,2},{16,16,1,UINT64_MAX,0},{17,16,1,127,1}};
        const uint64_t values[]={0,1,127,128,255,256,32767,32768,65535,UINT64_C(2147483647),UINT64_C(2147483648),UINT64_MAX,UINT64_MAX-127,UINT64_MAX-128};
        for(unsigned n=0;n<12;n++)for(unsigned w=0;w<4;w++){
            for(unsigned r=0;r<6;r++)for(unsigned s=0;s<6;s++)compare(&image,names[n],2,reg(registers[r],widths[w],0),reg(registers[s],widths[w],0),plain,0,0,1,3);
            for(unsigned d=0;d<5;d++){
                compare(&image,names[n],2,reg(8,widths[w],0),mem(widths[w]),addresses[d],0,0,1,3);
                compare(&image,names[n],2,mem(widths[w]),reg(8,widths[w],0),addresses[d],0,0,1,3);
                for(unsigned v=0;v<14;v++)for(unsigned sign=0;sign<2;sign++)compare(&image,names[n],2,mem(widths[w]),imm(0),addresses[d],values[v],sign,1,3);
            }
            for(unsigned r=0;r<6;r++)for(unsigned v=0;v<14;v++)for(unsigned sign=0;sign<2;sign++)compare(&image,names[n],2,reg(registers[r],widths[w],0),imm(0),plain,values[v],sign,1,3);
            for(unsigned r=0;r<4;r++){
                compare(&image,names[n],2,reg(r,8,1),reg(4,8,0),plain,0,0,1,3);
                compare(&image,names[n],2,reg(4,8,0),reg(r,8,1),plain,0,0,1,3);
                for(unsigned d=0;d<5;d++){
                    compare(&image,names[n],2,reg(r,8,1),mem(8),addresses[d],0,0,1,3);
                    compare(&image,names[n],2,mem(8),reg(r,8,1),addresses[d],0,0,1,3);
                }
                compare(&image,names[n],2,reg(r,8,1),imm(0),plain,128,0,1,3);
            }
        }
        const Part malformed[]={{1,16,0,64},{1,0,2,8},{1,0,1,32},{1,0,0,7},{3,0,0,7},{2,0,0,7},{4,0,0,7},{5,1,0,64},{5,0,1,64},{5,0,0,32},{0,0,0,0}};
        for(unsigned n=0;n<12;n++){
            for(unsigned k=0;k<11;k++){
                compare(&image,names[n],2,malformed[k],reg(0,64,0),plain,0,0,1,3);
                compare(&image,names[n],2,reg(0,64,0),malformed[k],plain,0,0,1,3);
            }
            for(unsigned count=0;count<5;count++)compare(&image,names[n],count,reg(0,64,0),imm(0),plain,0,0,1,3);
            compare(&image,names[n],2,reg(16,64,0),imm(0),plain,0,0,0,3);
            compare(&image,names[n],2,reg(0,64,0),imm(8),plain,256,0,1,3);
            compare(&image,names[n],2,reg(0,64,0),imm(0),plain,0,2,1,3);
            const Desc invalid_addresses[]={{18,16,1,0,0},{0,17,1,0,0},{0,4,1,0,0},{0,16,2,0,0},{17,0,1,0,0},{0,16,3,0,0},{0,16,1,UINT64_C(2147483648),0},{0,16,1,UINT64_MAX-UINT64_C(2147483648),0},{0,16,1,0,3}};
            for(unsigned d=0;d<9;d++){
                compare(&image,names[n],2,mem(64),reg(0,64,0),invalid_addresses[d],0,0,1,3);
                compare(&image,names[n],2,reg(0,64,0),mem(64),invalid_addresses[d],0,0,1,3);
            }
            compare(&image,names[n],2,mem(0),reg(0,64,0),plain,0,0,1,3);
            compare(&image,names[n],2,mem(80),reg(0,64,0),plain,0,0,1,3);
            compare(&image,names[n],2,reg(0,64,0),imm(8),plain,UINT64_MAX,1,1,3);
            compare(&image,names[n],2,reg(0,64,0),imm(8),plain,128,1,1,3);
            compare(&image,names[n],2,reg(0,64,0),reg(0,32,0),plain,0,0,1,3);
        }
        const unsigned controls[]={0,2,3,4,8,1,16};
        for(unsigned c=0;c<7;c++)for(unsigned r=0;r<6;r++)for(unsigned w=0;w<4;w++)for(unsigned p=0;p<4;p++){
            compare(&image,"read_cr",2,reg(registers[r],widths[w],0),cr(controls[c]),plain,0,0,1,p);
            compare(&image,"write_cr",2,cr(controls[c]),reg(registers[r],widths[w],0),plain,0,0,1,p);
        }
        for(unsigned w=0;w<4;w++)for(unsigned p=0;p<4;p++)for(unsigned v=0;v<14;v++){
            compare(&image,"in",2,reg(0,widths[w],0),imm(0),plain,values[v],0,1,p);
            compare(&image,"out",2,imm(0),reg(0,widths[w],0),plain,values[v],0,1,p);
            compare(&image,"in",2,reg(0,widths[w],0),reg(2,16,0),plain,0,0,1,p);
            compare(&image,"out",2,reg(2,16,0),reg(0,widths[w],0),plain,0,0,1,p);
        }
        const char*special[]={"in","out","read_cr","write_cr"};
        for(unsigned n=0;n<4;n++)for(unsigned k=0;k<11;k++)for(unsigned p=0;p<4;p++){
            compare(&image,special[n],2,malformed[k],malformed[0],plain,0,0,1,p);
            compare(&image,special[n],2,reg(0,8,1),imm(0),plain,0,0,0,p);
        }
        for(unsigned h=0;h<2;h++)for(unsigned c=0;c<7;c++){
            compare(&image,"read_cr",2,reg(3,8,h),cr(controls[c]),plain,0,0,1,0);
            compare(&image,"write_cr",2,cr(controls[c]),reg(3,8,h),plain,0,0,1,0);
        }
        for(unsigned w=0;w<4;w++)for(unsigned v=0;v<14;v++)for(unsigned sign=0;sign<3;sign++){
            compare(&image,"in",2,reg(0,widths[w],0),imm(8),plain,values[v],sign,1,0);
            compare(&image,"out",2,imm(8),reg(0,widths[w],0),plain,values[v],sign,1,0);
        }
        for(unsigned n=0;n<4;n++)for(unsigned count=0;count<5;count++)for(unsigned p=0;p<5;p++){
            compare(&image,special[n],count,malformed[0],malformed[0],plain,0,0,1,p);
        }
        compare(&image,"unknown",2,reg(0,64,0),imm(0),plain,0,0,1,3);
        nova_host_unmap(&image);
    }
    nt_artifact_free(&artifact);free(sources[0]);free(sources[1]);
    printf("NTASM_NOVA_X64_BINARY checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;
}
