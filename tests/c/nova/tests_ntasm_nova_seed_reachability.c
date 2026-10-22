#define _GNU_SOURCE
/* C_SEED_ORACLE tests only. No native producer claim. */
#include <unistd.h>
#include <signal.h>
static pid_t seed_dce_fork(void){pid_t p=fork();if(p==0)alarm(5);return p;}
#define fork seed_dce_fork
#define main prior_seed_dce_pe_observer_main
#include "tests_ntasm_pe_exec.c"
#undef main
#undef fork
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/nova/analysis/seed_reachability.h"

static NtCodeImage synthetic(unsigned export_dead,unsigned address_section){
    NtCodeImage im={0};im.size=im.capacity=26;im.bytes=calloc(26,1);im.entry=0;
    /* ABI-correct caller, unused function returning99, callee returning42. */
    const uint8_t text[]={0x48,0x83,0xec,0x28,0xe8,11,0,0,0,0x48,0x83,0xc4,0x28,0xc3,
                          0xb8,99,0,0,0,0xc3,0xb8,42,0,0,0,0xc3};
    if(im.bytes)memcpy(im.bytes,text,sizeof text);
    im.symbol_count=im.symbol_capacity=address_section?4:3;
    im.symbols=calloc(im.symbol_count,sizeof *im.symbols);
    im.relocation_count=im.relocation_capacity=address_section?2:1;
    im.relocations=calloc(im.relocation_count,sizeof *im.relocations);
    if(!im.bytes||!im.symbols||!im.relocations)return im;
    const char *names[]={"entry","unused","callee","address"};
    for(size_t i=0;i<im.symbol_count;i++){im.symbols[i].name=strdup(names[i]);im.symbols[i].module=strdup("synthetic");}
    im.symbols[0]=(NtCodeSymbol){im.symbols[0].name,im.symbols[0].module,1,1,0,14,1,0};
    im.symbols[1]=(NtCodeSymbol){im.symbols[1].name,im.symbols[1].module,1,export_dead,14,6,2,0};
    im.symbols[2]=(NtCodeSymbol){im.symbols[2].name,im.symbols[2].module,1,0,20,6,3,0};
    im.relocations[0]=(NtCodeReloc){1,NT_CODE_RELOC_REL32,5,3,0,0};
    if(address_section){
        NtCodeBuffer *b=address_section==2?&im.rdata:&im.data;
        b->size=b->capacity=8;b->bytes=calloc(8,1);
        im.symbols[3]=(NtCodeSymbol){im.symbols[3].name,im.symbols[3].module,address_section,0,0,8,0,100};
        im.relocations[1]=(NtCodeReloc){address_section,NT_CODE_RELOC_DIR64,0,2,0,0};
    }
    return im;
}
static void image_to_artifact(NtCodeImage *im,NtArtifact *out){
    out->text=(NtBuffer){im->bytes,im->size,im->capacity};out->entry=im->entry;
    out->rdata=(NtBuffer){im->rdata.bytes,im->rdata.size,im->rdata.capacity};
    out->data=(NtBuffer){im->data.bytes,im->data.size,im->data.capacity};
    im->bytes=NULL;im->rdata.bytes=NULL;im->data.bytes=NULL;
    NtCodeDiagnostic d={0};
    CHECK(nova_seed_materialize_dir64(im,out,&d),"typed DIR64 materialization E%u %s",d.code,d.message);
}
static void execute_artifact(NtArtifact *a,uint64_t wanted){
    CHECK(nt_make_pe(a)&&a->pe.bytes&&a->pe.size,"real PE emitted for independent execution");
    if(!a->pe.bytes)return;
    uint64_t got=0;char why[256]={0};
    int rc=run_child(a->pe.bytes,a->pe.size,&got,why,sizeof why);
    CHECK(rc==0&&got==wanted,"independent PE execution rc=%d got=%" PRIu64 " want=%" PRIu64 " %s",rc,got,wanted,why);
}
static void graph_cases(void){
    NtCodeDiagnostic d={0};NovaSeedReachabilityStats s={0};
    for(unsigned policy=0;policy<=1;policy++){
        cases++;NtCodeImage im=synthetic(1,0);CHECK(im.bytes&&im.symbols,"synthetic image allocated");
        int ok=nova_seed_compact_image(&im,policy,&s,&d);
        CHECK(ok,"policy compaction E%u %s",d.code,d.message);
        CHECK(s.graph_complete&&s.functions_before==3,"complete graph count from original image");
        CHECK(s.functions_kept==(policy?2:3),"default keeps public export; closed application drops unused visibility");
        CHECK(s.roots_entry==1&&s.roots_exported==(policy?0:2),"entry/export root policies are explicit");
        CHECK(im.relocation_count==1,"all reachable symbolic references retained");
        if(ok){NtArtifact a={0};image_to_artifact(&im,&a);execute_artifact(&a,42);nt_artifact_free(&a);}
        nt_code_image_free(&im);
    }
    for(unsigned section=2;section<=3;section++){
        cases++;NtCodeImage im=synthetic(0,section);
        int ok=nova_seed_compact_image(&im,NOVA_SEED_ENTRY_ONLY_CLOSED_APPLICATION,&s,&d);
        CHECK(ok&&s.functions_kept==3&&s.roots_data==1,"function address in data/rdata roots whole function");
        CHECK(im.relocation_count==2,"data function-address relocation is retained");
        const NtCodeBuffer *b=section==2?&im.rdata:&im.data;
        CHECK(b->size==8&&nvs_read(b->bytes,8)==0,"DIR64 remains placeholder until typed materialization");
        if(ok){
            NtArtifact a={0};image_to_artifact(&im,&a);
            const NtBuffer *stored=section==2?&a.rdata:&a.data;
            CHECK(a.base_relocation_count==1&&nvs_read(stored->bytes,8)==NT_PE_IMAGE_BASE+4096+14,
                  "data/rdata address binds to retained function identity");
            execute_artifact(&a,42);nt_artifact_free(&a);
        }
        nt_code_image_free(&im);
    }
    /* Reachable recursion must terminate graph traversal, not be dropped.
       It is inspected structurally here; finite recursion is executed below. */
    cases++;NtCodeImage cycle=synthetic(0,0);
    NtCodeReloc *cycle_refs=realloc(cycle.relocations,2*sizeof *cycle_refs);
    CHECK(cycle_refs!=NULL,"cycle relocation allocation");
    if(cycle_refs){
        cycle.relocations=cycle_refs;
        cycle.relocation_count=cycle.relocation_capacity=2;
        /* Retain callee body size6, replace it by call-self;ret with correct old REL32. */
        cycle.bytes[20]=0xe8;nvs_store(cycle.bytes+21,4,(uint32_t)-5);cycle.bytes[25]=0xc3;
        cycle.relocations[1]=(NtCodeReloc){1,NT_CODE_RELOC_REL32,21,3,0,0};
        CHECK(nova_seed_compact_image(&cycle,1,&s,&d)&&s.functions_kept==2&&cycle.relocation_count==2,
              "recursive reference closes on an already marked function");
    }
    nt_code_image_free(&cycle);
    cases++;NtCodeImage a=synthetic(0,0),b=synthetic(0,0);
    CHECK(nova_seed_compact_image(&a,1,&s,&d)&&nova_seed_compact_image(&b,1,&s,&d),"two compacted images accepted");
    CHECK(a.size==b.size&&a.entry==b.entry&&!memcmp(a.bytes,b.bytes,a.size),"deterministic retained instruction order");
    CHECK(a.relocation_count==b.relocation_count&&a.relocations[0].offset==b.relocations[0].offset,
          "deterministic relocation ordering/sites");
    nt_code_image_free(&a);nt_code_image_free(&b);
}
static void rejected_metadata(void){
    for(unsigned mutation=0;mutation<14;mutation++){
        cases++;NtCodeImage im=synthetic(0,mutation==11?2:0);
        CHECK(im.bytes&&im.symbols&&im.relocations,"mutation image allocated");
        if(!im.bytes||!im.symbols||!im.relocations){nt_code_image_free(&im);return;}
        switch(mutation){
          case 0:im.relocations[0].target_function=999;break;
          case 1:im.relocations[0].kind=99;break;
          case 2:im.relocations[0].source_section=4;break;
          case 3:im.relocations[0].offset=13;break;
          case 4:im.symbols[2].function_id=1;break;
          case 5:im.symbols[0].offset=1;break;
          case 6:im.bytes[5]^=1;break;
          case 7:im.symbols[1].flags=8;break;
          case 8:im.relocations[0].target_function=0;break;
          case 9:im.relocations[0].target_variable=100;break;
          case 10:im.relocations[0].addend=6;break;
          case 11:im.rdata.bytes[0]=1;break;
          case 12:im.entry=im.size;break;
          case 13:{
            NtCodeReloc *next=realloc(im.relocations,2*sizeof *next);
            CHECK(next!=NULL,"overlap relocation fixture allocated");
            if(!next){nt_code_image_free(&im);return;}
            im.relocations=next;im.relocations[1]=im.relocations[0];
            im.relocation_count=im.relocation_capacity=2;break;
          }
        }
        uint8_t before[26];memcpy(before,im.bytes,26);uint8_t *old=im.bytes;
        NtCodeSymbol *old_symbols=im.symbols;NtCodeReloc *old_relocations=im.relocations;
        size_t old_entry=im.entry;NovaSeedReachabilityStats s={0};NtCodeDiagnostic d={0};
        int ok=nova_seed_compact_image(&im,1,&s,&d);
        CHECK(!ok&&d.code&&!s.graph_complete,"unknown/broken metadata mutation%u is fail-closed",mutation);
        CHECK(im.bytes==old&&im.symbols==old_symbols&&im.relocations==old_relocations&&im.entry==old_entry&&
              !memcmp(before,im.bytes,26),"failed compaction is transactional mutation%u",mutation);
        nt_code_image_free(&im);
    }
}
static void run_nova_artifact(NtArtifact *a,uint64_t value,uint64_t error){
    NovaHostImage image={0};NovaContextV2 c={0};
    int initialized=nova_context_init_v2(&c);CHECK(initialized,"runtime initialized");
    int mapped=initialized&&nova_host_map(a,&image);CHECK(mapped,"actual Nova image mapped");
    if(mapped){uint64_t got=image.entry(&c,NULL,0);CHECK(got==value&&c.error==error,"full/compact Nova execution=%" PRIu64 "/%" PRIu64 " expected=%" PRIu64 "/%" PRIu64,got,c.error,value,error);}
    nova_host_unmap(&image);if(initialized)CHECK(nova_context_destroy_v2(&c),"runtime destroyed");
}
static int same_artifact(const NtArtifact *a,const NtArtifact *b){
    return a->entry==b->entry&&a->text.size==b->text.size&&a->rdata.size==b->rdata.size&&a->data.size==b->data.size&&
      (!a->text.size||!memcmp(a->text.bytes,b->text.bytes,a->text.size))&&
      (!a->rdata.size||!memcmp(a->rdata.bytes,b->rdata.bytes,a->rdata.size))&&
      (!a->data.size||!memcmp(a->data.bytes,b->data.bytes,a->data.size));
}
static void nova_case(const char *entry,const char *library,uint64_t value,uint64_t error){
    cases++;NtFInput inputs[]={{"entry.nova",entry,strlen(entry)},{"lib.nova",library,strlen(library)}};
    NtArtifact full={0},closed={0},again={0},default_policy={0},normal_again={0};
    NovaSeedReachabilityOptions options={1,sizeof options,NOVA_SEED_ENTRY_ONLY_CLOSED_APPLICATION,0};
    NovaSeedReachabilityStats s={0},all={0};
    int f=nova_compile_many_v2(inputs,2,&full);
    CHECK(f,"normal Nova source compilation E%u %s",full.error.code,full.error.message);
    int c=nova_compile_many_v2_seed_reachable(inputs,2,&closed,&options,&s);
    CHECK(c,"closed seed source compilation E%u %s",closed.error.code,closed.error.message);
    int a=nova_compile_many_v2_seed_reachable(inputs,2,&default_policy,NULL,&all);
    CHECK(a,"default all-exports seed compilation");
    CHECK(s.graph_complete&&all.graph_complete&&s.root_policy==1&&all.root_policy==0,"explicit/default policy reports");
    CHECK(c&&s.functions_kept<s.functions_before&&s.text_after<s.text_before,"dead private library code actually removed");
    CHECK(c&&a&&s.functions_kept<=all.functions_kept,"closed root set never exceeds all-exports roots");
    CHECK(f&&c&&full.rdata.size==closed.rdata.size&&
          (!full.rdata.size||!memcmp(full.rdata.bytes,closed.rdata.bytes,full.rdata.size)),"all original string/static data bytes retained");
    if(f)run_nova_artifact(&full,value,error);
    if(c)run_nova_artifact(&closed,value,error);
    if(a)run_nova_artifact(&default_policy,value,error);
    CHECK(nova_compile_many_v2_seed_reachable(inputs,2,&again,&options,NULL),"second compact compilation");
    CHECK(c&&same_artifact(&closed,&again),"opt-in compaction is byte deterministic");
    CHECK(nova_compile_many_v2(inputs,2,&normal_again),"normal API still compiles after opt-in");
    CHECK(f&&same_artifact(&full,&normal_again),"normal API output unchanged by optional optimizer");
    printf("SEED_DCE_NOVA before=%zu after=%zu functions=%zu/%zu roots=%zu/%zu/%zu all_exports_after=%zu\n",
      s.text_before,s.text_after,s.functions_kept,s.functions_before,s.roots_entry,s.roots_exported,s.roots_data,all.text_after);
    nt_artifact_free(&full);nt_artifact_free(&closed);nt_artifact_free(&again);nt_artifact_free(&default_policy);nt_artifact_free(&normal_again);
}
static void static_rip_case(void){
    cases++;size_t cap=65536;char *source=calloc(cap,1);CHECK(source!=NULL,"static source buffer allocated");if(!source)return;
    size_t n=(size_t)snprintf(source,cap,
      "module static_seed\ntarget x86_64-nexora-uefi\nsection .data { data counter:u64=40\n}\n"
      "section .text { fn a_dead()->u64 effects {} clobbers {} {\n");
    for(unsigned i=0;i<5000;i++)n+=(size_t)snprintf(source+n,cap-n,"nop\n");
    n+=(size_t)snprintf(source+n,cap-n,
      "return 1\n}\nexport fn main()->u64 effects {reads_mem(user),writes_mem(user),changes_flags} "
      "clobbers {rax,rflags} {load rax,[counter]:ptr<user,u64>\nadd rax,2\nstore [counter]:ptr<user,u64>,rax\n"
      "load rax,[counter]:ptr<user,u64>\nreturn rax\n}\n}\n");
    CHECK(n<cap,"real static source bounded");
    NtArtifact full={0},compact={0};NtFProgram program={0};NtCodeImage image={0};NtCodeDiagnostic d={0};NovaSeedReachabilityStats s={0};
    CHECK(nt_compile(source,n,&full),"normal static program compiles E%u %zu:%zu %s",
          full.error.code,full.error.line,full.error.column,full.error.message);
    NtFInput input={"static.ntasm",source,n};int parsed=nt_frontend_compile(&input,1,&program);
    CHECK(parsed,"actual static frontend code=%u %s",
          program.diagnostic_count?program.diagnostics[0].code:0,
          program.diagnostic_count?program.diagnostics[0].message:"no diagnostic");
    if(parsed){CHECK(nt_codegen_x64(&program,&image,&d),"actual static codegen");}
    int shrunk=image.bytes&&nova_seed_compact_image(&image,1,&s,&d);
    CHECK(shrunk&&s.text_before>4096&&s.text_after<4096,"real data-RIP layout crosses a page after compaction");
    if(shrunk){
        image_to_artifact(&image,&compact);
        CHECK(full.data.size==compact.data.size&&!memcmp(full.data.bytes,compact.data.bytes,full.data.size),"mutable static bytes are preserved");
        execute_artifact(&full,42);execute_artifact(&compact,42);
    }
    nt_code_image_free(&image);nt_frontend_free(&program);nt_artifact_free(&full);nt_artifact_free(&compact);free(source);
}
static void invalid_options(void){
    const char *text="module m;fn main()->u64{return 42;}";
    NtFInput input={"m.nova",text,strlen(text)};
    for(unsigned i=0;i<4;i++){
        cases++;NovaSeedReachabilityOptions o={1,sizeof o,0,0};
        if(i==0)o.version=2;
        if(i==1)o.size=0;
        if(i==2)o.root_policy=99;
        if(i==3)o.reserved=1;
        NtArtifact a={0};NovaSeedReachabilityStats s={0};
        CHECK(!nova_compile_many_v2_seed_reachable(&input,1,&a,&o,&s)&&a.error.code&&
              !a.text.bytes&&!a.pe.bytes&&!s.graph_complete,"invalid seed options%u refused",i);
        nt_artifact_free(&a);
    }
}
int main(void){
    graph_cases();rejected_metadata();invalid_options();
    const char *lib=
      "module lib;export fn sum(n:u64)->u64{if n==0{return 0;}else{return n+sum(n-1);}}"
      "export fn unused_public()->u64{return 99;}"
      "fn dead()->u64{let b:buf<u8>=alloc(runtime(),32);b[0]=77;rt_free(runtime(),b);return 123;}";
    nova_case("module entry;import lib;fn main()->u64{return lib.sum(9);}",lib,45,0);
    nova_case("module entry;import lib;fn main()->u64{return lib.text();}",
      "module lib;export fn text()->u64{let s:buf<u8>=\"four\";let n:u64=len(s);rt_free(runtime(),s);return n*10+2;}"
      "fn dead()->u64{let x:buf<u8>=\"retained dead data\";return len(x);}",42,0);
    nova_case("module entry;import lib;fn main()->u64{let d:buf<u8>=\"42\";let s:buf<u8>=alloc(runtime(),2);rt_copy(runtime(),d,s,2);return 99;}",
      "module lib;fn dead()->u64{return 123;}",0,NV2_READONLY);
    static_rip_case();
    printf("NTASM_NOVA_SEED_REACHABILITY checks=%u failures=%u cases=%u scope=C_SEED_ORACLE\n",checks,failures,cases);
    return failures?1:0;
}

