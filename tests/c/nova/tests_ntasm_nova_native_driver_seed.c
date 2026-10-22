#define _GNU_SOURCE
/* C_SEED_ORACLE: C compiles ONLY the driver/import closure below.
 * INPUT.NOVA is copied as bytes, then read/parsed/lowered/emitted by the
 * EXECUTING Nova driver. The independent observer reads only produced PE bytes.
 */
#include <unistd.h>
#include <signal.h>
static pid_t driver_observer_fork(void) { pid_t p=fork(); if(p==0)alarm(5); return p; }
#define fork driver_observer_fork
#define main independent_pe_observer_reference_main
#include "tests_ntasm_pe_exec.c"
#undef main
#undef fork
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <sys/stat.h>

/* THE APPLICATION ENTRY COMES FIRST, and it declares no function. Two reasons,
 * and both are read back by something other than this table:
 *  - the driver's `export fn main()->u64` is the program's ONLY main, so an
 *    entry that declared one would make public_entry_v2 refuse the whole
 *    closure ("Nova ABI2 main is ambiguous across modules"). A header-only
 *    module contributes zero functions, so function ids -- and therefore the
 *    driver's own text -- are exactly what they were before it joined;
 *  - placed first, the entry is source 1 of the compile, so its `import` is
 *    resolved against the other inputs (nova.c module_headers refuses an
 *    imported module that is not an input). A misspelled or missing driver
 *    fails the compile instead of being a name written down here.
 * The remaining 52 rows are the driver and its real dependencies, unchanged and
 * in the same order. The count is DRIVER_CLOSURE_N, never a literal: 53 today
 * (this entry + 52), and every diagnostic below prints the sizeof. */
static const char *const DRIVER_CLOSURE[] = {
    "tests/nova/tests/nova-native-driver-entry.nova",
    "compiler/nova/drivers/nova_native_driver.nova",
    "compiler/nova/ir/machine_pipeline.nova",
    "compiler/nova/frontend/stub_table.nova",
    "compiler/nova/analysis/validate.nova",
    "compiler/nova/macros/macro_splice.nova",
    "compiler/nova/formats/ntir/ntir.nova",
    "compiler/nova/macros/macro_expand.nova",
    "compiler/nova/analysis/types/constant_types.nova",
    "compiler/nova/macros/constant_eval.nova",
    "compiler/nova/analysis/types/initializer_types.nova",
    "compiler/nova/analysis/types/condition_types.nova",
    "compiler/nova/analysis/types/literal_initializers.nova",
    "compiler/nova/frontend/targets.nova",
    "compiler/nova/frontend/versions.nova",
    "compiler/nova/analysis/abi/feature_requirements.nova",
    "compiler/nova/analysis/abi/features.nova",
    "compiler/nova/analysis/types/pointer_spaces.nova",
    "compiler/nova/analysis/control_flow.nova",
    "compiler/nova/analysis/types/return_types.nova",
    "compiler/nova/analysis/abi/body_clobbers.nova",
    "compiler/nova/analysis/abi/body_intrinsics.nova",
    "compiler/nova/analysis/abi/body_effects.nova",
    "compiler/nova/analysis/calls/call_contracts.nova",
    "compiler/nova/analysis/abi/abi.nova",
    "compiler/nova/analysis/calls/call_clobbers.nova",
    "compiler/nova/analysis/calls/call_effects.nova",
    "compiler/nova/analysis/calls/call_types.nova",
    "compiler/nova/analysis/calls/calls.nova",
    "compiler/nova/frontend/refs.nova",
    "compiler/nova/analysis/abi/clobbers.nova",
    "compiler/nova/analysis/abi/contracts.nova",
    "compiler/nova/analysis/abi/effects.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/frontend/register_bindings.nova",
    "compiler/nova/frontend/bindings.nova",
    "compiler/nova/frontend/locals.nova",
    "compiler/nova/frontend/parameters.nova",
    "compiler/nova/analysis/types/types.nova",
    "compiler/nova/frontend/symbol_names.nova",
    "compiler/nova/analysis/calls/callable_names.nova",
    "compiler/nova/analysis/semantics.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova",
    "compiler/nova/ir/machine_ir.nova",
    "compiler/nova/backend/nova/machine_emit.nova",
    "compiler/nova/backend/x64/x64_fixed.nova",
    "compiler/nova/formats/nxo/nxo.nova",
    "compiler/nova/formats/nxo/nxo_pe.nova",
    "compiler/nova/formats/pe/pe.nova",
    "compiler/nova/frontend/nova_language_parse.nova",
    "compiler/nova/backend/nova/nova_machine_lower.nova",
};
#define DRIVER_CLOSURE_N (sizeof DRIVER_CLOSURE / sizeof DRIVER_CLOSURE[0])

static uint8_t *bounded_read(const char *path, size_t max, size_t *size) {
    FILE *f=fopen(path,"rb"); if(!f)return NULL;
    uint8_t *bytes=NULL; long n;
    if(fseek(f,0,SEEK_END)||(n=ftell(f))<0||(uint64_t)n>max||fseek(f,0,SEEK_SET))goto done;
    bytes=malloc((size_t)n+1);if(!bytes)goto done;
    if(fread(bytes,1,(size_t)n,f)!=(size_t)n||ferror(f)){free(bytes);bytes=NULL;goto done;}
    bytes[n]=0;*size=(size_t)n;
done:
    if(fclose(f)){free(bytes);bytes=NULL;}return bytes;
}
static int joined(char *out,size_t n,const char *dir,const char *name){
    int k=snprintf(out,n,"%s/%s",dir,name);return k>0&&(size_t)k<n;
}
static int fresh_write(const char *path,const void *data,size_t n){
    FILE *f=fopen(path,"wbx");if(!f)return 0;
    int ok=fwrite(data,1,n,f)==n&&!ferror(f);if(fclose(f))ok=0;return ok;
}
static int observe(const char *path,uint64_t expected,const char *reference){
    size_t n=0;uint8_t *bytes=bounded_read(path,64u*1024u*1024u,&n);
    CHECK(bytes&&n,"independent observer reads actual PE file");
    if(!bytes||!n){free(bytes);return 0;}
    if(reference){
        size_t rn=0;uint8_t *rb=bounded_read(reference,64u*1024u*1024u,&rn);
        CHECK(rb&&rn==n&&!memcmp(bytes,rb,n),"native output PE equals C-runtime driver's exact PE bytes");
        free(rb);
    }
    uint64_t got=0;char why[256]={0};int rc=run_child(bytes,n,&got,why,sizeof why);
    CHECK(rc==0&&got==expected,"PE observer rc=%d got=%" PRIu64 " expected=%" PRIu64 " %s",rc,got,expected,why);
    printf("NOVA_DRIVER_PE_OBSERVER file=%s bytes=%zu rc=%d returned=%" PRIu64
           " expected=%" PRIu64 " source_not_compiled_by_C=yes\n",path,n,rc,got,expected);
    free(bytes);return rc==0&&got==expected;
}
typedef struct{
    const char *name,*fixture;
    uint64_t code,error,pe_result;
    int kind; /*0=source file,1=empty,2=oversize,3=preexisting output,4=missing input*/
} DriverCase;
static const DriverCase driver_cases[]={
    {"loop42","loop42.nova",0,0,42,0},
    {"loop43","loop43.nova",0,0,43,0},
    {"unsupported","unsupported_buffer.nova",970,0,0,0},
    {"undeclared","undeclared.nova",803,0,0,0},
    {"empty",NULL,1103,0,0,1},
    {"oversize",NULL,1101,0,0,2},
    {"output-existing","loop42.nova",0,NV2_IO,0,3},
    {"input-missing",NULL,0,NV2_IO,0,4}
};
static void oracle_case(const DriverCase *test,NovaHostImage *image,
                        const char *fixture_dir,const char *out_dir){
    char dir[4096],input[4096],output[4096],fixture[4096],meta[4096],cwd[4096];
    CHECK(joined(dir,sizeof dir,out_dir,test->name),"oracle directory path fits");
    CHECK(joined(input,sizeof input,dir,"INPUT.NOVA"),"input path fits");
    CHECK(joined(output,sizeof output,dir,"OUTPUT.EFI"),"output path fits");
    CHECK(joined(meta,sizeof meta,dir,"oracle.json"),"oracle metadata path fits");
    if(failures)return;
    CHECK(mkdir(dir,0777)==0,"oracle case directory must be fresh");
    if(failures)return;
    uint8_t *text=NULL;size_t n=0;
    if(test->fixture){
        CHECK(joined(fixture,sizeof fixture,fixture_dir,test->fixture),"fixture path fits");
        text=bounded_read(fixture,65535,&n);CHECK(text!=NULL,"read actual INPUT.NOVA fixture bytes");
    }else if(test->kind==2){
        n=65536;text=malloc(n);if(text)memset(text,' ',n);
        CHECK(text!=NULL,"create exact65536-byte sentinel fixture");
    }else if(test->kind==1){text=calloc(1,1);CHECK(text!=NULL,"empty input fixture");}
    if(test->kind!=4)CHECK(text&&fresh_write(input,text,n),"persist input without passing it to C compiler");
    free(text);text=NULL;
    if(test->kind==3)CHECK(fresh_write(output,"UNCHANGED",9),"preexisting output control");
    if(failures)return;
    CHECK(getcwd(cwd,sizeof cwd)!=NULL,"save oracle cwd");
    CHECK(chdir(dir)==0,"oracle works in isolated input/output directory");
    if(failures)return;
    NovaContextV2 context={0};
    int live=nova_context_init_v2(&context);CHECK(live,"initialize C runtime oracle");
    uint64_t got=UINT64_MAX,error=UINT64_MAX;
    if(live){
        got=image->entry(&context,NULL,0);error=context.error;
        CHECK(got==test->code&&error==test->error,
              "%s driver return=%" PRIu64 "/error=%" PRIu64 " expected=%" PRIu64 "/%" PRIu64,
              test->name,got,error,test->code,test->error);
        CHECK(nova_context_destroy_v2(&context),"oracle destroy after normal/runtime refusal");
        CHECK(context.runtime==NULL&&context.error==0,"destroy resets context; snapshot is separate");
    }
    CHECK(chdir(cwd)==0,"restore oracle cwd");
    if(failures)return;
    if(test->kind==3){
        size_t keep_n=0;uint8_t *keep=bounded_read(output,64,&keep_n);
        CHECK(keep&&keep_n==9&&!memcmp(keep,"UNCHANGED",9),"driver preserves preexisting output exactly");free(keep);
    }else if(test->code==0&&test->error==0){
        observe(output,test->pe_result,NULL);
    }else{
        errno=0;int exists=access(output,F_OK);
        CHECK(exists==-1&&errno==ENOENT,"refused input publishes no output PE");
    }
    char json[1024];
    int written=snprintf(json,sizeof json,
      "{\n \"label\":\"C_SEED_ORACLE\",\n \"case\":\"%s\",\n"
      " \"driver_returned\":%" PRIu64 ",\n \"runtime_error_before_destroy\":%" PRIu64 ",\n"
      " \"input_compiled_by_C\":false,\n \"produced_pe_expected_return\":%" PRIu64 ",\n"
      " \"A8_selfhost_proven\":false\n}\n",test->name,got,error,test->pe_result);
    CHECK(written>0&&(size_t)written<sizeof json,"oracle metadata bounded");
    if(written>0&&(size_t)written<sizeof json)CHECK(fresh_write(meta,json,(size_t)written),"persist exact oracle result");
    ++cases;
    printf("NOVA_NATIVE_DRIVER_ORACLE case=%s returned=%" PRIu64 " runtime=%" PRIu64
           " input_compiled_by_C=no\n",test->name,got,error);
}
int main(int argc,char **argv){
    if(argc>=2&&!strcmp(argv[1],"observe")){
        if(argc!=4&&argc!=5){fprintf(stderr,"usage: seed observe OUTPUT.EFI expected-return [C-runtime-reference.EFI]\n");return 2;}
        char *end=NULL;uint64_t expected=strtoull(argv[3],&end,0);
        CHECK(end&&*end==0,"observer expected value is a full integer");
        if(!failures)observe(argv[2],expected,argc==5?argv[4]:NULL);
        return failures?1:0;
    }
    if(argc<3||argc>5){fprintf(stderr,"usage: seed absolute-candidate-root fresh-absolute-proof-root [--seed-all-exports|--seed-closed-application [normal-oracle-root]]\n");return 2;}
    int compact=argc>=4;
    unsigned policy=NOVA_SEED_ALL_EXPORTS;
    if(compact){
        if(!strcmp(argv[3],"--seed-closed-application"))policy=NOVA_SEED_ENTRY_ONLY_CLOSED_APPLICATION;
        else if(strcmp(argv[3],"--seed-all-exports")){fprintf(stderr,"unknown explicit seed compaction mode\n");return 2;}
    }
    const char *reference_root=argc==5?argv[4]:NULL;
    if(reference_root&&reference_root[0]!='/'){fprintf(stderr,"reference oracle root must be absolute\n");return 2;}
    CHECK(argv[1][0]=='/'&&argv[2][0]=='/',"absolute POSIX candidate/output roots required");
    if(failures)return 1;
    CHECK(mkdir(argv[2],0777)==0,"proof root must be fresh");
    if(failures)return 1;
    char closure_dir[4096],driver_pe[4096],fixture_dir[4096],metadata[4096];
    CHECK(joined(closure_dir,sizeof closure_dir,argv[2],"closure"),"closure snapshot path fits");
    CHECK(joined(driver_pe,sizeof driver_pe,argv[2],"DRIVER.EFI"),"driver PE path fits");
    CHECK(joined(metadata,sizeof metadata,argv[2],"driver.json"),"driver provenance path fits");
    CHECK(joined(fixture_dir,sizeof fixture_dir,argv[1],"compiler/nova/native-driver-inputs"),"fixture directory path fits");
    CHECK(mkdir(closure_dir,0777)==0,"closure snapshot directory fresh");
    if(failures)return 1;
    NtFInput inputs[DRIVER_CLOSURE_N];
    char *texts[DRIVER_CLOSURE_N];memset(texts,0,sizeof texts);memset(inputs,0,sizeof inputs);
    size_t total=0;
    for(size_t i=0;i<DRIVER_CLOSURE_N;i++){
        char path[4096],copy[4096];size_t n=0;
        CHECK(joined(path,sizeof path,argv[1],DRIVER_CLOSURE[i]),"closure input path fits");
        const char *base=strrchr(DRIVER_CLOSURE[i],'/');base=base?base+1:DRIVER_CLOSURE[i];
        CHECK(joined(copy,sizeof copy,closure_dir,base),"closure snapshot path fits");
        if(failures)break;
        texts[i]=(char*)bounded_read(path,1024u*1024u,&n);CHECK(texts[i]!=NULL,"required closure source %s",path);
        if(!texts[i])break;
        CHECK(n<=4u*1024u*1024u-total,"total seed closure bounded4MiB");
        if(failures)break;
        total+=n;CHECK(fresh_write(copy,texts[i],n),"persist borrowed closure source exactly");
        inputs[i]=(NtFInput){DRIVER_CLOSURE[i],texts[i],n};
    }
    NtArtifact artifact={0};NovaHostImage image={0};int pe_available=0;
    NovaSeedReachabilityStats reachability={0};
    if(!failures){
        /* Exactly ONE selected source-to-machine-code C API call. Inputs are
         * only the DRIVER_CLOSURE_N sources of the closure above (the
         * application entry plus the 52 driver sources), NEVER
         * INPUT.NOVA/fixtures. */
        NovaSeedReachabilityOptions options={1,sizeof options,policy,0};
        int ok=compact?nova_compile_many_v2_seed_reachable(inputs,DRIVER_CLOSURE_N,&artifact,
                    policy==NOVA_SEED_ALL_EXPORTS?NULL:&options,&reachability):
                    nova_compile_many_v2(inputs,DRIVER_CLOSURE_N,&artifact);
        CHECK(ok&&artifact.error.code==0,"seed compiles actual Nova driver closure");
        if(!ok)fprintf(stderr,"DRIVER_SEED E%u source%u %zu:%zu %s\n",artifact.error.code,
          artifact.error.source_index,artifact.error.line,artifact.error.column,artifact.error.message);
    }
    if(!failures){
        int pe_ok=nt_make_pe(&artifact);
        pe_available=pe_ok&&artifact.pe.bytes&&artifact.pe.size;
        fprintf(stderr,"DRIVER_SEED_PE ok=%d E%u source=%u offset=%zu line=%zu column=%zu message=[%s] "
                "text=%zu entry=%zu text_present=%d rdata=%zu rdata_present=%d data=%zu data_present=%d "
                "base_relocations=%zu relocation_table_present=%d pe=%zu\n",
                pe_ok,artifact.error.code,artifact.error.source_index,artifact.error.offset,
                artifact.error.line,artifact.error.column,artifact.error.message,
                artifact.text.size,artifact.entry,artifact.text.bytes!=NULL,
                artifact.rdata.size,artifact.rdata.bytes!=NULL,
                artifact.data.size,artifact.data.bytes!=NULL,
                artifact.base_relocation_count,artifact.base_relocations!=NULL,artifact.pe.size);
        /* Run the genuine Nova/C-runtime oracles even when the PE writer
         * refuses its envelope. UEFI unavailability is a deferred final FAIL,
         * never a published image or a skipped-success oracle. */
        CHECK(nova_host_map(&artifact,&image),"map actual driver with existing C host mapper");
        fprintf(stderr,"DRIVER_SEED modules=%zu source_bytes=%zu text_bytes=%zu pe_bytes=%zu text_host_limit=%u\n",
                (size_t)DRIVER_CLOSURE_N,total,artifact.text.size,artifact.pe.size,NOVA_HOST_TEXT_LIMIT);
        fprintf(stderr,"DRIVER_SEED_REACHABILITY enabled=%d policy=%u complete=%u text=%zu/%zu "
                "functions=%zu/%zu roots=%zu/%zu/%zu references=%zu relocations=%zu/%zu\n",
                compact,reachability.root_policy,reachability.graph_complete,
                reachability.text_after,reachability.text_before,reachability.functions_kept,
                reachability.functions_before,reachability.roots_entry,reachability.roots_exported,
                reachability.roots_data,reachability.function_references,
                reachability.relocations_after,reachability.relocations_before);
    }
    if(!failures&&image.entry){
        for(size_t i=0;i<sizeof driver_cases/sizeof driver_cases[0];i++){
            oracle_case(&driver_cases[i],&image,fixture_dir,argv[2]);if(failures)break;
        }
    }
    if(!failures&&reference_root){
        for(size_t i=0;i<sizeof driver_cases/sizeof driver_cases[0];i++){
            char relative[256],actual_path[4096],reference_path[4096];
            int m=snprintf(relative,sizeof relative,"%s/oracle.json",driver_cases[i].name);
            CHECK(m>0&&(size_t)m<sizeof relative,"oracle reference name bounded");
            CHECK(joined(actual_path,sizeof actual_path,argv[2],relative)&&
                  joined(reference_path,sizeof reference_path,reference_root,relative),"oracle reference paths bounded");
            size_t an=0,rn=0;uint8_t *a=bounded_read(actual_path,4096,&an),*r=bounded_read(reference_path,4096,&rn);
            CHECK(a&&r&&an==rn&&!memcmp(a,r,an),"same result/error as unmodified driver case%s",driver_cases[i].name);
            free(a);free(r);
            if(driver_cases[i].pe_result){
                m=snprintf(relative,sizeof relative,"%s/OUTPUT.EFI",driver_cases[i].name);
                CHECK(m>0&&(size_t)m<sizeof relative&&
                  joined(actual_path,sizeof actual_path,argv[2],relative)&&
                  joined(reference_path,sizeof reference_path,reference_root,relative),"PE reference paths bounded");
                a=bounded_read(actual_path,4194304,&an);r=bounded_read(reference_path,4194304,&rn);
                CHECK(a&&r&&an==rn&&!memcmp(a,r,an),"same produced PE bytes as unmodified driver");
                free(a);free(r);
            }
        }
    }
    if(!failures){
        char first[4096],second[4096];size_t a_n=0,b_n=0;
        CHECK(joined(first,sizeof first,argv[2],"loop42/OUTPUT.EFI"),"first output path");
        CHECK(joined(second,sizeof second,argv[2],"loop43/OUTPUT.EFI"),"second output path");
        uint8_t *a=bounded_read(first,4194304,&a_n),*b=bounded_read(second,4194304,&b_n);
        CHECK(a&&b&&(a_n!=b_n||memcmp(a,b,a_n)!=0),"changed INPUT changes real output PE; both execute independently");
        free(a);free(b);
    }
    /* The number of cases is the TABLE's own size, so a row added to
     * driver_cases cannot leave this line asserting an old count, and a row
     * that stopped being reached cannot pass as "all of them". A literal 8 here
     * would have to be edited by whoever adds the ninth row, which is the same
     * as saying nobody would notice. */
    CHECK(cases==sizeof driver_cases/sizeof driver_cases[0],
          "every declared driver case exercised: declared=%zu exercised=%u",
          sizeof driver_cases/sizeof driver_cases[0],cases);
    fprintf(stderr,"DRIVER_SEED_BOUNDARY oracle_cases=%u UEFI_image_available=%d "
            "A8_selfhost_proven=no reference_compared=%d\n",cases,pe_available,
            reference_root!=NULL);
    /* reference_compared is printed because the question this run answers is
     * "did the application entry move a byte", and a run that never handed a
     * reference root cannot answer it: the comparison block above is skipped,
     * every other number is the same, and the banner used to look identical. */
    if(!reference_root)
        fprintf(stderr,"DRIVER_SEED_BOUNDARY note=no-reference-root "
                "the old OUTPUT.EFI bytes were NOT compared, so this run does "
                "not show that the entry left the driver's output unchanged\n");
    CHECK(pe_available,"UEFI seed PE unavailable; C-runtime oracles are a separate partial proof");
    if(!failures){
        CHECK(fresh_write(driver_pe,artifact.pe.bytes,artifact.pe.size),"publish C_SEED driver only after oracle success");
        char json[1024];int n=snprintf(json,sizeof json,
          "{\n \"label\":\"C_SEED_ORACLE\",\n \"driver_sources\":%zu,\n"
          " \"driver_source_bytes\":%zu,\n \"driver_text_bytes\":%zu,\n \"driver_pe_bytes\":%zu,\n"
          " \"oracle_cases\":%zu,\n \"INPUT_NOVA_compiled_by_C\":false,\n"
          " \"A8_selfhost_proven\":false\n}\n",
          (size_t)DRIVER_CLOSURE_N,total,artifact.text.size,artifact.pe.size,
          sizeof driver_cases/sizeof driver_cases[0]);
        CHECK(n>0&&(size_t)n<sizeof json,"driver provenance fits");
        if(n>0&&(size_t)n<sizeof json)CHECK(fresh_write(metadata,json,(size_t)n),"driver provenance persisted");
    }
    nova_host_unmap(&image);nt_artifact_free(&artifact);
    for(size_t i=0;i<DRIVER_CLOSURE_N;i++)free(texts[i]);
    printf("NTASM_NOVA_NATIVE_DRIVER_SEED checks=%u failures=%u cases=%u label=C_SEED_ORACLE "
           "INPUT_NOVA_compiled_by_C=no A8_selfhost_proven=no\n",checks,failures,cases);
    return failures?1:0;
}

