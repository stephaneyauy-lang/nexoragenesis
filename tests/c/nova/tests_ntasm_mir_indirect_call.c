#define main prior_pipeline_main
#include "tests_ntasm_machine_pipeline.c"
#undef main

/* Callback code is itself emitted from genuine NTASM by the same Nova
 * pipeline. C only maps its PE and calls it with an explicit ms_abi typedef.
 * The callback checks its modeled incoming rsp, writes the four caller home
 * slots, and deliberately publishes all volatile GPRs from its declaration. */
typedef struct { uint64_t marker,calls,aligned,target; } CallbackContext;
_Static_assert(sizeof(CallbackContext)==32 && offsetof(CallbackContext,target)==24,"controlled callback table layout");
typedef struct { uint8_t *base;size_t size;void *entry; } CallbackImage;
typedef uint64_t (__attribute__((ms_abi)) *ControlledCallback)(CallbackContext*,uint64_t,uint64_t,uint64_t);
static int map_callback_pe(const uint8_t *f, size_t n, CallbackImage *mapped_out, char *why, size_t wn)
{
    uint8_t *mapped=NULL;size_t mapped_size=0;
#define REFUSE(...) do { snprintf(why, wn, __VA_ARGS__); if(mapped){munmap(mapped,mapped_size);} return 1; } while (0)
    if (n < 0x40 || f[0] != 'M' || f[1] != 'Z') REFUSE("no MZ header");
    uint32_t pe = r32(f + 0x3c);
    if (pe > n - 24 || memcmp(f + pe, "PE\0\0", 4)) REFUSE("no PE signature");
    const uint8_t *coff = f + pe + 4;
    if (r16(coff) != 0x8664) REFUSE("machine is not x86-64");
    unsigned nsec = r16(coff + 2), optsz = r16(coff + 16);
    const uint8_t *opt = coff + 20;
    if ((size_t)(opt - f) + optsz > n || optsz < 112 + 6 * 8) REFUSE("optional header out of file");
    if (r16(opt) != 0x20b) REFUSE("not PE32+");
    if (r16(opt + 68) != 10) REFUSE("subsystem %u is not EFI application", r16(opt + 68));
    uint32_t entry = r32(opt + 16), size_image = r32(opt + 56), size_headers = r32(opt + 60);
    uint64_t image_base = r64(opt + 24);
    if (r32(opt + 108) < 6) REFUSE("no base relocation directory");
    uint32_t reloc_rva = r32(opt + 112 + 5 * 8), reloc_size = r32(opt + 112 + 5 * 8 + 4);
    if (!size_image || size_image > (64u << 20) || size_headers > size_image || size_headers > n)
        REFUSE("image size");
    const uint8_t *sec = opt + optsz;
    if ((size_t)(sec - f) + 40 * (size_t)nsec > n) REFUSE("section table out of file");
    uint8_t *img = mmap(NULL, size_image, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (img == MAP_FAILED) REFUSE("mmap %s", strerror(errno));
    mapped=img;mapped_size=size_image;
    memcpy(img, f, size_headers);
    int text_seen = 0;
    for (unsigned i = 0; i < nsec; i++) {
        const uint8_t *s = sec + 40 * i;
        uint32_t vs = r32(s + 8), va = r32(s + 12), rs = r32(s + 16), rp = r32(s + 20), ch = r32(s + 36);
        uint32_t copy = rs < vs ? rs : vs;
        if (va < size_headers || va > size_image || vs > size_image - va) REFUSE("section %u outside image", i);
        if (copy && (rp > n || copy > n - rp)) REFUSE("section %u raw data outside file", i);
        if ((ch & 0x20000000u) && (ch & 0x80000000u)) REFUSE("section %u is W+X", i);
        memcpy(img + va, f + rp, copy);
        if (ch & 0x20000000u && entry >= va && entry < va + vs) text_seen = 1;
    }
    if (!text_seen) REFUSE("entry 0x%" PRIx32 " is not in an executable section", entry);
    /* Relocations de base : l'image n'est pas à image_base, donc chaque DIR64
     * doit être corrigé de delta, sinon un pointeur absolu vise l'adresse de
     * liaison, qui n'est pas mappée. */
    uint64_t delta = (uint64_t)(uintptr_t)img - image_base;
    uint32_t at = 0;
    if (reloc_size && (reloc_rva > size_image || reloc_size > size_image - reloc_rva)) REFUSE("reloc dir outside image");
    while (at + 8 <= reloc_size) {
        uint32_t page = r32(img + reloc_rva + at), block = r32(img + reloc_rva + at + 4);
        if (block < 8 || block > reloc_size - at) REFUSE("reloc block size %" PRIu32, block);
        for (uint32_t e = 8; e + 2 <= block; e += 2) {
            uint16_t v = r16(img + reloc_rva + at + e);
            unsigned type = v >> 12, off = v & 0xfff;
            if (type == 0) continue;
            if (type != 10) REFUSE("reloc type %u", type);
            if (page > size_image - 8 || off > size_image - 8 - page) REFUSE("reloc site outside image");
            uint64_t old = r64(img + page + off), now = old + delta;
            /* Une application EFI de ce corpus n'importe rien : tout pointeur
             * absolu relocalisé vise SA propre image. Un chargeur qui oublierait
             * delta échouerait ici sur chaque cas positif. */
            if (now < (uint64_t)(uintptr_t)img || now >= (uint64_t)(uintptr_t)img + size_image)
                REFUSE("DIR64 at rva 0x%" PRIx32 " points outside the image after relocation", page + off);
            memcpy(img + page + off, &now, 8);
        }
        at += block;
    }
    for (unsigned i = 0; i < nsec; i++) {
        const uint8_t *s = sec + 40 * i;
        uint32_t vs = r32(s + 8), va = r32(s + 12), ch = r32(s + 36);
        uintptr_t lo = (uintptr_t)(img + va) & ~(uintptr_t)4095, hi = (uintptr_t)(img + va + vs);
        int prot = PROT_READ | (ch & 0x80000000u ? PROT_WRITE : 0) | (ch & 0x20000000u ? PROT_EXEC : 0);
        if (vs && mprotect((void *)lo, hi - lo, prot)) REFUSE("mprotect section %u: %s", i, strerror(errno));
    }
    mapped_out->base=img;mapped_out->size=size_image;mapped_out->entry=img+entry;
    return 0;
#undef REFUSE
}

static int probe_callback(CallbackImage *image,uint64_t marker,uint64_t want){
    int fd[2];
    if(pipe(fd))return 0;
    pid_t pid=fork();
    if(pid==0){
        alarm(5);close(fd[0]);CallbackContext ctx={marker,0,0,0};
        uint64_t result=((ControlledCallback)image->entry)(&ctx,3,7,1);
        uint64_t packet[3]={result,ctx.calls,ctx.aligned};
        int ok=write(fd[1],packet,sizeof packet)==(ssize_t)sizeof packet;
        _exit(ok?0:3);
    }
    close(fd[1]);if(pid<0){close(fd[0]);return 0;}
    uint64_t packet[3]={0};ssize_t got=read(fd[0],packet,sizeof packet);close(fd[0]);int status=0;waitpid(pid,&status,0);
    int ok=WIFEXITED(status) && WEXITSTATUS(status)==0 && got==(ssize_t)sizeof packet && packet[0]==want && packet[1]==1 && packet[2]==1;
    if(!ok)fprintf(stderr,"CALLBACK_PROBE result=%llu calls=%llu alignment=%llu status=%d bytes=%zd\n",(unsigned long long)packet[0],(unsigned long long)packet[1],(unsigned long long)packet[2],status,got);
    return ok;
}
static int probe_transport_callback(CallbackImage *image,unsigned argc,uint64_t want){
    typedef uint64_t (__attribute__((ms_abi)) *Call0)(void);
    typedef uint64_t (__attribute__((ms_abi)) *Call6)(CallbackContext*,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
    int fd[2];
    if(pipe(fd))return 0;
    pid_t pid=fork();
    if(pid==0){
        alarm(5);close(fd[0]);CallbackContext ctx={21,0,0,0};
        uint64_t result=argc==0?((Call0)image->entry)():((Call6)image->entry)(&ctx,3,7,1,11,13);
        int ok=write(fd[1],&result,sizeof result)==(ssize_t)sizeof result;_exit(ok?0:3);
    }
    close(fd[1]);if(pid<0){close(fd[0]);return 0;}
    uint64_t got=0;ssize_t n=read(fd[0],&got,sizeof got);close(fd[0]);int status=0;waitpid(pid,&status,0);
    int ok=WIFEXITED(status) && WEXITSTATUS(status)==0 && n==(ssize_t)sizeof got && got==want;
    if(!ok)fprintf(stderr,"CALLBACK_TRANSPORT argc=%u got=%llu want=%llu status=%d\n",argc,(unsigned long long)got,(unsigned long long)want,status);
    return ok;
}
static int make_callback(NovaHostImage *image,Run *r,unsigned multiplier,CallbackImage *mapped){
  char source[4096];int n=0;
  if(multiplier==0)n=snprintf(source,sizeof source,"module zero\ntarget x86_64-nexora-uefi\ndefault_abi efi-x64-v0\nsection .text { export fn main()->u64 effects {} clobbers {rax} {return 42;} }\n");
  else if(multiplier==6)n=snprintf(source,sizeof source,"module six\ntarget x86_64-nexora-uefi\ndefault_abi efi-x64-v0\nsection .text { export fn main(in ctx:u64,in a:u64,in b:u64,in c:u64,in d:u64,in e:u64)->u64 effects {} clobbers {rax} {return a+b+c+d+e;} }\n");
  else n=snprintf(source,sizeof source,
    "module callback.native\ntarget x86_64-nexora-uefi\ndefault_abi efi-x64-v0\nsection .text {\n"
    "export fn main(in ctx:u64,in a:u64,in b:u64,in c:u64)->u64\n"
    "effects {reads_mem(user),writes_mem(user),changes_flags}\n"
    "clobbers {rax,rcx,rdx,r8,r9,r10,r11,rflags} {\n"
    "mov r10,rsp\nand r10,15\ncmp r10,8\njne bad\n"
    "mov r10,rsp\nadd r10,8\nstore [r10]:ptr<user,u64>,1\n"
    "add r10,8\nstore [r10]:ptr<user,u64>,1\n"
    "add r10,8\nstore [r10]:ptr<user,u64>,1\n"
    "add r10,8\nstore [r10]:ptr<user,u64>,1\n"
    "mov r10,rcx\nadd r10,8\nload r11,[r10]:ptr<user,u64>\nadd r11,1\nstore [r10]:ptr<user,u64>,r11\n"
    "cmp r11,1\njne bad\nadd r10,8\nstore [r10]:ptr<user,u64>,r11\n"
    "load rax,[rcx]:ptr<user,u64>\nadd rax,rdx\n"
    "shl r8,1\nadd rax,r8\nshl r9,2\nadd rax,r9\n"
    "%s"
    "mov rcx,0\nmov rdx,0\n"
    "return rax;\nbad:\nreturn 2989;\n}\n}\n",multiplier==2?"add rax,rax\n":"");
  CHECK(n>0 && (size_t)n<sizeof source,"native callback source bounded");if(n<=0 || (size_t)n>=sizeof source)return 0;
  uint64_t code=run(image,source,(size_t)n,5,0,r);
  if(code || r->runtime)fprintf(stderr,"CALLBACK_BUILD multiplier=%u code=%llu runtime=%llu stage=%llu line=%llu column=%llu reason=%llu owner3=%llu\nSOURCE:\n%.*s\n",multiplier,(unsigned long long)code,(unsigned long long)r->runtime,(unsigned long long)r->report[8],(unsigned long long)r->report[0],(unsigned long long)r->report[1],(unsigned long long)r->report[2],(unsigned long long)r->report[3],n,source);
  CHECK(code==0 && r->runtime==0 && r->length[0]>0 && r->length[0]<=TEXT,"callback PE produced by the house Nova/NTASM backend");
  if(code || r->runtime || !r->length[0] || r->length[0]>TEXT)return 0;
  char why[256]={0};int rc=map_callback_pe((const uint8_t*)r->out,(size_t)r->length[0],mapped,why,sizeof why);
  if(rc)fprintf(stderr,"CALLBACK_MAP %s\n",why);
  CHECK(rc==0 && mapped->entry!=NULL,"house callback PE mapped without foreign assembler");return rc==0 && mapped->entry!=NULL;
}
/* Exact source from the measured runtime13 failure. Keep its weighted oracle
 * distinct from the shorter ABI probe; never accept returned=0/runtime13. */
static int make_long_callback(NovaHostImage *image,Run *r,CallbackImage *mapped){
  size_t size=0;char *source=loadf("tests/nova/tests/fixtures/indirect-callback-handle-exhaustion.ntasm",&size);
  CHECK(source!=NULL && size>0,"original exhausted callback source retained");
  if(!source)return 0;
  uint64_t code=run(image,source,size,5,0,r);
  if(code || r->runtime)fprintf(stderr,"LONG_CALLBACK code=%llu runtime=%llu stage=%llu line=%llu column=%llu reason=%llu owner3=%llu\n",(unsigned long long)code,(unsigned long long)r->runtime,(unsigned long long)r->report[8],(unsigned long long)r->report[0],(unsigned long long)r->report[1],(unsigned long long)r->report[2],(unsigned long long)r->report[3]);
  free(source);
  CHECK(code==0 && r->runtime==0 && r->length[0]>0 && r->length[0]<=TEXT,"long callback completes without raising original handle or byte limits");
  if(code || r->runtime || !r->length[0] || r->length[0]>TEXT)return 0;
  char why[256]={0};int rc=map_callback_pe((const uint8_t*)r->out,(size_t)r->length[0],mapped,why,sizeof why);
  if(rc)fprintf(stderr,"LONG_CALLBACK_MAP %s\n",why);
  CHECK(rc==0 && mapped->entry!=NULL,"long callback PE maps");return rc==0 && mapped->entry!=NULL;
}
static const char *SOURCE=
 "module indirect\ntarget x86_64-nexora-uefi\ndefault_abi efi-x64-v0\nsection .text {\n"
 "fn callback_contract(in ctx:u64,in a:u64,in b:u64,in c:u64)->u64 effects {reads_mem(user),writes_mem(user),changes_flags} clobbers {rax,rcx,rdx,r8,r9,r10,r11,rflags} {return 0;}\n"
 "export fn main()->u64 effects {reads_mem(user),writes_mem(user),changes_flags} clobbers {rax} {return 0;}\n}\n";
static const char *SOURCE0="module indirect.zero\ntarget x86_64-nexora-uefi\ndefault_abi efi-x64-v0\nsection .text { fn callback_contract()->u64 effects {} clobbers {rax} {return 0;} export fn main()->u64 effects {reads_mem(user)} clobbers {rax} {return 0;} }\n";
static const char *SOURCE6="module indirect.six\ntarget x86_64-nexora-uefi\ndefault_abi efi-x64-v0\nsection .text { fn callback_contract(in ctx:u64,in a:u64,in b:u64,in c:u64,in d:u64,in e:u64)->u64 effects {} clobbers {rax} {return 0;} export fn main()->u64 effects {reads_mem(user)} clobbers {rax} {return 0;} }\n";static unsigned executed;
static int make_pe_source(NovaHostImage *image,Run *r,CallbackContext *ctx,uint64_t mode,uintptr_t callback,const char *source){
  r->words[0]=(uint64_t)(uintptr_t)ctx;cases++;
  uint64_t code=run(image,source,strlen(source),mode,(uint64_t)callback,r);
  if(code || r->runtime)fprintf(stderr,"INDIRECT code=%llu runtime=%llu report=%llu,%llu,%llu,%llu stage=%llu\n",(unsigned long long)code,(unsigned long long)r->runtime,(unsigned long long)r->report[0],(unsigned long long)r->report[1],(unsigned long long)r->report[2],(unsigned long long)r->report[3],(unsigned long long)r->report[8]);
  CHECK(code==0 && r->runtime==0,"real typed MIR indirect call produces PE without a C backend");
  CHECK(code!=0 || (r->length[0]>0 && r->length[0]<=TEXT),"indirect PE output bounded");
  return code==0 && r->runtime==0 && r->length[0]>0 && r->length[0]<=TEXT;
}
static int make_pe(NovaHostImage *image,Run *r,CallbackContext *ctx,uint64_t mode,uintptr_t callback){return make_pe_source(image,r,ctx,mode,callback,SOURCE);}
static void execute_pe(Run *r,uint64_t want){
  uint64_t got=0;char why[256]={0};int rc=run_child((const uint8_t*)r->out,r->length[0],&got,why,sizeof why);
  if(rc || got!=want)fprintf(stderr,"INDIRECT_EXEC rc=%d got=%llu want=%llu %s\n",rc,(unsigned long long)got,(unsigned long long)want,why);
  CHECK(rc==0 && got==want,"ms_abi callback target, context, argument order, alignment and home space executed");
  if(!rc && got==want)executed++;
}
static void execute_long_pe(Run *r,CallbackContext *ctx){
  typedef uint64_t (__attribute__((ms_abi)) *CallMain)(void);
  CallbackImage mapped={0};char why[256]={0};int fd[2];
  int rc=map_callback_pe((const uint8_t*)r->out,(size_t)r->length[0],&mapped,why,sizeof why);
  CHECK(rc==0,"long callback caller maps");if(rc)return;
  if(pipe(fd)){CHECK(0,"long callback pipe");munmap(mapped.base,mapped.size);return;}
  pid_t pid=fork();
  if(pid==0){
    alarm(5);close(fd[0]);ctx->calls=0;ctx->aligned=0;
    uint64_t result=((CallMain)mapped.entry)();
    uint64_t packet[3]={result,ctx->calls,ctx->aligned};
    int ok=write(fd[1],packet,sizeof packet)==(ssize_t)sizeof packet;_exit(ok?0:3);
  }
  close(fd[1]);
  if(pid<0){close(fd[0]);CHECK(0,"long callback fork");munmap(mapped.base,mapped.size);return;}
  uint64_t packet[3]={0};ssize_t got=read(fd[0],packet,sizeof packet);close(fd[0]);int status=0;waitpid(pid,&status,0);
  int ok=WIFEXITED(status) && WEXITSTATUS(status)==0 && got==(ssize_t)sizeof packet && packet[0]==42 && packet[1]==1 && packet[2]==1;
  if(!ok)fprintf(stderr,"LONG_INDIRECT result=%llu calls=%llu alignment=%llu status=%d bytes=%zd\n",(unsigned long long)packet[0],(unsigned long long)packet[1],(unsigned long long)packet[2],status,got);
  CHECK(ok,"long weighted callback executes once with aligned entry and writable four-slot home space");
  if(ok)executed++;
  munmap(mapped.base,mapped.size);
}
int main(void){
  NtFInput inputs[PATHS_N];char *texts[PATHS_N]={0};size_t sizes[PATHS_N]={0};int all=1;
  for(unsigned i=0;i<PATHS_N;i++){
    const char *path=i?PATHS[i]:"tests/nova/tests/mir-indirect-call-entry.nova";
    texts[i]=loadf(path,&sizes[i]);if(!texts[i])all=0;inputs[i]=(NtFInput){path,texts[i],sizes[i]};
  }
  NtArtifact art={0};NovaHostImage image={0};Run r={0};int ready=0;CallbackImage callback={0},alternate={0},zero={0},six={0},long_callback={0};
  CHECK(all,"indirect test source closure loaded");
  int compiled=all && nova_compile_many_v2(inputs,PATHS_N,&art);
  CHECK(compiled,"indirect Nova producer test entry compiles");
  if(!compiled){fprintf(stderr,"E%u %zu:%zu %s\n",art.error.code,art.error.line,art.error.column,art.error.message);goto cleanup;}
  CHECK(nova_host_map(&art,&image),"indirect test producer maps");if(!image.entry)goto cleanup;
  if(getenv("NOVA_V2_ALLOC_TRACE")) {
    char caller_bounds[64];snprintf(caller_bounds,sizeof caller_bounds,"0x%llx",(unsigned long long)(uintptr_t)image.memory);setenv("NOVA_V2_TRACE_TEXT_BASE",caller_bounds,1);
    snprintf(caller_bounds,sizeof caller_bounds,"%zu",art.text.size);setenv("NOVA_V2_TRACE_TEXT_SIZE",caller_bounds,1);
    fprintf(stderr,"NV2_TRACE_IMAGE base=0x%llx text_bytes=%zu entry_offset=%zu\n",(unsigned long long)(uintptr_t)image.memory,art.text.size,art.entry);
    const char *trace_image=getenv("NOVA_V2_TRACE_IMAGE");
    if(trace_image && trace_image[0]) {
      FILE *dump=fopen(trace_image,"wb");
      if(dump){size_t wrote=fwrite(art.text.bytes,1,art.text.size,dump);int closed=fclose(dump);CHECK(wrote==art.text.size && closed==0,"optional allocation trace text image saved");}
      else CHECK(0,"optional allocation trace text image opens");
    }
  }
  run_init(&r);ready=1;CallbackContext ctx={21,0,0,0};
  if(!make_callback(&image,&r,1,&callback) || !make_callback(&image,&r,2,&alternate))goto cleanup;
  CHECK(probe_callback(&callback,21,42) && probe_callback(&alternate,21,84),"native callbacks independently execute their ABI probe through a C ms_abi caller");
  ctx.calls=0;ctx.aligned=0;
  if(make_pe(&image,&r,&ctx,1,(uintptr_t)callback.entry))execute_pe(&r,42);
  if(make_pe(&image,&r,&ctx,1,(uintptr_t)alternate.entry))execute_pe(&r,84);
  ctx.target=(uint64_t)(uintptr_t)callback.entry;
  if(make_pe(&image,&r,&ctx,4,0)){
    execute_pe(&r,42);ctx.target=(uint64_t)(uintptr_t)alternate.entry;
    execute_pe(&r,84); /* Identical PE bytes; only callback table state changes. */
    uint64_t count=r.words[3],call=0,extra=0,signature=0,main_fn=0,target=0,parameter=0;
    CHECK(count<=(WORDS-10)/24,"indirect MIR bounded");
    if(count<=(WORDS-10)/24){
      for(uint64_t n=1;n<=count;n++){
        uint64_t *p=r.words+10+(n-1)*24;
        if(p[0]==2087){call=n;signature=p[15];}
        if(p[0]==2083 && !extra)extra=n;
        if(p[0]==2051)main_fn=n;
      }
      if(call){
        uint64_t value=r.words[10+(call-1)*24+5];
        for(uint64_t n=1;n<=count;n++){
          uint64_t *p=r.words+10+(n-1)*24;
          if(p[4]==value && p[0]!=2056)target=n;
          if(p[0]==2054 && p[16]==signature && !parameter)parameter=n;
        }
      }
      CHECK(call && extra && signature && main_fn && target && parameter,"indirect mutation witnesses are real records");
      size_t bytes=(size_t)(10+count*24)*8;uint64_t *clean=malloc(bytes);CHECK(clean!=NULL,"indirect mutation snapshot allocated");
      if(clean && call && extra && signature && main_fn && target && parameter){
        memcpy(clean,r.words,bytes);
        for(unsigned m=0;m<14;m++){
          memcpy(r.words,clean,bytes);uint64_t *c=r.words+10+(call-1)*24,*e=r.words+10+(extra-1)*24;cases++;
          if(m==0)c[5]=c[4];
          if(m==1)c[5]=r.words[6]+1;
          if(m==2)r.words[10+(target-1)*24+9]=32;
          if(m==3)c[15]=0;
          if(m==4)c[15]=main_fn;
          if(m==5)c[14]=3;
          if(m==6)c[23]^=UINT64_C(1)<<11;
          if(m==7)e[14]=3;
          if(m==8)e[5]=c[4];
          if(m==9)c[12]=3;
          if(m==10)r.words[10+(parameter-1)*24+9]=32;
          if(m==11)r.words[2]=2;
          if(m==12)c[5]=r.words[10+(parameter-1)*24+4];
          if(m==13)c[9]=32;
          uint64_t code=run(&image,SOURCE,strlen(SOURCE),2,0,&r);
          if(!code || r.runtime)fprintf(stderr,"INDIRECT_MUTATION %u code=%llu runtime=%llu\n",m,(unsigned long long)code,(unsigned long long)r.runtime);
          CHECK(code!=0 && r.runtime==0,"malformed indirect target/signature/arity/clobber/availability/version refused");
        }
        memcpy(r.words,clean,bytes);CHECK(run(&image,SOURCE,strlen(SOURCE),2,0,&r)==0 && r.runtime==0,"restored indirect MIR verifies");
      }
      free(clean);
    }
  }
  if(make_callback(&image,&r,0,&zero)){
    CHECK(probe_transport_callback(&zero,0,42),"zero-argument native callback independently called with its exact C ms_abi signature");
    ctx.target=(uint64_t)(uintptr_t)zero.entry;
    if(make_pe_source(&image,&r,&ctx,4,0,SOURCE0))execute_pe(&r,42);
  }
  if(make_callback(&image,&r,6,&six)){
    CHECK(probe_transport_callback(&six,6,35),"six-argument native callback independently verifies stack arguments from a C ms_abi caller");
    ctx.target=(uint64_t)(uintptr_t)six.entry;
    if(make_pe_source(&image,&r,&ctx,4,0,SOURCE6))execute_pe(&r,35);
  }
  if(make_long_callback(&image,&r,&long_callback)){
    CHECK(probe_callback(&long_callback,11,42),"original long callback independently proves 11+3+3*7+7*1=42 and exactly one aligned call");
    ctx.marker=11;ctx.target=(uint64_t)(uintptr_t)long_callback.entry;
    if(make_pe(&image,&r,&ctx,4,0))execute_long_pe(&r,&ctx);
  }
  CHECK(executed==7,"seven native indirect executions include original exhaustion regression");
cleanup:
  if(long_callback.base)munmap(long_callback.base,long_callback.size);
  if(zero.base)munmap(zero.base,zero.size);
  if(six.base)munmap(six.base,six.size);
  if(callback.base)munmap(callback.base,callback.size);
  if(alternate.base)munmap(alternate.base,alternate.size);
  if(ready)run_free(&r);
  nova_host_unmap(&image);nt_artifact_free(&art);
  for(unsigned i=0;i<PATHS_N;i++)free(texts[i]);
  printf("NTASM_MIR_INDIRECT_CALL checks=%u failures=%u cases=%u native=%u\n",checks,failures,cases,executed);return failures?1:0;
}
