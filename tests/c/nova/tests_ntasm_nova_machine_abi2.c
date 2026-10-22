#define main prior_pipeline_main
#include "tests_ntasm_machine_pipeline.c"
#undef main
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
/* The PE loader below is the already exercised quarantine mapper. The
 * generated product is Nova AST -> shared MIR -> NXO -> PE, never C codegen. */
typedef struct { uint8_t *base;size_t size;void *entry; } CallbackImage;
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

typedef uint64_t (__attribute__((ms_abi)) *Abi2Entry)(NovaContextV2*,const uint64_t*,uint64_t);
static unsigned abi_native;
static int build_abi2(NovaHostImage *image,Run *r,const char *source,CallbackImage *mapped){
  cases++;uint64_t code=run(image,source,strlen(source),1,0,r);
  if(code || r->runtime)fprintf(stderr,"ABI2_BUILD code=%llu runtime=%llu stage=%llu owner=%llu,%llu,%llu,%llu\n",(unsigned long long)code,(unsigned long long)r->runtime,(unsigned long long)r->report[8],(unsigned long long)r->report[0],(unsigned long long)r->report[1],(unsigned long long)r->report[2],(unsigned long long)r->report[3]);
  CHECK(code==0 && r->runtime==0,"Nova AST lowers to a native ABI2 PE");
  if(code || r->runtime)return 0;
  CHECK(r->length[0]>0 && r->length[0]<=TEXT,"ABI2 PE bounded");
  if(!r->length[0] || r->length[0]>TEXT)return 0;
  CHECK(r->report[11]==r->words[3] && r->report[12]==0,"ABI2 wrapper and body retain actual declaration provenance");
  char why[256]={0};int rc=map_callback_pe((const uint8_t*)r->out,(size_t)r->length[0],mapped,why,sizeof why);
  if(rc)fprintf(stderr,"ABI2_MAP %s\n",why);
  CHECK(rc==0,"ABI2 PE maps");return rc==0;
}
/* Each invocation runs in a bounded child. The parent's actual context is
 * copied, so every refusal has an independent initial error state. */
static void invoke_abi2(CallbackImage *pe,NovaContextV2 *context,const uint64_t *args,uint64_t count,uint64_t want,uint64_t error){
  cases++;int fd[2];if(pipe(fd)){CHECK(0,"ABI2 pipe");return;}
  pid_t pid=fork();
  if(pid==0){
    alarm(5);close(fd[0]);uint64_t result=((Abi2Entry)pe->entry)(context,args,count);
    uint64_t packet[4]={result,context?context->error:0,context?context->error_source:0,context?context->error_offset:0};
    int ok=write(fd[1],packet,sizeof packet)==(ssize_t)sizeof packet;_exit(ok?0:3);
  }
  close(fd[1]);if(pid<0){close(fd[0]);CHECK(0,"ABI2 fork");return;}
  uint64_t packet[4]={0};ssize_t got=read(fd[0],packet,sizeof packet);close(fd[0]);int status=0;waitpid(pid,&status,0);
  int ok=WIFEXITED(status) && WEXITSTATUS(status)==0 && got==(ssize_t)sizeof packet && packet[0]==want && packet[1]==error;
  if(!ok)fprintf(stderr,"ABI2_EXEC result=%llu error=%llu source=%llu offset=%llu want=%llu/%llu status=%d bytes=%zd\n",(unsigned long long)packet[0],(unsigned long long)packet[1],(unsigned long long)packet[2],(unsigned long long)packet[3],(unsigned long long)want,(unsigned long long)error,status,got);
  CHECK(ok,"native ABI2 result and context error match independent oracle");if(ok)abi_native++;
}
int main(void){
  NtFInput inputs[PATHS_N+3];char *texts[PATHS_N+3]={0};size_t sizes[PATHS_N+3]={0};int all=1;
  for(unsigned i=0;i<PATHS_N+3;i++){
    const char *path=i==0?"tests/nova/tests/nova-machine-abi2-entry.nova":i<PATHS_N?PATHS[i]:i==PATHS_N?"compiler/nova/frontend/nova_language_parse.nova":i==PATHS_N+1?"compiler/nova/backend/nova/nova_machine_abi2.nova":"compiler/nova/backend/nova/nova_machine_lower.nova";
    texts[i]=loadf(path,&sizes[i]);if(!texts[i])all=0;inputs[i]=(NtFInput){path,texts[i],sizes[i]};
  }
  NtArtifact art={0};NovaHostImage image={0};Run r={0};int ready=0;CallbackImage pe={0};NovaContextV2 ctx={2,48,0,0,0,NULL};uint64_t args[2]={6,7};
  CHECK(all,"ABI2 test source closure loaded");int compiled=all && nova_compile_many_v2(inputs,PATHS_N+3,&art);
  CHECK(compiled,"ABI2 test producer compiles");
  if(!compiled){fprintf(stderr,"E%u %zu:%zu %s\n",art.error.code,art.error.line,art.error.column,art.error.message);goto cleanup;}
  CHECK(nova_host_map(&art,&image),"ABI2 test producer maps");if(!image.entry)goto cleanup;
  run_init(&r);ready=1;
  if(build_abi2(&image,&r,"module m;fn main()->u64{return 42;}",&pe)){
    invoke_abi2(&pe,&ctx,NULL,0,42,0);
    invoke_abi2(&pe,NULL,NULL,0,0,0);
    ctx.size=8;invoke_abi2(&pe,&ctx,NULL,0,0,0);ctx.size=48;
    ctx.version=1;invoke_abi2(&pe,&ctx,NULL,0,0,NV2_RUNTIME);ctx.version=2;
    ctx.error=NV2_EXHAUSTED;invoke_abi2(&pe,&ctx,NULL,0,0,NV2_EXHAUSTED);ctx.error=0;
    invoke_abi2(&pe,&ctx,args,1,0,NV2_ARGUMENT);
    munmap(pe.base,pe.size);memset(&pe,0,sizeof pe);
  }
  if(build_abi2(&image,&r,"module m;fn main(x:u64,y:u64)->u64{return x*y;}",&pe)){
    invoke_abi2(&pe,&ctx,args,2,42,0);invoke_abi2(&pe,&ctx,NULL,2,0,NV2_ARGUMENT);invoke_abi2(&pe,&ctx,args,1,0,NV2_ARGUMENT);
    munmap(pe.base,pe.size);memset(&pe,0,sizeof pe);
  }
  if(build_abi2(&image,&r,"module m;fn recur(x:u64)->u64{if x==0{return 0;}return 7+recur(x-1);}fn main(x:u64)->u64{return recur(x);}",&pe)){
    invoke_abi2(&pe,&ctx,args,1,42,0);munmap(pe.base,pe.size);memset(&pe,0,sizeof pe);
  }
  if(build_abi2(&image,&r,"module m;fn main(x:u8)->u8{return x;}",&pe)){
    uint64_t narrow[1]={42};invoke_abi2(&pe,&ctx,narrow,1,42,0);narrow[0]=256;invoke_abi2(&pe,&ctx,narrow,1,0,NV2_ARGUMENT);
    munmap(pe.base,pe.size);memset(&pe,0,sizeof pe);
  }
  if(build_abi2(&image,&r,"module m;fn main(x:bool)->bool{return x;}",&pe)){
    uint64_t boolean[1]={1};invoke_abi2(&pe,&ctx,boolean,1,1,0);boolean[0]=2;invoke_abi2(&pe,&ctx,boolean,1,0,NV2_ARGUMENT);
    munmap(pe.base,pe.size);memset(&pe,0,sizeof pe);
  }
  CHECK(abi_native==14,"all fourteen ABI2 scalar execution/refusal oracles ran");
cleanup:
  if(pe.base)munmap(pe.base,pe.size);
  if(ready)run_free(&r);
  nova_host_unmap(&image);nt_artifact_free(&art);
  for(unsigned i=0;i<PATHS_N+3;i++)free(texts[i]);
  printf("NTASM_NOVA_MACHINE_ABI2 checks=%u failures=%u cases=%u native=%u\n",checks,failures,cases,abi_native);return failures?1:0;
}

