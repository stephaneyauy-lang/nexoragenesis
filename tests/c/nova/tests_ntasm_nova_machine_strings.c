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
/* THE SAME BOUNDED FORK, BUT THE POSITION IS PART OF THE VERDICT. A row that
 * pins a source and an offset must fail when the position moves, so the
 * position is asserted and not only printed. */
static void invoke_abi2_at(CallbackImage *pe,NovaContextV2 *context,uint64_t want,uint64_t error,uint64_t source,uint64_t offset) {
  cases++;int fd[2];if(pipe(fd)){CHECK(0,"ABI2 pipe");return;}
  pid_t pid=fork();
  if(pid==0) {
    alarm(5);close(fd[0]);uint64_t result=((Abi2Entry)pe->entry)(context,NULL,0);
    uint64_t packet[4]={result,context?context->error:0,context?context->error_source:0,context?context->error_offset:0};
    int ok=write(fd[1],packet,sizeof packet)==(ssize_t)sizeof packet;_exit(ok?0:3);
  }
  close(fd[1]);if(pid<0){close(fd[0]);CHECK(0,"ABI2 fork");return;}
  uint64_t packet[4]={0};ssize_t got=read(fd[0],packet,sizeof packet);close(fd[0]);int status=0;waitpid(pid,&status,0);
  int ok=WIFEXITED(status)&&WEXITSTATUS(status)==0&&got==(ssize_t)sizeof packet&&packet[0]==want&&packet[1]==error&&packet[2]==source&&packet[3]==offset;
  if(!ok)fprintf(stderr,"ABI2_AT result=%llu error=%llu source=%llu offset=%llu want=%llu/%llu/%llu/%llu status=%d bytes=%zd\n",
    (unsigned long long)packet[0],(unsigned long long)packet[1],(unsigned long long)packet[2],(unsigned long long)packet[3],
    (unsigned long long)want,(unsigned long long)error,(unsigned long long)source,(unsigned long long)offset,status,got);
  CHECK(ok,"the produced PE answers the oracle with the exact position");
  if(ok)abi_native++;
}
static void handles_case(NovaHostImage *image,Run *r,NovaContextV2 *ctx,const char *source,const uint64_t *args,uint64_t count,uint64_t want,uint64_t error){
  CallbackImage pe={0};
  if(build_abi2(image,r,source,&pe)){
    invoke_abi2(&pe,ctx,args,count,want,error);munmap(pe.base,pe.size);
  }
}
/* THE LAST ELEMENT OF THE LAST READABLE PAGE.
 *
 * TWO PAGES ARE MAPPED AND THE SECOND ONE IS PROT_NONE, so a read that
 * crosses the end of the first page lands on memory that CANNOT be read and
 * faults. The element is lent to the program as a borrowed buffer, the
 * program reads it, and the answer must be the element's own value.
 *
 * A ONE BYTE ELEMENT IS THE INTERESTING CASE: the access resolves ONE byte,
 * so a read of eight bytes would read seven bytes the program never had. The
 * u64 case is the other half: the value is above 255, so a reader that
 * narrowed EVERY load to one byte would answer a different number.
 *
 * THE CONTEXT IS FRESH FOR EACH CASE, IT IS DESTROYED BEFORE THE MAPPING IS
 * RELEASED, AND THE HOST TOUCHES NOTHING OUTSIDE THE FIRST PAGE: the value
 * is written at the last address of the first page and nowhere else. */
static void page_edge_case(NovaHostImage *image,Run *r,const char *source,size_t element_bytes,
                            const void *value,uint64_t borrow_bytes,uint64_t elements,uint64_t want) {
  CallbackImage pe={0};
  if(!build_abi2(image,r,source,&pe)) return;
  long raw=sysconf(_SC_PAGESIZE);
  CHECK(raw>0 && (size_t)raw%8==0,"the page size is known and holds a whole u64");
  if(raw<=0) { munmap(pe.base,pe.size); return; }
  size_t ps=(size_t)raw;
  uint8_t *region=(uint8_t *)mmap(NULL,ps*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  CHECK(region!=MAP_FAILED,"the two page region is mapped");
  if(region==MAP_FAILED) { munmap(pe.base,pe.size); return; }
  /* THE PAGE AFTER THE FIRST ONE CANNOT BE READ. */
  CHECK(mprotect(region+ps,ps,PROT_NONE)==0,"the page after the first one is unreadable");
  /* THE VALUE IS THE LAST ELEMENT OF THE FIRST PAGE, and the write is inside
   * that page: the last byte for one byte, the last eight bytes for a u64. */
  memcpy(region+ps-element_bytes,value,(size_t)element_bytes);
  NovaContextV2 c={0};
  int c_ready=nova_context_init_v2(&c);
  CHECK(c_ready,"the page edge context initializes");
  if(c_ready) {
    uint64_t handle=nova_borrow_v2(&c,(void *)(region+ps-element_bytes),borrow_bytes,0);
    CHECK(handle!=0,"the last element of the first page is lent to the program");
    if(handle) {
      /* THE TWO ABI2 WORDS OF A BUFFER: the handle and the length. The
       * length counts BYTES for a buf<u8> and ELEMENTS for a buf<u64>. */
      uint64_t args[2]={handle,elements};
      invoke_abi2(&pe,&c,args,2,want,0);
    }
  }
  /* THE CONTEXT GOES BEFORE THE MAPPING: the borrow still names the page. */
  CHECK(nova_context_destroy_v2(&c),"the page edge context is destroyed");
  munmap(region,ps*2);
  munmap(pe.base,pe.size);
}
static NovaCallV2 original_length;
static NovaCallV2 original_alloc;
static uint64_t NOVA_ABI doubled_length(NovaContextV2 *ctx,uint64_t a,uint64_t b,uint64_t c){return 2*original_length(ctx,a,b,c);}
static uint64_t NOVA_ABI failed_allocate(NovaContextV2 *ctx,uint64_t a,uint64_t b,uint64_t c){(void)a;(void)b;(void)c;ctx->error=NV2_EXHAUSTED;return 123;}
static uint64_t NOVA_ABI poison_length(NovaContextV2 *ctx,uint64_t a,uint64_t b,uint64_t c){(void)a;(void)b;(void)c;ctx->error=99;return 123;}
/* A FAULT THAT CARRIES A POSITION. The position the callback set is the
 * position the caller sees, byte for byte. */
static uint64_t NOVA_ABI located_fault(NovaContextV2 *ctx,uint64_t a,uint64_t b,uint64_t c){(void)a;(void)b;(void)c;ctx->error=NV2_IO;ctx->error_source=77;ctx->error_offset=88;return 0;}
/* A FAULT WITH NO POSITION AT ALL. The caller completes it. */
static uint64_t NOVA_ABI unlocated_fault(NovaContextV2 *ctx,uint64_t a,uint64_t b,uint64_t c){(void)a;(void)b;(void)c;ctx->error=NV2_IO;return 0;}
/* THE ALLOCATION THAT INSTALLS ANOTHER LENGTH. The table is read again at
 * every call, so the measurement that follows, in the SAME execution, sees
 * the callback this one installed. */
static uint64_t NOVA_ABI installing_allocate(NovaContextV2 *ctx,uint64_t a,uint64_t b,uint64_t c){uint64_t r=original_alloc(ctx,a,b,c);ctx->runtime->calls[NV2_LENGTH]=doubled_length;return r;}
int main(void){
  NtFInput inputs[PATHS_N+3];char *texts[PATHS_N+3]={0};size_t sizes[PATHS_N+3]={0};int all=1;
  for(unsigned i=0;i<PATHS_N+3;i++){
    const char *path=i==0?"tests/nova/tests/nova-machine-abi2-entry.nova":i<PATHS_N?PATHS[i]:i==PATHS_N?"compiler/nova/frontend/nova_language_parse.nova":i==PATHS_N+1?"compiler/nova/backend/nova/nova_machine_abi2.nova":"compiler/nova/backend/nova/nova_machine_lower.nova";
    texts[i]=loadf(path,&sizes[i]);if(!texts[i])all=0;inputs[i]=(NtFInput){path,texts[i],sizes[i]};
  }
  NtArtifact art={0};NovaHostImage image={0};Run r={0};int ready=0,context_ready=0;NovaContextV2 ctx={0};CallbackImage pe={0};
  char path[]="/tmp/nova-native-abi2-XXXXXX";int path_ready=0;
  CHECK(all,"native strings test source closure loaded");int compiled=all && nova_compile_many_v2(inputs,PATHS_N+3,&art);
  CHECK(compiled,"native strings producer compiles");
  if(!compiled){fprintf(stderr,"E%u %zu:%zu %s\n",art.error.code,art.error.line,art.error.column,art.error.message);goto cleanup;}
  CHECK(nova_host_map(&art,&image),"native strings producer maps");if(!image.entry)goto cleanup;
  run_init(&r);ready=1;context_ready=nova_context_init_v2(&ctx);CHECK(context_ready,"real string runtime initializes");if(!context_ready)goto cleanup;
  handles_case(&image,&r,&ctx,"module m;fn main()->u64{let s:buf<u8>=\"A\\n\\x42\\0\";return len(s)+u64(s[0])+u64(s[1])+u64(s[2])+u64(s[3]);}",NULL,0,145,0);
  handles_case(&image,&r,&ctx,"module m;fn main()->u64{let s:buf<u8>=\"\";return len(s);}",NULL,0,0,0);
  handles_case(&image,&r,&ctx,"module m;fn main()->u8{let s:buf<u8>=\"x\";s[0]=42;return s[0];}",NULL,0,0,NV2_READONLY);
  handles_case(&image,&r,&ctx,"module m;fn main()->u8{let s:buf<u8>=\"x\";rt_free(runtime(),s);return s[0];}",NULL,0,0,NV2_LIFETIME);
  handles_case(&image,&r,&ctx,"module m;fn main()->u8{let s:buf<u8>=\"*!\";let d:buf<u8>=alloc(runtime(),2);rt_copy(runtime(),d,s,2);return d[0];}",NULL,0,42,0);
  handles_case(&image,&r,&ctx,"module m;fn main()->u64{let s:buf<u8>=\"NV2\";rt_diag(runtime(),s);return len(s);}",NULL,0,3,0);
  handles_case(&image,&r,&ctx,"module m;fn main()->u64{let d:buf<u8>=alloc(runtime(),2);let s:buf<u8>=alloc(runtime(),1);rt_copy(runtime(),d,s,2);return 42;}",NULL,0,0,NV2_BOUNDS);
  handles_case(&image,&r,&ctx,"module m;struct Item{value:u64}fn main()->u64{let p:Item=null;if p==null{return 42;}return 1;}",NULL,0,42,0);
  handles_case(&image,&r,&ctx,"module m;fn main()->u64{let s:buf<u8>=\"ab\";let t:buf<u8>=slice(s,1,1);return u64(t[0]);}",NULL,0,98,0);
  /* THE BOOL FIELD IS AN EIGHT BYTE SLOT, so it is read whole and narrowed to
   * the declared width. A one bit load is not a machine width at all, and the
   * emitter refuses it -- so a bool field read at its declared width would be
   * a refusal instead of a read. The two rows are the true and the false.
   * The result is a BOOL: the frontend refuses a bool/integer conversion
   * (parser:1596, and the seed's own "no implicit narrowing or bool/integer
   * conversion"), so the field is returned as it is declared. */
  handles_case(&image,&r,&ctx,"module m;struct Item{flag:bool}fn main()->bool{let p:Item=Item{flag:true};return p.flag;}",NULL,0,1,0);
  handles_case(&image,&r,&ctx,"module m;struct Item{flag:bool}fn main()->bool{let p:Item=Item{flag:false};return p.flag;}",NULL,0,0,0);
  /* A RECORD INSIDE A RECORD: the inner record is a HANDLE, and the field
   * read of the inner record resolves through that handle. */
  handles_case(&image,&r,&ctx,"module m;struct Inner{v:u64}struct Outer{inner:Inner}fn main()->u64{let o:Outer=Outer{inner:Inner{v:42}};return o.inner.v;}",NULL,0,42,0);
  /* A BUFFER FIELD: the field holds the HANDLE, and the length is read back
   * from the runtime rather than stored beside the handle. The allocation is
   * bound to a NAME first: the frontend requires an allocation to be the
   * direct initializer of a buffer-typed binding (parser:2042), which is
   * where the seed lowers one at all (nova.c:2711). */
  handles_case(&image,&r,&ctx,"module m;struct S{buf:buf<u8>}fn main()->u64{let b:buf<u8>=alloc(runtime(),2);let s:S=S{buf:b};return len(s.buf);}",NULL,0,2,0);
  /* THE CHAIN STORAGE: 130 BYTES IS SEVENTEEN u64 ITEMS, so the ninth chunk
   * and every chunk after it are exercised, and the bytes at the chunk
   * boundaries 7/8 and 127/128 are read back. */
  char chain_pattern[131];
  for(int k=0;k<130;k++) chain_pattern[k]=(char)('A'+(k%26));
  char chain_source[4096];
  int chain_len=snprintf(chain_source,sizeof chain_source,"module m;fn main()->u64{let s:buf<u8>=\"%s\";return len(s)+u64(s[7])+u64(s[8])*100+u64(s[127])*10000+u64(s[128])*1000000;}",chain_pattern);
  CHECK(chain_len>0 && (size_t)chain_len<sizeof chain_source,"chain storage fixture bounded");
  if(chain_len>0 && (size_t)chain_len<sizeof chain_source)handles_case(&image,&r,&ctx,chain_source,NULL,0,89887502,0);
  /* A MULTI-BYTE UTF-8 LITERAL AMONG SEVERAL LITERALS: the bytes above 0x7f
   * must survive the decoder unchanged, and every literal must get its own
   * private storage name. The C escapes are the source of the raw bytes. */
  handles_case(&image,&r,&ctx,"module m;fn main()->u64{let a:buf<u8>=\"alpha\";let b:buf<u8>=\"\xc3\xa9\xe2\x82\xac\";let c:buf<u8>=\"gamma\";return len(a)+len(b)+len(c)+u64(a[0])+u64(c[0])*3+u64(b[0])*9+u64(b[1])*27+u64(b[2])*81+u64(b[3])*243+u64(b[4])*729;}",NULL,0,182023,0);
  /* EIGHT 0xFF BYTES ARE ONE u64 ITEM, AND ITS VALUE IS UINT64_MAX IN THE
   * DECLARATION TEXT. The number reader reserves a sentinel for "no magnitude"
   * and that sentinel cannot publish the maximum, so this case MEASURES the
   * boundary instead of assuming it. The sum of the eight bytes is 2040, and
   * each byte is bounded by u8, so the oracle proves that all eight are 255. */
  handles_case(&image,&r,&ctx,"module m;fn main()->u64{let s:buf<u8>=\"\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\";return u64(s[0])+u64(s[1])+u64(s[2])+u64(s[3])+u64(s[4])+u64(s[5])+u64(s[6])+u64(s[7]);}",NULL,0,2040,0);
  if(build_abi2(&image,&r,"module m;fn main()->u64{let b:buf<u8>=alloc(runtime(),42);return len(b);}",&pe)){
    original_length=ctx.runtime->calls[NV2_LENGTH];NovaCallV2 old_alloc=ctx.runtime->calls[NV2_ALLOC];
    invoke_abi2(&pe,&ctx,NULL,0,42,0);
    ctx.runtime->calls[NV2_LENGTH]=doubled_length;invoke_abi2(&pe,&ctx,NULL,0,84,0);
    ctx.runtime->calls[NV2_ALLOC]=failed_allocate;ctx.runtime->calls[NV2_LENGTH]=poison_length;invoke_abi2(&pe,&ctx,NULL,0,0,NV2_EXHAUSTED);
    ctx.runtime->calls[NV2_ALLOC]=old_alloc;ctx.runtime->calls[NV2_LENGTH]=original_length;
    ctx.runtime->version=1;invoke_abi2(&pe,&ctx,NULL,0,0,NV2_RUNTIME);ctx.runtime->version=2;
    ctx.runtime->size=119;invoke_abi2(&pe,&ctx,NULL,0,0,NV2_RUNTIME);ctx.runtime->size=sizeof *ctx.runtime;
    ctx.runtime->calls[NV2_ALLOC]=NULL;invoke_abi2(&pe,&ctx,NULL,0,0,NV2_RUNTIME);ctx.runtime->calls[NV2_ALLOC]=old_alloc;
    munmap(pe.base,pe.size);memset(&pe,0,sizeof pe);
  }
  /* THE TABLE'S OWN VERSION AND SIZE, THE POSITION OF A FAULT, AND THE TABLE
   * THAT IS READ AGAIN AT EVERY CALL. */
  {
    /* ONE PROGRAM, THREE VERDICTS: it allocates a buffer and measures it, so
     * the allocation, the measurement and the fault that replaces the
     * allocation are all at the same call site. */
    static const char *const source_alloc="module m;fn main()->u64{let b:buf<u8>=alloc(runtime(),42);return len(b);}";
    const char *call_at=strstr(source_alloc,"alloc");
    CallbackImage table_pe={0};
    CHECK(call_at!=NULL,"the allocation call is in the source");
    if(build_abi2(&image,&r,source_alloc,&table_pe)&&call_at!=NULL){
      uint64_t version=ctx.runtime->version,size=ctx.runtime->size;
      original_alloc=ctx.runtime->calls[NV2_ALLOC];
      /* A TABLE OF EXACTLY 120 BYTES HOLDS THE TWELVE SLOTS AND NOTHING MORE,
       * and a program that allocates and measures a buffer still works on it. */
      ctx.runtime->version=2;ctx.runtime->size=120;
      invoke_abi2(&table_pe,&ctx,NULL,0,42,0);
      /* A FAULT WITH A POSITION: THE POSITION IS THE CALLER'S, BYTE FOR BYTE. */
      ctx.runtime->calls[NV2_ALLOC]=located_fault;
      invoke_abi2_at(&table_pe,&ctx,0,NV2_IO,77,88);
      /* A FAULT WITH NO POSITION: THE CALLER COMPLETES IT, with the source
       * index and the offset of the CALL in the text. */
      ctx.runtime->calls[NV2_ALLOC]=unlocated_fault;
      invoke_abi2_at(&table_pe,&ctx,0,NV2_IO,1,(uint64_t)(call_at-source_alloc));
      /* THE TABLE IS READ AGAIN AT EVERY CALL: the allocation installs another
       * LENGTH, and the measurement that follows, IN THE SAME EXECUTION, sees
       * the callback this one installed. */
      ctx.runtime->calls[NV2_ALLOC]=installing_allocate;
      invoke_abi2(&table_pe,&ctx,NULL,0,84,0);
      ctx.runtime->calls[NV2_ALLOC]=original_alloc;
      ctx.runtime->version=version;ctx.runtime->size=size;
      munmap(table_pe.base,table_pe.size);memset(&table_pe,0,sizeof table_pe);
    }
  }
  /* THE COPY EXTENSION LIVES PAST THE TWELVE SLOTS, so a table of 120 bytes
   * does not hold it, and the copy must be REFUSED with the runtime's own
   * refusal instead of reading past the table. */
  {
    CallbackImage copy_pe={0};
    if(build_abi2(&image,&r,"module m;fn main()->u64{let d:buf<u8>=alloc(runtime(),2);let s:buf<u8>=alloc(runtime(),2);rt_copy(runtime(),d,s,2);return 42;}",&copy_pe)){
      uint64_t version=ctx.runtime->version,size=ctx.runtime->size;
      ctx.runtime->version=2;ctx.runtime->size=120;
      invoke_abi2(&copy_pe,&ctx,NULL,0,0,NV2_RUNTIME);
      ctx.runtime->version=version;ctx.runtime->size=size;
      munmap(copy_pe.base,copy_pe.size);memset(&copy_pe,0,sizeof copy_pe);
    }
  }
  /* THE LAST BYTE OF THE LAST READABLE PAGE. The access resolves ONE byte,
   * so the read must be one byte wide: a read of eight bytes would cross
   * into the page that is PROT_NONE and the program would fault on memory
   * it never had. */
  {
    const unsigned char byte=42;
    page_edge_case(&image,&r,"module m;fn main(b:buf<u8>)->u8{return b[0];}",1,&byte,1,1,42);
  }
  /* THE LAST u64 OF THE LAST READABLE PAGE, WITH A VALUE ABOVE 255. The read
   * must be eight bytes wide: a reader that narrowed every load to one byte
   * would answer the low byte and not the value. */
  {
    const uint64_t wide=UINT64_C(0x0102030405060708);
    page_edge_case(&image,&r,"module m;fn main(b:buf<u64>)->u64{return b[0];}",8,&wide,8,1,wide);
  }
  /* A PROGRAM THAT DECLARES THE HELPER'S OWN NAME: the generated helper is
   * renamed around it, and the program's own function still answers. */
  handles_case(&image,&r,&ctx,"module m;fn native_rt_helper()->u64{return 7;}fn main()->u64{return native_rt_helper();}",NULL,0,7,0);
  int fd=mkstemp(path);CHECK(fd>=0,"exclusive temporary IO path reserved");
  if(fd>=0){
    close(fd);path_ready=1;CHECK(unlink(path)==0,"reserved path released for native exclusive open");
    char source[2048];int n=snprintf(source,sizeof source,"module m;fn main()->u64{let path:buf<u8>=\"%s\";let s:buf<u8>=\"*!\";let f:u64=rt_open_new(runtime(),path);let wrote:u64=rt_write(runtime(),f,s);rt_close(runtime(),f);let g:u64=rt_open_read(runtime(),path);let d:buf<u8>=alloc(runtime(),2);let got:u64=rt_read(runtime(),g,d);rt_close(runtime(),g);return wrote+got+u64(d[0])+u64(d[1]);}",path);
    CHECK(n>0 && (size_t)n<sizeof source,"native IO fixture bounded");
    if(n>0 && (size_t)n<sizeof source)handles_case(&image,&r,&ctx,source,NULL,0,79,0);
    FILE *f=fopen(path,"rb");int a=f?fgetc(f):-1,b=f?fgetc(f):-1,end=f?fgetc(f):-1;if(f)fclose(f);
    CHECK(a==42 && b==33 && end==EOF,"independent native IO output bytes exact");
  }
  CHECK(abi_native==31,"all string, page edge, callback mutation, stop-on-error and IO oracles executed");
cleanup:
  if(path_ready)unlink(path);
  if(pe.base)munmap(pe.base,pe.size);
  if(context_ready)CHECK(nova_context_destroy_v2(&ctx),"real string runtime cleanup");
  if(ready)run_free(&r);
  nova_host_unmap(&image);nt_artifact_free(&art);
  for(unsigned i=0;i<PATHS_N+3;i++)free(texts[i]);
  printf("NTASM_NOVA_MACHINE_STRINGS checks=%u failures=%u cases=%u native=%u\n",checks,failures,cases,abi_native);return failures?1:0;
}
