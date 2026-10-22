#define main prior_pipeline_main
#include "tests_ntasm_machine_pipeline.c"
#undef main
#include "../../../compiler/c/nova/runtime/runtime_v2.h"

/* tests_ntasm_nova_machine_errors.c -- THE ABI2 ARITHMETIC ERROR GATE.
 *
 * WHAT THIS GATE IS FOR. The C seed guards four arithmetic events on the ABI2
 * path (nova.c, near the `guard` helper): division or remainder by zero, signed
 * i64 division/remainder where the left operand is the most negative i64 and the
 * right one is -1, and a shift whose count is not strictly less than the operand
 * width. On a guarded event the seed stores the named code in the context
 * (NV2_DIVZERO, NV2_OVERFLOW, NV2_SHIFT) together with the source position, and
 * returns zero. The Nova machine producer is a DIFFERENT producer of the same
 * language, so those four events have to be measured on ITS output too: an
 * emitter that lowers division straight to x86 `div` faults with SIGFPE on a
 * zero divisor, and one that lowers a shift straight to `shl`/`shr` lets the
 * hardware mask the count to six bits and silently answers a different question.
 *
 * HOW THE EXPECTATION IS OBTAINED, AND WHY NOT FROM THE PRODUCER. Every case is
 * first compiled AND EXECUTED BY THE C SEED (`nova_compile_v2`, which is the
 * safe v2 profile where the guards live) in a bounded child, and the seed's
 * (return value, context error) pair IS the expectation. The Nova producer then
 * compiles the same text and its image runs in its own bounded child against
 * that pair. So the two sides share the SOURCE and nothing else: one side is C
 * codegen plus the C runtime, the other is Nova AST -> MIR -> NXO -> PE. The
 * seed is an ORACLE here, never a fallback for the producer's PE, and the
 * producer's own bytes are the ones executed.
 *
 * THE ARGUMENTS ARE DYNAMIC ON PURPOSE. `x/y` with a literal zero denominator
 * would be foldable, and a folded constant refusal would agree with the oracle
 * for a reason that has nothing to do with the emitter's division path. Every
 * divisor, dividend and shift count below arrives in the ABI2 argument slots at
 * run time.
 *
 * WHAT IS COMPARED. The pair (return value, context error) is the contract and
 * every one of the sixteen rows asserts it. The source index is compared as
 * well, because both sides name the same single input. The byte offset is NOT
 * asserted equal: the seed stores the START of the binary expression
 * (`guard`, span.start) and abi_guard stores the node's END (NTIR field 5), so
 * the convention-free property is that the producer's position lies at or after
 * the seed's. A row that violates it is PRINTED as ERROR_POS_DIFF and counted;
 * silence is never read as agreement.
 *
 * NO ROW IS SKIPPABLE. Every fixture below was measured to be ACCEPTED by the
 * reference, so all sixteen must produce a comparison, and the banner asserts
 * compared==rows with skipped==0. Once the oracle has accepted and executed a
 * fixture, a producer that refuses it is a divergence and fails the gate.
 *
 * A CANARY COMES FIRST. `add-normal-u64` must compute 42 with error zero on
 * BOTH sides: agreement on a wrong value (0 with an argument error on both) is
 * exactly the vacuous result this row exists to rule out, so the canary is
 * checked against 42 rather than against the oracle. A red canary means the
 * rows below it are unmeasured rather than disproved.
 */

/* The quarantine PE mapper, unchanged from the already exercised ABI2 gates. */
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
    /* Base relocations: the image is not at image_base, so each DIR64 is
     * corrected by delta -- an absolute pointer aimed at the link address would
     * not be mapped. */
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

/* One execution, in a child, with the parent's result read back through a pipe.
 * The child builds its OWN context from zero, so no case starts from another
 * case's error state, and the five second alarm bounds a producer that faults
 * or loops instead of letting the gate hang. */
typedef struct { int exited,signal,wait_code,status,ran; uint64_t result,error,source,offset; } Probe;

static Probe probe_entry(Abi2Entry entry,const uint64_t *args,uint64_t count){
  Probe p={0};
  int fd[2];if(pipe(fd)){fprintf(stderr,"ERROR_PROBE pipe failed\n");return p;}
  pid_t pid=fork();
  if(pid==0){
    alarm(5);close(fd[0]);
    NovaContextV2 c={0};
    uint64_t packet[4]={0,0,0,0};
    if(!nova_context_init_v2(&c))_exit(5);
    packet[0]=entry(&c,args,count);
    packet[1]=c.error;packet[2]=c.error_source;packet[3]=c.error_offset;
    if(!nova_context_destroy_v2(&c))_exit(4);
    int wrote=write(fd[1],packet,sizeof packet)==(ssize_t)sizeof packet;
    _exit(wrote?0:3);
  }
  close(fd[1]);
  if(pid<0){close(fd[0]);fprintf(stderr,"ERROR_PROBE fork failed\n");return p;}
  uint64_t packet[4]={0};
  ssize_t got=read(fd[0],packet,sizeof packet);close(fd[0]);
  int status=0;waitpid(pid,&status,0);
  p.status=status;
  p.exited=WIFEXITED(status)&&WEXITSTATUS(status)==0&&got==(ssize_t)sizeof packet;
  p.signal=WIFSIGNALED(status)?WTERMSIG(status):0;
  p.wait_code=WIFEXITED(status)?WEXITSTATUS(status):(WIFSIGNALED(status)?WTERMSIG(status):-1);
  if(got==(ssize_t)sizeof packet){p.ran=1;p.result=packet[0];p.error=packet[1];p.source=packet[2];p.offset=packet[3];}
  return p;
}

/* The independent side: the C seed compiles the same text in its safe v2
 * profile (where the guards live) and the image is entered with the same two
 * dynamic argument slots the producer receives. */
static int seed_oracle(const char *source,const uint64_t *args,uint64_t count,Probe *out){
  NtArtifact art={0};
  if(!nova_compile_v2(source,strlen(source),&art)){
    fprintf(stderr,"ORACLE_REFUSED code=%u line=%zu column=%zu %s\n",art.error.code,art.error.line,art.error.column,art.error.message);
    nt_artifact_free(&art);return 0;
  }
  NovaHostImage image={0};
  if(!nova_host_map(&art,&image)){
    fprintf(stderr,"ORACLE_UNMAPPED bytes=%zu\n",(size_t)art.text.size);
    nt_artifact_free(&art);return 0;
  }
  *out=probe_entry((Abi2Entry)image.entry,args,count);
  nova_host_unmap(&image);nt_artifact_free(&art);
  return 1;
}

/* The measured side. No CHECK lives here on purpose: the refusal has to be
 * reported together with the row it belongs to, and the caller owns that
 * verdict. */
static int build_maison(NovaHostImage *image,Run *r,const char *source,CallbackImage *mapped){
  cases++;uint64_t code=run(image,source,strlen(source),1,0,r);
  if(code||r->runtime){
    fprintf(stderr,"ERROR_BUILD code=%llu runtime=%llu stage=%llu owner=%llu,%llu,%llu,%llu\n",(unsigned long long)code,(unsigned long long)r->runtime,(unsigned long long)r->report[8],(unsigned long long)r->report[0],(unsigned long long)r->report[1],(unsigned long long)r->report[2],(unsigned long long)r->report[3]);
    return 0;
  }
  if(!r->length[0]||r->length[0]>TEXT){fprintf(stderr,"ERROR_BUILD length=%llu\n",(unsigned long long)r->length[0]);return 0;}
  char why[256]={0};
  if(map_callback_pe((const uint8_t*)r->out,(size_t)r->length[0],mapped,why,sizeof why)){
    fprintf(stderr,"ERROR_MAP %s\n",why);return 0;
  }
  return 1;
}

/* name, source, x, y, expect. `expect` is non-zero only for the positive
 * control: the row must produce exactly that value with error zero on BOTH
 * sides. Every other row takes its expectation from the oracle. */
typedef struct { const char *name,*source; uint64_t x,y,expect; } ErrorCase;
static const ErrorCase rows[]={
  {"add-normal-u64", "module m;fn main(x:u64,y:u64)->u64{return x+y;}", 41, 1, 42},
  {"div-zero-u64",  "module m;fn main(x:u64,y:u64)->u64{return x/y;}", 7, 0, 0},
  {"mod-zero-u64",  "module m;fn main(x:u64,y:u64)->u64{return x%y;}", 7, 0, 0},
  {"div-normal-u64","module m;fn main(x:u64,y:u64)->u64{return x/y;}", 7, 2, 0},
  {"mod-normal-u64","module m;fn main(x:u64,y:u64)->u64{return x%y;}", 7, 2, 0},
  {"div-min-i64",   "module m;fn main(x:i64,y:i64)->i64{return x/y;}", UINT64_C(0x8000000000000000), UINT64_MAX, 0},
  {"mod-min-i64",   "module m;fn main(x:i64,y:i64)->i64{return x%y;}", UINT64_C(0x8000000000000000), UINT64_MAX, 0},
  {"div-normal-i64","module m;fn main(x:i64,y:i64)->i64{return x/y;}", UINT64_MAX-6, 2, 0},
  {"mod-normal-i64","module m;fn main(x:i64,y:i64)->i64{return x%y;}", UINT64_MAX-6, 2, 0},
  {"shl-u64-64",    "module m;fn main(x:u64,y:u64)->u64{return x<<y;}", 1, 64, 0},
  {"shl-u64-63",    "module m;fn main(x:u64,y:u64)->u64{return x<<y;}", 1, 63, 0},
  {"shr-u64-64",    "module m;fn main(x:u64,y:u64)->u64{return x>>y;}", 256, 64, 0},
  {"shl-u64-3",     "module m;fn main(x:u64,y:u64)->u64{return x<<y;}", 1, 3, 0},
  {"sar-i64-1",     "module m;fn main(x:i64,y:u64)->i64{return x>>y;}", UINT64_MAX-3, 1, 0},
  {"shl-u8-8",      "module m;fn main(x:u8,y:u8)->u8{return x<<y;}", 1, 8, 0},
  {"shr-u8-8",      "module m;fn main(x:u8,y:u8)->u8{return x>>y;}", 128, 8, 0}
};
#define ROWS_N ((unsigned)(sizeof rows / sizeof rows[0]))

static unsigned compared,skipped,faults,positions_differ;

static void errors_case(NovaHostImage *image,Run *r,const ErrorCase *row){
  uint64_t args[2]={row->x,row->y};
  Probe seed={0};
  if(!seed_oracle(row->source,args,2,&seed)){
    CHECK(0,"C seed accepts the error oracle fixture (an oracle that cannot run proves nothing)");
    return;
  }
  if(!seed.exited){
    /* The oracle faulted. That is a fact about the reference, not about the
     * producer, so no comparison is possible -- and the row is still a failure,
     * because every fixture here was measured to be accepted and to run. */
    printf("ERROR_ORACLE_FAULT name=%s signal=%d wait_code=%d status=%d\n",row->name,seed.signal,seed.wait_code,seed.status);
    CHECK(0,"C seed oracle survives its own fixture (otherwise this row is unmeasured)");
    return;
  }
  if(row->expect){
    printf("ERROR_CANARY name=%s expect=%llu seed=%llu/%llu\n",row->name,
           (unsigned long long)row->expect,(unsigned long long)seed.result,
           (unsigned long long)seed.error);
    CHECK(seed.result==row->expect&&seed.error==0,
          "canary: the C seed computes the expected positive value (the line above prints the pair)");
  }
  CallbackImage pe={0};
  if(!build_maison(image,r,row->source,&pe)){
    fprintf(stderr,"ERROR_BUILD_CASE name=%s\n",row->name);
    CHECK(0,"Nova producer lowers the error case to a native ABI2 PE");
    return;
  }
  Probe got=probe_entry((Abi2Entry)pe.entry,args,2);
  int agree=got.exited&&got.result==seed.result&&got.error==seed.error;
  printf("ERROR_CASE name=%-16s seed=%llu/%llu maison=%llu/%llu seed_pos=%llu:%llu maison_pos=%llu:%llu signal=%d outcome=%s\n",
         row->name,(unsigned long long)seed.result,(unsigned long long)seed.error,
         (unsigned long long)got.result,(unsigned long long)got.error,
         (unsigned long long)seed.source,(unsigned long long)seed.offset,
         (unsigned long long)got.source,(unsigned long long)got.offset,
         got.signal,agree?"AGREE":"DIVERGE");
  if(row->expect){
    CHECK(got.exited&&got.result==row->expect&&got.error==0,
          "canary: the Nova producer computes the expected positive value (ERROR_CASE prints it)");
  }
  /* The position is reported, and the part of it that the two conventions share
   * is checked: the source index must be the same, and the producer's offset is
   * the END of the binary expression while the seed's is its START, so a
   * position EARLIER than the seed's is outside the node the event belongs to.
   * The offset is not asserted equal, and a disagreement is a printed line and a
   * counter, never a silent pass. */
  if(seed.error&&got.error){
    int same_source=got.source==seed.source;
    int span_ok=got.offset>=seed.offset;
    if(!same_source||!span_ok){
      positions_differ++;
      fprintf(stderr,"ERROR_POS_DIFF name=%s seed=%llu:%llu(start) maison=%llu:%llu(end) source=%s span=%s\n",
              row->name,(unsigned long long)seed.source,(unsigned long long)seed.offset,
              (unsigned long long)got.source,(unsigned long long)got.offset,
              same_source?"agree":"DIFF",span_ok?"end-after-start":"OUTSIDE");
    }else{
      printf("ERROR_POS name=%-16s seed=%llu:%llu(start) maison=%llu:%llu(end) source=agree span=end-after-start\n",
             row->name,(unsigned long long)seed.source,(unsigned long long)seed.offset,
             (unsigned long long)got.source,(unsigned long long)got.offset);
    }
  }
  if(!agree){
    if(!got.exited){
      faults++;
      fprintf(stderr,"ERROR_FAULT name=%s signal=%d wait_code=%d status=%d seed=%llu/%llu\n",row->name,got.signal,got.wait_code,got.status,(unsigned long long)seed.result,(unsigned long long)seed.error);
    }else{
      fprintf(stderr,"ERROR_DIVERGE name=%s seed=%llu/%llu maison=%llu/%llu\n",row->name,(unsigned long long)seed.result,(unsigned long long)seed.error,(unsigned long long)got.result,(unsigned long long)got.error);
    }
  }
  CHECK(agree,"Nova ABI2 return value and context error agree with the C seed oracle");
  if(agree)compared++;
  munmap(pe.base,pe.size);
}

int main(void){
  NtFInput inputs[PATHS_N+3];char *texts[PATHS_N+3]={0};size_t sizes[PATHS_N+3]={0};int all=1;
  for(unsigned i=0;i<PATHS_N+3;i++){
    const char *path=i==0?"tests/nova/tests/nova-machine-abi2-entry.nova":i<PATHS_N?PATHS[i]:i==PATHS_N?"compiler/nova/frontend/nova_language_parse.nova":i==PATHS_N+1?"compiler/nova/backend/nova/nova_machine_abi2.nova":"compiler/nova/backend/nova/nova_machine_lower.nova";
    texts[i]=loadf(path,&sizes[i]);if(!texts[i])all=0;inputs[i]=(NtFInput){path,texts[i],sizes[i]};
  }
  NtArtifact art={0};NovaHostImage image={0};Run r={0};int ready=0;
  CHECK(all,"error gate producer closure loaded");
  int compiled=all&&nova_compile_many_v2(inputs,PATHS_N+3,&art);
  CHECK(compiled,"error gate producer compiles");
  if(!compiled){fprintf(stderr,"E%u %zu:%zu %s\n",art.error.code,art.error.line,art.error.column,art.error.message);goto cleanup;}
  CHECK(nova_host_map(&art,&image),"error gate producer maps");
  if(!image.entry)goto cleanup;
  run_init(&r);ready=1;
  for(unsigned i=0;i<ROWS_N;i++)errors_case(&image,&r,&rows[i]);
  CHECK(compared==ROWS_N,"every declared row is compared: a skipped row is never counted, so this is the no-skip control and the banner prints skipped= as rows-compared");
cleanup:
  /* DERIVED, NOT DECLARED. A hand-kept `skipped` counter was never incremented,
   * so its CHECK could not fail; the banner number is now the difference
   * between the declared rows and the rows that actually reached a verdict. */
  skipped=ROWS_N-compared;
  if(ready)run_free(&r);
  nova_host_unmap(&image);nt_artifact_free(&art);
  for(unsigned i=0;i<PATHS_N+3;i++)free(texts[i]);
  printf("NTASM_NOVA_MACHINE_ERRORS checks=%u failures=%u cases=%u rows=%u compared=%u skipped=%u faults=%u positions_differ=%u\n",
         checks,failures,cases,ROWS_N,compared,skipped,faults,positions_differ);
  return failures?1:0;
}
