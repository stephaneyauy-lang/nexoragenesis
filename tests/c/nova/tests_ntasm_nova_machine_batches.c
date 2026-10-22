#define main prior_pipeline_main
#include "tests_ntasm_machine_pipeline.c"
#undef main
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <sys/stat.h>

/* THE BATCH ORCHESTRATOR GATE.
 *
 * The producer is the Nova module itself: `nova_machine_batches` and
 * `tests/nova-machine-batches-entry.nova`. The harness compiles ONLY that
 * producer, hands it SEVERAL Nova sources in one blob with their spans, and
 * then EXECUTES the PE the batches produced on the real ABI2 runtime.
 *
 * The sources of a fixture are SEPARATE strings. The harness copies them into
 * one blob and publishes the spans, because `parse_many` takes a blob and a
 * span table; no source is renamed, no module is simulated by a
 * concatenation, and no C rewrites a fixture.
 *
 * WHAT IS MEASURED. The program is cut into LOTS of `batch_limit` reachable
 * functions, every lot becomes its own NXO object, and the objects are linked
 * into one PE. The lot boundary is invisible to the program: the answer the
 * PE gives is the answer the sources describe, and it is the answer the same
 * sources give in ONE lot.
 */
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
    /* Relocations de base : l'image n'est pas a image_base, donc chaque DIR64
     * doit etre corrige de delta, sinon un pointeur absolu vise l'adresse de
     * liaison, qui n'est pas mappee. */
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
static unsigned abi_native;

/* THE PE IS EXECUTED FOR REAL, in a bounded child, on the real ABI2 runtime.
 * The parent's context is copied, so every refusal has an independent initial
 * error state. */
static void invoke_pe(CallbackImage *pe,NovaContextV2 *ctx,uint64_t want,uint64_t error) {
  cases++;int fd[2];if(pipe(fd)){CHECK(0,"BATCH PE pipe");return;}
  pid_t pid=fork();
  if(pid==0) {
    alarm(5);close(fd[0]);uint64_t result=((Abi2Entry)pe->entry)(ctx,NULL,0);
    uint64_t packet[4]={result,ctx?ctx->error:0,ctx?ctx->error_source:0,ctx?ctx->error_offset:0};
    int ok=write(fd[1],packet,sizeof packet)==(ssize_t)sizeof packet;_exit(ok?0:3);
  }
  close(fd[1]);if(pid<0){close(fd[0]);CHECK(0,"BATCH PE fork");return;}
  uint64_t packet[4]={0};ssize_t got=read(fd[0],packet,sizeof packet);close(fd[0]);int status=0;waitpid(pid,&status,0);
  int ok=WIFEXITED(status)&&WEXITSTATUS(status)==0&&got==(ssize_t)sizeof packet&&packet[0]==want&&packet[1]==error;
  if(!ok)fprintf(stderr,"BATCH_PE result=%llu error=%llu want=%llu/%llu status=%d bytes=%zd\n",(unsigned long long)packet[0],(unsigned long long)packet[1],(unsigned long long)want,(unsigned long long)error,status,got);
  CHECK(ok,"the produced PE answers the oracle on the real ABI2 runtime");
  if(ok)abi_native++;
}

/* THE SIZES THE BATCH PIPELINE NEEDS. The node, scope, bind, field and module
 * tables are the frontend's own, the words buffer is the MIR image's, and the
 * arena is the linker's: sixty four descriptors of sixteen bytes and the NXO
 * payloads that follow them. The arena is four megabytes, which is far above
 * what the small fixtures need and far below the runtime's own borrow
 * ceiling, so the arena is never the binding limit of these rows. */
#define BATCH_NODES 65536
#define BATCH_SIDES 4096
#define BATCH_BINDS 8192
#define BATCH_FIELDS 8192
#define BATCH_MODULES 8192
#define BATCH_MIR 65536
#define BATCH_PE 65536
#define BATCH_BLOB 65536
#define BATCH_REPORT 14
#define BATCH_DECLS 65536
#define BATCH_ARENA (4u*1024u*1024u)
/* THE LENGTHS BUFFER: [0] the bytes the arena holds, [1] the number of
 * objects in it. The two are zero on every refusal, and the entry's PE size
 * is in the output buffer's first word, not here. */
#define BATCH_LENGTHS 4
/* THE STAGES AND THE CODES THE PRODUCER PUBLISHES, pinned here so the gate
 * does not carry a copy of the producer's logic: 5 is
 * machine_pipeline.STAGE_LOWER, 10 is machine_pipeline.STAGE_DELIVER, 970 is
 * machine_pipeline.E_OUTPUT and 800 is the tree's own "bad argument" code. */
#define BATCH_STAGE_LOWER 5
#define BATCH_STAGE_DELIVER 10
#define BATCH_E_OUTPUT 970
#define BATCH_BAD_ARGUMENT 800
/* A FAULT IN THE HARNESS IS NOT A REFUSAL OF THE SOURCES. The sentinel is a
 * value no stage produces, so a reader can tell "the pipeline refused" from
 * "the harness lost the context". */
#define BATCH_FAULT UINT64_C(0xfeedfacedeadbeef)

struct BatchFixture {
  const char *const *sources;
  unsigned count;
  unsigned root;
  uint64_t want;     /* the PE's answer */
  uint64_t objects;  /* the expected number of objects, zero when not checked */
  uint64_t code;     /* the expected refusal code, zero when not checked */
  uint64_t stage;    /* the expected refusal stage, zero when not checked */
  int refused;       /* 1: the pipeline must refuse the sources */
};

/* TWO MODULES, ONE EXPORTED CALL: with a limit of one the callee is in the
 * second lot and the caller imports it. */
static const char *const fx_two_modules[] = {
  "module app;\nimport lib;\nexport fn main() -> u64 { return lib.answer(); }\n",
  "module lib;\nexport fn answer() -> u64 { return 42; }\n"
};
/* THE PRIVATE HELPER DECLARED BEFORE THE FUNCTION THAT CALLS IT, so the two
 * are in two lots and the call crosses the boundary in the other direction. */
static const char *const fx_helper_first[] = {
  "module app;\nimport lib;\nexport fn main() -> u64 { return lib.answer(); }\n",
  "module lib;\nfn helper() -> u64 { return 21; }\nexport fn answer() -> u64 { return helper() * 2; }\n"
};
/* AN IMPORT CYCLE WITH FINITE CALLS, SPREAD OVER THE LOTS. */
static const char *const fx_cycle[] = {
  "module x;\nimport y;\nexport fn main() -> u64 { return y.down(3); }\n",
  "module y;\nimport x;\nexport fn down(n: u64) -> u64 { if n == 0 { return 42; } return x.half(n); }\n",
  "module x;\nimport y;\nexport fn half(n: u64) -> u64 { return y.down(n - 1); }\n"
};
/* A BUFFER IN ONE MODULE AND A STRING IN THE OTHER, WITH NAMES THAT DO NOT
 * COLLIDE. The string is READ, so it is a live literal and not a dropped
 * one, and the answer stays forty three. */
static const char *const fx_buffer_string[] = {
  "module app;\nimport lib;\nexport fn main() -> u64 { let b: buf<u8> = alloc(runtime(), 3); return lib.total(b); }\n",
  "module lib;\nexport fn total(b: buf<u8>) -> u64 { let s: buf<u8> = \"ok\"; return len(b) + 40 - len(s) + 2; }\n"
};
/* THE SAME LOCAL NAME IN TWO MODULES, AND A STRING READ IN EACH. The two
 * local names are the SAME on purpose: the data items they carry are named
 * after them, so a naming that is not module qualified would make the two
 * lots collide, and the answer is the first byte of each string. */
static const char *const fx_two_strings[] = {
  "module app;\nimport lib;\nexport fn main() -> u64 { let s: buf<u8> = \"A\"; return s[0] + lib.second(); }\n",
  "module lib;\nexport fn second() -> u64 { let s: buf<u8> = \"B\"; return s[0]; }\n"
};
/* The first lot defines only a(), but its synthetic wrapper must import
 * main from the second lot. The resulting PE must execute both directions. */
static const char *const fx_main_after_helper[] = {
  "module app;\nfn a() -> u64 { return 42; }\n"
  "export fn main() -> u64 { return a(); }\n"
};
static const char *const fx_direct_chain[] = {
  "module app;\nexport fn main() -> u64 { return a(); }\n"
  "fn a() -> u64 { return b(); }\nfn b() -> u64 { return 42; }\n"
};
/* With batch_limit=1 both recursive edges cross real NXO object boundaries. */
static const char *const fx_direct_recursion[] = {
  "module app;\nexport fn main() -> u64 { return a(3); }\n"
  "fn a(n: u64) -> u64 { if n == 0 { return 42; } return b(n - 1); }\n"
  "fn b(n: u64) -> u64 { if n == 0 { return 42; } return a(n - 1); }\n"
};
static const struct BatchFixture BATCH_FIXTURES[] = {
  { fx_two_modules,   2, 0, 42, 0, 0, 0, 0 },
  { fx_helper_first,  2, 0, 42, 0, 0, 0, 0 },
  { fx_cycle,         3, 0, 42, 0, 0, 0, 0 },
  { fx_buffer_string, 2, 0, 43, 0, 0, 0, 0 },
  { fx_two_strings,   2, 0, 131, 0, 0, 0, 0 },
  { fx_main_after_helper,1,0,42,0, 0, 0, 0 },
  { fx_direct_chain,  1, 0, 42, 0, 0, 0, 0 },
  { fx_direct_recursion,1,0,42,0, 0, 0, 0 }
};
#define BATCH_FIXTURE_N ((unsigned)(sizeof BATCH_FIXTURES / sizeof BATCH_FIXTURES[0]))

/* THE BLOB: the sources copied one after another, and the span of each. The
 * frontend refuses overlapping spans and a span outside the blob, so the
 * spans here are the contract and not a convenience. */
static size_t build_blob(const char *const *sources,unsigned count,char *blob,size_t cap,uint64_t *spans) {
  size_t at=0;
  for(unsigned i=0;i<count;i++) {
    size_t l=strlen(sources[i]);
    if(at+l>cap) return 0;
    memcpy(blob+at,sources[i],l);
    spans[i*2]=(uint64_t)at;spans[i*2+1]=(uint64_t)l;
    at+=l;
  }
  return at;
}

/* THE PIPELINE CALL. The flat argument list is the frontend's own sixteen
 * words (the blob, the spans, the count, the root and the five tables) plus
 * the outputs: the MIR words, the declaration text, the arena, the PE and the
 * two lengths and report buffers, plus the batch limit. The count is the
 * array's own size, because a count that does not match the callee's arity
 * is refused by the ABI before the callee runs. */
static uint64_t call_batches(const NovaHostImage *image,const char *blob,size_t blob_len,
                             const uint64_t *spans,uint64_t count,uint64_t root_idx,uint64_t batch_limit,
                             uint64_t *scratch,uint8_t *decls,uint8_t *arena,uint64_t arena_bytes,
                             uint8_t *pe_out,uint64_t *length,uint64_t *report,uint64_t *fault) {
  length[0]=0;length[1]=0;
  if(fault) { fault[0]=0;fault[1]=0;fault[2]=0; }
  NovaContextV2 c={0};
  if(!nova_context_init_v2(&c)) { fprintf(stderr,"BATCH_FAULT context init failed\n"); return BATCH_FAULT; }
  uint64_t *nodes=scratch;
  uint64_t *scopes=scratch+BATCH_NODES;
  uint64_t *binds=scopes+BATCH_SIDES;
  uint64_t *fields=binds+BATCH_BINDS;
  uint64_t *modules=fields+BATCH_FIELDS;
  uint64_t *words=modules+BATCH_MODULES;
  uint64_t sh=nova_borrow_v2(&c,(void *)blob,blob_len,0);
  uint64_t sph=nova_borrow_v2(&c,(void *)spans,count*2*sizeof(uint64_t),0);
  uint64_t n1=nova_borrow_v2(&c,nodes,BATCH_NODES*8,1);
  uint64_t n2=nova_borrow_v2(&c,scopes,BATCH_SIDES*8,1);
  uint64_t n3=nova_borrow_v2(&c,binds,BATCH_BINDS*8,1);
  uint64_t n4=nova_borrow_v2(&c,fields,BATCH_FIELDS*8,1);
  uint64_t n5=nova_borrow_v2(&c,modules,BATCH_MODULES*8,1);
  uint64_t n6=nova_borrow_v2(&c,words,BATCH_MIR*8,1);
  uint64_t dh=nova_borrow_v2(&c,decls,BATCH_DECLS,1);
  uint64_t ah=nova_borrow_v2(&c,arena,arena_bytes,1);
  uint64_t oh=nova_borrow_v2(&c,pe_out,BATCH_PE,1);
  uint64_t lh=nova_borrow_v2(&c,length,BATCH_LENGTHS*sizeof(uint64_t),1);
  uint64_t rh=nova_borrow_v2(&c,report,BATCH_REPORT*sizeof(uint64_t),1);
  int borrowed=(sh!=0)&&(count==0||sph!=0)&&n1!=0&&n2!=0&&n3!=0&&n4!=0&&n5!=0&&n6!=0&&dh!=0&&ah!=0&&oh!=0&&lh!=0&&rh!=0;
  CHECK(borrowed,"the batch pipeline borrows completed");
  if(!borrowed||c.error!=0) {
    fprintf(stderr,"BATCH_FAULT borrow error=%llu\n",(unsigned long long)c.error);
    uint64_t e0=c.error,e1=c.error_source,e2=c.error_offset;
    if(fault) { fault[0]=e0;fault[1]=e1;fault[2]=e2; }
    nova_context_destroy_v2(&c);
    return BATCH_FAULT;
  }
  uint64_t args[]={sh,(uint64_t)blob_len,sph,count*2,count,root_idx,
    n1,BATCH_NODES,n2,BATCH_SIDES,n3,BATCH_BINDS,n4,BATCH_FIELDS,n5,BATCH_MODULES,
    n6,BATCH_MIR,BATCH_MIR,dh,BATCH_DECLS,
    ah,arena_bytes,arena_bytes,oh,BATCH_PE,BATCH_PE,lh,BATCH_LENGTHS,rh,BATCH_REPORT,
    batch_limit};
  uint64_t argc=(uint64_t)(sizeof(args)/sizeof(args[0]));
  CHECK(argc==32,"the batches entry takes thirty two flat words");
  uint64_t returned=image->entry(&c,args,argc);
  /* THE FAULT IS CAPTURED BEFORE THE CONTEXT IS DESTROYED, and it is never
   * attributed to the producer: a context that faulted did not refuse
   * anything, and a refusal case must not pass on a fault. */
  uint64_t runtime=c.error,source=c.error_source,offset=c.error_offset;
  if(runtime!=0) fprintf(stderr,"BATCH_FAULT runtime error=%llu source=%llu offset=%llu\n",
                         (unsigned long long)runtime,(unsigned long long)source,(unsigned long long)offset);
  if(fault) { fault[0]=runtime;fault[1]=source;fault[2]=offset; }
  nova_context_destroy_v2(&c);
  if(runtime!=0) return BATCH_FAULT;
  return returned;
}

/* ONE FIXTURE, END TO END. The lot limit and the arena's size are the row's
 * own: the same program must answer the same thing in one lot and in many.
 *
 * A FAULT IS NEVER A VERDICT. The row fails when the harness lost the
 * context, and a refusal row additionally pins the code and the stage the
 * producer publishes, so a refusal for the wrong reason is not a pass. */
static void run_batch(const NovaHostImage *image,NovaContextV2 *ctx,const struct BatchFixture *f,
                      uint64_t batch_limit,uint64_t arena_bytes,char *blob,uint64_t *spans,uint64_t *scratch,
                      uint8_t *decls,uint8_t *arena,uint8_t *pe_out,uint64_t *length,uint64_t *report) {
  cases++;
  size_t blob_len=build_blob(f->sources,f->count,blob,BATCH_BLOB,spans);
  CHECK(blob_len>0,"the fixture's sources fit the blob");
  if(blob_len==0) return;
  for(unsigned i=0;i<BATCH_REPORT;i++) report[i]=0;
  memset(pe_out,0,BATCH_PE);
  memset(arena,0,arena_bytes);
  uint64_t fault[3]={0,0,0};
  uint64_t code=call_batches(image,blob,blob_len,spans,f->count,f->root,batch_limit,
                             scratch,decls,arena,arena_bytes,pe_out,length,report,fault);
  CHECK(fault[0]==0,"the run raised no runtime error");
  CHECK(code!=BATCH_FAULT,"the harness kept the context");
  if(code==BATCH_FAULT) { fprintf(stderr,"BATCH_FAULT the harness lost the context; no verdict\n"); return; }
  uint64_t pe_size=r64(pe_out);
  if(code!=0)
    fprintf(stderr,"BATCH_REFUSED code=%llu report=%llu/%llu/%llu/%llu stage=%llu batches=%llu reachable=%llu objects=%llu\n",
            (unsigned long long)code,(unsigned long long)report[0],(unsigned long long)report[1],
            (unsigned long long)report[2],(unsigned long long)report[3],(unsigned long long)report[8],
            (unsigned long long)report[4],(unsigned long long)report[5],(unsigned long long)report[6]);
  if(f->refused) {
    CHECK(code!=0,"the pipeline refuses the sources");
    if(f->code!=0) CHECK(code==f->code,"the refusal carries the expected code");
    if(f->stage!=0) CHECK(report[8]==f->stage,"the refusal carries the expected stage");
    CHECK(pe_size==0,"the refusal published no PE");
    CHECK(length[0]==0&&length[1]==0,"the refusal published no arena");
    return;
  }
  CHECK(code==0,"the batched sources lower to a native ABI2 PE");
  if(code!=0) return;
  CHECK(pe_size>0,"the produced PE has a length");
  CHECK(pe_size<=BATCH_PE-8,"the produced PE fits its buffer");
  /* THE ARENA THE LINKER READ. The descriptors are the linker's, and each one
   * must name bytes that are in the arena, and the slots that were not filled
   * must be zero. */
  uint64_t objects=length[1];
  CHECK(objects>=1&&objects<=64,"the arena holds between one and sixty four objects");
  if(f->objects!=0) CHECK(objects==f->objects,"the arena holds the expected number of objects");
  if(f->sources==fx_main_after_helper)
    CHECK(objects==(batch_limit==1?2:1),"main after its helper is linked from exactly two single-function objects or one whole object");
  if(f->sources==fx_direct_chain||f->sources==fx_direct_recursion)
    CHECK(objects==(batch_limit==1?3:1),"the direct-call chain or recursion is linked from exactly three single-function objects or one whole object");
  CHECK(length[0]>=1024,"the arena holds the descriptor table and the payloads");
  CHECK(length[0]<=arena_bytes,"the arena's used bytes are inside the arena");
  for(uint64_t k=0;k<objects;k++) {
    uint64_t off=r64(arena+k*16),len=r64(arena+k*16+8);
    CHECK(len>0&&off+len<=length[0],"the descriptor names bytes that are in the arena");
  }
  for(uint64_t k=objects;k<64;k++)
    CHECK(r64(arena+k*16)==0&&r64(arena+k*16+8)==0,"the unused descriptor slots are zero");
  char why[256]={0};CallbackImage pe={0};
  int rc=map_callback_pe(pe_out+8,(size_t)pe_size,&pe,why,sizeof why);
  if(rc)fprintf(stderr,"BATCH_MAP %s\n",why);
  CHECK(rc==0,"the produced PE maps");
  if(rc) return;
  invoke_pe(&pe,ctx,f->want,0);
  munmap(pe.base,pe.size);
}

/* A PROGRAM WITH MANY REACHABLE FUNCTIONS, so a limit of one asks for more
 * lots than the descriptor table holds. The text is BUILT and not written by
 * hand: sixty six functions the main SUMS, so they are all reachable and the
 * answer is sixty six. */
static char wide_source[32768];
static void build_wide_source(void) {
  char *p=wide_source;size_t room=sizeof wide_source;
  int n=snprintf(p,room,"module app;\nexport fn main() -> u64 { return");
  if(n<0||(size_t)n>=room){wide_source[0]=0;return;}
  p+=n;room-=(size_t)n;
  for(int i=0;i<66;i++){ n=snprintf(p,room,"%s f%02d()",i?" +":"",i); if(n<0||(size_t)n>=room)break; p+=n;room-=(size_t)n; }
  n=snprintf(p,room,"; }\n");if(n<0||(size_t)n>=room)return;p+=n;room-=(size_t)n;
  for(int i=0;i<66;i++){ n=snprintf(p,room,"fn f%02d() -> u64 { return 1; }\n",i); if(n<0||(size_t)n>=room)break; p+=n;room-=(size_t)n; }
}

int main(void){
  /* PATHS[0] IS THE PIPELINE ENTRY, AND IT IS REPLACED BY THE ENTRY BELOW,
   * NOT COPIED: two exported mains in one artifact make the entry ambiguous
   * before a single RED row is measured. THE SIX EXTRA MODULES are the ones
   * the batch path needs and the pipeline path does not: the frontend's
   * parser, the two adapters of the lower, the batch orchestrator, the linker
   * over a list and the merger it calls. Every module is named ONCE. */
  NtFInput inputs[PATHS_N+6];char *texts[PATHS_N+6]={0};size_t sizes[PATHS_N+6]={0};int all=1;
  for(unsigned i=0;i<PATHS_N+6;i++) {
    const char *path=i==0?"tests/nova/tests/nova-machine-batches-entry.nova"
                   :i<PATHS_N?PATHS[i]
                   :i==PATHS_N?"compiler/nova/frontend/nova_language_parse.nova"
                   :i==PATHS_N+1?"compiler/nova/backend/nova/nova_machine_many.nova"
                   :i==PATHS_N+2?"compiler/nova/backend/nova/nova_machine_lower.nova"
                   :i==PATHS_N+3?"compiler/nova/backend/nova/nova_machine_batches.nova"
                   :i==PATHS_N+4?"compiler/nova/formats/nxo/nxo_link_pe.nova"
                   :"compiler/nova/formats/nxo/nxo_merge.nova";
    texts[i]=loadf(path,&sizes[i]);if(!texts[i])all=0;
    inputs[i]=(NtFInput){path,texts[i],sizes[i]};
  }
  NtArtifact art={0};NovaHostImage image={0};int context_ready=0;NovaContextV2 ctx={0};
  CHECK(all,"the batch producer sources load");
  int compiled=all&&nova_compile_many_v2(inputs,PATHS_N+6,&art);
  CHECK(compiled,"the batch producer compiles");
  if(!compiled){fprintf(stderr,"E%u %zu:%zu %s\n",art.error.code,art.error.line,art.error.column,art.error.message);goto cleanup;}
  CHECK(nova_host_map(&art,&image),"the batch producer maps");
  if(!image.entry)goto cleanup;
  context_ready=nova_context_init_v2(&ctx);CHECK(context_ready,"the real ABI2 runtime initializes");
  if(!context_ready)goto cleanup;
  {
    uint64_t *scratch=(uint64_t *)malloc((size_t)(BATCH_NODES+BATCH_SIDES+BATCH_BINDS+BATCH_FIELDS+BATCH_MODULES+BATCH_MIR)*sizeof(uint64_t));
    char *blob=(char *)malloc(BATCH_BLOB);
    uint8_t *pe_out=(uint8_t *)malloc(BATCH_PE);
    uint8_t *decls=(uint8_t *)malloc(BATCH_DECLS);
    uint8_t *arena=(uint8_t *)malloc(BATCH_ARENA);
    uint64_t spans[160],length[BATCH_LENGTHS],report[BATCH_REPORT];
    CHECK(scratch&&blob&&pe_out&&decls&&arena,"the batch harness buffers allocated");
    if(scratch&&blob&&pe_out&&decls&&arena) {
      /* THE SAME PROGRAM IN ONE LOT AND IN MANY: the lot boundary must be
       * invisible to the answer. */
      for(unsigned i=0;i<BATCH_FIXTURE_N;i++) {
        run_batch(&image,&ctx,&BATCH_FIXTURES[i],1,BATCH_ARENA,blob,spans,scratch,decls,arena,pe_out,length,report);
        run_batch(&image,&ctx,&BATCH_FIXTURES[i],64,BATCH_ARENA,blob,spans,scratch,decls,arena,pe_out,length,report);
      }
      /* THE SAME PROGRAM TWICE: THE SAME ARENA AND THE SAME PE. A batching
       * whose output moved between two runs of the same input could not be
       * measured. */
      {
        uint8_t *first_arena=(uint8_t *)malloc(BATCH_ARENA);
        uint8_t *first_pe=(uint8_t *)malloc(BATCH_PE);
        CHECK(first_arena&&first_pe,"the determinism buffers are allocated");
        if(first_arena&&first_pe) {
          run_batch(&image,&ctx,&BATCH_FIXTURES[0],1,BATCH_ARENA,blob,spans,scratch,decls,first_arena,first_pe,length,report);
          uint64_t arena_len=length[0],objects=length[1],pe_len=r64(first_pe);
          uint8_t *second_arena=(uint8_t *)malloc(BATCH_ARENA);
          uint8_t *second_pe=(uint8_t *)malloc(BATCH_PE);
          CHECK(second_arena&&second_pe,"the second determinism buffers are allocated");
          if(second_arena&&second_pe) {
            run_batch(&image,&ctx,&BATCH_FIXTURES[0],1,BATCH_ARENA,blob,spans,scratch,decls,second_arena,second_pe,length,report);
            CHECK(length[0]==arena_len&&length[1]==objects,"the arena has the same shape twice");
            CHECK(arena_len<=BATCH_ARENA&&memcmp(first_arena,second_arena,arena_len)==0,"the arena is byte for byte the same twice");
            /* THE COMPARISON IS OVER THE HEADER AND THE IMAGE: the first word
             * of the buffer is the PE's size, and the image follows it. */
            CHECK(r64(second_pe)==pe_len&&pe_len+8<=BATCH_PE&&memcmp(first_pe,second_pe,pe_len+8)==0,"the PE is byte for byte the same twice");
          }
          free(second_arena);free(second_pe);
        }
        free(first_arena);free(first_pe);
      }
      /* THE WIDE PROGRAM, TWICE. With a limit of sixty four it is TWO lots
       * and the answer is sixty six; with a limit of one it asks for more
       * lots than the descriptor table holds, and it is refused at the
       * DELIVERY stage, before anything is emitted. */
      {
        build_wide_source();
        const char *const sources[]={wide_source};
        struct BatchFixture two_lots={sources,1,0,66,2,0,0,0};
        run_batch(&image,&ctx,&two_lots,64,BATCH_ARENA,blob,spans,scratch,decls,arena,pe_out,length,report);
        struct BatchFixture too_many={sources,1,0,0,0,BATCH_E_OUTPUT,BATCH_STAGE_DELIVER,1};
        run_batch(&image,&ctx,&too_many,1,BATCH_ARENA,blob,spans,scratch,decls,arena,pe_out,length,report);
      }
      /* A LIMIT OF ZERO: no lot can be cut, and nothing is published. */
      {
        struct BatchFixture f={fx_two_modules,2,0,0,0,BATCH_BAD_ARGUMENT,BATCH_STAGE_LOWER,1};
        run_batch(&image,&ctx,&f,0,BATCH_ARENA,blob,spans,scratch,decls,arena,pe_out,length,report);
      }
      /* AN ARENA TOO SMALL FOR THE DESCRIPTOR TABLE: refused, and nothing is
       * published. */
      {
        struct BatchFixture f={fx_two_modules,2,0,0,0,BATCH_E_OUTPUT,BATCH_STAGE_DELIVER,1};
        run_batch(&image,&ctx,&f,1,64,blob,spans,scratch,decls,arena,pe_out,length,report);
      }
      /* AN INVALID ROOT: the frontend refuses it, and there is no oracle but
       * the refusal itself. */
      {
        cases++;
        size_t blob_len=build_blob(fx_two_modules,2,blob,BATCH_BLOB,spans);
        CHECK(blob_len>0,"the invalid root fixture fits the blob");
        if(blob_len>0) {
          for(unsigned i=0;i<BATCH_REPORT;i++) report[i]=0;
          memset(pe_out,0,BATCH_PE);
          uint64_t fault[3]={0,0,0};
          uint64_t code=call_batches(&image,blob,blob_len,spans,2,99,1,scratch,decls,arena,BATCH_ARENA,pe_out,length,report,fault);
          CHECK(fault[0]==0,"the refused root raised no runtime error");
          CHECK(code!=0&&code!=BATCH_FAULT,"the pipeline refuses an out of range root index");
          CHECK(r64(pe_out)==0,"the refused root published no PE");
          CHECK(length[0]==0&&length[1]==0,"the refused root published no arena");
        }
      }
    }
    free(arena);free(decls);free(pe_out);free(blob);free(scratch);
  }
cleanup:
  if(context_ready)CHECK(nova_context_destroy_v2(&ctx),"the real ABI2 runtime cleanup");
  nova_host_unmap(&image);nt_artifact_free(&art);
  for(unsigned i=0;i<PATHS_N+6;i++)free(texts[i]);
  printf("NTASM_NOVA_MACHINE_BATCHES checks=%u failures=%u cases=%u native=%u\n",checks,failures,cases,abi_native);
  return failures?1:0;
}
